#!/usr/bin/env python3
"""Extract the selected node #94 spot metadata codec decisions from ELF bytes.

This is a bounded static instruction-pattern reader, not a disassembler or a
node emulator. It never calls external programs or executes the target.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = TOOLS.parent
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Each row selects the name, object-address setup and child-call instruction
# in the MessagePack-shaped writer, then the same three in the JSON writer,
# the reader's duplicate branch and its missing-field label (if applicable).
# Names, displacements, call targets and branch destinations are decoded from
# those bytes; these addresses select the inspected instructions only.
ROWS = (
 (0x2390bdf,0x2390bfd,0x2390c0c,0x2390848,0x2390841,0x2390857,0x1790469,0x178c3d4),
 (0x2390c23,0x2390c41,0x2390c5c,0x239086f,0x239088d,0x23908c5,0x1790be9,0x178c48e),
 (0x2390c73,0x2390c91,0x2390ca0,0x23908d8,0x23908f6,0x239092e,0x1790a6f,0x178ead2),
 (0x2390cb7,0x2390cd5,0x2390ce4,0x2390948,0x2390941,0x2390957,0x1790af2,0x178eba8),
 (0x2390d03,0x2390cf4,0x2390d2d,0x2390976,0x239096f,0x2390985,0x179084b,0x178ec78),
 (0x23d88c1,0x2390d3d,0x2390d4c,0x23d1454,0x2390993,0x239099d,0x1790c51,0x178edc3),
 (0x2390d63,0x2390d5c,0x2390d77,0x23909bc,0x23909b5,0x23909cb,0x1790d6b,0x178ef28),
 (0x23d5711,0x2390d87,0x2390d96,0x23d16c4,0x23909d9,0x23909e3,0x1790b63,0x178f033),
 (0x23d3461,0x2390da6,0x2390db5,0x23d2e14,0x23909f1,0x23909fb,0x1790e5b,0x178f186),
 (0x23d54c1,0x2390dc5,0x2390dd4,0x23d22c4,0x2390a09,0x2390a13,0x17909d8,0x178f2cd),
 (0x2390deb,0x2390de4,0x2390dff,0x2390a2e,0x2390a27,0x2390a3d,0x1790de6,0x178f3ff),
 (0x23d7611,0x2390e0f,0x2390e1e,0x23d1df4,0x2390a47,0x2390a51,0x17907d6,0x178f521),
 (0x23d7d11,0x2390e32,0x2390e35,0x23d2b64,0x2390a5e,0x2390a61,0x17908a7,0x178f5d3),
 (0x23d8461,0x2390e41,0x2390e53,0x23d1b84,0x2390a6b,0x2390a78,0x1790cd1,None),
)
# The first pair is the missing check; the mode says whether the absent
# arm branches directly, falls through, or reaches the label through a jump.
MISSING_GATES = ((0x178fc15,'jump'),(0x178ea75,'direct'),(0x178eaa8,'direct'),
 (0x178eba2,'fallthrough'),(0x178ec72,'fallthrough'),(0x178ed1b,'direct'),
 (0x178ee83,'direct'),(0x178efe2,'direct'),(0x178f0e7,'direct'),
 (0x178f234,'direct'),(0x178f372,'direct'),(0x178f49a,'direct'),
 (0x178f5c1,'fallthrough'))
COMPACT_CALLEES = (0x1e25dd0,0x1e4dd80,0x25e90b0,0x1e3ae20,0x1e4c850,
 0x23d88b0,0x23d58c0,0x23d5700,0x23d3450,0x23d54b0,0x23d58c0,
 0x23d7600,0x23d7d00,0x23d8450)
JSON_CALLEES = (0x2970a20,0x292ce80,0x25e3910,0x2963cf0,0x295c220,
 0x23d1440,0x2962b80,0x23d16b0,0x23d2e00,0x23d22b0,0x2962b80,
 0x23d1de0,0x23d2b50,0x23d1b70)
# Classifier code and jump tables: lengths 3..39, tags 0..14.
CLASSIFIER = 0x22e06e0
CLASS_END = 0x22e11e3
SELECTOR = 0x1790447
# Selected FDE starts, including the field helper bodies for both writers.
FUNCTIONS = (0x178bea0,0x1c39a20,0x22e06e0,0x23907f0,0x2390b60,
 0x23d88b0,0x23d5700,0x23d3450,0x23d54b0,0x23d7600,0x23d7d00,0x23d8450,
 0x23d1440,0x23d16b0,0x23d2e00,0x23d22b0,0x23d1de0,0x23d2b50,0x23d1b70)


BODY_SHA256 = {
    0x178bea0: '44856ebcc087dd3bec97ff44fbaccccc0265d4cf7dc385bcf13768598a734af9',
    0x1c39a20: '26157045826267c4d32b1d8bc7713126d561d3f952730fdaf738ba9071724c3e',
    0x22e06e0: '142725b6b82bdf950825086d64ea0fec72a1a3a02a50f3dfef84a867d6d76179',
    0x23907f0: '2f96a11b3eb718a1dcdd4f3ddd7e54d9dd112eb21fa562049952fd22e514cb26',
    0x2390b60: 'f1a5a8e15bee1b3de61219c95dd868cd87c4ee2f718b54c81b6cd97a4fff104e',
    0x23d1440: '8c64898ef4bc4095bfdf4499228691b504941700730337133a139a2ef24083f0',
    0x23d16b0: '5c05b27272efa74ba0f975f4781fd68b3e84757d50993151932f8c408886f43d',
    0x23d1b70: 'bbe6ebca1d093d6aac51ad1047555d059aa7409d7b97ebe58b97b047680942c8',
    0x23d1de0: 'd47103ddd4c233f267f418b39c854812b25dcf22ae3c6931735504096b5640f1',
    0x23d22b0: '5ec844ac101ee0fff877d08f9b463c6e9f65398eee1e0af2690ffda61903f9a7',
    0x23d2b50: '9eb4522ad6c844b35f80f2ea08b20f03c4661057249b113837eea01fb9293081',
    0x23d2e00: 'e89a9c618c6931a1142a3c1fd4cba792848d705d2e7b29cb75d6c9322b9f7c27',
    0x23d3450: '7efb5772c59b71a5fded9142a57bf7c28d5806a14141f59c88f1bec6ef0b7dd9',
    0x23d54b0: 'dfecc27d786195a05946ebf9a4a26aa6a8ba535fa564316fd837c2bcb3d40510',
    0x23d5700: 'ff3c344d0d8ecc04e402c166b754eaacab27e5686adf36c33ccc859259a923e7',
    0x23d7600: '25186b4d4d07624f773dc462226aba0754d2a9ee9feb3e67054ac0dd70e82eda',
    0x23d7d00: '9a4737b934e0eedeb66b4c093e644464deaecedac251974d63c1000f321fabf0',
    0x23d8450: 'cbfb4ab4c470d8c24e1c8699b62452e93a61db541202b691d5de93b660b5dc95',
    0x23d88b0: 'ea33f4989715f3b1193f176db4e35741600d806b444d57706f4fb30e3edea3e1',
}

class EvidenceError(ValueError):
    pass


def require(cond, message):
    if not cond:
        raise EvidenceError(message)


def authenticate(data):
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'target SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def mapping(self, va, size):
        require(isinstance(va,int) and isinstance(size,int) and va >= 0 and size > 0,
                'invalid address or length')
        hits = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2 and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(hits) == 1, 'address is not uniquely file-backed')
        s = hits[0]
        return s, s['offset'] + va - s['address']

    def read(self, va, size):
        _, off = self.mapping(va,size)
        return bytes(self.data[off:off+size])

    def window(self, va, size):
        s, off = self.mapping(va,size)
        return {'va':hex(va), 'file_offset':hex(off), 'section':s['name'],
                'bytes':self.read(va,size).hex()}


def rip(image, va):
    b = image.read(va,7)
    require(b[:2] == b'\x48\x8d' and b[2] in (0x05,0x0d,0x15,0x35,0x3d), 'unknown RIP LEA')
    return va+7+struct.unpack_from('<i',b,3)[0]


def call(image, va):
    b = image.read(va,5)
    require(b[0] == 0xe8, 'expected rel32 call')
    return va+5+struct.unpack_from('<i',b,1)[0]


def branch(image, va):
    b=image.read(va,2)
    if b[0] in (0x74,0x75,0x77,0xeb):
        return va+2+struct.unpack('<b',b[1:])[0]
    if b[0] == 0xe9:
        return va+5+struct.unpack('<i',image.read(va+1,4))[0]
    require(b[0] == 0x0f and b[1] in (0x84,0x85,0x87), 'unknown branch opcode')
    return va+6+struct.unpack('<i',image.read(va+2,4))[0]


def name(image, va):
    ptr=rip(image,va)
    # The writers put the length in EDX or ECX immediately after the LEA;
    # inline JSON stages use two intervening three-byte setup instructions.
    for delta in (7,10,12,15):
        op=image.read(va+delta,5)
        if op[0] in (0xba,0xb9):
            size=struct.unpack_from('<I',op,1)[0]
            require(0 < size < 64, 'invalid field name length')
            raw=image.read(ptr,size)
            require(all(32 <= b < 127 for b in raw), 'field name is not ASCII')
            return raw.decode('ascii'), ptr, va+delta
    raise EvidenceError('no supported length setup after field LEA')


def offset(image, va):
    raw=image.read(va,8)
    # Base is r14 in the compact writer, rbx in the JSON writer.
    if raw[:3] in (b'\x49\x8d\x96',b'\x49\x8d\xb6',b'\x4d\x8d\x86',
                   b'\x48\x8d\x8b',b'\x48\x8d\xb3',b'\x48\x8d\xbb'):
        return struct.unpack_from('<I',raw,3)[0]
    if raw[:4] == b'\x41\x0f\xb6\xae':
        return struct.unpack_from('<I',raw,4)[0]
    if raw[:3] in (b'\x49\x81\xc6',b'\x48\x81\xc3'):
        return struct.unpack_from('<I',raw,3)[0]
    if raw[:3] in (b'\x4c\x89\xf2',b'\x48\x89\xde'):
        return 0
    raise EvidenceError('unsupported field-address setup')


def classifier_table(image):
    head=image.read(CLASSIFIER,33)
    require(head[:11] == bytes.fromhex('4889f84883c2fd4883fa24'), 'classifier length gate changed')
    require(branch(image,CLASSIFIER+11) == 0x22e11da, 'length failure branch changed')
    table=rip(image,CLASSIFIER+17)
    require(image.read(CLASSIFIER+24,9) == bytes.fromhex('486314914801caffe2'), 'classifier table use changed')
    targets=[]
    for n in range(37):
        entry=table+4*n
        target=table+struct.unpack('<i',image.read(entry,4))[0]
        require(CLASSIFIER <= target < CLASS_END,'length table target outside classifier')
        targets.append(target)
    return table, targets


def classify(image, key, targets=None):
    """Evaluate only the pinned byte-compare decision grammar on synthetic keys."""
    if targets is None:
        _, targets=classifier_table(image)
    if not 3 <= len(key) <= 39:
        return 14
    pc=targets[len(key)-3]
    eq=None
    tag=None
    first=None
    for _ in range(512):
        require(CLASSIFIER <= pc < CLASS_END, 'classifier branch outside extent')
        a=image.read(pc,2)
        if a == b'\x80\x3e':
            c=image.read(pc,3)[2]; eq=key[0]==c; pc+=3
        elif a == b'\x80\x7e':
            off,c=image.read(pc,4)[2:4]
            require(off < len(key), 'field compare exceeds key')
            eq=key[off]==c; pc+=4
        elif a == b'\x0f\xb6':
            require(image.read(pc,3)==b'\x0f\xb6\x0e','unsupported classifier load')
            first=key[0]; pc+=3
        elif a == b'\x83\xf9':
            require(first is not None,'compare without classifier load')
            eq=first==image.read(pc,3)[2]; pc+=3
        elif a[0] == 0xb1:
            tag=a[1]; pc+=2
        elif a == b'\x31\xc9':
            tag=0; pc+=2
        elif a[0] in (0x74,0x75) or (a[0] == 0x0f and a[1] in (0x84,0x85)):
            require(eq is not None,'conditional branch without comparison')
            target=branch(image,pc)
            take=eq if a[0] == 0x74 or a == b'\x0f\x84' else not eq
            pc=target if take else pc+(6 if a[0]==0x0f else 2)
        elif a[0] in (0xeb,0xe9):
            pc=branch(image,pc)
        elif image.read(pc,7) == bytes.fromhex('884801c60009c3'):
            require(tag is not None,'classifier return without tag')
            return tag
        else:
            raise EvidenceError('unsupported classifier instruction at '+hex(pc))
    raise EvidenceError('classifier decision exceeds step limit')


def fde_records(image):
    secs,index=unwind_index(image.data)
    _, fdes=eh_frame_records(image.data,secs)
    by_start={}
    for f in fdes:
        if f['start'] in FUNCTIONS:
            require(f['start'] not in by_start,'duplicate selected FDE start')
            by_start[f['start']]=f
    idx={r['start']:r for r in index if r['start'] in FUNCTIONS}
    require(set(by_start)==set(FUNCTIONS)==set(idx),'selected FDE missing')
    out=[]
    for start in sorted(FUNCTIONS):
        f=by_start[start]
        require(idx[start]['fde']==f['fde'] and start < f['end'] <= idx[start]['next_index_upper_bound'],
                'selected FDE/index disagreement')
        raw=image.read(start,f['end']-start)
        require(hashlib.sha256(raw).hexdigest()==BODY_SHA256[start], 'selected FDE body changed')
        out.append({'start':hex(start),'end_exclusive':hex(f['end']),'fde':hex(f['fde']),
                    'cie':hex(f['cie']),'size':len(raw),'body_sha256':hashlib.sha256(raw).hexdigest()})
    return out


def duplicate(image, va):
    require(image.read(va,2)==b'\x0f\x85','expected duplicate JNE')
    diagnostic=branch(image,va)
    target=rip(image,diagnostic)
    # diagnostic LEA, stack store, then mov qword [rsp+disp32], imm32
    raw=image.read(diagnostic+15,12)
    require(raw[:4]==bytes.fromhex('48c78424'),'unexpected duplicate diagnostic length')
    length=struct.unpack_from('<I',raw,8)[0]
    require(0 < length < 64,'invalid duplicate label length')
    return diagnostic,image.read(target,length).decode('ascii')


def missing(image, va):
    target=rip(image,va)
    # Both stack layouts have mov qword [rsp+disp32], imm32 after the LEA.
    raw=image.read(va+15,12)
    require(raw[:4]==bytes.fromhex('48c78424'),'unexpected missing diagnostic length')
    length=struct.unpack_from('<I',raw,8)[0]
    require(0 < length < 64,'invalid missing label length')
    return image.read(target,length).decode('ascii')


def template_site(image, start, expected):
    # Search a narrow inspected diagnostic block for its exact RIP LEA; the
    # complete owner hash and the field-label LEA are checked independently.
    matches=[]
    for delta in range(100):
        va=start+delta
        if image.read(va,3)==bytes.fromhex('488d35') and rip(image,va)==expected:
            matches.append(va)
    require(len(matches)==1,'diagnostic template reference missing or ambiguous')
    return matches[0]


def json_diagnostics(image, names):
    """Find selected field labels with an adjacent diagnostic template.

    The scan is restricted to one authenticated FDE and matches the two
    inspected RIP-LEA/stack pointer/length layouts. It is not a disassembly
    or a whole-binary string-xref census.
    """
    start,end=0x1c39a20,0x1c3df96
    body=image.read(start,end-start)
    found={}
    pos=0
    while True:
        pos=body.find(bytes.fromhex('488d05'),pos)
        if pos<0:
            break
        va=start+pos
        pos+=1
        try:
            pointer=rip(image,va)
            tail=image.read(va+7,20)
            if tail[:4]==bytes.fromhex('48898424') and tail[8:12]==bytes.fromhex('48c78424'):
                count=struct.unpack_from('<I',tail,16)[0]
            elif tail[:4]==bytes.fromhex('48894424') and tail[5:9]==bytes.fromhex('48c74424'):
                count=struct.unpack_from('<I',tail,10)[0]
            else:
                continue
            if not 0<count<64:
                continue
            label=image.read(pointer,count).decode('ascii')
            if label not in names:
                continue
            templates=[]
            for delta in range(100):
                site=va+delta
                if image.read(site,3)==bytes.fromhex('488d3d'):
                    dst=rip(image,site)
                    if dst in (0x1df8f3,0x1e0fd5):
                        templates.append((site,'missing' if dst==0x1df8f3 else 'duplicate'))
            require(len(templates)==1,'JSON field has ambiguous diagnostic template')
            site,kind=templates[0]
            require((label,kind) not in found,'duplicate JSON diagnostic candidate')
            found[label,kind]={'field':label,'kind':kind,'label_site':hex(va),
                               'label_va':hex(pointer),'template_site':hex(site)}
        except (UnicodeDecodeError,struct.error):
            continue
    required={(n,'duplicate') for n in names}|{(n,'missing') for n in names if n!='ta2'}
    require(set(found)==required,'JSON diagnostic set changed')
    return [found[n,k] for n in names for k in ('missing','duplicate') if (n,k) in found]


def extract(image):
    funcs=fde_records(image)
    table,targets=classifier_table(image)
    require(image.read(SELECTOR+7,9)==bytes.fromhex('486304814801c8ffe0'), 'reader dispatch changed')
    require(call(image,0x17902a2)==CLASSIFIER,'reader field classifier call changed')
    jump_table=rip(image,SELECTOR)
    dispatch=[]
    for tag in range(15):
        dest=jump_table+struct.unpack('<i',image.read(jump_table+tag*4,4))[0]
        require(0x178bea0<=dest<0x1791ccc,'reader case outside FDE')
        dispatch.append(dest)
    require(image.read(0x1c39ac2,3)==bytes.fromhex('83ff5b') and
            image.read(0x1c39acb,3)==bytes.fromhex('83ff7b'), 'JSON entry markers changed')
    json_array_target=branch(image,0x1c39ac5)
    json_nonmap_target=branch(image,0x1c39ace)
    require(image.read(0x2390b7f,4)==bytes.fromhex('807a0b00'), 'compact mode gate changed')
    require(image.read(0x2390b8d,5)==bytes.fromhex('ba0e000000') and
            image.read(0x2390bc3,5)==bytes.fromhex('ba0e000000'), 'field count changed')
    require(branch(image,0x2390b83)==0x2390bbb,'compact mode branch changed')
    require(call(image,0x2390b92)==0x25a8f80 and call(image,0x2390bc8)==0x25a9bd0,
            'compact container callees changed')
    require(image.read(0x2390b9c,4)==bytes.fromhex('4883f802') and
            branch(image,0x2390ba0)==0x2390bd8 and
            image.read(0x2390bd2,4)==bytes.fromhex('4883f802') and
            branch(image,0x2390bd6)==0x2390ba2, 'compact header result gate changed')
    require(all(image.read(a,5)==bytes.fromhex('41807f0b01') for a in
                (0x2390bd8,0x2390c1c,0x2390c6c,0x2390cb0,0x2390cfc)),
            'compact field-name gates changed')
    require(b'missing field `' in image.read(0x1df8f3,16),'missing-field template changed')
    require(b'duplicate field `' in image.read(0x1e0fd5,18),'duplicate-field template changed')
    rows=[]
    for i,(cn,co,cc,jn,jo,jc,db,ms) in enumerate(ROWS):
        cname,cp,cl=name(image,cn)
        jname,jp,jl=name(image,jn)
        require(cname==jname,'writers disagree on name')
        coff,joff=offset(image,co),offset(image,jo)
        require(coff==joff,'writers disagree on object offset')
        tag=classify(image,cname.encode(),targets)
        require(tag==i,'classifier/tag mismatch')
        require(dispatch[tag] <= db < dispatch[tag]+64, 'reader case does not contain duplicate branch')
        require(call(image,cc)==COMPACT_CALLEES[i] and call(image,jc)==JSON_CALLEES[i], 'field call target changed')
        require(image.read(cc+5,5)==bytes.fromhex('4c39642408'),'compact result check changed')
        require(image.read(jc+5,3)==bytes.fromhex('4885c0'),'JSON result check changed')
        cf=branch(image,cc+10)
        jf=branch(image,jc+8)
        require(cf == (0x2390e77 if i<5 else 0x2390ea1), 'compact failure exit changed')
        require(jf == 0x2390aa6, 'JSON failure exit changed')
        diag,dname=duplicate(image,db)
        require(cname==dname,'duplicate label differs')
        dup_template=template_site(image,diag,0x1e0fd5)
        gate = None
        mode = None
        missing_template = None
        if ms is not None:
            require(missing(image,ms)==cname,'missing label differs')
            missing_template=template_site(image,ms,0x1df8f3)
            gate, mode=MISSING_GATES[i]
            if mode == 'direct':
                require(branch(image,gate)==ms,'missing branch changed')
            elif mode == 'fallthrough':
                require(image.read(gate,2)==b'\x0f\x85' and 0 <= ms-(gate+6) < 20,
                        'missing fallthrough changed')
            else:
                require(branch(image,0x178fc2a)==ms and image.read(gate,2)==b'\x0f\x85',
                        'missing jump changed')
        rows.append({'tag':tag,'field':cname,'object_offset':coff,
          'compact_name_site':hex(cn),'compact_name_va':hex(cp),'compact_length_site':hex(cl),
          'compact_object_site':hex(co),'compact_call_site':hex(cc),'compact_callee':hex(call(image,cc)),
          'json_name_site':hex(jn),'json_name_va':hex(jp),'json_length_site':hex(jl),
          'json_object_site':hex(jo),'json_call_site':hex(jc),'json_callee':hex(call(image,jc)),
          'compact_failure_target':hex(cf),'json_failure_target':hex(jf),
          'reader_case':hex(dispatch[i]),'duplicate_branch':hex(db),'duplicate_label':hex(diag),
          'duplicate_template_site':hex(dup_template),
          'missing_template_site':hex(missing_template) if missing_template else None,
          'missing_label':hex(ms) if ms else None,'missing_gate':hex(gate) if gate else None,
          'missing_gate_target':hex(branch(image,gate)) if gate else None,'missing_mode':mode})
    require(len({r['field'] for r in rows})==len(rows),'duplicate field labels')
    json_labels=json_diagnostics(image,[r['field'] for r in rows])
    # Unknown names have a distinct dispatch arm and a checked helper result.
    require(dispatch[14]==0x17907a3 and call(image,0x17907b3)==0x19682d0,
            'unknown-name handler changed')
    require(image.read(0x17907c1,4)==bytes.fromhex('4180fc09') and
            branch(image,0x17907c5)==0x1790ecd,'unknown-name result gate changed')
    # The JSON map route uses one presence slot for both the duplicate and
    # omission checks; match the two branch encodings and the zero path.
    require(image.read(0x1c3a0f0,9)==bytes.fromhex('4883bc24b000000000') and
            branch(image,0x1c3a0f9)==0x1c3c810,'JSON ta2 duplicate gate changed')
    require(image.read(0x1c3c49a,8)==bytes.fromhex('80bc24b000000000') and
            branch(image,0x1c3c4a2)==0x1c3c594 and
            image.read(0x1c3c594,4)==bytes.fromhex('31c931d2'),
            'JSON ta2 omission gate changed')
    require(image.read(0x1c3c714,8)==bytes.fromhex('48898c2470080000') and
            image.read(0x1c3c724,8)==bytes.fromhex('4889942480080000'),
            'JSON ta2 assembled-word stores changed')
    # Guard against confusing the default path with the error path.
    require(image.read(0x178f729,8)==bytes.fromhex('80bc24e000000000'),'default presence test changed')
    require(branch(image,0x178f731)==0x178f89c and image.read(0x178f89c,4)==bytes.fromhex('31c931d2'),
            'default zero path changed')
    require(image.read(0x178fa75,8)==bytes.fromhex('48898c24300c0000') and
            image.read(0x178fa85,8)==bytes.fromhex('48899424400c0000'),
            'compact ta2 assembled-word stores changed')
    cases=[]
    for row in rows:
        key=row['field'].encode('ascii')
        cases.append((row['field'],'exact',key.hex(),classify(image,key,targets)))
        for j in range(len(key)):
            alt=key[:j]+bytes([key[j]^1])+key[j+1:]
            cases.append((row['field'],'bit-flip-'+str(j),alt.hex(),classify(image,alt,targets)))
        cases.append((row['field'],'truncated',key[:-1].hex(),classify(image,key[:-1],targets)))
        cases.append((row['field'],'extended',(key+b'_').hex(),classify(image,key+b'_',targets)))
    require(all(t==int(next(r['tag'] for r in rows if r['field']==n)) if k=='exact' else t==14
                for n,k,_,t in cases),'classifier negative case unexpectedly recognized')
    raw_windows=[]
    sites=set([CLASSIFIER,SELECTOR,0x2390b7f,0x2390b8d,0x2390bc3,0x2390b9c,0x2390bd2,0x178f729,0x178f89c,
               0x1c39ac2,0x1c39acb,0x1df8f3,0x1e0fd5,0x17902a2,0x17907b3,0x17907c1,
               0x1c3a0f0,0x1c3c49a,0x1c3c594,0x1c3c714,0x1c3c724,0x178fa75,0x178fa85])
    for cn,co,cc,jn,jo,jc,db,ms in ROWS:
        sites.update((cn,co,cc,jn,jo,jc,db))
        if ms is not None: sites.add(ms)
    sites.update(x[0] for x in MISSING_GATES)
    sites.update(int(x['label_site'],16) for x in json_labels)
    for va in sorted(sites): raw_windows.append(image.window(va,24))
    return {'target_sha256':DIGEST,'coordinate_system':'unrelocated ELF virtual addresses',
      'scope':'selected FDE extents and instruction windows; not a function census',
      'functions':funcs,'fields':rows,'json_diagnostics':json_labels,'classifier_length_table':hex(table),
      'classifier_length_targets':[{'length':n+3,'target':hex(x)} for n,x in enumerate(targets)],
      'reader_dispatch_table':hex(jump_table),'reader_dispatch':[{'tag':n,'target':hex(x)} for n,x in enumerate(dispatch)],
      'default_branch':{'site':hex(0x178f731),'target':hex(branch(image,0x178f731))},
      'compact_header':{'named_count_site':hex(0x2390b8d),
                        'named_callee':hex(call(image,0x2390b92)),
                        'named_success_target':hex(branch(image,0x2390ba0)),
                        'positional_count_site':hex(0x2390bc3),
                        'positional_callee':hex(call(image,0x2390bc8)),
                        'positional_failure_target':hex(branch(image,0x2390bd6))},
      'json_entry':{'array_target':hex(json_array_target),'non_map_target':hex(json_nonmap_target)},
      'json_ta2':{'duplicate_branch':hex(0x1c3a0f9),
                  'duplicate_target':hex(branch(image,0x1c3a0f9)),
                  'missing_branch':hex(0x1c3c4a2),
                  'missing_target':hex(branch(image,0x1c3c4a2))},
      'unknown_field':{'case':hex(dispatch[14]),'child_call':hex(0x17907b3),
                       'child_target':hex(call(image,0x17907b3)),
                       'success_target':hex(branch(image,0x17907c5))},
      'raw_windows':raw_windows},cases


def generate(image,out):
    evidence,cases=extract(image)
    out.mkdir(parents=True,exist_ok=True)
    (out/'evidence.json').write_text(json.dumps(evidence,indent=2,ensure_ascii=True)+'\n',encoding='ascii')
    cols=('tag','field','object_offset','compact_call_site','compact_callee','json_call_site','json_callee',
          'reader_case','duplicate_branch','duplicate_label','missing_gate','missing_gate_target','missing_mode','missing_label')
    with (out/'fields.tsv').open('w',encoding='ascii',newline='') as f:
        w=csv.writer(f,delimiter='\t',lineterminator='\n');w.writerow(cols)
        for row in evidence['fields']:
            w.writerow([hex(row[c]) if c=='object_offset' else (row[c] if row[c] is not None else 'default') for c in cols])
    with (out/'json-diagnostics.tsv').open('w',encoding='ascii',newline='') as f:
        w=csv.writer(f,delimiter='\t',lineterminator='\n')
        cols=('field','kind','label_site','label_va','template_site');w.writerow(cols)
        for row in evidence['json_diagnostics']: w.writerow([row[c] for c in cols])
    with (out/'classifier-cases.tsv').open('w',encoding='ascii',newline='') as f:
        w=csv.writer(f,delimiter='\t',lineterminator='\n');w.writerow(('field','case','candidate_hex','result_tag'))
        w.writerows(cases)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',required=True,type=Path)
    args=ap.parse_args()
    data=BINARY.read_bytes()
    authenticate(data)
    generate(Image(data),args.out)

if __name__=='__main__':
    main()
