#!/usr/bin/env python3
"""Extract a bounded state-context codec from the authenticated #94 ELF."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
# FDE body hashes bind the selected ranges, not their source-level identities.
FUNCTIONS = {
 0x18571b0: (0x185976a, '59ed3acd24876a19f63d6bc9381e2c138f7de4b602544ba3fca74eb9eabe9861', 'compact reader'),
 0x1cbf300: (0x1cc09ee, '931d337e598f73c06355e1722f05c27957d37f91e972ef2cdd8d32185472cc4c', 'JSON reader'),
 0x2218b30: (0x2218e5c, '85e59e9366b3ef74a315771921b8dedc7ddcfa6fa9c59815916c747c29b71d72', 'JSON writer'),
 0x2218e60: (0x22192c9, '2c19c80574be36a651d698186c582d0fa16f3b0110e3d1e0c0de4479ed189d2a', 'compact writer'),
 0x21f6110: (0x21f6347, '36dd55f57a1ea70f36b887c7b6540ecd79fe261f21213696195867fa48785944', 'JSON hardfork writer'),
 0x21e4170: (0x21e4663, '74645f0067b473f1fa7135d8255ae808234a7b9d0f8c4ceb97cf71cbde74234a', 'compact key classifier'),
 0x21e4870: (0x21e4a6a, '82b7cb9e3fd36d6206ecbd6090978f43be444a580d7bbe68793b998176b8720a', 'JSON key classifier'),
 0x22bdd40: (0x22bddd1, 'd0cf99663d810fbfe175abcda0c586528030937d9285d14dcab42052b48d1711', 'compact nonce writer'),
 0x22bdee0: (0x22bdf3d, '5e1b59eff28aa086f5498c41b413ee00f3c5b4e218572711e71bed296ef17ed2', 'compact timestamp field writer'),
 0x1e4fc10: (0x1e4fcbc, '275bd67ef2c03e171907f337f43cd15777b99f7317e68d0cfca4d82b19cb4242', 'timestamp type gate'),
 0x1dfca40: (0x1dfcb91, '53404c658c477544f6921af8516b6d915760d0a5231b3e23a60fc690e656da20', 'timestamp formatting and string writer'),
}
# Site, immediate-length site, source-offset instruction, expected offset.
FIELDS = [
 (0x2218ee4,0x2218eeb,0x2218ed9,0x10),
 (0x2218f28,0x2218f2f,0x2218f90,0x18),
 (0x2219028,0x221902f,0x221901d,0x28),
 (0x221906c,0x2219073,0x221908c,0x08),
 (0x2219106,0x221910d,0x2219124,0x30),
 (0x2219148,0x2219154,0x2219144,0x60),
 (0x2219170,0x221917c,0x221916c,0x6c),
 (0x2219198,0x22191a4,0x2219194,0x38),
 (0x22191c0,0x22191cc,0x22191bc,0x40),
 (0x22191e8,0x22191f4,0x22191e4,0x48),
 (0x22bdd5e,0x22bdd68,0x221920c,0x50),
 (0x221922c,0x2219238,0x2219228,0x78),
 (0x2219250,0x221925c,0x221924c,0x58),
]
# Selected reader edges: duplicates and end-of-map missing-field routes.
DUP_BRANCHES = [0x185906c,0x18592aa,0x18591c9,0x1859214,0x18590e8,
                0x18592fe,0x185937e,0x185925f,0x185940c,0x185917e,
                0x18593c4,0x18590b2,0x1859133]
MISSING_BRANCHES = [0x1858504,0x1858554,0x1858584,0x1858592,0x18585a0,0x18585ae,
                    0x1cc0014,0x1cc0022,0x1cc0059,0x1cc0064,0x1cc0072,0x1cc0080]


def check_digest(data, expected=DIGEST):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('input digest mismatch')


def check_body(body, expected):
    if hashlib.sha256(body).hexdigest() != expected:
        raise ValueError('body hash mismatch')


def read_va(data, secs, va, size):
    if size < 0 or va < 0:
        raise ValueError('invalid range')
    found = [s for s in secs if s['type'] != 8 and s['address'] <= va
             and va + size <= s['address'] + s['size'] and (size or va < s['address'] + s['size'])]
    if len(found) != 1:
        raise ValueError('unmapped or ambiguous file-backed range')
    s = found[0]
    off = s['offset'] + va - s['address']
    if off + size > len(data):
        raise ValueError('range outside file')
    return data[off:off + size], off


def relative(data, secs, va, prefix):
    b, _ = read_va(data, secs, va, len(prefix) + 4)
    if b[:len(prefix)] != prefix:
        raise ValueError('unexpected relative instruction')
    return va + len(b) + struct.unpack_from('<i', b, len(prefix))[0]


def branch(data, secs, va):
    b, _ = read_va(data, secs, va, 6)
    if b[0] != 0x0f or b[1] not in (0x84, 0x85):
        raise ValueError('unexpected conditional branch')
    return {'site': hex(va), 'bytes': b.hex(), 'condition': 'equal' if b[1] == 0x84 else 'not-equal',
            'target': hex(va + 6 + struct.unpack_from('<i', b, 2)[0])}


def classify(image, base, table, value):
    """Evaluate only the fixed byte-comparison classifier, not arbitrary x86."""
    if not 3 <= len(value) <= 16:
        return 13
    def get(va, n):
        i = va - base
        if i < 0 or i + n > len(image):
            raise ValueError('classifier branch outside image')
        return image[i:i+n]
    ix = len(value) - 3
    if len(table) != 56:
        raise ValueError('bad classifier table')
    pc = 0x3d4114 + struct.unpack_from('<i', table, ix * 4)[0]
    cl = None
    equal = False
    for _ in range(200):
        b = get(pc, 1)[0]
        if b == 0x80:
            op = get(pc, 2)[1]
            if op == 0x3e:
                imm = get(pc, 3)[2]; off = 0; pc += 3
            elif op == 0x7e:
                raw = get(pc, 4); off, imm = raw[2], raw[3]; pc += 4
            else:
                raise ValueError('unsupported byte comparison')
            if off >= len(value):
                raise ValueError('classifier read beyond input')
            equal = value[off] == imm
        elif b == 0x0f and get(pc, 3)[:3] in (b'\x0f\xb6\x0e', b'\x0f\xb6\x4e'):
            op = get(pc, 3)
            off = 0 if op[2] == 0x0e else get(pc, 4)[3]
            if off >= len(value): raise ValueError('classifier read beyond input')
            cl = value[off]; pc += 3 if op[2] == 0x0e else 4
        elif b == 0x83 and get(pc, 2) == b'\x83\xf9':
            equal = cl == get(pc, 3)[2]; pc += 3
        elif b == 0xb1:
            cl = get(pc, 2)[1]; pc += 2
        elif get(pc, 2) == b'\x31\xc9':
            cl = 0; pc += 2
        elif b == 0x0f and get(pc, 2)[1] in (0x84,0x85):
            p = get(pc, 6); take = equal if p[1] == 0x84 else not equal
            pc = pc + 6 + (struct.unpack_from('<i', p, 2)[0] if take else 0)
        elif b in (0x74,0x75):
            p = get(pc, 2); take = equal if b == 0x74 else not equal
            pc = pc + 2 + (struct.unpack_from('<b',p,1)[0] if take else 0)
        elif b in (0xe9,0xeb):
            n = 5 if b == 0xe9 else 2; p = get(pc,n)
            pc = pc + n + struct.unpack_from('<i' if n == 5 else '<b',p,1)[0]
        elif get(pc, 7) == b'\x88\x48\x01\xc6\x00\x09\xc3':
            if cl is None: raise ValueError('uninitialized classifier result')
            return cl
        else:
            raise ValueError('unsupported classifier instruction')
    raise ValueError('classifier step limit')


def build(data):
    check_digest(data)
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {}
    for f in fdes:
        by_start.setdefault(f['start'], []).append(f)
    funcs = []
    for start, (end, digest, role) in FUNCTIONS.items():
        fs = by_start.get(start, [])
        if len(fs) != 1 or fs[0]['end'] != end:
            raise ValueError('unexpected FDE extent')
        body, off = read_va(data, secs, start, end-start)
        check_body(body, digest)
        funcs.append({'role':role,'start':hex(start),'end_exclusive':hex(end),
                      'fde':hex(fs[0]['fde']),'file_offset':hex(off),'sha256':digest})
    image,_ = read_va(data,secs,0x21e4170,0x21e4663-0x21e4170)
    if relative(data,secs,0x21e4181,b'\x48\x8d\x0d') != 0x3d4114:
        raise ValueError('classifier table reference mismatch')
    table,_ = read_va(data,secs,0x3d4114,56)
    counts=[]
    for site in (0x2218e8e,0x2218ec4,0x2218f55,0x2218f77):
        imm,_=read_va(data,secs,site,5)
        if imm[0] != 0xba: raise ValueError('unexpected container count instruction')
        counts.append({'site':hex(site),'bytes':imm.hex(),'count':struct.unpack_from('<I',imm,1)[0]})
    if [x['count'] for x in counts] != [13,13,2,2]:
        raise ValueError('unexpected container counts')
    fields=[]
    for index, (site, length_site, offset_site, offset) in enumerate(FIELDS):
        prefix=read_va(data,secs,site,3)[0]
        if prefix not in (b'\x48\x8d\x35',b'\x48\x8d\x15',b'\x48\x8d\x05'):
            raise ValueError('unexpected field pointer')
        target=relative(data,secs,site,prefix)
        lb,_=read_va(data,secs,length_site,5)
        if lb[0] not in (0xb9,0xba): raise ValueError('unexpected field length')
        length=struct.unpack_from('<I',lb,1)[0]
        name_bytes,_=read_va(data,secs,target,length)
        name=name_bytes.decode('ascii')
        ins,_=read_va(data,secs,offset_site,4)
        if ins[-1] != offset: raise ValueError('unexpected field offset')
        if classify(image,0x21e4170,table,name_bytes) != index:
            raise ValueError('writer and classifier disagree')
        fields.append({'index':index,'name':name,'name_va':hex(target),'name_site':hex(site),
                       'length':length,'value_offset':hex(offset),'offset_site':hex(offset_site),
                       'offset_bytes':ins.hex()})
    alias_code,_=read_va(data,secs,0x21e4a14,0x20)
    if alias_code[:2] != b'\x48\xb9' or alias_code[13:15] != b'\x48\xba' or alias_code[27:31] != b'\x48\x09\xca\x74':
        raise ValueError('unexpected JSON alias comparisons')
    first,second=alias_code[2:10],alias_code[15:23]
    if first[7:] != second[:1] or alias_code[31] != 9:
        raise ValueError('inconsistent JSON alias comparisons')
    alias=first+second[1:]
    if classify(image,0x21e4170,table,alias)!=4:
        raise ValueError('alias predicate changed')
    # Check every one-byte change, not merely a string equality model.
    controls=0
    for field in fields + [{'name':alias.decode(),'index':4}]:
        value=field['name'].encode('ascii')
        for i, old in enumerate(value):
            for replacement in range(256):
                if replacement == old: continue
                probe=value[:i]+bytes([replacement])+value[i+1:]
                if classify(image,0x21e4170,table,probe)==field['index']:
                    raise ValueError('classifier accepts changed key')
                controls+=1
    if relative(data,secs,0x185904b,b'\x48\x8d\x0d') != 0x306eb8:
        raise ValueError('reader table reference mismatch')
    dt,_=read_va(data,secs,0x306eb8,14*4)
    dispatch=[]
    for index in range(14):
        dst=0x306eb8+struct.unpack_from('<i',dt,index*4)[0]
        if not FUNCTIONS[0x18571b0][0] > dst >= 0x18571b0:
            raise ValueError('reader dispatch outside extent')
        dispatch.append({'index':index,'target':hex(dst),'field':fields[index]['name'] if index<13 else 'unknown'})
    duplicates=[branch(data,secs,a) for a in DUP_BRANCHES]
    missing=[branch(data,secs,a) for a in MISSING_BRANCHES]
    missing_leas=[0x1857742,0x1858420,0x1858676,0x18586f7,0x1858772,0x18587e8,
                  0x1cc0265,0x1cc028b,0x1cc02a2,0x1cc02b9,0x1cc02d0,0x1cc02d9]
    for row, site, field_index in zip(missing,missing_leas,[0,2,5,6,7,8]*2):
        addr=relative(data,secs,site,b'\x48\x8d\x05')
        expected=fields[field_index]['name'].encode('ascii')
        raw,_=read_va(data,secs,addr,len(expected))
        if raw != expected: raise ValueError('missing-field name mismatch')
        row.update({'name_site':hex(site),'name_va':hex(addr),'field':raw.decode('ascii')})
    contextual_calls=[]
    for site, expected in [(0x17362e0,0x18571b0),(0x1bf0a1d,0x1cbf300),
                           (0x2755813,0x2218b30),(0x28194d0,0x2218e60),
                           (0x1858cbc,0x21e4170),(0x1cbf550,0x21e4870)]:
        target=relative(data,secs,site,b'\xe8')
        if target != expected: raise ValueError('context call target mismatch')
        raw,off=read_va(data,secs,site,5)
        contextual_calls.append({'site':hex(site),'target':hex(target),'file_offset':hex(off),'bytes':raw.hex()})
    time_edges=[]
    for site, opcode, expected in [(0x221915c,b'\xe8',0x22bdee0),
                                   (0x2219184,b'\xe8',0x22bdee0),
                                   (0x22bdf22,b'\xe9',0x1e4fc10),
                                   (0x1e4fc51,b'\xe8',0x1dfca40)]:
        target=relative(data,secs,site,opcode)
        if target != expected: raise ValueError('timestamp edge mismatch')
        raw,_=read_va(data,secs,site,5)
        time_edges.append({'site':hex(site),'target':hex(target),'bytes':raw.hex()})
    type_va=relative(data,secs,0x22bdf16,b'\x48\x8d\x15')
    type_name,_=read_va(data,secs,type_va,4)
    separator,_=read_va(data,secs,0x1dfcab1,5)
    if type_name != b'Time' or separator != b'\xbe\x54\x00\x00\x00':
        raise ValueError('timestamp format mismatch')
    parent_name_va=relative(data,secs,0x27557c1,b'\x48\x8d\x35')
    parent_name,_=read_va(data,secs,parent_name_va,3)
    if parent_name != b'ctx': raise ValueError('unexpected parent field')
    missing_template,_=read_va(data,secs,0x1df8f3,16)
    if missing_template != b'\x0fmissing field `': raise ValueError('missing-field template changed')
    # A selection of fixed, independently addressable code windows, including
    # the JSON alias, writer header/mode, and reader's option/default decisions.
    windows=[(0x2218e80,0x56),(0x2218f46,0x4a),(0x2219086,0x34),
             (0x221920c,0x60),(0x22bdd58,0x42),(0x21e4a14,0x30),
             (0x1857821,0xd4),(0x185849e,0x11a),(0x1cc000c,0xe5),
             (0x1859046,0x1b),(0x22bdee0,0x3d),(0x1e4fc1a,0x4d),
             (0x1dfca8b,0x62)]
    pins=[]
    for va,n in windows:
        b,off=read_va(data,secs,va,n)
        pins.append({'va':hex(va),'file_offset':hex(off),'bytes':b.hex()})
    return {'binary_sha256':DIGEST,'coordinate':'unrelocated ELF virtual address; end exclusive',
            'functions':funcs,'container_counts':counts,'fields':fields,'classifier_alias':{'name':alias.decode(),'index':4,'json_compare_va':hex(0x21e4a14),'json_compare_bytes':alias_code.hex()},
            'classifier_table_va':hex(0x3d4114),'reader_table_va':hex(0x306eb8),
            'reader_dispatch':dispatch,'duplicate_branches':duplicates,'missing_branches':missing,
            'single_byte_substitution_controls':controls,'contextual_calls':contextual_calls,
            'parent_field':{'name':parent_name.decode(),'name_va':hex(parent_name_va),'site':hex(0x27557c1)},
            'timestamp':{'type_name':type_name.decode(),'type_name_va':hex(type_va),
                         'separator_immediate':separator.hex(),'edges':time_edges},
            'missing_field_template':{'va':hex(0x1df8f3),'bytes':missing_template.hex()},'windows':pins,
            'limits':'Selected static paths only; FDE ranges are unwind extents. No node execution, snapshot file, whole codec or cross-release equivalence is claimed.'}


def emit(out, record):
    out.mkdir(parents=True,exist_ok=True)
    (out/'evidence.json').write_text(json.dumps(record,indent=2,ensure_ascii=True)+'\n',encoding='utf-8')
    buff=io.StringIO(newline='')
    w=csv.writer(buff,delimiter='\t',lineterminator='\n')
    w.writerow(['index','field','field_va','writer_site','value_offset','reader_arm'])
    for x in record['fields']:
        w.writerow([x['index'],x['name'],x['name_va'],x['name_site'],x['value_offset'],record['reader_dispatch'][x['index']]['target']])
    (out/'fields.tsv').write_text(buff.getvalue(),encoding='utf-8')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',required=True,type=Path)
    a=p.parse_args()
    emit(a.out,build(BINARY.read_bytes()))

if __name__=='__main__':
    main()
