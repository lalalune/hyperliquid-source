#!/usr/bin/env python3
"""Independent byte-interval peer check; no oracle/repository-parser imports.

Usage: python3 -O verify_independent.py [repository_root]
Only static ELF parsing and newly authored Python value calculations are used.
No captured execution, instruction emulator, or Rust/native rerun.
"""
import collections
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import capstone
N=1<<64
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODIES = [(0x53cf560, bytes.fromhex('f30f1efa488b87a0010000c78708010000010000004885c07403c60000c3'), 2)]
CALLERS = [(85588544, 85591133, '2c4f691e6e65de9b138e2db0a67e985ed25fd2aebed8d469cf00533578f76769', 577, 85590412, 87881056), (85600592, 85605593, '747be80b2d988cbc711704767d2bf43e3dfdab8f05870a4e7cef4fe64dde88c8', 1076, 85605328, 87881056), (85798288, 85802409, 'a5d6ca338246398258ffe4c31cb4d298abe833f0e964aaadf61468aa27d32dfd', 826, 85802062, 87881056), (85847376, 85851065, 'ad9c5773a3a0994307149fd5e0918bfc59cf9aae5b22c6843107c58abbf0e176', 716, 85848717, 87881056), (87464656, 87472808, '1ee5cc957136409caf7892262e17fc83954737f9af7b4962eacce1dccb621c49', 1541, 87471372, 87881056), (87531184, 87547233, '0e3b2ad652bb2efc5a477a25d4f494512fb7fef9b03d735261c5d6e03ebc7654', 3053, 87544224, 87881056), (87884688, 87884877, '29a7b36ea5e16dc0ca247d5c8ac1ee8f9b3d6c592cbe236438ce6b8d7fa1a0e5', 50, 87884851, 87881056)]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def authenticate(raw):
    require(len(raw) == 91774280 and sha(raw) == TARGET, 'target identity')
    require(raw[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian')
    require(struct.unpack_from('<HH', raw, 16) == (3, 62), 'ET_DYN x86-64')
    phoff, shoff = struct.unpack_from('<QQ', raw, 32)
    phsize, phnum, shsize, shnum, strindex = struct.unpack_from('<5H', raw, 54)
    require(phsize == 56 and shsize == 64, 'ELF table record sizes')
    segments = [struct.unpack_from('<II6Q', raw, phoff+i*phsize) for i in range(phnum)]
    sections = [struct.unpack_from('<II4QII2Q', raw, shoff+i*shsize) for i in range(shnum)]
    st = sections[strindex]
    names = raw[st[4]:st[4]+st[5]]
    named = {names[s[0]:].split(b'\0', 1)[0].decode(): s for s in sections}
    def mapped(address, size):
        matches = [s for s in segments if s[0] == 1 and s[3] <= address and address+size <= s[3]+s[5]]
        require(len(matches) == 1, 'unique file-backed PT_LOAD')
        s = matches[0]
        offset = s[2]+address-s[3]
        return raw[offset:offset+size], offset, s[1]
    records = []
    decoder = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    for index,(address,body,pad) in enumerate(BODIES):
        data,offset,flags = mapped(address,len(body)+pad)
        require(flags & 1 and data == body+b'\xcc'*pad,'complete executable body/padding')
        decoded = list(decoder.disasm(body,address))
        require(b''.join(i.bytes for i in decoded) == body and len(decoded) == 7, 'complete leaf decode')
        branches = [(i.address,int(i.op_str,16)) for i in decoded if i.mnemonic.startswith('j')]
        expected = [(0x53cf578,0x53cf57d)]
        require(branches == expected, 'leaf CFG and tail closure')
        require(not any(i.mnemonic == 'call' or 'rip' in i.op_str for i in decoded), 'closed leaf dependencies')
        records.append({'entry':address,'end':address+len(body),'body_sha256':sha(body),'file_offset':offset,'instructions':len(decoded),'edges':branches})
    for begin,end,digest,count,site,target in CALLERS:
        data,offset,flags = mapped(begin,end-begin)
        require(flags & 1 and sha(data) == digest, 'complete caller bytes')
        decoded = list(decoder.disasm(data,begin))
        require(b''.join(i.bytes for i in decoded) == data and len(decoded) == count, 'complete caller decode')
        lookup = {i.address:i for i in decoded}
        require(site in lookup and lookup[site].mnemonic == 'call' and lookup[site].op_str == hex(target), 'actual decoded caller boundary')
        records.append({'entry':begin,'end':end,'body_sha256':digest,'file_offset':offset,'instructions':len(decoded),'edges':[(site,target)]})
    # Parse all frame extents directly. All three actual CIEs specify 0x1b:
    # PC-relative signed-four-byte initial location; unsigned-four-byte range.
    frames = []
    cies = {}
    section = named['.eh_frame']
    pos, end = section[4], section[4]+section[5]
    while pos < end:
        length, = struct.unpack_from('<I', raw, pos)
        if not length:
            require(not any(raw[pos:end]), 'nonzero bytes after frame terminator')
            break
        require(length != 0xffffffff and pos+4+length <= end, 'bounded normal frame record')
        pointer, = struct.unpack_from('<I', raw, pos+4)
        va = section[3]+pos-section[4]
        if pointer == 0:
            value = raw[pos:pos+4+length]
            if value[8:12] == b'\x01zR\0':
                require(value[12:16] == b'\x01\x78\x10\x01' and value[16] == 0x1b, 'zR CIE encoding')
            else:
                require(value[8:15] == b'\x01zPLR\0\x01' and value[15:19] == b'\x78\x10\x07\x9b' and value[23:25] == b'\x1b\x1b', 'zPLR CIE encoding')
            cies[va] = sha(value)
        else:
            cie = va+4-pointer
            require(cie in cies, 'known backward CIE')
            relative, extent = struct.unpack_from('<iI', raw, pos+8)
            start = va+8+relative
            frames.append((start, start+extent, va, cie, raw[pos:pos+4+length].hex()))
        pos += length+4
    for record in records:
        address,end = record['entry'],record['end']
        overlaps = [f for f in frames if f[0] < end and address < f[1]]
        require(len(overlaps) == 1 and overlaps[0][:2] == (address,end), 'unique complete FDE')
        record['frame'] = overlaps[0]
        record['cie_sha256'] = cies[overlaps[0][3]]
    count = 0
    starts = {b[0] for b in BODIES}
    for section in sections:
        require(section[1] != 9, 'unsupported REL section')
        if section[1] != 4:
            continue
        require(section[9] == 24 and section[5] % 24 == 0, 'RELA shape')
        for off in range(section[4],section[4]+section[5],24):
            dst,info,add = struct.unpack_from('<QQq',raw,off)
            require(info & 0xffffffff in (1,6,7,8,18), 'known eight-byte relocation')
            require(add not in starts,'unexpected naming addend')
            for address,body,pad in BODIES:
                require(not (dst < address+len(body)+pad and address < dst+8),'leaf/padding writer')
            count += 1
    text = named['.text']
    code,_,flags = mapped(text[3],text[5])
    scans = {}
    for opcode,width in [(0xe8,5),(0xe9,5)]:
        sites = []
        pos = 0
        while (pos := code.find(bytes([opcode]),pos)) >= 0:
            if pos+width <= len(code):
                target = text[3]+pos+5+struct.unpack_from('<i',code,pos+1)[0]
                if target in starts:
                    sites.append((text[3]+pos,target))
            pos += 1
        expected = [(c[4],c[5]) for c in CALLERS] if opcode == 0xe8 else []
        require(sites == expected,'full text incoming candidate scan')
        scans[hex(opcode)] = sites
    return {'bodies_and_callers':records,'fde_count':len(frames),'cie_count':len(cies),'rela_count':count,'incoming_scans':scans,'capstone_version':capstone.__version__,'body_padding_writers':0,'naming_addends':0}


def derive(record):
    base,obj,rdx,length=struct.unpack_from('<4Q',record)
    data=record[32:]
    require(length<=512 and len(data)==512,'fixture shape')
    refusal=bytes(24)+data
    if base+length>N:return refusal,'image-wrap',{}
    source=(obj+416)&(N-1);flag=(obj+264)&(N-1)
    def interval(address,width):
        return address-base if base<=address and address+width<=base+length else None
    at=interval(source,8)
    if at is None:return refusal,'missing-source',{}
    # A direct byte snapshot is independent of all later mutable stores.
    pointer_bytes=bytes(data[at:at+8]);pointer=struct.unpack('<Q',pointer_bytes)[0]
    flag_at=interval(flag,4)
    if flag_at is None:return refusal,'missing-flag',{}
    clear_at=None
    if pointer!=0:
        clear_at=interval(pointer,1)
        if clear_at is None:return refusal,'missing-selected-clear',{}
    final=bytearray(data)
    final[flag_at:flag_at+4]=b'\x01\x00\x00\x00'
    if clear_at is not None:final[clear_at]=0
    facts={'pointer':pointer,'source':source,'flag':flag,'obj':obj,'rdx':rdx,
           'wrapped':obj+416>=N,'flag_alias':pointer!=0 and flag<=pointer<flag+4,
           'source_alias':pointer!=0 and source<=pointer<source+8,
           'null_zero_mapped_unchanged':pointer==0 and base==0 and length>0 and final[0]==data[0],
           'nonzero_low32_zero':pointer!=0 and pointer&0xffffffff==0,
           'source_modified':final[at:at+8]!=pointer_bytes,
           'final_flag':bytes(final[flag_at:flag_at+4]).hex()}
    return struct.pack('<Q',1)+pointer_bytes+record[16:24]+bytes(final),'admitted',facts


def display_check(packet,static):
    locks={0x51d344d:bytes.fromhex('f04881407000040000'),
           0x536a51a:bytes.fromhex('f00fab1481'),0x537b600:bytes.fromhex('f00fab1481')}
    decoded=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    all_splits={};records=[]
    target=(packet.parents[2]/'artifacts/node/94/hl-node').read_bytes()
    for i,body in enumerate(static['bodies_and_callers']):
        label='member0' if i==0 else 'caller'+str(i-1)
        start,end=body['entry'],body['end'];raw=target[body['file_offset']:body['file_offset']+end-start]
        machine=[(x.address,bytes(x.bytes))for x in decoded.disasm(raw,start)]
        for extension in ['gnu','llvm']:
            path=packet/(label+'.'+extension+'.txt');rows=[];cursor=start
            for line in path.read_text().splitlines():
                match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)',line)
                if match:
                    address=int(match[1],16);value=bytes.fromhex(match[2]);require(address==cursor,'display byte interval')
                    rows.append((address,value));cursor+=len(value)
            require(cursor==end and b''.join(b for _,b in rows)==raw,'complete display bytes')
            k=0
            for address,instruction in machine:
                pieces=[];where=address
                while where<address+len(instruction):
                    require(k<len(rows) and rows[k][0]==where,'instruction/display partition')
                    pieces.append(rows[k][1]);where+=len(rows[k][1]);k+=1
                require(where==address+len(instruction) and b''.join(pieces)==instruction,'instruction bytes')
                if len(pieces)>1:
                    require(extension=='llvm' and address in locks and instruction==locks[address]
                            and pieces==[b'\xf0',instruction[1:]],'unapproved display split')
                    all_splits[hex(address)]={'bytes':instruction.hex(),'file':path.name,'parts':[x.hex()for x in pieces]}
            require(k==len(rows),'display coverage')
            records.append({'file':path.name,'sha256':sha(path.read_bytes()),'bytes':len(raw),'instructions':len(machine)})
    require(set(all_splits)=={hex(x)for x in locks},'exact LOCK split census')
    return {'files':records,'exact_llvm_splits':all_splits}


def main():
    root=Path(sys.argv[1]).resolve()if len(sys.argv)>1 else Path(__file__).resolve().parents[4]
    packet=root/'research/work-items/RE-004-flag-set-clear-rust-94';source=root/'src/node94-flag-set-clear'
    source_hashes={name:sha((source/name).read_bytes())for name in ['lib.rs','input_only_driver.rs']}
    frozen=json.loads((packet/'frozen.json').read_bytes())
    for name,key in [('oracle.py','oracle_sha256_at_freeze'),('static.json','static_sha256_at_freeze')]:
        require(sha((packet/name).read_bytes())==frozen[key],'frozen '+name)
    inputs=gzip.decompress((packet/'inputs.bin.gz').read_bytes());expected=gzip.decompress((packet/'expected.bin.gz').read_bytes())
    require(sha(inputs)==frozen['inputs_sha256']and sha(expected)==frozen['expected_sha256'],'fixture identities')
    require(len(inputs)%544==0 and len(expected)==len(inputs)//544*536,'fixture dimensions')
    digest=hashlib.sha256();paths=collections.Counter();counts=collections.Counter();witnesses={}
    for index,offset in enumerate(range(0,len(inputs),544)):
        actual,path,facts=derive(inputs[offset:offset+544]);require(actual==expected[index*536:(index+1)*536],f'independent mismatch {index}')
        digest.update(actual);paths[path]+=1
        if path!='admitted':continue
        marks={'null_pointer':facts['pointer']==0,'clear_aliases_pointer':facts['source_alias'],
               'clear_aliases_flag':facts['flag_alias'],'zero_object':facts['obj']==0,
               'wrapped_object_fields':facts['wrapped'],'clear_changes_pointer_source':facts['source_modified'],
               'null_preserves_mapped_zero':facts['null_zero_mapped_unchanged'],
               'nonzero_pointer_low32_zero':facts['nonzero_low32_zero'],
               'rdx_high32_nonzero':facts['rdx']>=1<<32,'clear_flag_low_byte':facts['pointer']==facts['flag']}
        for label,yes in marks.items():
            if yes:
                counts[label]+=1;witnesses.setdefault(label,{'row_zero_based':index,**facts})
    require(paths['admitted']==frozen['admitted']==3842 and len(inputs)//544-paths['admitted']==frozen['refusals']==1281,'admission counts')
    for field in ['null_pointer','clear_aliases_pointer','clear_aliases_flag','zero_object','wrapped_object_fields']:
        require(counts[field]==frozen[field],'frozen coverage '+field)
    require(digest.hexdigest()==frozen['expected_sha256'],'complete independent output digest')
    static=authenticate((root/'artifacts/node/94/hl-node').read_bytes());displays=display_check(packet,static)
    retained=json.loads((packet/'static.json').read_bytes())
    for actual,saved in zip(static['bodies_and_callers'],retained['members']+retained['callers']):
        require((actual['entry'],actual['end'],actual['body_sha256'])==(saved['begin'],saved['end'],saved['body_sha256']),'retained body')
        f=actual['frame'];require(f[2]==saved['records']['fde']['va']and f[3]==saved['records']['cie']['va']and f[4]==saved['records']['fde']['hex'],'actual full FDE')
        require(actual['cie_sha256']==sha(bytes.fromhex(saved['records']['cie']['hex'])),'actual complete CIE')
    require(source_hashes=={name:sha((source/name).read_bytes())for name in source_hashes},'source changed during review')
    result={'source_sha256':source_hashes,'proof_sha256':sha((packet/'PROOF.md').read_bytes()),
            'peer_script_sha256':sha(Path(__file__).read_bytes()),'frozen_oracle_sha256':frozen['oracle_sha256_at_freeze'],
            'frozen_static_sha256':frozen['static_sha256_at_freeze'],'cases':len(inputs)//544,'paths':dict(paths),
            'counts':dict(counts),'witnesses':witnesses,'input_sha256':sha(inputs),'independent_expected_sha256':digest.hexdigest(),
            'static':static,'display_audit':displays,
            'preserved_initial_failure_sha256':sha((packet/'initial-static-boundary-failure.json.gz').read_bytes()),
            'review':'No blocker in complete Rust/proof/driver. Entry pointer snapshot and ordered four-byte then optional one-byte stores agree.',
            'limits':['No native/Rust rerun by peer','No captured execution or instruction emulator',
                      'No original partial-fault, ABI, flags, control-stack or concurrent/MMIO projection',
                      'Caller bytes/edges are context only; indirect references remain open']}
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':
    main()
