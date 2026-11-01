#!/usr/bin/env python3
"""Portable peer review: direct byte intervals, independent ELF/FDE/RELA parsing.

Usage: python3 -O verify_independent.py [repository_root]
Imports neither the frozen oracle nor repository ELF/FDE helpers. Does not run
Rust, captured code or an instruction emulator. All expectations are calculated
from the frozen inputs, not from the expected stream or source implementation.
"""
import collections
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys
import capstone

N = 1 << 64
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODIES = [(address,bytes.fromhex('f30f1efa488b8788070000488b80e8080000488b80')
           + struct.pack('<I',field) + bytes.fromhex('488906b801000000c3'),14)
          for address,field in [(0x514acc0,0xcd0),(0x514acf0,0xa70),(0x514ad20,0xa78)]]
CALLERS = []
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
        expected = []
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
    member,base,obj,dest,rdx,length = struct.unpack_from('<6Q',record)
    original = record[48:]
    require(member < 3 and length <= 1280 and len(original) == 1280,'fixture descriptor')
    refused = bytes(24)+original
    facts = {'member':member,'rdx':rdx}
    if base+length > N:
        return refused,'global-image-wrap',facts

    def interval(address):
        if address < base or address+8 > base+length:
            return None
        return address-base

    # Explicit reached byte intervals. The final payload is copied directly
    # from the entry bytes, with no numeric word re-encoding or address map.
    output = interval(dest)
    if output is None:
        return refused,'missing-destination',facts
    field = (0xcd0,0xa70,0xa78)[member]
    addresses = [(obj+0x788)&(N-1)]
    first_at = interval(addresses[0])
    if first_at is None:
        return refused,'missing-first',facts
    first = struct.unpack_from('<Q',original,first_at)[0]
    addresses.append((first+0x8e8)&(N-1))
    second_at = interval(addresses[1])
    if second_at is None:
        return refused,'missing-second',facts
    second = struct.unpack_from('<Q',original,second_at)[0]
    addresses.append((second+field)&(N-1))
    third_at = interval(addresses[2])
    if third_at is None:
        return refused,'missing-final',facts
    payload = bytes(original[third_at:third_at+8])
    updated = bytearray(original)
    updated[output:output+8] = payload
    facts.update(addresses=addresses,roots=[obj,first,second],destination=dest,
                 wraps=[obj+0x788>=N,first+0x8e8>=N,second+field>=N],
                 output_alias=any(dest<a+8 and a<dest+8 for a in addresses),
                 source_alias=any(a<b+8 and b<a+8 for i,a in enumerate(addresses) for b in addresses[i+1:]),
                 payload=payload.hex(),final_word=int.from_bytes(payload,'little'))
    # Full incoming RDX bytes are preserved verbatim, including their high32.
    return struct.pack('<QQ',1,1)+record[32:40]+bytes(updated),'admitted',facts


def main():
    root = Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path(__file__).resolve().parents[4]
    packet = root/'research/work-items/RE-004-three-hop-trio-rust-94'
    source = root/'src/node94-three-hop-trio'
    source_hashes = {name:sha((source/name).read_bytes()) for name in ['lib.rs','input_only_driver.rs']}
    frozen = json.loads((packet/'frozen.json').read_bytes())
    for name,key in [('oracle.py','oracle_sha256_at_freeze'),('static.json','static_sha256_at_freeze')]:
        require(sha((packet/name).read_bytes()) == frozen[key],'frozen source '+name)
    inputs = gzip.decompress((packet/'inputs.bin.gz').read_bytes())
    expected = gzip.decompress((packet/'expected.bin.gz').read_bytes())
    require(sha(inputs) == frozen['inputs_sha256'] and sha(expected) == frozen['expected_sha256'],'fixture identities')
    require(len(inputs)%1328 == 0 and len(expected) == len(inputs)//1328*1304,'fixture dimensions')
    digest = hashlib.sha256()
    paths = collections.Counter()
    admitted = [0,0,0]
    counts = collections.Counter()
    first_witness = {}
    for number,begin in enumerate(range(0,len(inputs),1328)):
        actual,path,facts = derive(inputs[begin:begin+1328])
        require(actual == expected[number*1304:(number+1)*1304],f'independent fixture mismatch {number}')
        digest.update(actual)
        paths[path] += 1
        if path != 'admitted':
            continue
        member = facts['member'];admitted[member] += 1
        markers = {'output_alias':facts['output_alias'],'read_role_alias':facts['source_alias'],
                   'nonzero_rdx_high32':facts['rdx'] >= 2**32,
                   'loaded_value_differs_from_return1':facts['final_word'] != 1,
                   'zero_destination':facts['destination'] == 0}
        for i,name in enumerate(['object','first','second']):
            markers[name+'_zero'] = facts['roots'][i] == 0
            markers[name+'_field_wraps'] = facts['wraps'][i]
        for name,yes in markers.items():
            if yes:
                counts[name] += 1
                first_witness.setdefault(name,{'row_zero_based':number,**facts})
    require(admitted == frozen['admitted_per_member'] and sum(admitted) == 5177,'admitted counts')
    require(len(inputs)//1328-sum(admitted) == frozen['refusals'] == 2476,'refusal counts')
    require(counts['output_alias'] == frozen['admitted_output_aliases'] == 992,'output alias count')
    require(counts['read_role_alias'] == frozen['admitted_read_role_aliases'] == 270,'read-role alias count')
    require(counts['object_field_wraps'] == frozen['admitted_wrapped_object_fields'] == 1719,'object wrap count')
    require(digest.hexdigest() == frozen['expected_sha256'],'independent complete output hash')
    static = authenticate((root/'artifacts/node/94/hl-node').read_bytes())
    retained = json.loads((packet/'static.json').read_bytes())
    for observed,saved in zip(static['bodies_and_callers'],retained['members']):
        require(observed['entry'] == saved['begin'] and observed['end'] == saved['end'] and
                observed['body_sha256'] == saved['body_sha256'],'retained member fact')
        frame = observed['frame']
        require(frame[2] == saved['records']['fde']['va'] and frame[3] == saved['records']['cie']['va'] and
                frame[4] == saved['records']['fde']['hex'],'retained complete FDE')
        require(observed['cie_sha256'] == sha(bytes.fromhex(saved['records']['cie']['hex'])),'retained complete CIE')
    require(static['rela_count'] == retained['rela_records_checked'] == 80300,'RELA census')
    require(source_hashes == {name:sha((source/name).read_bytes()) for name in source_hashes},'source changed during peer review')
    result = {'reviewed_source_sha256':source_hashes,'proof_sha256':sha((packet/'PROOF.md').read_bytes()),
              'peer_script_sha256':sha(Path(__file__).read_bytes()),'oracle_sha256':frozen['oracle_sha256_at_freeze'],
              'static_sha256':frozen['static_sha256_at_freeze'],'input_sha256':sha(inputs),
              'independent_expected_sha256':digest.hexdigest(),'cases':len(inputs)//1328,
              'admitted_per_member':admitted,'paths':dict(paths),'counts':dict(counts),'witnesses':first_witness,
              'static':static,'source_review':'No blocker found in full source/proof and exact final store/register relation.',
              'limits':['No Rust/native rerun in this peer check','No captured execution or instruction emulation',
                        'No claim that wrapped numeric fixtures describe real native virtual mappings',
                        'RAX/RDX/full image only; original fault order, flags, ABI and control/stack excluded',
                        'No direct incoming E8/E9 candidates or naming RELAs; not a complete indirect-reference census']}
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__ == '__main__':
    main()
