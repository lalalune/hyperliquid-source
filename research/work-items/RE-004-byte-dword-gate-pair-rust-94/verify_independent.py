#!/usr/bin/env python3
"""Read-only peer verification; standard library and Capstone, no oracle imports/execution.

Usage: python3 -O verify_independent.py /path/to/hyperliquid-source
Expected registers use signed-order partitions and independently admitted intervals.
This does not run Rust, captured instructions, or an instruction emulator.
"""
import base64
import re
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
BODIES = [
    (0x5172c70, bytes.fromhex('f30f1efa0fb647158b571084c0740485d27f063957040f9ec0c3'), 6),
    (0x5172c90, bytes.fromhex('f30f1efa488b470848635710483b5010740eb801000000c30f1f840000000000e9bbffffff'), 1),
]
CALLERS = [
    (84125680,84126576,'f7b754a7928a4143926fce5670d0161782feb69ee616cc8b90076f1f17c2a4a1',217,84126135,0x5172c70),
    (84179920,84186036,'66513bed292f4bf072f50f3135b70c748e423bb2124d78c3140c0a6be96fa533',1219,84180958,0x5172c70),
    (84855440,84857859,'5e0dafc940f3f34ef4dfdddcd29bb49e67a8d9ed7230dd72fa99ffeac2c437af',442,84855734,0x5172c90),
    (85241392,85241432,'edccc20b7e55d78684df3abda3b3aaa87183838e8db10dfca5efd74791af3f5f',11,85241414,0x5172c70),
]

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
        require(b''.join(i.bytes for i in decoded) == body and len(decoded) == [10,9][index], 'complete leaf decode')
        branches = [(i.address,int(i.op_str,16)) for i in decoded if i.mnemonic.startswith('j')]
        expected = [[(0x5172c7d,0x5172c83),(0x5172c81,0x5172c89)],[(0x5172ca0,0x5172cb0),(0x5172cb0,0x5172c70)]][index]
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
        expected = [(c[4],c[5]) for c in CALLERS] if opcode == 0xe8 else [(0x5172cb0,0x5172c70)]
        require(sites == expected,'full text incoming candidate scan')
        scans[hex(opcode)] = sites
    return {'bodies_and_callers':records,'fde_count':len(frames),'cie_count':len(cies),'rela_count':count,'incoming_scans':scans,'capstone_version':capstone.__version__,'body_padding_writers':0,'naming_addends':0}


def derive(row):
    member,base,obj,length = struct.unpack_from('<4Q',row)
    data = row[32:]
    require(member < 2 and length <= 128 and len(data) == 128,'descriptor')
    metadata = {'member':member}
    if base+length > N:
        return (0,0,0),'image-wrap',metadata
    def exists(delta,width):
        address = (obj+delta) % N
        return base <= address and address+width <= base+length
    def read(address,width):
        offset = address-base
        if offset < 0 or offset+width > length:
            raise IndexError
        return int.from_bytes(data[offset:offset+width],'little')
    metadata['flag_present'] = exists(21,1)
    metadata['compared_present'] = exists(4,4)
    try:
        prefix = 'direct'
        if member:
            pointer = read((obj+8)%N,8)
            count = read((obj+16)%N,4)
            extended = count | (0xffffffff00000000 if count & 0x80000000 else 0)
            pointed = read((pointer+16)%N,8)
            metadata.update(count=count,pointed=pointed,extended=extended)
            if pointed != extended:
                return (1,1,extended),'tail-mismatch',metadata
            prefix = 'tail-equal'
        flag = read((obj+21)%N,1)
        count = read((obj+16)%N,4)
        metadata.update(flag=flag,count=count)
        positive = count != 0 and count & 0x80000000 == 0
        if flag != 0 and positive:
            return (1,flag,count),prefix+'-flag',metadata
        compared = read((obj+4)%N,4)
        metadata['compared'] = compared
        # Distinct signed-order derivation: partition the two sign bits, then
        # compare their raw magnitudes only when both occupy the same half.
        sign_c,sign_v = count >> 31,compared >> 31
        le = sign_v > sign_c if sign_c != sign_v else compared <= count
        return (1,int(le),count),prefix+'-compare',metadata
    except IndexError:
        return (0,0,0),'missing-selected-span',metadata


def main():
    root = Path(sys.argv[1]).resolve()
    packet = root/'research/work-items/RE-004-byte-dword-gate-pair-rust-94'
    inputs = gzip.decompress((packet/'inputs.bin.gz').read_bytes())
    expected = gzip.decompress((packet/'expected.bin.gz').read_bytes())
    frozen = json.loads((packet/'frozen.json').read_bytes())
    require(sha(inputs) == frozen['inputs_sha256'] and sha(expected) == frozen['expected_sha256'],'frozen fixture hashes')
    for name,key in [('oracle.py','oracle_sha256_at_freeze'),('static.json','static_sha256_at_freeze')]:
        require(sha((packet/name).read_bytes()) == frozen[key],'frozen source '+name)
    require(len(inputs) % 160 == 0 and len(expected) == len(inputs)//160*24,'fixture dimensions')
    digest = hashlib.sha256()
    paths = collections.Counter()
    signs = collections.Counter()
    witnesses = {}
    admitted = [0,0]
    flags = [set(),set()]
    for i in range(len(inputs)//160):
        row = inputs[i*160:(i+1)*160]
        result,path,meta = derive(row)
        raw = struct.pack('<3Q',*result)
        require(raw == expected[i*24:(i+1)*24],'independent expectation '+str(i))
        digest.update(raw)
        paths[path] += 1
        admitted[meta['member']] += result[0]
        if 'flag' in meta:
            flags[meta['member']].add(meta['flag'])
        label = None
        if result[0] and path == 'tail-mismatch' and not meta['flag_present']:
            label = 'tail-mismatch-without-flag'
        elif result[0] and path.endswith('-flag') and not meta['compared_present']:
            label = 'flag-path-without-compared-word'
        if label and label not in witnesses:
            witnesses[label] = {'row':i,'input_hex':row.hex(),'result':result,'metadata':meta}
        if result[0] and meta.get('count',0) >= 0x80000000:
            extension = 'sign-extended' if result[2] >= (1<<32) else 'zero-extended'
            signs[path+':'+extension] += 1
            label = path+':'+extension
            if label not in witnesses:
                witnesses[label] = {'row':i,'input_hex':row.hex(),'result':result,'metadata':meta}
    require(admitted == frozen['admitted_per_member'] and all(len(f) == 256 for f in flags),'admitted/gate coverage')
    for key in ['tail-mismatch-without-flag','flag-path-without-compared-word','tail-mismatch:sign-extended','tail-equal-compare:zero-extended']:
        require(key in witnesses,'missing independent witness '+key)
    failed = json.loads(gzip.decompress((packet/'initial-static-boundary-failure.json.gz').read_bytes()))
    failure_hashes = {}
    for label,item in failed['streams'].items():
        raw = base64.b64decode(item['base64'],validate=True)
        require(sha(raw) == item['sha256'],'retained strict failure hash')
        failure_hashes[label] = sha(raw)
        if label == 'static.log':
            require(b'ValueError: complete caller three-decoder boundaries' in raw,'actual initial strict failure')
    joins = []
    for caller,site,hexbytes in [(0,0x503a84c,'f083423801'),(0,0x503a9c4,'f083453801'),(2,0x50ecdb7,'f04183453801')]:
        lines = (packet/f'caller{caller}.llvm.txt').read_text().splitlines()
        parsed = []
        for line in lines:
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$',line)
            if match:
                parsed.append((int(match[1],16),bytes.fromhex(match[2])))
        i = next(i for i,item in enumerate(parsed) if item[0] == site)
        require(parsed[i][1] == b'\xf0' and parsed[i+1][0] == site+1 and (parsed[i][1]+parsed[i+1][1]).hex() == hexbytes,'exact retained LLVM split display')
        decoded = list(capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(bytes.fromhex(hexbytes),site))
        require(len(decoded) == 1 and decoded[0].mnemonic == 'lock add','single actual LOCK ADD instruction')
        joins.append({'address':hex(site),'hex':hexbytes})
    hashes = {str(p.relative_to(root)):sha(p.read_bytes()) for p in [root/'src/node94-byte-dword-gate-pair/lib.rs',packet/'PROOF.md',packet/'oracle.py',packet/'frozen.json',packet/'static.json',packet/'verify_static.py']}
    report = {'reviewed_hashes':hashes,'independent_script_sha256':sha(Path(__file__).read_bytes()),'cases':len(inputs)//160,'admitted_per_member':admitted,'path_counts':dict(sorted(paths.items())),'negative_count_extensions':dict(sorted(signs.items())),'flag_values_per_member':[len(f) for f in flags],'witnesses':witnesses,'independent_expected_sha256':digest.hexdigest(),'static':authenticate((root/'artifacts/node/94/hl-node').read_bytes()),'initial_strict_failure_hashes':failure_hashes,'exact_llvm_display_joins':joins,'blockers':[],'limitations':['Read-only static/mathematical review; no independent native Rust rerun.','Finite-image successful-access/stability premises, new refusal semantics and no native ABI/fault/concurrent observation claims remain essential.','Caller body identity and call boundaries are checked; caller semantics and LSDA behavior are not reconstructed.','Incoming raw scan is not a complete indirect-reference census.','Capstone is a static disassembler, not an instruction emulator; no captured instructions are executed.'],'captured_execution':False,'instruction_emulation':False}
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__ == '__main__':
    main()
