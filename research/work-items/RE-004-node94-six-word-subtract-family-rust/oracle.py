"""Pre-Rust whole-integer/snapshot-overlay oracle for the six-word subtraction family."""
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__ as capstone_version

TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
STARTS = [0x56570a0, 0x56570e0, 0x5657180, 0x56580a0, 0x565ae00]
SCAN_TARGETS = STARTS + [0x56570fb, 0x56580bb, 0x565ae1b]
LOCK_SHA = '3989734ef615bfa016fb2c3dda9ac57d3a252cb1ab3a9e6c94b67d76ed375a16'
WORD = 2**64


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def mapping(data):
    secs = sections(data)
    for name in ('.text', '.eh_frame', '.rela.dyn'):
        require(sum(s['name'] == name for s in secs) == 1, 'Ambiguous section ' + name)

    def offset(va, size):
        found = [s for s in secs if s['type'] != 8 and s['address'] <= va
                 and va + size <= s['address'] + s['size']]
        require(len(found) == 1, 'VA mapping is not unique')
        return found[0]['offset'] + va - found[0]['address']
    return secs, offset


def structure(data):
    require(digest(PACKET / 'static-lock.json') == LOCK_SHA, 'Static lock changed')
    contract = json.loads((PACKET / 'static-lock.json').read_text())
    secs, offset = mapping(data)
    read = lambda va, size: data[offset(va, size):offset(va, size) + size]
    _, frames = eh_frame_records(data)
    bodies = []
    for item in contract['bodies']:
        start, end = item['start'], item['end']
        overlapping = [f for f in frames if f['start'] < end and start < f['end']]
        require(len(overlapping) == 1 and (overlapping[0]['start'], overlapping[0]['end']) == (start, end), 'Unique complete FDE changed')
        raw = read(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == item['body_sha256'], 'Complete body changed')
        for record in item['frames'].values():
            encoded = bytes.fromhex(record['hex'])
            require(read(record['va'], len(encoded)) == encoded, 'FDE/CIE changed')
        fde, cie = item['frames']['fde'], item['frames']['cie']
        encoded = bytes.fromhex(fde['hex'])
        pc = fde['va'] + 8 + struct.unpack_from('<i', encoded, 8)[0]
        extent = struct.unpack_from('<I', encoded, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE extent changed')
        require(fde['va'] + 4 - struct.unpack_from('<I', encoded, 4)[0] == cie['va'], 'CIE pointer changed')
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(raw, start))
        require(b''.join(i.bytes for i in decoded) == raw, 'Incomplete linear decode')
        rows = [{'va': hex(i.address), 'hex': i.bytes.hex(), 'mnemonic': i.mnemonic,
                 'operands': i.op_str} for i in decoded]
        if start in STARTS:
            calls = [i.op_str for i in decoded if i.mnemonic == 'call']
            require(calls == ([hex(0x56570e0)] * (2 if start == 0x5657180 else 1) if start in (0x56570a0,0x5657180) else []), 'Closed call relation changed')
            edges = [(i.address, i.mnemonic, i.op_str) for i in decoded if i.mnemonic.startswith('j')]
            require(not edges, 'Straight-line body changed')
            require(decoded[-1].address == end - 2 and decoded[-1].mnemonic == 'repz ret', 'Return closure changed')
            memory = [i for i in decoded if '[' in i.op_str and i.mnemonic != 'lea']
            require(len(memory) == ({0x56570a0:6,0x5657180:10}.get(start,24)), 'Explicit memory census changed')
            stores = [i for i in memory if i.mnemonic == 'mov' and i.op_str.startswith('qword ptr [rdi')]
            require(len(stores) == (0 if start in (0x56570a0,0x5657180) else 6), 'Data stores changed')
            stack_reads = [i for i in memory if 'rsp' in i.op_str]
            require(len(stack_reads) == {0x56570a0:6,0x5657180:10}.get(start,0), 'Stack access census changed')
            require(not any('rip' in i.op_str for i in decoded), 'Static dependency appeared')
        sites = {i.address: i for i in decoded}
        for site, target in item['sites']:
            require(site in sites and sites[site].mnemonic in ('call','jmp') and sites[site].op_str == hex(target), 'Caller/tail boundary changed')
        bodies.append({**item, 'instructions': rows})
    for pad in contract['padding']:
        raw = bytes.fromhex(pad['hex'])
        require(read(pad['start'], len(raw)) == raw, 'Alignment padding changed')
    relocation_count = 0
    for section in secs:
        require(section['type'] != 9, 'Unexpected REL table')
        if section['type'] == 4:
            require(section['size'] % 24 == 0, 'Malformed RELA extent')
            for address, info, addend in struct.iter_unpack('<QQq', read(section['address'], section['size'])):
                require((info & 0xffffffff) in (1, 6, 7, 8, 18), 'Unknown relocation width')
                require(addend not in SCAN_TARGETS, 'Unexpected naming relocation')
                for body in contract['bodies']:
                    require(not (address < body['end'] and address + 8 > body['start']), 'Body relocation appeared')
                for pad in contract['padding']:
                    require(not (address < pad['start'] + len(bytes.fromhex(pad['hex'])) and address + 8 > pad['start']), 'Padding relocation appeared')
                relocation_count += 1
    text = next(s for s in secs if s['name'] == '.text')
    code, scans = read(text['address'], text['size']), {}
    for start in SCAN_TARGETS:
        scan = {}
        for opcode, width in ((b'\xe8', 5), (b'\xe9', 5), (b'\xeb', 2)):
            hits, pos = [], 0
            while (pos := code.find(opcode, pos)) >= 0:
                if pos + width <= len(code):
                    displacement = struct.unpack_from('<b' if width == 2 else '<i', code, pos + 1)[0]
                    if text['address'] + pos + width + displacement == start:
                        hits.append(text['address'] + pos)
                pos += 1
            scan[opcode.hex()] = hits
        scans[hex(start)] = scan
    require(scans == contract['scans'], 'Incoming pattern scan changed')
    return {'target_sha256': TARGET_SHA, 'bodies': bodies, 'incoming_candidates': scans,
            'relocation_records': relocation_count, 'naming_relocations': 0,
            'text_scan_bytes': len(code), 'capstone_version': capstone_version,
            'static_lock_sha256': LOCK_SHA, 'complete_xref_census': False}


def admit():
    raw = TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == TARGET_SHA, 'Target identity changed')
    return structure(raw)


IMAGE_SIZE = 384
INPUT_SIZE = 536
OUTPUT_SIZE = 496
K = WORD**6


def relation(row):
    # raw=0, saved=1, high-first pair=2, prepared interior=3.
    member,base,ap,bp,mp,destination,length,*tail = row
    saved,prepared,raw = tail[:6],tail[6:12],tail[12]
    refused = (0,)*14,raw,{'refused':True}
    if base+length > WORD:
        return refused
    width = 96 if member == 2 else 48
    required = [(bp,width),(mp,48),(destination,width)]
    if member != 3:
        required.append((ap,width))
    if any(a < base or a+n > base+length for a,n in required):
        return refused
    def integer(address,patch=None):
        data = bytearray(raw[address-base:address-base+48])
        if patch is not None:
            at,payload = patch
            lo,hi = max(address,at),min(address+48,at+48)
            if lo < hi:
                data[lo-address:hi-address] = payload[lo-at:hi-at]
        return int.from_bytes(data,'little')
    # An immutable high-output patch determines every low-call snapshot in the
    # pair. This is whole 384-bit arithmetic, not a limb/instruction interpreter.
    high_patch = None
    high_borrow = None
    if member == 2:
        ah,bh,mh = integer(ap+48),integer(bp+48),integer(mp)
        high_borrow = int(ah < bh)
        high = (ah-bh+high_borrow*mh) % K
        high_patch = (destination+48,high.to_bytes(48,'little'))
    a = sum(word*WORD**i for i,word in enumerate(prepared)) if member == 3 else integer(ap,high_patch)
    b,m = integer(bp,high_patch),integer(mp,high_patch)
    borrow = int(a < b)
    u = (a-b+borrow*m) % K
    result = [u//WORD**i % WORD for i in range(6)]
    masked = [borrow*(m//WORD**i % WORD) for i in range(6)]
    callee = saved if member in (1,2) else [masked[3],masked[4],result[4],result[5],masked[0],masked[1]]
    registers = (1,masked[2],(-borrow)%WORD,masked[5],*result[:4],*callee)
    final = bytearray(raw)
    if high_patch is not None:
        at,payload = high_patch;final[at-base:at-base+48] = payload
    final[destination-base:destination-base+48] = u.to_bytes(48,'little')
    facts = {'refused':False,'member':member,'borrow':borrow,'high_borrow':high_borrow,
             'alias':any(a < destination+width and destination < a+n for a,n in ([(bp,width),(mp,48)]+([] if member == 3 else [(ap,width)]))),
             'low_a_changed':member == 2 and a != integer(ap),
             'low_b_changed':member == 2 and b != integer(bp),
             'low_m_changed':member == 2 and m != integer(mp),
             'prepared_missing_a':member == 3 and (ap < base or ap+48 > base+length)}
    return registers,bytes(final),facts


def corpus():
    cases = set()
    def add(member,a,b,m,ah=0,bh=0,base=0,ao=0,bo=96,mo=192,dout=240,length=384,salt=0,saved=None,prepared=None):
        image = bytearray((i*61+salt*13)%256 for i in range(384))
        aw,bw = (a+K*ah,b+K*bh) if member == 2 else (a,b)
        width = 96 if member == 2 else 48
        for at,value,size in [(ao,aw,width),(bo,bw,width),(mo,m,48)]:
            if 0 <= at and at+size <= 384:
                image[at:at+size] = value.to_bytes(size,'little')
        if saved is None:
            saved = [((i+1)*0x123456789abcdef ^ salt*0x1000100010001)%WORD for i in range(6)]
        if prepared is None:
            prepared = [a//WORD**i%WORD for i in range(6)]
        cases.add((member,base,(base+ao)%WORD,(base+bo)%WORD,(base+mo)%WORD,(base+dout)%WORD,length,*saved,*prepared,bytes(image)))
    for member in range(4):
        for bit in range(384):
            for delta in [-1,0,1]:
                v=((1<<bit)+delta)%K
                add(member,v,K-1-v,K-1,ah=K-1-v,bh=v,salt=bit)
                add(member,0,K-1,v,ah=1,bh=2,salt=bit+500)
        for a,b in [(0,0),(0,1),(1,0),(K-1,K-1),(K-1,1),(K//2,K-1)]:
            for m in [0,1,K//2,K-1]:
                add(member,a,b,m,ah=b,bh=a)
        if member in (1,2):
            for slot in range(6):
                for bit in range(64):
                    saved=[0]*6;saved[slot]=1<<bit
                    add(member,0,0,0,saved=saved)
    rng = random.Random(0x56570e0)
    for member in range(4):
        for i in range(700):
            add(member,rng.getrandbits(384),rng.getrandbits(384),rng.getrandbits(384),
                ah=rng.getrandbits(384),bh=rng.getrandbits(384),salt=i,
                saved=[rng.getrandbits(64) for _ in range(6)],prepared=[rng.getrandbits(64) for _ in range(6)])
        for ao,bo,mo in [(0,96,192),(96,0,256),(0,0,0),(32,88,144),(96,64,0)]:
            for dout in range(289 if member == 2 else 337):
                add(member,rng.getrandbits(384),rng.getrandbits(384),rng.getrandbits(384),
                    ah=rng.getrandbits(384),bh=rng.getrandbits(384),ao=ao,bo=bo,mo=mo,dout=dout,salt=dout)
        for base in [0,1,0x1000,WORD-384,WORD-192]:
            for length in [0,47,48,95,96,191,192,239,240,287,288,335,336,383,384]:
                for ao,bo,mo,dout in [(0,96,192,240),(0,0,0,0),(-1,96,192,240),(0,96,192,337)]:
                    add(member,K-1,1,K-1,ah=0,bh=1,base=base,ao=ao,bo=bo,mo=mo,dout=dout,length=length)
    return sorted(cases)


def fixture_bytes():
    inputs=bytearray();expected=bytearray()
    coverage={'cases':0,'admitted':0,'refusals':0,'by_member':[0]*4,'admitted_by_member':[0]*4,
              'borrow_classes':{},'pair_borrow_classes':{},'low_a_changed':0,'low_b_changed':0,
              'low_m_changed':0,'prepared_missing_a':0,'alias_admitted':0}
    for row in corpus():
        registers,image,facts=relation(row)
        inputs.extend(struct.pack('<19Q',*row[:-1])+row[-1])
        expected.extend(struct.pack('<14Q',*registers)+image)
        coverage['cases']+=1;coverage['by_member'][row[0]]+=1
        if facts['refused']:
            coverage['refusals']+=1
        else:
            coverage['admitted']+=1;coverage['admitted_by_member'][row[0]]+=1
            for key in ['low_a_changed','low_b_changed','low_m_changed','prepared_missing_a']:
                coverage[key]+=facts[key]
            coverage['alias_admitted']+=facts['alias']
            key=str(row[0])+':'+str(facts['borrow'])
            coverage['borrow_classes'][key]=coverage['borrow_classes'].get(key,0)+1
            if row[0]==2:
                key=str(facts['high_borrow'])+str(facts['borrow'])
                coverage['pair_borrow_classes'][key]=coverage['pair_borrow_classes'].get(key,0)+1
    return bytes(inputs),bytes(expected),coverage


def main():
    require(not (ROOT/'src/node94-six-word-subtract-family').exists(),'Freeze must precede Rust source')
    facts=admit();inputs,expected,coverage=fixture_bytes()
    folder=PACKET/'frozen';folder.mkdir()
    for name,raw in [('inputs.bin',inputs),('expected.bin',expected)]:
        (folder/(name+'.gz')).write_bytes(gzip.compress(raw,mtime=0))
    record={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'oracle_source_sha256':digest(__file__),
            'static_facts':facts,'coverage':coverage,'inputs_sha256':hashlib.sha256(inputs).hexdigest(),
            'expected_sha256':hashlib.sha256(expected).hexdigest(),'rust_source_existed':False,'captured_execution':False}
    (folder/'ORACLE-FREEZE.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k!='static_facts'},indent=2))


if __name__ == '__main__':
    main()


