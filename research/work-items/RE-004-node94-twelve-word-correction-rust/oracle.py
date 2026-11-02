"""Pre-Rust whole-integer and immutable-overlay oracle for twelve-word corrections."""
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
STARTS = [0x5657ce0, 0x5657e00, 0x5657f20]
LOCK_SHA = 'd91d7aae90ac2aeb39d7f9b1960aa80852fd9e44d3b17fb383edde9b74bdd5e8'
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
            require(not any(i.mnemonic == 'call' for i in decoded), 'Closure acquired a callee')
            edges = [(i.address, i.mnemonic, i.op_str) for i in decoded if i.mnemonic.startswith('j')]
            require(not edges, 'Straight-line body changed')
            require(decoded[-1].address == end - 2 and decoded[-1].mnemonic == 'repz ret', 'Return closure changed')
            memory = [i for i in decoded if '[' in i.op_str and i.mnemonic != 'lea']
            require(len(memory) == (42 if start == STARTS[2] else 48), 'Explicit memory census changed')
            stores = [i for i in memory if i.mnemonic == 'mov' and i.op_str.startswith('qword ptr [rdi')]
            require(len(stores) == 12, 'Twelve data stores changed')
            stack_reads = [i for i in memory if 'rsp' in i.op_str]
            require(len(stack_reads) == (0 if start == STARTS[2] else 6), 'Saved-register restoration changed')
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
                require(addend not in STARTS, 'Unexpected naming relocation')
                for body in contract['bodies']:
                    require(not (address < body['end'] and address + 8 > body['start']), 'Body relocation appeared')
                for pad in contract['padding']:
                    require(not (address < pad['start'] + len(bytes.fromhex(pad['hex'])) and address + 8 > pad['start']), 'Padding relocation appeared')
                relocation_count += 1
    text = next(s for s in secs if s['name'] == '.text')
    code, scans = read(text['address'], text['size']), {}
    for start in STARTS:
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
INPUT_SIZE = 488
OUTPUT_SIZE = 496
ADD_ORDER = (0,1,2,4,3,5)


def relation(row):
    member,base,ap,bp,mp,destination,length,*tail = row
    saved,raw = tail[:6],tail[6]
    empty = (0,)*14,raw,{'refused':True}
    if base+length > WORD:
        return empty
    def offset(address,size):
        index = address-base
        if index < 0 or index+size > length:
            raise IndexError
        return index
    try:
        for address,size in [(ap,96),(bp,96),(mp,48),(destination,96)]:
            offset(address,size)
    except IndexError:
        return empty
    def read(address,size,writes=()):
        begin = offset(address,size)
        result = []
        for i in range(size):
            at = address+i
            sources = [(a,value) for a,value in writes if a <= at < a+len(value)]
            result.append(sources[-1][1][at-sources[-1][0]] if sources else raw[begin+i])
        return bytes(result)
    a = int.from_bytes(read(ap,96),'little')
    low_b = int.from_bytes(read(bp,48),'little')
    add = member == 0
    low = ((a % WORD**6)+low_b if add else (a % WORD**6)-low_b) % WORD**6
    low_words = [low//WORD**i % WORD for i in range(6)]
    order = ADD_ORDER if add else tuple(range(6))
    patches = tuple((destination+8*i,low_words[i].to_bytes(8,'little')) for i in order)
    # Each high B word sees exactly its prefix of the already-known low stores.
    high_b = sum(int.from_bytes(read(bp+48+8*i,8,patches[:i+1]),'little')*WORD**i for i in range(6))
    b = low_b+WORD**6*high_b
    wide = a+b if add else a-b
    residue = wide % WORD**12
    high = residue//WORD**6
    # Addition loads all correction words after the low stores. Subtraction's
    # correction word i sees only low stores0..i, before the next one is issued.
    modulus = sum(int.from_bytes(read(mp+8*i,8,patches if add else patches[:i+1]),'little')*WORD**i for i in range(6))
    if add:
        carry = int(wide >= WORD**12)
        borrow = int(high < modulus)
        corrected = (high-modulus) % WORD**6 if carry or not borrow else high
        rdx = (-carry-borrow) % WORD
        auxiliary = [high//WORD**i % WORD for i in range(4)]
        chosen = bool(carry or not borrow)
    else:
        borrow = int(wide < 0)
        corrected = (high+borrow*modulus) % WORD**6
        rdx = (-borrow) % WORD
        auxiliary = [borrow*(modulus//WORD**i % WORD) for i in range(4)]
        carry = 0
        chosen = bool(borrow)
    upper = [corrected//WORD**i % WORD for i in range(6)]
    if member == 2:
        final_saved = [upper[3],upper[4],borrow*(modulus//WORD**4 % WORD),
                       borrow*(modulus//WORD**5 % WORD),upper[0],upper[1]]
    else:
        final_saved = saved
    registers = (upper[2],rdx,upper[5],*auxiliary,*final_saved)
    all_writes = patches+tuple((destination+48+8*i,upper[i].to_bytes(8,'little')) for i in range(6))
    # Pure overlay evaluation of the final image; no instruction interpreter.
    final = bytearray(raw)
    for index in range(IMAGE_SIZE):
        address = base+index
        sources = [(a,value) for a,value in all_writes if a <= address < a+len(value)]
        if sources:
            final[index] = sources[-1][1][address-sources[-1][0]]
    facts = {'refused':False,'member':member,'carry':carry,'borrow':borrow,'corrected':chosen,
             'alias':any(address < destination+96 and destination < address+size for address,size in [(ap,96),(bp,96),(mp,48)]),
             'b_live_changed':read(bp+48,48) != high_b.to_bytes(48,'little'),
             'm_live_changed':read(mp,48) != modulus.to_bytes(48,'little')}
    return (1,*registers),bytes(final),facts


def corpus():
    cases = set()
    full = WORD**12
    half = WORD**6
    def add(member,a,b,m,base=0,ao=0,bo=96,mo=192,dout=240,length=384,salt=0,saved=None):
        raw = bytearray((i*83+salt)%256 for i in range(384))
        for off,value,width in [(ao,a,96),(bo,b,96),(mo,m,48)]:
            if 0 <= off and off+width <= 384:
                raw[off:off+width] = value.to_bytes(width,'little')
        if saved is None:
            saved = tuple(((0x123456789abcdef*(i+1)) ^ (salt*0x1000100010001))%WORD for i in range(6))
        cases.add((member,base,(base+ao)%WORD,(base+bo)%WORD,(base+mo)%WORD,(base+dout)%WORD,length,*saved,bytes(raw)))
    for member in range(3):
        for bit in range(768):
            for delta in [-1,0,1]:
                a = ((1<<bit)+delta)%full
                add(member,a,full-1-a,half-1,salt=bit)
        for bit in range(384):
            for delta in [-1,0,1]:
                m = ((1<<bit)+delta)%half
                add(member,full-1,full-1,m,salt=bit)
        for a,b in [(0,0),(0,1),(1,0),(full-1,full-1),(half-1,1),(half,half-1),(full//2,full//2)]:
            for m in [0,1,half//2,half-1]:
                add(member,a,b,m)
        for slot in range(6):
            for bit in range(64):
                saved = [0]*6;saved[slot] = 1<<bit
                add(member,0,0,0,saved=saved)
    rng = random.Random(0x5657ce0)
    for member in range(3):
        for i in range(900):
            add(member,rng.getrandbits(768),rng.getrandbits(768),rng.getrandbits(384),salt=i,
                saved=tuple(rng.getrandbits(64) for _ in range(6)))
        for ao,bo,mo in [(0,96,192),(64,0,256),(0,0,0),(32,88,144),(96,64,0)]:
            for dout in range(289):
                add(member,rng.getrandbits(768),rng.getrandbits(768),rng.getrandbits(384),
                    ao=ao,bo=bo,mo=mo,dout=dout,salt=dout)
        for base in [0,1,0x1000,WORD-384,WORD-192]:
            for length in [0,47,48,95,96,191,192,239,240,335,336,383,384]:
                for ao,bo,mo,dout in [(0,96,192,240),(0,0,0,0),(-1,96,192,240),(0,96,192,289)]:
                    add(member,full-1,full-1,half-1,base,ao,bo,mo,dout,length)
    return sorted(cases)


def fixture_bytes():
    inputs = bytearray();expected = bytearray()
    coverage = {'cases':0,'admitted':0,'refusals':0,'by_member':[0,0,0],
                'admitted_by_member':[0,0,0],'alias_admitted':0,'live_b_changes':0,
                'live_m_changes':0,'carry_and_borrow':{},'corrected_cases':0}
    for row in corpus():
        registers,image,facts = relation(row)
        inputs.extend(struct.pack('<13Q',*row[:-1])+row[-1])
        expected.extend(struct.pack('<14Q',*registers)+image)
        coverage['cases'] += 1;coverage['by_member'][row[0]] += 1
        if facts['refused']:
            coverage['refusals'] += 1
        else:
            coverage['admitted'] += 1;coverage['admitted_by_member'][row[0]] += 1
            coverage['alias_admitted'] += facts['alias']
            coverage['live_b_changes'] += facts['b_live_changed']
            coverage['live_m_changes'] += facts['m_live_changed']
            coverage['corrected_cases'] += facts['corrected']
            key = str(row[0])+':'+str(facts['carry'])+str(facts['borrow'])
            coverage['carry_and_borrow'][key] = coverage['carry_and_borrow'].get(key,0)+1
    return bytes(inputs),bytes(expected),coverage


def main():
    require(not (ROOT/'src/node94-twelve-word-correction').exists(),'Freeze must precede Rust source')
    facts = admit()
    inputs,expected,coverage = fixture_bytes()
    folder = PACKET/'frozen';folder.mkdir()
    for name,raw in [('inputs.bin',inputs),('expected.bin',expected)]:
        (folder/(name+'.gz')).write_bytes(gzip.compress(raw,mtime=0))
    record = {'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'oracle_source_sha256':digest(__file__),'static_facts':facts,'coverage':coverage,
              'inputs_sha256':hashlib.sha256(inputs).hexdigest(),'expected_sha256':hashlib.sha256(expected).hexdigest(),
              'rust_source_existed':False,'captured_execution':False}
    (folder/'ORACLE-FREEZE.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k != 'static_facts'},indent=2))


if __name__ == '__main__':
    main()
