"""Pre-Rust threshold-interval and modular-power oracle for all-count doubling."""
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
STARTS = [0x5656c40, 0x5656d20, 0x5656de0, 0x5656f00]
LOCK_SHA = '48beb52b79fe0d7a420443ab83f97f24f7651da759921e01209ca60b2d9389f1'
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
            require([i.op_str for i in decoded if i.mnemonic == 'call'] == ([hex(0x5656d20)]*({0x5656de0:3,0x5656f00:6}.get(start,0))), 'Closed call relation changed')
            edges = [(i.address, i.mnemonic, i.op_str) for i in decoded if i.mnemonic.startswith('j')]
            require(edges == ([(0x5656cc6,'jne',hex(0x5656c66))] if start == 0x5656c40 else []), 'Closed loop edge changed')
            require(decoded[-1].address == end - 2 and decoded[-1].mnemonic == 'repz ret', 'Return closure changed')
            memory = [i for i in decoded if '[' in i.op_str and i.mnemonic != 'lea']
            require(len(memory) == {0x5656c40:25,0x5656d20:6,0x5656de0:18,0x5656f00:31}[start], 'Explicit memory census changed')
            stores = [i for i in memory if i.mnemonic == 'mov' and i.op_str.startswith('qword ptr [rdi')]
            require(len(stores) == ({0x5656d20:0,0x5656f00:12}.get(start,6)), 'Data store census changed')
            stack_reads = [i for i in memory if 'rsp' in i.op_str]
            require(len(stack_reads) == {0x5656c40:7,0x5656d20:0,0x5656de0:6,0x5656f00:7}[start], 'Saved-register restoration changed')
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
INPUT_SIZE = 536
OUTPUT_SIZE = 512
RANGE = WORD**6


def advance(x, m, count):
    """Closed threshold search from the initial excess, then modular power."""
    if count == 0:
        return x
    if m == 0:
        return 0 if count >= 384 else (x * 2**count) % RANGE
    if x < m:
        return x * pow(2, count, m) % m
    if x == m:
        return m
    excess = x-m
    for k in range(1, min(count,384)+1):
        residue = (excess * 2**k) % RANGE
        if residue >= RANGE-m:
            reduced = residue-(RANGE-m)
            return reduced * pow(2,count-k,m) % m
    return m + (excess * 2**min(count,384)) % RANGE


def observation(x, m, count):
    previous = advance(x,m,count-1)
    result = advance(x,m,count)
    doubled = 2*previous
    carry = int(doubled >= RANGE)
    low = doubled % RANGE
    borrow = int(low < m)
    require(result == (low-m if carry or not borrow else low) % RANGE,
            'Independent closed relation disagrees with last-step algebra')
    words = [result//WORD**i % WORD for i in range(6)]
    temporary = [low//WORD**i % WORD for i in range(6)]
    return result,words,temporary,(-carry-borrow)%WORD


def relation(row):
    member,base,ap,mp,destination,length,raw_count,*tail = row
    saved,prepared,raw = tail[:6],tail[6:12],tail[12]
    empty = (0,)*16,raw,{'refused':True}
    if base+length > WORD:
        return empty
    def offset(address,size):
        index = address-base
        if index < 0 or index+size > length:
            raise IndexError
        return index
    try:
        offset(mp,48)
        if member != 0:
            offset(ap,96 if member == 3 else 48)
            offset(destination,96 if member == 3 else 48)
    except IndexError:
        return empty
    def read(address,size,writes=()):
        begin = offset(address,size)
        return bytes(next((value[address+i-at] for at,value in reversed(writes)
                           if at <= address+i < at+len(value)),raw[begin+i]) for i in range(size))
    initial_m = int.from_bytes(read(mp,48),'little')
    initial_x = sum(value*WORD**i for i,value in enumerate(prepared)) if member == 0 else int.from_bytes(read(ap,48),'little')
    count = (raw_count % 2**32 or 2**32) if member == 2 else (1 if member == 0 else 3)
    value,words,temp,mask = observation(initial_x,initial_m,count)
    writes = () if member == 0 else ((destination,value.to_bytes(48,'little')),)
    m_changed = a_changed = False
    if member == 3:
        high_x = int.from_bytes(read(ap+48,48,writes),'little')
        high_m = int.from_bytes(read(mp,48,writes),'little')
        a_changed = high_x != int.from_bytes(read(ap+48,48),'little')
        m_changed = high_m != initial_m
        value,words,temp,mask = observation(high_x,high_m,3)
        writes += ((destination+48,value.to_bytes(48,'little')),)
    callee = [temp[3],temp[4],words[4],words[5],temp[0],temp[1]] if member == 0 else saved
    registers = (temp[2],0 if member == 2 else mask,temp[5],mp,destination,*words[:4],*callee)
    final = bytes(next((value[base+i-at] for at,value in reversed(writes)
                        if at <= base+i < at+len(value)),raw[i]) for i in range(IMAGE_SIZE))
    facts = {'refused':False,'member':member,'count':count,'mask':mask,
             'raw_state':int(initial_x >= initial_m),'equal_state':int(initial_x == initial_m),
             'zero_m':int(initial_m == 0),'one_m':int(initial_m == 1),
             'alias':member != 0 and any(address < destination+(96 if member==3 else 48) and destination < address+size for address,size in [(ap,96 if member==3 else 48),(mp,48)]),
             'a_live_changed':a_changed,'m_live_changed':m_changed}
    return (1,*registers),final,facts


def corpus():
    cases = set()
    def add(member,x,m,count=1,high=0,base=0,ao=0,mo=96,dout=192,length=384,salt=0,saved=None,prepared=None):
        raw = bytearray((i*83+salt)%256 for i in range(384))
        for off,value,width in [(ao,x+RANGE*high,96),(mo,m,48)]:
            if 0 <= off and off+width <= 384:
                raw[off:off+width] = value.to_bytes(width,'little')
        if saved is None:
            saved = tuple(((0x123456789abcdef*(i+1)) ^ (salt*0x1000100010001))%WORD for i in range(6))
        if prepared is None:
            prepared = tuple(x//WORD**i % WORD for i in range(6))
        cases.add((member,base,(base+ao)%WORD,(base+mo)%WORD,(base+dout)%WORD,length,count,*saved,*prepared,bytes(raw)))
    for member in range(4):
        for bit in range(384):
            for delta in [-1,0,1]:
                x = ((1<<bit)+delta)%RANGE
                add(member,x,RANGE-1-x,[1,2,3,383,384,385][bit%6],high=RANGE-1-x,salt=bit)
                add(member,RANGE-1,x,3,high=RANGE//2,salt=bit)
        for slot in range(6):
            for bit in range(64):
                saved = [0]*6;saved[slot] = 1<<bit
                add(member,0,0,saved=saved)
        for m in [0,1,2,3,RANGE//2,RANGE-1]:
            for x in sorted({0,1,2,m,(m-1)%RANGE,(m+1)%RANGE,RANGE-1}):
                for count in ([0,1,2,3,383,384,385,2**31,2**32-1,2**32,2**32+1,WORD-1] if member == 2 else [1]):
                    add(member,x,m,count,high=(x+1)%RANGE)
    rng = random.Random(0x5656c40)
    for member in range(4):
        for i in range(160 if member == 2 else 500):
            count = [0,2**32-1,2**31,123456789][i%4] if member == 2 and i<32 else i%385+1
            add(member,rng.getrandbits(384),rng.getrandbits(384),count,high=rng.getrandbits(384),salt=i,
                saved=tuple(rng.getrandbits(64) for _ in range(6)))
        for ao,mo in [(0,96),(96,0),(0,0),(32,64)]:
            for dout in range(289 if member == 3 else 337):
                add(member,rng.getrandbits(384),rng.getrandbits(384),3,high=rng.getrandbits(384),ao=ao,mo=mo,dout=dout,salt=dout)
        for base in [0,1,0x1000,WORD-384,WORD-192]:
            for length in [0,47,48,95,96,143,144,191,192,239,240,287,288,383,384]:
                for ao,mo,dout in [(0,96,192),(0,0,0),(-1,96,192),(0,-1,192),(0,96,337),(-1,0,-1)]:
                    add(member,RANGE-1,RANGE-1,2,high=RANGE-1,base=base,ao=ao,mo=mo,dout=dout,length=length)
    return sorted(cases)


def fixture_bytes():
    inputs = bytearray();expected = bytearray()
    coverage = {'cases':0,'admitted':0,'refusals':0,'by_member':[0]*4,
                'admitted_by_member':[0]*4,'alias_admitted':0,'live_a_changes':0,
                'live_m_changes':0,'mask_counts':{},'raw_states':0,'equal_states':0,
                'zero_m':0,'one_m':0,'count_zero_low32':0,'count_high32':0}
    for row in corpus():
        registers,image,facts = relation(row)
        inputs.extend(struct.pack('<19Q',*row[:-1])+row[-1])
        expected.extend(struct.pack('<16Q',*registers)+image)
        coverage['cases'] += 1;coverage['by_member'][row[0]] += 1
        if facts['refused']:
            coverage['refusals'] += 1
        else:
            coverage['admitted'] += 1;coverage['admitted_by_member'][row[0]] += 1
            coverage['alias_admitted'] += facts['alias']
            coverage['live_a_changes'] += facts['a_live_changed']
            coverage['live_m_changes'] += facts['m_live_changed']
            for key,fact in [('raw_states','raw_state'),('equal_states','equal_state'),('zero_m','zero_m'),('one_m','one_m')]:
                coverage[key] += facts[fact]
            coverage['count_zero_low32'] += row[0] == 2 and row[6]%2**32 == 0
            coverage['count_high32'] += row[0] == 2 and row[6]>=2**32
            key = str(row[0])+':'+hex(facts['mask'])
            coverage['mask_counts'][key] = coverage['mask_counts'].get(key,0)+1
    return bytes(inputs),bytes(expected),coverage


def main():
    require(not (ROOT/'src/node94-repeated-doubling').exists(),'Freeze must precede Rust source')
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
