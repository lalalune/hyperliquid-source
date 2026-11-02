"""Pre-Rust whole-integer oracle for the five-word masked-top coefficient combination."""
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
STARTS = [0x565e960]
LOCK_SHA = '3a02def99eae064b5a4490ab86c200f8bf83fdf71900be9a77faeb6f2ea39658'
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
            require(len(memory) == 15, 'Memory closure changed')
            require(all(i.mnemonic == 'mov' and '[rsi' in i.op_str for i in memory[:10]), 'All snapshot reads precede stores')
            require(all(i.mnemonic == 'mov' and i.op_str.startswith('qword ptr [rdi') for i in memory[10:]), 'Five ordered qword stores changed')
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


IMAGE_SIZE = 128
INPUT_SIZE = 168
OUTPUT_SIZE = 240


def contribution(value, raw_coefficient):
    signed = raw_coefficient if raw_coefficient < WORD//2 else raw_coefficient-WORD
    magnitude = abs(signed)
    transformed = (value if signed >= 0 else -value) % WORD**5
    low, top = transformed % WORD**4, transformed // WORD**4
    product = low*magnitude
    corrected = (product - (top & magnitude)*WORD**4) % WORD**5
    last_product = (low//WORD**3)*magnitude
    return corrected, magnitude, last_product


def relation(row):
    ca, cb, source, destination, length, raw = row
    if source+80 > length or destination+40 > length:
        return (0,)*14, raw, {'refused': True}
    a = int.from_bytes(raw[source:source+40], 'little')
    b = int.from_bytes(raw[source+40:source+80], 'little')
    pa, _, _ = contribution(a, ca)
    pb, magnitude, last = contribution(b, cb)
    total = (pa+pb) % WORD**5
    limbs = lambda value, count: tuple(value//WORD**i % WORD for i in range(count))
    out = limbs(total, 5)
    # RAX,RDX are the final second contribution's raw 64x64 MUL result.
    # RCX is that contribution's corrected high word; RBP is the sum's high.
    registers = (last % WORD, last//WORD, magnitude, pb//WORD**4,
                 out[4], *out[:4], *limbs(pb, 4))
    updated = raw[:destination]+total.to_bytes(40, 'little')+raw[destination+40:]
    return (1, *registers), updated, {'refused': False, 'coeff_signs': (ca >= WORD//2, cb >= WORD//2),
                                      'overlap': source < destination+40 and destination < source+80,
                                      'noncanonical_top': a//WORD**4 not in (0, WORD-1) or b//WORD**4 not in (0, WORD-1)}


def corpus():
    cases = set()
    def add(a, b, ca, cb, source=0, destination=80, length=128, salt=0):
        raw = bytearray((i*73+salt)%256 for i in range(IMAGE_SIZE))
        if source+80 <= IMAGE_SIZE:
            raw[source:source+40] = a.to_bytes(40, 'little')
            raw[source+40:source+80] = b.to_bytes(40, 'little')
        cases.add((ca, cb, source, destination, length, bytes(raw)))
    full = WORD**5
    values = {0, 1, full-1, full//2, full//2-1, WORD**4-1, WORD**4, WORD**4+1}
    for bit in range(320):
        values.update(((1 << bit)-1, 1 << bit, ((1 << bit)+1) % full))
    coeffs = [0, 1, 2, 3, WORD//2-1, WORD//2, WORD//2+1, WORD-2, WORD-1, 0x5555555555555555, 0xaaaaaaaaaaaaaaaa]
    for i, value in enumerate(sorted(values)):
        for ca, cb in [(1,1),(WORD-1,1),(1,WORD-1),(WORD-1,WORD-1),(WORD//2,WORD//2),(0,1),(1,0)]:
            add(value, (full-1)^value, ca, cb, salt=i)
    # Every coefficient rank, including MIN, with top-mask witnesses for both terms.
    for bit in range(64):
        for delta in [-1, 0, 1]:
            c = ((1 << bit)+delta) % WORD
            for top in [0, WORD-1, 1 << bit, (WORD-1) ^ (1 << bit), 0x5555555555555555]:
                a = top*WORD**4 + WORD**4-1
                for coefficient in [c, (-c)%WORD]:
                    add(a, 1, coefficient, 0)
                    add(1, a, 0, coefficient)
    for ca in coeffs:
        for cb in coeffs:
            for a,b in [(0,0),(full-1,full-1),(WORD**4,WORD**4),(WORD**4-1,WORD**4-1),(full//2,full//2)]:
                add(a,b,ca,cb)
    rng = random.Random(0x565e960)
    for i in range(1800):
        add(rng.getrandbits(320), rng.getrandbits(320), rng.getrandbits(64), rng.getrandbits(64), salt=i)
    # Dense arbitrary byte aliases: all eighty reads precede the first store.
    for source in [0,1,8,16,32,47,48]:
        for destination in range(89):
            add(rng.getrandbits(320),rng.getrandbits(320),rng.choice(coeffs),rng.choice(coeffs),source,destination,salt=destination)
    for source,destination in [(0,80),(1,81),(48,0),(48,88),(49,0),(0,89),(WORD-1,0),(0,WORD-1)]:
        for length in [0,39,40,79,80,119,120,127,128]:
            add(WORD**4-1,full-1,WORD-1,WORD//2,source,destination,length)
    return sorted(cases)


def fixture_bytes():
    inputs = bytearray()
    expected = bytearray()
    coverage = {'cases': 0, 'admitted': 0, 'refusals': 0, 'overlap_admitted': 0,
                'noncanonical_top_admitted': 0, 'coefficient_signs': {}}
    for row in corpus():
        output, image, facts = relation(row)
        inputs.extend(struct.pack('<5Q', *row[:5])+row[5])
        expected.extend(struct.pack('<14Q', *output)+image)
        coverage['cases'] += 1
        if facts['refused']:
            coverage['refusals'] += 1
        else:
            coverage['admitted'] += 1
            coverage['overlap_admitted'] += facts['overlap']
            coverage['noncanonical_top_admitted'] += facts['noncanonical_top']
            key = ''.join(str(int(x)) for x in facts['coeff_signs'])
            coverage['coefficient_signs'][key] = coverage['coefficient_signs'].get(key, 0)+1
    return bytes(inputs), bytes(expected), coverage


def main():
    require(not (ROOT/'src/node94-five-word-combine').exists(), 'Freeze must precede Rust source')
    facts = admit()
    inputs, expected, coverage = fixture_bytes()
    folder = PACKET/'frozen'
    folder.mkdir()
    for name, raw in [('inputs.bin', inputs), ('expected.bin', expected)]:
        (folder/(name+'.gz')).write_bytes(gzip.compress(raw, mtime=0))
    record = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'oracle_source_sha256': digest(__file__), 'static_facts': facts, 'coverage': coverage,
              'inputs_sha256': hashlib.sha256(inputs).hexdigest(),
              'expected_sha256': hashlib.sha256(expected).hexdigest(),
              'rust_source_existed': False, 'captured_execution': False}
    (folder/'ORACLE-FREEZE.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k != 'static_facts'}, indent=2))


if __name__ == '__main__':
    main()
