#!/usr/bin/env python3
"""Static byte/caller binding and an unbounded-power value oracle."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODY_SHA = '870d7451ce9ea720f99ed16dcdb9b410544afaf279db5803df18e0a14d683168'
CALLER_SHA = 'ed7af38f042124f8ca00f384c424099f3db890839e6e1721ccd679d07bc7a9b1'
START, END, PAD_END = 0x55c6c40, 0x55c6c77, 0x55c6c80
CALLER_START, CALLER_END, CALL = 0x555b930, 0x555bbf8, 0x555ba70
MAX = (1 << 32) - 1
SETUP_START = 0x555ba4b
SETUP = bytes.fromhex('f3410f6f064c894c24284883ec204c8944244044895c243c0f110424498b46104889442410e8cbb10600')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def listing(name, image, begin, end):
    rows, cursor = [], begin
    for line in (PACKET / name).read_text().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if match:
            address, raw = int(match[1], 16), bytes.fromhex(match[2])
            require(address == cursor and address + len(raw) <= end, 'listing coverage differs')
            require(image.va_bytes(address, len(raw), executable=True)[0] == raw, 'listing bytes differ')
            rows.append((address, raw))
            cursor += len(raw)
    require(cursor == end, 'listing incomplete')
    return rows


def inspect(data):
    image = Elf(data, 3)
    cies, frames = eh_frame_records(data)
    sections = {}
    for name, begin, end in [('window', START, END), ('caller', CALLER_START, CALLER_END)]:
        raw, mapping = image.va_bytes(begin, end - begin, executable=True)
        require(sha(raw) == (BODY_SHA if name == 'window' else CALLER_SHA),
                name + ' complete body differs')
        overlapping = [f for f in frames if f['start'] < end and begin < f['end']]
        require(len(overlapping) == 1 and overlapping[0]['start'] == begin and overlapping[0]['end'] == end,
                name + ' complete FDE differs')
        frame = overlapping[0]
        records = {}
        for kind in ['fde', 'cie']:
            address = frame[kind]
            size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
            value, where = image.va_bytes(address, size)
            records[kind] = {'va': address, 'file_offset': where['file_offset'], 'hex': value.hex()}
        rows = listing(name + '.gnu.txt', image, begin, end)
        llvm_rows = listing(name + '.llvm.txt', image, begin, end)
        require(rows == llvm_rows, 'decoder instruction boundaries differ')
        sections[name] = {'begin': begin, 'end': end, 'bytes': len(raw), 'hex': raw.hex(),
                          'sha256': sha(raw), 'file_offset': mapping['file_offset'],
                          'frame': frame, 'cie': cies[frame['cie']], 'records': records,
                          'instruction_starts': [address for address, _ in rows],
                          'llvm_raw_rows': len(llvm_rows)}
    body = bytes.fromhex(sections['window']['hex'])
    require(sections['window']['frame']['lsda'] is None, 'unexpected leaf LSDA')
    require(body[4:16] == bytes.fromhex('31c0837c2408017403c36690'), 'gate or internal NOP differs')
    branch_target = START + 13 + struct.unpack('b', body[12:13])[0]
    require(branch_target == START + 16 and branch_target in sections['window']['instruction_starts'],
            'gate destination differs')
    require(body[16:38] == bytes.fromhex('8b54240c8b442410be0800000039c289d10f46c229c1'),
            'stack loads or unsigned minimum differs')
    require(body[38:] == bytes.fromhex('b80100000048d3e089d148d3e64801f0c3'),
            '64-bit shifts or wrapping sum differs')
    require(image.va_bytes(END, PAD_END - END)[0] == b'\xcc' * 9, 'external padding differs')
    successor = [f for f in frames if f['start'] == PAD_END]
    require(len(successor) == 1 and successor[0]['end'] == 0x55c6c9d, 'successor FDE differs')
    require(image.va_bytes(SETUP_START, len(SETUP), executable=True)[0] == SETUP,
            'caller stack copy chain differs')
    require(image.va_bytes(0x555b93a, 3, executable=True)[0] == bytes.fromhex('4989f6'),
            'caller RSI to R14 origin differs')
    require(CALL in sections['caller']['instruction_starts'], 'call is not instruction aligned')
    require(image.va_bytes(CALL, 5)[0][0] == 0xe8 and
            CALL + 5 + struct.unpack('<i', image.va_bytes(CALL + 1, 4)[0])[0] == START,
            'caller destination differs')
    text = next(s for s in image.sections if s['name'] == '.text')
    code = image.va_bytes(text['address'], text['size'], executable=True)[0]
    candidates, position = [], 0
    while (position := code.find(b'\xe8', position)) >= 0:
        if position + 5 <= len(code) and text['address'] + position + 5 + struct.unpack_from('<i', code, position + 1)[0] == START:
            candidates.append(text['address'] + position)
        position += 1
    require(candidates == [CALL], 'direct-call candidate census differs')
    relocations = 0
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:
            continue
        require(section['entsize'] == 24 and section['size'] % 24 == 0, 'RELA shape differs')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            destination, _, addend = struct.unpack_from('<QQq', data, offset)
            require(not any(destination < high and low < destination + 8 for low, high in
                            [(START, PAD_END), (CALLER_START, CALLER_END)]), 'protected code relocation')
            require(addend != START, 'relocation names entry')
            relocations += 1
    return {'target_sha256': sha(data), 'target_bytes': len(data), 'sections': sections,
            'branches': [[START + 11, branch_target]], 'internal_nop': [START + 14, '6690'],
            'successor_fde': successor[0], 'padding_hex': 'cc' * 9,
            'caller_setup_hex': SETUP.hex(), 'caller_setup_start': SETUP_START,
            'caller_copy': {'bytes': 24, 'source': 'R14 (caller entry RSI)',
                            'destination': 'pre-call RSP', 'leaf_u32_offsets': [8, 12, 16]},
            'direct_e8_candidates': candidates, 'complete_caller_census': False,
            'rela_records_checked': relocations, 'external_leaf_data': [],
            'leaf_memory_writes': [], 'leaf_calls': [],
            'normal_return_domain': 'all u32 triples, with required stack reads and return address valid'}


def oracle(flag, first, second):
    """Mathematical powers in unbounded integers; no machine shifts/emulation."""
    if flag != 1:
        return 0
    exponent = max(first - second, 0) % 64
    return (2 ** exponent + 2 ** (3 + first % 64)) % (2 ** 64)


def fixtures():
    triples = set()
    # Exhaust all residue pairs in both unsigned order regions, twice: low
    # values and crossing the signed-u32 boundary. Include equal representatives.
    for a in range(64):
        for b in range(64):
            for first, second in [(64 + a, b), (a, 64 + b),
                                  (0x80000000 + a, b), (a, 0x80000000 + b)]:
                triples.add((1, first, second))
        for base in [0, 64, 0x7fffffc0, 0xffffffc0]:
            triples.add((1, base + a, base + a))
    edges = {0, 1, 2, 3, 31, 32, 33, 59, 60, 61, 62, 63, 64, 65,
             124, 125, 127, 128, 255, 256, 257, MAX}
    for power in range(32):
        edges.update(2 ** power + delta for delta in [-1, 0, 1]
                     if 0 <= 2 ** power + delta <= MAX)
    for first in edges:
        for second in edges:
            triples.add((1, first, second))
        for flag in [0, 2, 3, 0x80000001, MAX]:
            for second in [0, first, MAX]:
                triples.add((flag, first, second))
    for index in range(1024):
        raw = hashlib.sha256(f'stack-shift-sum94:{index}'.encode()).digest()
        first, second = struct.unpack('<II', raw[:8])
        triples.add((1, first, second))
        triples.add((struct.unpack('<I', raw[8:12])[0], first, second))
    triples = sorted(triples)
    values = [oracle(*triple) for triple in triples]
    for (flag, first, second), value in zip(triples, values):
        active_zero = first > second and first % 64 == 60 and second % 64 == 61
        require((value == 0) == (flag != 1 or active_zero), 'zero-result theorem differs')
    inputs = b''.join(struct.pack('<III', *triple) for triple in triples)
    expected = b''.join(struct.pack('<Q', value) for value in values)
    coverage = {'cases': len(triples), 'active_cases': sum(f == 1 for f, _, _ in triples),
                'inactive_cases': sum(f != 1 for f, _, _ in triples),
                'active_zero_cases': sum(f == 1 and v == 0 for (f, _, _), v in zip(triples, values)),
                'active_order_cases': {name: sum(f == 1 and relation(a, b) for f, a, b in triples)
                    for name, relation in [('less', lambda a, b: a < b), ('equal', lambda a, b: a == b),
                                           ('greater', lambda a, b: a > b)]},
                'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected),
                'oracle': 'unbounded integer powers: (2**(max(first-second,0)%64) + 2**(3+first%64)) % 2**64',
                'semantic_partition': 'all 4096 residue pairs in each strict order, low and signed-boundary representatives',
                'active_zero_iff': 'first>second and first%64==60 and second%64==61'}
    return inputs, expected, coverage


def validate():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity differs')
    record = inspect(data)
    leaf, caller = record['sections']['window'], record['sections']['caller']
    modifications = {'flag compare': leaf['file_offset'] + 10,
                     'gate polarity': leaf['file_offset'] + 11,
                     'first stack offset': leaf['file_offset'] + 19,
                     'unsigned minimum': leaf['file_offset'] + 34,
                     'first shift width': leaf['file_offset'] + 43,
                     'second shift': leaf['file_offset'] + 50,
                     'wrapping sum': leaf['file_offset'] + 52,
                     'internal NOP': leaf['file_offset'] + 14,
                     'padding': leaf['file_offset'] + END - START,
                     'leaf FDE extent': leaf['records']['fde']['file_offset'] + 12,
                     'caller FDE extent': caller['records']['fde']['file_offset'] + 12,
                     'caller stack allocation': caller['file_offset'] + 0x555ba58 - CALLER_START,
                     'caller copy': caller['file_offset'] + 0x555ba63 - CALLER_START,
                     'caller edge': caller['file_offset'] + CALL - CALLER_START}
    controls = {}
    for name, offset in modifications.items():
        changed = bytearray(data)
        changed[offset] ^= 1
        try:
            inspect(bytes(changed))
        except ValueError as error:
            controls[name] = str(error)
        else:
            raise ValueError('accepted structural corruption: ' + name)
    record['corruption_controls'] = controls
    inputs, expected, coverage = fixtures()
    return {'static.json': encoded(record), 'coverage.json': encoded(coverage)}, inputs, expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', action='store_true')
    args = parser.parse_args()
    records, inputs, expected = validate()
    archives = {'inputs.bin.gz': inputs, 'expected.bin.gz': expected}
    if args.freeze:
        require(all(not (PACKET / name).exists() for name in [*records, *archives]), 'freeze refuses overwrite')
        for name, raw in records.items():
            (PACKET / name).write_bytes(raw)
        for name, raw in archives.items():
            (PACKET / name).write_bytes(gzip.compress(raw, mtime=0))
    else:
        for name, raw in records.items():
            require((PACKET / name).read_bytes() == raw, name + ' drift')
        for name, raw in archives.items():
            require(gzip.decompress((PACKET / name).read_bytes()) == raw, name + ' drift')
    print(records['coverage.json'].decode(), end='')


if __name__ == '__main__':
    main()
