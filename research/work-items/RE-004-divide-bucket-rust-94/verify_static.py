#!/usr/bin/env python3
"""Static byte/caller binding and a division-free threshold oracle."""
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
BODY_SHA = '6a5f51de0418a80d23313f6f8c849a6058bff5676858fa9a292cd9266b5b5011'
START, END, PAD_END = 0x4f9eb10, 0x4f9eb82, 0x4f9eb90
CALLER_START, CALLER_END, CALL = 0x4f9cf20, 0x4f9d393, 0x4f9d240
MAX = (1 << 64) - 1
SETUP = bytes.fromhex('be000008004c89f744898d78ffffff4c894580894d90f20f118d70fffffff20f114588e8cb180000')


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
        if name == 'window':
            require(sha(raw) == BODY_SHA, 'complete leaf body differs')
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
        # Apple's printer emits LOCK as a separate row in this caller. Join
        # only that prefix with its contiguous successor; retain raw exports
        # and every joined address. No instruction bytes are discarded/masked.
        joined, prefix_rows, index = [], [], 0
        while index < len(llvm_rows):
            address, value = llvm_rows[index]
            if value == b'\xf0':
                require(index + 1 < len(llvm_rows) and llvm_rows[index + 1][0] == address + 1,
                        'noncontiguous LOCK printer row')
                prefix_rows.append(address)
                value += llvm_rows[index + 1][1]
                index += 1
            joined.append((address, value))
            index += 1
        require(rows == joined, 'decoder boundaries differ after explicit LOCK-row grouping')
        sections[name] = {'begin': begin, 'end': end, 'bytes': len(raw), 'hex': raw.hex(),
                          'sha256': sha(raw), 'file_offset': mapping['file_offset'],
                          'frame': frame, 'cie': cies[frame['cie']], 'records': records,
                          'instruction_starts': [address for address, _ in rows],
                          'llvm_raw_rows': len(llvm_rows), 'llvm_joined_lock_prefix_rows': prefix_rows}
    body = bytes.fromhex(sections['window']['hex'])
    require(sections['window']['frame']['lsda'] is None, 'unexpected leaf LSDA')
    require(body[4:12] == bytes.fromhex('31d24889f848f7f6'), 'zero high dividend/unsigned divide differs')
    branches = []
    starts = sections['window']['instruction_starts']
    for offset, target in [(0x12, 0x50), (0x1b, 0x58), (0x24, 0x60), (0x2d, 0x66), (0x36, 0x6c)]:
        require(body[offset] == 0x74 and offset + 2 + struct.unpack('b', body[offset + 1:offset + 2])[0] == target,
                'conditional branch differs')
        require(START + target in starts, 'branch target is not an instruction start')
        branches.append([START + offset, START + target])
    require(body[0x38:0x46] == bytes.fromhex('48c1e8060f95c00fb6c083c005c3'), 'arithmetic cap differs')
    nops = [(0x46, '662e0f1f840000000000'), (0x53, '0f1f440000'), (0x5e, '6690')]
    for offset, value in nops:
        require(body[offset:offset + len(bytes.fromhex(value))].hex() == value, 'internal NOP differs')
    require(image.va_bytes(END, PAD_END - END)[0] == b'\xcc' * 14, 'external padding differs')
    successor = [f for f in frames if f['start'] == PAD_END]
    require(len(successor) == 1 and successor[0]['end'] == 0x4f9eba5, 'successor FDE differs')
    require(image.va_bytes(0x4f9d21d, len(SETUP), executable=True)[0] == SETUP, 'caller argument chain differs')
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
            'branches': branches, 'internal_nops': nops, 'successor_fde': successor[0],
            'padding_hex': 'cc' * 14, 'caller_setup_hex': SETUP.hex(),
            'caller_setup_start': 0x4f9d21d, 'observed_caller_divisor': 0x80000,
            'direct_e8_candidates': candidates, 'complete_caller_census': False,
            'rela_records_checked': relocations, 'external_leaf_data': [],
            'zero_divisor_target_result': 'no normal return; safe API refusal is newly chosen'}


def oracle(dividend, divisor):
    """No division, bit length, floating logarithm or instruction evaluator."""
    if divisor == 0:
        return bytes([0, 0])  # Newly chosen API refusal, not a target return.
    return bytes([1, sum(dividend >= (1 << power) * divisor for power in range(1, 7))])


def fixtures():
    divisors = {0, 1, 2, 3, 5, 7, 255, 256, 257, 0x7ffff, 0x80000, 0x80001, MAX}
    for power in range(64):
        divisors.update((1 << power) + delta for delta in [-1, 0, 1]
                        if 0 <= (1 << power) + delta <= MAX)
    pairs = set()
    for divisor in divisors:
        pairs.update((n, divisor) for n in [0, 1, divisor - 1, divisor, divisor + 1, MAX]
                     if 0 <= n <= MAX)
        if divisor:
            for quotient in [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128]:
                for residue in [0, 1, divisor - 1]:
                    n = quotient * divisor + residue
                    if n <= MAX:
                        pairs.add((n, divisor))
            for power in range(1, 7):
                threshold = (1 << power) * divisor
                pairs.update((threshold + delta, divisor) for delta in [-1, 0, 1]
                             if 0 <= threshold + delta <= MAX)
        pairs.add((divisor, 0))
    for index in range(1024):
        raw = hashlib.sha256(f'divide-bucket94:{index}'.encode()).digest()
        pairs.add(struct.unpack('<QQ', raw[:16]))
    pairs = sorted(pairs)
    inputs = b''.join(struct.pack('<QQ', *pair) for pair in pairs)
    expected = b''.join(oracle(*pair) for pair in pairs)
    normal = [oracle(n, d)[1] for n, d in pairs if d]
    coverage = {'cases': len(pairs), 'normal_return_cases': len(normal),
                'zero_divisor_refusal_cases': len(pairs) - len(normal),
                'bucket_counts': {str(k): normal.count(k) for k in range(7)},
                'observed_caller_divisor_cases': sum(d == 0x80000 for _, d in pairs),
                'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected),
                'oracle': 'count true unbounded inequalities dividend >= 2^k * divisor, k=1..6',
                'zero_case': 'new API refusal; no target output asserted'}
    return inputs, expected, coverage


def validate():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity differs')
    record = inspect(data)
    leaf, caller = record['sections']['window'], record['sections']['caller']
    modifications = {'zero high dividend': leaf['file_offset'] + 4,
                     'unsigned divide': leaf['file_offset'] + 11,
                     'shift cap': leaf['file_offset'] + 0x3b,
                     'arithmetic cap condition': leaf['file_offset'] + 0x3d,
                     'internal NOP': leaf['file_offset'] + 0x46,
                     'padding': leaf['file_offset'] + END - START,
                     'leaf FDE extent': leaf['records']['fde']['file_offset'] + 12,
                     'caller FDE extent': caller['records']['fde']['file_offset'] + 12,
                     'caller divisor': caller['file_offset'] + 0x4f9d21e - CALLER_START,
                     'caller intervening store': caller['file_offset'] + 0x4f9d225 - CALLER_START,
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
