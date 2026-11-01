#!/usr/bin/env python3
"""Bind arithmetic expectations to the captured leaf; never execute its code."""
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
BODY_SHA = '30eff3374e960cd9973a58b50251b45a09b8e4c9b4976817a932f71e34f7ca53'
START, END, NEXT = 0x555e610, 0x555e65b, 0x555e660
CUTOFF, SENTINEL = 0xff00ff00ff00feff, (1 << 64) - 72
SMALL_END, MODULUS = 1 << 17, 1 << 64


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def listing(name, image):
    rows, cursor = [], START
    for line in (PACKET / name).read_text().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if match:
            address, raw = int(match[1], 16), bytes.fromhex(match[2])
            require(address == cursor and address + len(raw) <= END, 'listing coverage')
            require(image.va_bytes(address, len(raw), executable=True)[0] == raw, 'listing bytes')
            rows.append((address, raw))
            cursor += len(raw)
    require(cursor == END, 'incomplete listing')
    return rows


def inspect(data):
    """Structural validation below the separate full-file digest admission."""
    image = Elf(data, 3)
    raw, location = image.va_bytes(START, END - START, executable=True)
    require(sha(raw) == BODY_SHA, 'complete body hash differs')
    require(image.va_bytes(END, NEXT - END)[0] == b'\xcc' * 5, 'stride padding differs')
    cies, frames = eh_frame_records(data)
    selected = [f for f in frames if f['start'] < END and START < f['end']]
    require(len(selected) == 1 and selected[0]['start'] == START and selected[0]['end'] == END,
            'selected FDE extent differs')
    successor = [f for f in frames if f['start'] == NEXT]
    require(len(successor) == 1 and successor[0]['end'] == 0x555e66c, 'successor FDE differs')
    frame = selected[0]
    require(frame['lsda'] is None, 'unexpected leaf LSDA')
    records = {}
    for name, address in [('fde', frame['fde']), ('cie', frame['cie']),
                          ('next_fde', successor[0]['fde'])]:
        size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
        value, where = image.va_bytes(address, size)
        records[name] = {'va': address, 'file_offset': where['file_offset'], 'hex': value.hex()}
    require(cies[frame['cie']]['augmentation'] == 'zR', 'unexpected CIE augmentation')
    rows = listing('window.gnu.txt', image)
    require(rows == listing('window.llvm.txt', image), 'decoder boundaries disagree')
    require([address - START for address, _ in rows] ==
            [0, 4, 14, 21, 24, 26, 29, 33, 36, 43, 45, 50, 53, 57, 60, 63, 70, 74],
            'instruction start map differs')
    require(raw[24:26] == bytes.fromhex('7230') and START + 26 + 0x30 == END - 1,
            'cutoff branch differs')
    require(raw[43:45] == bytes.fromhex('770f') and START + 45 + 15 == START + 60,
            'small-path branch differs')
    require(struct.unpack_from('<Q', raw, 6)[0] == CUTOFF and
            struct.unpack_from('<i', raw, 17)[0] == -72 and
            struct.unpack_from('<i', raw, 66)[0] == -72, 'cutoff or sentinel differs')
    relocations = 0
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:
            continue
        require(section['entsize'] == 24 and section['size'] % 24 == 0, 'RELA shape differs')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            destination, _, addend = struct.unpack_from('<QQq', data, offset)
            require(not (destination < NEXT and START < destination + 8), 'body/padding relocation')
            require(addend != START, 'relocation names entry')
            relocations += 1
    return {'target_sha256': sha(data), 'target_bytes': len(data),
            'start_va': START, 'end_va_exclusive': END, 'file_offset': location['file_offset'],
            'body_hex': raw.hex(), 'body_sha256': sha(raw), 'instructions': len(rows),
            'fde': frame, 'cie': cies[frame['cie']], 'records': records,
            'padding_hex': 'cc' * 5, 'rela_records_checked': relocations,
            'data_dependencies': 'Immediate constants only; ret requires valid return stack',
            'outgoing_calls': [], 'branches': [[START + 24, END - 1], [START + 43, START + 60]]}


def oracle(n):
    """Independent quotient/remainder grouping, not an instruction evaluator."""
    if n > CUTOFF:
        return SENTINEL
    if n < SMALL_END:
        block, residue = divmod(n, 2048)
        return 2055 * block + residue + residue // 256 + 64 - int(residue != 0)
    return (257 * n) // 256


def fixtures():
    values = set(range(SMALL_END))
    collision = 0xff00ff00ff00feba
    for anchor in [SMALL_END, 1 << 32, 1 << 63, collision, CUTOFF, CUTOFF + 2, MODULUS - 1]:
        values.update(anchor + delta for delta in range(-257, 258)
                      if 0 <= anchor + delta < MODULUS)
        block = anchor // 256
        values.update(256 * block + residue for residue in range(256)
                      if 256 * block + residue < MODULUS)
    values.update(CUTOFF + 1 + (MODULUS - CUTOFF - 2) * i // 256 for i in range(257))
    values.update(int.from_bytes(hashlib.sha256(f'mask-rounding94:{i}'.encode()).digest()[:8], 'little')
                  for i in range(1024))
    values = sorted(values)
    inputs = b''.join(struct.pack('<Q', n) for n in values)
    expected = b''.join(struct.pack('<Q', oracle(n)) for n in values)
    # Exact monotone large-path and grouped small-path bounds, not samples.
    require((257 * CUTOFF) // 256 == MODULUS - 3, 'admitted upper bound')
    require((257 * collision) // 256 == SENTINEL, 'admitted sentinel collision')
    require((257 * (CUTOFF + 2)) // 256 == MODULUS, 'first excluded arithmetic wrap')
    small = [oracle(n) for n in range(SMALL_END)]
    require(min(small) == 64 and max(small) == 131582 and all(small), 'small domain bounds')
    coverage = {'cases': len(values), 'small_domain_cases': SMALL_END,
                'small_residues_mod2048': len({n % 2048 for n in values if n < SMALL_END}),
                'large_admitted_cases': sum(SMALL_END <= n <= CUTOFF for n in values),
                'rejected_cases': sum(n > CUTOFF for n in values),
                'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected),
                'small_bounds': [min(small), max(small)],
                'large_admitted_bounds': [131584, MODULUS - 3],
                'internal_zero_reachable': False,
                'admitted_sentinel_preimage': collision,
                'first_excluded_arithmetic_wrap_input': CUTOFF + 2,
                'oracle': 'Grouped 2048-block formula for small inputs; floor(257*n/256) for large inputs'}
    return inputs, expected, coverage


def validate():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity differs')
    record = inspect(data)
    changes = {'body': record['file_offset'], 'cutoff': record['file_offset'] + 6,
               'sentinel': record['file_offset'] + 17, 'small limit': record['file_offset'] + 39,
               'zero cmove': record['file_offset'] + 72,
               'padding': record['file_offset'] + END - START,
               'FDE extent': record['records']['fde']['file_offset'] + 12,
               'CIE encoding': record['records']['cie']['file_offset'] + 16}
    controls = {}
    for name, offset in changes.items():
        changed = bytearray(data)
        changed[offset] ^= 1
        try:
            inspect(bytes(changed))
        except ValueError as error:
            controls[name] = str(error)
        else:
            raise ValueError('accepted static corruption: ' + name)
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
        require(all(not (PACKET / name).exists() for name in [*records, *archives]),
                'freeze refuses to overwrite evidence')
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
