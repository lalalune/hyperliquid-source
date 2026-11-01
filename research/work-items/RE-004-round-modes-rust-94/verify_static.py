#!/usr/bin/env python3
"""Revalidate complete round-leaf bytes, constants, FDE and relocation binding."""
import argparse
import json
from pathlib import Path
import re
import struct
import sys

from oracle import ROOT, PACKET, require, sha
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BEGIN, END, SLOT = 0x565f410, 0x565f481, 0x576f6d8
BODY = 'f7c392977c4396033ea04a9e1ae21f5e7dc28b6318aedcf99b17b9ba4d6702e8'


def listing(path, image):
    rows, cursor = [], BEGIN
    for line in path.read_text().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if match:
            address, raw = int(match[1], 16), bytes.fromhex(match[2])
            require(address == cursor and address + len(raw) <= END, 'listing extent')
            require(image.va_bytes(address, len(raw), executable=True)[0] == raw, 'listing bytes')
            rows.append((address, raw))
            cursor += len(raw)
    require(cursor == END, 'incomplete listing')
    return rows


def inspect(data):
    image = Elf(data, 3)
    body, mapping = image.va_bytes(BEGIN, END - BEGIN, executable=True)
    require(sha(body) == BODY, 'round body hash')
    _, fdes = eh_frame_records(data)
    overlaps = [f for f in fdes if f['start'] < END and BEGIN < f['end']]
    require(len(overlaps) == 1 and overlaps[0]['start'] == BEGIN and overlaps[0]['end'] == END,
            'round unique complete FDE')
    frame, records = overlaps[0], {}
    for kind in ('fde', 'cie'):
        address = frame[kind]
        size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
        raw, location = image.va_bytes(address, size)
        records[kind] = {'va': address, 'file_offset': location['file_offset'],
                         'hex': raw.hex(), 'sha256': sha(raw)}
    rows = listing(PACKET / 'round.gnu.txt', image)
    require(rows == listing(PACKET / 'round.llvm.txt', image), 'decoder boundaries disagree')
    starts = {a for a, _ in rows}
    branches, returns = [], []
    for address, opcode in rows:
        if len(opcode) == 2 and 0x70 <= opcode[0] <= 0x7f:
            target = address + 2 + struct.unpack('b', opcode[1:])[0]
            require(target in starts, 'branch leaves instruction boundary')
            branches.append({'from': address, 'to': target, 'hex': opcode.hex()})
        if opcode == b'\xc3':
            returns.append(address)
    require(len(branches) == 2 and returns == [END - 1], 'branch/return closure')
    constants = []
    for instruction, address, prefix, expected in (
        (0x565f414, 0x2082f0, '660f2805', '0000000000000080' * 2),
        (0x565f420, 0x203ae0, '660f5605', 'ffffffffffffdf3f' * 2),
    ):
        raw, _ = image.va_bytes(instruction, 8, executable=True)
        require(raw[:4].hex() == prefix and
                instruction + 8 + struct.unpack('<i', raw[4:])[0] == address, 'constant read edge')
        value, location = image.va_bytes(address, 16)
        require(value.hex() == expected, 'constant value')
        constants.append({'instruction': instruction, 'va': address,
                          'file_offset': location['file_offset'], 'hex': value.hex()})
    relocation = image.relative(SLOT)
    require(relocation['addend'] == BEGIN, 'slot target')
    protected = [(BEGIN, END), (SLOT, SLOT + 8)] + [(x['va'], x['va'] + 16) for x in constants]
    count, writes = 0, []
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:
            continue
        require(section['entsize'] == 24 and section['size'] % 24 == 0, 'RELA shape')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            dest, info, addend = struct.unpack_from('<QQq', data, offset)
            count += 1
            if any(dest < hi and lo < dest + 8 for lo, hi in protected):
                require(dest == SLOT and info == 8 and addend == BEGIN, 'protected relocation')
                writes.append(offset)
    require(writes == [relocation['record_file_offset']], 'nonunique slot write')
    return {'target_sha256': sha(data), 'target_bytes': len(data),
            'body': {'begin': BEGIN, 'end': END, 'bytes': len(body), 'hex': body.hex(),
                     'sha256': sha(body), 'file_offset': mapping['file_offset'],
                     'instructions': len(rows), 'branches': branches, 'returns': returns},
            'frame': frame, 'frame_records': records, 'constants': constants,
            'relocation': relocation, 'rela_records_checked': count,
            'captured_code_executed': False, 'instruction_emulation': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(sha(data) == TARGET, 'target identity')
    record = inspect(data)
    locations = {'body': record['body']['file_offset'] + 0x18,
                 'FDE extent': record['frame_records']['fde']['file_offset'] + 12,
                 'slot addend': record['relocation']['record_file_offset'] + 16}
    locations.update({f'constant {i}': x['file_offset'] for i, x in enumerate(record['constants'])})
    rejected = {}
    for name, offset in locations.items():
        changed = bytearray(data)
        changed[offset] ^= 1
        try:
            inspect(bytes(changed))
        except ValueError as error:
            rejected[name] = str(error)
        else:
            raise ValueError('accepted corrupted ' + name)
    record['corruption_controls'] = rejected
    text = json.dumps(record, indent=2, sort_keys=True) + '\n'
    if args.write:
        with (PACKET / 'static.json').open('x') as file:
            file.write(text)
    else:
        require((PACKET / 'static.json').read_text() == text, 'retained static record drift')
    print(json.dumps({'instructions': record['body']['instructions'],
                      'corruption_controls': rejected}, indent=2))


if __name__ == '__main__':
    main()
