#!/usr/bin/env python3
"""RE-012 static common output-option producer, bound exclusively to node115."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-node115-cli-common-settings'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_BYTES = 105896032


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.cies, self.fdes = eh_frame_records(data, self.sections)
        self.relocations = {}
        for section in self.sections:
            if section['name'] != '.rela.dyn':
                continue
            require(section['size'] % 24 == 0, 'RELA entry width')
            for pos in range(section['offset'], section['offset'] + section['size'], 24):
                slot, info, addend = struct.unpack_from('<QQq', data, pos)
                self.relocations.setdefault(slot, []).append(
                    {'slot': hex(slot), 'type': info & 0xffffffff,
                     'symbol': info >> 32, 'addend': hex(addend)})

    def offset(self, va, size):
        matches = [section['offset'] + va - section['address']
                   for section in self.sections if section['type'] != 8
                   and section['address'] <= va
                   and va + size <= section['address'] + section['size']]
        require(len(matches) == 1 and size >= 0, 'unambiguous mapped interval')
        return matches[0]

    def read(self, va, size):
        start = self.offset(va, size)
        return self.data[start:start + size]

    def fde(self, start, end):
        matches = [f for f in self.fdes if f['start'] == start]
        require(len(matches) == 1 and matches[0]['end'] == end, 'FDE extent')
        return matches[0]

    def relative(self, va, opcode):
        raw = self.read(va, len(opcode) + 4)
        require(raw.startswith(opcode), 'relative instruction opcode')
        return va + len(raw) + struct.unpack_from('<i', raw, len(opcode))[0]

    def writer(self, slot, target):
        actual = self.relocations.get(slot, [])
        require(actual == [{'slot': hex(slot), 'type': 8, 'symbol': 0,
                            'addend': hex(target)}], 'exact RELATIVE writer')
        return actual[0]


def validate_anchors(image, spec):
    for anchor in spec['anchors']:
        require(image.read(int(anchor['va'], 16), len(bytes.fromhex(anchor['hex'])))
                == bytes.fromhex(anchor['hex']), 'anchor: ' + anchor['label'])


def splice(chunks, size):
    result = [None] * size
    for offset, data in chunks:
        require(offset >= 0 and offset + len(data) <= size, 'comparison chunk bounds')
        for index, value in enumerate(data, offset):
            require(result[index] is None or result[index] == value,
                    'comparison overlap')
            result[index] = value
    require(all(value is not None for value in result), 'complete comparison bytes')
    return bytes(result).decode('ascii')


def style_names(image):
    # Original complete comparison operands, not guessed zero-terminated pools.
    return [
        splice([(0, image.read(0x565985e, 4)),
                (3, image.read(0x5659865, 4))], 7),
        splice([(0, image.read(0x5659877, 8)),
                (6, image.read(0x5659884, 8))], 14),
        splice([(0, image.read(0x450640, 16)),
                (5, image.read(0x454130, 16))], 21),
    ]


def read_options(image, spec):
    validate_anchors(image, spec)
    options = []
    for expected in spec['options']:
        va = int(expected['nameWriter'], 16)
        raw = image.read(va, 7)
        require(raw[:3] in (b'\x48\x8d\x05', b'\x4c\x8d\x3d'),
                'option-name RIP LEA')
        name_va = va + 7 + struct.unpack_from('<i', raw, 3)[0]
        length_raw = image.read(int(expected['lengthWriter'], 16), 12)
        require(length_raw[:4] == b'\x48\xc7\x84\x24', 'name-length store')
        length = struct.unpack_from('<I', length_raw, 8)[0]
        name = image.read(name_va, length).decode('ascii')
        require(name == expected['longName'], 'exact long option name')
        flag_raw = image.read(int(expected['flagWriter'], 16), 11)
        require(flag_raw[:3] == b'\xc7\x84\x24', 'flag store')
        flags = struct.unpack_from('<I', flag_raw, 7)[0]
        require(flags == expected['flags'], 'initial option flags')
        call = int(expected['registration'], 16)
        require(image.relative(call, b'\xff\x15') == 0x64e1cf0,
                'argument-registration call slot')
        options.append({'order': len(options) + 1, 'longName': name,
                        'literalVA': hex(name_va), 'length': length,
                        'initialFlags': hex(flags), 'registration': hex(call)})
    image.writer(0x64e1cf0, 0x1638840)
    require(len(options) == 14, 'complete local registration count')
    return options


def lsda_table(image, function):
    if function['lsda'] is None:
        return None
    va = function['lsda']
    start = image.offset(va, 1)
    section = next(s for s in image.sections if s['type'] != 8
                   and s['address'] <= va < s['address'] + s['size'])
    end = section['offset'] + section['size']
    pos = start

    def byte():
        nonlocal pos
        require(pos < end, 'LSDA byte bounds')
        value = image.data[pos]
        pos += 1
        return value

    def uleb():
        value = shift = 0
        while True:
            require(shift <= 63, 'LSDA ULEB width')
            part = byte()
            value |= (part & 127) << shift
            if not part & 128:
                require(value < 1 << 64, 'LSDA ULEB overflow')
                return value
            shift += 7

    require(byte() == 255, 'LSDA omitted LPStart')
    type_encoding = byte()
    require(type_encoding in (255, 155), 'LSDA type encoding')
    type_offset = None if type_encoding == 255 else uleb()
    encoding_va = va + pos - start
    require(byte() == 1, 'LSDA call-site encoding')
    table_size = uleb()
    table_end = pos + table_size
    require(table_end <= end, 'LSDA table bounds')
    sites = []
    while pos < table_end:
        offset, length, landing, action = uleb(), uleb(), uleb(), uleb()
        require(pos <= table_end and function['start'] + offset + length <= function['end'],
                'LSDA call interval')
        require(not landing or function['start'] <= function['start'] + landing < function['end'],
                'LSDA landing interval')
        sites.append({'start': hex(function['start'] + offset),
                      'end': hex(function['start'] + offset + length),
                      'landing': hex(function['start'] + landing) if landing else None,
                      'action': action})
    require(pos == table_end, 'LSDA exact table end')
    return {'va': hex(va), 'callSiteEncodingVA': hex(encoding_va),
            'typeEncoding': type_encoding, 'typeOffset': type_offset,
            'raw': image.data[start:pos].hex(), 'sites': sites,
            'limits': 'Action/type chains and arbitrary callee unwinding remain unresolved.'}


def derive(image, spec):
    require(spec['targetSHA256'] == TARGET_SHA256 and spec['targetBytes'] == TARGET_BYTES,
            'sole node115 identity')
    options = read_options(image, spec)
    functions = []
    for entry in spec['functions']:
        start, end = int(entry['start'], 16), int(entry['end'], 16)
        fde = image.fde(start, end)
        raw = image.read(start, end - start)
        functions.append({'name': entry['name'], 'start': hex(start), 'end': hex(end),
                          'bytes': len(raw), 'fileOffset': hex(image.offset(start, len(raw))),
                          'sha256': hashlib.sha256(raw).hexdigest(), 'raw': raw.hex(),
                          'fde': fde, 'cie': image.cies[fde['cie']],
                          'exceptionTable': lsda_table(image, fde)})
    vtables = []
    for table, targets in [(0x64aacf8, [0x561fb30, 0x564e0f0, 0x564e0f0]),
                           (0x64aa908, [0x5620110, 0x5659830, 0x5659830])]:
        require(image.read(table, 24) == struct.pack('<QQQ', 0, 0, 1), 'validator vtable header')
        vtables.append({'va': hex(table), 'header': [0, 0, 1],
                        'writers': [image.writer(table + 24 + index * 8, target)
                                    for index, target in enumerate(targets)]})
    require(style_names(image) == ['actions', 'recent-actions', 'actions-and-responses'],
            'exact validator comparison strings')
    # Both observed storage branches write the same alias entry and false byte.
    alias = image.read(0x92adf4, 13).decode('ascii')
    require(alias == 'serve-eth-rpc', 'exact alias string')
    require(image.relative(0x5658d67, b'\x48\x8d\x0d') == 0x92adf4
            and image.relative(0x5658dc6, b'\x48\x8d\x15') == 0x92adf4,
            'both alias pointer writers')
    require(image.relative(0x565945e, b'\x48\x8d\x05') == 0x92aca0
            and image.read(0x92aca0, 7) == b'actions', 'style internal name')
    require(image.relative(0x56594c9, b'\x48\x8d\x05') == 0x92acb8
            and image.read(0x92acb8, 5) == b'0.1.0', 'returned App version')
    naming = [row for rows in image.relocations.values() for row in rows
              if row['addend'] == '0x5656bf0']
    require(naming == [{'slot': '0x64ebcc8', 'type': 8, 'symbol': 0,
                        'addend': '0x5656bf0'}], 'complete actual constructor naming writers')
    callers = []
    factory = image.fde(0x564e1a0, 0x56544a9)
    for site in (0x564e250, 0x564e336):
        require(image.relative(site, b'\xff\x15') == 0x64ebcc8, 'factory call')
        callers.append({'site': hex(site), 'bytes': image.read(site, 6).hex(),
                        'ownerFDE': factory, 'ownership': 'Prior PR2497 context, not new coverage.'})
    return {'schemaVersion': 1, 'targetSHA256': TARGET_SHA256,
            'options': options, 'functions': functions, 'vtables': vtables,
            'alias': {'name': alias, 'length': 13, 'entryByte': 0,
                      'sites': ['0x5658d67', '0x5658dc6'],
                      'interpretation': 'Hidden alias correspondence to licensed Clap, not a vendor-version or parser-equivalence claim.'},
            'style': {'internalName': 'actions', 'longName': 'replica-cmds-style',
                      'acceptedComparisons': style_names(image),
                      'successFirstQword': '0x8000000000000000',
                      'errorText': image.read(0x94a8dc, 26).decode('ascii')},
            'constructorNamingRelocations': naming, 'factoryCallSites': callers,
            'masks': [], 'capturedExecution': False,
            'limits': ['No Rust implementation, parser equivalence, stable ABI or whole-node gate.',
                       'Shared registration, allocation, memcpy, drop and grammar helpers retain their separate boundaries.',
                       'No arbitrary input/output aliasing or concurrent-mutation contract is inferred.']}


def collect(data, spec):
    require(len(data) == TARGET_BYTES and hashlib.sha256(data).hexdigest() == TARGET_SHA256,
            'target size/SHA256')
    return derive(Image(data), spec)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--spec', type=Path, default=PACKET / 'spec.json')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    records = collect(args.target.read_bytes(), json.loads(args.spec.read_text(encoding='utf-8')))
    args.output.write_text(json.dumps(records, indent=2) + '\n', encoding='utf-8', newline='\n')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error, KeyError) as error:
        print('node115-cli-common-settings: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
