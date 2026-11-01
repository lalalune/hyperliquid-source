#!/usr/bin/env python3
"""Bind the full record-copy body, GOT relocation and four indirect calls."""
import argparse
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
START, END, SLOT = 0x3818d40, 0x3818dc4, 0x5775570
RANGES = [
    ('window', START, END, 'b71e7d985a8e36e530abbe68d074df86d2ad0d0700525d85bc2902baedc474df'),
    ('caller1', 0x326b090, 0x326cfb3, 'f4bb1602abd69472ac9080331d5d9600593a3e8ae9ea7aaa6709497c2b0d7662'),
    ('caller2', 0x3284c70, 0x3284d85, 'acbb6844cc39474c2835d9fe0b4b94531142ed971db1676afd6c3d5e790b1287'),
]
CALLS = [0x326b4b1, 0x326b9b5, 0x326c50d, 0x3284c87]


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
            rows.append((address, raw)); cursor += len(raw)
    require(cursor == end, 'listing incomplete')
    return rows


def inspect(data):
    image = Elf(data, 3)
    cies, frames = eh_frame_records(data)
    def frame_record(begin, end):
        overlapping = [f for f in frames if f['start'] < end and begin < f['end']]
        require(len(overlapping) == 1 and (overlapping[0]['start'], overlapping[0]['end']) == (begin, end),
                'complete unique FDE differs')
        frame, records = overlapping[0], {}
        for kind in ['fde', 'cie']:
            address = frame[kind]
            size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
            raw, where = image.va_bytes(address, size)
            records[kind] = {'va': address, 'file_offset': where['file_offset'], 'hex': raw.hex()}
        return {'frame': frame, 'cie': cies[frame['cie']], 'records': records}
    sections = {}
    for name, begin, end, digest in RANGES:
        raw, mapping = image.va_bytes(begin, end - begin, executable=True)
        require(sha(raw) == digest, name + ' complete body differs')
        rows = listing(name + '.gnu.txt', image, begin, end)
        llvm = listing(name + '.llvm.txt', image, begin, end)
        joined, prefixes, index = [], [], 0
        while index < len(llvm):
            address, value = llvm[index]
            if value == b'\xf0':
                require(index + 1 < len(llvm) and llvm[index + 1][0] == address + 1, 'LOCK prefix adjacency')
                prefixes.append(address); value += llvm[index + 1][1]; index += 1
            joined.append((address, value)); index += 1
        require(rows == joined, 'decoder boundaries differ')
        sections[name] = {**frame_record(begin, end), 'begin': begin, 'end': end, 'bytes': len(raw),
                          'hex': raw.hex(), 'sha256': sha(raw), 'file_offset': mapping['file_offset'],
                          'instruction_starts': [address for address, _ in rows],
                          'llvm_raw_rows': len(llvm), 'llvm_joined_lock_prefix_rows': prefixes}
    body = bytes.fromhex(sections['window']['hex'])
    require(sections['window']['frame']['lsda'] is None, 'unexpected leaf LSDA')
    require(body[:16].hex() == '4889f88b4e30894f100f1046200f1107', 'return pointer or ordered headers differ')
    require(body[16:25].hex() == 'f30f6f4610660fefc9', 'first field or zero unpack source differs')
    require(body[0x43:0x50].hex() == '660f67c2f30f7f4714f30f6f06', 'first pack/store then second load differs')
    require(body[0x7a:].hex() == '660f67c2f30f7f4724c3', 'final pack/store/return differs')
    require(image.va_bytes(START - 2, 2)[0] == b'\xcc' * 2, 'leading padding differs')
    require(image.va_bytes(END, 12)[0] == b'\xcc' * 12, 'trailing padding differs')
    neighbors = [frame_record(0x3818cf0, START - 2), frame_record(END + 12, 0x3818e68)]
    slot, mapping = image.va_bytes(SLOT, 8)
    require(mapping['section']['name'] == '.got' and slot == b'\0' * 8, 'GOT file bytes differ')
    relocation = image.relative(SLOT)
    require(relocation['addend'] == START, 'GOT relocation target differs')
    require(relocation['record_file_offset'] == 1865240, 'GOT RELA location differs')
    relocation['raw_hex'] = data[relocation['record_file_offset']:relocation['record_file_offset'] + 24].hex()
    for site in CALLS:
        owner = sections['caller1' if site < 0x3280000 else 'caller2']
        require(site in owner['instruction_starts'], 'indirect call is not aligned')
        raw = image.va_bytes(site, 6)[0]
        require(raw[:2] == b'\xff\x15' and site + 6 + struct.unpack('<i', raw[2:])[0] == SLOT,
                'indirect call slot differs')
    text = next(s for s in image.sections if s['name'] == '.text')
    code = image.va_bytes(text['address'], text['size'], executable=True)[0]
    candidates, position = [], 0
    while (position := code.find(b'\xe8', position)) >= 0:
        if position + 5 <= len(code) and text['address'] + position + 5 + struct.unpack_from('<i', code, position + 1)[0] == START:
            candidates.append(text['address'] + position)
        position += 1
    require(candidates == [], 'unexpected direct-call candidate')
    indirect = {}
    for pattern in [b'\xff\x15', b'\xff\x25']:
        hits, position = [], 0
        while (position := code.find(pattern, position)) >= 0:
            if position + 6 <= len(code) and text['address'] + position + 6 + struct.unpack_from('<i', code, position + 2)[0] == SLOT:
                hits.append(text['address'] + position)
            position += 1
        indirect[pattern.hex()] = hits
    require(indirect == {'ff15': CALLS, 'ff25': []}, 'GOT call/jump candidate census differs')
    naming = []
    relocations, kinds = 0, {}
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:
            continue
        require(section['entsize'] == 24 and section['size'] % 24 == 0, 'RELA shape differs')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            destination, info, addend = struct.unpack_from('<QQq', data, offset)
            require((info & 0xffffffff) in [1, 6, 7, 8, 18], 'unreviewed relocation width')
            require(not any(destination < high and low < destination + 8 for low, high in
                            [(START - 2, END + 12)] + [(a, b) for _, a, b, _ in RANGES[1:]]), 'protected code relocation')
            if addend == START:
                naming.append({'slot': destination, 'kind': info & 0xffffffff, 'symbol': info >> 32,
                               'addend': addend, 'record_file_offset': offset})
            relocations += 1
            kind = str(info & 0xffffffff); kinds[kind] = kinds.get(kind, 0) + 1
    require(naming == [{k: relocation[k] for k in ['slot', 'kind', 'symbol', 'addend', 'record_file_offset']}],
            'entry naming relocation census differs')
    return {'target_sha256': sha(data), 'target_bytes': len(data), 'sections': sections,
            'neighbors': neighbors, 'padding_before_hex': 'cccc', 'padding_after_hex': 'cc' * 12,
            'got': {'va': SLOT, 'file_offset': mapping['file_offset'], 'section': mapping['section']['name'],
                    'file_hex': slot.hex(), 'relocation': relocation},
            'direct_e8_candidates': candidates, 'got_ff15_ff25_candidates': indirect,
            'complete_caller_census': False, 'rela_records_checked': relocations, 'rela_kinds': kinds,
            'stages': [{'source_offset': 48, 'destination_offset': 16, 'bytes': 4, 'reverse': False},
                       {'source_offset': 32, 'destination_offset': 0, 'bytes': 16, 'reverse': False},
                       {'source_offset': 16, 'destination_offset': 20, 'bytes': 16, 'reverse': True},
                       {'source_offset': 0, 'destination_offset': 36, 'bytes': 16, 'reverse': True}],
            'rax': 'unchanged entry RDI (destination pointer)', 'leaf_calls': [],
            'external_constant_data': [], 'ordinary_stable_memory_required': True}


def validate():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity differs')
    record = inspect(data); leaf = record['sections']['window']; base = leaf['file_offset']
    modifications = {'returned pointer': base + 2, 'header dword source': base + 5,
                     'header dword destination': base + 8, 'header vector source': base + 12,
                     'first field source': base + 20, 'unpack zero source': base + 23,
                     'dword shuffle': base + 37, 'low word shuffle': base + 42,
                     'packing': base + 69, 'first reversed store': base + 75,
                     'second field load': base + 76, 'final reversed store': base + 130,
                     'leading padding': base - 1, 'trailing padding': base + END - START,
                     'leaf FDE': leaf['records']['fde']['file_offset'] + 12,
                     'GOT file bytes': record['got']['file_offset'],
                     'GOT RELA kind': record['got']['relocation']['record_file_offset'] + 8,
                     'GOT RELA addend': record['got']['relocation']['record_file_offset'] + 16}
    for number, site in enumerate(CALLS, 1):
        c = record['sections']['caller1' if site < 0x3280000 else 'caller2']
        modifications['GOT call ' + str(number)] = c['file_offset'] + site - c['begin'] + 2
    for name in ['caller1', 'caller2']:
        modifications[name + ' FDE'] = record['sections'][name]['records']['fde']['file_offset'] + 12
    controls = {}
    for name, offset in modifications.items():
        changed = bytearray(data); changed[offset] ^= 1
        try:
            inspect(bytes(changed))
        except ValueError as error:
            controls[name] = str(error)
        else:
            raise ValueError('accepted structural corruption: ' + name)
    record['corruption_controls'] = controls
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--freeze', action='store_true')
    args = parser.parse_args(); raw = encoded(validate())
    if args.freeze:
        with (PACKET / 'static.json').open('xb') as stream:
            stream.write(raw)
    else:
        require((PACKET / 'static.json').read_bytes() == raw, 'static record drift')
    record = json.loads(raw)
    print(json.dumps({'instructions': {k: len(v['instruction_starts']) for k, v in record['sections'].items()},
                      'controls_rejected': len(record['corruption_controls'])}))


if __name__ == '__main__':
    main()
