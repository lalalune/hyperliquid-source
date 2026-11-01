#!/usr/bin/env python3
"""Bind the full strided leaf, three callers, memory operands and FDEs."""
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
START, END = 0x52cfe00, 0x52cfe4d
RANGES = [
    ('window', START, END, '38f96284a7dbdba93c5d71048539f400cc09d1363f4107b557500a9d6eb9e869'),
    ('caller1', 0x52cfe60, 0x52cfea2, '596e61aa8905ed50385870ad2915bedf069fd4c5a6ed7462e775ae359cdc21d5'),
    ('caller2', 0x52d01e0, 0x52d0485, '7de551aa5479e89281671ac42ebc64c2ff0e37d292e770f8ac7adaae70a5e00e'),
    ('caller3', 0x52d5a00, 0x52d5fe5, '549ed288744e2220dc02f95f56146250e59010deaf847234b5b00ec42372c418'),
]
CALLS = [0x52cfe7e, 0x52d0265, 0x52d5b03]
SETUPS = [(0x52cfe79, '89ee4889df'), (0x52d0260, '8b334c89ef'),
          (0x52d5af8, '488b1c24488b7c24288b33')]


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
        require(rows == listing(name + '.llvm.txt', image, begin, end), 'decoder boundaries differ')
        sections[name] = {**frame_record(begin, end), 'begin': begin, 'end': end, 'bytes': len(raw),
                          'hex': raw.hex(), 'sha256': sha(raw), 'file_offset': mapping['file_offset'],
                          'instruction_starts': [address for address, _ in rows]}
    body = bytes.fromhex(sections['window']['hex'])
    require(sections['window']['frame']['lsda'] is None, 'unexpected leaf LSDA')
    require(body[4:6].hex() == '89f6', 'index zero extension differs')
    require(body[0x18:0x20].hex() == '0f1f840000000000', 'internal NOP differs')
    require(body[0x20:0x24].hex() == '488b4760' and body[0x3e:0x41].hex() == '8b4f68',
            'reloaded base or count memory operand differs')
    require(body[0x2b:0x32].hex() == '4981c040ce0000', 'byte stride differs')
    require(body[0x35:0x3b].hex() == '488b004901c1', 'qword load or wrapping sum differs')
    require(body[0x41:0x49].hex() == '48d3e04839c272d7', 'masked count or unsigned loop differs')
    target = START + 0x49 + struct.unpack('b', body[0x48:0x49])[0]
    require(target == START + 0x20 and target in sections['window']['instruction_starts'], 'loop target differs')
    require(image.va_bytes(START - 3, 3)[0] == b'\xcc' * 3, 'leading padding differs')
    require(image.va_bytes(END, 1)[0] == b'\xcc', 'trailing padding differs')
    require(max(f['end'] for f in frames if f['end'] <= START) == START - 3, 'previous FDE end differs')
    successor = frame_record(END + 1, 0x52cfe5e)
    for index, site in enumerate(CALLS, 1):
        require(site in sections['caller' + str(index)]['instruction_starts'], 'call is not aligned')
        raw = image.va_bytes(site, 5)[0]
        require(raw[0] == 0xe8 and site + 5 + struct.unpack('<i', raw[1:])[0] == START, 'caller edge differs')
        begin, value = SETUPS[index - 1]
        require(image.va_bytes(begin, len(bytes.fromhex(value)))[0].hex() == value, 'caller arguments differ')
    text = next(s for s in image.sections if s['name'] == '.text')
    code = image.va_bytes(text['address'], text['size'], executable=True)[0]
    candidates, position = [], 0
    while (position := code.find(b'\xe8', position)) >= 0:
        if position + 5 <= len(code) and text['address'] + position + 5 + struct.unpack_from('<i', code, position + 1)[0] == START:
            candidates.append(text['address'] + position)
        position += 1
    require(candidates == CALLS, 'direct-call candidate census differs')
    pattern = bytes.fromhex('4981c040ce0000')
    require(code.count(pattern) == 1 and text['address'] + code.find(pattern) == START + 0x2b,
            'stride pattern census differs')
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
                            [(START - 3, END + 1)] + [(a, b) for _, a, b, _ in RANGES[1:]]), 'protected code relocation')
            require(addend != START, 'relocation names entry')
            relocations += 1
            kind = str(info & 0xffffffff); kinds[kind] = kinds.get(kind, 0) + 1
    return {'target_sha256': sha(data), 'target_bytes': len(data), 'sections': sections,
            'successor': successor, 'loop_edge': [START + 0x47, target],
            'padding_before_hex': 'cccccc', 'padding_after_hex': 'cc',
            'caller_setups': SETUPS, 'direct_e8_candidates': candidates, 'complete_caller_census': False,
            'stride_pattern_hits': [START + 0x2b], 'rela_records_checked': relocations, 'rela_kinds': kinds,
            'leaf_memory_reads': ['qword [rdi+0x60] each iteration', 'qword computed element each iteration',
                                  'dword [rdi+0x68] each iteration', 'ordinary RET stack read'],
            'leaf_memory_writes': [], 'leaf_calls': [], 'external_constant_data': [],
            'stable_memory_premise_required': True}


def validate():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity differs')
    record = inspect(data); leaf = record['sections']['window']; base = leaf['file_offset']
    modifications = {'index width': base + 4, 'base field offset': base + 0x23,
                     'count field offset': base + 0x40, 'stride': base + 0x2e,
                     'load width': base + 0x35, 'sum': base + 0x39, 'loop branch': base + 0x47,
                     'internal NOP': base + 0x18, 'leading padding': base - 1,
                     'trailing padding': base + END - START,
                     'leaf FDE': leaf['records']['fde']['file_offset'] + 12}
    for number, site in enumerate(CALLS, 1):
        c = record['sections']['caller' + str(number)]
        modifications['caller ' + str(number) + ' FDE'] = c['records']['fde']['file_offset'] + 12
        modifications['caller ' + str(number) + ' edge'] = c['file_offset'] + site - c['begin'] + 1
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
