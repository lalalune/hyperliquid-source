#!/usr/bin/env python3
"""Extract the digest-bound Node115 option-registration contract without execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections
from fde_extents import eh_frame_records

TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_BYTES = 105896032
ROOT = Path(__file__).resolve().parents[1]

def require(condition, message):
    if not condition:
        raise ValueError(message)

class Image:
    def __init__(self, data, verify_identity=True):
        self.data = data
        if verify_identity:
            require(len(data) == TARGET_BYTES and hashlib.sha256(data).hexdigest() == TARGET_SHA256, 'sole Node115 identity')
        self.sections = sections(data)
        self.cies, self.fdes = eh_frame_records(data, self.sections)

    def offset(self, va, size):
        matches = [s['offset'] + va - s['address'] for s in self.sections
                   if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(size >= 0 and len(matches) == 1, 'unique file-backed VA')
        return matches[0]

    def read(self, va, size):
        p = self.offset(va, size)
        return self.data[p:p + size]

    def relative_writers(self, slot):
        writers = []
        for s in self.sections:
            if s['name'] != '.rela.dyn':
                continue
            require(s['size'] % 24 == 0, 'RELA size')
            for p in range(s['offset'], s['offset'] + s['size'], 24):
                address, info, addend = struct.unpack_from('<QQq', self.data, p)
                if address == slot:
                    writers.append((info & 0xffffffff, info >> 32, addend))
        return writers

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
    if type_offset is not None:
        require(pos + type_offset <= end, 'LSDA type-table bounds')
    encoding_va = va + pos - start
    require(byte() == 1, 'LSDA call-site encoding')
    table_size = uleb()
    table_end = pos + table_size
    require(table_end <= end, 'LSDA table bounds')
    sites = []
    previous_end = function['start']
    while pos < table_end:
        offset, length, landing, action = uleb(), uleb(), uleb(), uleb()
        low = function['start'] + offset
        high = low + length
        require(pos <= table_end and previous_end <= low <= high <= function['end'],
                'LSDA ordered call interval')
        require(not landing or function['start'] <= function['start'] + landing < function['end'],
                'LSDA landing interval')
        sites.append({'start': hex(low), 'end': hex(high),
                      'landing': hex(function['start'] + landing) if landing else None,
                      'action': action})
        previous_end = high
    require(pos == table_end, 'LSDA exact table end')
    return {'va': hex(va), 'callSiteEncodingVA': hex(encoding_va),
            'typeEncoding': type_encoding, 'typeOffset': type_offset,
            'raw': bytes(image.data[start:pos]).hex(), 'sites': sites,
            'limits': 'Action/type chains and arbitrary callee unwinding remain unresolved.'}

def derive(image, spec):
    require(spec['targetSHA256'] == TARGET_SHA256 and spec['targetBytes'] == TARGET_BYTES, 'spec target')
    ranges = []
    for row in spec['functions']:
        start, end = int(row['start'], 16), int(row['end'], 16)
        actual = [f for f in image.fdes if f['start'] == start and f['end'] == end]
        require(len(actual) == 1 and end - start == row['bytes'], 'function FDE range')
        body = image.read(start, end - start)
        ranges.append({'start': row['start'], 'end': row['end'], 'bytes': len(body),
                       'sha256': hashlib.sha256(body).hexdigest(), 'fde': actual[0],
                       'cie': image.cies[actual[0]['cie']], 'exceptionTable': lsda_table(image, actual[0])})
    facts = []
    formats = {'u8': ('<B', 1), 'u16': ('<H', 2), 'u32': ('<I', 4), 'i32': ('<i', 4)}
    for row in spec['facts']:
        site = int(row['site'], 16)
        prefix = bytes.fromhex(row['prefix'])
        require(image.read(site, len(prefix)) == prefix, 'fact opcode: ' + row['name'])
        if row['kind'] == 'bytes4':
            value = image.read(site + len(prefix), 4).hex()
        else:
            require(row['kind'] in formats, 'fact kind')
            fmt, size = formats[row['kind']]
            value = struct.unpack(fmt, image.read(site + len(prefix), size))[0]
        require(value == row['expected'], 'fact operand: ' + row['name'])
        facts.append({'name': row['name'], 'site': row['site'], 'value': value,
                      'observation': row['observation']})
    calls = []
    for row in spec['calls']:
        site = int(row['site'], 16)
        if row['form'] == 'direct':
            require(image.read(site, 1) == b'\xe8', 'direct call opcode')
            target = site + 5 + struct.unpack('<i', image.read(site + 1, 4))[0]
        else:
            require(row['form'] == 'rip' and image.read(site, 2) == b'\xff\x15', 'RIP call opcode')
            target = site + 6 + struct.unpack('<i', image.read(site + 2, 4))[0]
        require(target == int(row['target'], 16), 'call binding')
        calls.append(dict(row, actualTarget=hex(target)))
    for row in spec['relativeWriters']:
        expected = (8, 0, int(row['target'], 16))
        require(image.relative_writers(int(row['slot'], 16)) == [expected], 'unique RELATIVE writer')
    by_name = {f['name']: f['value'] for f in facts}
    a, b = bytes.fromhex(by_name['version-first']), bytes.fromhex(by_name['version-overlap'])
    require(a[-1:] == b[:1], 'overlapping version literal')
    version = (a + b[1:]).decode('ascii')
    require(version == 'version' and bytes.fromhex(by_name['help-literal']) == b'help', 'special long names')
    return {'targetSHA256': TARGET_SHA256, 'task': 'RE-012', 'component': 'node-runtime',
            'functions': ranges, 'facts': facts, 'calls': calls,
            'relativeWriters': spec['relativeWriters'], 'versionLiteral': version,
            'capturedExecution': False, 'normalizationMasks': [], 'componentGate': False,
            'limits': spec['limits']}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--spec', type=Path, default=ROOT / 'research/work-items/RE-012-node115-cli-option-registration/spec.json')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = derive(Image(args.target.read_bytes()), json.loads(args.spec.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n', encoding='utf8')

if __name__ == '__main__':
    main()
