#!/usr/bin/env python3
"""Authenticate and export bounded Visor configuration-byte request protocol ranges. No target execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

TARGET = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
SIZE = 8305392
RANGES = {'primary-reader': (4901312, 4901741), 'default-reader': (4885584, 4885886), 'default-path': (4881440, 4881641), 'default-path-callback': (4881408, 4881428), 'primary-path-callback': (4901744, 4901763), 'trim': (4902432, 4903095), 'parser-wrapper': (4891568, 4891838), 'selected-field-control': (4896656, 4900239), 'credited-factory': (4901840, 4902223), 'credited-factory-callback': (4900240, 4900260)}
SLOTS = {8276864: 7423280, 8276960: 4828080, 8276992: 4828672, 8277024: 2878384, 8277072: 4823776, 8277088: 4828640, 8277152: 4832544, 8277192: 554361, 8277264: 4832704, 8277272: 4828203, 8279560: 6843664, 8281912: 6874544, 8282192: 6616128, 8282200: 6616752, 8285496: 4881440, 8285504: 4901056, 8285512: 4900512, 8285520: 4885584, 8285528: 4889312, 8285536: 4901312}
DATA = {'code-format': (411758, b'\xc0\x05/code\x00'), 'config-format': (415784, b'\xc0\x0e/static_config\x00'), 'fallback-format': (419147, b'\xc0\t/aws_name\x00'), 'trim-table': (554361, b'\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), 'diagnostic-text': (556943, b'called `Result::unwrap()` on an `Err` value'), 'field-text': (451856, b'aws_name')}
DIRECT = {4901431: 4902224, 4901518: 4891568, 4901592: 4902224, 4901736: 8022048, 4885675: 4902432, 4885843: 4888944, 4885881: 8022048, 4881636: 8022048, 4891641: 4896656, 4891789: 4891840, 4891833: 8022048, 4896770: 4891840, 4897857: 4893200, 4897972: 4903232, 4898567: 4881648, 4898634: 4891840, 4898790: 4891840, 4898873: 4881648, 4899026: 4891840, 4899046: 4895392, 4899095: 4891840, 4899122: 4895232, 4899174: 4891840, 4899300: 4891840, 4899320: 4895392, 4899347: 4900416, 4899548: 4891840, 4899625: 4894448, 4899669: 4891840, 4899696: 4891840, 4899869: 4891840, 4899896: 4891840, 4899969: 4903344, 4900140: 4895312, 4900157: 4895312, 4900188: 8022048, 4900203: 4895312, 4900220: 4895312, 4900228: 8022048, 4902091: 4902224, 4902218: 8022048}

class InvalidEvidence(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise InvalidEvidence(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()

class Image:
    def __init__(self, data):
        require(len(data) == SIZE and sha(data) == TARGET, 'Wrong full Visor identity')
        self.data = data
        require(data[:7] == b'\x7fELF\x02\x01\x01', 'Expected ELF64 little endian')
        require(struct.unpack_from('<H', data, 18)[0] == 62, 'Expected x86-64')
        phoff, shoff = struct.unpack_from('<QQ', data, 32)
        phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', data, 54)
        require(phsize == 56 and shsize == 64, 'Unexpected ELF table sizes')
        self.loads = []
        for i in range(phnum):
            entry = struct.unpack('<IIQQQQQQ', self.cut(phoff + i * phsize, phsize))
            if entry[0] == 1:
                self.loads.append((entry[2], entry[3], entry[5]))
        self.sections = [struct.unpack('<IIQQQQIIQQ', self.cut(shoff + i * shsize, shsize))
                         for i in range(shnum)]

    def cut(self, offset, length):
        require(offset >= 0 and length >= 0 and offset + length <= len(self.data),
                'ELF byte extent outside the admitted image')
        return self.data[offset:offset + length]

    def at(self, address, length):
        offsets = [offset + address - va for offset, va, size in self.loads
                   if va <= address and address + length <= va + size]
        require(len(offsets) == 1, 'VA lacks one file-backed PT_LOAD mapping')
        return self.cut(offsets[0], length)

    def relocations(self):
        result = {slot: [] for slot in SLOTS}
        for section in self.sections:
            if section[1] != 4:
                continue
            require(section[9] == 24 and section[5] % 24 == 0, 'Unexpected RELA records')
            for offset in range(section[4], section[4] + section[5], 24):
                slot, info, addend = struct.unpack('<QQq', self.cut(offset, 24))
                if slot not in result:
                    continue
                symbol_index, kind = info >> 32, info & 0xffffffff
                symbol = ''
                if symbol_index:
                    symbols = self.sections[section[6]]
                    require(symbols[9] == 24, 'Unexpected ELF symbol size')
                    symbol_offset = symbols[4] + symbol_index * 24
                    require(symbol_offset + 24 <= symbols[4] + symbols[5], 'Symbol outside table')
                    name = struct.unpack('<I', self.cut(symbol_offset, 4))[0]
                    strings = self.sections[symbols[6]]
                    require(name < strings[5], 'Symbol name outside string table')
                    table = self.cut(strings[4], strings[5])
                    end = table.find(b'\0', name)
                    require(end >= 0, 'Unterminated ELF symbol')
                    symbol = table[name:end].decode('utf-8')
                result[slot].append({'slot': hex(slot), 'type': kind, 'symbolIndex': symbol_index,
                                     'symbol': symbol, 'addend': addend})
        records = []
        for slot, expected in SLOTS.items():
            require(len(result[slot]) == 1, 'Relocation slot is absent or ambiguous')
            row = result[slot][0]
            if isinstance(expected, str):
                require(row['type'] == 6 and row['symbol'] == expected and row['addend'] == 0,
                        'Imported symbol binding differs')
            else:
                require(row['type'] == 8 and row['symbolIndex'] == 0 and row['addend'] == expected,
                        'Relative callee binding differs at ' + hex(slot))
            records.append(row)
        return records

def command(args, cwd):
    result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=60,
                            env=dict(os.environ, LC_ALL='C'))
    require(result.returncode == 0, 'Native provider failed: ' + args[0])
    return result.stdout.decode('utf-8')

def native_rows(text, image, start, end):
    rows = []
    cursor = start
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$', line)
        if not match:
            continue
        address = int(match[1], 16)
        raw = bytes.fromhex(match[2])
        require(address == cursor and raw and cursor + len(raw) <= end,
                'Native export is not a complete contiguous range')
        require(raw == image.at(address, len(raw)), 'Native instruction bytes differ')
        require('(bad)' not in match[3], 'Native decoder reports a bad instruction')
        rows.append({'va': hex(address), 'bytes': raw.hex(), 'instruction': match[3].strip()})
        cursor += len(raw)
    require(cursor == end and rows, 'Native export leaves missing bytes')
    return rows

def collect(binary):
    image = Image(Path(binary).read_bytes())
    relocations = image.relocations()
    data_records = []
    for name, (va, expected) in DATA.items():
        raw = image.at(va, len(expected))
        require(raw == expected, 'Bound data differs: ' + name)
        data_records.append({'label': name, 'va': hex(va), 'bytes': raw.hex(),
                             'length': len(raw), 'sha256': sha(raw)})
    direct_records = []
    for va, expected in DIRECT.items():
        raw = image.at(va, 5)
        require(raw[0] == 0xe8 and va + 5 + struct.unpack('<i', raw[1:])[0] == expected,
                'Direct call binding differs')
        direct_records.append({'va': hex(va), 'bytes': raw.hex(), 'destination': hex(expected)})
    files = {}
    with tempfile.TemporaryDirectory(prefix='visor-config-protocol-static-') as temporary:
        root = Path(temporary)
        snapshot = root / 'visor.elf'
        snapshot.write_bytes(image.data)
        snapshot.chmod(0o400)
        versions = {tool: command([tool, '--version'], root).splitlines()[0]
                    for tool in ['readelf', 'objdump']}
        require(all('2.42' in value for value in versions.values()), 'Use retained GNU 2.42 recipe')
        frames = command(['readelf', '-W', '--debug-dump=frames', 'visor.elf'], root)
        blocks = re.split(r'\n\s*\n', frames)
        ranges = []
        for label, (start, end) in RANGES.items():
            matched = []
            for block in blocks:
                match = re.search(r'FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)', block)
                if match and int(match[2], 16) == start:
                    matched.append((int(match[3], 16), match[1], block))
            require(len(matched) == 1 and matched[0][0] == end, 'Exact FDE extent differs')
            _, cie, fde = matched[0]
            cies = [block for block in blocks if re.match(r'^\s*' + cie + r'\s+.*\bCIE\b', block)]
            require(len(cies) == 1, 'CIE record is missing or ambiguous')
            listing = command(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                               '--start-address=' + hex(start), '--stop-address=' + hex(end),
                               'visor.elf'], root)
            rows = native_rows(listing, image, start, end)
            files['records/' + label + '.txt'] = listing.encode()
            files['records/' + label + '.fde.txt'] = (fde + '\n').encode()
            files['records/cie-' + cie + '.txt'] = (cies[0] + '\n').encode()
            ranges.append({'label': label, 'start': hex(start), 'end': hex(end), 'bytes': end - start,
                           'sha256': sha(image.at(start, end - start)), 'cieOffset': cie, 'rows': rows})
        readelf_relocations = command(['readelf', '-Wr', 'visor.elf'], root)
        selected = []
        for slot in SLOTS:
            found = [line for line in readelf_relocations.splitlines()
                     if re.match(r'^0*' + f'{slot:x}' + r'\s', line)]
            require(len(found) == 1, 'Native relocation record is missing or ambiguous')
            selected.extend(found)
        files['records/relocations.txt'] = ('\n'.join(selected) + '\n').encode()
        require(snapshot.read_bytes() == image.data, 'Private snapshot changed during analysis')
    summary = {'schema': 'visor-config-protocol-static-1', 'targetSha256': TARGET, 'targetBytes': SIZE,
               'versions': versions, 'ranges': ranges, 'relocations': relocations,
               'data': data_records, 'directCalls': direct_records,
               'rangeBytes': sum(row['bytes'] for row in ranges),
               'instructionRows': sum(len(row['rows']) for row in ranges),
               'scope': 'Static native exports and bindings; no instruction evaluator, target execution, recovered function count or gate.'}
    files['summary.json'] = json_bytes(summary)
    return files

def write_new(output, files):
    output = Path(output)
    require(not output.exists(), 'Existing output must be preserved')
    output.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.output.exists(), 'Existing output must be preserved')
        files = collect(args.binary)
        write_new(args.output, files)
        print(json.dumps({'files': len(files), 'output': str(args.output)}))
    except (InvalidEvidence, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')

if __name__ == '__main__':
    main()
