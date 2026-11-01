#!/usr/bin/env python3
"""Authenticate and export bounded Visor directory preparation request policy ranges. No target execution."""
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
RANGES = {'preparation': (6790048, 6793663), 'component-back': (6900976, 6902017), 'remaining-slice': (6786976, 6787574), 'component-comparison': (6880656, 6880839), 'error-classification': (6862240, 6862377), 'last-component': (6786672, 6786963), 'long-cstring-adapter': (6699360, 6699519), 'mkdir-callback': (6732768, 6732816), 'path-caller': (3807104, 3808019), 'prefix-caller': (4900512, 4900933), 'metadata-context': (6843664, 6844200), 'nul-converter-context': (2879744, 2880122), 'nul-finalizer-context': (2877952, 2878177)}
SLOTS = {8281848: 6900976, 8281904: 6786976, 8276840: 'memcpy', 8240016: 777903, 8289256: 'mkdir', 8280320: '__errno_location', 8279560: 6843664, 8276800: 2878196, 8276832: 7388976, 8276864: 7423280, 8277272: 4828203, 8244768: 427058, 8277120: 4831072, 8244792: 427058, 8277088: 4828640, 8244744: 427058, 8244720: 427058, 8241864: 427058, 8241936: 427058, 8277112: 'bcmp', 8241912: 427058, 8241888: 427058, 8277064: 2879744, 8279016: 8298072, 8277024: 2878384, 8277288: 4830560, 8281840: 3800080, 8281936: 6790048, 8053872: 441925, 8278944: 6759392, 8290008: 'stat64', 8276944: 2877952, 8276936: 7409312}
DATA = {'data-bd100': (774400, b'\xe6\xd0[\x00\x0f\xd1[\x00\xed\xd0[\x00\xfb\xd0[\x00'), 'data-bd110': (774416, b'\x05\xd3[\x00.\xd3[\x00\x0c\xd3[\x00\x1a\xd3[\x00'), 'data-bd120': (774432, b'?\xd7[\x00h\xd7[\x00F\xd7[\x00T\xd7[\x00'), 'data-bd89c': (776348, b"\x1b\xdd\\\x00]\xdd\\\x00x\xdd\\\x00i\xdd\\\x00x\xdd\\\x00x\xdd\\\x00l\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00`\xdd\\\x00c\xdd\\\x00\x1b\xdd\\\x00x\xdd\\\x00x\xdd\\\x00N\xdd\\\x00T\xdd\\\x00B\xdd\\\x00x\xdd\\\x00Q\xdd\\\x00r\xdd\\\x00o\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00E\xdd\\\x00\x81\xdd\\\x00\x84\xdd\\\x006\xdd\\\x00\x8a\xdd\\\x009\xdd\\\x00f\xdd\\\x00x\xdd\\\x00x\xdd\\\x003\xdd\\\x00<\xdd\\\x00x\xdd\\\x00\x1e\xdd\\\x00{\xdd\\\x00H\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00\x1e\xdd\\\x00x\xdd\\\x00x\xdd\\\x000\xdd\\\x00-\xdd\\\x00K\xdd\\\x00W\xdd\\\x00x\xdd\\\x00~\xdd\\\x00Z\xdd\\\x00x\xdd\\\x00x\xdd\\\x00$\xdd\\\x00x\xdd\\\x00x\xdd\\\x00?\xdd\\\x00\x87\xdd\\\x00x\xdd\\\x00!\xdd\\\x00x\xdd\\\x00*\xdd\\\x00u\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00x\xdd\\\x00'\xdd\\\x00"), 'data-7dbb90': (8240016, b'\x00\x00\x00\x00\x00\x00\x00\x00*\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00'), 'data-bdeaf': (777903, b'file name contained ')}
DIRECT = {6790406: 6880656, 6791035: 6880656, 6791668: 6862240, 6791718: 6681184, 6791786: 6699360, 6792227: 6862240, 6792320: 6681184, 6792366: 6681184, 6792570: 6726368, 6793325: 6862240, 6793422: 6681184, 6793452: 6699360, 6793502: 6681184, 6793564: 6699360, 6793589: 6681184, 6793608: 6681184, 6793658: 8022048, 6901124: 6786672, 6901249: 6786672, 6901333: 6786672, 6901497: 6786672, 6901622: 6786672, 6901702: 6786672, 6787206: 6786672, 6787302: 6786672, 6787467: 6786672, 6699514: 8022048, 3807494: 3800384, 3807745: 3800384, 3808014: 8022048, 4900628: 4902224, 4900750: 4902224, 4900871: 4900944, 4900928: 8022048, 6843976: 6855040, 6844193: 6698848, 2878080: 2877808, 2878172: 8022048}

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
    with tempfile.TemporaryDirectory(prefix='visor-preparation-static-') as temporary:
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
    summary = {'schema': 'visor-preparation-static-1', 'targetSha256': TARGET, 'targetBytes': SIZE,
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
