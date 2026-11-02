#!/usr/bin/env python3
"""Bounded node94 static evidence for the qualified owned-byte pipeline.

Only static ELF parsing and objdump of owned small spans. No target execution
or PC/register evaluator. Allocation/TLS/unwind internals are explicit gaps.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from libcore_fmt_correspondence import Elf, eh_frame_records

TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SPECS = [
    ('primary', 0x466dc10, 228, 68, '9a3b3cd2415548969ea5283e8d016db778f88277570504b2645ec592e234e3d0'),
    ('collection', 0x4589a30, 251, 78, 'cbf287e223893da3e39c9d68a5c9e830dfc1d69faea0ebb2498b8ab1c04df447'),
    ('validator', 0x157a200, 503, 143, 'caf200c8b1aebe6f36869b03f9d684c2eb6ffc7fdf5d16addc768658b4795d62'),
    ('context-u64-wrapper', 0x466bd10, 229, 69, 'fca33a99b93d22ee7cde15b995c1faf05b6fc7f4967c1489ecaf77030d0f6f5e'),
    ('context-u64-reader', 0x466d980, 316, 95, '1f88da45c1b59f158544acc1df436cf698e6e4dcc10e960db50b102f8ae42f5b'),
    ('context-error', 0x466dac0, 14, 5, 'e9c285d5d073c7afed38f1407c356d1bbd68f7d91948f2527ca58b5c55e64841'),
]
SLOTS = {0x576e3f8: 0x157a200, 0x576e010: 0x54c8cb0,
         0x576dfb8: 0x1346068, 0x576e298: 0x54c0780,
         0x57745e0: 0x466d980, 0x57745e8: 0x466dac0}
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def derive(data):
    """Lower structural seam permits copied-input controls below full SHA."""
    image = Elf(data, 3)
    cies, fdes = eh_frame_records(data, image.sections)
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', data, 54)
    loads = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize) for i in range(phcount)]
    relocations = []
    counts = {}
    for section in image.sections:
        need(section['type'] not in (9, 19), 'Unsupported REL/RELR encoding')
        if section['type'] != 4:
            continue
        need(section['entsize'] == 24 and section['size'] % 24 == 0, 'Invalid RELA extent')
        for at in range(section['offset'], section['offset'] + section['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', data, at)
            kind = info & 0xffffffff
            need(kind in (1, 6, 7, 8, 18), 'Unknown relocation write width')
            counts[str(kind)] = counts.get(str(kind), 0) + 1
            relocations.append({'address': address, 'type': kind, 'symbol': info >> 32,
                                'addend': addend, 'record_file_offset': at,
                                'symbol_table': section['link'], 'raw': data[at:at + 24].hex()})
    need(len(relocations) == 80300, 'Actual relocation denominator differs')

    def overlaps(start, size):
        return [r for r in relocations if r['address'] < start + size and start < r['address'] + 8]

    records = {}
    for role, base, size, rows, expected in SPECS:
        body, mapping = image.va_bytes(base, size, executable=True)
        need(sha(body) == expected, 'Complete ' + role + ' body differs')
        programs = [p for p in loads if p[0] == 1 and p[3] <= base and base + size <= p[3] + p[5]]
        need(len(programs) == 1 and programs[0][1] & 5 == 5, 'Code is not readable executable PT_LOAD')
        need(not overlaps(base, size), 'Relocation writes overlap selected code')
        found = [f for f in fdes if f['start'] == base]
        need(len(found) == 1 and found[0]['end'] == base + size, 'Exact FDE extent differs')
        frame = found[0]
        fhead = image.va_bytes(frame['fde'], 4)[0]
        chead = image.va_bytes(frame['cie'], 4)[0]
        fraw = image.va_bytes(frame['fde'], struct.unpack('<I', fhead)[0] + 4)[0]
        craw = image.va_bytes(frame['cie'], struct.unpack('<I', chead)[0] + 4)[0]
        records[role] = {'start': base, 'end': base + size, 'bytes': size, 'rows': rows,
                         'body_sha256': expected, 'mapping': mapping,
                         'PT_LOAD_flags': programs[0][1], 'FDE': frame, 'CIE': cies[frame['cie']],
                         'FDE_raw': fraw.hex(), 'CIE_raw': craw.hex(), 'code_RELA_overlaps': []}
    table = image.va_bytes(0x2564a0, 256)[0]
    expected = bytes(1 if b < 128 else 2 if 0xc2 <= b <= 0xdf else 3 if 0xe0 <= b <= 0xef
                     else 4 if 0xf0 <= b <= 0xf4 else 0 for b in range(256))
    need(table == expected, 'Actual validator width table differs')
    need(not overlaps(0x2564a0, 256), 'Relocation writes overlap classifier table')
    bindings = []
    for slot, destination in SLOTS.items():
        found = overlaps(slot, 8)
        need(len(found) == 1 and found[0]['address'] == slot
             and found[0]['type'] == 8 and found[0]['symbol'] == 0
             and found[0]['addend'] == destination, 'Selected RELATIVE slot binding differs')
        need(image.va_bytes(slot, 8)[0] == bytes(8), 'Selected file slot bytes differ')
        bindings.append({'slot': slot, **found[0]})
    imports = []
    for slot, kind, symbol_name in [(0x576dfe0, 6, 'memcpy'), (0x5778db0, 7, '_Unwind_Resume')]:
        found = overlaps(slot, 8)
        need(len(found) == 1 and found[0]['address'] == slot and found[0]['type'] == kind
             and found[0]['addend'] == 0, 'Actual import slot differs')
        row = found[0]
        symbols = image.section(row['symbol_table'])
        strings = image.section(symbols['link'])
        at = symbols['offset'] + row['symbol'] * symbols['entsize']
        record = struct.unpack_from('<IBBHQQ', data, at)
        start = strings['offset'] + record[0]
        end = data.find(b'\0', start, strings['offset'] + strings['size'])
        need(end >= start and data[start:end].decode() == symbol_name and record[3] == 0,
             'Actual dynamic import name/definition differs')
        imports.append({'slot': slot, 'symbol_name': symbol_name, 'symbol_record_hex': data[at:at + 24].hex(), **row})
    for va, destination in [(0x466dc28, 0x4589a30), (0x4589a49, 0x466bd10), (0x466dcef, 0x5660110)]:
        raw = image.va_bytes(va, 5)[0]
        need(raw[0] == 0xe8 and va + 5 + struct.unpack_from('<i', raw, 1)[0] == destination,
             'Actual selected direct call differs')
    return {'target_sha256': sha(data), 'functions': records,
            'new_native_denominator': {'bytes': 982, 'rows': 289},
            'existing_context_denominator': {'bytes': 559, 'rows': 169},
            'classifier_table_sha256': sha(table), 'classifier_table_RELA_overlaps': [],
            'RELA_entries': len(relocations), 'RELA_type_counts': counts,
            'bindings': bindings, 'imports': imports,
            'limits': ['Ordinary allocation/copy/release functional premises only, not transitive allocator closure.',
                       'Inactive Option payload and native padding excluded.',
                       'Existing header/Reader/error semantics credited separately; no1365 API/code copy.',
                       'No native ABI/type/pointer/compiler/machine-byte/full-component claim.'],
            'captured_execution_or_instruction_evaluator': False}


def analyze(data):
    need(type(data) is bytes and len(data) == 91774280 and sha(data) == TARGET_SHA, 'Target identity differs')
    return derive(data)


def collect(target, output):
    need(not os.path.lexists(output), 'Preserve previous native output')
    data = Path(target).read_bytes()
    record = analyze(data)
    output.mkdir(parents=True)
    calls = []

    def command(label, argv):
        p = subprocess.run(argv, env=ENV, capture_output=True)
        (output / (label + '.stdout')).write_bytes(p.stdout)
        (output / (label + '.stderr')).write_bytes(p.stderr)
        calls.append({'label': label, 'argv': argv, 'exit': p.returncode,
                      'stdout': {'bytes': len(p.stdout), 'sha256': sha(p.stdout)},
                      'stderr': {'bytes': len(p.stderr), 'sha256': sha(p.stderr)}})
        (output / 'COMMANDS.json').write_text(json.dumps(calls, sort_keys=True, indent=2) + '\n')
        need(p.returncode == 0, 'Static binutils command failed')
        return p.stdout

    command('objdump-version', ['/usr/bin/objdump', '--version'])
    image = Elf(data, 3)
    for role, base, size, count, _ in SPECS:
        body = image.va_bytes(base, size, executable=True)[0]
        path = output / (role + '.raw')
        path.write_bytes(body)
        text = command(role, ['/usr/bin/objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
                              '-M', 'intel', '--insn-width=16', '--adjust-vma=' + hex(base), str(path)])
        cursor, rows = base, []
        for line in text.decode().splitlines():
            fields = line.split('\t')
            if len(fields) < 3 or not re.fullmatch(r'\s*[0-9a-f]+:', fields[0]):
                continue
            address, raw = int(fields[0].strip()[:-1], 16), bytes.fromhex(fields[1])
            need(address == cursor and raw and body[address - base:address - base + len(raw)] == raw
                 and '(bad)' not in fields[2], 'Native row partition differs')
            cursor += len(raw)
            rows.append({'address': address, 'raw': raw.hex(), 'assembly': fields[2]})
        need(cursor == base + size and len(rows) == count, 'Full native row denominator differs')
        record['functions'][role]['native_rows'] = rows
    (output / 'REPORT.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = collect(args.target, args.out)
    print(json.dumps({'status': 'PASS_STATIC_ONLY', 'new_scope': report['new_native_denominator'],
                      'context_separate': report['existing_context_denominator']}, sort_keys=True))
