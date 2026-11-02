#!/usr/bin/env python3
"""Bounded node94 static evidence for the selector and two-field pipeline.

Only static ELF parsing and objdump of owned small spans. No target execution
or PC/register evaluator. No original type/ABI or full response grammar is recovered.
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
    ('primary', 0x466c770, 318, 86, '47be169576f57402f5681a43722cf6b25f16d52e33187c39a6a2ccf7990569fb'),
    ('context-u64-wrapper', 0x466bd10, 229, 69, 'fca33a99b93d22ee7cde15b995c1faf05b6fc7f4967c1489ecaf77030d0f6f5e'),
    ('context-u64-reader', 0x466d980, 316, 95, '1f88da45c1b59f158544acc1df436cf698e6e4dcc10e960db50b102f8ae42f5b'),
    ('context-error', 0x466dac0, 14, 5, 'e9c285d5d073c7afed38f1407c356d1bbd68f7d91948f2527ca58b5c55e64841'),
]
SLOTS = {0x57745e0: 0x466d980, 0x57745e8: 0x466dac0}
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
    datasets = {}
    for name, base, size, expected in [
        ('literal', 0x6f86ca, 52, 'a350d6033e8d300634905ed50f0444bb5a36ff3e7a9d1b5cb7c22f4939f99447'),
        ('opaque-context', 0x203f40, 16, '741939ccb979df0dbf391a6548f88fd9d1873aa3fb996f1df39abc6a66df7025'),
        ('scalar-fast-table', 0x6f6ea8, 16, '7d2505181a6832c2b966ef2bac5b321fa46675d303099fa5efa7178e4297855e'),
        ('scalar-reader-table', 0x6f6ed8, 16, '5d75f79a041f2e2f624d39570d917c96f8428302724464176febde8b46b4abb5'),
        ('existing-response-table', 0x6ef9c0, 16, '00689a7dd71f9983d6e14d0402e01a1f15161c865e028f4e387e848ec2becec3'),
    ]:
        body, mapping = image.va_bytes(base, size)
        need(sha(body) == expected, 'Bound ' + name + ' data differs')
        need(mapping['PT_LOAD']['flags'] == 4, 'Data is not readonly PT_LOAD')
        need(not overlaps(base, size), 'Relocation writes overlap ' + name)
        datasets[name] = {'start': base, 'bytes': size, 'raw_hex': body.hex(), 'sha256': expected, 'mapping': mapping}
    bindings = []
    for slot, destination in SLOTS.items():
        found = overlaps(slot, 8)
        need(len(found) == 1 and found[0]['address'] == slot
             and found[0]['type'] == 8 and found[0]['symbol'] == 0
             and found[0]['addend'] == destination, 'Selected RELATIVE slot binding differs')
        need(image.va_bytes(slot, 8)[0] == bytes(8), 'Selected file slot bytes differ')
        bindings.append({'slot': slot, **found[0]})
    for va, destination in [(0x466c7de, 0x466bd10), (0x466c7fe, 0x466bd10), (0x438b79b, 0x466c770)]:
        raw = image.va_bytes(va, 5)[0]
        need(raw[0] == 0xe8 and va + 5 + struct.unpack_from('<i', raw, 1)[0] == destination,
             'Actual selected direct call differs')
    for va, destination in [(0x466c842, 0x6f86ca), (0x466c85e, 0x203f40)]:
        raw = image.va_bytes(va, 7)[0]
        need(raw[:2] == bytes.fromhex('488d') and va + 7 + struct.unpack_from('<i', raw, 3)[0] == destination,
             'Actual RIP data reference differs')
    caller, caller_mapping = image.va_bytes(0x438b6e0, 612, executable=True)
    need(caller_mapping['PT_LOAD']['flags'] & 5 == 5, 'Caller is not readable executable PT_LOAD')
    need(sha(caller) == 'e39709a89eda075e7e8272d5f4c0fc83214c46764cd1166abfe26c886d45423b', 'Existing selected caller differs')
    need(not overlaps(0x438b6e0, 612), 'Relocation writes overlap caller context')
    found = [f for f in fdes if f['start'] == 0x438b6e0]
    need(len(found) == 1 and found[0]['end'] == 0x438b944, 'Caller FDE extent differs')
    caller_record = {'start': 0x438b6e0, 'bytes': 612, 'sha256': sha(caller), 'mapping': caller_mapping, 'FDE': found[0], 'new_native_credit': 0}
    return {'target_sha256': sha(data), 'functions': records,
            'new_native_denominator': {'bytes': 318, 'rows': 86},
            'existing_context_denominator': {'bytes': 559, 'rows': 169},
            'datasets': datasets, 'selected_existing_caller': caller_record,
            'RELA_entries': len(relocations), 'RELA_type_counts': counts,
            'bindings': bindings,
            'limits': ['Ordinary accepted scalar helper theorem; no new wrapper/caller credit.',
                       'Inactive selector epilogue fields and scalar forwarding padding excluded.',
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
