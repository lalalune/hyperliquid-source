#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Static, digest-bound evidence for a node #94 order-id queue filter."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# The half-open chunks partition both complete FDEs, including cleanup code.
WINDOWS = (
    ('scan-before-first-keep', 0x24c47f0, 0x24c489b, 'c4d98d71baeb2c1ecdb0ffe49bf15d64c779bb844a81f35b38d5baf4a5a9e655'),
    ('first-keep-allocation', 0x24c489b, 0x24c4914, '8b316b5b293944f510f511394023bb551105ac4bc79610f72a75e381366c2b37'),
    ('remaining-slices', 0x24c4914, 0x24c49f6, '0e1ed50941ad6af8b2367682b23879595a7bbeb937f0745771d3879a71cfbf6c'),
    ('empty-return-and-unwind', 0x24c49f6, 0x24c4a64, '71da0138eb1835b82122984c5d665e198d1d4eebfbf745c41011b9a6e1b92b3b'),
    ('hash-table-probe', 0x2775400, 0x27754bf, '9cd8c6c7bfad01cc36f05a53c6a2d0b1bc9edac9df21ca1e9914ef9f4868d302'),
    ('slot-guards-and-position-call', 0x27754bf, 0x277551f, 'f6f2dc24bccca1aa9fcba38f3c8532514495ba2868f581c855d61daebbd56666'),
    ('position-tree-search', 0x277551f, 0x277559a, 'd3320319fa48f20f3c5455e9f0498acd2e3ff1eccac7f4bc0d10f2efba12e5b2'),
    ('sign-and-reject-append', 0x277559a, 0x27755d5, 'd307712d5b574733ee175242685216ebc2502f7648bb6a8470683dd0881bffe0'),
)
FUNCTIONS = (
    ('queue-rebuild', 0x24c47f0, 0x24c4a64, 0x10beb64),
    ('slot-position-filter', 0x2775400, 0x27755d5, 0xd84004),
)
# Instruction starts checked by manual disassembly; the parser reads only these
# fixed opcodes and rel8/rel32 encodings. This is not a disassembler or CFG census.
BRANCHES = (
    (0x24c4833, '74', 0x24c4858, 'first slice exhausted'),
    (0x24c4854, '74', 0x24c4830, 'first slice predicate false'),
    (0x24c4856, 'eb', 0x24c489b, 'first slice first survivor'),
    (0x24c4873, '0f84', 0x24c49f6, 'both slices exhausted before survivor'),
    (0x24c4899, '74', 0x24c4870, 'second slice predicate false'),
    (0x24c48a9, '0f84', 0x24c4a2a, 'initial allocation failed'),
    (0x24c4912, 'eb', 0x24c4936, 'continue after first survivor'),
    (0x24c4953, '74', 0x24c4980, 'remaining first slice exhausted'),
    (0x24c4976, '74', 0x24c4950, 'remaining first slice predicate false'),
    (0x24c4978, 'eb', 0x24c49b8, 'remaining first slice survivor'),
    (0x24c4993, '74', 0x24c49ea, 'remaining second slice exhausted'),
    (0x24c49b6, '74', 0x24c4990, 'remaining second slice predicate false'),
    (0x24c49c2, '0f85', 0x24c4925, 'survivor buffer has capacity'),
    (0x24c49e5, 'e9', 0x24c4920, 'resume after grow'),
    (0x24c49f4, 'eb', 0x24c4a00, 'return nonempty buffer'),
    (0x24c4a49, '74', 0x24c4a5c, 'unwind without allocated buffer'),
    (0x2775415, '0f84', 0x27755c8, 'empty id table'),
    (0x2775472, '74', 0x27754a0, 'no fingerprint match'),
    (0x277548f, '74', 0x27754bf, 'id key equals'),
    (0x277549c, '75', 0x2775474, 'try remaining fingerprints'),
    (0x27754ac, '0f85', 0x27755c8, 'empty control terminates lookup'),
    (0x27754bd, 'eb', 0x277545a, 'probe next group'),
    (0x27754d3, '0f83', 0x27755c8, 'slot index at or beyond length'),
    (0x27754e8, '0f84', 0x27755c8, 'vacant slot tag'),
    (0x277552b, '74', 0x27755a3, 'position tree has no root'),
    (0x2775553, '74', 0x277557c, 'node keys exhausted'),
    (0x2775570, '74', 0x2775550, 'continue node key scan'),
    (0x2775578, '74', 0x277558f, 'position key equals'),
    (0x277557a, 'eb', 0x277557f, 'choose tree edge'),
    (0x2775583, '72', 0x27755a3, 'position key absent at leaf'),
    (0x277558d, 'eb', 0x2775531, 'descend position tree'),
    (0x277559a, '74', 0x27755a3, 'position signed value zero'),
    (0x27755a1, '74', 0x27755ca, 'nonzero position sign equals slot byte'),
    (0x27755ae, '75', 0x27755b9, 'reject vector has capacity'),
)
CALLS = (
    (0x26ee927, 0x24c47f0, 'existing insertion body to queue rebuild'),
    (0x24c484a, 0x2775400, 'first slice before first survivor'),
    (0x24c488f, 0x2775400, 'second slice before first survivor'),
    (0x24c496c, 0x2775400, 'first slice after first survivor'),
    (0x24c49ac, 0x2775400, 'second slice after first survivor'),
    (0x24c49e0, 0x251b070, 'survivor buffer grow'),
    (0x277551f, 0x36f57f0, 'position-map accessor, external'),
    (0x24c4a5f, 0x5660110, 'unwind resume'),
)
# The indirect operands name ELF relocation slots, not direct branches.
INDIRECT = (
    (0x24c48a0, 0x576dfd8, 0x54c06b0, 'initial buffer allocation'),
    (0x24c4a34, 0x576dfb8, 0x1346068, 'allocation failure handler'),
    (0x24c4a56, 0x576e010, 0x54c8cb0, 'unwind buffer release'),
    (0x27755b3, 0x5774458, 0x32d5780, 'reject vector grow'),
)
# Each immediate is extracted from its checked instruction bytes.
FIELDS = (
    ('filter-table-entry-count-offset', 0x2775410, '48837a1800', 3, 1, False),
    ('hash-multiplier', 0x277541e, '48b8c5a9622eea7a35f1', 2, 8, False),
    ('hash-rotate-left-bits', 0x277542c, '48c1c014', 3, 1, False),
    ('fingerprint-shift-bits', 0x2775433, '48c1ee39', 3, 1, False),
    ('hash-entry-shift-bits', 0x2775482, '49c1e204', 3, 1, False),
    ('probe-group-bytes', 0x27754b5, '4883c010', 3, 1, False),
    ('slab-length-offset', 0x27754cf, '483b4810', 3, 1, False),
    ('slab-pointer-offset', 0x27754d9, '488b4008', 3, 1, False),
    ('slot-stride', 0x27754dd, '4869c9f8000000', 3, 4, False),
    ('vacant-tag', 0x27754e4, '833c0802', 3, 1, False),
    ('slot-side-byte-offset', 0x2775515, '0fb6a8c2000000', 3, 4, False),
    ('position-node-key-count-offset', 0x2775531, '0fb7b122030000', 3, 4, False),
    ('position-key-array-displacement', 0x2775555, '4c3bbcd1d0020000', 4, 4, False),
    ('position-value-stride', 0x2775565, '4883c740', 3, 1, False),
    ('position-child-array-offset', 0x2775585, '488b8cd128030000', 4, 4, False),
    ('position-found-value-displacement', 0x277558f, '488b4439d0', 4, 1, True),
    ('reject-vector-pointer-offset', 0x27755a3, '488b5b28', 3, 1, False),
    ('reject-vector-length-offset', 0x27755a7, '4c8b7b10', 3, 1, False),
    ('initial-allocation-bytes', 0x24c489b, 'bf20000000', 1, 4, False),
    ('initial-capacity', 0x24c48b2, '48c744240804000000', 5, 4, False),
    ('initial-length', 0x24c48c5, '48c744241801000000', 5, 4, False),
    ('empty-output-pointer', 0x24c49f6, 'ba08000000', 1, 4, False),
)


def authenticate(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('node #94 SHA-256 mismatch')


def executable_mapping(secs, data_len, va, length):
    if va < 0 or length <= 0:
        raise ValueError('invalid executable range')
    found = [s for s in secs if s['type'] != 8 and s['flags'] & 4
             and s['address'] <= va and va + length <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('range lacks a unique file-backed executable section')
    s = found[0]
    off = s['offset'] + va - s['address']
    if off < 0 or off + length > data_len:
        raise ValueError('range outside file')
    return s, off


def read_code(data, secs, va, length):
    _, off = executable_mapping(secs, len(data), va, length)
    return data[off:off + length]


def check_window(raw, expected_digest):
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValueError('function evidence window changed')


def branch(raw, site, opcode):
    op = bytes.fromhex(opcode)
    if not raw.startswith(op):
        raise ValueError('branch opcode changed')
    if len(op) == 1 and op[0] in (0xe8, 0xe9):
        size = 5
        fmt = '<i'
    elif len(op) == 2 and op[0] == 0x0f and 0x80 <= op[1] <= 0x8f:
        size = 6
        fmt = '<i'
    elif len(op) == 1 and (0x70 <= op[0] <= 0x7f or op[0] == 0xeb):
        size = 2
        fmt = '<b'
    else:
        raise ValueError('unsupported branch opcode')
    if len(raw) < size:
        raise ValueError('truncated branch')
    return site + size + struct.unpack_from(fmt, raw, len(op))[0], raw[:size]


def immediate(raw, expected_hex, start, width, signed):
    expected = bytes.fromhex(expected_hex)
    if raw != expected or start < 0 or width <= 0 or start + width > len(raw):
        raise ValueError('instruction bytes or immediate bounds changed')
    return int.from_bytes(raw[start:start + width], 'little', signed=signed)


def require_fde(rows, expected_end, expected_fde):
    if len(rows) != 1 or rows[0]['end'] != expected_end or rows[0]['fde'] != expected_fde:
        raise ValueError('FDE identity or extent changed')
    return rows[0]


def require_relocation(relocations, slot, expected_addend):
    row = relocations.get(slot)
    if row != (8, expected_addend):
        raise ValueError('indirect slot or relocation changed')
    return row[1]


def collect(data):
    authenticate(data)
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    functions = []
    for label, start, end, fde_va in FUNCTIONS:
        fde = require_fde(by_start.get(start, []), end, fde_va)
        section, offset = executable_mapping(secs, len(data), fde['start'], fde['end'] - fde['start'])
        raw = data[offset:offset + fde['end'] - fde['start']]
        functions.append([label, hex(fde['start']), hex(fde['end']), hex(fde['fde']), section['name'],
                          hex(offset), str(len(raw)), hashlib.sha256(raw).hexdigest()])
    windows = []
    for label, start, end, expected in WINDOWS:
        raw = read_code(data, secs, start, end - start)
        check_window(raw, expected)
        windows.append([label, hex(start), hex(end), str(len(raw)), raw.hex(), expected])
    branches = []
    for site, opcode, expected, label in BRANCHES:
        target, raw = branch(read_code(data, secs, site, 6), site, opcode)
        if target != expected:
            raise ValueError('branch destination changed')
        branches.append([hex(site), raw.hex(), hex(target), label])
    calls = []
    for site, expected, label in CALLS:
        target, raw = branch(read_code(data, secs, site, 5), site, 'e8')
        if target != expected:
            raise ValueError('call destination changed')
        calls.append([hex(site), raw.hex(), hex(target), label])
    relocations = {}
    selected_slots = {row[1] for row in INDIRECT}
    for section in secs:
        if section['type'] != 4:
            continue
        if section['size'] % 24:
            raise ValueError('partial ELF64 relocation')
        for pos in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if slot in selected_slots:
                if slot in relocations:
                    raise ValueError('duplicate relocation slot')
                relocations[slot] = (info, addend)
    indirect = []
    for site, expected_slot, expected_addend, label in INDIRECT:
        raw = read_code(data, secs, site, 6)
        if raw[:2] != b'\xff\x15':
            raise ValueError('indirect call opcode changed')
        slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
        if slot != expected_slot:
            raise ValueError('indirect slot changed')
        addend = require_relocation(relocations, slot, expected_addend)
        indirect.append([hex(site), raw.hex(), hex(slot), hex(addend), label])
    fields = []
    for label, site, pattern, start, width, signed in FIELDS:
        raw = read_code(data, secs, site, len(bytes.fromhex(pattern)))
        value = immediate(raw, pattern, start, width, signed)
        fields.append([label, hex(site), raw.hex(), str(value), hex(value) if value >= 0 else '-'+hex(-value)])
    return {'functions.tsv': (['role','start_va','end_va','fde_va','section','file_offset','bytes','sha256'], functions),
            'windows.tsv': (['role','start_va','end_va','bytes','raw_hex','sha256'], windows),
            'branches.tsv': (['site_va','raw_hex','taken_va','observation'], branches),
            'calls.tsv': (['site_va','raw_hex','target_va','role'], calls),
            'fields.tsv': (['observation','site_va','raw_hex','decimal','hex'], fields),
            'indirect.tsv': (['site_va','raw_hex','slot_va','relative_addend_va','role'], indirect)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = collect(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, (header, rows) in sorted(result.items()):
        with (args.out / name).open('w', encoding='utf-8', newline='') as handle:
            writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
            writer.writerow(header)
            writer.writerows(rows)
    summary = {'target_sha256': SHA256, 'coordinate_system': 'linked ELF virtual address',
               'counts': {name: len(rows) for name, (_, rows) in sorted(result.items())},
               'coverage': 'two complete FDE byte windows; selected verified branch sites only',
               'captured_binary_executed': False}
    (args.out / 'summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
