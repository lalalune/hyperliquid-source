#!/usr/bin/env python3
"""Pin the four sub-vector drain callees of the RE-015 record
element drops on node 115.

Context: the record element drops packet (#2714) traced the two
drops that destroy the assembled 0x40-byte records -- each drop
hands the record's +0x18 sub-vector to a drain callee on its
normal path and to an alternate drain callee from its first
landing pad -- but left all four callees hash-pinned:

    normal   0x153deb0 (235 B)    unwind   0x1539990 (86 B)
    normal   0x474e8a0 (235 B)    unwind   0x474e270 (86 B)

This packet opens all four.  The packet pins: (1) the header
layout the drains read -- the argument is the sub-vector header
at record +0x18, a 24-byte vector header whose word at +0x8 is
the buffer pointer and whose word at +0x10 is the live element
count (the record word at +0x28 that #2714 found never loaded
by the drops themselves; the word at header +0x0 is the
capacity word the drops size their buffer free by); (2) the
per-element behaviour of the normal drains -- the buffer holds
0x10-byte tagged pairs {data, descriptor}; for each pair, in
buffer order, descriptor word 0 is called on the data when
non-null, then the data is freed through the dealloc slot
0x64df4a0 with the size class computed from descriptor words
+0x8 (size) and +0x10 (align) by the tzcnt/cmov idiom, gated
on the size word; the buffer itself is NOT freed by the normal
drain; (3) the landing pad inside the normal drains --
the interrupted element's descriptor free is re-run through
the slot (with the pad's cmov variant), the remaining elements
are handed pairwise to a pair-destroy helper (0x1537b00 /
0x474e0b0, hash-pinned boundaries here), and the body ends
with a call through the cleanup slot 0x64df4c0; (4) the
unwind drains -- thin wrappers that call their module's
normal drain and then free the buffer themselves (header word
at +0x0, shifted left 4, through the dealloc slot, as a tail
jump; the pad re-runs the same free through the slot before
_Unwind_Resume); (5) the clone verdicts -- both same-size
pairs are clones at the masked instruction shape, judged
exactly as #2714 judged the drops; (6) the call census --
each normal drain has nine direct call sites and each unwind
drain two, the element drops' own sites among them, the
remaining callers recorded by containing FDE only.  Static
evidence only; no captured code is executed.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export, require

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'

OWNERS = {
    'vec_a_subvec_drain': (
        0x153deb0, 0x153df9b,
        '77384034eb0db4b419f2ae44c146d2b4b1d234915d41503715cc2f93235ea2be'),
    'vec_a_subvec_drain_unwind': (
        0x1539990, 0x15399e6,
        '8bf08c4e4144116fc33dc99728b6575dfbe2fa7e8a60badb30148531415e7b6e'),
    'reader_subvec_drain': (
        0x474e8a0, 0x474e98b,
        '21ec3b9046cb0e2e6cd091e7d20552f94cbe40a9da2ab582c98111a771b7417e'),
    'reader_subvec_drain_unwind': (
        0x474e270, 0x474e2c6,
        '6307eff4fed38574504cb88e145950f5d83deb72ee5d032e082f767dd3de1680'),
}
BOUNDARIES = {
    'vec_a_element_drop': (
        0x1538ec0, 0x1538fc2,
        '7e210dddf72e2ea2174d3e9ab9f5e285c76d2dedee2762fa42b3aaea7d41033d'),
    'reader_element_drop': (
        0x474dcd0, 0x474ddd2,
        '1eb9998a3ae04a9d04b65c94b6152313072624627f05778250ee744c157d068e'),
    'vec_a_pair_destroy_helper': (
        0x1537b00, 0x1537b82,
        '30ce062b876d862e3961d70031ed434c3e520457bc3c16900e1b6fafa6a4511a'),
    'reader_pair_destroy_helper': (
        0x474e0b0, 0x474e132,
        'ae6e68cf8978e52df9dda3f1d2849d62d09fa99f0f880c04137413d82a93a12d'),
}

DRAIN_A_PINS = {
    'count_word': (0x153debb, b'L\x8b\x7f\x10'),
    'buffer_word': (0x153dec4, b'L\x8b\x67\x08'),
    'cursor_seed': (0x153dec8, b'I\x83\xc4\x18'),
    'dealloc_load': (0x153dece, b'L\x8b\x2d'),
    'elem_data_load': (0x153dee9, b'M\x8b\x74\x24\xe8'),
    'elem_desc_load': (0x153deee, b'I\x8b\x6c\x24\xf0'),
    'desc_drop_word': (0x153def3, b'H\x8b\x45\x00'),
    'desc_drop_call': (0x153deff, b'\xff\xd0'),
    'desc_size_word': (0x153df01, b'H\x8b\x75\x08'),
    'desc_align_word': (0x153df0a, b'H\x8b\x45\x10'),
    'desc_align_tzcnt': (0x153df0e, b'\xf3H\x0f\xbc\xc8'),
    'dealloc_call_reg': (0x153df25, b'A\xff\xd5'),
    'pad_desc_size_word': (0x153df3c, b'H\x8b\x75\x08'),
    'pad_helper_call': (0x153df83, b'\xe8\x78\x9b\xff\xff'),
    'unwind_resume_call': (0x153df90, b'\xe8\xbb\x2a\xeb\x04'),
}
DRAIN_B_PINS = {
    'count_word': (0x474e8ab, b'L\x8b\x7f\x10'),
    'buffer_word': (0x474e8b4, b'L\x8b\x67\x08'),
    'cursor_seed': (0x474e8b8, b'I\x83\xc4\x18'),
    'dealloc_load': (0x474e8be, b'L\x8b\x2d'),
    'elem_data_load': (0x474e8d9, b'M\x8b\x74\x24\xe8'),
    'elem_desc_load': (0x474e8de, b'I\x8b\x6c\x24\xf0'),
    'desc_drop_word': (0x474e8e3, b'H\x8b\x45\x00'),
    'desc_drop_call': (0x474e8ef, b'\xff\xd0'),
    'desc_size_word': (0x474e8f1, b'H\x8b\x75\x08'),
    'desc_align_word': (0x474e8fa, b'H\x8b\x45\x10'),
    'desc_align_tzcnt': (0x474e8fe, b'\xf3H\x0f\xbc\xc8'),
    'dealloc_call_reg': (0x474e915, b'A\xff\xd5'),
    'pad_desc_size_word': (0x474e92c, b'H\x8b\x75\x08'),
    'pad_helper_call': (0x474e973, b'\xe8\x38\xf7\xff\xff'),
    'unwind_resume_call': (0x474e980, b'\xe8\xcb\x20\xca\x01'),
}
UNWIND_A_PINS = {
    'header_keep': (0x1539994, b'H\x89\xfb'),
    'drain_call': (0x1539997, b'\xe8\x14\x45\x00\x00'),
    'cap_word': (0x153999c, b'H\x8b\x33'),
    'buffer_word': (0x15399a4, b'H\x8b\x7b\x08'),
    'size_shift': (0x15399a8, b'H\xc1\xe6\x04'),
    'pad_cap_word': (0x15399c6, b'H\x8b\x33'),
    'pad_buffer_word': (0x15399ce, b'H\x8b\x7b\x08'),
    'unwind_resume_call': (0x15399e1, b'\xe8\x6a\x70\xeb\x04'),
}
UNWIND_B_PINS = {
    'header_keep': (0x474e274, b'H\x89\xfb'),
    'drain_call': (0x474e277, b'\xe8\x24\x06\x00\x00'),
    'cap_word': (0x474e27c, b'H\x8b\x33'),
    'buffer_word': (0x474e284, b'H\x8b\x7b\x08'),
    'size_shift': (0x474e288, b'H\xc1\xe6\x04'),
    'pad_cap_word': (0x474e2a6, b'H\x8b\x33'),
    'pad_buffer_word': (0x474e2ae, b'H\x8b\x7b\x08'),
    'unwind_resume_call': (0x474e2c1, b'\xe8\x8a\x27\xca\x01'),
}
HELPER_PIN_TABLES = {
    'vec_a_subvec_drain': DRAIN_A_PINS,
    'reader_subvec_drain': DRAIN_B_PINS,
    'vec_a_subvec_drain_unwind': UNWIND_A_PINS,
    'reader_subvec_drain_unwind': UNWIND_B_PINS,
}
SLOT_CALL_PINS = {
    'a_pad_dealloc': (0x153df60, 0x64df4a0),
    'a_cleanup_tail': (0x153df95, 0x64df4c0),
    'b_pad_dealloc': (0x474e950, 0x64df4a0),
    'b_cleanup_tail': (0x474e985, 0x64df4c0),
    'a_unwind_free_tail': (0x15399b5, 0x64df4a0),
    'a_unwind_pad_dealloc': (0x15399d8, 0x64df4a0),
    'b_unwind_free_tail': (0x474e295, 0x64df4a0),
    'b_unwind_pad_dealloc': (0x474e2b8, 0x64df4a0),
}
CALL_CENSUS_TARGETS = {
    'vec_a_subvec_drain': 0x153deb0,
    'vec_a_subvec_drain_unwind': 0x1539990,
    'reader_subvec_drain': 0x474e8a0,
    'reader_subvec_drain_unwind': 0x474e270,
}
EXPECTED_CENSUS = {
    'vec_a_subvec_drain': [
        ('0x1538559', ['0x1538460', '0x153871b']),
        ('0x1538f28', ['0x1538ec0', '0x1538fc2']),
        ('0x1539997', ['0x1539990', '0x15399e6']),
        ('0x1569cd7', ['0x1569cd0', '0x1569d26']),
        ('0x156a109', ['0x156a010', '0x156a2cb']),
        ('0x158b8e7', ['0x158b8e0', '0x158b936']),
        ('0x15ac917', ['0x15ac910', '0x15ac966']),
        ('0x15bb967', ['0x15bb960', '0x15bb9b6']),
        ('0x15bf22f', ['0x15bf200', '0x15bf2b5']),
    ],
    'vec_a_subvec_drain_unwind': [
        ('0x15386a3', ['0x1538460', '0x153871b']),
        ('0x1538f92', ['0x1538ec0', '0x1538fc2']),
    ],
    'reader_subvec_drain': [
        ('0x4747d18', ['0x4747cb0', '0x4747db2']),
        ('0x4747f57', ['0x4747f50', '0x4747fa6']),
        ('0x47487ed', ['0x4748500', '0x4749aa9']),
        ('0x474dbf0', ['0x474dba0', '0x474dc86']),
        ('0x474dd38', ['0x474dcd0', '0x474ddd2']),
        ('0x474e277', ['0x474e270', '0x474e2c6']),
        ('0x4753130', ['0x47530e0', '0x47531c6']),
        ('0x4753238', ['0x47531d0', '0x47532d2']),
        ('0x4753457', ['0x4753450', '0x47534a6']),
    ],
    'reader_subvec_drain_unwind': [
        ('0x474dc56', ['0x474dba0', '0x474dc86']),
        ('0x474dda2', ['0x474dcd0', '0x474ddd2']),
    ],
}
DEALLOC_SLOT = 0x64df4a0
CLEANUP_SLOT = 0x64df4c0
PAIRS = [('vec_a_subvec_drain', 'reader_subvec_drain'),
         ('vec_a_subvec_drain_unwind', 'reader_subvec_drain_unwind')]


def read(data, va, n):
    for s in sections(data):
        if s['type'] != 8 and s['address'] <= va < s['address'] + s['size']:
            off = s['offset'] + va - s['address']
            if off + n > s['offset'] + s['size']:
                break
            return off, data[off:off + n]
    raise ValueError(f'unmapped {va:#x}')


def _pin(data, site, expected, label):
    if read(data, site, len(expected))[1] != expected:
        raise ValueError(f'{label} changed')


def _pins(data, table, role):
    for label, (site, expected) in table.items():
        _pin(data, site, expected, f'{role} {label}')


def _slot_call(data, site, slot, label):
    raw = read(data, site, 6)[1]
    require(raw[:2] in (b'\xff\x15', b'\xff\x25', b'\xff%'),
            f'{label} is not a slot call')
    disp = struct.unpack('<i', raw[2:])[0]
    require(site + 6 + disp == slot, f'{label} slot changed')


def _relocations(data):
    s = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    out = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        offset, info, addend = struct.unpack_from('<QQq', data, off)
        out[offset] = {'type': info & 0xffffffff,
                       'symbol': info >> 32, 'addend': addend}
    return out


def slot_bindings(data):
    rel = _relocations(data)
    out = {}
    for name, slot in (('dealloc', DEALLOC_SLOT),
                       ('unwind_cleanup', CLEANUP_SLOT)):
        entry = rel[slot]
        out[name] = {'slot': hex(slot), 'type': entry['type'],
                     'addend': hex(entry['addend'])}
    return out


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)], text=True)


def _decoded(data, start, end):
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node115.elf'
        snapshot.write_bytes(data)
        asm = _objdump(snapshot, start, end)
    return decode_export(asm, start, end,
                         read(data, start, end - start)[1]), asm


def _mask(raw):
    """Zero the address-dependent tail of a branch/slot instruction."""
    if raw[:1] in (b'\xe8', b'\xe9'):
        return raw[:-4] + b'\0\0\0\0', 'rel32'
    if raw[:1] == b'\xeb' or (raw and 0x70 <= raw[0] <= 0x7f):
        return raw[:-1] + b'\0', 'rel8'
    if len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return raw[:-4] + b'\0\0\0\0', 'rel32'
    if raw[:2] in (b'\xff\x15', b'\xff\x25'):
        return raw[:-4] + b'\0\0\0\0', 'ripdisp32'
    if len(raw) >= 7 and 0x40 <= raw[0] <= 0x4f and raw[1] == 0x8b \
            and (raw[2] & 0xc7) == 0x05:
        return raw[:-4] + b'\0\0\0\0', 'ripdisp32'
    return raw, None


def _pair_shape(data, role_a, role_b):
    a0, a1, _ = OWNERS[role_a]
    b0, b1, _ = OWNERS[role_b]
    ins_a, _ = _decoded(data, a0, a1)
    ins_b, _ = _decoded(data, b0, b1)
    offs_a = sorted(s - a0 for s in ins_a)
    offs_b = sorted(s - b0 for s in ins_b)
    require(offs_a == offs_b,
            f'{role_a}/{role_b} instruction offsets diverged')
    differences = []
    for off in offs_a:
        raw_a, raw_b = ins_a[a0 + off], ins_b[b0 + off]
        masked_a, kind_a = _mask(raw_a)
        masked_b, kind_b = _mask(raw_b)
        require(masked_a == masked_b and kind_a == kind_b,
                f'{role_a}/{role_b} shape diverged at offset {off:#x}')
        if raw_a != raw_b:
            row = {'offset': hex(off), 'kind': kind_a,
                   'a_bytes': raw_a.hex(), 'b_bytes': raw_b.hex()}
            if kind_a == 'rel32' and raw_a[:1] == b'\xe8':
                row['a_target'] = hex(
                    a0 + off + 5 + struct.unpack('<i', raw_a[1:])[0])
                row['b_target'] = hex(
                    b0 + off + 5 + struct.unpack('<i', raw_b[1:])[0])
            if kind_a == 'ripdisp32':
                row['a_target'] = hex(
                    a0 + off + len(raw_a)
                    + struct.unpack('<i', raw_a[-4:])[0])
                row['b_target'] = hex(
                    b0 + off + len(raw_b)
                    + struct.unpack('<i', raw_b[-4:])[0])
            differences.append(row)
    return {'a': role_a, 'b': role_b,
            'instructions': len(offs_a),
            'masked_identical': True,
            'differences': differences}


def shape_compare(data):
    return [_pair_shape(data, a, b) for a, b in PAIRS]


def header_census(data):
    """Collect the header/element displacements each drain loads."""
    import re
    out = {}
    for role in ('vec_a_subvec_drain', 'reader_subvec_drain'):
        a, b, _ = OWNERS[role]
        _, asm = _decoded(data, a, b)
        out[role] = {
            'rdi_displacements': sorted(set(
                re.findall(r'\[rdi\+(0x[0-9a-f]+)\]', asm))),
            'rbp_displacements': sorted(set(
                re.findall(r'\[rbp\+(0x[0-9a-f]+)\]', asm))),
            'rbp_entry_loads': len(re.findall(r'\[rbp\+0x0\]', asm)),
            'cursor_loads': sorted(set(
                re.findall(r'\[r12-(0x[0-9a-f]+)\]', asm))),
        }
    for role in ('vec_a_subvec_drain_unwind',
                 'reader_subvec_drain_unwind'):
        a, b, _ = OWNERS[role]
        _, asm = _decoded(data, a, b)
        out[role] = {
            'rbx_displacements': sorted(set(
                re.findall(r'\[rbx\+(0x[0-9a-f]+)\]', asm))),
            'rbx_entry_loads': len(re.findall(r'\[rbx\]', asm)),
        }
    return out


def direct_call_census(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, raw = sec['address'], data[sec['offset']:sec['offset'] + sec['size']]
    _, fs, _ = fde_extents(data)
    starts = sorted(f['start'] for f in fs)
    by_start = {f['start']: f for f in fs}
    found = {name: [] for name in CALL_CENSUS_TARGETS}
    wanted = {v: k for k, v in CALL_CENSUS_TARGETS.items()}
    i = raw.find(b'\xe8')
    while i != -1:
        if i + 5 <= len(raw):
            rel = struct.unpack_from('<i', raw, i + 1)[0]
            target = base + i + 5 + rel
            if target in wanted:
                j = bisect.bisect_right(starts, base + i) - 1
                owner = None
                if j >= 0:
                    f = by_start[starts[j]]
                    if f['start'] <= base + i < f['end']:
                        owner = [hex(f['start']), hex(f['end'])]
                found[wanted[target]].append(
                    {'site': hex(base + i), 'owner_fde': owner})
        i = raw.find(b'\xe8', i + 1)
    return {name: {'target': hex(CALL_CENSUS_TARGETS[name]),
                   'sites': [r['site'] for r in rows], 'rows': rows}
            for name, rows in found.items()}


def analyze(data):
    bindings = slot_bindings(data)
    if bindings['dealloc'] != {'slot': hex(DEALLOC_SLOT), 'type': 8,
                                'addend': '0x635de30'}:
        raise ValueError('dealloc slot binding changed')
    if bindings['unwind_cleanup'] != {'slot': hex(CLEANUP_SLOT),
                                       'type': 8, 'addend': '0x1680cab'}:
        raise ValueError('unwind cleanup slot binding changed')
    for role, table in HELPER_PIN_TABLES.items():
        _pins(data, table, role)
    for label, (site, slot) in SLOT_CALL_PINS.items():
        _slot_call(data, site, slot, label)
    census = direct_call_census(data)
    for name, expected in EXPECTED_CENSUS.items():
        rows = [(r['site'], r['owner_fde']) for r in census[name]['rows']]
        if rows != expected:
            raise ValueError(f'direct call census changed for {name}')
    shapes = shape_compare(data)
    headers = header_census(data)
    for role in ('vec_a_subvec_drain', 'reader_subvec_drain'):
        if headers[role] != {
                'rdi_displacements': ['0x10', '0x8'],
                'rbp_displacements': ['0x0', '0x10', '0x8'],
                'rbp_entry_loads': 1,
                'cursor_loads': ['0x10', '0x18', '0x8']}:
            raise ValueError(f'{role} header census changed')
    for role in ('vec_a_subvec_drain_unwind',
                 'reader_subvec_drain_unwind'):
        if headers[role] != {'rbx_displacements': ['0x8'],
                             'rbx_entry_loads': 2}:
            raise ValueError(f'{role} header census changed')
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}

    def frame_records(a, b, sha, role):
        if (a, b) not in fdes:
            raise ValueError(f'{role} scope FDE changed')
        offset, raw = read(data, a, b - a)
        digest = hashlib.sha256(raw).hexdigest()
        if sha is not None and digest != sha:
            raise ValueError(f'{role} body changed')
        records = {}
        for kind in ['fde', 'cie']:
            va = fdes[(a, b)][kind]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            records[kind] = {'va': hex(va),
                             'bytes_hex': read(data, va, n)[1].hex()}
        return {'role': role, 'start': hex(a), 'end': hex(b),
                'file_offset': hex(offset), 'bytes': b - a,
                'sha256': digest, 'frames': records}

    owners = []
    for role, (a, b, sha) in OWNERS.items():
        owners.append(frame_records(a, b, sha, role))
    boundaries = []
    for role, (a, b, sha) in BOUNDARIES.items():
        boundaries.append(frame_records(a, b, sha, role))
    return {
        'target_sha256': SHA, 'owners': owners, 'boundaries': boundaries,
        'slot_bindings': bindings, 'direct_calls': census,
        'shapes': shapes, 'headers': headers,
        'header_verdict':
            'All four drains take the sub-vector header itself in '
            'rdi -- in the drops, the lea of record +0x18 (#2714).  '
            'The header is 24 bytes: the word at +0x0 is the '
            'capacity word (the drops size their post-drain buffer '
            'free by it, word * 0x10, and the unwind drains free '
            'by it the same way); the word at +0x8 is the buffer '
            'pointer; the word at +0x10 is the live element '
            'count.  The normal drains load exactly the +0x8 and '
            '+0x10 header words (header census), so the record '
            'word at +0x28 that #2714 found never loaded by the '
            'drop bodies is the sub-vector length, and it is '
            'loaded here -- as header +0x10.  The buffer holds '
            '0x10-byte elements.',
        'element_verdict':
            'Per element, the normal drains (0x153deb0 / '
            '0x474e8a0) walk the buffer in order with a cursor '
            'seeded at buffer + 0x18 (loads at cursor -0x18 / '
            '-0x10, advancing 0x10 per element, counted by the '
            'header +0x10 word).  Each element is a tagged pair '
            '{data at +0x0, descriptor at +0x8} -- the same '
            'element shape #2559 staged and the drops consume at '
            'record level.  For each pair: descriptor word 0 is '
            'called on the data when non-null (0x153deff / '
            '0x474e8ef); then descriptor word +0x8 is loaded as '
            'the size and, when non-zero, the data is freed '
            'through the dealloc target loaded once from slot '
            '0x64df4a0 (RELATIVE target 0x635de30, called through '
            'r13) with the size class computed from descriptor '
            'words +0x8 (size) and +0x10 (align) by the '
            'tzcnt/cmov idiom (tzcnt at 0x153df0e / 0x474e8fe; '
            'class 0 when align <= size, the tzcnt otherwise, '
            'and the tzcnt whenever align >= 0x11) -- the same '
            'descriptor protocol as the drops\' tagged pair, one '
            'level down.  The normal drain does NOT free the '
            'buffer: on the drops\' normal path the caller frees '
            'it afterwards by the capacity word (#2714 stage 2).  '
            'A zero length returns immediately.',
        'unwind_verdict':
            'The 86-byte bodies (0x1539990 / 0x474e270) are '
            'drain-and-free wrappers, not a second drain '
            'implementation: each calls its own module\'s normal '
            'drain on the header (0x1539997 / 0x474e277), then '
            'frees the buffer itself -- capacity word at header '
            '+0x0 loaded (0x153999c / 0x474e27c), buffer pointer '
            'at +0x8, size word << 4, align 0 -- as a tail jump '
            'through the dealloc slot 0x64df4a0, gated on the '
            'capacity word.  This is exactly the free the drops '
            'perform inline on their normal path, which is why '
            'the drops\' first landing pads route here: on the '
            'unwind path the inline free never runs.  Each '
            'wrapper\'s own landing pad saves the exception, '
            're-runs the same buffer free through the slot '
            '(0x15399d8 / 0x474e2b8), and resumes through '
            '_Unwind_Resume (PLT 0x63f0a50).  Inside the normal '
            'drains, the landing pad (0x153df39 / 0x474e929) '
            'saves the exception, re-runs the interrupted '
            'element\'s descriptor free through the dealloc slot '
            'with the pad cmov variant (class 0 unless align > '
            'size), hands each remaining element pairwise -- '
            'data word, descriptor word, cursor advancing 0x10 '
            '-- to the pair-destroy helper (0x1537b00 / '
            '0x474e0b0, 130 bytes each, hash-pinned boundaries '
            'here), and resumes through _Unwind_Resume; the '
            'normal-drain FDE\'s final instruction is a call '
            'through the cleanup slot 0x64df4c0 (RELATIVE target '
            '0x1680cab) at 0x153df95 / 0x474e985, whose '
            'continuation lies outside the FDE.',
        'clone_verdict':
            'Both same-size pairs are clones at the pinned '
            'instruction shape, judged by the #2714 method '
            '(unmasked instruction diff + consumption order).  '
            'The 235-byte normal drains decode to identical '
            'instruction offsets (72 instructions each) and, '
            'after masking the address-dependent tails of branch '
            'and slot instructions, byte-identical streams; the '
            'unmasked difference is exactly five sites -- three '
            'RIP-relative displacements (the dealloc slot load, '
            'the pad dealloc call, and the cleanup-slot tail '
            'call, all to the same slots in both instances) and '
            'two rel32 calls (the module-local pair-destroy '
            'helper and the shared _Unwind_Resume PLT entry).  '
            'The 86-byte unwind drains are identical under the '
            'same test (29 instructions each, exactly four '
            'differing sites): two RIP-relative dealloc-slot '
            'references to the same slot and two rel32 calls '
            '(the module-local normal-drain target and the '
            'shared _Unwind_Resume).  '
            'Consumption order is the same in both pairs: the '
            'vec-A and reader instances read the same header '
            'words, walk the same cursor, and free through the '
            'same slots.  The bodies\' own hashes differ, as the '
            'pinned records show; identity is claimed at the '
            'masked instruction shape only.',
        'census_verdict':
            'Direct-call census over the whole .text (sites '
            'attributed by containing FDE): the drains are shared '
            'helpers, not drop-private.  Each normal drain has '
            'exactly nine direct call sites and each unwind '
            'drain exactly two, with matching counts per module.  '
            'The vec-A normal drain 0x153deb0 is called by the '
            'element drop 0x1538ec0 (0x1538f28), by its unwind '
            'wrapper (0x1539997), from FDE 0x1538460 (0x1538559) '
            'and from six further FDEs (0x1569cd0, 0x156a010, '
            '0x158b8e0, 0x15ac910, 0x15bb960, 0x15bf200); the '
            'vec-A unwind drain 0x1539990 only from the element '
            'drop\'s first landing pad (0x1538f92) and from FDE '
            '0x1538460 (0x15386a3).  The reader normal drain '
            '0x474e8a0 is called by the reader element drop '
            '(0x474dd38), by its unwind wrapper (0x474e277), by '
            'the merge delegate 0x4748500 (0x47487ed -- the call '
            'the merge-delegate packet #2615 recorded while '
            'leaving this body a hash-pinned boundary), and from '
            'six further FDEs (0x4747cb0, 0x4747f50, 0x474dba0, '
            '0x47530e0, 0x47531d0, 0x4753450); the reader unwind '
            'drain 0x474e270 only from the reader drop\'s first '
            'landing pad (0x474dda2) and from FDE 0x474dba0 '
            '(0x474dc56).  All non-drop callers are recorded by '
            'FDE range only; several are 86-byte FDEs whose shape '
            'matches the unwind wrappers, not traced here.  No '
            'other direct caller of any of the four exists in '
            'the binary.',
        'limits':
            'Static trace only.  Hash-pinned, not traced: the '
            'two element drops (#2714 owners, retained here as '
            'boundary context), the two pair-destroy helpers '
            '0x1537b00 / 0x474e0b0 the normal drains\' landing '
            'pads hand remaining elements to, the dealloc target '
            '0x635de30, the cleanup target 0x1680cab, and '
            '_Unwind_Resume.  Non-drop callers of the drains are '
            'recorded by FDE range only, and whether every '
            'caller passes the same 24-byte header layout is '
            'established only for the drops\' sites (record '
            '+0x18) and the merge delegate\'s element +0x18/+0x20 '
            'site recorded by #2615.  What the elements\' '
            'descriptor drop functions do beyond the call, and '
            'any semantic name for the element type, are not '
            'claimed.  No captured code executed, no runtime '
            'value or reconstruction gate is claimed.',
        'next_question':
            'Are the two pair-destroy helpers the normal drains\' '
            'landing pads hand remaining elements to (0x1537b00 '
            '/ 0x474e0b0, 130 bytes each, hash-pinned in this '
            'packet) also clones of one another -- and do the '
            '86-byte caller FDEs in the drains\' census (several '
            'per module) form a wrapper family of the same '
            'drain-and-free shape over other vector headers?'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('expected pinned node115')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    lines = []
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node115.elf'
        snapshot.write_bytes(data)
        native = subprocess.check_output(['readelf', '-wf', str(snapshot)],
                                         text=True)
        for role, (a, b, _) in list(OWNERS.items()) + \
                list(BOUNDARIES.items()):
            rows = [l for l in native.splitlines()
                    if f'pc={a:016x}..{b:016x}' in l]
            if len(rows) != 1:
                raise ValueError('native FDE disagreement')
            lines.extend(rows)
        prefixes = {'vec_a_subvec_drain': 'a_',
                    'vec_a_subvec_drain_unwind': 'a_unwind_',
                    'reader_subvec_drain': 'b_',
                    'reader_subvec_drain_unwind': 'b_unwind_'}
        for name, a, b in [(role, v[0], v[1]) for role, v in
                           OWNERS.items()]:
            easm = _objdump(snapshot, a, b)
            eins = decode_export(easm, a, b, read(data, a, b - a)[1])
            esites = {site for site, _ in
                      HELPER_PIN_TABLES[name].values()}
            esites |= {site for label, (site, _) in SLOT_CALL_PINS.items()
                       if label.startswith(prefixes[name])
                       and a <= site < b}
            if not esites <= set(eins):
                raise ValueError(f'{name} evidence site not native '
                                 'instruction start')
            (output / f'{name}_objdump.txt').write_bytes(
                easm.replace(str(snapshot),
                             '<authenticated-node115>').encode('utf-8'))
    (output / 'frames.txt').write_bytes(
        ('\n'.join(lines) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes(
        (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--output', type=Path,
                   default=ROOT / 'work/subvec-drain-callees115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
