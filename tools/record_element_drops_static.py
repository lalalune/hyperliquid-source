#!/usr/bin/env python3
"""Pin the two element drops that consume the RE-015 assembled
0x40-byte records on the destroy paths of node 115.

Context: the assembled-record readers packet (#2559) traced the
destroy paths of the records -- the pair drop 0x15ac5f0 drops every
first-vector element through the element drop 0x1538ec0, and the
exit reader 0x4749ab0 destroys its temp pair copy's first-vector
elements through 0x474dcd0 -- but left both element drops as
hash-pinned boundaries (258 bytes each).  The second-structure
readers packet (#2506) had left the same disposition open from the
other side: the final disposition of the taken entries' words,
which sit at the records' +0x30/+0x38 slots, is exactly what these
two drops perform.

The packet pins: (1) the field-by-field consumption of one
0x40-byte record by the drop -- the buffer pair at +0x0/+0x8 freed
through the dealloc slot gated on the size word, the tagged pair
at +0x30/+0x38 destroyed through its descriptor (drop word, then
dealloc with the tzcnt size-class idiom over descriptor words
+0x8/+0x10), and the 0x10-byte-element sub-vector headed at +0x18
drained by a callee and freed at word * 0x10 from the buffer word
at +0x20; the record words at +0x10 and +0x28 are never loaded;
(2) the clone verdict -- the two bodies are identical at the
pinned instruction shape, their byte differences confined to
RIP-relative displacements (the same two slots), the
_Unwind_Resume rel32 (the same target) and the two sub-vector
drain call targets per body; (3) the call census -- the
0x1538ec0 instance is called only by the pair drop (its main
element loop and its landing-pad loop), the 0x474dcd0 instance is
shared by eight call sites in four functions of the delegate
module, the exit reader among them; (4) the unwind shape -- each
landing pad re-runs the descriptor free, drains the sub-vector
through the alternate (unwind) drain callee, and the second
landing pad calls through the cleanup slot 0x64df4c0 before
freeing the sub-vector buffer and resuming.  Static evidence
only; no captured code is executed.
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
    'vec_a_element_drop': (
        0x1538ec0, 0x1538fc2,
        '7e210dddf72e2ea2174d3e9ab9f5e285c76d2dedee2762fa42b3aaea7d41033d'),
    'reader_element_drop': (
        0x474dcd0, 0x474ddd2,
        '1eb9998a3ae04a9d04b65c94b6152313072624627f05778250ee744c157d068e'),
}
BOUNDARIES = {
    'pair_drop': (
        0x15ac5f0, 0x15ac779,
        'e2953a3c6bd271b64b76fcef0d618208195a928d6a9b24ffb2da1b9734079995'),
    'exit_reader': (
        0x4749ab0, 0x4749d71,
        '6f4caa139b97d81e99776e8cf0f570c906c02c5133d755baec41104d77e9b0bb'),
    'vec_a_subvec_drain': (
        0x153deb0, 0x153df9b,
        '77384034eb0db4b419f2ae44c146d2b4b1d234915d41503715cc2f93235ea2be'),
    'vec_a_subvec_drain_unwind': (
        0x1539990, 0x15399e6,
        '8bf08c4e4144116fc33dc99728b6575dfbe2fa7e8a60badb30148531415e7b6e'),
    'reader_subvec_drop': (
        0x474e8a0, 0x474e98b,
        '21ec3b9046cb0e2e6cd091e7d20552f94cbe40a9da2ab582c98111a771b7417e'),
    'reader_subvec_drain_unwind': (
        0x474e270, 0x474e2c6,
        '6307eff4fed38574504cb88e145950f5d83deb72ee5d032e082f767dd3de1680'),
}

DROP_A_PINS = {
    'buf_size_word': (0x1538ecb, b'H\x8b7'),
    'buf_ptr_word': (0x1538ed3, b'H\x8b{\x08'),
    'tagged_data_word': (0x1538edf, b'L\x8b{0'),
    'tagged_desc_word': (0x1538ee3, b'L\x8bc8'),
    'desc_drop_word': (0x1538ee7, b'I\x8b\x04$'),
    'desc_data_arg': (0x1538ef0, b'L\x89\xff'),
    'desc_drop_call': (0x1538ef3, b'\xff\xd0'),
    'desc_size_word': (0x1538ef5, b'I\x8bt$\x08'),
    'desc_align_word': (0x1538eff, b'I\x8bD$\x10'),
    'desc_align_tzcnt': (0x1538f04, b'\xf3H\x0f\xbc\xc8'),
    'subvec_base_lea': (0x1538f21, b'L\x8d{\x18'),
    'subvec_drain_call': (0x1538f28, b'\xe8\x83O\x00\x00'),
    'subvec_count_word': (0x1538f2d, b'I\x8b7'),
    'subvec_buffer_word': (0x1538f35, b'H\x8b{\x20'),
    'subvec_size_shift': (0x1538f39, b'H\xc1\xe6\x04'),
    'lp_desc_size_word': (0x1538f5f, b'I\x8bt$\x08'),
    'lp_subvec_drain_call': (0x1538f92, b'\xe8\xf9\x09\x00\x00'),
    'lp2_subvec_count_word': (0x1538fa2, b'I\x8b7'),
    'unwind_resume_call': (0x1538fbd, b'\xe8\x8ez\xeb\x04'),
}
DROP_B_PINS = {
    'buf_size_word': (0x474dcdb, b'H\x8b7'),
    'buf_ptr_word': (0x474dce3, b'H\x8b{\x08'),
    'tagged_data_word': (0x474dcef, b'L\x8b{0'),
    'tagged_desc_word': (0x474dcf3, b'L\x8bc8'),
    'desc_drop_word': (0x474dcf7, b'I\x8b\x04$'),
    'desc_data_arg': (0x474dd00, b'L\x89\xff'),
    'desc_drop_call': (0x474dd03, b'\xff\xd0'),
    'desc_size_word': (0x474dd05, b'I\x8bt$\x08'),
    'desc_align_word': (0x474dd0f, b'I\x8bD$\x10'),
    'desc_align_tzcnt': (0x474dd14, b'\xf3H\x0f\xbc\xc8'),
    'subvec_base_lea': (0x474dd31, b'L\x8d{\x18'),
    'subvec_drain_call': (0x474dd38, b'\xe8c\x0b\x00\x00'),
    'subvec_count_word': (0x474dd3d, b'I\x8b7'),
    'subvec_buffer_word': (0x474dd45, b'H\x8b{\x20'),
    'subvec_size_shift': (0x474dd49, b'H\xc1\xe6\x04'),
    'lp_desc_size_word': (0x474dd6f, b'I\x8bt$\x08'),
    'lp_subvec_drain_call': (0x474dda2, b'\xe8\xc9\x04\x00\x00'),
    'lp2_subvec_count_word': (0x474ddb2, b'I\x8b7'),
    'unwind_resume_call': (0x474ddcd, b'\xe8~,\xca\x01'),
}
HELPER_PIN_TABLES = {
    'vec_a_element_drop': DROP_A_PINS,
    'reader_element_drop': DROP_B_PINS,
}
SLOT_CALL_PINS = {
    'a_buf_free': (0x1538ed9, 0x64df4a0),
    'a_desc_free': (0x1538f1b, 0x64df4a0),
    'a_subvec_free_tail': (0x1538f4a, 0x64df4a0),
    'a_lp_desc_free': (0x1538f85, 0x64df4a0),
    'a_lp_cleanup': (0x1538f99, 0x64df4c0),
    'a_lp2_subvec_free': (0x1538fb4, 0x64df4a0),
    'b_buf_free': (0x474dce9, 0x64df4a0),
    'b_desc_free': (0x474dd2b, 0x64df4a0),
    'b_subvec_free_tail': (0x474dd5a, 0x64df4a0),
    'b_lp_desc_free': (0x474dd95, 0x64df4a0),
    'b_lp_cleanup': (0x474dda9, 0x64df4c0),
    'b_lp2_subvec_free': (0x474ddc4, 0x64df4a0),
}
CALL_CENSUS_TARGETS = {
    'vec_a_element_drop': 0x1538ec0,
    'reader_element_drop': 0x474dcd0,
}
EXPECTED_CENSUS = {
    'vec_a_element_drop': [
        ('0x15ac61d', ['0x15ac5f0', '0x15ac779']),
        ('0x15ac73d', ['0x15ac5f0', '0x15ac779']),
    ],
    'reader_element_drop': [
        ('0x4740dfd', ['0x4740dd0', '0x4740e7c']),
        ('0x4740e4d', ['0x4740dd0', '0x4740e7c']),
        ('0x4747ded', ['0x4747dc0', '0x4747f49']),
        ('0x4747f0d', ['0x4747dc0', '0x4747f49']),
        ('0x47481ed', ['0x47481c0', '0x474826c']),
        ('0x474823d', ['0x47481c0', '0x474826c']),
        ('0x4749b6d', ['0x4749ab0', '0x4749d71']),
        ('0x4749d2c', ['0x4749ab0', '0x4749d71']),
    ],
}
DEALLOC_SLOT = 0x64df4a0
CLEANUP_SLOT = 0x64df4c0


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
    require(raw[:2] in (b'\xff\x15', b'\xff%'),
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
    return raw, None


def shape_compare(data):
    """Compare the two drop bodies instruction by instruction."""
    a0, a1, _ = OWNERS['vec_a_element_drop']
    b0, b1, _ = OWNERS['reader_element_drop']
    ins_a, _ = _decoded(data, a0, a1)
    ins_b, _ = _decoded(data, b0, b1)
    offs_a = sorted(s - a0 for s in ins_a)
    offs_b = sorted(s - b0 for s in ins_b)
    require(offs_a == offs_b, 'drop instruction offsets diverged')
    differences = []
    for off in offs_a:
        raw_a, raw_b = ins_a[a0 + off], ins_b[b0 + off]
        masked_a, kind_a = _mask(raw_a)
        masked_b, kind_b = _mask(raw_b)
        require(masked_a == masked_b and kind_a == kind_b,
                f'drop instruction shape diverged at offset {off:#x}')
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
                    a0 + off + 6 + struct.unpack('<i', raw_a[2:])[0])
                row['b_target'] = hex(
                    b0 + off + 6 + struct.unpack('<i', raw_b[2:])[0])
            differences.append(row)
    return {'instructions': len(offs_a),
            'masked_identical': True,
            'differences': differences}


def field_census(data):
    """Collect the element-pointer displacements each drop loads."""
    import re
    out = {}
    for role, (a, b, _) in OWNERS.items():
        _, asm = _decoded(data, a, b)
        disps = set()
        for m in re.finditer(r'\[rbx\+(0x[0-9a-f]+)\]', asm):
            disps.add(m.group(1))
        out[role] = {'rbx_displacements': sorted(disps),
                     'rdi_entry_loads': len(re.findall(r'\[rdi\]', asm))}
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
    shape = shape_compare(data)
    fields = field_census(data)
    for role in OWNERS:
        if fields[role] != {'rbx_displacements':
                            ['0x18', '0x20', '0x30', '0x38', '0x8'],
                            'rdi_entry_loads': 1}:
            raise ValueError(f'{role} element field census changed')
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
        'shape': shape, 'element_fields': fields,
        'field_verdict':
            'Both element drops consume one 0x40-byte record '
            '(argument in rdi, kept in rbx) in the same order.  '
            '(1) The buffer pair: the word at +0x0 is loaded as the '
            'size (0x1538ecb / 0x474dcdb); if it is non-zero the '
            'pointer at +0x8 (0x1538ed3 / 0x474dce3) is freed '
            'through the dealloc slot 0x64df4a0 (RELATIVE target '
            '0x635de30) with that size and align 0.  (2) The tagged '
            'pair: data word at +0x30 and descriptor word at +0x38 '
            'are loaded (0x1538edf / 0x1538ee3); descriptor word 0 '
            'is called on the data when non-null (0x1538ef3), then '
            'the data is freed through the dealloc slot with the '
            'size class computed from descriptor words +0x8 (size) '
            'and +0x10 (align) by the tzcnt/cmova idiom (0x1538f04), '
            'gated on the size word.  This is the final disposition '
            'of the taken entries\' +0x8/+0x10 words that #2506 '
            'staged into the records and #2559 followed to these '
            'drops.  (3) The sub-vector headed at +0x18: a drain '
            'callee is called on element+0x18, then the header word '
            'at +0x18 is loaded and, if non-zero, the buffer at '
            '+0x20 is freed through the dealloc slot at word * 0x10 '
            'bytes (shl 4 at 0x1538f39) as a tail jump.  The record '
            'words at +0x10 and +0x28 are never loaded anywhere in '
            'either body (element field census over both dumps: '
            'the +0x0 word is loaded once at entry through rdi, '
            'and the rbx displacements are exactly +0x8, +0x18, '
            '+0x20, +0x30, +0x38).',
        'clone_verdict':
            'The two bodies (258 bytes each) are one implementation '
            'instantiated twice.  Decoded instruction offsets are '
            'identical (80 instructions), and after masking the '
            'address-dependent tails of branch and slot '
            'instructions the byte streams are identical.  Every '
            'unmasked difference is one of: a RIP-relative '
            'displacement to one of the same two slots (0x64df4a0 '
            'five times per body, 0x64df4c0 once), the rel32 to the '
            'same _Unwind_Resume PLT entry 0x63f0a50, or a drain '
            'callee rel32 -- the normal-path drain (0x153deb0 in '
            'the vec-A instance, 0x474e8a0 in the reader instance) '
            'and the unwind-path drain (0x1539990 / 0x474e270).  '
            'The bodies\' own hashes differ, as the pinned records '
            'show; identity is claimed at the masked instruction '
            'shape only, exactly as #2559 claimed for its tagged '
            'destroy pair.',
        'census_verdict':
            'Direct-call census over the whole .text (sites '
            'attributed by containing FDE): the vec-A drop '
            '0x1538ec0 has exactly two call sites, both in the pair '
            'drop 0x15ac5f0 -- its main element loop (0x15ac61d) '
            'and its landing-pad loop (0x15ac73d), which re-walks '
            'the remaining elements stepping 0x40 before freeing '
            'the buffer and calling the pair tail helper.  The '
            'reader drop 0x474dcd0 has eight call sites in four '
            'functions of the delegate module: 0x4740dd0 (0x4740dfd, '
            '0x4740e4d), 0x4747dc0 (0x4747ded, 0x4747f0d), 0x47481c0 '
            '(0x47481ed, 0x474823d) and the exit reader 0x4749ab0 '
            '(0x4749b6d in the discriminant arm, 0x4749d2c in its '
            'cleanup).  The three sibling callers are recorded by '
            'FDE range only; no other direct caller of either drop '
            'exists in the binary.',
        'unwind_verdict':
            'Each body carries the same two landing pads.  The '
            'first pad (0x1538f5c / 0x474dd6c) saves the exception, '
            're-runs the tagged pair\'s descriptor free with the '
            'same tzcnt class idiom, drains the sub-vector through '
            'the alternate unwind drain callee (0x1539990 / '
            '0x474e270, called on element+0x18), and falls into the '
            'resume.  The second pad (0x1538f99 / 0x474dda9) first '
            'calls through the cleanup slot 0x64df4c0 (RELATIVE '
            'target 0x1680cab), then frees the sub-vector buffer '
            '(header word at +0x18, buffer at +0x20, size word * '
            '0x10) through the dealloc slot, and resumes through '
            '_Unwind_Resume (PLT 0x63f0a50).  Neither pad touches '
            'the +0x0/+0x8 buffer pair or the tagged pair\'s drop '
            'word beyond the first pad\'s descriptor free.',
        'limits':
            'Static trace only.  Hash-pinned, not traced: the pair '
            'drop and the exit reader (owners of #2559, retained '
            'here as boundary context), the four sub-vector drain '
            'callees (0x153deb0 / 0x1539990 / 0x474e8a0 / '
            '0x474e270), the dealloc target 0x635de30, the cleanup '
            'target 0x1680cab, and _Unwind_Resume.  The three '
            'sibling callers of the reader drop are recorded by '
            'FDE range only.  What the drain callees do per '
            '0x10-byte sub-vector element, what the record words '
            'at +0x10 and +0x28 hold (never loaded here), and any '
            'semantic name for the record type are not claimed.  '
            'No captured code executed, no runtime value or '
            'reconstruction gate is claimed.',
        'next_question':
            'What do the four sub-vector drain callees do per '
            '0x10-byte element of the record\'s +0x18 sub-vector -- '
            'and are the two drain pairs (normal 0x153deb0 / '
            '0x474e8a0, 235 bytes each; unwind 0x1539990 / '
            '0x474e270, 86 bytes each) also shape-identical clones '
            'of one another, as their matching sizes suggest?'}


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
        prefixes = {'vec_a_element_drop': 'a_', 'reader_element_drop': 'b_'}
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
                   default=ROOT / 'work/record-element-drops115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
