#!/usr/bin/env python3
"""Pin the RE-015 pair-destroy helper pair and the caller family
of the 86-byte drain+free wrappers on node 115.

Context: the sub-vector drain callees packet traced the four
drain callees of the record element drops and left two questions:
(1) the pair-destroy helpers 0x1537b00 / 0x474e0b0 (130 bytes
each, hash-pinned there) that the normal drains' landing pads
hand the remaining elements to -- what one call does per element,
and whether the two are clones of one another; (2) whether the
caller FDEs of the 86-byte unwind drains (two per module: the
element drop and one further record destructor) form a wrapper
family of the same drain-and-free shape over other vector
headers.

This packet opens both helpers in full and pins the shape of
all four wrapper callers.  Findings: (1) one pair-destroy call
destroys exactly ONE element -- rdi = the element's data word,
rsi = its descriptor word: descriptor word 0 is called on the
data when non-null, then, when the descriptor size word (+0x8)
is non-zero, the data is freed through the dealloc slot
0x64df4a0 with the class computed from the align word (+0x10)
by the tzcnt/cmov idiom, as a tail jump; the landing pad
re-runs the same free in call form when the descriptor call
throws, then resumes.  The loop over the remaining elements
lives in the drain pads, not in the helpers.  (2) The helpers
are clones at the masked instruction shape: 44 instructions
each, identical offsets, exactly three unmasked differences,
all of them 4-byte displacement fields resolving to the SAME
shared targets (the dealloc slot twice, the _Unwind_Resume
PLT once) -- no difference resolves to a module-local target.
(3) The four wrapper callers are NOT wrappers themselves and
are not mutual clones (258 / 699 / 258 / 230 bytes); each is a
record destructor that embeds the same two-half pattern over
its record's sub-vector header: on the normal path it calls
its module's normal drain on the header and then frees the
buffer inline by the capacity word (header +0x0 word, << 4,
through the same dealloc slot, gated on the capacity word);
on the unwind path a landing pad that protects the pre-drain
fields calls the 86-byte drain+free wrapper for the same
header, and a landing pad that protects the drain call itself
re-runs only the inline buffer free.  The 86-byte body is the
shared out-of-line unwind half of that pattern.  Two measured
deviations: the vec-A record destructor's normal-path free is
a slot call (more fields follow it), where the other three
callers use the epilogue tail-jump form; and the reader record
destructor's header sits at record +0x0 (the record pointer
itself is the header), where the other three callers pass
record +0x18.  Static evidence only; no captured code is
executed.
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
    'vec_a_pair_destroy': (
        0x1537b00, 0x1537b82,
        '30ce062b876d862e3961d70031ed434c3e520457bc3c16900e1b6fafa6a4511a'),
    'reader_pair_destroy': (
        0x474e0b0, 0x474e132,
        'ae6e68cf8978e52df9dda3f1d2849d62d09fa99f0f880c04137413d82a93a12d'),
}
BOUNDARIES = {
    'vec_a_element_drop': (
        0x1538ec0, 0x1538fc2,
        '7e210dddf72e2ea2174d3e9ab9f5e285c76d2dedee2762fa42b3aaea7d41033d'),
    'reader_element_drop': (
        0x474dcd0, 0x474ddd2,
        '1eb9998a3ae04a9d04b65c94b6152313072624627f05778250ee744c157d068e'),
    'vec_a_record_destructor': (
        0x1538460, 0x153871b,
        '17facf13231741b34331e4472b2e1f0ae54de483a6820989bed7fabf255c1913'),
    'reader_record_destructor': (
        0x474dba0, 0x474dc86,
        'fc8d195bff8814b116c5b6eee405931c1d37dc8f31d06eb5aa5aba1f437ef50e'),
    'vec_a_subvec_drain': (
        0x153deb0, 0x153df9b,
        '77384034eb0db4b419f2ae44c146d2b4b1d234915d41503715cc2f93235ea2be'),
    'reader_subvec_drain': (
        0x474e8a0, 0x474e98b,
        '21ec3b9046cb0e2e6cd091e7d20552f94cbe40a9da2ab582c98111a771b7417e'),
    'vec_a_subvec_drain_unwind': (
        0x1539990, 0x15399e6,
        '8bf08c4e4144116fc33dc99728b6575dfbe2fa7e8a60badb30148531415e7b6e'),
    'reader_subvec_drain_unwind': (
        0x474e270, 0x474e2c6,
        '6307eff4fed38574504cb88e145950f5d83deb72ee5d032e082f767dd3de1680'),
}


def _h(hexstr):
    return bytes.fromhex(hexstr)


HELPER_A_PINS = {
    'keep_descriptor': (0x1537B05, _h('4989f6')),
    'keep_data': (0x1537B08, _h('4889fb')),
    'desc_word0_load': (0x1537B0B, _h('488b06')),
    'desc_word0_test': (0x1537B0E, _h('4885c0')),
    'desc_call': (0x1537B16, _h('ffd0')),
    'size_word': (0x1537B18, _h('498b7608')),
    'size_test': (0x1537B1C, _h('4885f6')),
    'align_word': (0x1537B21, _h('498b4610')),
    'align_tzcnt': (0x1537B25, _h('f3480fbcc8')),
    'class_cmova': (0x1537B2F, _h('0f47d1')),
    'align_hi_cmp': (0x1537B32, _h('4883f811')),
    'class_cmovae': (0x1537B36, _h('0f43d1')),
    'data_arg': (0x1537B39, _h('4889df')),
    'pad_exc_keep': (0x1537B4D, _h('4989c7')),
    'pad_size_word': (0x1537B50, _h('498b7608')),
    'pad_align_word': (0x1537B59, _h('498b4610')),
    'pad_align_tzcnt': (0x1537B5D, _h('f3480fbcc8')),
    'pad_data_arg': (0x1537B71, _h('4889df')),
    'resume_call': (0x1537B7D, _h('e8ce8eeb04')),
}
HELPER_B_PINS = {
    'keep_descriptor': (0x474E0B5, _h('4989f6')),
    'keep_data': (0x474E0B8, _h('4889fb')),
    'desc_word0_load': (0x474E0BB, _h('488b06')),
    'desc_word0_test': (0x474E0BE, _h('4885c0')),
    'desc_call': (0x474E0C6, _h('ffd0')),
    'size_word': (0x474E0C8, _h('498b7608')),
    'size_test': (0x474E0CC, _h('4885f6')),
    'align_word': (0x474E0D1, _h('498b4610')),
    'align_tzcnt': (0x474E0D5, _h('f3480fbcc8')),
    'class_cmova': (0x474E0DF, _h('0f47d1')),
    'align_hi_cmp': (0x474E0E2, _h('4883f811')),
    'class_cmovae': (0x474E0E6, _h('0f43d1')),
    'data_arg': (0x474E0E9, _h('4889df')),
    'pad_exc_keep': (0x474E0FD, _h('4989c7')),
    'pad_size_word': (0x474E100, _h('498b7608')),
    'pad_align_word': (0x474E109, _h('498b4610')),
    'pad_align_tzcnt': (0x474E10D, _h('f3480fbcc8')),
    'pad_data_arg': (0x474E121, _h('4889df')),
    'resume_call': (0x474E12D, _h('e81e29ca01')),
}
DROP_A_PINS = {
    'header_lea': (0x1538F21, _h('4c8d7b18')),
    'drain_call': (0x1538F28, _h('e8834f0000')),
    'cap_word': (0x1538F2D, _h('498b37')),
    'buffer_word': (0x1538F35, _h('488b7b20')),
    'size_shift': (0x1538F39, _h('48c1e604')),
    'pad1_header_add': (0x1538F8B, _h('4883c318')),
    'pad1_wrapper_call': (0x1538F92, _h('e8f9090000')),
    'pad2_cap_word': (0x1538FA2, _h('498b37')),
    'pad2_buffer_word': (0x1538FAA, _h('488b7b20')),
}
DROP_B_PINS = {
    'header_lea': (0x474DD31, _h('4c8d7b18')),
    'drain_call': (0x474DD38, _h('e8630b0000')),
    'cap_word': (0x474DD3D, _h('498b37')),
    'buffer_word': (0x474DD45, _h('488b7b20')),
    'size_shift': (0x474DD49, _h('48c1e604')),
    'pad1_header_add': (0x474DD9B, _h('4883c318')),
    'pad1_wrapper_call': (0x474DDA2, _h('e8c9040000')),
    'pad2_cap_word': (0x474DDB2, _h('498b37')),
    'pad2_buffer_word': (0x474DDBA, _h('488b7b20')),
}
BIG_A_PINS = {
    'header_lea': (0x1538552, _h('4c8d7b18')),
    'drain_call': (0x1538559, _h('e852590000')),
    'cap_word': (0x153855E, _h('498b37')),
    'buffer_word': (0x1538566, _h('488b7b20')),
    'size_shift': (0x153856A, _h('48c1e604')),
    'drainpad_cap_word': (0x1538609, _h('498b37')),
    'drainpad_buffer_word': (0x153861E, _h('488b7b20')),
    'drainpad_size_shift': (0x1538622, _h('48c1e604')),
    'wrapper_header_lea': (0x153869F, _h('488d7b18')),
    'wrapper_call': (0x15386A3, _h('e8e8120000')),
}
BIG_B_PINS = {
    'first_pair_data': (0x474DBAB, _h('4c8b7f18')),
    'first_pair_desc': (0x474DBAF, _h('4c8b6720')),
    'first_pair_call': (0x474DBBF, _h('ffd0')),
    'first_pair_tzcnt': (0x474DBD0, _h('f3480fbcc8')),
    'drain_call': (0x474DBF0, _h('e8ab0c0000')),
    'cap_word': (0x474DBF5, _h('488b33')),
    'buffer_word': (0x474DBFD, _h('488b7b08')),
    'size_shift': (0x474DC01, _h('48c1e604')),
    'pad1_wrapper_call': (0x474DC56, _h('e815060000')),
    'drainpad_cap_word': (0x474DC66, _h('488b33')),
    'drainpad_buffer_word': (0x474DC6E, _h('488b7b08')),
    'drainpad_size_shift': (0x474DC72, _h('48c1e604')),
}
PIN_TABLES = {
    'vec_a_pair_destroy': HELPER_A_PINS,
    'reader_pair_destroy': HELPER_B_PINS,
    'vec_a_element_drop': DROP_A_PINS,
    'reader_element_drop': DROP_B_PINS,
    'vec_a_record_destructor': BIG_A_PINS,
    'reader_record_destructor': BIG_B_PINS,
}
SLOT_CALL_PINS = {
    'a_dealloc_tail': (0x1537B41, 0x64DF4A0),
    'a_pad_dealloc': (0x1537B74, 0x64DF4A0),
    'b_dealloc_tail': (0x474E0F1, 0x64DF4A0),
    'b_pad_dealloc': (0x474E124, 0x64DF4A0),
    'drop_a_free_tail': (0x1538F4A, 0x64DF4A0),
    'drop_a_pad2_free': (0x1538FB4, 0x64DF4A0),
    'drop_b_free_tail': (0x474DD5A, 0x64DF4A0),
    'drop_b_pad2_free': (0x474DDC4, 0x64DF4A0),
    'big_a_free_call': (0x1538570, 0x64DF4A0),
    'big_a_drainpad_free': (0x1538628, 0x64DF4A0),
    'big_b_first_pair_free': (0x474DBE7, 0x64DF4A0),
    'big_b_free_tail': (0x474DC12, 0x64DF4A0),
    'big_b_pad1_pair_free': (0x474DC4D, 0x64DF4A0),
    'big_b_drainpad_free': (0x474DC78, 0x64DF4A0),
}
CENSUS_TARGETS = {
    'vec_a_pair_destroy': 0x1537B00,
    'reader_pair_destroy': 0x474E0B0,
    'vec_a_subvec_drain_unwind': 0x1539990,
    'reader_subvec_drain_unwind': 0x474E270,
}
EXPECTED_CALLS = {
    'vec_a_pair_destroy': [
        ('0x153df83', ['0x153deb0', '0x153df9b'])],
    'reader_pair_destroy': [
        ('0x474e973', ['0x474e8a0', '0x474e98b'])],
    'vec_a_subvec_drain_unwind': [
        ('0x15386a3', ['0x1538460', '0x153871b']),
        ('0x1538f92', ['0x1538ec0', '0x1538fc2'])],
    'reader_subvec_drain_unwind': [
        ('0x474dc56', ['0x474dba0', '0x474dc86']),
        ('0x474dda2', ['0x474dcd0', '0x474ddd2'])],
}
DEALLOC_SLOT = 0x64DF4A0
RESUME_PLT = 0x63F0A50

CALLER_SHAPES = [
    {'role': 'vec_a_element_drop',
     'header_offset': '0x18',
     'header_form': 'lea r15,[rbx+0x18] at 0x1538f21',
     'drain_call': '0x1538f28', 'drain_target': '0x153deb0',
     'normal_free': {
         'form': 'tail_jump', 'site': '0x1538f4a',
         'gate': 'capacity word [r15] (header +0x0) at 0x1538f2d',
         'buffer': '[rbx+0x20] (header +0x8) at 0x1538f35',
         'size': 'capacity << 4 (shl at 0x1538f39), align 0'},
     'pad_before_drain': {
         'wrapper_call': '0x1538f92', 'wrapper_target': '0x1539990',
         'header_form': 'add rbx,0x18 at 0x1538f8b'},
     'pad_after_drain': {
         'free_call': '0x1538fb4',
         'capacity': 'capacity word [r15] at 0x1538fa2'}},
    {'role': 'reader_element_drop',
     'header_offset': '0x18',
     'header_form': 'lea r15,[rbx+0x18] at 0x474dd31',
     'drain_call': '0x474dd38', 'drain_target': '0x474e8a0',
     'normal_free': {
         'form': 'tail_jump', 'site': '0x474dd5a',
         'gate': 'capacity word [r15] (header +0x0) at 0x474dd3d',
         'buffer': '[rbx+0x20] (header +0x8) at 0x474dd45',
         'size': 'capacity << 4 (shl at 0x474dd49), align 0'},
     'pad_before_drain': {
         'wrapper_call': '0x474dda2', 'wrapper_target': '0x474e270',
         'header_form': 'add rbx,0x18 at 0x474dd9b'},
     'pad_after_drain': {
         'free_call': '0x474ddc4',
         'capacity': 'capacity word [r15] at 0x474ddb2'}},
    {'role': 'vec_a_record_destructor',
     'header_offset': '0x18',
     'header_form': 'lea r15,[rbx+0x18] at 0x1538552',
     'drain_call': '0x1538559', 'drain_target': '0x153deb0',
     'normal_free': {
         'form': 'call', 'site': '0x1538570',
         'gate': 'capacity word [r15] (header +0x0) at 0x153855e',
         'buffer': '[rbx+0x20] (header +0x8) at 0x1538566',
         'size': 'capacity << 4 (shl at 0x153856a), align 0'},
     'pad_before_drain': {
         'wrapper_call': '0x15386a3', 'wrapper_target': '0x1539990',
         'header_form': 'lea rdi,[rbx+0x18] at 0x153869f'},
     'pad_after_drain': {
         'free_call': '0x1538628',
         'capacity': 'capacity word [r15] at 0x1538609'}},
    {'role': 'reader_record_destructor',
     'header_offset': '0x0',
     'header_form': 'the record pointer itself (rdi = rbx at '
                    '0x474dbf0); no header lea exists',
     'drain_call': '0x474dbf0', 'drain_target': '0x474e8a0',
     'normal_free': {
         'form': 'tail_jump', 'site': '0x474dc12',
         'gate': 'capacity word [rbx] (header +0x0) at 0x474dbf5',
         'buffer': '[rbx+0x8] (header +0x8) at 0x474dbfd',
         'size': 'capacity << 4 (shl at 0x474dc01), align 0'},
     'pad_before_drain': {
         'wrapper_call': '0x474dc56', 'wrapper_target': '0x474e270',
         'header_form': 'record pointer (rdi = rbx at 0x474dc53)'},
     'pad_after_drain': {
         'free_call': '0x474dc78',
         'capacity': 'capacity word [rbx] at 0x474dc66'}},
]


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
    entry = rel[DEALLOC_SLOT]
    return {'dealloc': {'slot': hex(DEALLOC_SLOT),
                        'type': entry['type'],
                        'addend': hex(entry['addend'])}}


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
    """Zero the address-dependent tail of a branch/slot instruction
    (the drain packet's mask, generalised to RIP-relative modrm)."""
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


def _pair_shape(data):
    a0, a1, _ = OWNERS['vec_a_pair_destroy']
    b0, b1, _ = OWNERS['reader_pair_destroy']
    ins_a, _ = _decoded(data, a0, a1)
    ins_b, _ = _decoded(data, b0, b1)
    offs_a = sorted(s - a0 for s in ins_a)
    offs_b = sorted(s - b0 for s in ins_b)
    require(offs_a == offs_b,
            'pair-destroy instruction offsets diverged')
    differences = []
    for off in offs_a:
        raw_a, raw_b = ins_a[a0 + off], ins_b[b0 + off]
        masked_a, kind_a = _mask(raw_a)
        masked_b, kind_b = _mask(raw_b)
        require(masked_a == masked_b and kind_a == kind_b,
                f'pair-destroy shape diverged at offset {off:#x}')
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
    return {'a': 'vec_a_pair_destroy', 'b': 'reader_pair_destroy',
            'instructions': len(offs_a),
            'masked_identical': True,
            'differences': differences}


def transfer_census(data):
    """Whole-.text E8/E9 census for the helper and wrapper targets,
    sites attributed by containing FDE (the drain packet's method,
    extended to tail jumps)."""
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, raw = sec['address'], data[sec['offset']:sec['offset']
                                      + sec['size']]
    _, fs, _ = fde_extents(data)
    starts = sorted(f['start'] for f in fs)
    by_start = {f['start']: f for f in fs}
    wanted = {v: k for k, v in CENSUS_TARGETS.items()}
    found = {name: {'calls': [], 'jmps': []} for name in CENSUS_TARGETS}
    for opcode, kind in ((b'\xe8', 'calls'), (b'\xe9', 'jmps')):
        i = raw.find(opcode)
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
                    found[wanted[target]][kind].append(
                        {'site': hex(base + i), 'owner_fde': owner})
            i = raw.find(opcode, i + 1)
    return {name: {'target': hex(CENSUS_TARGETS[name]),
                   'call_sites': [r['site'] for r in rows['calls']],
                   'call_rows': rows['calls'],
                   'jmp_sites': [r['site'] for r in rows['jmps']]}
            for name, rows in found.items()}


def analyze(data):
    bindings = slot_bindings(data)
    if bindings['dealloc'] != {'slot': hex(DEALLOC_SLOT), 'type': 8,
                                'addend': '0x635de30'}:
        raise ValueError('dealloc slot binding changed')
    for role, table in PIN_TABLES.items():
        _pins(data, table, role)
    for label, (site, slot) in SLOT_CALL_PINS.items():
        _slot_call(data, site, slot, label)
    census = transfer_census(data)
    for name, expected in EXPECTED_CALLS.items():
        rows = [(r['site'], r['owner_fde'])
                for r in census[name]['call_rows']]
        if rows != expected:
            raise ValueError(f'transfer census changed for {name}')
        if census[name]['jmp_sites']:
            raise ValueError(f'unexpected tail-jump caller for {name}')
    shapes = [_pair_shape(data)]
    diffs = shapes[0]['differences']
    if shapes[0]['instructions'] != 44 or len(diffs) != 3:
        raise ValueError('pair-destroy clone shape changed')
    for row in diffs:
        if row['a_target'] != row['b_target']:
            raise ValueError('pair-destroy difference resolves to '
                             'different targets')
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}

    def frame_records(a, b, sha, role):
        if (a, b) not in fdes:
            raise ValueError(f'{role} scope FDE changed')
        offset, raw = read(data, a, b - a)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != sha:
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

    owners = [frame_records(a, b, sha, role)
              for role, (a, b, sha) in OWNERS.items()]
    boundaries = [frame_records(a, b, sha, role)
                  for role, (a, b, sha) in BOUNDARIES.items()]
    return {
        'target_sha256': SHA, 'owners': owners,
        'boundaries': boundaries, 'slot_bindings': bindings,
        'transfers': census, 'shapes': shapes,
        'caller_shapes': CALLER_SHAPES,
        'pair_verdict':
            'One pair-destroy call destroys exactly one element.  '
            'The arguments are the element\'s two words: rdi = the '
            'data word, rsi = the descriptor word (a pointer to '
            'the 0x18-byte descriptor record).  The helper saves '
            'both, then: (1) descriptor word 0 ([rsi+0x0]) is '
            'called on the data when non-null (call at '
            '0x1537b16 / 0x474e0c6); (2) the size word '
            '([rsi+0x8]) is tested -- when zero the helper simply '
            'returns; when non-zero the dealloc class is computed '
            'from the align word ([rsi+0x10]) by the same '
            'tzcnt/cmov idiom as the drains (tzcnt at 0x1537b25 '
            '/ 0x474e0d5; class 0 when align <= size, the tzcnt '
            'when align > size, and the tzcnt whenever align '
            '>= 0x11), the registers are restored, and the data '
            'is freed through the dealloc slot 0x64df4a0 '
            '(RELATIVE target 0x635de30) as a TAIL JUMP '
            '(0x1537b41 / 0x474e0f1) with (data, size, class).  '
            'Order is descriptor call first, free second -- the '
            'normal drains\' per-element order.  There is no '
            'loop in the helper: the iteration over the '
            'remaining elements lives in the drain landing pads '
            '(counter dec at 0x153df70 / 0x474e960, cursor '
            'advancing 0x10, one helper call per element at '
            '0x153df83 / 0x474e973).  Unwind behaviour: the '
            'helper\'s own landing pad (+0x4d) saves the '
            'exception, re-runs the same size/class computation '
            'and frees the data through the slot in CALL form '
            '(0x1537b74 / 0x474e124) when the size word is '
            'non-zero, then calls _Unwind_Resume (PLT '
            '0x63f0a50) with the saved exception.',
        'clone_verdict':
            'The two helpers are clones at the pinned instruction '
            'shape, judged by the #2714 method (unmasked '
            'instruction diff + consumption order).  Both decode '
            'to 44 instructions at identical offsets and, after '
            'masking the address-dependent tails, byte-identical '
            'streams.  The unmasked difference is exactly three '
            'sites, each a 4-byte displacement field, and every '
            'one resolves to the SAME shared target in both '
            'instances: the tail jump\'s RIP-relative displacement '
            '(offset 0x41) and the pad free\'s RIP-relative '
            'displacement (offset 0x74) both name the dealloc '
            'slot 0x64df4a0, and the resume call\'s rel32 '
            '(offset 0x7d) names the shared _Unwind_Resume PLT '
            '0x63f0a50.  Unlike the drain pairs -- whose five '
            'and four differences each include a module-local '
            'call target -- NO difference here resolves to a '
            'module-local target: the helpers call nothing of '
            'their own module (the descriptor function is '
            'indirect through the descriptor, the free goes '
            'through the shared slot, the resume through the '
            'shared PLT).  The bodies\' own hashes differ, as '
            'the pinned records show; identity is claimed at '
            'the masked instruction shape only.',
        'family_verdict':
            'The four caller FDEs of the 86-byte wrappers are '
            'not themselves wrappers and are not mutual clones '
            '(258 / 699 / 258 / 230 bytes; the two element drops '
            'are clones of each other per #2714, the two record '
            'destructors are not clones of anything).  Each of '
            'the four is a record destructor that embeds the '
            'same two-half drain-and-free pattern over its '
            'record\'s sub-vector header, at the pinned sites '
            'in caller_shapes: NORMAL half -- call the module\'s '
            'normal drain on the header, then free the buffer '
            'inline: capacity word (header +0x0) loaded, gated '
            'non-zero, buffer pointer (header +0x8), size = '
            'capacity << 4, align 0, through the dealloc slot '
            '0x64df4a0.  UNWIND half -- a landing pad that '
            'protects the fields destroyed before the drain '
            'call routes the same header through the 86-byte '
            'drain+free wrapper (exactly one wrapper call per '
            'caller FDE, all in pad blocks), while a landing '
            'pad that protects the drain call itself re-runs '
            'only the inline buffer free (the drain has already '
            'consumed the elements, so the wrapper\'s drain '
            'half must not run again).  The 86-byte body is '
            'therefore the shared out-of-line unwind half of '
            'one pattern that every wrapper caller embeds -- '
            'the whole drop path in each module is generated '
            'from this one pattern, with the wrapper as its '
            'unwind form.  Two measured deviations: (a) the '
            'vec-A record destructor 0x1538460 performs the '
            'normal-path free as a slot CALL at 0x1538570 '
            '(further fields follow), where the other three '
            'callers use the epilogue tail-jump form after '
            'restoring registers; (b) the reader record '
            'destructor 0x474dba0 has its header at record '
            '+0x0 -- the record pointer itself is passed to '
            'both drain and wrapper, and its first field is an '
            'inline pair-destroy of the tagged pair at record '
            '+0x18/+0x20 (descriptor call 0x474dbbf, tzcnt '
            '0x474dbd0, dealloc call 0x474dbe7, re-run on the '
            'pad at 0x474dc4d) -- where the other three '
            'callers pass record +0x18 as the header.',
        'census_verdict':
            'Transfer census over the whole .text (E8 calls and '
            'E9 tail jumps, sites attributed by containing '
            'FDE): each pair-destroy helper has exactly ONE '
            'direct caller -- its own module\'s normal-drain '
            'landing-pad loop (0x153df83 in 0x153deb0; '
            '0x474e973 in 0x474e8a0) -- and no tail-jump caller '
            'exists for either helper or for either wrapper.  '
            'Each 86-byte wrapper has exactly the two callers '
            'the drain packet recorded (the element drop\'s '
            'first landing pad and the record destructor\'s '
            'pad, per module).  No other direct caller of any '
            'of the four exists in the binary.',
        'limits':
            'Static trace only.  Hash-pinned, not traced: the '
            'two normal drains and the two 86-byte wrappers '
            '(traced by the drain-callees packet, retained here '
            'as boundary context), the dealloc target '
            '0x635de30, and _Unwind_Resume.  Caller shapes are '
            'pinned at the drain/free/wrapper sites listed in '
            'caller_shapes; the remaining fields of the two '
            'record destructors (strings, tagged pairs, the '
            'tag-3 dispatch in 0x1538460) are not traced, and '
            'which landing pad protects which call range is '
            'identified by pad content and position, not by '
            're-decoding the LSDA.  What the elements\' '
            'descriptor drop functions do beyond the call, and '
            'any semantic name for the element or record types, '
            'are not claimed.  No captured code executed, no '
            'runtime value or reconstruction gate is claimed.',
        'next_question':
            'Do the further 86-byte drain callers in the drain '
            'packet\'s census (vec-A FDEs 0x1569cd0 / 0x158b8e0 '
            '/ 0x15ac910 / 0x15bb960, reader FDEs 0x4747f50 / '
            '0x4753450) -- whose size already matches the '
            'wrappers -- form further instances of the same '
            'drain+free wrapper over other headers: are they '
            'clones of the 86-byte pair or a wider wrapper '
            'family, which headers do they wrap, and do their '
            'own callers again embed the same two-half pattern?'}


DUMPED = list(OWNERS.items()) + [
    (role, BOUNDARIES[role]) for role in (
        'vec_a_element_drop', 'reader_element_drop',
        'vec_a_record_destructor', 'reader_record_destructor')]


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
        for name, (a, b, _) in DUMPED:
            easm = _objdump(snapshot, a, b)
            eins = decode_export(easm, a, b, read(data, a, b - a)[1])
            esites = {site for site, _ in PIN_TABLES[name].values()}
            esites |= {site for label, (site, _) in
                       SLOT_CALL_PINS.items() if a <= site < b}
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


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args(argv)
    data = args.binary.read_bytes()
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('expected pinned node115')
    if args.verify:
        packet = Path(__file__).resolve().parents[1] / 'research' / \
            'work-items' / 'RE-015-node115-pair-destroy-helpers'
        committed = json.loads((packet / 'records.json').read_text())
        report = analyze(data)
        print(json.dumps({'matches': report == committed}))
        return 0 if report == committed else 1
    if args.output:
        generate(args.binary, args.output)
        print(json.dumps({'generated': True}))
        return 0
    report = analyze(data)
    print(json.dumps({'matches': True,
                      'instructions':
                      report['shapes'][0]['instructions']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
