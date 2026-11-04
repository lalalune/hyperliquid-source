#!/usr/bin/env python3
"""Pin the readers of the RE-015 assembled 0x40-byte records in node 115.

Question (the recorded next question of the second-structure readers
packet, #2506): who reads the two assembled 0x40-byte records the
large consumer's post-loop region appends -- carrying the taken
entries' +0x8/+0x10 words at their +0x30/+0x38 slots -- once the
drain region (0x15a5501..0x15a5861) and the consumer tail take over?
In particular: the role of the map-#1 drain helper 0x149e5b0 and the
final disposition of the extracted words.

The packet pins: (1) the drain verdict -- a stack census over the
whole consumer body shows the drain region never touches the
records' storage, and the helper 0x149e5b0 is a map-#1 cursor
function that never loads a record field; (2) the normal-exit
reader -- the consumer calls 0x4749ab0 through slot 0x64e1480 with
the saved record pair at [rsp+0x240], and that reader's two arms
(discriminant-6 extraction versus verbatim pair move-out) plus its
delegate 0x4748500's two element loops; (3) the destroy paths --
the pair drop 0x15ac5f0 and the tagged destroys 0x158bee0 /
0x15ad360 that consume the taken words directly on unwind paths.
Static evidence only; no captured code is executed.
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

CONSUMER, CONSUMER_END = 0x15a3b90, 0x15a6509
CONSUMER_SHA = '7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb'
PHASE2_START = 0x15a44e0
POSTLOOP_START = 0x15a4cb0
DRAIN_START = 0x15a5501
TAIL_START = 0x15a5861
EXIT_START = 0x15a58f2
SENTINEL = 0x8000000000000000

OWNERS = {
    'large_consumer': (CONSUMER, CONSUMER_END, CONSUMER_SHA),
    'exit_reader': (
        0x4749ab0, 0x4749d71,
        '6f4caa139b97d81e99776e8cf0f570c906c02c5133d755baec41104d77e9b0bb'),
    'pair_drop': (
        0x15ac5f0, 0x15ac779,
        'e2953a3c6bd271b64b76fcef0d618208195a928d6a9b24ffb2da1b9734079995'),
    'tagged_destroy_a': (
        0x158bee0, 0x158bf62,
        '843692aaa8b2a5d2e2bd2ce150f1211842a558804f66db3e53d3a1586c959862'),
    'tagged_destroy_b': (
        0x15ad360, 0x15ad3e2,
        'bcb8ecc826669ce312d41cea207fe154dc20649bb7c3adba25550e12acf82303'),
    'map1_drain_helper': (
        0x149e5b0, 0x149e70e,
        '341f372e53bbbca10894eb94e045628d3fb576e6e97824e4ce9cd28a4ce49e0c'),
}
BOUNDARIES = {
    'merge_delegate': (
        0x4748500, 0x4749aa9,
        '7b1d3b86c285b089e030cba72aa9fc2b71cba2009d2849c91ec06977ea9b2691'),
    'drain_iterator': (
        0x153ba90, 0x153be3a,
        'a5c096486429b29251c1adf8a1b25f31766b5c31a4db944805b6eda072d3868f'),
    'vec_a_element_drop': (
        0x1538ec0, 0x1538fc2,
        '7e210dddf72e2ea2174d3e9ab9f5e285c76d2dedee2762fa42b3aaea7d41033d'),
    'reader_element_drop': (
        0x474dcd0, 0x474ddd2,
        '1eb9998a3ae04a9d04b65c94b6152313072624627f05778250ee744c157d068e'),
    'pair_vec_b_drop': (
        0x15ad260, 0x15ad354,
        'cc066f5f37b16056e64656b430f2e33bdefeb1ba0c508f9ab746392986f5eb14'),
    'transform_gate': (
        0x474ba60, 0x474bcd3,
        '4527e1e0d1ad267cdd6951f2eb2898a962a2124d6096038fd63087ea43637d44'),
    'entry_vec_grow': (
        0x474e490, 0x474e4f4,
        'fe1531d90ea4cec8186fadce65b5b41958fc149a15603278e5d6afe7179123f3'),
    'vec40_grow': (
        0x474e420, 0x474e484,
        '447b3ab590a04170647c65d904bb5f18f8239c675c6f2d8f51fa1617f0f604d8'),
    'assert_entry': (
        0x1680c30, 0x1680c82,
        '2d00fd36dc6102ab0738e08907482bb818bca6e76e32a5b941eabf431f20767a'),
}

WINDOWS = [
    ('consumer_postloop', POSTLOOP_START, DRAIN_START),
    ('consumer_drain', DRAIN_START, TAIL_START),
    ('consumer_tail', TAIL_START, CONSUMER_END),
    ('delegate_vec_a', 0x4748500, 0x474885a),
    ('delegate_vec_b', 0x4748c47, 0x4748e00),
]
FULL_EXPORTS = [
    ('exit_reader', 0x4749ab0, 0x4749d71),
    ('pair_drop', 0x15ac5f0, 0x15ac779),
    ('tagged_destroy_a', 0x158bee0, 0x158bf62),
    ('tagged_destroy_b', 0x15ad360, 0x15ad3e2),
    ('map1_drain_helper', 0x149e5b0, 0x149e70e),
]

CONSUMER_PINS = {
    'saveback_pair_word0': (0x15a54c4, b'\x0f)\x84$@\x02\x00\x00'),
    'saveback_pair_word4': (0x15a54dc, b'H\x89\x84$`\x02\x00\x00'),
    'saveback_pair_word5': (0x15a54ec, b'H\x89\x84$h\x02\x00\x00'),
    'drain_handle_load': (0x15a5506, b'H\x8b\x8c$x\x01\x00\x00'),
    'drain_iterator_call': (0x15a5580, b'\xe8\x0be\xf9\xff'),
    'drain_helper_call': (0x15a569e, b'\xe8\r\x8f\xef\xff'),
    'drain_result_word2': (0x15a56ea, b'H\x89C\x10'),
    'drain_result_copy': (0x15a56ee, b'\x0f\x11\x03'),
    'exit_empty_low': (0x15a58f5, b'\x0f)\x84$\xc0\x00\x00\x00'),
    'exit_empty_cap': (0x15a58fd, b'H\xc7\x84$\xd0\x00\x00\x00\x08\x00\x00\x00'),
    'exit_empty_len': (0x15a5909, b'H\xc7\x84$\xd8\x00\x00\x00\x00\x00\x00\x00'),
    'exit_out_arg': (0x15a5915, b'H\x8d|$ '),
    'exit_pair_arg': (0x15a591a, b'H\x8d\xb4$@\x02\x00\x00'),
    'exit_disc_cmp': (0x15a5930, b'\x83|$ \x06'),
    'exit_dest_load': (0x15a5940, b'H\x8b\x84$x\x02\x00\x00'),
    'exit_copy_high': (0x15a5948, b'\x0f\x11@@'),
    'exit_copy_low': (0x15a596c, b'\x0f\x11\x00'),
    'unwind_tagged1_word_a': (0x15a5dea, b'H\x8b\xbc$ \x02\x00\x00'),
    'unwind_tagged1_word_b': (0x15a5df2, b'H\x8b\xb4$\x18\x02\x00\x00'),
    'unwind_tagged1_call': (0x15a5dfa, b'\xe8\xe1`\xfe\xff'),
    'unwind_pair90_arg': (0x15a5e0c, b'H\x8d\xbc$\x90\x00\x00\x00'),
    'unwind_pair90_call': (0x15a5e14, b'\xe8\xd7g\x00\x00'),
    'unwind_tagged2_word_a': (0x15a5e3c, b'H\x8b\xbc$\x10\x02\x00\x00'),
    'unwind_tagged2_word_b': (0x15a5e44, b'H\x8b\xb4$\x08\x02\x00\x00'),
    'unwind_tagged2_call': (0x15a5e4c, b'\xe8\x8f`\xfe\xff'),
    'unwind_pair_d_arg': (0x15a5eaa, b'H\x8d\xbc$\xd0\x01\x00\x00'),
    'unwind_pair_d_call': (0x15a5eb2, b'\xe89g\x00\x00'),
    'tail_tagged3_word_a': (0x15a6176, b'H\x8b\xbc$ \x02\x00\x00'),
    'tail_tagged3_word_b': (0x15a617e, b'H\x8b\xb4$\x18\x02\x00\x00'),
    'tail_tagged3_call': (0x15a6186, b'\xe8\xd5q\x00\x00'),
    'tail_tagged4_word_a': (0x15a6193, b'H\x8b\xbc$\x10\x02\x00\x00'),
    'tail_tagged4_word_b': (0x15a619b, b'H\x8b\xb4$\x08\x02\x00\x00'),
    'tail_tagged4_call': (0x15a61a3, b'\xe8\xb8q\x00\x00'),
    'unwind_pair_c0_arg': (0x15a60d1, b'H\x8d\xbc$\xc0\x00\x00\x00'),
    'unwind_pair_c0_call': (0x15a60d9, b'\xe8\x12e\x00\x00'),
    'final_pair_arg': (0x15a64cc, b'H\x8d\xbc$@\x02\x00\x00'),
    'final_pair_call': (0x15a64d4, b'\xe8\x17a\x00\x00'),
}
EXIT_READER_PINS = {
    'temp_word50': (0x4749b0d, b'H\x8b\xb4$\xc0\x00\x00\x00'),
    'temp_word58': (0x4749b15, b'H\x8b\xbc$\xc8\x00\x00\x00'),
    'temp_word60': (0x4749b1d, b'H\x8b\x84$\xd0\x00\x00\x00'),
    'out_word8': (0x4749b2e, b'H\x89s\x08'),
    'out_word10': (0x4749b32, b'H\x89{\x10'),
    'out_word18': (0x4749b36, b'H\x89C\x18'),
    'out_disc6': (0x4749b3a, b'H\xc7\x03\x06\x00\x00\x00'),
    'vec_a_elem_drop_call': (0x4749b6d, b'\xe8^A\x00\x00'),
    'vec_b_elem_ptr': (0x4749c54, b'H\x8b{\x10'),
    'zero_copy_src': (0x4749cc4, b'\x0f(D$P'),
    'zero_copy_high': (0x4749cc9, b'\x0f\x11C@'),
    'zero_copy_low': (0x4749ced, b'\x0f\x11\x03'),
    'zero_free_shift': (0x4749cf5, b'H\xc1\xe6\x05'),
}
PAIR_DROP_PINS = {
    'vec_a_buffer': (0x15ac601, b'L\x8bw\x08'),
    'vec_a_count': (0x15ac605, b'L\x8bo\x10'),
    'vec_a_elem_step': (0x15ac616, b'L\x8dg@'),
    'vec_a_elem_drop_call': (0x15ac61d, b'\xe8\x9e\xc8\xf8\xff'),
    'vec_a_buf_size': (0x15ac62f, b'H\xc1\xe6\x06'),
    'vec_b_buffer': (0x15ac63e, b'H\x8bC '),
    'vec_b_count': (0x15ac64b, b'H\x8bC('),
    'vec_b_elem_size': (0x15ac689, b'H\x8bt\x01\x08'),
    'vec_b_elem_ptr': (0x15ac693, b'H\x8b{\x10'),
    'vec_b_sub_buffer': (0x15ac69b, b'L\x8b{('),
    'vec_b_sub_count': (0x15ac69f, b'L\x8bc0'),
    'vec_b_sub_size_shift': (0x15ac6d9, b'H\xc1\xe0\x03'),
    'vec_b_buf_size': (0x15ac6f8, b'H\xc1\xe6\x06'),
    'vec_b_drop_call': (0x15ac766, b'\xe8\xf5\n\x00\x00'),
}
TAGGED_A_PINS = {
    'desc_drop_word': (0x158beeb, b'H\x8b\x06'),
    'desc_drop_call': (0x158bef6, b'\xff\xd0'),
    'desc_size_word': (0x158bef8, b'I\x8bv\x08'),
    'desc_align_word': (0x158bf01, b'I\x8bF\x10'),
}
TAGGED_B_PINS = {
    'desc_drop_word': (0x15ad36b, b'H\x8b\x06'),
    'desc_drop_call': (0x15ad376, b'\xff\xd0'),
    'desc_size_word': (0x15ad378, b'I\x8bv\x08'),
    'desc_align_word': (0x15ad381, b'I\x8bF\x10'),
}
MAP1_PINS = {
    'cursor_word0': (0x149e5be, b'H\x8b>'),
    'cursor_word1': (0x149e5c1, b'H\x8bF\x08'),
    'cursor_word2': (0x149e5c5, b'L\x8bv\x10'),
    'node_count_112': (0x149e5c9, b'\x0f\xb7\x8f\x12\x01\x00\x00'),
    'node_size_120': (0x149e5dd, b'A\xbd \x01\x00\x00'),
    'node_count_110': (0x149e5fc, b'D\x0f\xb7\xb7\x10\x01\x00\x00'),
    'node_size_180': (0x149e607, b'\xbe\x80\x01\x00\x00'),
    'child_head_load': (0x149e640, b'H\x8b\x08'),
    'child_link_lea': (0x149e643, b'H\x8d\x81 \x01\x00\x00'),
    'child_link_load': (0x149e6a3, b'H\x8b\x80 \x01\x00\x00'),
    'out_word0': (0x149e6e1, b'H\x89\x0b'),
    'out_word18': (0x149e6f0, b'L\x89{\x18'),
}
DELEGATE_PINS = {
    'out_ptr_save': (0x474851c, b'H\x89\xbc$\x18\x01\x00\x00'),
    'vec_b_count_in': (0x474853f, b'H\x8bF('),
    'vec_b_header_in': (0x474854b, b'\xf3\x0foF\x18'),
    'vec_a_buffer_in': (0x47485d4, b'I\x8bm\x08'),
    'vec_a_count_in': (0x47485d8, b'I\x8bM\x10'),
    'vec_a_elem_word0': (0x474868b, b'L\x8bm\xc0'),
    'sentinel_movabs': (0x474868f, b'H\xb8\x00\x00\x00\x00\x00\x00\x00\x80'),
    'transform_word0': (0x47486a6, b'L\x89\xac$p\x01\x00\x00'),
    'transform_word38': (0x47486ae, b'I\x8bF8'),
    'gate_call_a': (0x4748742, b'\xe8\x193\x00\x00'),
    'entry_word0': (0x4748772, b'H\xc7\x04\x08\x00\x00\x00\x00'),
    'entry_word8': (0x474877a, b'L\x89l\x08\x08'),
    'elem_tagged_data': (0x4748791, b'H\x8b\x9c$\xa0\x01\x00\x00'),
    'elem_tagged_desc': (0x4748799, b'L\x8b\xa4$\xa8\x01\x00\x00'),
    'vec_b_loop_word0': (0x4748c47, b'H\x8b\x84$@\x02\x00\x00'),
    'vec_b_loop_word1': (0x4748c4f, b'H\x8b\xac$H\x02\x00\x00'),
    'vec_b_loop_word2': (0x4748c57, b'H\x8b\x8c$P\x02\x00\x00'),
    'gate_call_b': (0x4748dae, b'\xe8\xad,\x00\x00'),
    'out_vec_count': (0x47494d6, b'H\x89A`'),
    'out_vec_header': (0x47494df, b'\x0f\x11AP'),
}
HELPER_PIN_TABLES = {
    'exit_reader': EXIT_READER_PINS,
    'pair_drop': PAIR_DROP_PINS,
    'tagged_destroy_a': TAGGED_A_PINS,
    'tagged_destroy_b': TAGGED_B_PINS,
    'map1_drain_helper': MAP1_PINS,
}
SLOT_CALL_PINS = {
    'exit_reader_call': (0x15a592a, 0x64e1480),
    'delegate_call': (0x4749ac9, 0x64eafd8),
    'reader_vec_a_free': (0x4749b8f, 0x64df4a0),
    'tagged_a_dealloc': (0x158bf21, 0x64df4a0),
}
CALL_CENSUS_TARGETS = {
    'pair_drop': 0x15ac5f0,
    'tagged_destroy_a': 0x158bee0,
    'tagged_destroy_b': 0x15ad360,
    'map1_drain_helper': 0x149e5b0,
    'drain_iterator': 0x153ba90,
    'vec_a_element_drop': 0x1538ec0,
    'reader_element_drop': 0x474dcd0,
    'transform_gate': 0x474ba60,
}
CENSUS_SLOTS = [
    '0x1d0', '0x1d8', '0x1e0', '0x1e8', '0x1f0', '0x1f8',
    '0x208', '0x210', '0x218', '0x220',
    '0x240', '0x248', '0x250', '0x258', '0x260', '0x268',
    '0x278', '0x20',
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
    require(raw[:2] in (b'\xff\x15', b'\xff%'),
            f'{label} is not a slot call')
    disp = struct.unpack('<i', raw[2:])[0]
    require(site + 6 + disp == slot, f'{label} slot changed')


def _relocations(data):
    s = next((s for s in sections(data) if s['name'] == '.rela.dyn'), None)
    require(s is not None, 'missing.rela.dyn section')
    require(s['size'] % 24 == 0, 'truncated.rela.dyn section')
    out = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        offset, info, addend = struct.unpack_from('<QQq', data, off)
        out[offset] = {'type': info & 0xffffffff,
                       'symbol': info >> 32, 'addend': addend}
    return out


def _dynsym_name(data, index):
    ds = next((s for s in sections(data) if s['name'] == '.dynsym'), None)
    require(ds is not None, 'missing.dynsym section')
    dstr = next((s for s in sections(data) if s['name'] == '.dynstr'), None)
    require(dstr is not None, 'missing.dynstr section')
    name_off = struct.unpack_from('<I', data, ds['offset'] + index * 24)[0]
    start = dstr['offset'] + name_off
    try:
        return data[start:data.index(b'\0', start)].decode()
    except UnicodeDecodeError:
        require(False, 'dynamic symbol name is not valid UTF-8')


def slot_bindings(data):
    rel = _relocations(data)
    wanted = {
        'exit_reader': 0x64e1480, 'merge_delegate': 0x64eafd8,
        'entry_vec_grow': 0x64eafe0, 'vec40_grow_a': 0x64e1470,
        'vec40_grow_b': 0x64e1478, 'alloc': 0x64df480,
        'dealloc': 0x64df4a0, 'assert_entry': 0x64df6a0,
        'memcpy': 0x64df508, 'panic': 0x64df830,
    }
    out = {}
    for name, slot in wanted.items():
        entry = rel.get(slot)
        require(entry is not None, f'missing relocation for slot {slot:#x}')
        row = {'slot': hex(slot), 'type': entry['type'],
               'addend': hex(entry['addend'])}
        if entry['type'] == 6:
            row['symbol'] = _dynsym_name(data, entry['symbol'])
        out[name] = row
    return out


def parse_objdump(text):
    import re
    out = {}
    for line in text.splitlines():
        m = re.match(r'\s+([0-9a-f]+):\t([0-9a-f ]+?)\s*\t(.*)', line)
        if m:
            site = int(m.group(1), 16)
            raw = bytes(int(x, 16) for x in m.group(2).split())
            out[site] = (raw, m.group(3).strip())
    return out


def _region(site):
    if site < PHASE2_START:
        return 'pre_phase2'
    if site < POSTLOOP_START:
        return 'phase2'
    if site < DRAIN_START:
        return 'postloop'
    if site < TAIL_START:
        return 'drain'
    return 'tail'


def stack_census(textmap):
    out = {}
    for slot in CENSUS_SLOTS:
        rows = [{'site': hex(s), 'region': _region(s), 'text': t}
                for s, (_, t) in sorted(textmap.items())
                if f'[rsp+{slot}]' in t]
        out[slot] = rows
    return out


def direct_call_census(data):
    sec = next((s for s in sections(data) if s['name'] == '.text'), None)
    require(sec is not None, 'missing.text section')
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


def consumer_textmap(data):
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node115.elf'
        snapshot.write_bytes(data)
        asm = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', '--insn-width=16',
             f'--start-address={CONSUMER:#x}',
             f'--stop-address={CONSUMER_END:#x}', str(snapshot)],
            text=True)
    textmap = parse_objdump(asm)
    decoded = decode_export(asm, CONSUMER, CONSUMER_END,
                            read(data, CONSUMER,
                                 CONSUMER_END - CONSUMER)[1])
    if set(textmap) != set(decoded):
        raise ValueError('consumer text map disagrees with byte decode')
    for site, raw in decoded.items():
        if textmap[site][0] != raw:
            raise ValueError('consumer text map byte disagreement')
    return textmap


def analyze(data):
    bindings = slot_bindings(data)
    _pins(data, CONSUMER_PINS, 'consumer')
    for role, table in HELPER_PIN_TABLES.items():
        _pins(data, table, role)
    _pins(data, DELEGATE_PINS, 'merge_delegate')
    for label, (site, slot) in SLOT_CALL_PINS.items():
        _slot_call(data, site, slot, label)
    if bindings['exit_reader']['addend'] != '0x4749ab0':
        raise ValueError('exit reader slot binding changed')
    if bindings['merge_delegate']['addend'] != '0x4748500':
        raise ValueError('merge delegate slot binding changed')
    if bindings['entry_vec_grow']['addend'] != '0x474e490':
        raise ValueError('entry vector grow slot binding changed')
    if bindings['vec40_grow_a']['addend'] != '0x474e420' or \
            bindings['vec40_grow_b']['addend'] != '0x474e420':
        raise ValueError('vec40 grow slot binding changed')
    if bindings['assert_entry']['addend'] != '0x1680c30':
        raise ValueError('assert slot binding changed')
    if bindings['memcpy'].get('symbol') != 'memcpy':
        raise ValueError('memcpy slot binding changed')
    census = direct_call_census(data)
    for name, site in (('pair_drop', '0x15a5e14'),
                       ('tagged_destroy_a', '0x15a5dfa'),
                       ('tagged_destroy_b', '0x15a6186'),
                       ('map1_drain_helper', '0x15a569e')):
        if site not in census[name]['sites']:
            raise ValueError(f'direct call census lost {name} site {site}')
    consumer_sites = {
        name: [r['site'] for r in census[name]['rows']
               if r['owner_fde'] == [hex(CONSUMER), hex(CONSUMER_END)]]
        for name in census}
    if consumer_sites['pair_drop'] != \
            ['0x15a5e14', '0x15a5eb2', '0x15a60d9', '0x15a64d4']:
        raise ValueError('consumer pair drop census changed')
    if consumer_sites['tagged_destroy_a'] != ['0x15a5dfa', '0x15a5e4c']:
        raise ValueError('consumer tagged destroy A census changed')
    if consumer_sites['tagged_destroy_b'] != ['0x15a6186', '0x15a61a3']:
        raise ValueError('consumer tagged destroy B census changed')
    if consumer_sites['map1_drain_helper'] != ['0x15a569e']:
        raise ValueError('consumer map1 helper census changed')
    if consumer_sites['drain_iterator'] != \
            ['0x15a5580', '0x15a6459', '0x15a64b5']:
        raise ValueError('consumer drain iterator census changed')
    textmap = consumer_textmap(data)
    stacks = stack_census(textmap)
    # Drain verdict: no access to the records' storage in the drain
    # region, for the pair home, the post-loop working copy, or the
    # taken-word slots.
    for slot in CENSUS_SLOTS:
        if slot in ('0x20', '0x278'):
            continue
        drain = [r for r in stacks[slot] if r['region'] == 'drain']
        if drain:
            raise ValueError(f'drain access to [rsp+{slot}] appeared')
    exit_rows = [r for r in stacks['0x240']
                 if int(r['site'], 16) >= EXIT_START]
    if [r['site'] for r in exit_rows] != ['0x15a591a', '0x15a64cc']:
        raise ValueError('exit-region pair home access changed')
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
        'consumer_call_sites': consumer_sites, 'stack_census': stacks,
        'assembly':
            'Post-loop (#2506 pins, restated for context): the two '
            'taken entries\' words are staged at [rsp+0x208]/[rsp+0x210] '
            '(key 0) and [rsp+0x218]/[rsp+0x220] (key 1); each assembled '
            '0x40-byte record is built at [rsp+0x20] with the taken '
            'words at its +0x30/+0x38 slots and appended to a vector '
            '(grow 0x474e420 through slots 0x64e1470/0x64e1478); a '
            'third record built from saved words is appended to the '
            'second vector of the working pair at [rsp+0x1d0]; at '
            '0x15a54c4..0x15a54ec the updated pair (0x30 bytes) is '
            'stored back to its home at [rsp+0x240] before the tree '
            'drop at 0x15a54fc and the drain region.',
        'drain_verdict':
            'The drain region (0x15a5501..0x15a5861) never reads the '
            'assembled records.  A stack census over the whole '
            'consumer body shows zero drain-region accesses to the '
            'pair home [rsp+0x240..0x268], the working pair '
            '[rsp+0x1d0..0x1f8], or the taken-word slots '
            '[rsp+0x208..0x220].  The drain works on a different '
            'map (handle words at [rsp+0x178..0x188], cursors at '
            '[rsp+0x28]/[rsp+0x48]) through the iterator 0x153ba90 '
            'and on the 0x18-byte-element vector at [rsp+0x90].  Its '
            'single call to the helper 0x149e5b0 (site 0x15a569e, '
            'arguments rdi = &[rsp+0xc0], rsi = &[rsp+0x28]) does '
            'not touch the records either: the helper loads only '
            'its cursor argument\'s three words, walks map-#1 nodes '
            'by the count words at node +0x110/+0x112 and the child '
            'link at node +0x120, frees nodes with the size class '
            '0x120 (first) or 0x180 (deeper) through the dealloc '
            'slot, and writes a fresh 0x30-byte cursor {next node, '
            '0, remainder, node, index, count} to its out argument; '
            'the consumer stores that cursor over its cursor-1 '
            'slot (0x15a56ea..0x15a56ee) and loops.  No 0x40-byte '
            'record field is loaded anywhere in the helper.',
        'exit_verdict':
            'On the normal path the saved pair is read exactly '
            'once, at the consumer exit block (0x15a58f2): the '
            'consumer builds an empty vector {0, 8, 0} at '
            '[rsp+0xc0] and calls the exit reader 0x4749ab0 through '
            'slot 0x64e1480 with rdi = &[rsp+0x20] (out), rsi = '
            '&[rsp+0x240] (the saved pair), rdx = &[rsp+0xc0].  The '
            'reader first calls its delegate 0x4748500 through slot '
            '0x64eafd8 to fill a 0x68-byte temp from the pair.  If '
            'the temp word at +0x60 is non-zero, the reader writes '
            'out = {6, temp+0x50, temp+0x58, temp+0x60} (0x20 bytes) '
            'and destroys the temp\'s pair copy inline: first-vector '
            'elements through the element drop 0x474dcd0, its buffer '
            'freed at capacity * 0x40, second-vector elements freed '
            'inline (the +0x8/+0x10 allocation and the +0x28 '
            '0x18-byte sub-vector of each).  If the word is zero, '
            'the reader copies the temp\'s first 0x50 bytes verbatim '
            'to out -- the pair copy moves out with it -- and frees '
            'only the delegate\'s 0x20-byte entry vector buffer '
            '(count << 5).  Back in the consumer, an out word of 6 '
            'branches to the assertion arm at 0x15a5b8c (slot '
            '0x64df6a0, target 0x1680c30); otherwise the consumer '
            'copies the 0x50-byte out struct to the destination '
            'pointer loaded from [rsp+0x278] and returns.',
        'delegate_verdict':
            'The delegate 0x4748500 (5,545 bytes, hash-pinned '
            'boundary; entry loops pinned here) consumes both '
            'vectors of the pair.  It copies the second vector\'s '
            'header in at the entry (words from pair +0x18/+0x28 to '
            'its local at [rsp+0x240]) and runs the same transform '
            'loop over each vector in turn (first-vector loop head '
            'at 0x47485d4, second-vector loop head at 0x4748c47): '
            'for every 0x40-byte element whose first word is not '
            'the sentinel 0x8000000000000000, it stages the element '
            'at [rsp+0x170] (word 0 verbatim, word at +0x38 '
            're-staged at +0x30), copies the element\'s string '
            '(length word at +0x8 region, pointer at +0x10 region '
            'of the staged record) through alloc + memcpy, gates '
            'the element through the transform gate 0x474ba60, and '
            'on a true result appends a 0x20-byte entry {0, element '
            'word 0, length, pointer} to a fresh local vector (grow '
            '0x474e490 through slot 0x64eafe0); the element\'s '
            'tagged pair (staged at [rsp+0x1a0]/[rsp+0x1a8]) is then '
            'destroyed through its descriptor.  At the end it '
            'writes the entry vector\'s header to the temp at '
            '+0x50/+0x60 (count at +0x60, 0x47494d6) -- the words '
            'the exit reader\'s discriminant-6 arm extracts.  The '
            'delegate\'s later merge phases are not traced.',
        'disposition_verdict':
            'Final disposition of the extracted words.  On unwind '
            'paths the taken words never reach the records: the '
            'consumer\'s landing pads destroy each taken pair '
            'directly through a tagged destroy -- 0x158bee0 at '
            '0x15a5dfa (key-1 words) and 0x15a5e4c (key-0 words), '
            'and its byte-twin 0x15ad360 at 0x15a6186 / 0x15a61a3 -- '
            'which calls descriptor word 0 (drop) on the +0x8 word '
            'when non-null and frees it through the dealloc slot '
            'with the class from descriptor words +0x8 (size) and '
            '+0x10 (align, tzcnt).  The assembled records '
            'themselves are destroyed by the pair drop 0x15ac5f0, '
            'called on the working pair at [rsp+0x1d0] (0x15a5eb2), '
            'on the pair at [rsp+0x90] (0x15a5e14), on the pair in '
            'the [rsp+0xc0] scratch (0x15a60d9) and on the saved '
            'pair at [rsp+0x240] (0x15a64d4, the final cleanup '
            'before _Unwind_Resume): it drops every first-vector '
            'element through the element drop 0x1538ec0 stepping '
            '0x40 from the buffer, frees that buffer at capacity * '
            '0x40, then destroys every second-vector element '
            'inline -- freeing the allocation at element +0x10 '
            'with size element +0x8, dropping the 0x18-byte '
            'sub-vector at element +0x28 (each sub-element\'s '
            'allocation freed, the sub-buffer freed at count * '
            '0x18) -- and frees the second buffer at capacity * '
            '0x40 through the pair tail helper 0x15ad260.  On the '
            'normal path the words\' ownership passes out of the '
            'consumer inside the records (exit verdict); no other '
            'consumer of the +0x30/+0x38 slots exists in the '
            'consumer body (stack census) or in any direct caller '
            'of the pinned helpers (call census).',
        'limits':
            'Static trace only.  The merge delegate 0x4748500 is a '
            'hash-pinned boundary beyond its two entry loops and '
            'its temp writes: its later merge phases, the transform '
            'gate 0x474ba60, the element drops 0x1538ec0 / '
            '0x474dcd0, the pair tail helper 0x15ad260, the drain '
            'iterator 0x153ba90, the grow functions 0x474e420 / '
            '0x474e490 and the assertion entry 0x1680c30 are '
            'hash-pinned boundaries.  What the delegate\'s entry '
            'vector means semantically, why the discriminant-6 arm '
            'is an assertion in the consumer, and what the '
            'destination object at [rsp+0x278] does with the '
            '0x50-byte result are not claimed.  The two '
            'tagged-destroy instances are claimed identical only at '
            'their pinned instruction shape.  No captured code '
            'executed, no runtime value or reconstruction gate is '
            'claimed.',
        'next_question':
            'What does the merge delegate 0x4748500 do in its later '
            'phases -- in particular how the 0x20-byte entry vector '
            'built from both record vectors is merged with the '
            'third argument\'s vector (the consumer passes an empty '
            '{0, 8, 0} vector) and what the transform gate '
            '0x474ba60 decides per element?'}


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)], text=True)


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
        asm = _objdump(snapshot, CONSUMER, CONSUMER_END)
        ins = decode_export(asm, CONSUMER, CONSUMER_END,
                            read(data, CONSUMER,
                                 CONSUMER_END - CONSUMER)[1])
        sites = {site for site, _ in CONSUMER_PINS.values()}
        sites |= {site for site, _ in SLOT_CALL_PINS.values()
                  if site < CONSUMER_END and site >= CONSUMER}
        if not sites <= set(ins):
            raise ValueError('consumer evidence site not native '
                             'instruction start')
        for name, wa, wb in WINDOWS:
            wasm = _objdump(snapshot, wa, wb)
            decode_export(wasm, wa, wb, read(data, wa, wb - wa)[1])
            (output / f'{name}_window_{wa:x}_{wb:x}_objdump.txt'
             ).write_bytes(wasm.replace(
                 str(snapshot), '<authenticated-node115>').encode('utf-8'))
        for name, a, b in FULL_EXPORTS:
            easm = _objdump(snapshot, a, b)
            eins = decode_export(easm, a, b, read(data, a, b - a)[1])
            esites = {site for site, _ in
                      HELPER_PIN_TABLES[name].values()}
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
                   default=ROOT / 'work/assembled-record-readers115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
