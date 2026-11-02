#!/usr/bin/env python3
"""Export selected node-94 interpreter call-frame evidence without executing it.

The decoder recognizes only reviewed byte shapes. It is not an x86 decoder or
an exhaustive control-flow analysis. All linked addresses are pre-load-bias.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Selected FDEs only; external call targets and older dependency boundaries are
# excluded. Hashes bind the entire decoded unwind interval, not source bodies.
BODIES = {
    0x4c94040: ('raw9_f1', 'ccf8fab68ae74472e0ff372ecaca9abc44128ef6864c9254688c63852731c35c'),
    0x4c947a0: ('raw18_f1', '5ef48f246d1411e2a675f7990979f278a50710b92897d0cbf085a3d230ba1e2d'),
    0x4c98090: ('raw9_f2', 'd6a2a674815d43ce867b27be944c56c6f5b7bac846277d98fb1aaab083571120'),
    0x4c986d0: ('raw18_f2', 'd8510a35bde88ce1212da926e11f63f84f907f9c642c88280f616ada252d4621'),
    0x4c91eb0: ('raw9_f4', 'e4014c406bdd112787c2cd596243c7697410a6ad43e2b51c952138700db6ae0d'),
    0x4c92430: ('raw18_f4', 'bf1a059751f540fb6562d7d1d9edc23045ad33b7ecef2e7154bd9fedc2806e29'),
    0x4c914c0: ('raw9_fa', 'edb0b965aa9f44abfd02f0eebdbbc26a44d82aa514d2e5428f7c7b0645c82cfb'),
    0x4c90e50: ('raw18_fa', 'e6d6776b6d04c0e1e49f384209c8e89e1688a890494fa48e71a91369493cf8bb'),
    0x4c91b10: ('range_helper', 'a15b31c66f47276f5bac02a2b72a42d19cb08c44eb5e3a54458c5b0fdd32e474'),
    0x44c9ec0: ('host_adapter', '98c9ac0a7eb93faefc19e163f6a5eeb9b92df9720cc99179f2a0a5692243c17e'),
    0x4da4c60: ('loop_adapter', '913fcd8a6bcec96144cb04247e7a4de890751b95b6092d3b5dd492bf59a8eae0'),
    0x4da6590: ('result_adapter', '031c76afb6f1ab749ef8f257fca310cfb23acf6188028f6eaad84d0a3b1582e0'),
}
# Table slots are decoded from RELA rather than read as already-relocated words.
TABLES = {
    9: (0x5723e88, {0xf1: 0x4c94040, 0xf2: 0x4c98090, 0xf4: 0x4c91eb0, 0xfa: 0x4c914c0}),
    18: (0x5724688, {0xf1: 0x4c947a0, 0xf2: 0x4c986d0, 0xf4: 0x4c92430, 0xfa: 0x4c90e50}),
}

# Each fixed window is a bounded, human-reviewed span, not a decoded CFG.
WINDOWS = [
    ('fa9_pop_and_key_save', 0x4c914c0, 0x4c91601),
    ('fa9_guards_and_range', 0x4c91601, 0x4c916ba),
    ('fa9_host_key', 0x4c916e7, 0x4c917a6),
    ('fa9_price_and_cap', 0x4c917a6, 0x4c91826),
    ('fa9_frame_publish', 0x4c91826, 0x4c91a71),
    ('fa9_allocation_unwind', 0x4c91a85, 0x4c91b06),
    ('fa18_pop_and_key_save', 0x4c90e50, 0x4c90f91),
    ('fa18_guards_and_range', 0x4c90f91, 0x4c9104a),
    ('fa18_host_key', 0x4c91077, 0x4c91136),
    ('fa18_price_and_cap', 0x4c91136, 0x4c911d7),
    ('fa18_frame_publish', 0x4c911d7, 0x4c91429),
    ('f4_9_source_lanes', 0x4c91f01, 0x4c91fc8),
    ('f4_9_host_lanes', 0x4c920a4, 0x4c92158),
    ('f4_9_price', 0x4c92158, 0x4c921d0),
    ('f4_9_frame_lanes', 0x4c9224d, 0x4c92356),
    ('f4_9_publish', 0x4c92356, 0x4c9242c),
    ('f4_18_source_lanes', 0x4c92481, 0x4c92548),
    ('f4_18_host_lanes', 0x4c92624, 0x4c926d8),
    ('f4_18_price', 0x4c926d8, 0x4c92778),
    ('f4_18_frame_lanes', 0x4c927f5, 0x4c928fe),
    ('f4_18_publish', 0x4c928fe, 0x4c929d4),
    ('f1_9_static_guard', 0x4c942a2, 0x4c942b6),
    ('f1_9_price', 0x4c943da, 0x4c9449f),
    ('f1_18_static_guard', 0x4c94a02, 0x4c94a16),
    ('f1_18_price', 0x4c94b3a, 0x4c94c33),
    ('f2_9_price', 0x4c983a0, 0x4c9845f),
    ('f2_18_price', 0x4c989e0, 0x4c98ad4),
    ('range_stack_and_first_bounds', 0x4c91b1e, 0x4c91c05),
    ('range_first_growth', 0x4c91c05, 0x4c91c66),
    ('range_copy_and_second_bounds', 0x4c91c66, 0x4c91dd7),
    ('range_finish_and_failures', 0x4c91dd7, 0x4c91eae),
    ('host_account_and_classify', 0x44c9ec0, 0x44c9fe5),
    ('host_error_publication', 0x44c9fe5, 0x44ca0f2),
    ('loop_adapter_entry', 0x4da4c60, 0x4da4d03),
    ('loop_adapter_restore', 0x4da4d03, 0x4da4dd1),
    ('result_adapter_precheck', 0x4da6590, 0x4da6650),
    ('result_adapter_handoff', 0x4da6650, 0x4da66ce),
]

# Reviewed transfers only. All rel8/rel32 destinations are read from ELF bytes.
TRANSFERS = [
    ('fa9_first_empty', 0x4c914de, 0x4c9160d),
    ('fa9_second_empty', 0x4c914f1, 0x4c9160d),
    ('fa9_range', 0x4c916a9, 0x4c91b10),
    ('fa9_range_failed', 0x4c916b4, 0x4c9180d),
    ('fa9_host', 0x4c9179b, 0x44c9ec0),
    ('fa9_host_error', 0x4c917a4, 0x4c917e4),
    ('fa9_base_gas_short', 0x4c917b5, 0x4c917e4),
    ('fa9_forward_ok', 0x4c917e2, 0x4c9181f),
    ('fa9_alloc_null', 0x4c91a33, 0x4c91a85),
    ('fa9_old_action_drop', 0x4c91a52, 0x4db4340),
    ('fa18_first_empty', 0x4c90e6e, 0x4c90f9d),
    ('fa18_second_empty', 0x4c90e81, 0x4c90f9d),
    ('fa18_range', 0x4c91039, 0x4c91b10),
    ('fa18_range_failed', 0x4c91044, 0x4c911c5),
    ('fa18_host', 0x4c9112b, 0x44c9ec0),
    ('fa18_host_error', 0x4c91134, 0x4c9119c),
    ('fa18_base_gas_short', 0x4c91173, 0x4c9119c),
    ('fa18_forward_ok', 0x4c9119a, 0x4c911d7),
    ('fa18_alloc_null', 0x4c913eb, 0x4c9143d),
    ('fa18_old_action_drop', 0x4c9140a, 0x4db4340),
    ('f4_9_range', 0x4c92072, 0x4c91b10),
    ('f4_9_host', 0x4c92158, 0x44c9ec0),
    ('f4_9_old_action_drop', 0x4c92383, 0x4db4340),
    ('f4_18_range', 0x4c925f2, 0x4c91b10),
    ('f4_18_host', 0x4c926d8, 0x44c9ec0),
    ('f4_18_old_action_drop', 0x4c9292b, 0x4db4340),
    ('f1_9_range', 0x4c942e4, 0x4c91b10),
    ('f1_9_host', 0x4c943da, 0x44c9ec0),
    ('f1_9_static_allowed', 0x4c942a8, 0x4c942b6),
    ('f1_9_old_action_drop', 0x4c946cf, 0x4db4340),
    ('f1_18_range', 0x4c94a44, 0x4c91b10),
    ('f1_18_host', 0x4c94b3a, 0x44c9ec0),
    ('f1_18_static_allowed', 0x4c94a08, 0x4c94a16),
    ('f1_18_old_action_drop', 0x4c94e63, 0x4db4340),
    ('f2_9_range', 0x4c982be, 0x4c91b10),
    ('f2_9_host', 0x4c983a0, 0x44c9ec0),
    ('f2_9_old_action_drop', 0x4c9860e, 0x4db4340),
    ('f2_18_range', 0x4c988fe, 0x4c91b10),
    ('f2_18_host', 0x4c989e0, 0x44c9ec0),
    ('f2_18_old_action_drop', 0x4c98c83, 0x4db4340),
    ('range_four_available', 0x4c91b29, 0x4c91b34),
    ('range_high_zero_continue', 0x4c91b8b, 0x4c91ba9),
    ('range_first_growth_failed', 0x4c91c57, 0x4c91b8d),
    ('range_second_growth_ok', 0x4c91e23, 0x4c91dd7),
    ('host_load', 0x44c9eeb, 0x44bb790),
    ('host_non_success', 0x44c9ef9, 0x44c9fe5),
    ('host_secondary', 0x44c9fbf, 0x44ba840),
    ('loop_table_zero', 0x4da4cc5, 0x4da4ce4),
    ('loop_other', 0x4da4cdd, 0x4c095a0),
    ('loop_zero', 0x4da4cfe, 0x4c09420),
    ('result_old_error', 0x4da664e, 0x4da668e),
]

# Prefixes identify a particular instruction and the expected value prevents a
# changed immediate from being silently accepted as a new finding.
IMMEDIATES = [
    ('fa9_base_cost', 0x4c917af, '483d', 4, 700),
    ('f4_9_base_cost', 0x4c9216c, '483d', 4, 700),
    ('f1_9_zero_cost', 0x4c94415, 'be', 4, 700),
    ('f1_9_value_cost', 0x4c94401, 'b8', 4, 9700),
    ('f1_9_value_empty_cost', 0x4c94406, 'ba', 4, 34700),
    ('f2_9_zero_cost', 0x4c983d5, 'ba', 4, 700),
    ('f2_9_value_cost', 0x4c983da, '41b8', 4, 9700),
    ('fa18_price_high', 0x4c9113f, 'ba', 4, 2600),
    ('fa18_price_low', 0x4c91144, 'be', 4, 100),
    ('f4_18_price_high', 0x4c926ec, 'ba', 4, 2600),
    ('f4_18_price_low', 0x4c926f1, 'be', 4, 100),
    ('f1_18_price_high', 0x4c94b69, 'be', 4, 2600),
    ('f1_18_price_low', 0x4c94b6e, 'bf', 4, 100),
    ('f1_18_value', 0x4c94b96, 'b8', 4, 9000),
    ('f1_18_value_empty', 0x4c94b9b, '41b8', 4, 34000),
    ('f2_18_price_high', 0x4c98a1d, '41b8', 4, 2600),
    ('f2_18_price_low', 0x4c98a23, '41b9', 4, 100),
    ('f2_18_value', 0x4c98a49, '4d8d88', 4, 9000),
    ('f1_9_stipend', 0x4c9448d, '4981c7', 4, 2300),
    ('f1_18_stipend', 0x4c94c21, '4981c7', 4, 2300),
    ('f2_9_stipend', 0x4c9844d, '4881c5', 4, 2300),
    ('f2_18_stipend', 0x4c98ac2, '4881c5', 4, 2300),
    ('fa9_underflow_status', 0x4c9160d, 'c683f3010000', 1, 0x5b),
    ('fa18_underflow_status', 0x4c90f9d, 'c683f3010000', 1, 0x5b),
    ('f1_9_static_status', 0x4c942aa, 'c687f3010000', 1, 0x56),
    ('f1_18_static_status', 0x4c94a0a, 'c687f3010000', 1, 0x56),
    ('range_underflow_status', 0x4c91b2b, 'c686f3010000', 1, 0x5b),
    ('range_width_status', 0x4c91b89, 'b2', 1, 0x54),
    ('range_growth_status', 0x4c91c53, 'b2', 1, 0x51),
    ('fa9_host_status', 0x4c917a0, 'b1', 1, 0x65),
    ('fa9_gas_status', 0x4c917ad, 'b1', 1, 0x50),
    ('fa18_host_status', 0x4c91130, 'b1', 1, 0x65),
    ('fa18_gas_status', 0x4c9116e, 'b1', 1, 0x50),
    ('fa9_scheme', 0x4c91a13, 'c68424be000000', 1, 3),
    ('fa18_scheme', 0x4c913cb, 'c68424be000000', 1, 3),
    ('fa9_static_and_padding', 0x4c91a1b, '66c78424bc000000', 2, 1),
    ('fa18_static_and_padding', 0x4c913d3, '66c78424bc000000', 2, 1),
    ('f4_9_scheme_word', 0x4c9234c, '66c78424dd000000', 2, 0x200),
    ('f4_18_scheme_word', 0x4c928f4, '66c78424dd000000', 2, 0x200),
    ('f2_9_scheme_word', 0x4c985d8, '66c78424dd000000', 2, 0x100),
    ('f2_18_scheme_word', 0x4c98c4d, '66c78424dd000000', 2, 0x100),
    ('f1_9_scheme_word', 0x4c94699, '66c78424bd000000', 2, 0),
    ('f1_18_scheme_word', 0x4c94e2d, '66c78424bd000000', 2, 0),
    ('f4_9_value_tag', 0x4c9233c, '48c7442440', 4, 1),
    ('f4_18_value_tag', 0x4c928e4, '48c7442440', 4, 1),
    ('fa9_frame_size', 0x4c91a25, 'bf', 4, 160),
    ('fa18_frame_size', 0x4c913dd, 'bf', 4, 160),
]

ACTION_SITES = [(0x4c946e0, 0x4c946e7), (0x4c94e74, 0x4c94e7b),
                (0x4c9861f, 0x4c98626), (0x4c98c94, 0x4c98c9b),
                (0x4c9238f, 0x4c92396), (0x4c92937, 0x4c9293e),
                (0x4c91a5e, 0x4c91a65), (0x4c91416, 0x4c9141d)]
DROP_SITES = [0x4c946cf, 0x4c94e63, 0x4c9860e, 0x4c98c83,
              0x4c92383, 0x4c9292b, 0x4c91a52, 0x4c9140a]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_offset(secs, va, size, executable=False):
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
            'invalid file-backed address or size')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'unmapped, crossing, NOBITS or ambiguous address')
    sec = matches[0]
    return sec['offset'] + va - sec['address']


def read_va(data, secs, va, size, executable=False):
    off = file_offset(secs, va, size, executable)
    require(off + size <= len(data), 'file-backed range is truncated')
    return data[off:off + size]


def relative(raw, site):
    require(bool(raw), 'empty transfer')
    if raw[0] in (0xe8, 0xe9):
        require(len(raw) == 5, 'invalid near transfer length')
        delta = struct.unpack_from('<i', raw, 1)[0]
    elif raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f:
        require(len(raw) == 2, 'invalid short transfer length')
        delta = struct.unpack_from('<b', raw, 1)[0]
    elif raw[0] == 0x0f and len(raw) == 6 and 0x80 <= raw[1] <= 0x8f:
        delta = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported transfer opcode')
    return site + len(raw) + delta


def transfer(data, secs, site, expected):
    head = read_va(data, secs, site, 2, True)
    length = 6 if head[0] == 0x0f else 5 if head[0] in (0xe8, 0xe9) else 2
    raw = read_va(data, secs, site, length, True)
    dest = relative(raw, site)
    require(dest == expected, 'transfer target differs from reviewed target')
    return raw, dest


def immediate(data, secs, site, prefix_hex, width, expected):
    prefix = bytes.fromhex(prefix_hex)
    require(width in (1, 2, 4), 'unsupported immediate width')
    raw = read_va(data, secs, site, len(prefix) + width, True)
    require(raw.startswith(prefix), 'immediate instruction prefix changed')
    val = int.from_bytes(raw[len(prefix):], 'little')
    require(val == expected, 'immediate value changed')
    return raw, val


def relocations(data, secs):
    found = {}
    for sec in secs:
        if sec['type'] != 4:  # SHT_RELA
            continue
        require(sec['size'] % 24 == 0, 'unsupported RELA entry size')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            found.setdefault(slot, []).append((info, addend, off))
    return found


def rela_at(data, rels, slot, expected=None):
    choices = rels.get(slot, [])
    require(len(choices) == 1, 'missing or duplicate relocation')
    info, addend, off = choices[0]
    require(info == 8, 'expected symbol-free R_X86_64_RELATIVE')
    if expected is not None:
        require(addend == expected, 'unexpected relocation addend')
    return {'slot_va': hex(slot), 'info': hex(info), 'addend_va': hex(addend),
            'entry_file_offset': hex(off), 'raw': data[off:off + 24].hex()}


def table_records(data, secs, rels):
    rows = []
    for case, (base, wanted) in sorted(TABLES.items()):
        for opcode, expected in sorted(wanted.items()):
            slot = base + 8 * opcode
            slot_raw = read_va(data, secs, slot, 8)
            require(slot_raw == bytes(8), 'unexpected unrelocated opcode slot')
            rec = rela_at(data, rels, slot, expected)
            rows.append([case, hex(base), hex(opcode), hex(slot),
                         hex(file_offset(secs, slot, 8)), slot_raw.hex(), hex(expected),
                         rec['entry_file_offset'], rec['raw']])
    return rows


def selector_records(data, secs):
    # These two short anchors are integration boundaries in the earlier
    # selector FDE. Its full body is not among this packet's selected FDEs.
    table = 0x6f2a8c
    rows = []
    for case, site, expected_case, expected_table in (
        (9, 0x44bce6a, 0x44bce62, 0x5723e88),
        (10, 0x44bce6a, 0x44bce62, 0x5723e88),
        (18, 0x44bd991, 0x44bd989, 0x5724688),
    ):
        word = read_va(data, secs, table + case * 4, 4)
        branch = table + struct.unpack('<i', word)[0]
        require(branch == expected_case, 'selector entry changed')
        destination = read_va(data, secs, branch, 8, True)
        require(destination == bytes.fromhex('488dbc24b0010000'), 'selector destination changed')
        lea = read_va(data, secs, site, 7, True)
        require(lea[:3] == b'\x48\x8d\x35', 'selector LEA changed')
        dest = site + 7 + struct.unpack_from('<i', lea, 3)[0]
        require(dest == expected_table and branch + 8 == site,
                'selector case/table association changed')
        copy = read_va(data, secs, site + 7, 5, True)
        require(copy == b'\xba\x00\x08\x00\x00', 'table copy size changed')
        rows.append([case, hex(table + case * 4), word.hex(), hex(branch),
                     hex(site), lea.hex(), hex(dest), int.from_bytes(copy[1:], 'little'), copy.hex(),
                     destination.hex()])
    return rows


def callback_bindings(data, secs, rels):
    # Small integration anchors in earlier constructor FDEs; these FDEs are
    # not selected or exported as new coverage here.
    specs = [
        (9, 'loop', 0x4ddd698, 0x5745d40, 0x18, 0x4da4c60),
        (18, 'loop', 0x4ddd128, 0x5745bf0, 0x18, 0x4da4c60),
        (9, 'child', 0x4ddd6ac, 0x5745d70, 0x28, 0x4da4e20),
        (18, 'child', 0x4ddd13c, 0x5745c20, 0x28, 0x4da4e20),
        (9, 'result', 0x4ddd6d4, 0x5745920, 0x48, 0x4da6590),
        (18, 'result', 0x4ddd164, 0x5745920, 0x48, 0x4da6590),
    ]
    rows = []
    for case, role, site, wanted_descriptor, wanted_field, wanted_method in specs:
        raw = read_va(data, secs, site, 11, True)
        require(raw[:3] == bytes.fromhex('488d0d') and raw[7:10] == bytes.fromhex('48894b'),
                'callback boundary instruction shape changed')
        descriptor = site + 7 + struct.unpack_from('<i', raw, 3)[0]
        field = raw[10]
        require(descriptor == wanted_descriptor and field == wanted_field, 'callback descriptor changed')
        slot = descriptor + 0x28
        rec = rela_at(data, rels, slot, wanted_method)
        rows.append([case, role, hex(site), raw.hex(), hex(descriptor), hex(field),
                     hex(slot), hex(wanted_method), rec['entry_file_offset'], rec['raw']])
    return rows


def handoff_boundaries(data, secs):
    specs = [
        ('handler_table_copy_destination', 0x44be921, '488dbb', 0x198),
        ('handler_table_copy_source', 0x44be928, '488db424', 0x1a8),
        ('handler_table_copy_length', 0x44be937, 'ba', 0x1000),
        ('handler_callback_destination', 0x44be9eb, '4881c3', 0xe8),
        ('handler_callback_copy_length', 0x44be9fa, 'ba', 0xb0),
        ('engine_loop_table', 0x47f3688, '498d86', 0x2a8),
        ('engine_loop_data', 0x47f36a0, '498b86', 0x208),
        ('engine_loop_descriptor', 0x47f36a7, '4d8b96', 0x210),
        ('engine_result_data', 0x47f4083, '498b86', 0x238),
        ('engine_result_descriptor', 0x47f408a, '498b8e', 0x240),
        ('engine_child_data', 0x47f379e, '498b86', 0x218),
        ('engine_child_descriptor', 0x47f37a5, '4d8b86', 0x220),
    ]
    rows = []
    for label, site, prefix, expected in specs:
        raw, value = immediate(data, secs, site, prefix, 4, expected)
        rows.append([label, hex(site), hex(file_offset(secs, site, len(raw), True)), raw.hex(), value, hex(value)])
    # For action 0x6c, the prior executor indexes relative table entry zero.
    base = 0x6fd0ec
    raw = read_va(data, secs, base, 4)
    target = base + struct.unpack('<i', raw)[0]
    require(target == 0x47f379e, 'action table entry changed')
    witnesses = []
    # These are existing executor-FDE boundary instructions only.
    for label, site, expected in (
        ('action_subtract', 0x47f377b, '8d5094'),
        ('action_compare', 0x47f377e, '3c6c'),
        ('action_clamp', 0x47f3788, '0f42c2'),
        ('loop_method_call', 0x47f36dc, '41ff5228'),
        ('child_method_call', 0x47f37d2, '41ff5028'),
        ('result_method_load', 0x47f4095, '4c8b5128'),
        ('result_indirect_call', 0x47f40de, '41ffd2'),
    ):
        actual = read_va(data, secs, site, len(bytes.fromhex(expected)), True)
        require(actual == bytes.fromhex(expected), 'executor boundary instruction changed')
        witnesses.append({'label': label, 'site_va': hex(site),
                          'file_offset': hex(file_offset(secs, site, len(actual), True)),
                          'raw': actual.hex()})
    return rows, {'table_va': hex(base), 'entry_file_offset': hex(file_offset(secs, base, 4)),
                  'entry_raw': raw.hex(), 'target_va': hex(target), 'witnesses': witnesses}


def source_locations(data, secs, rels):
    specs = [
        (0x4c91e3e, 0x5743478, 'revm-interpreter-15.0.0/src/instructions/contract/call_helpers.rs', 42, 18),
        (0x4c91e68, 0x5743478, 'revm-interpreter-15.0.0/src/instructions/contract/call_helpers.rs', 42, 18),
        (0x4c91e4b, 0x5743460, 'revm-interpreter-15.0.0/src/interpreter/shared_memory.rs', 117, 9),
        (0x4c91e77, 0x5743460, 'revm-interpreter-15.0.0/src/interpreter/shared_memory.rs', 117, 9),
    ]
    rows = []
    for site, location, suffix, want_line, want_col in specs:
        lea = read_va(data, secs, site, 7, True)
        require(lea[:3] == bytes.fromhex('488d3d') and
                site + 7 + struct.unpack_from('<i', lea, 3)[0] == location, 'source location LEA changed')
        rec = rela_at(data, rels, location)
        ptr = int(rec['addend_va'], 16)
        location_raw = read_va(data, secs, location, 24)
        file_pointer, length, line, column = struct.unpack('<QQII', location_raw)
        require(file_pointer == 0 and 0 < length < 1024 and line == want_line and column == want_col,
                'source location record changed')
        path = read_va(data, secs, ptr, length)
        require(path.endswith(suffix.encode('ascii')), 'source suffix changed')
        rows.append([hex(site), lea.hex(), hex(location), hex(file_offset(secs, location, 24)),
                     location_raw.hex(), rec['entry_file_offset'], rec['raw'], hex(ptr), length,
                     hashlib.sha256(path).hexdigest(), suffix, line, column])
    return rows


def host_constants(data, secs):
    # These vectors are the two operands of the host adapter's file-backed
    # 32-byte comparison; the digest name is a separate inference.
    specs = [(0x206160, 'c5d2460186f7233c927e7db2dcc703c0'),
             (0x204be0, 'e500b653ca82273b7bfad8045d85a470')]
    rows = []
    for index, (va, expected) in enumerate(specs):
        raw = read_va(data, secs, va, 16)
        require(raw.hex() == expected, 'host comparison constant changed')
        rows.append([index, hex(va), hex(file_offset(secs, va, len(raw))), raw.hex()])
    return rows


def host_classification(data, secs):
    """Pin the selected adapter's classification and normal result packing."""
    shapes = [
        ('revision_byte', 0x44c9ed4, '440fb6b7b0000000'),
        ('primary_tag_load', 0x44c9ef0, '0fb66c2410'),
        ('primary_success_tag', 0x44c9ef5, '4080fd05'),
        ('revision_threshold', 0x44c9f04, '4180fe04'),
        ('hash_first_half', 0x44c9f0a, 'f30f6f4068'),
        ('hash_second_half', 0x44c9f0f, 'f30f6f4878'),
        ('compare_second_half', 0x44c9f14, '660f740dc4acd3fb'),
        ('compare_first_half', 0x44c9f1c, '660f74053cc2d3fb'),
        ('compare_halves_and', 0x44c9f24, '660fdbc1'),
        ('compare_mask', 0x44c9f28, '660fd7c8'),
        ('all_lanes_equal', 0x44c9f2c, '81f9ffff0000'),
        ('hash_word_70', 0x44c9f34, '488b4870'),
        ('hash_word_80', 0x44c9f38, '480b8880000000'),
        ('hash_word_68', 0x44c9f3f, '488b5068'),
        ('hash_word_78', 0x44c9f43, '480b5078'),
        ('hash_zero_fold', 0x44c9f47, '4809ca'),
        ('account_word_48', 0x44c9f4c, '488b4848'),
        ('account_word_58', 0x44c9f50, '480b4858'),
        ('account_word_40', 0x44c9f54, '488b5040'),
        ('account_word_50', 0x44c9f58, '480b5050'),
        ('account_words_zero_fold', 0x44c9f5c, '4809ca'),
        ('class_clear', 0x44c9f65, '4531ff'),
        ('primary_result_byte', 0x44c9f68, '440fb6742420'),
        ('secondary_default', 0x44c9f6e, '66b90200'),
        ('account_tag_test', 0x44c9f72, '833803'),
        ('old_account_flag', 0x44c9f79, '0fb688b0000000'),
        ('old_flag_mask', 0x44c9f80, '80e10c'),
        ('old_flag_value', 0x44c9f83, '80f908'),
        ('class_boolean', 0x44c9f86, '410f94c7'),
        ('secondary_success_tag', 0x44c9fc9, '4080fd05'),
        ('secondary_result_byte', 0x44c9fcf, '0fb64c2420'),
        ('class_zero_extend', 0x44c9fd4, '410fb6c7'),
        ('class_shift', 0x44c9fd8, 'c1e008'),
        ('secondary_zero_extend', 0x44c9fdb, '0fb7c9'),
        ('class_or_secondary', 0x44c9fde, '09c1'),
        ('error_primary_result', 0x44ca0cd, '41b602'),
        ('combined_shift', 0x44ca0d0, 'c1e108'),
        ('primary_zero_extend', 0x44ca0d3, '410fb6c6'),
        ('normal_result_or', 0x44ca0d7, '09c8'),
        ('account_word_60_zero', 0x44ca0e8, '4883786000'),
    ]
    pins, raw_by_label = [], {}
    for label, site, expected_hex in shapes:
        expected = bytes.fromhex(expected_hex)
        raw = read_va(data, secs, site, len(expected), True)
        require(raw == expected, 'host classification instruction changed')
        raw_by_label[label] = raw
        pins.append({'label': label, 'site_va': hex(site),
                     'file_offset': hex(file_offset(secs, site, len(raw), True)), 'raw': raw.hex()})
    branches = []
    for label, site, target in (
        ('old_revision', 0x44c9f08, 0x44c9f79),
        ('empty_digest', 0x44c9f32, 0x44c9f4c),
        ('nonzero_other_digest', 0x44c9f4a, 0x44c9f65),
        ('zero_account_words', 0x44c9f5f, 0x44ca0e8),
        ('secondary_requested', 0x44c9f75, 0x44c9f99),
        ('secondary_error', 0x44c9fcd, 0x44c9fe5),
        ('word60_flags_to_class', 0x44ca0ed, 0x44c9f86),
    ):
        raw, dest = transfer(data, secs, site, target)
        branches.append({'label': label, 'site_va': hex(site), 'raw': raw.hex(), 'target_va': hex(dest)})
    return {'pins': pins, 'branches': branches,
            'revision_threshold': raw_by_label['revision_threshold'][-1],
            'old_flag_mask': raw_by_label['old_flag_mask'][-1],
            'old_flag_value': raw_by_label['old_flag_value'][-1],
            'secondary_default': int.from_bytes(raw_by_label['secondary_default'][2:], 'little'),
            'secondary_account_tag': raw_by_label['account_tag_test'][-1],
            'class_shift_within_secondary': raw_by_label['class_shift'][-1],
            'secondary_shift_within_return': raw_by_label['combined_shift'][-1],
            'note': 'Normal-return packing only. Field names and account-class meaning are inferred; loader/helper effects and error-path upper bits remain open.'}


def project_host_class(revision, account_flag, hash_bytes, account_words, word60):
    """Synthetic interpretation of the selected host-class predicates."""
    require(type(revision) is int and 0 <= revision < 256 and
            type(account_flag) is int and 0 <= account_flag < 256, 'invalid byte input')
    require(isinstance(hash_bytes, bytes) and len(hash_bytes) == 32, 'invalid hash bytes')
    require(isinstance(account_words, tuple) and len(account_words) == 4 and
            all(type(v) is int and 0 <= v < 1 << 64 for v in account_words), 'invalid account words')
    require(type(word60) is int and 0 <= word60 < 1 << 64, 'invalid account word')
    if revision <= 4:
        return (account_flag & 12) == 8
    empty_hash = bytes.fromhex('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
    return hash_bytes in (bytes(32), empty_hash) and not any(account_words) and word60 == 0


def pack_host_success(primary_byte, secondary_byte, class_flag):
    """Synthetic normal-return bit packing; no helper or error behavior."""
    require(type(primary_byte) is int and 0 <= primary_byte < 256 and
            type(secondary_byte) is int and 0 <= secondary_byte < 256 and
            type(class_flag) is bool, 'invalid packed host inputs')
    return primary_byte | (secondary_byte << 8) | (int(class_flag) << 16)


def frame_records(data, secs):
    # For each opcode the selected stores use one of two stack frame bases.
    # Decode the stack destination, copy size, tag and scheme from bytes.
    specs = [
        (9, 0xf1, 0x4c94689, 0x4c94699, 0x4c94692, 0x4c946b0, 0x4c946b5),
        (18, 0xf1, 0x4c94e1d, 0x4c94e2d, 0x4c94e26, 0x4c94e44, 0x4c94e49),
        (9, 0xf2, 0x4c985c8, 0x4c985d8, 0x4c985d1, 0x4c985ef, 0x4c985f4),
        (18, 0xf2, 0x4c98c3d, 0x4c98c4d, 0x4c98c46, 0x4c98c64, 0x4c98c69),
        (9, 0xf4, 0x4c9233c, 0x4c9234c, 0x4c92345, 0x4c92369, 0x4c9236e),
        (18, 0xf4, 0x4c928e4, 0x4c928f4, 0x4c928ed, 0x4c92911, 0x4c92916),
        (9, 0xfa, 0x4c91a04, 0x4c91a13, 0x4c91a1b, 0x4c91a38, 0x4c91a3d),
        (18, 0xfa, 0x4c913bc, 0x4c913cb, 0x4c913d3, 0x4c913f0, 0x4c913f5),
    ]
    rows = []
    for case, opcode, tag_site, scheme_site, flag_site, lea_site, size_site in specs:
        lea = read_va(data, secs, lea_site, 5, True)
        require(lea[:4] == bytes.fromhex('488d7424'), 'frame source LEA changed')
        base = lea[4]
        size_raw, size = immediate(data, secs, size_site, 'ba', 4, 160)
        zero_site, zero_raw = None, b''
        if opcode == 0xfa:
            zero_site = 0x4c91937 if case == 9 else 0x4c912ef
            zero_raw = read_va(data, secs, zero_site, 4, True)
            require(zero_raw == bytes.fromhex('660fefc0'), 'SIMD tag zeroing changed')
            tag_raw = read_va(data, secs, tag_site, 6, True)
            require(tag_raw == bytes.fromhex('660f7f442420'), 'zero frame tag store changed')
            scheme_raw = read_va(data, secs, scheme_site, 8, True)
            require(scheme_raw[:3] == bytes.fromhex('c68424'), 'static scheme store changed')
            scheme_offset = struct.unpack_from('<I', scheme_raw, 3)[0] - base
            scheme = scheme_raw[7]
            flag_raw = read_va(data, secs, flag_site, 10, True)
            require(flag_raw[:4] == bytes.fromhex('66c78424'), 'static flag store changed')
            flag_offset = struct.unpack_from('<I', flag_raw, 4)[0] - base
            flag = int.from_bytes(flag_raw[8:], 'little')
            require(flag == 1, 'static flag changed')
            tag = 0
            tag_kind = 'simd_zero'
            flag_kind = 'constant_one'
        else:
            tag_raw = read_va(data, secs, tag_site, 9, True)
            require(tag_raw[:4] == bytes.fromhex('48c74424') and tag_raw[4] == base,
                    'frame tag store changed')
            tag = int.from_bytes(tag_raw[5:], 'little')
            scheme_raw = read_va(data, secs, scheme_site, 10, True)
            require(scheme_raw[:4] == bytes.fromhex('66c78424'), 'scheme word store changed')
            scheme_offset = struct.unpack_from('<I', scheme_raw, 4)[0] + 1 - base
            scheme = scheme_raw[9]
            require(scheme_raw[8] == 0, 'scheme companion byte changed')
            flag_raw = read_va(data, secs, flag_site, 7, True)
            require(flag_raw[:3] == bytes.fromhex('888424'), 'inherited flag store changed')
            flag_offset = struct.unpack_from('<I', flag_raw, 3)[0] - base
            flag_kind = 'copied_interpreter_flag'
            tag_kind = 'immediate'
        expected_scheme = {0xf1: 0, 0xf2: 1, 0xf4: 2, 0xfa: 3}[opcode]
        require(tag == (1 if opcode == 0xf4 else 0) and scheme == expected_scheme and
                scheme_offset == 0x9e and flag_offset == 0x9c, 'frame field relation changed')
        rows.append([case, hex(opcode), hex(lea_site), lea.hex(), hex(base), hex(tag_site),
                     tag_raw.hex(), tag, tag_kind, hex(zero_site) if zero_site is not None else '', zero_raw.hex(),
                     hex(flag_site), flag_raw.hex(),
                     hex(flag_offset), flag_kind, hex(scheme_site), scheme_raw.hex(),
                     hex(scheme_offset), scheme, hex(size_site), size_raw.hex(), size])
    return rows


def memcpy_binding(data, secs, rels):
    """Resolve one reviewed indirect slot through its ELF dynamic symbol."""
    slot = 0x576dfe0
    records = rels.get(slot, [])
    require(len(records) == 1, 'memcpy relocation missing or duplicated')
    info, addend, rela_off = records[0]
    symbol_index, reloc_type = info >> 32, info & 0xffffffff
    require(reloc_type == 6 and addend == 0, 'memcpy relocation kind changed')
    symbols = [s for s in secs if s['name'] == '.dynsym' and s['type'] == 11]
    strings = [s for s in secs if s['name'] == '.dynstr' and s['type'] == 3]
    require(len(symbols) == len(strings) == 1, 'dynamic symbol sections missing or duplicated')
    sym, string = symbols[0], strings[0]
    require(sym['size'] % 24 == 0 and symbol_index < sym['size'] // 24,
            'dynamic symbol index outside table')
    sym_off = sym['offset'] + symbol_index * 24
    sym_raw = data[sym_off:sym_off + 24]
    require(len(sym_raw) == 24, 'dynamic symbol truncated')
    name_off = struct.unpack_from('<I', sym_raw)[0]
    require(name_off < string['size'], 'dynamic symbol name outside table')
    begin = string['offset'] + name_off
    stop = data.find(b'\0', begin, string['offset'] + string['size'])
    require(stop >= 0 and data[begin:stop] == b'memcpy', 'dynamic symbol name changed')
    witnesses = []
    for site in (0x4c91ce6, 0x4c92376, 0x4c9291e):
        raw = read_va(data, secs, site, 6, True)
        require(raw[:2] == bytes.fromhex('ff15') and
                site + 6 + struct.unpack_from('<i', raw, 2)[0] == slot,
                'indirect copy slot changed')
        witnesses.append({'site_va': hex(site), 'file_offset': hex(file_offset(secs, site, 6, True)),
                          'raw': raw.hex()})
    return {'slot_va': hex(slot), 'slot_file_offset': hex(file_offset(secs, slot, 8)),
            'slot_raw': read_va(data, secs, slot, 8).hex(),
            'relocation_file_offset': hex(rela_off), 'relocation_raw': data[rela_off:rela_off + 24].hex(),
            'relocation_type': reloc_type, 'symbol_index': symbol_index,
            'symbol_file_offset': hex(sym_off), 'symbol_raw': sym_raw.hex(),
            'name_file_offset': hex(begin), 'name': 'memcpy', 'calls': witnesses,
            'note': 'Dynamic symbol binding is subject to runtime loader and interposition.'}


def payload_flow(data, secs, rels=None):
    """Follow the reviewed f4 helper-result words into each copied frame.

    The pins identify specific x86 forms, not a general disassembler. The
    projection assumes ordinary non-aliasing helper calls and normal returns.
    """
    pins = []

    def pin(label, site, prefix_hex, operand=None):
        prefix = bytes.fromhex(prefix_hex)
        raw = read_va(data, secs, site, len(prefix) + (operand is not None), True)
        require(raw[:len(prefix)] == prefix, 'payload instruction shape changed')
        if operand is not None:
            require(raw[-1] == operand, 'payload displacement changed')
        pins.append({'label': label, 'site_va': hex(site),
                     'file_offset': hex(file_offset(secs, site, len(raw), True)),
                     'raw': raw.hex()})
        return raw[-1] if operand is not None else None

    # With the four-word count check satisfied, rdx is stack_count << 5.
    # Relative to that cursor the top word is at -0x20 and the next word's
    # low limb, loaded into r14, is at -0x40.
    shift = pin('stack_word_shift', 0x4c91b3e, '48c1e2', 5)
    top_byte = pin('top_word_low_limb', 0x4c91b42, '4a8b6c12', 0xe0)
    len_byte = pin('length_word_low_limb', 0x4c91b56, '4e8b7412', 0xc0)
    pin('test_length_register', 0x4c91bca, '4d85f6')
    pin('allocation_size_register', 0x4c91cc5, '4c89f7')
    pin('input_copy_size_register', 0x4c91ce3, '4c89f2')
    local_words = [
        pin('helper_word_0', 0x4c91d55, '48894424', 0x28),
        pin('helper_word_1', 0x4c91d5a, '4c897c24', 0x30),
        pin('helper_word_2_length', 0x4c91d5f, '4c897424', 0x38),
        pin('helper_word_3', 0x4c91d64, '48894c24', 0x40),
    ]
    helper_load = [pin('helper_vector_0_load', 0x4c91de0, '0f104424', 0x28),
                   pin('helper_vector_1_load', 0x4c91de5, '0f104c24', 0x38)]
    helper_return_1 = pin('helper_vector_1_return', 0x4c91dea, '0f114f', 0x10)
    pin('helper_vector_0_return', 0x4c91dee, '0f1107')
    signed_top = struct.unpack('<b', bytes([top_byte]))[0]
    signed_len = struct.unpack('<b', bytes([len_byte]))[0]
    word_size = 1 << shift
    require(signed_top == -word_size and signed_len == -2 * word_size,
            'stack word relationship changed')

    rows = []
    variants = [
        (9, 0x4c9206a, 0x4c92072, 0x4c92083, 0x4c92088,
         0x4c9209f, 0x4c9209a, 0x4c921d7, 0x4c921dc,
         0x4c921e6, 0x4c921e1, 0x4c92369),
        (18, 0x4c925ea, 0x4c925f2, 0x4c92603, 0x4c92608,
         0x4c9261f, 0x4c9261a, 0x4c9277f, 0x4c92784,
         0x4c9278e, 0x4c92789, 0x4c92911),
    ]
    for (case, out_site, call_site, load0, load1, spill0, spill1,
         reload0, reload1, final0, final1, base_site) in variants:
        label = 'raw' + str(case) + '_'
        out_base = pin(label + 'helper_output', out_site, '488d7c24', 0x40)
        call_raw, target = transfer(data, secs, call_site, 0x4c91b10)
        pins.append({'label': label + 'helper_call', 'site_va': hex(call_site),
                     'file_offset': hex(file_offset(secs, call_site, len(call_raw), True)),
                     'raw': call_raw.hex(), 'target_va': hex(target)})
        input_vec = [pin(label + 'load_0', load0, '0f104424', 0x40),
                     pin(label + 'load_1', load1, '0f104c24', 0x50)]
        spill = [pin(label + 'spill_0', spill0, '0f294424', 0x20),
                 pin(label + 'spill_1', spill1, '0f294c24', 0x30)]
        reload = [pin(label + 'reload_0', reload0, '0f284424', 0x20),
                  pin(label + 'reload_1', reload1, '0f284c24', 0x30)]
        final = [pin(label + 'frame_store_0', final0, '0f114424', 0x68),
                 pin(label + 'frame_store_1', final1, '0f114c24', 0x78)]
        frame_base = pin(label + 'copied_frame_base', base_site, '488d7424', 0x40)
        require(spill == reload and input_vec == [out_base, out_base + helper_return_1],
                'payload vector handoff changed')
        for index, local in enumerate(local_words):
            vector, lane = divmod(index, 2)
            lane *= 8
            return_offset = vector * helper_return_1 + lane
            require(local == helper_load[vector] + lane, 'helper payload word relation changed')
            frame_offset = final[vector] + lane - frame_base
            rows.append({'raw_case': case, 'word_index': index,
                         'helper_local_stack_offset': hex(local),
                         'helper_output_offset': hex(return_offset),
                         'caller_spill_offset': hex(spill[vector] + lane),
                         'frame_offset': hex(frame_offset),
                         'role_inferred': 'input_length' if index == 2 else 'unspecified_word'})
        require([int(r['frame_offset'], 16) for r in rows[-4:]] == [0x28, 0x30, 0x38, 0x40],
                'payload frame offsets changed')
    if rels is None:
        rels = relocations(data, secs)
    return {'stack_word_bytes': word_size, 'length_word_from_top': -signed_len // word_size,
            'length_word_low_limb_relative_to_cursor': signed_len,
            'rows': rows, 'pins': pins, 'copy_symbol': memcpy_binding(data, secs, rels),
            'note': 'Selected normal-path byte projection, not execution; register preservation and no unexpected aliasing are assumptions.'}


def symbolic_lanes(data, secs, source_start, source_end, host_start, host_end,
                   frame_start, frame_end):
    """Follow reviewed f4 byte-load/spill/store shapes, not arbitrary x86."""
    src = read_va(data, secs, source_start, source_end - source_start, True)
    host = read_va(data, secs, host_start, host_end - host_start, True)
    frame = read_va(data, secs, frame_start, frame_end - frame_start, True)
    temp, source_sites = {}, {}
    first = bytes.fromhex('0fb63c0240887c241f')
    require(src.startswith(first), 'first key load changed')
    temp[0x1f] = 0
    source_sites[0] = source_start
    pattern = re.compile(re.escape(bytes.fromhex('0fb67c02')) + b'(.)' + re.escape(bytes.fromhex('40887c24')) + b'(.)', re.DOTALL)
    matches = list(pattern.finditer(src))
    require(len(matches) == 16, 'unexpected key spill count')
    for match in matches:
        idx, spill = match.group(1)[0], match.group(2)[0]
        require(idx not in source_sites and spill not in temp, 'duplicate key spill')
        temp[spill] = idx
        source_sites[idx] = source_start + match.start()
    middle = bytes.fromhex('0fb64c0211884c240e')
    at = src.find(middle)
    require(at >= 0 and src.count(middle) == 1 and 0x0e not in temp, 'key byte 17 changed')
    temp[0x0e] = 17
    source_sites[17] = source_start + at
    for idx, raw in ((18, '440fb6640212'), (19, '440fb66c0213')):
        needle = bytes.fromhex(raw)
        at = src.find(needle)
        require(at >= 0 and src.count(needle) == 1, 'saved key register changed')
        source_sites[idx] = source_start + at
    require(set(source_sites) == set(range(20)), 'incomplete source key lanes')

    def collect_targets(blob, start, is_frame):
        direct = [(19, bytes.fromhex('4488ac24') if is_frame else bytes.fromhex('44886c24')),
                  (18, bytes.fromhex('4488a424') if is_frame else bytes.fromhex('44886424'))]
        entries = {}
        for idx, prefix in direct:
            pos = blob.find(prefix)
            require(pos >= 0 and blob.count(prefix) == 1, 'register key store changed')
            pos2 = pos + len(prefix)
            dst = int.from_bytes(blob[pos2:pos2 + (4 if is_frame else 1)], 'little')
            entries[dst] = (idx, start + pos)
        if is_frame:
            pat = re.compile(re.escape(bytes.fromhex('0fb64424')) + b'(.)' + re.escape(bytes.fromhex('888424')) + b'(.{4})', re.DOTALL)
        else:
            pat = re.compile(re.escape(bytes.fromhex('0fb64424')) + b'(.)' + re.escape(bytes.fromhex('884424')) + b'(.)', re.DOTALL)
        found = list(pat.finditer(blob))
        require(len(found) == 18, 'unexpected selected key store count')
        for match in found:
            spill = match.group(1)[0]
            dst = int.from_bytes(match.group(2), 'little')
            require(spill in temp and dst not in entries, 'unknown or duplicate key store')
            entries[dst] = (temp[spill], start + match.start() + 5)
        return entries

    host_entries = collect_targets(host, host_start, False)
    frame_entries = collect_targets(frame, frame_start, True)
    require(set(host_entries) == set(range(0x40, 0x54)), 'host key destination changed')
    require(set(frame_entries) == set(range(0xa0, 0xb4)), 'frame key destination changed')
    rows = []
    for lane in range(20):
        source, host_site = host_entries[0x40 + lane]
        frame_source, frame_site = frame_entries[0xa0 + lane]
        require(source == frame_source == 19 - lane, 'host/frame source lane mismatch')
        rows.append([lane, source, hex(source_sites[source]), hex(host_site),
                     hex(frame_site), hex(0x60 + lane)])
    return rows


def lsda_records(data, secs, fde):
    if fde['lsda'] is None:
        return None
    sec_list = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(sec_list) == 1, 'exception section missing or duplicated')
    sec = sec_list[0]
    start = file_offset(secs, fde['lsda'], 1)
    end = sec['offset'] + sec['size']
    require(sec['offset'] <= start < end and start + 2 <= end, 'LSDA outside section')
    require(data[start] == 0xff, 'unsupported LPStart encoding')
    typ, pos = data[start + 1], start + 2
    type_table = None
    if typ == 0x9b:
        delta, pos = uleb(data, pos, end)
        type_table = pos + delta
        require(type_table <= end, 'type table outside exception section')
    else:
        require(typ == 0xff, 'unsupported type encoding')
    require(pos < end and data[pos] == 1, 'unsupported call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, end)
    stop = pos + size
    require(stop <= end and (type_table is None or stop <= type_table), 'invalid call-site extent')
    header_end, entries, last = pos, [], 0
    while pos < stop:
        before = pos
        offset, pos = uleb(data, pos, stop)
        length, pos = uleb(data, pos, stop)
        landing, pos = uleb(data, pos, stop)
        action, pos = uleb(data, pos, stop)
        require(offset >= last and fde['start'] + offset + length <= fde['end'],
                'call-site outside or out of order')
        require(not landing or fde['start'] + landing < fde['end'], 'landing outside FDE')
        last = offset + length
        entries.append({'start_va': hex(fde['start'] + offset), 'length': length,
                        'landing_va': hex(fde['start'] + landing) if landing else None,
                        'action': action, 'raw': data[before:pos].hex()})
    return {'function_va': hex(fde['start']), 'lsda_va': hex(fde['lsda']),
            'file_offset': hex(start), 'header': data[start:header_end].hex(),
            'table': data[header_end:stop].hex(), 'entries': entries}


def unwind_bytes(data, secs, va):
    head = read_va(data, secs, va, 4)
    size = struct.unpack('<I', head)[0]
    require(4 <= size < 0xffffffff, 'unsupported unwind record size')
    return read_va(data, secs, va, size + 4)


def load_authenticated(path=TARGET):
    data = Path(path).read_bytes()
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'target SHA-256 mismatch')
    return data


def tsv(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue()


def json_text(obj):
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True) + '\n'


def select_fdes(data, secs, all_fdes, index):
    frame_by_start = {}
    for frame in all_fdes:
        frame_by_start.setdefault(frame['start'], []).append(frame)
    index_by_start = {}
    for ent in index:
        index_by_start.setdefault(ent['start'], []).append(ent)
    chosen = {}
    for start in sorted(BODIES):
        matches = frame_by_start.get(start, [])
        header = index_by_start.get(start, [])
        require(len(matches) == len(header) == 1, 'missing or duplicate selected FDE')
        fde, ent = matches[0], header[0]
        require(ent['fde'] == fde['fde'] and fde['end'] > start, 'unwind index disagrees with FDE')
        raw = read_va(data, secs, start, fde['end'] - start, True)
        require(hashlib.sha256(raw).hexdigest() == BODIES[start][1], 'selected body hash changed')
        chosen[start] = fde
    return chosen


def collect(data):
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'target SHA-256 mismatch')
    secs = sections(data)
    _, all_fdes = eh_frame_records(data, secs)
    _, index = unwind_index(data)
    chosen = select_fdes(data, secs, all_fdes, index)
    rels = relocations(data, secs)
    opcodes = table_records(data, secs, rels)
    selectors = selector_records(data, secs)
    callbacks = callback_bindings(data, secs, rels)
    handoff, action_entry = handoff_boundaries(data, secs)
    locations = source_locations(data, secs, rels)
    frames = frame_records(data, secs)
    payload = payload_flow(data, secs, rels)
    host_words = host_constants(data, secs)
    host_class = host_classification(data, secs)

    functions, bodies, unwind, exceptions = [], {}, [], []
    for start, fde in chosen.items():
        raw = read_va(data, secs, start, fde['end'] - start, True)
        functions.append([hex(start), hex(fde['end']), len(raw),
                          hex(file_offset(secs, start, len(raw), True)), hex(fde['fde']),
                          hex(fde['cie']), hex(fde['lsda']) if fde['lsda'] else '',
                          hashlib.sha256(raw).hexdigest(), BODIES[start][0]])
        bodies[hex(start)] = {'role': BODIES[start][0], 'bytes': raw.hex()}
        unwind.append({'start_va': hex(start), 'end_va': hex(fde['end']),
                       'fde_va': hex(fde['fde']), 'fde_raw': unwind_bytes(data, secs, fde['fde']).hex(),
                       'cie_va': hex(fde['cie']), 'cie_raw': unwind_bytes(data, secs, fde['cie']).hex(),
                       'lsda_va': hex(fde['lsda']) if fde['lsda'] else None})
        lsda = lsda_records(data, secs, fde)
        if lsda is not None:
            exceptions.append(lsda)

    windows = []
    for label, begin, end in WINDOWS:
        owners = [f for f in chosen.values() if f['start'] <= begin < end <= f['end']]
        require(len(owners) == 1, 'window outside selected FDE')
        raw = read_va(data, secs, begin, end - begin, True)
        windows.append([label, hex(owners[0]['start']), hex(begin), hex(end),
                        hex(file_offset(secs, begin, len(raw), True)), raw.hex(),
                        hashlib.sha256(raw).hexdigest()])
    transfers = []
    for label, site, dest in TRANSFERS:
        raw, target = transfer(data, secs, site, dest)
        owners = [f for f in chosen.values() if f['start'] <= site and site + len(raw) <= f['end']]
        require(len(owners) == 1, 'transfer outside selected FDE')
        transfers.append([label, hex(owners[0]['start']), hex(site),
                          hex(file_offset(secs, site, len(raw), True)), raw.hex(), hex(target)])
    operands = []
    for label, site, prefix, width, expected in IMMEDIATES:
        raw, value = immediate(data, secs, site, prefix, width, expected)
        operands.append([label, hex(site), hex(file_offset(secs, site, len(raw), True)),
                         raw.hex(), width, value, hex(value)])
    actions = []
    for action_site, status_site in ACTION_SITES:
        a = read_va(data, secs, action_site, 7, True)
        s = read_va(data, secs, status_site, 7, True)
        require(a[:2] in (b'\xc6\x83', b'\xc6\x80') and
                s[:2] == a[:2] and struct.unpack_from('<I', a, 2)[0] == 0x188 and
                struct.unpack_from('<I', s, 2)[0] == 0x1f3 and a[6] == 0x6c and s[6] == 0x20,
                'action/status publication changed')
        actions.append([hex(action_site), a.hex(), hex(struct.unpack_from('<I', a, 2)[0]), a[6],
                        hex(status_site), s.hex(), hex(struct.unpack_from('<I', s, 2)[0]), s[6]])
    lanes = []
    for case, source, host, frame in (
        (9, (0x4c91f01, 0x4c91fc8), (0x4c920a4, 0x4c92150), (0x4c9224d, 0x4c92335)),
        (18, (0x4c92481, 0x4c92548), (0x4c92624, 0x4c926d0), (0x4c927f5, 0x4c928dd)),
    ):
        for row in symbolic_lanes(data, secs, *source, *host, *frame):
            lanes.append([case] + row)

    key = read_va(data, secs, 0x574f0c0, 20)
    require(key == bytes(19) + b'\x09', 'existing address-09 key changed')
    obj_rela = rela_at(data, rels, 0x574f0b0, 0x4e9d2a0)
    as_word = int.from_bytes(key, 'big').to_bytes(32, 'little')
    require(bytes(as_word[row[2]] for row in lanes[:20]) == key, 'address-09 lane projection mismatch')
    object_boundary = {'key_va': hex(0x574f0c0), 'key_file_offset': hex(file_offset(secs, 0x574f0c0, 20)),
                       'key_bytes': key.hex(), 'record_callback_relocation': obj_rela,
                       'key_as_little_endian_stack_word': as_word.hex(),
                       'projected_key': bytes(as_word[row[2]] for row in lanes[:20]).hex(),
                       'note': 'Projection from file-backed key; not a captured runtime input.'}

    boundary_relas = []
    for slot, target in ((0x5745d68, 0x4da4c60), (0x5745c18, 0x4da4c60),
                         (0x5745948, 0x4da6590), (0x5774df8, 0x4e8f2b0),
                         (0x5773f40, 0x4e8fcb0)):
        boundary_relas.append(rela_at(data, rels, slot, target))
    # The old-action drop must be covered by an FDE/LSDA landing. The action
    # chains remain opaque; byte sequences in the landing are evidence only.
    landings = []
    for site in DROP_SITES:
        matches = []
        for table in exceptions:
            for entry in table['entries']:
                if int(entry['start_va'], 16) <= site < int(entry['start_va'], 16) + entry['length'] and entry['landing_va']:
                    matches.append((table, entry))
        require(len(matches) == 1, 'drop site missing unique LSDA landing')
        tab, entry = matches[0]
        landing = int(entry['landing_va'], 16)
        # These two reviewed shapes publish the new pointer and action tag,
        # then resume unwinding without writing the normal-path status byte.
        owner = int(tab['function_va'], 16)
        if owner in (0x4c94040, 0x4c947a0, 0x4c98090, 0x4c986d0):
            prefix = bytes.fromhex('4889c3488b4424184c89b050010000c680880100006c4889df')
        else:
            prefix = bytes.fromhex('4989c64c89bb50010000c683880100006c4c89f7')
        raw = read_va(data, secs, landing, len(prefix), True)
        require(raw == prefix, 'drop landing publication changed')
        resume, target = transfer(data, secs, landing + len(prefix), 0x5660110)
        landings.append([hex(site), tab['function_va'], entry['start_va'], entry['length'],
                         entry['landing_va'], entry['action'], (raw + resume).hex(), hex(target)])

    metrics = {'target': 'node-94', 'binary_sha256': DIGEST,
               'coordinate_system': 'linked ELF virtual addresses before load bias',
               'selected_fdes': len(functions), 'selected_fde_bytes': sum(r[2] for r in functions),
               'selected_opcode_slots': len(opcodes), 'selector_boundary_rows': len(selectors),
               'reviewed_windows': len(windows), 'selected_direct_transfers': len(transfers),
               'selected_immediates': len(operands), 'action_publications': len(actions),
               'key_lane_rows': len(lanes), 'lsda_tables': len(exceptions),
               'lsda_call_sites': sum(len(x['entries']) for x in exceptions),
               'drop_landings': len(landings), 'boundary_relocations': len(boundary_relas),
               'callback_boundary_rows': len(callbacks), 'handoff_boundary_rows': len(handoff),
               'source_location_rows': len(locations), 'frame_layout_rows': len(frames),
               'payload_word_rows': len(payload['rows']), 'payload_instruction_pins': len(payload['pins']),
               'host_class_instruction_pins': len(host_class['pins']),
               'host_class_branches': len(host_class['branches']),
               'host_constant_rows': len(host_words),
               'limits': 'Selected static observations; no general x86 decoding, reachability, native execution or whole-node coverage.'}
    return {
        'summary.json': json_text(metrics),
        'functions.tsv': tsv(['start_va', 'end_va', 'bytes', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'sha256', 'role_inferred'], functions),
        'bodies.json': json_text(bodies),
        'unwind.json': json_text(unwind),
        'opcode-table.tsv': tsv(['raw_case', 'table_va', 'opcode', 'slot_va', 'slot_file_offset', 'slot_raw', 'target_va', 'rela_file_offset', 'rela_raw'], opcodes),
        'selector-boundaries.tsv': tsv(['raw_case', 'table_entry_va', 'table_entry_raw', 'case_va', 'lea_va', 'lea_raw', 'opcode_table_va', 'copy_size', 'copy_raw', 'destination_raw'], selectors),
        'windows.tsv': tsv(['label', 'function_va', 'start_va', 'end_va', 'file_offset', 'raw', 'sha256'], windows),
        'transfers.tsv': tsv(['label', 'function_va', 'site_va', 'file_offset', 'raw', 'target_va'], transfers),
        'immediates.tsv': tsv(['label', 'site_va', 'file_offset', 'raw', 'width', 'value', 'value_hex'], operands),
        'publications.tsv': tsv(['action_site_va', 'action_raw', 'action_offset', 'action_value', 'status_site_va', 'status_raw', 'status_offset', 'status_value'], actions),
        'delegate-key-lanes.tsv': tsv(['raw_case', 'output_lane', 'source_word_byte', 'source_load_va', 'host_store_va', 'frame_store_va', 'frame_offset'], lanes),
        'exceptions.json': json_text(exceptions),
        'drop-landings.tsv': tsv(['drop_call_va', 'function_va', 'interval_start_va', 'interval_length', 'landing_va', 'action', 'landing_through_resume', 'resume_target_va'], landings),
        'boundary-relocations.json': json_text(boundary_relas),
        'callback-boundaries.tsv': tsv(['raw_case', 'role', 'site_va', 'raw', 'descriptor_va', 'output_offset', 'method_slot_va', 'method_va', 'rela_file_offset', 'rela_raw'], callbacks),
        'handoff-boundaries.tsv': tsv(['label', 'site_va', 'file_offset', 'raw', 'operand', 'operand_hex'], handoff),
        'action-table-boundary.json': json_text(action_entry),
        'object-boundary.json': json_text(object_boundary),
        'host-constants.tsv': tsv(['order', 'va', 'file_offset', 'raw'], host_words),
        'host-classification.json': json_text(host_class),
        'frame-layout.tsv': tsv(['raw_case', 'opcode', 'source_lea_va', 'source_lea_raw', 'frame_stack_base', 'tag_site_va', 'tag_raw', 'tag', 'tag_kind', 'zero_site_va', 'zero_raw', 'flag_site_va', 'flag_raw', 'flag_offset', 'flag_kind', 'scheme_site_va', 'scheme_raw', 'scheme_offset', 'scheme', 'copy_size_site_va', 'copy_size_raw', 'frame_size'], frames),
        'delegate-payload-flow.json': json_text(payload),
        'source-locations.tsv': tsv(['lea_va', 'lea_raw', 'location_va', 'location_file_offset', 'location_raw', 'rela_file_offset', 'rela_raw', 'path_va', 'path_length', 'path_sha256', 'sanitized_suffix', 'line', 'column'], locations),
    }


def price(case, opcode, host, value_nonzero=False):
    """Synthetic projection of the selected machine predicates, not execution."""
    require(case in TABLES and opcode in TABLES[case][1], 'unsupported table case or opcode')
    require(type(host) is int and 0 <= host < (1 << 24), 'host word outside modeled width')
    require(type(value_nonzero) is bool, 'value flag must be boolean')
    if host & 0xff == 2:
        return None
    if case == 9:
        base = 700
    else:
        part0 = 2600 if host & 1 else 100
        part1 = 0 if ((host >> 8) & 0xff) == 2 else (2600 if host & 0x100 else 100)
        base = part0 + part1
    if value_nonzero and opcode == 0xf1:
        base += 34000 if host & 0x10000 else 9000
    elif value_nonzero and opcode == 0xf2:
        base += 9000
    return base


def project_charge(case, opcode, host, value_nonzero, remaining, request):
    require(type(remaining) is int and 0 <= remaining < 1 << 64, 'remaining out of range')
    require(type(request) is int and 0 <= request < 1 << 256, 'request out of range')
    cost = price(case, opcode, host, value_nonzero)
    if cost is None:
        return {'status': 0x65}
    if remaining < cost:
        return {'status': 0x50}
    after = remaining - cost
    forwarded = min(request, after - (after >> 6))
    child = min((1 << 64) - 1, forwarded + (2300 if value_nonzero and opcode in (0xf1, 0xf2) else 0))
    return {'status': 0x20, 'cost': cost, 'forwarded': forwarded,
            'parent_remaining': after - forwarded, 'child_gas': child}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    contents = collect(load_authenticated())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(contents.items()):
        (args.out / name).write_text(text, encoding='ascii', newline='\n')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        print('re21_callframe_forks94:', exc, file=sys.stderr)
        raise SystemExit(1)
