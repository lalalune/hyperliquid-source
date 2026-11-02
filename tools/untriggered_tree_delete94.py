#!/usr/bin/env python3
"""Recover node 94's per-user untriggered-order tree deletion evidence.

The input is read only.  FDEs, ELF sections and the unwind index use the
repository's parsers; selected x86 instructions use explicit byte signatures.
This is a bounded static analysis, not an x86 decoder or target execution.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are entry selectors.  Neither a selector nor an unwind entry alone
# establishes an original source function boundary or component ownership.
FAMILIES = {
    'remove': (0x49454a0, 0x2866870, 0x28660a0),
    'cursor': (0x42b66c0, 0x1b22a90),
    'delete_leaf': (0x429f690, 0x1b17160),
    'rotate_from_left': (0x42788d0, 0x1af72d0),
    'rotate_from_right': (0x427ecd0, 0x1afcfe0),
}

# Each item names the start of one four-byte PC-relative operand relative to
# the selected FDE start and the exact opcode bytes immediately preceding it.
# No conditional branch, structure offset or immediate is masked.
MASKS = {
    'remove': (
        (0xc3, 'e8'), (0x1ce, 'ff15'), (0x32a, '488d3d'),
        (0x330, 'ff15'), (0x339, '488d3d'), (0x340, '488d15'),
        (0x34b, 'ff15'), (0x367, 'ff15'), (0x36f, 'e8'),
    ),
    'cursor': (
        (0x126, 'e8'), (0x143, 'ff15'), (0x1ad, '4c8b2d'),
        (0x22f, 'e8'), (0x2a8, 'ff15'),
    ),
    'delete_leaf': (
        (0x5f, '488b2d'), (0x288, '488b05'), (0x2c2, 'ff15'),
        (0x2e7, 'ff15'), (0x307, 'ff15'), (0x32c, '488b1d'),
        (0x37c, 'ff15'), (0x49b, 'ff15'), (0x556, 'ff15'),
        (0x602, '488d15'), (0x60e, '488d3d'), (0x625, 'e8'),
        (0x645, 'e8'), (0x767, 'ff15'), (0x906, '488b05'),
        (0x938, '488b05'), (0x95f, 'ff15'), (0x97b, '4c8b25'),
        (0x9a3, '4c8b35'), (0xaff, 'ff15'), (0xc16, 'e8'),
        (0xc30, 'e8'), (0xc3c, '488d3d'), (0xc43, '488d15'),
        (0xc4e, 'ff15'), (0xc57, '488d3d'), (0xc5e, '488d15'),
        (0xc69, 'ff15'), (0xc72, '488d15'), (0xc7e, '488d3d'),
        (0xc84, 'ff15'), (0xca4, 'ff15'), (0xcac, 'e8'),
    ),
    'rotate_from_left': (
        (0x7c, 'ff15'), (0xa9, 'ff15'), (0xd8, '4c8b2d'),
        (0x1e9, 'ff15'), (0x20a, 'ff15'), (0x23a, '488d3d'),
        (0x241, '488d15'), (0x24c, 'ff15'), (0x2ff, '488d3d'),
        (0x306, '488d15'), (0x311, 'ff15'), (0x318, '488d3d'),
        (0x31f, '488d15'), (0x32a, 'ff15'), (0x331, '488d3d'),
        (0x338, '488d15'), (0x343, 'ff15'),
    ),
    'rotate_from_right': (
        (0x8f, '488b2d'), (0x181, '488b2d'), (0x1f6, 'ff15'),
        (0x211, 'ff15'), (0x2c5, '488d3d'), (0x2cc, '488d15'),
        (0x2d7, 'ff15'), (0x38f, '488d3d'), (0x396, '488d15'),
        (0x3a1, 'ff15'), (0x3a8, '488d3d'), (0x3af, '488d15'),
        (0x3ba, 'ff15'),
    ),
}

# Windows are fixed observations, selected after manual instruction-boundary
# inspection. They are not a complete disassembly of any FDE.
WINDOWS = (
    ('caller_perp', 0x42f8912, '4c8db3b8000000418b4710898424d0000000410f10070f298424c0000000488db424c00000004c89f7e840b02a00488d7038488dbc24d0040000488d9424b0000000e847cb6400'),
    ('caller_spot_a', 0x26de562, '4c8db3b8000000418b4710898424d0000000410f10070f298424c0000000488db424c00000004c89f7e8b094ecff488d7038488dbc24d0040000488d9424b0000000e8c7821800'),
    ('caller_spot_b', 0x26df5b2, '498dbeb8000000418b442410898424d0000000f3410f6f0424660f7f8424c0000000488db424c000000048897c2438e84a81ecff488d7038488dbc24e0040000488d9424b0000000e8a16a1800'),
    ('search_prologue', 0x49454b4, '488b0641bd020000004885c00f84e9020000'),
    ('search_keys', 0x49454d0, '0fb7b84a0800004189f841c1e00348c7c6ffffffff66662e0f1f8400000000004d85c0742b483b54f010410f97c14180d90048ffc64983c0f84180f90174e1410fb6f985ff7420eb0a0f1f80000000004889fe4883e9010f8282020000488b84f050080000eb99'),
    ('found_call', 0x4945537, '488944241048894c241848897424204c89742428c644240f00488dbc2490000000488d742410488d54240fe8591197ff'),
    ('length_and_root', 0x4945619, '49ff4e10488b84244801000048898424e0010000807c240f01753e498b3e4885ff0f8487010000498b46084885c00f8489010000488b8f5008000049890e48ffc84989460848c70100000000beb008000031d2ff159e89e200'),
    ('returned_tag', 0x4945713, '4883fd020f8492000000'),
    ('root_failure', 0x49457c7, '488d3d3ae7de00ff159c8ce200eb19488d3d5b8adafb488d15b46cdd00be21000000ff151989e2000f0b'),
    ('cursor_route', 0x42b66d4, '488b06488b7e08488b4e104885ff0f84eb010000488b8cc8500800004889f848ffc80f84c2000000'),
    ('cursor_predecessor', 0x42b67be, '0fb7814a08000048ffc848894c242048c7442428000000004889442430488d7c2438488d742420e8a68efeff4c8b6c2438488d742440488dbc2410010000bab8000000ff15d9774b01'),
    ('cursor_swap', 0x42b6848, '4969c4b80000004d8d34074983c6604b8b44e708488904244f896ce708488d7c24384c8b2d6f774b01bab80000004c89f641ffd5488db42410010000bab80000004c89f741ffd5'),
    ('cursor_leaf', 0x42b68d3, '488944240848c74424100000000048894c2418488d7424084889dfe89d8dfeffe98d000000'),
    ('leaf_key_shift', 0x429f6b1, '4c8b264c8b7e10450fb7ac244a0800004b8d7cfc084b8b44fc0848898424800000004b8d34fc4883c6104d89fe49f7d64d01ee4a8d14f500000000488b2dede94c01ffd54c897c24484969c7b8000000498d3c044883c760'),
    ('leaf_value_shift_and_threshold', 0x429f7d2, '498d34044881c6180100004969d6b80000004d89e6ffd5418d7dff664189bc244a080000488b43086683ff0448894424680f87f20400004d8b264d85e40f84e6040000'),
    ('leaf_sibling_left', 0x429f87a, '0fb7a94a0800004101ed4183fd0c0f8319040000'),
    ('leaf_merge_bound', 0x429f8b6, '0fb7cf48894c24184801e948ffc14883f90c0f83310a0000'),
    ('leaf_sibling_right', 0x429fc5d, '0fb78b4a0800004101cd4183fd0c735a'),
    ('leaf_child_parent_repair', 0x429fa40, '488d4301498bb4dc500800004c892666899e480800004889c3'),
    ('leaf_parent_continue', 0x429fce0, '4885ed74110fb7854a0800006683f8040f86e60000004c8b7c2438'),
    ('leaf_flag', 0x42a026d, '4885c00f8580faffff488b442478c60001e973faffff'),
    ('leaf_rotate', 0x42a0295, 'be050000004829c6488dbc2400010000e82686fdffe947faffffbe050000004829c6488dbc2438010000e80ceafdffe92dfaffff'),
    ('leaf_failure', 0x42a02c9, '488d3d89df44fc488d15d9c14701be28000000ff1526de4c01eb34488d3d10df44fc488d158ec14701be7b000000ff159bdd4c01eb19488d15cac24701be2a000000488d3d35e144fcff15f0dd4c010f0b'),
)

# Address and exact encoding precede each integer field. These are evidence
# selectors; all recorded values are unpacked from the input ELF.
CONSTANTS = (
    ('book_user_states_offset', 0x42f8912, '4c8db3', 4),
    ('user_untriggered_tree_offset', 0x42f8940, '488d70', 1),
    ('tree_height_offset', 0x49454c9, '488b4e', 1),
    ('tree_count_offset', 0x4945619, '49ff4e', 1),
    ('node_key_base_offset', 0x429f6c1, '4b8d7cfc', 1),
    ('node_value_stride', 0x429f6fa, '4969c7', 4),
    ('node_value_base_offset', 0x429f705, '4883c7', 1),
    ('node_parent_index_offset', 0x429f81e, '410fb7b6', 4),
    ('node_count_offset', 0x429f6b8, '450fb7ac24', 4),
    ('node_edge_base_offset', 0x42b66e8, '488b8cc8', 4),
    ('result_missing_tag', 0x49454b7, '41bd', 4),
    ('wrapper_tag_compare', 0x4945713, '4883fd', 1),
    ('caller_tag_compare', 0x42f8959, '83bc24d0040000', 1),
    ('leaf_small_count_limit', 0x429f7fa, '6683ff', 1),
    ('merge_exclusive_limit', 0x429f8c4, '4883f9', 1),
    ('repair_desired_count', 0x42a0295, 'be', 4),
    ('root_deallocation_size', 0x4945665, 'be', 4),
)

# Relative branch sites are reviewed instruction starts. Their destinations
# are decoded directly, not from external disassembler text. Descriptions
# describe machine conditions only; product labels are kept in the README.
BRANCHES = {
    'remove': (
        ('null_root', 0x49454c0, 'je'),
        ('node_scan_exhausted', 0x49454f3, 'je'),
        ('key_greater_continue', 0x494550d, 'je'),
        ('key_equal', 0x4945515, 'je'),
        ('height_exhausted', 0x4945527, 'jb'),
        ('root_flag_not_one', 0x4945632, 'jne'),
        ('collapse_root_null', 0x494563a, 'je'),
        ('collapse_height_zero', 0x4945647, 'je'),
        ('returned_value_tag_two', 0x4945717, 'je'),
    ),
    'cursor': (
        ('leaf_height_zero', 0x42b66e2, 'je'),
        ('internal_height_one', 0x42b66f6, 'je'),
        ('predecessor_walk_short', 0x42b6707, 'je'),
        ('predecessor_walk_unrolled', 0x42b672f, 'jb'),
        ('rebuild_walk_done', 0x42b6892, 'je'),
    ),
    'delete_leaf': (
        ('remaining_above_four', 0x429f803, 'ja'),
        ('no_parent', 0x429f80f, 'je'),
        ('leftmost_child', 0x429f82d, 'je'),
        ('left_combined_at_least_twelve', 0x429f888, 'jae'),
        ('left_track_out_of_bounds', 0x429f8a2, 'ja'),
        ('merged_length_at_least_twelve', 0x429f8c8, 'jae'),
        ('right_combined_at_least_twelve', 0x429fc6b, 'jae'),
        ('first_copy_length_mismatch', 0x429fb09, 'jne'),
        ('first_empty_internal_node', 0x429fc0a, 'je'),
        ('upward_empty_internal_node', 0x429feca, 'je'),
        ('upward_left_transfer_threshold', 0x429fe8d, 'jae'),
        ('upward_right_transfer_threshold', 0x429ff2a, 'jae'),
        ('upward_copy_length_mismatch', 0x42a016d, 'jne'),
        ('parent_absent_after_repair', 0x429fce3, 'je'),
        ('parent_at_most_four', 0x429fcf0, 'jbe'),
        ('reached_root', 0x429fe19, 'je'),
        ('root_nonempty', 0x42a0270, 'jne'),
    ),
    'rotate_from_left': (
        ('destination_at_least_twelve', 0x42788f5, 'jae'),
        ('source_subtraction_borrow', 0x427890f, 'jb'),
        ('rotation_copy_length_mismatch', 0x4278990, 'jne'),
        ('leaf_sides', 0x4278a92, 'je'),
        ('mismatched_side_height', 0x4278a97, 'je'),
        ('both_sides_leaf', 0x4278b01, 'je'),
    ),
    'rotate_from_right': (
        ('destination_at_least_twelve', 0x427ecf5, 'jae'),
        ('source_subtraction_borrow', 0x427ed10, 'jb'),
        ('leaf_sides', 0x427ee84, 'je'),
        ('mismatched_side_height', 0x427ee8d, 'je'),
        ('both_sides_leaf', 0x427ef8c, 'je'),
    ),
}

CALL_SITES = (
    ('book_context_perp', 0x42f8954, 'remove'),
    ('book_context_spot_a', 0x26de5a4, 'remove'),
    ('book_context_spot_b', 0x26df5fa, 'remove'),
    ('remove_to_cursor', 0x4945562, 'cursor'),
    ('spot_remove_to_cursor_a', 0x2866932, 'cursor'),
    ('spot_remove_to_cursor_b', 0x2866162, 'cursor'),
    ('cursor_predecessor_to_leaf', 0x42b67e5, 'delete_leaf'),
    ('cursor_direct_to_leaf', 0x42b68ee, 'delete_leaf'),
    ('spot_cursor_predecessor_to_leaf', 0x1b22bb5, 'delete_leaf'),
    ('spot_cursor_direct_to_leaf', 0x1b22cbe, 'delete_leaf'),
    ('leaf_rotate_left_one', 0x429fcb4, 'rotate_from_left'),
    ('leaf_rotate_right_one', 0x429fcd4, 'rotate_from_right'),
    ('leaf_rotate_left_bulk', 0x42a02a5, 'rotate_from_left'),
    ('leaf_rotate_right_bulk', 0x42a02bf, 'rotate_from_right'),
    ('spot_leaf_rotate_left', 0x1b17784, 'rotate_from_left'),
    ('spot_leaf_rotate_right', 0x1b177a4, 'rotate_from_right'),
    ('spot_leaf_rotate_left_bulk', 0x1b17d75, 'rotate_from_left'),
    ('spot_leaf_rotate_right_bulk', 0x1b17d8f, 'rotate_from_right'),
)

# Each pair binds the LEA of a Location and the LEA of a diagnostic, then
# the instruction loading the diagnostic length. Paths in Location structures
# are reduced to relative suffixes in output; their full bytes are hashed.
DIAGNOSTICS = (
    ('collapse_height_zero', 0x49457dd, 0x49457d6, 0x49457e4),
    ('tracked_edge_outside_length', 0x429fc8f, 0x429fc9b, 0x429fc96),
    ('copy_lengths_differ', 0x42a02d0, 0x42a02c9, 0x42a02d7),
    ('merged_left_capacity', 0x42a02ff, 0x42a030b, 0x42a0306),
    ('left_rotation_height_mismatch', 0x4278b0e, 0x4278b07, 0x4278b15),
    ('right_rotation_height_mismatch', 0x427ef99, 0x427ef92, 0x427efa0),
    ('left_rotation_capacity', 0x4278bd3, 0x4278bcc, 0x4278bda),
    ('left_rotation_source', 0x4278bec, 0x4278be5, 0x4278bf3),
    ('right_rotation_capacity', 0x427f063, 0x427f05c, 0x427f06a),
    ('right_rotation_source', 0x427f07c, 0x427f075, 0x427f083),
)

WINDOWS += (
    ('rotate_left_guards', 0x42788e1, '4c8b7f28450fb7af4a0800004a8d042e4883f80c0f83d10200004989f4488b5f180fb7ab4a0800004989ee4929f60f82d002000048897c2450664489b34a0800004889442428664189874a080000'),
    ('rotate_left_parent_swap', 0x42789e4, '4a8b44f30848894424304969c6b8000000488d34034883c660488d7c2458bab800000041ffd44d89e64c8b642450498b0424498b4c24104869d1b8000000488d2c104883c560488b54c8084889542438488b542430488954c808488dbc2410010000bab80000004889ee41ffd6bab80000004889ef488d74245841ffd6488b6c2440488b442438498904ef4c036c2408bab80000004c89ef488db4241001000041ffd6'),
    ('rotate_left_edges', 0x4278aa0, '498d3cef4881c750080000488b5424184883c2084c89f6ff1523564f01488b442410488d34c34881c650080000488d14ed000000004c89f7ff1502554f01'),
    ('rotate_left_failure', 0x4278bcc, '488d3d325747fc488d154e394a01be33000000ff1523554f01488d3d4c5747fc488d154d394a01be27000000ff150a554f01488d3d545647fc488d15a4384a01be28000000ff15f1544f01'),
    ('rotate_right_guards', 0x427ece1, '4c8b7718450fb7a64a0800004a8d04264883f80c0f83610300004989f54889fb4c8b7f28410fb78f4a0800004829f10f825f030000664189864a0800006641898f4a080000'),
    ('rotate_right_parent_swap', 0x427ed72, '488b03488b4b104869d1b8000000488d2c104883c56048895c24304c89eb488b54c80848891424488b542408488954c808488dbc24f0000000bab80000004889ee4d89c541ffd0bab80000004889ef488d74243841ffd5488b04244b8944e6084969ecb8000000498d3c2e4883c760bab8000000488db424f000000041ffd5'),
    ('rotate_right_edges', 0x427eea1, '4d8db750080000488b2c24488dbcc550080000488b5c2410488d14dd000000004c89f6ff1516f14e01498d34df4881c6500800004983c4084c89f74c89e2ff15fbf14e014a8b84ed58080000488928488b4c241866898848080000'),
    ('rotate_right_failure', 0x427f05c, '488d3dfcf246fc488d1506d54901be32000000ff1593f04e01488d3d15f346fc488d1505d54901be28000000ff157af04e01'),
)


WINDOWS += (
    ('caller_result_tag_width', 0x42f8959, '83bc24d00400000248895c24200f85a4000000'),
)


WINDOWS += (
    ('left_rotation_copy_guard', 0x427897d, '4d8d66014c29e54c896c2440498d45ff4839c50f8568020000'),
    ('leaf_copy_guard_a', 0x429fb03, '4829e84939c40f85ba070000'),
    ('leaf_empty_internal_a', 0x429fc00, '664183bc244a080000000f84d4060000'),
    ('leaf_empty_internal_b', 0x429fec0, '0fb7954a0800006685d20f8414040000'),
    ('leaf_upward_left_guard', 0x429fe7d, '410fb7b74a0800008d1430ffc283fa0c0f8302040000'),
    ('leaf_upward_right_guard', 0x429ff17, '410fb7b84a080000488d343848ffc64883fe0c0f837f030000'),
    ('leaf_copy_guard_b', 0x42a0165, '482b4424184839c20f8556010000'),
)


WINDOWS += (
    ('left_rotation_late_height_check', 0x4278a87, '49837c242000498b442430746a4885c0746e'),
    ('right_rotation_late_height_check', 0x427ee76, '488b4424304883782000488b40300f84ff0000004885c00f84ff000000'),
)


def authenticate(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET_SHA256:
        raise ValueError('node 94 SHA-256 mismatch')
    return digest


def va_offset(secs, address: int, length: int, executable: bool = False) -> int:
    """Map exactly one allocated, file-backed section; NOBITS has no bytes."""
    if address < 0 or length <= 0:
        raise ValueError('invalid VA range')
    candidates = [s for s in secs if s['type'] != 8 and s['flags'] & 2
                  and (not executable or s['flags'] & 4)
                  and s['address'] <= address
                  and address + length <= s['address'] + s['size']]
    if len(candidates) != 1:
        raise ValueError('VA range is not uniquely file-backed')
    s = candidates[0]
    return s['offset'] + address - s['address']


def read_va(data, secs, address, length, executable=False):
    offset = va_offset(secs, address, length, executable)
    result = data[offset:offset + length]
    if len(result) != length:
        raise ValueError('truncated file-backed range')
    return bytes(result)


def expect_bytes(data, secs, address, expected, executable=True):
    expected = bytes.fromhex(expected) if isinstance(expected, str) else bytes(expected)
    actual = read_va(data, secs, address, len(expected), executable)
    if actual != expected:
        raise ValueError(f'byte signature mismatch at {address:#x}')
    return actual


def decode_rel32(raw, site):
    if len(raw) != 5 or raw[0] != 0xe8:
        raise ValueError('expected direct x86 rel32 call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def decode_lea(data, secs, site):
    raw = read_va(data, secs, site, 7, True)
    if raw[:2] != b'\x48\x8d' or raw[2] & 0xc7 != 0x05:
        raise ValueError('expected RIP-relative lea')
    return site + 7 + struct.unpack_from('<i', raw, 3)[0]


CONDS = {0x72: 'jb', 0x73: 'jae', 0x74: 'je', 0x75: 'jne',
         0x76: 'jbe', 0x77: 'ja'}


def decode_branch(raw, site):
    """Decode only conditional branch forms used at manually selected sites."""
    if len(raw) >= 2 and raw[0] in CONDS:
        return CONDS[raw[0]], site + 2, site + 2 + struct.unpack_from('<b', raw, 1)[0], raw[:2]
    if len(raw) >= 6 and raw[0] == 0x0f and raw[1] - 0x10 in CONDS:
        return CONDS[raw[1] - 0x10], site + 6, site + 6 + struct.unpack_from('<i', raw, 2)[0], raw[:6]
    raise ValueError('unsupported conditional branch encoding')


def normalize(body, masks):
    result = bytearray(body)
    covered = set()
    for offset, prefix_hex in masks:
        prefix = bytes.fromhex(prefix_hex)
        if offset < len(prefix) or offset + 4 > len(body):
            raise ValueError('PC-relative mask outside function')
        if body[offset - len(prefix):offset] != prefix:
            raise ValueError('PC-relative operand opcode mismatch')
        positions = set(range(offset, offset + 4))
        if covered & positions:
            raise ValueError('overlapping PC-relative operands')
        covered.update(positions)
        result[offset:offset + 4] = b'\0' * 4
    return bytes(result)


def leaf_shift_lengths(count, index, value_stride):
    """Checked arithmetic for valid leaf fixtures, not a model of corruption."""
    if not (0 < count <= 0xffff and 0 <= index < count and value_stride > 0):
        raise ValueError('invalid leaf fixture')
    following = count - index - 1
    return following * 8, following * value_stride


def tsv(columns, rows):
    output = io.StringIO(newline='')
    writer = csv.writer(output, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    writer.writerows(rows)
    return output.getvalue().encode('utf-8')


def named_section(secs, name):
    selected = [s for s in secs if s['name'] == name and s['type'] != 8]
    if len(selected) != 1:
        raise ValueError(f'expected one file-backed section {name}')
    return selected[0]


def relocation_records(data, secs, sought):
    rel = named_section(secs, '.rela.dyn')
    if rel['type'] != 4 or rel['size'] % 24:
        raise ValueError('unsupported ELF64 relocation table')
    result = {}
    for pos in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot in sought:
            if slot in result:
                raise ValueError('duplicate relocation at selected slot')
            result[slot] = (info & 0xffffffff, info >> 32, addend)
    if set(result) != set(sought):
        raise ValueError('missing selected relocation')
    return result


def symbol_name(data, secs, index):
    symbols = named_section(secs, '.dynsym')
    strings = named_section(secs, '.dynstr')
    if symbols['type'] != 11 or strings['type'] != 3 or symbols['size'] % 24:
        raise ValueError('unsupported dynamic symbol table')
    if index >= symbols['size'] // 24:
        raise ValueError('dynamic symbol index outside table')
    name_offset = struct.unpack_from('<I', data, symbols['offset'] + index * 24)[0]
    if name_offset >= strings['size']:
        raise ValueError('dynamic symbol name outside table')
    pos = strings['offset'] + name_offset
    end = data.find(b'\0', pos, strings['offset'] + strings['size'])
    if end < 0:
        raise ValueError('unterminated dynamic symbol name')
    return bytes(data[pos:end]).decode('ascii')


def input_fdes(data):
    secs, index = unwind_index(data)
    _, records = eh_frame_records(data, secs)
    selected = {entry for entries in FAMILIES.values() for entry in entries}
    by_start = {}
    for record in records:
        if record['start'] in selected:
            if record['start'] in by_start:
                raise ValueError('ambiguous FDE start')
            by_start[record['start']] = record
    if set(by_start) != selected:
        raise ValueError('selected start has no FDE')
    index_by_start = {row['start']: row for row in index if row['start'] in selected}
    if set(index_by_start) != selected:
        raise ValueError('selected start is not in unwind index')
    for start, fde in by_start.items():
        if fde['fde'] != index_by_start[start]['fde'] or fde['end'] <= start:
            raise ValueError('FDE and unwind index disagree')
        va_offset(secs, start, fde['end'] - start, True)
    return secs, by_start


def make_outputs(data):
    digest = authenticate(data)
    secs, by_start = input_fdes(data)
    window_rows = []
    for name, start, signature in WINDOWS:
        raw = expect_bytes(data, secs, start, signature)
        window_rows.append((name, hex(start), hex(start + len(raw)),
                            hex(va_offset(secs, start, len(raw), True)), raw.hex(),
                            hashlib.sha256(raw).hexdigest()))

    constant_rows = []
    constant_values = {}
    for name, insn, prefix_hex, width in CONSTANTS:
        prefix = bytes.fromhex(prefix_hex)
        expect_bytes(data, secs, insn, prefix)
        raw = read_va(data, secs, insn + len(prefix), width, True)
        value = int.from_bytes(raw, 'little')
        constant_values[name] = value
        constant_rows.append((name, hex(insn), hex(insn + len(prefix)), width,
                              prefix.hex() + raw.hex(), value, hex(value)))

    # The SIB scale is encoded in the key address instruction, not stored as
    # a literal byte. Its opcode and all other bytes are separately pinned.
    key_address_insn = read_va(data, secs, 0x429f6c1, 5, True)
    if key_address_insn[:3] != bytes.fromhex('4b8d7c'):
        raise ValueError('unexpected key-address instruction')
    key_stride = 1 << (key_address_insn[3] >> 6)
    constant_values['node_key_stride'] = key_stride
    constant_rows.append(('node_key_stride', hex(0x429f6c1), hex(0x429f6c4), 1,
                          key_address_insn.hex(), key_stride, hex(key_stride)))
    edge_address_insn = read_va(data, secs, 0x42b66e8, 8, True)
    if edge_address_insn[:3] != bytes.fromhex('488b8c'):
        raise ValueError('unexpected child-address instruction')
    edge_stride = 1 << (edge_address_insn[3] >> 6)
    constant_values['node_edge_stride'] = edge_stride
    constant_rows.append(('node_edge_stride', hex(0x42b66e8), hex(0x42b66eb), 1,
                          edge_address_insn.hex(), edge_stride, hex(edge_stride)))
    layout_rows = []
    for label, begin, end, stride in (
        ('key_region', constant_values['node_key_base_offset'], constant_values['node_value_base_offset'], key_stride),
        ('value_region', constant_values['node_value_base_offset'], constant_values['node_parent_index_offset'], constant_values['node_value_stride']),
        ('internal_edge_region', constant_values['node_edge_base_offset'], constant_values['root_deallocation_size'], edge_stride),
    ):
        span = end - begin
        if span < 0 or not stride or span % stride:
            raise ValueError('selected layout offsets do not define whole strides')
        layout_rows.append((label, hex(begin), hex(end), stride, span, span // stride))

    # These are arithmetic projections of the selected predicates, not runs of
    # target instructions. Inputs straddle the immediates read from the ELF.
    small = constant_values['leaf_small_count_limit']
    exclusive = constant_values['merge_exclusive_limit']
    tag = constant_values['result_missing_tag']
    if tag != constant_values['wrapper_tag_compare'] or tag != constant_values['caller_tag_compare']:
        raise ValueError('selected tag immediates disagree')
    high_tag = (1 << (4 * 8)) | tag
    near_sibling = exclusive - small - 2
    at_sibling = exclusive - small - 1
    projected = (
        ('remaining_at_limit', small, '>', small, small > small, 'remaining count > small limit'),
        ('remaining_above_limit', small + 1, '>', small, small + 1 > small, 'remaining count > small limit'),
        ('merge_below_limit', small + near_sibling + 1, '>=', exclusive, small + near_sibling + 1 >= exclusive, 'remaining + sibling + separator'),
        ('merge_at_limit', small + at_sibling + 1, '>=', exclusive, small + at_sibling + 1 >= exclusive, 'remaining + sibling + separator'),
        ('rotation_below_limit', small + near_sibling + 1, '>=', exclusive, small + near_sibling + 1 >= exclusive, 'destination + requested count'),
        ('rotation_at_limit', small + at_sibling + 1, '>=', exclusive, small + at_sibling + 1 >= exclusive, 'destination + requested count'),
        ('donor_short_by_one', at_sibling - 1, '<', at_sibling, at_sibling - 1 < at_sibling, 'donor count < requested count'),
        ('donor_exact', at_sibling, '<', at_sibling, at_sibling < at_sibling, 'donor count < requested count'),
        ('wrapper_full_tag_high_bits', high_tag, '==', tag, high_tag == tag, 'wrapper compares full qword'),
        ('caller_low_tag_high_bits', high_tag & ((1 << (4 * 8)) - 1), '==', tag, (high_tag & ((1 << (4 * 8)) - 1)) == tag, 'caller compares low dword'),
    )

    functions, operands, branch_rows, comparisons = [], [], [], []
    for family, starts in FAMILIES.items():
        base = starts[0]
        originals, normalized = [], []
        for start in starts:
            fde = by_start[start]
            size = fde['end'] - start
            body = read_va(data, secs, start, size, True)
            norm = normalize(body, MASKS[family])
            originals.append(body)
            normalized.append(norm)
            for off, prefix_hex in MASKS[family]:
                prefix = bytes.fromhex(prefix_hex)
                target = start + off + 4 + struct.unpack_from('<i', body, off)[0]
                kind = ('call' if prefix == b'\xe8' else
                        'indirect_call_slot' if prefix == b'\xff\x15' else
                        'lea' if prefix[1] == 0x8d else 'rip_load')
                operands.append((family, hex(start), hex(off), hex(start + off - len(prefix)),
                                 kind, prefix.hex(), body[off:off + 4].hex(), hex(target)))
            functions.append((family, hex(start), hex(fde['end']), size,
                              hex(va_offset(secs, start, size, True)), hex(fde['fde']),
                              hex(fde['cie']), '' if fde['lsda'] is None else hex(fde['lsda']),
                              hashlib.sha256(body).hexdigest(), hashlib.sha256(norm).hexdigest()))
            for label, canonical_site, expected_condition in BRANCHES[family]:
                site = start + canonical_site - base
                condition, fallthrough, target, raw = decode_branch(read_va(data, secs, site, 6, True), site)
                if condition != expected_condition or not (start <= target < fde['end']):
                    raise ValueError(f'branch disagrees with selected path at {site:#x}')
                branch_rows.append((family, hex(start), label, hex(site), condition, raw.hex(),
                                    hex(fallthrough), hex(target)))
        if len({len(x) for x in originals}) != 1 or any(x != normalized[0] for x in normalized[1:]):
            raise ValueError(f'copies disagree outside stated operands: {family}')
        for start, original in zip(starts, originals):
            comparisons.append({'family': family, 'entry': hex(start),
                                'reference_entry': hex(base),
                                'raw_different_byte_positions': sum(a != b for a, b in zip(originals[0], original)),
                                'masked_byte_positions': 4 * len(MASKS[family]),
                                'different_positions_outside_mask': sum(a != b for a, b in zip(normalized[0], normalize(original, MASKS[family]))),
                                'raw_sha256': hashlib.sha256(original).hexdigest(),
                                'masked_sha256': hashlib.sha256(normalized[0]).hexdigest()})

    # One call-site continuation is retained as context, without selecting
    # the already studied enclosing FDE as a subject of this packet.
    site = 0x42f8966
    condition, fallthrough, target, raw = decode_branch(read_va(data, secs, site, 6, True), site)
    if condition != 'jne':
        raise ValueError('caller result-tag branch opcode mismatch')
    branch_rows.append(('caller_context', '', 'low_dword_not_two', hex(site), condition,
                        raw.hex(), hex(fallthrough), hex(target)))

    call_rows = []
    for label, site, expected_family in CALL_SITES:
        raw = read_va(data, secs, site, 5, True)
        target = decode_rel32(raw, site)
        if target not in FAMILIES[expected_family]:
            raise ValueError(f'call target outside selected family at {site:#x}')
        call_rows.append((label, hex(site), hex(va_offset(secs, site, 5, True)), raw.hex(),
                          hex(target), expected_family))

    # Two paths use a different calling convention from the plain string
    # diagnostic helper. Keep its argument word raw rather than treating it as
    # a byte length. The same empty-internal handler has two incoming branches.
    failure_rows = []
    for label, branch_site, call_site, location_insn, text_insn, arg_insn in (
        ('null_root_after_collapse', 0x494563a, 0x49457ce, 0x49457c7, None, None),
        ('empty_internal_first', 0x429fc0a, 0x42a02f7, 0x42a02eb, 0x42a02e4, 0x42a02f2),
        ('empty_internal_upward', 0x429feca, 0x42a02f7, 0x42a02eb, 0x42a02e4, 0x42a02f2),
    ):
        condition, _, branch_target, branch_raw = decode_branch(read_va(data, secs, branch_site, 6, True), branch_site)
        handler = location_insn if text_insn is None else text_insn
        if branch_target != handler:
            raise ValueError('failure branch no longer enters its selected handler')
        indirect = read_va(data, secs, call_site, 6, True)
        if indirect[:2] != b'\xff\x15':
            raise ValueError('failure edge does not end in an indirect call')
        slot = call_site + 6 + struct.unpack_from('<i', indirect, 2)[0]
        location = decode_lea(data, secs, location_insn)
        text_address = '' if text_insn is None else hex(decode_lea(data, secs, text_insn))
        argument = ''
        if arg_insn is not None:
            raw = read_va(data, secs, arg_insn, 5, True)
            if raw[0] != 0xbe:
                raise ValueError('failure argument is not mov esi, immediate')
            argument = hex(struct.unpack_from('<I', raw, 1)[0])
        failure_rows.append((label, hex(branch_site), condition, branch_raw.hex(),
                             hex(branch_target), hex(call_site), indirect.hex(), hex(slot),
                             hex(location), text_address, argument))

    locations = [decode_lea(data, secs, loc) for _, loc, _, _ in DIAGNOSTICS]
    failure_locations = sorted({int(row[8], 16) for row in failure_rows})
    got_slots = (0x576dfe0, 0x576e0e0, 0x576e010, 0x576e098, 0x576e108, 0x576e470)
    relocs = relocation_records(data, secs, set(locations) | set(failure_locations) | set(got_slots))
    failure_location_rows = []
    for slot in failure_locations:
        typ, sym, path_addr = relocs[slot]
        if typ != 8 or sym != 0:
            raise ValueError('failure Location path is not R_X86_64_RELATIVE')
        header = read_va(data, secs, slot, 24)
        length, line, col = struct.unpack_from('<QII', header, 8)
        if not 0 < length <= 4096:
            raise ValueError('invalid failure Location path length')
        path = read_va(data, secs, path_addr, length)
        suffix = b'/'.join(path.split(b'/')[-4:]).decode('ascii')
        failure_location_rows.append((hex(slot), hex(path_addr), hashlib.sha256(path).hexdigest(), suffix, line, col))
    diag_rows = []
    for (label, loc_insn, text_insn, len_insn), slot in zip(DIAGNOSTICS, locations):
        typ, sym, path_addr = relocs[slot]
        if typ != 8 or sym != 0:
            raise ValueError('Location path is not R_X86_64_RELATIVE')
        header = read_va(data, secs, slot, 24)
        length, line, col = struct.unpack_from('<QII', header, 8)
        if not 0 < length <= 4096:
            raise ValueError('invalid Location path length')
        path = read_va(data, secs, path_addr, length)
        path_tail = b'/'.join(path.split(b'/')[-4:]).decode('ascii')
        instruction = read_va(data, secs, len_insn, 5, True)
        if instruction[0] != 0xbe:
            raise ValueError('expected mov esi, immediate')
        text_len = struct.unpack_from('<I', instruction, 1)[0]
        if not 0 < text_len <= 4096:
            raise ValueError('invalid diagnostic length')
        text_va = decode_lea(data, secs, text_insn)
        message = read_va(data, secs, text_va, text_len).decode('ascii')
        diag_rows.append((label, hex(slot), hex(path_addr), hashlib.sha256(path).hexdigest(),
                          path_tail, line, col, hex(text_va), text_len,
                          json.dumps(message, ensure_ascii=True)))
    relocation_rows = []
    for slot in got_slots:
        typ, sym, addend = relocs[slot]
        if slot in (0x576dfe0, 0x576e0e0):
            name = symbol_name(data, secs, sym)
            if typ != 6 or name not in ('memcpy', 'memmove'):
                raise ValueError('selected dynamic relocation does not bind the expected symbol')
        else:
            if typ != 8 or sym != 0:
                raise ValueError('selected internal slot is not R_X86_64_RELATIVE')
            name = ''
        relocation_rows.append((hex(slot), typ, sym, name, hex(addend)))

    peers = [row for row in comparisons if row['entry'] != row['reference_entry']]
    pairwise = {
        'selected_peer_pairs': len(peers),
        'raw_equal': sum(row['raw_different_byte_positions'] == 0 for row in peers),
        'masked_only': sum(row['raw_different_byte_positions'] != 0 and row['different_positions_outside_mask'] == 0 for row in peers),
        'unmatched_outside_mask': sum(row['different_positions_outside_mask'] != 0 for row in peers),
    }
    summary = {
        'target_sha256': digest,
        'selected_copy_pair_comparison': pairwise,
        'coordinates': 'linked ELF virtual address; FDE end is exclusive',
        'function_count': len(functions), 'family_count': len(FAMILIES),
        'anchored_window_count': len(window_rows), 'recorded_branch_count': len(branch_rows),
        'recorded_call_count': len(call_rows), 'recorded_diagnostic_count': len(diag_rows),
        'boundary_projection_count': len(projected), 'additional_failure_edge_count': len(failure_rows),
        'layout_projection_count': len(layout_rows),
        'function_comparisons': comparisons,
        'limitations': [
            'FDE ranges describe unwind coverage and do not establish original source boundaries.',
            'The branch and call lists are selected instruction-boundary pins, not complete decoding.',
            'Masking identifies local shapes only; helper targets, data and relocations remain distinct.',
            'No captured target was executed and no reconstruction or whole-ELF equivalence is claimed.',
        ],
    }
    return {
        'functions.tsv': tsv(('family', 'entry_va', 'end_va', 'bytes', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'sha256', 'masked_sha256'), functions),
        'anchors.tsv': tsv(('label', 'start_va', 'end_va', 'file_offset', 'raw_hex', 'sha256'), window_rows),
        'constants.tsv': tsv(('label', 'instruction_va', 'operand_va', 'width', 'instruction_hex', 'value_decimal', 'value_hex'), constant_rows),
        'layout-capacity.tsv': tsv(('label', 'begin_offset', 'end_offset', 'stride', 'span', 'whole_strides'), layout_rows),
        'branches.tsv': tsv(('family', 'entry_va', 'label', 'site_va', 'condition', 'raw_hex', 'fallthrough_va', 'taken_va'), branch_rows),
        'boundary-cases.tsv': tsv(('label', 'left', 'operator', 'right', 'predicate_true', 'expression'), projected),
        'failure-edges.tsv': tsv(('label', 'branch_va', 'condition', 'branch_hex', 'branch_target_va', 'call_va', 'call_hex', 'slot_va', 'location_va', 'text_va', 'argument_word_hex'), failure_rows),
        'failure-locations.tsv': tsv(('location_va', 'path_va', 'path_sha256', 'path_suffix', 'line', 'column'), failure_location_rows),
        'calls.tsv': tsv(('label', 'site_va', 'file_offset', 'raw_hex', 'target_va', 'target_family'), call_rows),
        'masked-operands.tsv': tsv(('family', 'entry_va', 'offset', 'instruction_va', 'kind', 'opcode_hex', 'operand_hex', 'resolved_va'), operands),
        'diagnostics.tsv': tsv(('label', 'location_va', 'path_va', 'path_sha256', 'path_suffix', 'line', 'column', 'message_va', 'message_length', 'message_json'), diag_rows),
        'relocations.tsv': tsv(('slot_va', 'type', 'symbol_index', 'symbol_name', 'addend'), relocation_rows),
        'evidence.json': (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode('utf-8'),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    outputs = make_outputs(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in outputs.items():
        (args.out / name).write_bytes(content)
    print(f'Wrote {len(outputs)} static evidence files.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error, UnicodeError) as exc:
        print(f'untriggered_tree_delete94: {exc}', file=sys.stderr)
        raise SystemExit(1)
