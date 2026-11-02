#!/usr/bin/env python3
"""Static, digest-bound evidence for the user-map copy before a book halt sweep."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Names describe the observed role; they are not recovered symbol names.
FUNCTIONS = (
    ('outer_tree_copy', 0x49a1a00, 0x49a1f40, '76d1d03f9de03d76e87bca9835e7419b1248f02f20888ed2b4a3cf3652211f35'),
    ('user_value_copy', 0x496c1a0, 0x496c2bf, '72c0305ffee79f7f1f4da40374b2f7c2f6c9c1b1b8a5b3697ab0c9af75fa9c41'),
    ('qword_deque_copy', 0x458fba0, 0x45903d5, '88ca4bc119563311f7129d98b3f228a6a15490d60e726cb92eca24798666a23a'),
    ('nested_set_copy', 0x497b9b0, 0x497bcb5, '334b7ff7b77e13cc4d232c2b6edf89f3d3ea12b63ce12efb806e2cbd14f8f1a8'),
    ('nested_map_copy', 0x498a7f0, 0x498b1e6, '64315253e634cefb461f904ec5804c4711f2dc833f9a3b7117a1aa51b4921138'),
    ('user_value_drop', 0x49082e0, 0x490840c, '6c86c0fbd1020c340f200ef4ffe74487bbed40e330980c681e31f5b61c699f0e'),
    ('nested_map_drain', 0x494ecc0, 0x494f06d, '380a8522c883d638e47f6335541c5dad066f2acfcef6c68e754908e5bae7f71e'),
    ('outer_map_drain', 0x494e170, 0x494e531, 'f8529ff8509befb3049ba440d0a419170d742a6b01da6d5a5e7006f711bd0580'),
)

# Context belongs to previously studied callers and is not a new FDE claim.
CONTEXT = (
    ('sweep_a_gate_and_copy', 0x430786e, bytes.fromhex('4883bfc8000000000f84620200004989f64989ff488bb7b80000004885f60f84770200004889d3498b97c0000000488d7c2408e85aa16900')),
    ('sweep_b_gate_and_copy', 0x4307e6e, bytes.fromhex('4883bfc8000000000f84620200004989f64989ff488bb7b80000004885f60f84770200004889d3498b97c0000000488d7c2408e85a9b6900')),
    ('sweep_a_cancel', 0x4307a77, bytes.fromhex('488d04928b948188030000895424300f108481780300000f294424204c89ff488d742420ba010000004c89f14989d841b90c000000e8ffc2ffff')),
    ('sweep_b_cancel', 0x4308077, bytes.fromhex('488d04928b948188030000895424300f108481780300000f294424204c89ff488d742420ba010000004c89f14989d841b90c000000e89fb5ffff')),
    ('sweep_a_copy_result', 0x43078a6, bytes.fromhex('488b4424084c8b6c24184885c00f95c14d85ed0f95c220ca80fa010f85290200004c8b64241031ed6690')),
    ('sweep_b_copy_result', 0x4307ea6, bytes.fromhex('488b4424084c8b6c24184885c00f95c14d85ed0f95c220ca80fa010f85290200004c8b64241031ed6690')),
    ('sweep_b_tree_walk', 0x4307f8e, bytes.fromhex('31c04531e40fb78d560400004939cc0f824bffffff666666662e0f1f840000000000488b8d700300004885c90f845601000048ffc00fb795540400004889cd663b915604000073da4885c00f8491000000488d34d14881c660040000')),
    ('sweep_b_next_and_drop', 0x43080b1, bytes.fromhex('b101b80000000049ffcd0f850ffeffffeb2d666666662e0f1f8400000000004889c74883f8087288e942ffffff48c74424080000000048c744241800000000488d7c2408e8464f6a00')),
    ('sweep_a_next_and_drop', 0x4307ab1, bytes.fromhex('b101b80000000049ffcd0f850ffeffffeb2d666666662e0f1f8400000000004889c74883f8087288e942ffffff48c74424080000000048c744241800000000488d7c2408e846556a00')),
    ('sweep_a_missing_root_failure', 0x4307b09, bytes.fromhex('488d3da8dc4201ff155a694601')),
    ('sweep_b_missing_root_failure', 0x4308109, bytes.fromhex('488d3da8d64201ff155a634601')),
    ('outer_drop_value_context', 0x49ad0c0, bytes.fromhex('488b4c2418488d3c8948c1e7044801c7e80bb2f5ff')),
)

# Selected contiguous body windows; complete FDE bytes remain in functions.tsv.
WITNESSES = (
 ('outer_recursive_entry',0x49a1a14,0x49a1a9a),
 ('outer_internal_key_value',0x49a1af0,0x49a1b2d),
 ('outer_internal_commit',0x49a1bcc,0x49a1c7d),
 ('outer_leaf_allocate',0x49a1ca5,0x49a1cf7),
 ('outer_leaf_value_copy',0x49a1d20,0x49a1dd3),
 ('outer_failures',0x49a1e00,0x49a1e9d),
 ('value_three_components',0x496c1ad,0x496c222),
 ('value_result_fields',0x496c222,0x496c268),
 ('value_failures_cleanup',0x496c268,0x496c2bf),
 ('deque_allocation',0x458fbae,0x458fc38),
 ('deque_wrap_split',0x458fc38,0x458fc7f),
 ('deque_result',0x4590358,0x459038e),
 ('set_recursive_allocation',0x497b9c1,0x497ba30),
 ('set_leaf_copy',0x497bb3f,0x497bba7),
 ('set_failures_cleanup',0x497bbe2,0x497bcb5),
 ('map_recursive_allocation',0x498a807,0x498a883),
 ('map_value_vector_copy',0x498a8b4,0x498a997),
 ('map_internal_commit',0x498ab32,0x498abc6),
 ('map_failures_cleanup',0x498b048,0x498b1e6),
 ('value_drop_key_tree_queue',0x49082ec,0x490830d),
 ('value_drop_map_setup',0x490830d,0x490836b),
 ('value_drop_nested_values',0x490836b,0x49083cd),
 ('value_drop_unwind',0x49083d7,0x490840c),
 ('outer_drain_entry',0x494e170,0x494e1a6),
 ('outer_drain_release_chain',0x494e2b9,0x494e329),
 ('outer_drain_exit_failure',0x494e4c1,0x494e531),
 ('nested_drain_entry',0x494ecc0,0x494ecf6),
 ('nested_drain_release_chain',0x494ee3d,0x494ee75),
 ('nested_drain_exit_failure',0x494f003,0x494f06d),
)

# Selected, manually instruction-boundary-reviewed transfers. This is not a CFG census.
BRANCHES = (
 ('a_empty_count',0x4307876,0x4307ade),('a_missing_root',0x430788c,0x4307b09),
 ('b_empty_count',0x4307e76,0x43080de),('b_missing_root',0x4307e8c,0x4308109),
 ('outer_leaf',0x49a1a1c,0x49a1ca5),('outer_child_null',0x49a1a41,0x49a1e5d),
 ('outer_internal_alloc_null',0x49a1a5a,0x49a1e6c),('outer_height_wrap',0x49a1a84,0x49a1e7e),
 ('outer_empty_internal',0x49a1ab0,0x49a1c87),('outer_existing_child',0x49a1b8c,0x49a1bb8),
 ('outer_leaf_alloc_null',0x49a1b9c,0x49a1e4b),('outer_height_mismatch',0x49a1bbd,0x49a1e00),
 ('outer_internal_full',0x49a1bd0,0x49a1e15),('outer_internal_more',0x49a1c77,0x49a1af0),
 ('outer_leaf_alloc_null_2',0x49a1cb3,0x49a1e8d),('outer_empty_leaf',0x49a1cf1,0x49a1dd5),
 ('outer_leaf_full',0x49a1d45,0x49a1e30),('outer_leaf_more',0x49a1dcd,0x49a1d20),
 ('value_empty_set',0x496c1b2,0x496c1d1),('value_missing_set_root',0x496c1bb,0x496c268),
 ('value_empty_map',0x496c1f5,0x496c210),('value_missing_map_root',0x496c1fe,0x496c275),
 ('value_unwind_deque_empty',0x496c294,0x496c2a7),
 ('queue_size_valid',0x458fbd6,0x458fbe3),('queue_empty_allocation',0x458fbe6,0x458fc13),
 ('queue_allocation_succeeds',0x458fc03,0x458fc1a),('queue_empty_input',0x458fc36,0x458fc61),
 ('queue_wrap_choice',0x458fc5a,0x458fc6d),('queue_room',0x458fc8b,0x458fd26),
 ('queue_cleanup_empty',0x45903b5,0x45903cd),
 ('set_leaf',0x497b9c9,0x497bb3f),('set_child_null',0x497b9e8,0x497bc2a),
 ('set_internal_alloc_null',0x497ba01,0x497bc39),('set_height_wrap',0x497ba21,0x497bc4b),
 ('set_internal_empty',0x497ba43,0x497bb20),('set_fresh_leaf',0x497ba89,0x497baa0),
 ('set_heights_equal',0x497ba95,0x497bad3),('set_leaf_alloc_null',0x497baae,0x497bc18),
 ('set_internal_full',0x497badd,0x497bbe2),('set_leaf_empty',0x497bb76,0x497bba9),
 ('set_leaf_full',0x497bb88,0x497bbfd),
 ('nested_leaf',0x498a80a,0x498acf5),('nested_child_null',0x498a832,0x498b048),
 ('nested_internal_alloc_null',0x498a84b,0x498b05a),('nested_height_wrap',0x498a871,0x498b06f),
 ('nested_empty_internal',0x498a896,0x498acd6),('nested_size_invalid',0x498a904,0x498b0fd),
 ('nested_empty_payload',0x498a952,0x498a97b),('nested_payload_alloc_null',0x498a963,0x498b0f8),
 ('nested_flag_not_one',0x498a99c,0x498a9b3),('nested_tag_not_one',0x498aa09,0x498aa34),
 ('nested_fresh_leaf',0x498aacf,0x498aae8),('nested_heights_equal',0x498aae1,0x498ab32),
 ('nested_leaf_alloc_null',0x498ab01,0x498b0e6),('nested_internal_full',0x498ab3d,0x498b096),
 ('nested_leaf_alloc_null_2',0x498ad03,0x498b0bb),('nested_empty_leaf',0x498ad40,0x498b015),
 ('nested_leaf_size_invalid',0x498ad8b,0x498b117),('nested_leaf_payload_empty',0x498add7,0x498ae02),
 ('nested_leaf_payload_null',0x498aded,0x498b10d),('nested_leaf_full',0x498aee9,0x498b0cb),
 ('drop_deque_empty',0x49082fb,0x490830d),('drop_map_empty',0x4908314,0x490834b),
 ('drop_map_end_first',0x4908372,0x49083cd),('drop_map_end_next',0x49083a2,0x49083cd),
 ('drop_payload_empty',0x49083b8,0x4908390),('drop_unwind_deque_empty',0x49083e0,0x49083f2),
 ('outer_drain_empty',0x494e185,0x494e2b9),('outer_drain_bad_state',0x494e195,0x494e522),
 ('outer_drain_cursor',0x494e1a0,0x494e23f),('outer_drain_node_end',0x494e255,0x494e32e),
 ('outer_drain_leaf',0x494e264,0x494e39c),('outer_drain_finished',0x494e2cf,0x494e4e3),
 ('outer_drain_no_cursor',0x494e2d8,0x494e412),('outer_drain_root_parent',0x494e2eb,0x494e4c1),
 ('outer_drain_missing_parent',0x494e35a,0x494e4fa),('outer_drain_continue_up',0x494e4bb,0x494e2f1),
 ('map_drain_empty',0x494ecd5,0x494ee09),('map_drain_bad_state',0x494ece5,0x494f05e),
 ('map_drain_cursor',0x494ecf0,0x494ed8f),('map_drain_node_end',0x494eda5,0x494ee7a),
 ('map_drain_leaf',0x494edb4,0x494eed8),('map_drain_finished',0x494ee1f,0x494f01f),
 ('map_drain_no_cursor',0x494ee28,0x494ef52),('map_drain_root_parent',0x494ee37,0x494effd),
 ('map_drain_missing_parent',0x494ee96,0x494f036),
)

DIRECT = (
 ('sweep_a_copy',0x43078a1,0x49a1a00),('sweep_b_copy',0x4307ea1,0x49a1a00),
 ('sweep_a_user_cancel',0x4307aac,0x4303db0),('sweep_b_user_cancel',0x43080ac,0x4303650),
 ('outer_first_child',0x49a1a35,0x49a1a00),('outer_next_child',0x49a1b28,0x49a1a00),
 ('outer_internal_value',0x49a1b0e,0x496c1a0),('outer_leaf_value',0x49a1d34,0x496c1a0),
 ('value_set',0x496c1ca,0x497b9b0),('value_deque',0x496c1eb,0x458fba0),
 ('value_map',0x496c209,0x498a7f0),('set_first_child',0x497b9dc,0x497b9b0),
 ('set_next_child',0x497ba72,0x497b9b0),('map_first_child',0x498a825,0x498a7f0),
 ('map_next_child',0x498aab7,0x498a7f0),('deque_grow',0x458fca6,0x454f5d0),
 ('value_cleanup_set',0x496c2ac,0x49a9fb0),('outer_cleanup_value_a',0x49a1eb4,0x49082e0),
 ('outer_cleanup_value_b',0x49a1ee1,0x49082e0),('set_cleanup_a',0x497bc90,0x49a9fb0),
 ('set_cleanup_b',0x497bca2,0x49a9fb0),('map_cleanup_a',0x498b1bf,0x49a9ab0),
 ('map_cleanup_b',0x498b1d3,0x49a9ab0),
 ('sweep_a_drop',0x4307af5,0x49ad040),('sweep_b_drop',0x43080f5,0x49ad040),
 ('outer_drop_first',0x49ad0a1,0x494e170),('outer_drop_next',0x49ad0db,0x494e170),
 ('outer_drop_user_value',0x49ad0d0,0x49082e0),('drop_key_tree',0x49082f0,0x49a9fb0),
 ('drop_nested_first',0x4908366,0x494ecc0),('drop_nested_next',0x4908396,0x494ecc0),
 ('drop_unwind_nested_map',0x49083f9,0x49a9ab0),
 ('value_unwind_resume',0x496c2b4,0x5660110),('drop_unwind_resume',0x4908401,0x5660110),
 ('outer_leaf_partial_drop',0x49a1f02,0x4901620),('outer_internal_partial_drop',0x49a1f27,0x4901620),
 ('outer_unwind_resume',0x49a1f2f,0x5660110),
)
INDIRECT = (
 ('outer_internal_alloc',0x49a1a51,0x576dfd8),('outer_leaf_alloc',0x49a1caa,0x576dfd8),
 ('outer_size_failure',0x49a1e55,0x576e020),('outer_invariant_failure',0x49a1e64,0x576e470),
 ('set_internal_alloc',0x497b9f8,0x576dfd8),('set_leaf_alloc',0x497bb44,0x576dfd8),
 ('map_internal_alloc',0x498a842,0x576dfd8),('map_leaf_alloc',0x498acfa,0x576dfd8),
 ('map_payload_alloc',0x498a95a,0x576dfd8),('map_payload_copy',0x498a991,0x576dfe0),
 ('deque_alloc',0x458fbf1,0x576dfd8),('deque_size_failure',0x458fbdd,0x576dfb8),
 ('deque_null_failure',0x458fc0d,0x576dfb8),('deque_unwind_free',0x45903c7,0x576e010),
 ('value_unwind_free',0x496c2a1,0x576e010),
 ('drop_deque_free',0x4908307,0x576e010),('drop_unwind_deque_free',0x49083ec,0x576e010),
 ('outer_drain_root_free',0x494e4dd,0x576e010),('outer_drain_bad_root_free',0x494e50d,0x576e010),
 ('outer_drain_failure',0x494e51a,0x576e470),('nested_drain_root_free',0x494f019,0x576e010),
 ('nested_drain_bad_root_free',0x494f049,0x576e010),('nested_drain_failure',0x494f056,0x576e470),
 ('nested_drain_bad_state',0x494f065,0x576e470),
 ('value_missing_set_failure',0x496c26f,0x576e470),('value_missing_map_failure',0x496c27c,0x576e470),
 ('sweep_a_missing_root_failure',0x4307b10,0x576e470),('sweep_b_missing_root_failure',0x4308110,0x576e470),
)
# Each tuple contains an exact instruction encoding and the byte position and
# size of the encoded immediate/displacement being reported.
FIELDS = (
 ('sweep_count_offset',0x4307e6e,'4883bfc800000000',3,4),
 ('sweep_root_offset',0x4307e82,'488bb7b8000000',3,4),
 ('sweep_height_offset',0x4307e95,'498b97c0000000',3,4),
 ('sweep_reason',0x43080a6,'41b90c000000',2,4),
 ('outer_leaf_bytes',0x49a1ca5,'bf58040000',1,4),
 ('set_first_key',0x497bb8a,'4a8b54ff08',4,1),
 ('set_parent_index',0x497ba2a,'66c743600000',3,1),
 ('map_first_value',0x498a8d0,'4983c460',3,1),
 ('outer_children',0x49a1a25,'488bb658040000',3,4),('outer_internal_bytes',0x49a1a4c,'bfb8040000',1,4),
 ('outer_parent',0x49a1a63,'48c7807003000000000000',3,4),('outer_count',0x49a1a6e,'66c780560400000000',3,4),
 ('outer_parent_index',0x49a1a91,'66c783540400000000',3,4),('outer_keys',0x49a1aca,'488da878030000',3,4),
 ('outer_capacity_bound',0x49a1bcc,'4883f90b',3,1),('outer_value_stride',0x49a1c6c,'4983c650',3,1),
 ('outer_key_stride',0x49a1c70,'4883c514',3,1),('value_set_len',0x496c1ad,'48837e3000',3,1),
 ('value_set_root',0x496c1b4,'498b7620',3,1),('value_set_height',0x496c1c1,'498b5628',3,1),
 ('value_map_len',0x496c1f0,'49837e4800',3,1),('value_map_root',0x496c1f7,'498b7638',3,1),
 ('value_map_height',0x496c200,'498b5640',3,1),('deque_len',0x458fbae,'4c8b7618',3,1),
 ('deque_head',0x458fc3b,'4c8b6610',3,1),('set_children',0x497b9cf,'488b7668',3,1),
 ('set_internal_bytes',0x497b9f3,'bfc8000000',1,4),('set_leaf_bytes',0x497bb3f,'bf68000000',1,4),
 ('set_capacity_bound',0x497bb84,'4883f90b',3,1),('set_count',0x497bb95,'66897062',3,1),
 ('map_children',0x498a813,'498bb550080000',3,4),('map_internal_bytes',0x498a83d,'bfb0080000',1,4),
 ('map_count',0x498a85b,'66c7804a0800000000',3,4),('map_parent_index',0x498a87a,'66c783480800000000',3,4),
 ('map_capacity_bound',0x498ab39,'4883f90b',3,1),('map_leaf_bytes',0x498acf5,'bf50080000',1,4),
 ('map_value_stride',0x498ab57,'4869f1b8000000',3,4),('queue_size_shift',0x458fbbd,'48c1e83d',3,1),
 ('queue_max_bytes',0x458fbc4,'48b9f8ffffffffffff7f',2,8),
 ('map_value_cursor_base',0x498a8d4,'4d8db511010000',3,4),
 ('map_value_payload_len_disp8',0x498a8ea,'498b768f',3,1),
 ('map_value_payload_ptr_disp8',0x498a94b,'498b7687',3,1),
 ('drop_key_tree_offset',0x49082ec,'4883c720',3,1),
 ('drop_queue_pointer_offset',0x49082fd,'488b7b08',3,1),('drop_map_root_offset',0x490830d,'488b4b38',3,1),
 ('drop_map_value_stride',0x49083a4,'48694c2410b8000000',5,4),
 ('drop_payload_capacity_offset',0x49083ad,'488bb40890000000',4,4),
 ('drop_payload_pointer_offset',0x49083ba,'488bbc0898000000',4,4),
 ('nested_drain_remaining',0x494ecce,'488b4640',3,1),
 ('nested_drain_count',0x494ed9b,'0fb78f4a080000',3,4),
 ('nested_drain_leaf_bytes',0x494ee3d,'41bf50080000',2,4),
 ('nested_drain_internal_bytes',0x494ee5a,'beb0080000',1,4),
)


# Known relative addends and one slot without a relative addend.
EXPECTED_SLOTS = {
    0x576dfd8: 0x54c06b0,
    0x576e020: 0x1345e2a,
    0x576e470: 0x157a9f0,
    0x576dfe0: None,
    0x576dfb8: 0x1346068,
    0x576e010: 0x54c8cb0,
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    if digest(data) != SHA256:
        raise ValueError('node 94 SHA-256 mismatch')


def va_offset(secs, va, size=1):
    if va < 0 or size <= 0:
        raise ValueError('invalid address range')
    hits = [s for s in secs if s['type'] != 8 and s['address'] <= va
            and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError('address is not in exactly one file-backed section')
    return hits[0]['offset'] + va - hits[0]['address']


def read_va(data, secs, va, size):
    offset = va_offset(secs, va, size)
    raw = bytes(data[offset:offset + size])
    if len(raw) != size:
        raise ValueError('truncated mapped bytes')
    return raw


def check_exact(data, secs, site, expected):
    actual = read_va(data, secs, site, len(expected))
    if actual != expected:
        raise ValueError('selected instruction bytes changed')
    return actual


def verify_body(data, secs, start, end, expected):
    raw = read_va(data, secs, start, end - start)
    if digest(raw) != expected:
        raise ValueError('FDE body hash mismatch')
    return raw


def branch(raw, site):
    if len(raw) >= 2 and 0x70 <= raw[0] <= 0x7f:
        return 2, site + 2 + struct.unpack_from('<b', raw, 1)[0]
    if len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return 6, site + 6 + struct.unpack_from('<i', raw, 2)[0]
    raise ValueError('unsupported branch encoding')


def checked_branch(raw, site, expected):
    size, target = branch(raw, site)
    if target != expected:
        raise ValueError('branch target changed')
    return size, target


def rel32(raw, site):
    if len(raw) != 5 or raw[0] != 0xe8:
        raise ValueError('expected direct rel32 call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def indirect_slot(raw, site):
    if len(raw) != 6 or raw[:2] != b'\xff\x15':
        raise ValueError('expected RIP-relative indirect call')
    return site + 6 + struct.unpack_from('<i', raw, 2)[0]


def relative_relocations(data, secs):
    out = {}
    for section in secs:
        if section['type'] != 4:
            continue
        if section['size'] % 24:
            raise ValueError('partial ELF64 RELA')
        for off in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if info == 8:
                if slot in out:
                    raise ValueError('duplicate relative relocation')
                out[slot] = addend
    return out


def checked_slot(relocations, slot):
    if slot not in EXPECTED_SLOTS or relocations.get(slot) != EXPECTED_SLOTS[slot]:
        raise ValueError('selected relocation changed')
    return relocations.get(slot)


def decode_lsda(data, secs, fde):
    """Decode only this target's omitted-LPStart, ULEB call-site encoding."""
    table = next((s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8), None)
    va = fde['lsda']
    if table is None or va is None or not table['address'] <= va < table['address'] + table['size']:
        raise ValueError('selected LSDA outside file-backed exception table')
    begin = va_offset(secs, va)
    section_end = table['offset'] + table['size']
    pos = begin
    if pos + 2 > section_end or data[pos] != 0xff or data[pos + 1] not in (0xff, 0x9b):
        raise ValueError('unsupported selected LSDA header')
    type_encoding = data[pos + 1]
    pos += 2
    if type_encoding != 0xff:
        _, pos = uleb(data, pos, section_end)
    if pos >= section_end or data[pos] != 1:
        raise ValueError('unsupported selected LSDA call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, section_end)
    header_end = pos
    table_end = pos + size
    if table_end > section_end:
        raise ValueError('LSDA call-site table outside section')
    rows = []
    prior_end = fde['start']
    while pos < table_end:
        row_start = pos
        values = []
        for _ in range(4):
            value, pos = uleb(data, pos, table_end)
            values.append(value)
        start, length, landing, action = values
        lo = fde['start'] + start
        hi = lo + length
        pad = fde['start'] + landing if landing else None
        if length == 0 or lo < prior_end or hi > fde['end']:
            raise ValueError('invalid LSDA call-site interval')
        if pad is not None and not fde['start'] <= pad < fde['end']:
            raise ValueError('LSDA landing pad outside FDE')
        rows.append((lo, hi, pad, action, bytes(data[row_start:pos]).hex()))
        prior_end = hi
    if pos != table_end:
        raise ValueError('incomplete LSDA call-site table')
    return bytes(data[begin:header_end]).hex(), rows


def collect(data):
    authenticate(data)
    secs = sections(data)
    _, fdes, _ = fde_extents(data)
    indexed = {}
    for row in fdes:
        if row['start'] in indexed:
            raise ValueError('duplicate FDE start')
        indexed[row['start']] = row
    functions = []
    for name, start, end, expected in FUNCTIONS:
        f = indexed.get(start)
        if f is None or f['end'] != end:
            raise ValueError('selected FDE extent mismatch')
        raw = verify_body(data, secs, start, end, expected)
        functions.append((name, hex(start), hex(end), hex(va_offset(secs, start, len(raw))),
                          hex(f['fde']), len(raw), digest(raw), raw.hex()))
    context = []
    for name, start, expected in CONTEXT:
        raw = check_exact(data, secs, start, expected)
        context.append((name, hex(start), hex(start + len(raw)),
                        hex(va_offset(secs, start, len(raw))), digest(raw), raw.hex()))
    witnesses = []
    for name, start, end in WITNESSES:
        if not any(lo <= start < end <= hi for _, lo, hi, _ in FUNCTIONS):
            raise ValueError('witness outside selected FDE')
        raw = read_va(data, secs, start, end - start)
        witnesses.append((name, hex(start), hex(end), digest(raw), raw.hex()))
    branches = []
    for name, site, expected in BRANCHES:
        raw = read_va(data, secs, site, 6)
        size, target = checked_branch(raw, site, expected)
        branches.append((name, hex(site), raw[:size].hex(), hex(site + size), hex(target)))
    calls = []
    for name, site, expected in DIRECT:
        raw = read_va(data, secs, site, 5)
        target = rel32(raw, site)
        if target != expected:
            raise ValueError('direct call target changed')
        calls.append((name, hex(site), raw.hex(), hex(target)))
    relocs = relative_relocations(data, secs)
    slots = []
    for name, site, expected in INDIRECT:
        raw = read_va(data, secs, site, 6)
        slot = indirect_slot(raw, site)
        if slot != expected:
            raise ValueError('indirect call slot changed')
        addend = checked_slot(relocs, slot)
        slots.append((name, hex(site), raw.hex(), hex(slot), '' if addend is None else hex(addend)))
    fields = []
    for name, site, pattern, position, size in FIELDS:
        expected = bytes.fromhex(pattern)
        raw = check_exact(data, secs, site, expected)
        if position + size > len(raw):
            raise ValueError('field operand out of instruction')
        value = int.from_bytes(raw[position:position + size], 'little')
        fields.append((name, hex(site), raw.hex(), hex(value)))
    return functions, context, witnesses, branches, calls, slots, fields


def tsv(path, header, rows):
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(data, out):
    functions, context, witnesses, branches, calls, slots, fields = collect(data)
    out.mkdir(parents=True, exist_ok=True)
    tsv(out / 'functions.tsv', ('role','start_va','end_va','file_offset','fde_va','size','sha256','raw_hex'), functions)
    tsv(out / 'context.tsv', ('role','start_va','end_va','file_offset','sha256','raw_hex'), context)
    tsv(out / 'witnesses.tsv', ('role','start_va','end_va','sha256','raw_hex'), witnesses)
    tsv(out / 'branches.tsv', ('role','site_va','bytes','fallthrough_va','taken_va'), branches)
    tsv(out / 'calls.tsv', ('role','site_va','bytes','target_va'), calls)
    tsv(out / 'indirect.tsv', ('role','site_va','bytes','slot_va','relative_addend_va'), slots)
    tsv(out / 'fields.tsv', ('role','site_va','instruction_bytes','encoded_operand'), fields)
    secs = sections(data)
    _, fdes, _ = fde_extents(data)
    by_start = {f['start']: f for f in fdes}
    lsda_rows = []
    for name, start, _, _ in FUNCTIONS:
        fde = by_start[start]
        header, rows = decode_lsda(data, secs, fde)
        for lo, hi, pad, action, raw in rows:
            lsda_rows.append((name, hex(start), hex(fde['lsda']), header, hex(lo), hex(hi),
                              '' if pad is None else hex(pad), action, raw))
    tsv(out / 'lsda.tsv', ('role','fde_start_va','lsda_va','header_bytes','call_start_va',
                           'call_end_va','landing_pad_va','action','row_bytes'), lsda_rows)
    summary = {'target_sha256': SHA256, 'coordinate_system': 'linked ELF virtual addresses',
               'fde_ranges': len(functions), 'caller_context_windows': len(context),
               'body_witness_windows': len(witnesses), 'selected_conditional_branches': len(branches), 'direct_calls': len(calls),
               'indirect_calls': len(slots), 'encoded_operands': len(fields),
               'lsda_tables': len(FUNCTIONS), 'lsda_callsite_rows': len(lsda_rows),
               'scope': 'selected FDEs and context windows only; no target execution or complete CFG census'}
    (out / 'summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(generate(TARGET.read_bytes(), args.out), sort_keys=True))


if __name__ == '__main__':
    main()
