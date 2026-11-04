#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Extract selected node-115 state-root tree serialization evidence from ELF bytes.

The selected input is authenticated before parsing or output.  The observations
are static and deliberately do not execute a captured executable.  The small
encoding model below describes only the explicitly selected normal path.
"""

import argparse
import bisect
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are chosen unwind ranges, not a whole-program function census.  Hashes
# bind all bytes in each range, including bytes outside the selected windows.
FUNCTIONS = (
    ('history_insert_adapter', 0x51f32f0, 0x51f3414, 'a635eaf6225e7e15356533d282117bca92f1cb7899fe414b00ccbdc54ab905ac'),
    ('history_node_insert', 0x4c5f1b0, 0x4c5fda6, '064f76b582e71485454db210e65f8953df362dcb0535657a3bfaaf39403d1c10'),
    ('buffered_array', 0x41771f0, 0x417753c, '8bc2c942eaece201717325f520b927e9d332720ce7f48a681a39dddb0ee4ac2a'),
    ('direct_array', 0x3d50540, 0x3d50663, 'bcd351b7daae75aeb38a0fb2f07249164eca15754d88f8d5afd8756ac4422528'),
    ('buffered_unsigned', 0x3d51450, 0x3d517d5, 'a3e11114e95fb6a85bbe334594156a4d1e0a1b4e9e61dae30ebff98d84fc2d96'),
    ('buffered_string', 0x41c6610, 0x41c6824, '12a2f7238376a185f77e1dff69f6ca4baaf4df4b5accdb48a69dd596d97fc2bd'),
    ('buffered_array_finish', 0x41acd70, 0x41ace9a, '6e27c420705f8b1d0bcea2aaacd37ad1a1f81f79373b49152ce0a1bf789dfde2'),
    ('buffered_pair_finish', 0x41d4150, 0x41d4294, 'f5518c65117b44db07a391a1364b7e8e2b469ca7b3a1de37d4a2b47cf377749e'),
    ('array_writer', 0x41444a0, 0x414471e, 'c9060a3bcbfc8408ac56a6715f5cebaf74f4098461117d0688264ebc47d31eb5'),
    ('pair_writer', 0x41c7780, 0x41c7b27, 'c33f1452fa83e84123eaa077a8cb9cee75e1cabd1030f141fd38f70b883580e1'),
    ('buffered_pair', 0x41b9330, 0x41b94ff, 'de3b2af7e41d804d783d83798b03f8a13763629598f2fa013a0d52f556b21b37'),
    ('index_wrapper', 0x41d2670, 0x41d27ac, '473a18215664fe96d1176edc1895d1b56935476c470427ded50bdc9c6ea526cc'),
    ('unsigned_writer', 0x3d517e0, 0x3d51a52, 'c388d76609d2e06536318df3a5a303cc618d894e4dbc18e047462a42d46dfd83'),
    ('unsigned16', 0x3d51d10, 0x3d51e9d, '7ad839d6212504d3ac065d51f13cd6e9e3ac0c5f44ae16e0268ed5df6c693df9'),
    ('unsigned32', 0x3d51f40, 0x3d520cb, '06f4f222f1e0ca0304df5a331587e2eb875ed422f3cfd3538dd5225ecae54822'),
    ('unsigned64', 0x3d520d0, 0x3d52264, '2758643110bdef1d8ef564972d40ccb29dc38aa2ae2f091424d1d02ba61e733d'),
    ('array_finish', 0x41acea0, 0x41ad05e, '42fcdd29d04dd93b4d97a0081240f3c7e705aa06bd60020f6b6032d798474e42'),
    ('pair_finish', 0x41d3f60, 0x41d4149, 'bf2fe1feb1c9876774407180246837589adc7e5e7bd5eb429429aa899bb67b8f'),
)

# Half-open selected instruction windows.  Context is already owned in earlier
# packets; it is retained only to make the new path's boundary checkable.
WINDOWS = (
    ('context_loader_location', 'context', 0x3c1352f, 0x3c1353f),
    ('context_root_mode', 'context', 0x41c5185, 0x41c51be),
    ('context_root_capacity', 'context', 0x4e3493d, 0x4e34954),
    ('context_capture_reducer', 'context', 0x4e34957, 0x4e3499f),
    ('context_digest_input', 'context', 0x548d8ef, 0x548d910),
    ('context_end_handoff', 'context', 0x5a08826, 0x5a0884a),
    ('context_failed_output', 'context', 0x41c5233, 0x41c5276),
    ('context_root_hash_result', 'context', 0x41c5379, 0x41c53b1),
    ('context_reducer_scan', 'context', 0x141a3b0, 0x141a409),
    ('context_reducer_row_store', 'context', 0x141a6c2, 0x141a702),
    ('context_array_header_choices', 'context', 0x3d5027e, 0x3d50297),
    ('context_array_header_pack', 'context', 0x3d52353, 0x3d5235e),
    ('context_array_header_u16', 'context', 0x3d5037e, 0x3d5038c),
    ('context_string_header', 'context', 0x41c6153, 0x41c6164),
    ('context_hex_prefix', 'context', 0x2eabb59, 0x2eabb67),
    ('context_hex_first', 'context', 0x2eabb67, 0x2eabbbe),
    ('context_hex_loop', 'context', 0x2eabc20, 0x2eabc5c),
    ('context_string_length', 'context', 0x41c61e5, 0x41c6202),
    ('context_string_copy', 'context', 0x41c6429, 0x41c6452),
    ('context_history_wrapper', 'context', 0x5a03fa7, 0x5a03fbd),
    ('context_history_input', 'context', 0x4dd45d1, 0x4dd45e0),
    ('context_history_tree_mode', 'context', 0x4dd472b, 0x4dd473e),
    ('context_history_search', 'context', 0x4dd48d8, 0x4dd495a),
    ('context_history_insert', 'context', 0x4dd4988, 0x4dd49bf),
    ('history_adapter_existing_node', 'history_insert_adapter', 0x51f32fb, 0x51f3351),
    ('history_adapter_allocate', 'history_insert_adapter', 0x51f3351, 0x51f3389),
    ('history_adapter_empty_store', 'history_insert_adapter', 0x51f3389, 0x51f33c5),
    ('history_adapter_result_and_failure', 'history_insert_adapter', 0x51f33c5, 0x51f3414),
    ('history_node_nonfull_choice', 'history_node_insert', 0x4c5f1c1, 0x4c5f1fb),
    ('history_node_shift', 'history_node_insert', 0x4c5f228, 0x4c5f297),
    ('history_node_write', 'history_node_insert', 0x4c5f297, 0x4c5f2cb),
    ('history_node_split_allocation', 'history_node_insert', 0x4c5f2cb, 0x4c5f329),
    ('history_node_split_init', 'history_node_insert', 0x4c5f329, 0x4c5f35e),
    ('history_node_return', 'history_node_insert', 0x4c5fc46, 0x4c5fc66),
    ('history_node_allocation_failure', 'history_node_insert', 0x4c5fcfb, 0x4c5fd0b),
    ('buffered_array_count', 'buffered_array', 0x4177209, 0x4177260),
    ('buffered_array_header', 'buffered_array', 0x4177260, 0x4177286),
    ('buffered_array_loop', 'buffered_array', 0x41772ce, 0x4177305),
    ('buffered_array_finish_call', 'buffered_array', 0x4177305, 0x417733b),
    ('buffered_array_allocation', 'buffered_array', 0x417735a, 0x4177374),
    ('buffered_array_count_guard', 'buffered_array', 0x4177410, 0x417743a),
    ('buffered_array_error', 'buffered_array', 0x4177485, 0x41774e2),
    ('direct_array_marker', 'direct_array', 0x3d50550, 0x3d5057b),
    ('direct_array_lengths', 'direct_array', 0x3d50589, 0x3d505e6),
    ('buffered_unsigned_widths', 'buffered_unsigned', 0x3d51458, 0x3d51540),
    ('buffered_unsigned_cc', 'buffered_unsigned', 0x3d51540, 0x3d51586),
    ('buffered_unsigned_wide', 'buffered_unsigned', 0x3d51586, 0x3d515d3),
    ('buffered_string_marker', 'buffered_string', 0x41c6688, 0x41c66c7),
    ('buffered_string_copy', 'buffered_string', 0x41c66e6, 0x41c6713),
    ('buffered_array_finish_sentinel', 'buffered_array_finish', 0x41acd81, 0x41acdbc),
    ('buffered_array_finish_copy', 'buffered_array_finish', 0x41acdbc, 0x41ace21),
    ('buffered_array_finish_error', 'buffered_array_finish', 0x41ace21, 0x41ace52),
    ('buffered_pair_finish_sentinel', 'buffered_pair_finish', 0x41d4161, 0x41d417a),
    ('buffered_pair_finish_header', 'buffered_pair_finish', 0x41d417a, 0x41d41cf),
    ('buffered_pair_finish_copy', 'buffered_pair_finish', 0x41d41cf, 0x41d4219),
    ('array_count_and_mode', 'array_writer', 0x41444b9, 0x41444fb),
    ('array_header_and_result', 'array_writer', 0x41444fb, 0x414451a),
    ('array_wrapper_init', 'array_writer', 0x414451a, 0x414454c),
    ('array_header_error', 'array_writer', 0x41445c8, 0x41445ec),
    ('array_buffer_allocation', 'array_writer', 0x41445ec, 0x4144600),
    ('array_rows_and_loop', 'array_writer', 0x4144650, 0x41446a5),
    ('array_finish_call', 'array_writer', 0x41446a5, 0x41446d5),
    ('array_allocation_failure', 'array_writer', 0x41446ea, 0x41446fc),
    ('pair_mode_and_header', 'pair_writer', 0x41c77a4, 0x41c781c),
    ('pair_index_dispatch', 'pair_writer', 0x41c7838, 0x41c786b),
    ('pair_nested_branch', 'pair_writer', 0x41c7875, 0x41c78af),
    ('pair_leaf_and_finish', 'pair_writer', 0x41c79f7, 0x41c7a7a),
    ('pair_error_and_cleanup', 'pair_writer', 0x41c7a7a, 0x41c7ad4),
    ('pair_counter_and_unwind', 'pair_writer', 0x41c7ae6, 0x41c7b27),
    ('buffered_pair_header', 'buffered_pair', 0x41b9344, 0x41b93ac),
    ('buffered_pair_variant', 'buffered_pair', 0x41b93ac, 0x41b9405),
    ('buffered_pair_leaf', 'buffered_pair', 0x41b9405, 0x41b947a),
    ('buffered_pair_finish', 'buffered_pair', 0x41b947a, 0x41b94ab),
    ('index_mode_and_header', 'index_wrapper', 0x41d2684, 0x41d26c8),
    ('index_write_and_result', 'index_wrapper', 0x41d2732, 0x41d276c),
    ('unsigned_width_dispatch', 'unsigned_writer', 0x3d517f0, 0x3d51891),
    ('unsigned_cc_marker', 'unsigned_writer', 0x3d51918, 0x3d51939),
    ('unsigned_partial_failure', 'unsigned_writer', 0x3d51938, 0x3d519ba),
    ('unsigned_byte_store', 'unsigned_writer', 0x3d519ba, 0x3d519da),
    ('u16_marker', 'unsigned16', 0x3d51d2a, 0x3d51d3b),
    ('u16_byte_order', 'unsigned16', 0x3d51dc9, 0x3d51de0),
    ('u32_marker', 'unsigned32', 0x3d51f5a, 0x3d51f6b),
    ('u32_byte_order', 'unsigned32', 0x3d51ff9, 0x3d5200e),
    ('u64_marker', 'unsigned64', 0x3d520eb, 0x3d520fc),
    ('u64_byte_order', 'unsigned64', 0x3d5218c, 0x3d521a2),
    ('array_finish_sentinel', 'array_finish', 0x41acebb, 0x41acedc),
    ('array_finish_header', 'array_finish', 0x41acedc, 0x41acf02),
    ('array_finish_error', 'array_finish', 0x41acf1e, 0x41acf60),
    ('array_finish_copy', 'array_finish', 0x41acf7c, 0x41acfb8),
    ('pair_finish_sentinel', 'pair_finish', 0x41d3f7b, 0x41d3f92),
    ('pair_finish_mode', 'pair_finish', 0x41d3f92, 0x41d3ff3),
    ('pair_finish_error', 'pair_finish', 0x41d40b1, 0x41d40d6),
    ('pair_finish_copy', 'pair_finish', 0x41d40e8, 0x41d4126),
)

# Selected transfer sites.  Addresses and targets are checked against the
# encoded signed displacements, not against disassembler text.
TRANSFERS = (
    ('history_null_node', 0x51f3309, 0x51f3351),
    ('history_nonempty_insert', 0x51f3338, 0x4c5f1b0),
    ('history_nonempty_done', 0x51f334f, 0x51f33c5),
    ('history_empty_allocate', 0x51f3359, 0x64df480),
    ('history_empty_allocation_failure', 0x51f3362, 0x51f33eb),
    ('history_empty_count_guard', 0x51f3394, 0x51f33fb),
    ('history_allocation_failure_slot', 0x51f33f5, 0x64df490),
    ('history_count_failure_slot', 0x51f340e, 0x64df730),
    ('history_node_full', 0x4c5f1d9, 0x4c5f1fb),
    ('history_node_shift_required', 0x4c5f1f1, 0x4c5f228),
    ('history_node_append', 0x4c5f1f6, 0x4c5f297),
    ('history_node_move_keys', 0x4c5f256, 0x64df568),
    ('history_node_move_values', 0x4c5f289, 0x64df568),
    ('history_node_return', 0x4c5f2c6, 0x4c5fc46),
    ('history_node_split_position', 0x4c5f20b, 0x4c5f2cb),
    ('history_node_split_allocate', 0x4c5f31a, 0x64df480),
    ('history_node_split_alloc_failed', 0x4c5f323, 0x4c5fcfb),
    ('history_node_split_failure_slot', 0x4c5fd05, 0x64df490),
    ('buffered_array_wide_count', 0x417725a, 0x417735a),
    ('buffered_array_header', 0x4177272, 0x3d50540),
    ('buffered_array_header_failure', 0x4177280, 0x4177340),
    ('buffered_array_loop_selection', 0x41772a0, 0x41772ce),
    ('buffered_array_initial_pair', 0x41772b7, 0x41b9330),
    ('buffered_array_initial_failure', 0x41772c8, 0x41774c6),
    ('buffered_array_empty', 0x41772d4, 0x4177305),
    ('buffered_array_pair', 0x41772e9, 0x41b9330),
    ('buffered_array_pair_failure', 0x41772f6, 0x41774bf),
    ('buffered_array_loop', 0x4177303, 0x41772e0),
    ('buffered_array_finish', 0x4177336, 0x41acd70),
    ('buffered_array_allocate', 0x4177365, 0x64df480),
    ('buffered_array_allocation_failure', 0x417736e, 0x4177506),
    ('buffered_array_deferred_pair', 0x417741b, 0x41b9330),
    ('buffered_array_deferred_failure', 0x4177425, 0x4177460),
    ('buffered_array_count_overflow', 0x417742e, 0x41774f7),
    ('buffered_array_count_failure', 0x41774fe, 0x64df520),
    ('buffered_array_alloc_failure_slot', 0x4177510, 0x64df498),
    ('buffered_array_unwind', 0x4177537, 0x63f0a50),
    ('direct_array_pack', 0x3d5056d, 0x3d52310),
    ('direct_array_u32', 0x3d5058d, 0x3d505b9),
    ('direct_array_fix', 0x3d50598, 0x3d505d7),
    ('direct_array_u16_growth', 0x3d505ac, 0x3d50619),
    ('direct_array_u32_growth', 0x3d505c9, 0x3d5063e),
    ('buffered_uint_small', 0x3d5145f, 0x3d5148f),
    ('buffered_uint_high_bit', 0x3d51463, 0x3d51540),
    ('buffered_uint_byte_growth', 0x3d51470, 0x3d515d3),
    ('buffered_uint_u16', 0x3d51496, 0x3d514e7),
    ('buffered_uint_u16_marker_growth', 0x3d514a2, 0x3d51609),
    ('buffered_uint_u16_payload_growth', 0x3d514c3, 0x3d51642),
    ('buffered_uint_u32', 0x3d514ee, 0x3d51586),
    ('buffered_uint_u32_marker_growth', 0x3d514fe, 0x3d516ef),
    ('buffered_uint_u32_payload_growth', 0x3d5151d, 0x3d51728),
    ('buffered_uint_cc_marker_growth', 0x3d5154a, 0x3d5167c),
    ('buffered_uint_cc_payload_growth', 0x3d51563, 0x3d516b5),
    ('buffered_uint_u64_marker_growth', 0x3d51590, 0x3d51762),
    ('buffered_uint_u64_payload_growth', 0x3d515b0, 0x3d5179b),
    ('buffered_string_short_limit', 0x41c662a, 0x41c6688),
    ('buffered_string_initial_growth', 0x41c6636, 0x41c673e),
    ('buffered_string_pack', 0x41c6645, 0x3d52310),
    ('buffered_string_u8_limit', 0x41c668f, 0x41c6722),
    ('buffered_string_marker_growth', 0x41c669f, 0x41c67d8),
    ('buffered_string_length_growth', 0x41c66b8, 0x41c67ff),
    ('buffered_string_payload_growth', 0x41c66ef, 0x41c6762),
    ('buffered_string_copy', 0x41c66ff, 0x64df508),
    ('buffered_string_grow', 0x41c67ee, 0x43bd910),
    ('buffered_array_finish_fast', 0x41acd94, 0x41ace0b),
    ('buffered_array_finish_header', 0x41acdac, 0x3d50540),
    ('buffered_array_finish_header_failure', 0x41acdba, 0x41ace21),
    ('buffered_array_finish_capacity', 0x41acdd3, 0x41ace52),
    ('buffered_array_finish_copy', 0x41acde9, 0x64df508),
    ('buffered_array_finish_grow', 0x41ace66, 0x43bd910),
    ('buffered_array_finish_unwind', 0x41ace95, 0x63f0a50),
    ('buffered_pair_finish_fast', 0x41d4174, 0x41d4212),
    ('buffered_pair_finish_count', 0x41d418c, 0x41d41a0),
    ('buffered_pair_finish_alt_header', 0x41d41ac, 0x41c5b90),
    ('buffered_pair_finish_header', 0x41d41bf, 0x3d50540),
    ('buffered_pair_finish_header_failure', 0x41d41cd, 0x41d422b),
    ('buffered_pair_finish_capacity', 0x41d41dd, 0x41d4251),
    ('buffered_pair_finish_copy', 0x41d41f1, 0x64df508),
    ('buffered_pair_finish_grow', 0x41d4265, 0x43bd910),
    ('buffered_pair_finish_unwind', 0x41d428f, 0x63f0a50),
    ('array_wide_count', 0x41444f5, 0x41445ec),
    ('array_header', 0x4144506, 0x3d50270),
    ('array_header_failure', 0x4144514, 0x41445c8),
    ('array_regular_loop', 0x414453d, 0x4144650),
    ('array_initial_pair', 0x4144559, 0x41c7780),
    ('array_no_free_sentinel', 0x41445a7, 0x41446d5),
    ('array_no_free_empty', 0x41445b0, 0x41446d5),
    ('array_alloc_failure', 0x41445fa, 0x41446ea),
    ('array_empty', 0x414465e, 0x41446a5),
    ('array_pair', 0x4144689, 0x41c7780),
    ('array_pair_failure', 0x4144696, 0x414457a),
    ('array_loop', 0x41446a3, 0x4144680),
    ('array_finish', 0x41446d0, 0x41acea0),
    ('array_alloc_failure_slot', 0x41446f4, 0x64df498),
    ('pair_buffered', 0x41c77a9, 0x41c77bc),
    ('pair_header_mode', 0x41c77b6, 0x41c77f8),
    ('pair_buffered_body', 0x41c77c7, 0x41b9330),
    ('pair_buffered_error', 0x41c77d5, 0x41c78af),
    ('pair_counter_overflow', 0x41c77e3, 0x41c7ae6),
    ('pair_header', 0x41c7805, 0x3d50270),
    ('pair_header_failure', 0x41c7813, 0x41c78f1),
    ('pair_index', 0x41c784d, 0x41d2670),
    ('pair_index_failure', 0x41c785b, 0x41c78c5),
    ('pair_index_buffered', 0x41c7865, 0x41c7906),
    ('pair_leaf_branch', 0x41c787c, 0x41c79f7),
    ('pair_nested', 0x41c7893, 0x41444a0),
    ('pair_nested_success', 0x41c78a4, 0x41c7a6b),
    ('pair_buffered_hex', 0x41c794d, 0x64e4d08),
    ('pair_buffered_header', 0x41c7966, 0x3d50270),
    ('pair_buffered_header_failure', 0x41c7974, 0x41c7a7a),
    ('pair_buffered_index', 0x41c79b0, 0x3d517e0),
    ('pair_buffered_index_failure', 0x41c79be, 0x41c7a81),
    ('pair_leaf_hex', 0x41c7a37, 0x64e4d08),
    ('pair_leaf_string', 0x41c7a45, 0x41c6110),
    ('pair_leaf_string_success', 0x41c7a4e, 0x41c7a5d),
    ('pair_leaf_error', 0x41c7a69, 0x41c7a9d),
    ('pair_finish', 0x41c7a73, 0x41d3f60),
    ('pair_counter_failure', 0x41c7aed, 0x64df520),
    ('pair_unwind_resume', 0x41c7b22, 0x63f0a50),
    ('buffered_pair_mode', 0x41b9348, 0x41b936b),
    ('buffered_pair_capacity_one', 0x41b9354, 0x41b94b7),
    ('buffered_pair_capacity_two', 0x41b9372, 0x41b94de),
    ('buffered_pair_index', 0x41b939c, 0x3d51450),
    ('buffered_pair_index_failure', 0x41b93aa, 0x41b93f0),
    ('buffered_pair_leaf_branch', 0x41b93b1, 0x41b9405),
    ('buffered_pair_nested', 0x41b93c2, 0x41771f0),
    ('buffered_pair_nested_success', 0x41b93d4, 0x41b947a),
    ('buffered_pair_hex', 0x41b943c, 0x64e4d08),
    ('buffered_pair_string', 0x41b9448, 0x41c6610),
    ('buffered_pair_string_error', 0x41b9451, 0x41b945a),
    ('buffered_pair_failure', 0x41b9474, 0x41b93da),
    ('buffered_pair_finish', 0x41b94a6, 0x41d4150),
    ('index_buffered', 0x41d2697, 0x41d26a2),
    ('index_buffered_header', 0x41d26b5, 0x3d50270),
    ('index_header_failure', 0x41d26c2, 0x41d276c),
    ('index_buffered_write', 0x41d26fc, 0x3d517e0),
    ('index_buffered_write_failure', 0x41d2709, 0x41d277e),
    ('index_direct_write', 0x41d2745, 0x3d517e0),
    ('index_direct_failure', 0x41d2752, 0x41d275a),
    ('uint_small_boundary', 0x3d517f7, 0x3d5183c),
    ('uint_byte_high_bit', 0x3d51812, 0x3d51918),
    ('uint_u16_boundary', 0x3d51843, 0x3d5185b),
    ('uint_u16', 0x3d5184a, 0x3d51d10),
    ('uint_u32_boundary', 0x3d51862, 0x3d5187a),
    ('uint_u32', 0x3d51869, 0x3d51f40),
    ('uint_u64', 0x3d51880, 0x3d520d0),
    ('uint_after_marker_capacity', 0x3d5193b, 0x3d519ba),
    ('uint_after_marker_overflow', 0x3d5194a, 0x3d51967),
    ('uint_after_marker_realloc', 0x3d5199b, 0x43bd550),
    ('uint_after_marker_alloc_failure', 0x3d519a5, 0x3d5194c),
    ('array_finish_buffered', 0x41acec4, 0x41acedc),
    ('array_finish_header', 0x41acef2, 0x3d50270),
    ('array_finish_header_failure', 0x41acf00, 0x41acf47),
    ('array_finish_capacity', 0x41acf1c, 0x41acf7c),
    ('array_finish_growth', 0x41acf21, 0x41acfb8),
    ('array_finish_copy', 0x41acf8b, 0x64df508),
    ('array_finish_realloc', 0x41acfea, 0x43bd550),
    ('array_finish_realloc_failure', 0x41acff4, 0x41acf27),
    ('pair_finish_buffered', 0x41d3f84, 0x41d3f92),
    ('pair_finish_count', 0x41d3fa5, 0x41d3fc0),
    ('pair_finish_alt_header', 0x41d3fcc, 0x41c5d30),
    ('pair_finish_short_header', 0x41d3fdf, 0x3d50270),
    ('pair_finish_header_failure', 0x41d3fed, 0x41d40b1),
    ('pair_finish_capacity', 0x41d4007, 0x41d40e8),
    ('pair_finish_length_overflow', 0x41d4023, 0x41d40b6),
    ('pair_finish_realloc', 0x41d4064, 0x43bd550),
    ('pair_finish_realloc_failure', 0x41d406e, 0x41d40b6),
    ('pair_finish_copy', 0x41d40f7, 0x64df508),
    ('pair_finish_unwind', 0x41d4144, 0x63f0a50),
)

CONTEXT_HASHES = {
    'context_loader_location': '1ea1073c406146d87720d4cf9fc27ab9f6b6e3591bd9b71337067f3330015c30',
    'context_root_mode': 'e5d670d8671174b6639fe6866f74034602cec330030059d1e39825de1425d7d5',
    'context_root_capacity': '4ad88cd49a3040485f387b5e0d9843dbb2d5bf2a51998b2d3d9cb49af1185a9f',
    'context_capture_reducer': 'd203e4d05856b4836da36ea42bc2681b141811a24fa5262500f6ba6d0ecb8f7e',
    'context_digest_input': '5d3b1671f8c29043c1f578fc2ff53e080e57ae3a86ba3d308d9c623d9a1ba875',
    'context_end_handoff': '6c3f285b4f17fc49cf59fb594dabc9fe479eab9b82267515dc56f97a22b36c7b',
    'context_failed_output': 'b036b1511b72bdefcc8af9b05095f51c672430987eca6b3e8415d753b8db5e33',
    'context_root_hash_result': '413abd05c74ee8f809856c7aab7f4b936922d7e26471627e41dce80f35c1c919',
    'context_reducer_scan': 'e55112ab26f3d1938135ca2b4f78dc3a95092ce729f956e1505f7f03cf4b9549',
    'context_reducer_row_store': '98f9f022d9fc9bfef0346deeae0490d27d037863b47f8b698c8343016b3ad01a',
    'context_array_header_choices': '0b1201719aac088f504f0d017f9a48d007b9d4e56e2049ed98587d828e7a02e1',
    'context_array_header_pack': '9d52242ae03797833013602ee89ffb4334562dd6d5da5e7a106e6d4e7e4c3303',
    'context_array_header_u16': '1aac276ba4127a063e1d56722454770c2cc4d3e22033bca045b20103a2d7017f',
    'context_string_header': '924c812434bd103f200f7b25e2ddbc499140c36476ecfd7b03fd4a3d6d2bba83',
    'context_hex_prefix': '5781dc40f2ec853de0555eceb63078b590d111a867044a9b35cc5208fe3f0280',
    'context_hex_first': 'e261076b4a47a21dddc50a3ecab798b3f9facf9697e25ba851059384190a4cc3',
    'context_hex_loop': '1791dcaba9b92aff5dfb2451a928e20dc0cd568ded3e9f4907fbe288f51a7f32',
    'context_string_length': '7c78163716d8a3a3bc59db7f1e39cd823cb548080e6561aec3d605fe0444d83c',
    'context_string_copy': '3a3c3b517a30429dc274142890521d8fe24923609894346ca13d2faa3a99e59f',
    'context_history_wrapper': '37be8797819550403e0f2ae3049a1f31bf2aeeae39bcf76df8891ab5b913bc22',
    'context_history_input': 'c88072d50c760147ca58b3b9cd7d9f043a924d72441ae8a07832590ef1b20652',
    'context_history_tree_mode': 'f0f8d4b3fbb23753d929c695396efd7c4808e89cd59117303283abce6e4070af',
    'context_history_search': '492431a9a3441dcf996a764c00e61e69478e6fcfd30b6febcf25cf1da36c14f8',
    'context_history_insert': 'aef738247b9e854b86b94e8500dd2a0c77f5b5c714da4a9ba9ac2640191ce03a',
}


def authenticate(data, expected=TARGET_SHA):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('target SHA-256 mismatch')
    return actual


def one_section(secs, name):
    matches = [s for s in secs if s['name'] == name]
    if len(matches) != 1 or matches[0]['type'] == 8:
        raise ValueError('missing, duplicate, or fileless section: ' + name)
    return matches[0]


def mapping(secs, va, size, executable=False):
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
        raise ValueError('invalid file-backed address range')
    found = [s for s in secs if s['type'] != 8 and s['address'] <= va
             and va + size <= s['address'] + s['size']
             and (not executable or s['flags'] & 4)]
    if len(found) != 1:
        raise ValueError('range is not in one file-backed section')
    sec = found[0]
    return sec['offset'] + va - sec['address']


def read_va(data, secs, va, size, executable=False):
    off = mapping(secs, va, size, executable)
    if off + size > len(data):
        raise ValueError('mapped range is truncated')
    return bytes(data[off:off + size])


def exact(data, secs, va, expected, executable=True):
    if read_va(data, secs, va, len(expected), executable) != expected:
        raise ValueError(f'selected instruction or data bytes changed at {va:#x}')


def find_relocation(data, secs, slot):
    sec = one_section(secs, '.rela.dyn')
    if sec['size'] % 24:
        raise ValueError('invalid relocation section size')
    found = []
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        r_offset, info, addend = struct.unpack_from('<QQq', data, off)
        if r_offset == slot:
            found.append((off, info, addend))
    if len(found) != 1:
        raise ValueError('relocation slot is missing or ambiguous')
    off, info, addend = found[0]
    if info != 8:
        raise ValueError('relocation is not symbol-zero R_X86_64_RELATIVE')
    return {'slot_va': hex(slot), 'record_file_offset': hex(off),
            'info': hex(info), 'addend_va': hex(addend)}


def dynamic_binding(data, secs, slot, expected_name):
    """Bind one selected GLOB_DAT relocation through the shared ELF sections."""
    rela = one_section(secs, '.rela.dyn')
    symbols = one_section(secs, '.dynsym')
    strings = one_section(secs, '.dynstr')
    if rela['size'] % 24 or symbols['size'] % 24:
        raise ValueError('truncated ELF relocation or symbol table')
    records = []
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', data, off)
        if target == slot:
            records.append((off, info, addend))
    if len(records) != 1:
        raise ValueError('dynamic slot missing or duplicated')
    off, info, addend = records[0]
    index, kind = info >> 32, info & 0xffffffff
    if kind != 6 or addend != 0 or index >= symbols['size'] // 24:
        raise ValueError('unexpected dynamic binding')
    symoff = symbols['offset'] + 24 * index
    nameoff, sym_info, other, section_index, value, size = struct.unpack_from('<IBBHQQ', data, symoff)
    if nameoff >= strings['size'] or section_index != 0:
        raise ValueError('invalid dynamic symbol')
    first = strings['offset'] + nameoff
    limit = strings['offset'] + strings['size']
    end = data.find(b'\0', first, limit)
    if end < 0:
        raise ValueError('unterminated dynamic symbol')
    name = bytes(data[first:end]).decode('ascii')
    if name != expected_name:
        raise ValueError('dynamic symbol name changed')
    return {'slot_va': hex(slot), 'record_file_offset': hex(off),
            'info': hex(info), 'symbol_index': index, 'symbol': name,
            'symbol_record_file_offset': hex(symoff), 'name_file_offset': hex(first)}


def validate_body(data, secs, start, end, expected_hash):
    if end <= start:
        raise ValueError('invalid selected FDE extent')
    off = mapping(secs, start, end - start, executable=True)
    body = bytes(data[off:off + end - start])
    if hashlib.sha256(body).hexdigest() != expected_hash:
        raise ValueError('selected FDE code bytes changed')
    return off, body


def selected_fdes(data, secs):
    indexed_secs, index = unwind_index(data)
    if indexed_secs != secs:
        raise ValueError('section results changed')
    _, all_fdes = eh_frame_records(data, secs)
    indexed = {row['start']: row for row in index}
    if len(indexed) != len(index):
        raise ValueError('duplicate indexed starts')
    result = []
    for role, start, expected_end, expected_hash in FUNCTIONS:
        matches = [f for f in all_fdes if f['start'] == start]
        if len(matches) != 1:
            raise ValueError('selected FDE missing or duplicate')
        f = matches[0]
        if f['end'] != expected_end or f['end'] <= start:
            raise ValueError('selected FDE extent mismatch')
        header = indexed.get(start)
        if header is None or header['fde'] != f['fde']:
            raise ValueError('unwind index and selected FDE disagree')
        overlaps = [other for other in all_fdes
                    if other is not f and other['start'] < f['end']
                    and start < other['end']]
        if overlaps:
            raise ValueError('selected FDE overlaps another unwind extent')
        off, body = validate_body(data, secs, start, f['end'], expected_hash)
        result.append({'role': role, 'start': start, 'end': f['end'],
                       'fde': f['fde'], 'cie': f['cie'], 'lsda': f['lsda'],
                       'file_offset': off, 'body_sha256': expected_hash,
                       'body_hex': body.hex()})
    return result


def selected_windows(data, secs, fdes):
    by_role = {f['role']: f for f in fdes}
    rows = []
    for label, role, start, end in WINDOWS:
        if end <= start:
            raise ValueError('invalid selected window')
        if role != 'context':
            fde = by_role[role]
            if not fde['start'] <= start < end <= fde['end']:
                raise ValueError('window outside its FDE')
        raw = read_va(data, secs, start, end - start, executable=True)
        digest = hashlib.sha256(raw).hexdigest()
        if role == 'context' and digest != CONTEXT_HASHES[label]:
            raise ValueError('context boundary bytes changed')
        rows.append({'label': label, 'scope': role, 'start_va': hex(start),
                     'end_va_exclusive': hex(end),
                     'file_offset': hex(mapping(secs, start, end - start, True)),
                     'bytes_hex': raw.hex()})
    return rows


def decode_transfer(data, secs, va):
    raw = read_va(data, secs, va, 2, executable=True)
    if raw[0] in (0xe8, 0xe9):
        length, kind, disp_off = 5, 'call' if raw[0] == 0xe8 else 'jump', 1
    elif raw[0] == 0xff and raw[1] in (0x15, 0x25):
        length, kind, disp_off = 6, 'rip_slot', 2
    elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        length, kind, disp_off = 6, 'conditional', 2
    elif 0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb:
        length, kind, disp_off = 2, 'conditional' if raw[0] != 0xeb else 'jump', 1
    else:
        raise ValueError('unsupported transfer opcode')
    raw = read_va(data, secs, va, length, executable=True)
    displacement = struct.unpack_from('<b' if length == 2 else '<i', raw, disp_off)[0]
    return kind, va + length + displacement, raw


def validate_transfer(data, secs, va, expected_target):
    kind, target, raw = decode_transfer(data, secs, va)
    if target != expected_target:
        raise ValueError('selected transfer target mismatch')
    return kind, target, raw


def selected_transfers(data, secs, fdes):
    rows = []
    for label, va, expected_target in TRANSFERS:
        owners = [f for f in fdes if f['start'] <= va < f['end']]
        if len(owners) != 1:
            raise ValueError('transfer site has no unique selected FDE')
        kind, target, raw = validate_transfer(data, secs, va, expected_target)
        if va + len(raw) > owners[0]['end']:
            raise ValueError('transfer target or extent mismatch')
        rows.append({'label': label, 'role': owners[0]['role'], 'va': va,
                     'file_offset': mapping(secs, va, len(raw), True),
                     'bytes': raw.hex(), 'kind': kind, 'target': target})
    return rows


def lsda_call_sites(data, secs, fde):
    if fde['lsda'] is None:
        return []
    sec = one_section(secs, '.gcc_except_table')
    va = fde['lsda']
    if not sec['address'] <= va < sec['address'] + sec['size']:
        raise ValueError('LSDA outside exception section')
    pos = mapping(secs, va, 1)
    limit = sec['offset'] + sec['size']
    if pos + 2 > limit or data[pos] != 0xff or data[pos + 1] not in (0xff, 0x9b):
        raise ValueError('unsupported LSDA header')
    type_enc = data[pos + 1]
    pos += 2
    if type_enc == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
    else:
        type_base = limit
    if type_base > limit or pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    size, pos = uleb(data, pos + 1, limit)
    end = pos + size
    if end > min(limit, type_base):
        raise ValueError('truncated LSDA call-site table')
    out = []
    while pos < end:
        first = pos
        begin, pos = uleb(data, pos, end)
        length, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        extent = fde['end'] - fde['start']
        if begin + length > extent or landing >= extent and landing != 0:
            raise ValueError('LSDA call site or landing outside selected FDE')
        out.append({'role': fde['role'], 'lsda_va': va, 'record_offset': first,
                    'start_va': fde['start'] + begin,
                    'end_va_exclusive': fde['start'] + begin + length,
                    'landing_va': fde['start'] + landing if landing else None,
                    'action': action, 'bytes': bytes(data[first:pos]).hex()})
    if pos != end:
        raise ValueError('LSDA table boundary mismatch')
    return out


def location(data, secs):
    va = 0x64767a8
    relocation = find_relocation(data, secs, va)
    raw = read_va(data, secs, va, 24)
    pointer, length, line, column = struct.unpack('<QQII', raw)
    if pointer != 0 or (length, line, column) != (20, 123, 37):
        raise ValueError('target Location record changed')
    path_va = int(relocation['addend_va'], 16)
    if path_va != 0x443168:
        raise ValueError('target Location pointer changed')
    path = read_va(data, secs, path_va, length)
    if path != b'l1/src/abci/state.rs':
        raise ValueError('target Location path changed')
    # RIP-relative Location reference and the following result comparison.
    exact(data, secs, 0x3c1352f, bytes.fromhex('488d1572328602'))
    disp = struct.unpack_from('<i', read_va(data, secs, 0x3c1352f, 7, True), 3)[0]
    if 0x3c1352f + 7 + disp != va:
        raise ValueError('target Location reference changed')
    exact(data, secs, 0x3c1353b, bytes.fromhex('4883f801'))
    return {'scope': 'context from prior loader packet', 'va': hex(va),
            'file_offset': hex(mapping(secs, va, 24)), 'raw_hex': raw.hex(),
            'path_va': hex(path_va), 'path': path.decode('ascii'), 'length': length,
            'line': line, 'column': column, 'relocation': relocation,
            'reference_va': hex(0x3c1352f), 'comparison_va': hex(0x3c1353b)}


def historical_check(data):
    """Optionally verify the separate #94 lead without using it as #115 input."""
    authenticate(data, HISTORICAL_SHA)
    secs = sections(data)
    va = 0x56dfbf8
    rel = find_relocation(data, secs, va)
    raw = read_va(data, secs, va, 24)
    pointer, length, line, column = struct.unpack('<QQII', raw)
    if pointer != 0 or (length, line, column) != (49, 107, 37):
        raise ValueError('historical Location record changed')
    path_va = int(rel['addend_va'], 16)
    if path_va != 0x1dd8eb:
        raise ValueError('historical Location relocation changed')
    if not read_va(data, secs, path_va, length).endswith(b'l1/src/abci/state.rs'):
        raise ValueError('historical Location path changed')
    exact(data, secs, 0x3273856, bytes.fromhex('488d0d9bc34602'))
    exact(data, secs, 0x3273871, bytes.fromhex('4983fd02'))
    disp = struct.unpack_from('<i', read_va(data, secs, 0x3273856, 7, True), 3)[0]
    if 0x3273856 + 7 + disp != va:
        raise ValueError('historical Location reference changed')


def extracted_constants(data, secs):
    # Validate the specific instruction forms before reading immediates.
    pins = {
        0x3d5027e: '81fa00000100', 0x3d50284: '0f92c034dd',
        0x3d50289: '83fa10', 0x3d5028f: 'bd90000000',
        0x4e3493d: '48c74424183b000000',
        0x3d52353: '4080e60f4080ce9089f0c3',
        0x41b935e: 'c6043092', 0x414469c: '4983c730',
        0x41c6160: 'c60430d9', 0x2eabb62: '66c7073078',
        0x41c7a27: 'be42000000', 0x41c7a2c: 'b920000000',
        0x3d517f0: '4881fa00010000', 0x3d5183c: '4881fa00000100',
        0x3d5185e: '48c1e820', 0x3d51925: 'c60430cc',
        0x3d51d37: 'c60401cd', 0x3d51dc9: '66c1c608',
        0x3d51f67: 'c60401ce', 0x3d51ff9: '0fce',
        0x3d520f8: 'c60401cf', 0x3d5218c: '480fce',
        0x414466a: '48b80000000000000080', 0x4144674: '488d5804',
        0x41c7875: '410fb6470884c0', 0x41b93ac: '41807f0801',
        0x4c5f1cd: '410fb79dc2010000', 0x4c5f1d5: '4883fb0b',
        0x4c5f1e3: '488d04d568010000', 0x4c5f29c: '48c1e005',
        0x51f3354: 'bfc8010000', 0x51f33c5: '49ff442410',
    }
    for va, encoded in pins.items():
        exact(data, secs, va, bytes.fromhex(encoded))
    alphabet = read_va(data, secs, 0x455d40, 16)
    if alphabet != b'0123456789abcdef':
        raise ValueError('hexadecimal alphabet changed')
    marker32 = read_va(data, secs, 0x3d50287, 2, True)[1]
    base = struct.unpack('<I', read_va(data, secs, 0x3d50290, 4, True))[0]
    constants = {
        'array_fix_base': base,
        'array_fix_limit': read_va(data, secs, 0x3d5028b, 1, True)[0],
        'array16_limit': struct.unpack('<I', read_va(data, secs, 0x3d50280, 4, True))[0],
        'root_capture_slots': struct.unpack('<I', read_va(data, secs, 0x4e34942, 4, True))[0],
        'array16_marker': marker32 ^ 1,
        'array32_marker': marker32,
        'pair_marker': read_va(data, secs, 0x41b9361, 1, True)[0],
        'uint8_marker': read_va(data, secs, 0x3d51928, 1, True)[0],
        'uint16_marker': read_va(data, secs, 0x3d51d3a, 1, True)[0],
        'uint32_marker': read_va(data, secs, 0x3d51f6a, 1, True)[0],
        'uint64_marker': read_va(data, secs, 0x3d520fb, 1, True)[0],
        'string_marker': read_va(data, secs, 0x41c6163, 1, True)[0],
        'hex_prefix': read_va(data, secs, 0x2eabb65, 2, True).decode('ascii'),
        'hex_alphabet': alphabet.decode('ascii'),
        'formatted_length': struct.unpack('<I', read_va(data, secs, 0x41c7a28, 4, True))[0],
        'leaf_bytes': struct.unpack('<I', read_va(data, secs, 0x41c7a2d, 4, True))[0],
        'row_stride': read_va(data, secs, 0x414469f, 1, True)[0],
        'sentinel': struct.unpack('<Q', read_va(data, secs, 0x414466c, 8, True))[0],
        'success_delta': read_va(data, secs, 0x4144677, 1, True)[0],
        'uint16_cutoff': struct.unpack('<I', read_va(data, secs, 0x3d517f3, 4, True))[0],
        'uint32_cutoff': struct.unpack('<I', read_va(data, secs, 0x3d5183f, 4, True))[0],
        'uint_wide_shift': read_va(data, secs, 0x3d51861, 1, True)[0],
        'buffered_nested_tag': read_va(data, secs, 0x41b93b0, 1, True)[0],
        'history_nonfull_cutoff': read_va(data, secs, 0x4c5f1d8, 1, True)[0],
        'history_node_count_offset': struct.unpack('<I', read_va(data, secs, 0x4c5f1d1, 4, True))[0],
        'history_node_keys_offset': struct.unpack('<I', read_va(data, secs, 0x4c5f1e7, 4, True))[0],
        'history_value_shift': read_va(data, secs, 0x4c5f29f, 1, True)[0],
        'history_empty_allocation': struct.unpack('<I', read_va(data, secs, 0x51f3355, 4, True))[0],
    }
    if (constants['pair_marker'] != base + 2 or constants['formatted_length'] != 2 + 2 * constants['leaf_bytes']
            or constants['row_stride'] != 0x30 or constants['success_delta'] != 4):
        raise ValueError('derived selected-path constants disagree')
    return constants


def array_header(count, c):
    """Model the selected 32-bit-count normal-capacity header path."""
    if type(count) is not int or not 0 <= count <= 0xffffffff:
        raise ValueError('count outside model scope')
    if count < c['array_fix_limit']:
        return bytes([c['array_fix_base'] | count])
    if count < c['array16_limit']:
        return bytes([c['array16_marker']]) + count.to_bytes(2, 'big')
    return bytes([c['array32_marker']]) + count.to_bytes(4, 'big')


def unsigned(index, c):
    """Model the writer's normal-capacity unsigned integer cases."""
    if type(index) is not int or not 0 <= index < 1 << 64:
        raise ValueError('index outside model scope')
    if index < c['uint16_cutoff'] // 2:
        return bytes([index])
    if index < c['uint16_cutoff']:
        return bytes([c['uint8_marker'], index])
    if index < c['uint32_cutoff']:
        return bytes([c['uint16_marker']]) + index.to_bytes(2, 'big')
    if index < 1 << c['uint_wide_shift']:
        return bytes([c['uint32_marker']]) + index.to_bytes(4, 'big')
    return bytes([c['uint64_marker']]) + index.to_bytes(8, 'big')


def child_kind(tag, buffered, c):
    """Synthetic classification for the two observed byte tests."""
    if type(tag) is not int or not 0 <= tag <= 255 or type(buffered) is not bool:
        raise ValueError('invalid synthetic tag or mode')
    return 'nested' if (tag == c['buffered_nested_tag'] if buffered else tag != 0) else 'leaf'


def tree_preimage(rows, c, active=None):
    """Synthetic model only: list of (index, 32-byte leaf or nested list)."""
    if not isinstance(rows, list):
        raise ValueError('tree must be a list')
    active = set() if active is None else active
    if id(rows) in active:
        raise ValueError('cyclic synthetic tree')
    active.add(id(rows))
    try:
        out = bytearray(array_header(len(rows), c))
        for row in rows:
            if not isinstance(row, tuple) or len(row) != 2:
                raise ValueError('invalid synthetic row')
            index, value = row
            out.append(c['pair_marker'])
            out.extend(unsigned(index, c))
            if isinstance(value, bytes):
                if len(value) != c['leaf_bytes']:
                    raise ValueError('invalid synthetic leaf size')
                text = c['hex_prefix'].encode('ascii') + value.hex().encode('ascii')
                if len(text) != c['formatted_length']:
                    raise ValueError('synthetic formatter length mismatch')
                out.extend((c['string_marker'], c['formatted_length']))
                out.extend(text)
            elif isinstance(value, list):
                out.extend(tree_preimage(value, c, active))
            else:
                raise ValueError('invalid synthetic child')
        return bytes(out)
    finally:
        active.remove(id(rows))


def boundary_relocations(data, secs):
    result = {}
    for name, slot, target in (('formatter', 0x64e4d08, 0x2eabb50),
                               ('reducer', 0x64df500, 0x141a250),
                               ('digest', 0x64e7820, 0x41c5140)):
        row = find_relocation(data, secs, slot)
        if row['addend_va'] != hex(target):
            raise ValueError('previously bound context relocation changed')
        result[name] = row
    return result


def collect(data):
    digest = authenticate(data)
    if len(data) < 64 or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('target is not x86-64 ELF')
    secs = sections(data)
    fdes = selected_fdes(data, secs)
    windows = selected_windows(data, secs, fdes)
    transfers = selected_transfers(data, secs, fdes)
    loc = location(data, secs)
    constants = extracted_constants(data, secs)
    # These slots were already bound in the prior block-root packet.  Check
    # them as contextual boundaries, not as new GOT or call-site ownership.
    boundaries = boundary_relocations(data, secs)
    move_binding = dynamic_binding(data, secs, 0x64df568, 'memmove')
    exception_rows = []
    for fde in fdes:
        exception_rows.extend(lsda_call_sites(data, secs, fde))
    witnesses = []
    by_role = {f['role']: f for f in fdes}
    for transfer in transfers:
        if transfer['kind'] not in ('call', 'rip_slot'):
            continue
        candidates = [r for r in exception_rows if r['role'] == transfer['role']
                      and r['start_va'] <= transfer['va'] < r['end_va_exclusive']]
        if len(candidates) > 1:
            raise ValueError('overlapping LSDA coverage at a selected transfer')
        if candidates:
            witness = candidates[0]
            coverage = 'covered'
            landing, action = witness['landing_va'], witness['action']
        else:
            coverage = 'no_lsda' if by_role[transfer['role']]['lsda'] is None else 'not_in_table'
            landing = action = None
        witnesses.append({'label': transfer['label'], 'role': transfer['role'],
                          'site_va': transfer['va'], 'coverage': coverage,
                          'landing_va': landing, 'action': action})
    return {'sha256': digest, 'fdes': fdes, 'windows': windows,
            'transfers': transfers, 'exceptions': exception_rows,
            'witnesses': witnesses, 'location': loc, 'constants': constants,
            'boundaries': boundaries, 'move_binding': move_binding}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n', encoding='utf-8')


def render_fdes(fdes):
    result = []
    for f in fdes:
        result.append({'role': f['role'], 'start_va': hex(f['start']),
                       'end_va_exclusive': hex(f['end']),
                       'file_offset': hex(f['file_offset']),
                       'length': f['end'] - f['start'], 'fde_va': hex(f['fde']),
                       'cie_va': hex(f['cie']),
                       'lsda_va': hex(f['lsda']) if f['lsda'] is not None else None,
                       'body_sha256': f['body_sha256'], 'body_hex': f['body_hex']})
    return result


def write_tsv(path, columns, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(columns)
        writer.writerows(rows)


def emit(out, evidence):
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / 'functions.json', render_fdes(evidence['fdes']))
    write_json(out / 'constants.json', {'derived': evidence['constants'],
                                        'location_115': evidence['location'],
                                        'prior_relocation_boundaries': evidence['boundaries'],
                                        'history_dynamic_move': evidence['move_binding']})
    write_tsv(out / 'windows.tsv',
              ['label', 'scope', 'start_va', 'end_va_exclusive', 'file_offset', 'bytes_hex'],
              [(w['label'], w['scope'], w['start_va'], w['end_va_exclusive'], w['file_offset'], w['bytes_hex'])
               for w in evidence['windows']])
    write_tsv(out / 'transfers.tsv',
              ['label', 'role', 'site_va', 'file_offset', 'bytes_hex', 'kind', 'target_va'],
              [(r['label'], r['role'], hex(r['va']), hex(r['file_offset']), r['bytes'], r['kind'], hex(r['target']))
               for r in evidence['transfers']])
    write_tsv(out / 'lsda.tsv',
              ['role', 'lsda_va', 'record_file_offset', 'start_va', 'end_va_exclusive', 'landing_va', 'action', 'bytes_hex'],
              [(r['role'], hex(r['lsda_va']), hex(r['record_offset']), hex(r['start_va']),
                hex(r['end_va_exclusive']), hex(r['landing_va']) if r['landing_va'] is not None else '-',
                r['action'], r['bytes']) for r in evidence['exceptions']])
    write_tsv(out / 'unwind-witnesses.tsv',
              ['label', 'role', 'site_va', 'coverage', 'landing_va', 'action'],
              [(w['label'], w['role'], hex(w['site_va']), w['coverage'],
                hex(w['landing_va']) if w['landing_va'] is not None else '-',
                w['action'] if w['action'] is not None else '-') for w in evidence['witnesses']])
    write_json(out / 'summary.json', {
        'target_release': '115', 'target_sha256': evidence['sha256'],
        'selected_fde_count': len(evidence['fdes']),
        'selected_windows': sum(w['scope'] != 'context' for w in evidence['windows']),
        'context_windows': sum(w['scope'] == 'context' for w in evidence['windows']),
        'selected_transfers': len(evidence['transfers']),
        'selected_lsda_rows': len(evidence['exceptions']),
        'selected_call_witnesses': len(evidence['witnesses']),
        'covered_call_witnesses': sum(w['coverage'] == 'covered' for w in evidence['witnesses']),
        'limitations': 'Selected static ELF evidence only; unwind extents are not source-function boundaries and these counts are not coverage denominators.'
    })


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--historical', type=Path,
                        help='optional separately authenticated historical node-94 input')
    args = parser.parse_args(argv)
    evidence = collect(TARGET.read_bytes())
    if args.historical is not None:
        historical_check(args.historical.read_bytes())
    emit(args.out, evidence)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print('abci_root_tree115:', error, file=sys.stderr)
        raise SystemExit(1)
