#!/usr/bin/env python3
"""Recover one node-115 block-to-root path from authenticated ELF bytes.

The x86 recognizers deliberately accept only the fixed forms in this packet.
This is static analysis: it does not execute the input or invoke other tools.
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
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# A label is a local description, not a recovered source function name.
FUNCTIONS = [
    ('outer_wrapper', 0x4f122c0),
    ('upper_block_caller', 0x4fcb590),
    ('entry_adapter', 0x56186c0),
    ('block_engine', 0x5a06600),
    ('begin_state', 0x5483f50),
    ('action_collect', 0x54864a0),
    ('item_reserve', 0x564bab0),
    ('item_transform', 0x59618e0),
    ('item_guard', 0x5868030),
    ('item_state_update', 0x560dbb0),
    ('action_join', 0x4e44ef0),
    ('action_item', 0x4dd0010),
    ('end_selector', 0x5a08720),
    ('hash_adapter', 0x548d8c0),
    ('capture_adapter', 0x4e47350),
    ('state_captures', 0x4e34320),
    ('descriptor_dispatch', 0x54423c0),
    ('dispatch_bridge', 0x57c3b30),
    ('serial_worker', 0x5b37320),
    ('freeze_callback', 0x4d3ebe0),
    ('neighbor_callback', 0x4d3f3a0),
    ('pair_allocator', 0x4d3e540),
    ('scalar_writer', 0x14199b0),
    ('hasher_initializer', 0x14196d0),
    ('tree_reducer', 0x141a250),
    ('root_digest', 0x41c5140),
    ('leaf_hex', 0x2eabb50),
    ('string_writer', 0x41c6110),
    ('history_wrapper', 0x5a03fa0),
    ('history_insert', 0x4dd45c0),
    ('digest_update', 0x160b3a0),
    ('digest_finalize', 0x160bcd0),
]

# SHA-256 pins cover selected contiguous byte ranges, in linked ELF VAs.
# Full selected FDE bodies are separately retained in functions.json.
WINDOWS = [
    ('outer_entry', 0x4f122c0, 0x4f12366, '175873d440422f371d1f4c369719d90b124a79d0c24c1893f2c1e52cbe757475'),
    ('outer_instrumented_return', 0x4f12ad8, 0x4f12b2b, 'f3bbadb412e76f08e444820a5c4a512c1b4ccd5b849ddc595799ac86be3bf4fc'),
    ('upper_enter', 0x4fcb590, 0x4fcb611, 'faa30ae7bf3a6631b4cd7486db68f02940a74aa1a4d338ef4c8c45c2fc96c66d'),
    ('upper_handoff', 0x4fcb75b, 0x4fcb818, '92d1ab3d57086ae81761e50047433cd3f5f0546fb219e05711247a8b9dd22d0f'),
    ('upper_result', 0x4fcb818, 0x4fcb9c0, '9a84adc20272d5c023049ea35dcbb6656777b5e8ad0f32ca06f3d41102d1184e'),
    ('upper_return_buffer', 0x4fcba20, 0x4fcbb30, '209d79157b372b7f67a28dbd9fb5cfb38118cf4075f9af2bff1d1f3a2edb8dbb'),
    ('upper_return', 0x4fcbb80, 0x4fcbbcc, 'e33335ecaf3cb2c844df05b7d68ec452a3ed2cf28da2e689e0517170c0662951'),
    ('upper_past_failure', 0x4fcbcd1, 0x4fcbcec, '2f27ea3d4501757e8e94061bcfdb48b4bf23c04193616e8cbf6a51cd2e6131fc'),
    ('entry_tls', 0x56186c0, 0x56186f3, '1dc916c2e4b6865b66390f42fb88102b257de72bd64ad8abcce2023fa6e6d8a3'),
    ('entry', 0x56186f3, 0x5618715, '45f2049ef35a8c51fdc38d2f0a4abd34335be1b996003bd0eebad3705a453392'),
    ('entry_return', 0x5618715, 0x561872f, '15287254b77874945957fe236a0b43e5d10574799c021fa3df2b6454c74d7005'),
    ('engine_validation', 0x5a0663d, 0x5a06727, 'f9aea16c4b35578a96a470ecac0c7b0ea76d55dea97d4a7a7ebc980edd03fe13'),
    ('engine_state_slot', 0x5a06727, 0x5a06790, '934737c905e9f2076c70a58b6705e3c0ccbcc6c642cdece387e805312cb8615c'),
    ('engine_begin', 0x5a06790, 0x5a06889, 'cb001c300838d3562a5bfc47b2380e77c688eecaf06ebb051abe6925c970a137'),
    ('engine_items', 0x5a068db, 0x5a06ab7, '02a1f67556a0ffbc58da50fa07f74fc6afb02639459f8b801e3d59035d6050ad'),
    ('engine_actions', 0x5a06ac1, 0x5a06b84, 'd2b9643fed1af019936df08b40dfc257761e85145f1513e4186d87dfe90ffe8a'),
    ('engine_middle', 0x5a06b84, 0x5a06cd8, '36a693d1b76abe2ca906b5d85ed46f5fad4d9915846371da1c7f98a5e2700a4b'),
    ('engine_process', 0x5a06d8b, 0x5a06de4, 'de07d0db86d2380c2dc3c2340af15dbf494e47bad6964ac12197a617b2bd9120'),
    ('engine_result', 0x5a077be, 0x5a0793f, '2c2443c146b9d416f87675a03b00423c86522ab9252a6f249f977b9aad7d05fa'),
    ('engine_errors', 0x5a07a5b, 0x5a07b63, 'a9b39d31f55ad1dd927387497a8d2dc8d4dd05252c98cde60fdeec1480521534'),
    ('begin_update', 0x5483f61, 0x5484040, 'd793f52d69e298ed77652caf4a6729ef7df3c62b3cafa579263fa282a3f28507'),
    ('begin_finish', 0x548452e, 0x54845c1, '29aaeea7252c870a0e94c60a3f655eae74738eefccbc6df65d3c73a4da752bc9'),
    ('begin_error', 0x54845ff, 0x5484618, '662108d42a7835946af2387745518feedf13a66dae748ad6c00e7c581f44c47b'),
    ('root_gate', 0x5a08731, 0x5a0884a, '3c1999f989fe4982cb4a94ee34bc622cde42f98db2307da889b04666c66fae15'),
    ('root_normal', 0x5a08c3a, 0x5a08cc3, '105e0abf9952f33ff29096a060d8c7f7529e7e7d820324e8aa24d76bcd7848fa'),
    ('root_error', 0x5a08dc3, 0x5a08df5, '007d4ef4230e3dbedf885c05e43345d65b6c1152cb7ce0922eafeb9660b6e52f'),
    ('hash_wrapper', 0x548d8d1, 0x548d910, 'f8f0264198b9347f8c24a3abefe13c0c2b2e041f8a61ae00ae96c98f3a7e0e80'),
    ('hash_output', 0x548d997, 0x548d9f3, 'ebac4f54cf60c0c186e3073b059e9e9c5e5f9149ea47c5fd14e212cff40b547f'),
    ('capture_pointers', 0x4e34331, 0x4e34795, '00ed06f9ed54dd2ce6e0dea6cff262f0c0bbe6bc67b84b8a165a4dfee4cc6df8'),
    ('capture_slots', 0x4e34795, 0x4e3496d, '3d4d3afbe2ca0bcac636cb46d36ca5a10b74b97637a0f41182d2fcfd5ad594aa'),
    ('capture_result', 0x4e3496d, 0x4e349f0, 'e93485206f815090c2aa052b08c3a170a591fcb86510e32531db23a61034e3ba'),
    ('capture_adapter', 0x4e4735c, 0x4e473ee, '1ec0621749ef3832fe41f6c3c5b8c13739e0b67de557e3390bdfb5d0298176d7'),
    ('dispatch_init', 0x54423c0, 0x5442a38, '64972f5c08ac0b3236f14c0d51e9f02e674e874bca37a25178298f8f7379161b'),
    ('dispatch_call', 0x5443533, 0x54435c4, '595b2219b2d90894b25683eaa9e230230ac4f92178243028a292779b6c58ce69'),
    ('dispatch_bridge', 0x57c3b30, 0x57c3bb9, '9d559b20b1270c1ec85f4b2bf19e52a58c08c42ccb8b99a7a531af4063109344'),
    ('dispatch_worker', 0x5b37331, 0x5b37450, 'b9ad8459eb1ca9abb7998c5c22cbf4488f6ab513324a681048862b4c79ea1c17'),
    ('hash_reduce_leaf', 0x141a250, 0x141a346, '92124943a686abec576283cdd9adcf17a6b51b5526fcf1997ff7bcbb97d60af5'),
    ('hash_reduce_vector', 0x141a3b0, 0x141a409, 'e55112ab26f3d1938135ca2b4f78dc3a95092ce729f956e1505f7f03cf4b9549'),
    ('hash_reduce_empty', 0x141a728, 0x141a751, '99f0bd491f1d7b0637d30818e77ec5a263ba34bf51003af521f8db0975e89825'),
    ('digest_encode', 0x41c5140, 0x41c5233, '2fe4ec84654cec7d2fb4e5a80921aad143d2ba8dab7e1b2c85cf5b89ea0abd6e'),
    ('digest_final', 0x41c52c9, 0x41c53b1, '3958822b6b305d3d8729e4f5f040586a2d3fac10400c01fb84b3dadf74115f3a'),
    ('hex_entry', 0x2eabb50, 0x2eabbca, '9fcac1621d7cc79453c6297ae1b1dc31e99d44defdd68a92d76b1a98976af297'),
    ('hex_loop', 0x2eabbd1, 0x2eabc6f, 'ceae6d29be919cd51a9f1b0692550338505a48ff3252792d32c21cac6567e017'),
    ('string_length', 0x41c6110, 0x41c6178, '8c2071469ca19f76da14de1eb58ed8cb95984a5869d082008c0167208fc36702'),
    ('string_length_write', 0x41c61e5, 0x41c6202, '7c78163716d8a3a3bc59db7f1e39cd823cb548080e6561aec3d605fe0444d83c'),
    ('string_copy', 0x41c63b8, 0x41c6452, '11e82b2b9486f2f192248dc8df1b8de1928c1727613b4f6ad0f8aff3edc1119e'),
    ('option_first', 0x4d3ebe9, 0x4d3ece8, 'a17da73b2f72a103ca1681cae8fbbfee59dfa2a00a012588ecf0db37d3ee7795'),
    ('option_second', 0x4d3f3a9, 0x4d3f4a6, 'b42aed055678d52bf75b73da7ed28a68aa3abf4f7c81ec31e2ea25c6f7cc85bf'),
    ('scalar_writer', 0x14199b0, 0x1419a0a, '03b778208f99f6854f74f391070f6c3a4404a24950652cdd58ad1721806a4047'),
    ('option_allocate', 0x4d3e540, 0x4d3e58d, 'b0f2f4fb4bbdc3ae7b244e65f8e14d5d8b3d02ee12f3d102179f99d639a3309a'),
    ('history', 0x5a03fa0, 0x5a040aa, '29342b2f83251616dc936ef4f9fbb650a70aff5a692665f04ccbf60360664d94'),
    ('history_inner', 0x4dd45d1, 0x4dd472b, 'bce5ed096c29b41e4f4d6f40a9c9b189bdf171b6ea29fa8d644ea90a9fe4367d'),
    ('loc_blake3', 0x160bb6b, 0x160bb72, '9399649ee388652b9881fa313931315e8fe695529272574aad864ca70dae7fda'),
    ('hash_state_init', 0x14196de, 0x141976a, '9d07de26005e3b473ad32d2c2a85556e7c8719238c1819f235a3173496bc4bd7'),
    ('action_collection', 0x54864c8, 0x54865a8, 'b9d3d75c2ee62765e45064fd8a8e78da4a7c3dbd4e99a484902d6370e4de95c2'),
    ('item_reserve', 0x564bab0, 0x564bbc2, '5ba8bfe12ff2087d251c4a956259ffdbc1410388bb06a57118337a8c65d649a4'),
    ('item_transform', 0x59618e0, 0x5961a00, 'a4140def00acbe053b5e1e3ba8c0a940105725f259942973117118d6ac9f823b'),
    ('item_guard', 0x5868030, 0x586817f, 'df038ce6847ebd1bc786fa7d26e4e34caaa916e4f292bbbdc557b9619c7bc88f'),
    ('item_finish', 0x58681e3, 0x5868337, '8cb79c0e4fc76cfb9e1b4cade2b484f98420349c7ce4d7244573a54e4f358c17'),
    ('state_action', 0x560dbb0, 0x560dc99, '66ede1ec1f283597f176446da936f5a51a4c09eef233e85fa6d87dc40c90ad0d'),
    ('action_join_detail', 0x4e44ef0, 0x4e44f9b, '52c8697a06dbe5b67e44c6db636e0e826bbb6d251bf252b68cb4314cd5e3c9bd'),
    ('action_item_detail', 0x4dd0035, 0x4dd017c, 'b9436f3fa00d1ebabdfd639b8fcf04a0f7a5a074e460399ac5348c70525abfff'),
    ('root_post_hash', 0x5a0884a, 0x5a08853, '0b047a220b6af94c564a896e5f655183cf3657fe26392350de39e17b2bda9d25'),
    ('begin_literal_ref', 0x5484143, 0x548415e, 'e14925c89fd17d6a708d3e576c7e8403a39391d258e6ecdb20692111f238c8ea'),
]

# Sites were selected after instruction-aligned human inspection. The decoder
# recomputes targets from the ELF; this is not a whole-function transfer census.
EDGES = [
    ('outer_mode', 0x4f122e3, 'branch'),
    ('outer_tls_one', 0x4f1232d, 'branch'),
    ('outer_tls_two', 0x4f12332, 'branch'),
    ('outer_tls_error', 0x4f1233b, 'call'),
    ('outer_direct_to_upper', 0x4f1234c, 'call'),
    ('outer_buffer_empty', 0x4f12ae3, 'branch'),
    ('outer_instrumented_to_upper', 0x4f12b02, 'call'),
    ('outer_instrumented_cleanup', 0x4f12b0f, 'call'),
    ('outer_instrumented_error', 0x4f12b23, 'call'),
    ('upper_clock_state', 0x4fcb5d6, 'branch'),
    ('upper_lock_acquired', 0x4fcb5f4, 'branch'),
    ('upper_to_entry', 0x4fcb795, 'call'),
    ('upper_result_empty', 0x4fcb7d7, 'branch'),
    ('upper_state_tag_zero', 0x4fcb87f, 'branch'),
    ('upper_state_tag_one', 0x4fcb8d3, 'branch'),
    ('upper_state_past', 0x4fcb8dc, 'branch'),
    ('upper_state_past_failure', 0x4fcbce4, 'call'),
    ('upper_optional_post', 0x4fcba8e, 'branch'),
    ('entry_tls_clear', 0x56186dd, 'branch'),
    ('entry_tls_helper', 0x56186ec, 'branch'),
    ('entry_to_engine', 0x5618710, 'call'),
    ('entry_cleanup', 0x561871a, 'call'),
    ('engine_freeze_tag', 0x5a066a0, 'branch'),
    ('engine_freeze_past', 0x5a066a9, 'branch'),
    ('engine_freeze_equal', 0x5a066af, 'branch'),
    ('engine_header_order', 0x5a066b8, 'branch'),
    ('engine_header_word', 0x5a066ca, 'branch'),
    ('engine_header_pair_first', 0x5a066e5, 'branch'),
    ('engine_header_pair_second', 0x5a066ee, 'branch'),
    ('engine_header_count', 0x5a06714, 'branch'),
    ('engine_mode', 0x5a06721, 'branch'),
    ('engine_mode_two', 0x5a06752, 'branch'),
    ('engine_to_begin', 0x5a067ad, 'call'),
    ('engine_no_items', 0x5a067fc, 'branch'),
    ('engine_first_allocation_null', 0x5a06811, 'branch'),
    ('engine_second_allocation_nonnull', 0x5a0684b, 'branch'),
    ('engine_empty_input', 0x5a06920, 'branch'),
    ('engine_item_sentinel', 0x5a069a7, 'branch'),
    ('engine_to_action_collect', 0x5a06af4, 'call'),
    ('engine_to_action_join', 0x5a06b7f, 'call'),
    ('action_collect_stage', 0x5486507, 'call'),
    ('action_collect_finish', 0x54865a3, 'call'),
    ('item_capacity_grow', 0x564bad9, 'branch'),
    ('item_capacity_underflow', 0x564bade, 'branch'),
    ('item_capacity_bounds', 0x564bae3, 'branch'),
    ('item_reserve_worker', 0x564bb0f, 'call'),
    ('item_count_mismatch', 0x564bb21, 'branch'),
    ('item_reserve_grow', 0x564bb4a, 'call'),
    ('item_transform_to_guard', 0x5961924, 'call'),
    ('item_guard_empty', 0x5868059, 'branch'),
    ('item_guard_predicate', 0x586811e, 'call'),
    ('item_guard_skip_state_update', 0x586812a, 'branch'),
    ('item_guard_to_state_update', 0x586816e, 'call'),
    ('item_guard_return_tag', 0x586817d, 'branch'),
    ('item_guard_common', 0x58681ff, 'call'),
    ('item_guard_projection', 0x586825f, 'call'),
    ('item_guard_loop', 0x58682f3, 'branch'),
    ('state_update_lookup', 0x560dbf2, 'call'),
    ('state_update_inner', 0x560dc1c, 'call'),
    ('state_update_tag', 0x560dc29, 'branch'),
    ('action_join_count_mismatch', 0x4e44f13, 'branch'),
    ('action_join_proceed', 0x4e44f6e, 'call'),
    ('action_join_failure', 0x4e44f93, 'call'),
    ('action_item_sentinel', 0x4dd0051, 'branch'),
    ('action_item_replacement', 0x4dd0177, 'call'),
    ('engine_to_action_item', 0x5a06c36, 'call'),
    ('engine_to_result_collector', 0x5a06d9b, 'call'),
    ('engine_to_late_helper', 0x5a06db6, 'call'),
    ('engine_to_end', 0x5a077e1, 'call'),
    ('engine_compare_old_new_tag', 0x5a077fe, 'branch'),
    ('begin_time_first', 0x5483f93, 'branch'),
    ('begin_time_second', 0x5483fa0, 'branch'),
    ('begin_time_third', 0x5483faa, 'branch'),
    ('begin_extra_flag', 0x548400b, 'branch'),
    ('begin_extra_word', 0x5484014, 'branch'),
    ('begin_extra_mode', 0x548401e, 'branch'),
    ('begin_late_transfer', 0x54845a7, 'call'),
    ('begin_fail_call', 0x5484612, 'call'),
    ('root_ten_thousand', 0x5a08761, 'branch'),
    ('root_optional_tag', 0x5a0876a, 'branch'),
    ('root_optional_past_first', 0x5a08773, 'branch'),
    ('root_skip_tag_two_a', 0x5a08781, 'branch'),
    ('root_skip_tag_two_b', 0x5a0878c, 'branch'),
    ('root_optional_tag_again', 0x5a087af, 'branch'),
    ('root_optional_past_second', 0x5a087b8, 'branch'),
    ('root_special', 0x5a087e3, 'branch'),
    ('root_division_width', 0x5a087f6, 'branch'),
    ('root_remainder_64', 0x5a08803, 'branch'),
    ('root_remainder_32', 0x5a08815, 'branch'),
    ('root_to_hash_adapter', 0x5a0882e, 'call'),
    ('root_to_history', 0x5a08845, 'call'),
    ('root_post_hash_special', 0x5a0884d, 'branch'),
    ('root_past_failure_a', 0x5a08dd6, 'call'),
    ('root_past_failure_b', 0x5a08def, 'call'),
    ('hash_to_capture_adapter', 0x548d8ff, 'call'),
    ('hash_to_final_digest', 0x548d90a, 'call'),
    ('capture_adapter_to_builder', 0x4e473e9, 'call'),
    ('capture_allocation_failure', 0x4e347a3, 'branch'),
    ('capture_to_dispatch', 0x4e34964, 'call'),
    ('capture_status_failure', 0x4e3496b, 'branch'),
    ('capture_to_reducer', 0x4e34999, 'call'),
    ('dispatch_negative_header', 0x5442a25, 'branch'),
    ('dispatch_count_mismatch', 0x5442a32, 'branch'),
    ('dispatch_to_bridge', 0x54435b7, 'call'),
    ('bridge_to_worker', 0x57c3bac, 'call'),
    ('worker_make_callback', 0x5b373ff, 'vcall'),
    ('worker_process_callback', 0x5b373da, 'vcall'),
    ('worker_status', 0x5b373e4, 'branch'),
    ('worker_initial_sentinel', 0x5b373f5, 'branch'),
    ('option_tag', 0x4d3ebf6, 'branch'),
    ('option_invalid_first_word', 0x4d3ec05, 'branch'),
    ('option_invalid_count', 0x4d3ec12, 'branch'),
    ('option_value_init', 0x4d3ec33, 'call'),
    ('option_value_write', 0x4d3ec50, 'call'),
    ('option_value_status', 0x4d3ec58, 'branch'),
    ('option_one_init', 0x4d3ec73, 'call'),
    ('option_zero_init', 0x4d3ecc1, 'call'),
    ('option_marker_write', 0x4d3ece2, 'call'),
    ('neighbor_tag', 0x4d3f3b6, 'branch'),
    ('neighbor_payload_init', 0x4d3f3f3, 'call'),
    ('neighbor_payload_write', 0x4d3f40f, 'call'),
    ('neighbor_status', 0x4d3f416, 'branch'),
    ('neighbor_marker_write', 0x4d3f4a0, 'call'),
    ('option_pair_alloc', 0x4d3e549, 'call'),
    ('option_pair_null', 0x4d3e552, 'branch'),
    ('option_pair_failure', 0x4d3e587, 'call'),
    ('scalar_capacity', 0x14199d6, 'branch'),
    ('scalar_grow', 0x14199fa, 'call'),
    ('reduce_leaf_update', 0x141a2d2, 'call'),
    ('reduce_leaf_finish', 0x141a2e8, 'call'),
    ('reduce_vector_skip', 0x141a3d2, 'branch'),
    ('reduce_recursive', 0x141a3f1, 'call'),
    ('reduce_child_skip', 0x141a407, 'branch'),
    ('digest_update', 0x41c5387, 'call'),
    ('digest_finalize', 0x41c539a, 'call'),
    ('digest_leaf_hex', 0x41c5203, 'call'),
    ('digest_leaf_string', 0x41c5211, 'call'),
    ('hex_buffer_bound', 0x2eabb5c, 'branch'),
    ('string_length_lower', 0x41c612a, 'branch'),
    ('string_length_upper', 0x41c613a, 'branch'),
    ('string_copy_capacity', 0x41c63c8, 'branch'),
    ('history_to_insert', 0x5a03fb8, 'call'),
    ('history_retention', 0x5a03fc5, 'branch'),
    ('history_convert_sentinel', 0x4dd4604, 'branch'),
]


class Image:
    """Authenticated, file-backed ELF view and selected unwind records."""

    def __init__(self, data, verify=True):
        self.data = data
        if verify and hashlib.sha256(data).hexdigest() != DIGEST:
            raise ValueError('input digest mismatch')
        self.sections = sections(data)
        names = [s['name'] for s in self.sections]
        if len(names) != len(set(names)):
            raise ValueError('duplicate ELF section names')
        self.by_name = {s['name']: s for s in self.sections}
        _, index = unwind_index(data)
        self.index = {r['start']: r for r in index}
        if len(self.index) != len(index):
            raise ValueError('duplicate unwind starts')
        _, fdes = eh_frame_records(data, self.sections)
        self.all_fdes = sorted(fdes, key=lambda f: (f['start'], f['end'], f['fde']))
        self.starts = [f['start'] for f in self.all_fdes]
        wanted = {va for _, va in FUNCTIONS}
        self.fdes = {}
        for f in fdes:
            if f['start'] not in wanted:
                continue
            if f['start'] in self.fdes:
                raise ValueError('duplicate selected FDE start')
            ix = self.index.get(f['start'])
            if not ix or ix['fde'] != f['fde'] or f['end'] <= f['start']:
                raise ValueError('selected FDE and index disagree')
            self.offset(f['start'], f['end'] - f['start'], executable=True)
            self.fdes[f['start']] = f
        if set(self.fdes) != wanted:
            raise ValueError('selected FDE missing')
        check_extent_overlaps(self.fdes.values(), self.all_fdes)
        self.relocations = parse_relocations(self)

    def offset(self, va, size, executable=False):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise ValueError('invalid address range')
        matches = [s for s in self.sections if s['type'] != 8 and (s['flags'] & 2)
                   and (not executable or s['flags'] & 4)
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('address is not uniquely file backed')
        s = matches[0]
        return s['offset'] + va - s['address']

    def read(self, va, size, executable=False):
        offset = self.offset(va, size, executable=executable)
        return self.data[offset:offset + size]

    def containing_fde(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0:
            return None
        f = self.all_fdes[i]
        return f if f['start'] <= va < f['end'] else None


def check_extent_overlaps(selected, all_fdes):
    """Reject any other unwind extent overlapping a selected unwind extent."""
    for chosen in selected:
        matches = [f for f in all_fdes
                   if f['start'] < chosen['end'] and chosen['start'] < f['end']]
        if len(matches) != 1 or matches[0]['fde'] != chosen['fde']:
            raise ValueError('selected unwind extent overlaps another FDE')


def parse_relocations(image):
    s = image.by_name.get('.rela.dyn')
    if s is None or s['type'] == 8 or s['size'] % 24:
        raise ValueError('invalid relocation table')
    out = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, off)
        out.setdefault(slot, []).append((info, addend, off))
    return out


def relative_relocation(image, slot):
    entries = image.relocations.get(slot, [])
    if len(entries) != 1 or entries[0][0] != 8:
        raise ValueError('missing, duplicate or non-relative relocation')
    info, addend, offset = entries[0]
    if addend < 0:
        raise ValueError('negative relocation addend')
    return {'slot': slot, 'type': info & 0xffffffff, 'symbol': info >> 32,
            'addend': addend, 'file_offset': offset}


def check_windows(image):
    rows = []
    for label, start, end, expected in WINDOWS:
        body = image.read(start, end - start, executable=True)
        if hashlib.sha256(body).hexdigest() != expected:
            raise ValueError('changed instruction window: ' + label)
        containing = [f for f in image.fdes.values() if f['start'] <= start < end <= f['end']]
        if len(containing) != 1:
            raise ValueError('window outside unique selected FDE: ' + label)
        rows.append({'label': label, 'start_va': hex(start), 'end_va': hex(end),
                     'file_offset': hex(image.offset(start, end - start, executable=True)),
                     'fde_start': hex(containing[0]['start']), 'bytes_hex': body.hex(),
                     'sha256': expected})
    return rows


def decode_transfer(image, va, expected_kind):
    raw = image.read(va, 8, executable=True)
    op = raw[0]
    if op in (0xe8, 0xe9):
        kind = 'call' if op == 0xe8 else 'jump'
        length = 5
        target = va + length + struct.unpack_from('<i', raw, 1)[0]
        dest_type = 'va'
    elif raw[:2] == b'\xff\x15':
        kind, length, dest_type = 'call', 6, 'slot'
        target = va + length + struct.unpack_from('<i', raw, 2)[0]
    elif raw[:3] == b'\x41\xff\x55':
        kind, length, dest_type = 'vcall', 4, 'vtable_offset'
        target = raw[3]
    elif op == 0x0f and 0x80 <= raw[1] <= 0x8f:
        kind, length, dest_type = 'branch', 6, 'va'
        target = va + length + struct.unpack_from('<i', raw, 2)[0]
    elif 0x70 <= op <= 0x7f:
        kind, length, dest_type = 'branch', 2, 'va'
        target = va + length + struct.unpack_from('<b', raw, 1)[0]
    elif op == 0xeb:
        kind, length, dest_type = 'jump', 2, 'va'
        target = va + length + struct.unpack_from('<b', raw, 1)[0]
    else:
        raise ValueError('unsupported transfer opcode')
    if kind != expected_kind:
        raise ValueError('unexpected transfer kind')
    if target < 0 or target >= 1 << 64:
        raise ValueError('transfer target outside address space')
    row = {'site_va': hex(va), 'file_offset': hex(image.offset(va, length, executable=True)),
           'bytes_hex': raw[:length].hex(), 'kind': kind, 'target_type': dest_type,
           'target': hex(target)}
    if dest_type == 'va':
        image.offset(target, 1, executable=True)
        f = image.containing_fde(target)
        row['target_fde'] = hex(f['start']) if f else None
    elif dest_type == 'slot':
        reloc = relative_relocation(image, target)
        image.offset(reloc['addend'], 1, executable=True)
        row['resolved_addend'] = hex(reloc['addend'])
        row['relocation_file_offset'] = hex(reloc['file_offset'])
    return row


def transfer_rows(image):
    out = []
    for label, va, kind in EDGES:
        if not any(start <= va < end for _, start, end, _ in WINDOWS):
            raise ValueError('transfer is outside pinned windows: ' + label)
        row = decode_transfer(image, va, kind)
        row['label'] = label
        out.append(row)
    return out


def need(condition, message):
    if not condition:
        raise ValueError(message)


def captures(image):
    """Recognize the straight-line r15-relative capture array, with no gaps."""
    pos = 0x4e34346
    data = image.read(pos, 15, executable=True)
    need(data[:3] == bytes.fromhex('498d87') and data[7:11] == bytes.fromhex('4c89bc24'),
         'capture base setup changed')
    first_offset = struct.unpack_from('<I', data, 11)[0]
    pending = struct.unpack_from('<I', data, 3)[0]
    result = {first_offset: {'state_offset': 0, 'site': pos + 7, 'lea_site': None}}
    pos += 15
    store = image.read(pos, 8, executable=True)
    need(store[:4] == bytes.fromhex('48898424'), 'first capture store changed')
    stack_offset = struct.unpack_from('<I', store, 4)[0]
    result[stack_offset] = {'state_offset': pending, 'site': pos, 'lea_site': pos - 15}
    pos += 8
    while pos < 0x4e34795:
        raw = image.read(pos, 15, executable=True)
        need(raw[:3] == bytes.fromhex('498d87') and raw[7:11] == bytes.fromhex('48898424'),
             'unrecognized capture instruction')
        value = struct.unpack_from('<I', raw, 3)[0]
        dest = struct.unpack_from('<I', raw, 11)[0]
        need(dest not in result, 'duplicate capture stack slot')
        result[dest] = {'state_offset': value, 'site': pos + 7, 'lea_site': pos}
        pos += 15
    need(pos == 0x4e34795, 'capture stream did not end at allocation')
    ordered = sorted(result)
    need(ordered == list(range(first_offset, first_offset + 8 * len(result), 8)),
         'capture stack slots are not contiguous')
    rows = []
    for index, dest in enumerate(ordered):
        c = result[dest]
        rows.append({'index': index, 'stack_offset': hex(dest),
                     'state_offset': hex(c['state_offset']), 'store_va': hex(c['site']),
                     'store_file_offset': hex(image.offset(c['site'], 8, executable=True)),
                     'lea_va': '' if c['lea_site'] is None else hex(c['lea_site'])})
    return rows


def parse_descriptor_stream(image, capture_rows):
    """Symbolically follow only mov/lea forms in the straight-line setup."""
    prologue = image.read(0x54423c0, 7, executable=True)
    need(prologue[:3] == bytes.fromhex('4881ec'), 'dispatcher prologue changed')
    regs = {7: ('base', 0)}
    stack = {}
    pos = 0x54423c7
    end = 0x5442a1e
    while pos < end:
        b = image.read(pos, 8, executable=True)
        rex, op, modrm = b[0], b[1], b[2]
        reg = (((rex >> 2) & 1) << 3) | ((modrm >> 3) & 7)
        mode, rm = modrm >> 6, modrm & 7
        if rex in (0x48, 0x4c) and op == 0x8d and mode == 0 and rm == 5:
            regs[reg] = ('descriptor', pos + 7 + struct.unpack_from('<i', b, 3)[0])
            pos += 7
        elif rex in (0x48, 0x4c) and op == 0x8b and mode == 2 and rm == 7:
            disp = struct.unpack_from('<I', b, 3)[0]
            need(disp % 8 == 0 and disp // 8 < len(capture_rows), 'bad capture index')
            regs[reg] = ('capture', disp // 8)
            pos += 7
        elif rex in (0x48, 0x4c) and op == 0x89 and rm == 4 and b[3] == 0x24 and mode in (1, 2):
            size = 5 if mode == 1 else 8
            dest = b[4] if mode == 1 else struct.unpack_from('<I', b, 4)[0]
            need(reg in regs and dest not in stack, 'undefined register or repeated stack slot')
            stack[dest] = (regs[reg], pos)
            pos += size
        else:
            raise ValueError('unsupported instruction in descriptor setup')
    need(pos == end, 'descriptor setup did not end at checked boundary')
    count_insn = image.read(0x4e3493d, 9, executable=True)
    need(count_insn[:5] == bytes.fromhex('48c7442418'), 'allocation count instruction changed')
    count = struct.unpack_from('<I', count_insn, 5)[0]
    alloc = image.read(0x4e34795, 5, executable=True)
    need(alloc[0] == 0xbf, 'allocation size instruction changed')
    allocation_size = struct.unpack_from('<I', alloc, 1)[0]
    need(allocation_size == count * 24 and len(stack) == count * 2,
         'allocation/descriptor count mismatch')
    need(len(capture_rows) >= count, 'not enough capture slots')
    group_size = len(capture_rows) - count + 1
    rows = []
    for index in range(count):
        in_offset, desc_offset = 0x10 + index * 16, 0x18 + index * 16
        need(in_offset in stack and desc_offset in stack, 'missing descriptor pair')
        source, source_site = stack[in_offset]
        descriptor, desc_site = stack[desc_offset]
        need(descriptor[0] == 'descriptor', 'descriptor pointer not RIP-relative')
        if index == 0:
            need(source == ('base', 0), 'first descriptor is not the capture-array base')
            state_offset, capture_index = 'group', '0..' + str(group_size - 1)
        else:
            expected_index = group_size + index - 1
            need(source == ('capture', expected_index), 'descriptor source order changed')
            state_offset = capture_rows[expected_index]['state_offset']
            capture_index = str(expected_index)
        table = descriptor[1]
        size, align = struct.unpack('<QQ', image.read(table + 8, 16))
        need(size > 0 and align > 0 and align & (align - 1) == 0, 'bad descriptor layout')
        visit = relative_relocation(image, table + 24)
        create = relative_relocation(image, table + 32)
        image.offset(visit['addend'], 1, executable=True)
        image.offset(create['addend'], 1, executable=True)
        rows.append({'index': index, 'capture_index': capture_index, 'state_offset': state_offset,
                     'source_store_va': hex(source_site), 'descriptor_store_va': hex(desc_site),
                     'descriptor_va': hex(table), 'descriptor_file_offset': hex(image.offset(table, 40)),
                     'size': size, 'alignment': align,
                     'visit_target_va': hex(visit['addend']),
                     'visit_relocation_file_offset': hex(visit['file_offset']),
                     'create_target_va': hex(create['addend']),
                     'create_relocation_file_offset': hex(create['file_offset'])})
    return rows, count, allocation_size, group_size


def decode_rip_lea(image, va):
    b = image.read(va, 7, executable=True)
    need(b[0] in (0x48, 0x4c) and b[1] == 0x8d and (b[2] & 0xc7) == 0x05,
         'expected RIP-relative lea')
    return va + 7 + struct.unpack_from('<i', b, 3)[0]


def location_rows(image):
    selected = [
        ('engine_guard', 0x5a07a8a, 'l1/src/abci/engine.rs'),
        ('root_past_guard', 0x5a08dca, 'l1/src/exchange/exchange.rs'),
        ('hash_adapter', 0x548d997, 'l1/src/abci/abci_hash.rs'),
        ('digest_update', 0x160bb6b, 'blake3/src/lib.rs'),
    ]
    rows = []
    for label, ref, suffix in selected:
        address = decode_rip_lea(image, ref)
        reloc = relative_relocation(image, address)
        length, line, column = struct.unpack('<QII', image.read(address + 8, 16))
        need(0 < length <= 1024 and line > 0 and column > 0, 'invalid Location fields')
        path = image.read(reloc['addend'], length)
        need(path.endswith(suffix.encode('ascii')), 'Location path suffix mismatch')
        rows.append({'label': label, 'reference_va': hex(ref), 'location_va': hex(address),
                     'location_file_offset': hex(image.offset(address, 24)),
                     'relocation_file_offset': hex(reloc['file_offset']),
                     'path_va': hex(reloc['addend']), 'path_length': length,
                     'path_suffix': suffix, 'line': line, 'column': column})
    return rows


def constants(image, count, alloc_size, group_size):
    multiplier = image.read(0x5a08742, 10, executable=True)
    rotate = image.read(0x5a08750, 4, executable=True)
    limit = image.read(0x5a08754, 10, executable=True)
    need(multiplier[:2] == b'\x48\xb8' and rotate[:3] == b'\x48\xc1\xc8'
         and limit[:2] == b'\x48\xb9', 'periodic test form changed')
    magic, threshold = struct.unpack_from('<Q', multiplier, 2)[0], struct.unpack_from('<Q', limit, 2)[0]
    shift = rotate[3]
    need(0 < shift < 64 and magic & 1, 'invalid modular test constants')
    divisor = pow(magic, -1, 1 << 64) << shift
    need(divisor < 1 << 64 and threshold == ((1 << 64) - 1) // divisor + 1,
         'periodic test identity failed')
    iv = image.read(0x457ae0, 32)
    freeze_text = b'assertion failed: freeze_height >= self.locus.context.height()'
    need(image.read(0x929b14, len(freeze_text)) == freeze_text, 'freeze diagnostic changed')
    begin_text = b'begin_block'
    need(image.read(0x929dad, len(begin_text)) == begin_text, 'begin label changed')
    need(decode_rip_lea(image, 0x5a08dc3) == 0x929b14, 'freeze literal reference changed')
    need(decode_rip_lea(image, 0x5484143) == 0x929dad, 'begin label reference changed')
    need(image.read(0x459280, 8) == struct.pack('<Q', 1), 'one marker changed')
    need(image.read(0x459348, 8) == struct.pack('<Q', 0), 'zero marker changed')
    args = image.read(0x41c51f6, 10, executable=True)
    need(args[:1] == b'\xbe' and args[5:6] == b'\xb9', 'leaf formatter arguments changed')
    output_size, input_size = struct.unpack_from('<I', args, 1)[0], struct.unpack_from('<I', args, 6)[0]
    prefix_instruction = image.read(0x2eabb62, 5, executable=True)
    need(prefix_instruction[:3] == b'\x66\xc7\x07', 'hex prefix instruction changed')
    prefix = prefix_instruction[3:5]
    need(decode_rip_lea(image, 0x2eabb89) == 0x455d40, 'hex alphabet reference changed')
    alphabet = image.read(0x455d40, 16)
    string_instruction = image.read(0x41c6160, 4, executable=True)
    need(string_instruction[:3] == b'\xc6\x04\x30', 'string tag instruction changed')
    string_tag = string_instruction[3]
    need(input_size == 32 and output_size == 2 + 2 * input_size and prefix == b'0x'
         and alphabet == b'0123456789abcdef' and string_tag == 0xd9,
         'leaf format constants changed')
    first_load = image.read(0x560dbcc, 7, executable=True)
    first_store = image.read(0x560dbe1, 7, executable=True)
    second_load = image.read(0x560dc2b, 7, executable=True)
    second_store = image.read(0x560dc39, 7, executable=True)
    tag_cmp = image.read(0x560dc22, 7, executable=True)
    need(first_load[:3] == bytes.fromhex('488b86') and first_store[:3] == bytes.fromhex('488986')
         and second_load[:3] == bytes.fromhex('498b86') and second_store[:3] == bytes.fromhex('498986')
         and tag_cmp[:5] == bytes.fromhex('66817c2410'), 'item counter instruction changed')
    first_offset = struct.unpack_from('<I', first_load, 3)[0]
    second_offset = struct.unpack_from('<I', second_load, 3)[0]
    need(first_store[3:] == first_load[3:] and second_store[3:] == second_load[3:],
         'item counter load/store offsets differ')
    tag_value = struct.unpack_from('<H', tag_cmp, 5)[0]
    need(image.read(0x560dbd3, 14, executable=True) ==
         bytes.fromhex('48ffc049c7c5ffffffff490f44c5')
         and image.read(0x560dc32, 7, executable=True) == bytes.fromhex('48ffc0490f44c5'),
         'item counter saturation form changed')
    begin_height = image.read(0x5483fd3, 22, executable=True)
    need(begin_height[:3] == bytes.fromhex('498b75')
         and begin_height[4:18] == bytes.fromhex('48ffc648c7c2ffffffff480f45d6')
         and begin_height[18:21] == bytes.fromhex('498955')
         and begin_height[3] == begin_height[21], 'begin height saturation form changed')
    need(image.read(0x5483f8c, 7, executable=True) == bytes.fromhex('413b45600f9ec2')
         and image.read(0x5483f99, 7, executable=True) == bytes.fromhex('413b55640f96c2')
         and image.read(0x5483fa6, 6, executable=True) == bytes.fromhex('413b55687706'),
         'begin comparison form changed')
    need(image.read(0x5a077fc, 2, executable=True) == bytes.fromhex('85c3')
         and image.read(0x5a07808, 10, executable=True) == bytes.fromhex('483b87601c00000f95c3')
         and image.read(0x5a07825, 2, executable=True) == bytes.fromhex('09c3'),
         'engine result flag form changed')
    flag_store = image.read(0x5a07927, 6, executable=True)
    need(flag_store[:2] == bytes.fromhex('8898'), 'engine flag store changed')
    flag_offset = struct.unpack_from('<I', flag_store, 2)[0]
    return {
        'test_multiplier_le_u64': hex(magic), 'rotate_bits': shift,
        'unsigned_limit': hex(threshold), 'derived_divisor': divisor,
        'inverse_mod_2_64': hex(pow(magic, -1, 1 << 64)),
        'capture_records': count, 'capture_group_pointers': group_size,
        'result_slot_allocation_bytes': alloc_size,
        'result_slot_stride_bytes': alloc_size // count,
        'digest_iv_va': hex(0x457ae0), 'digest_iv_bytes_hex': iv.hex(),
        'freeze_literal_va': hex(0x929b14), 'freeze_literal': freeze_text.decode('ascii'),
        'begin_label_va': hex(0x929dad), 'begin_label': begin_text.decode('ascii'),
        'one_marker_va': hex(0x459280), 'zero_marker_va': hex(0x459348),
        'leaf_input_bytes': input_size, 'leaf_hex_bytes': output_size,
        'leaf_hex_prefix': prefix.decode('ascii'),
        'leaf_hex_alphabet_va': hex(0x455d40), 'leaf_hex_alphabet': alphabet.decode('ascii'),
        'leaf_string_tag': hex(string_tag), 'leaf_preimage_bytes': output_size + 2,
        'item_counter_first_offset': hex(first_offset), 'item_counter_second_offset': hex(second_offset),
        'item_counter_second_tag_u16': hex(tag_value),
        'begin_counter_offset': hex(begin_height[3]),
        'engine_result_flag_offset': hex(flag_offset),
    }


def periodic_test(height, magic, rotate, threshold):
    """Model only the pinned unsigned multiply/rotate comparison."""
    need(isinstance(height, int) and 0 <= height < 1 << 64, 'height is not u64')
    need(isinstance(rotate, int) and 0 < rotate < 64, 'bad rotate')
    mask = (1 << 64) - 1
    product = (height * magic) & mask
    rotated = ((product >> rotate) | (product << (64 - rotate))) & mask
    return rotated < threshold


def entry_freeze_model(tag, target, height):
    """Model the selected engine-entry qword comparison only."""
    for value in (tag, target, height):
        need(isinstance(value, int) and 0 <= value < 1 << 64, 'entry value is not u64')
    if tag == 1 and target < height:
        return 'past'
    if tag == 1 and target == height:
        return 'equal'
    return 'continue'


def begin_height_model(height):
    need(isinstance(height, int) and 0 <= height < 1 << 64, 'height is not u64')
    return min(height + 1, (1 << 64) - 1)


def begin_words_model(incoming, current):
    """Return whether the selected mixed-signedness comparison replaces words."""
    need(len(incoming) == 3 and len(current) == 3, 'word tuple length is not three')
    for value in (*incoming, *current):
        need(isinstance(value, int) and 0 <= value < 1 << 32, 'word is not u32')
    def signed32(value):
        return value if value < 1 << 31 else value - (1 << 32)
    return (signed32(incoming[0]), incoming[1], incoming[2]) > (
        signed32(current[0]), current[1], current[2])


def selector_model(height, tag, target, mode, period):
    """Partial branch model; no node instructions are executed."""
    for value in (height, target, period):
        need(isinstance(value, int) and 0 <= value < 1 << 64, 'value is not u64')
    for value in (tag, mode):
        need(isinstance(value, int) and 0 <= value < 1 << 32, 'tag is not u32')
    periodic = height % 10000 == 0
    if not periodic and tag == 1 and target < height:
        return 'past_first'
    special = periodic or (tag == 1 and target == height)
    if mode == 2:
        return 'mode_sentinel'
    if tag == 1 and target < height:
        return 'past_second'
    if special:
        return 'hash_special'
    if period == 0:
        return 'divide_by_zero'
    return 'hash_interval' if height % period == 0 else 'skip_interval'


def leaf_preimage(digest):
    """Model the selected successful leaf-string path, before digest update."""
    need(isinstance(digest, bytes) and len(digest) == 32, 'leaf must be 32 bytes')
    encoded = b'0x' + digest.hex().encode('ascii')
    return b'\xd9' + bytes([len(encoded)]) + encoded


def item_counter_model(first, second, result_tag):
    """Model the two local stores, assuming intervening calls preserve them."""
    for value in (first, second):
        need(isinstance(value, int) and 0 <= value < 1 << 64, 'counter is not u64')
    need(isinstance(result_tag, int) and 0 <= result_tag < 1 << 16, 'tag is not u16')
    maximum = (1 << 64) - 1
    first = min(first + 1, maximum)
    if result_tag == 0x1a2:
        second = min(second + 1, maximum)
    return first, second


def result_flag_model(old_tag, new_tag, old_value, new_value):
    """Model the low output byte from the selected engine-result branch."""
    for value in (old_tag, new_tag):
        need(isinstance(value, int) and 0 <= value < 1 << 32, 'tag is not u32')
    for value in (old_value, new_value):
        need(isinstance(value, int) and 0 <= value < 1 << 64, 'payload is not u64')
    if old_tag & new_tag:
        return int(old_value != new_value)
    return (old_tag | new_tag) & 0xff


def upper_projection(image):
    """Decode the selected argument and return-copy instruction operands."""
    # Each prefix identifies one inspected instruction form. The displacement
    # is parsed from the file, not from disassembler text.
    specs = [
        ('input_owner', 0x4fcb5ac, '4c8b76', 1),
        ('owner_context', 0x4fcb77c, '498d86', 4),
        ('context_state_slot', 0x5a06687, '498b8f', 4),
        ('owner_state_slot', 0x4fcb86d, '498b8e', 4),
        ('engine_result_stack', 0x4fcb788, '488dbc24', 4),
        ('load_fragment_first', 0x4fcb79a, '660f108424', 4),
        ('save_fragment_first', 0x4fcb7a3, '660f294424', 1),
        ('load_fragment_second', 0x4fcb7a9, '488b8424', 4),
        ('save_fragment_second', 0x4fcb7b1, '48894424', 1),
        ('reload_second', 0x4fcb910, '4c8b4424', 1),
        ('record_second', 0x4fcb915, '4c894424', 1),
        ('reload_first', 0x4fcb91a, '660f284424', 1),
        ('record_first', 0x4fcb920, '660f294424', 1),
        ('buffer_load_first', 0x4fcba20, '0f284424', 1),
        ('buffer_store_first', 0x4fcba39, '0f298424', 4),
        ('buffer_load_second', 0x4fcba25, '660f284c24', 1),
        ('buffer_store_second', 0x4fcba41, '660f298c24', 4),
        ('restore_load_first', 0x4fcbab5, '660f288424', 4),
        ('restore_store_first', 0x4fcbaec, '660f294424', 1),
        ('restore_load_second', 0x4fcbabe, '660f288c24', 4),
        ('restore_store_second', 0x4fcbae6, '660f294c24', 1),
        ('output_load_first', 0x4fcbb94, '0f284424', 1),
        ('output_store_first', 0x4fcbbb7, '0f1100', 0),
        ('output_load_second', 0x4fcbb99, '0f284c24', 1),
        ('output_store_second', 0x4fcbbb3, '0f1148', 1),
    ]
    rows, values = [], {}
    for label, va, prefix_hex, length in specs:
        prefix = bytes.fromhex(prefix_hex)
        raw = image.read(va, len(prefix) + length, executable=True)
        need(raw.startswith(prefix), 'projection instruction changed: ' + label)
        value = int.from_bytes(raw[len(prefix):], 'little') if length else 0
        values[label] = value
        rows.append({'label': label, 'instruction_va': hex(va),
                     'file_offset': hex(image.offset(va, len(raw), executable=True)),
                     'bytes_hex': raw.hex(), 'decoded_offset': hex(value)})
    v = values
    need(v['owner_context'] + v['context_state_slot'] == v['owner_state_slot'],
         'state-pointer offset does not join')
    need(v['load_fragment_second'] == v['load_fragment_first'] + 16
         and v['save_fragment_second'] == v['save_fragment_first'] + 16,
         'fragment is not contiguous')
    for chain in (
        ('save_fragment_first', 'reload_first'),
        ('save_fragment_second', 'reload_second'),
        ('record_first', 'buffer_load_first'),
        ('record_second', 'buffer_load_second'),
        ('buffer_store_first', 'restore_load_first'),
        ('buffer_store_second', 'restore_load_second'),
        ('restore_store_first', 'output_load_first'),
        ('restore_store_second', 'output_load_second'),
    ):
        need(v[chain[0]] == v[chain[1]], 'projection stack offsets do not join')
    need(v['output_store_first'] == 0 and v['output_store_second'] == 16,
         'output stores do not join')
    facts = {'input_to_owner_offset': hex(v['input_owner']),
             'owner_to_context_offset': hex(v['owner_context']),
             'context_to_state_pointer_offset': hex(v['context_state_slot']),
             'owner_to_state_pointer_offset': hex(v['owner_state_slot']),
             'engine_result_stack_offset': hex(v['engine_result_stack']),
             'engine_result_fragment_offset': hex(v['load_fragment_first'] - v['engine_result_stack']),
             'fragment_bytes': 16 + 8, 'outer_result_fragment_offset': v['output_store_first'],
             'condition': 'selected normal return and intervening calls preserve recorded stack slots'}
    return rows, facts


def function_rows(image):
    out = []
    for label, start in FUNCTIONS:
        f = image.fdes[start]
        body = image.read(start, f['end'] - start, executable=True)
        out.append({'label': label, 'start_va': hex(start), 'end_va': hex(f['end']),
                    'file_offset': hex(image.offset(start, len(body), executable=True)),
                    'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']),
                    'lsda_va': None if f['lsda'] is None else hex(f['lsda']),
                    'length': len(body), 'body_hex': body.hex(),
                    'sha256': hashlib.sha256(body).hexdigest()})
    return out


def write_json(path, data):
    path.write_text(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + '\n', encoding='ascii')


def write_tsv(path, rows):
    need(bool(rows), 'cannot write an empty table')
    columns = list(dict.fromkeys(key for row in rows for key in row))
    with path.open('w', encoding='ascii', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def extract(data):
    # All analysis, including the complete digest, finishes before any output.
    image = Image(data)
    windows = check_windows(image)
    edges = transfer_rows(image)
    capture_rows = captures(image)
    job_rows, count, alloc_size, group_size = parse_descriptor_stream(image, capture_rows)
    locs = location_rows(image)
    facts = constants(image, count, alloc_size, group_size)
    functions = function_rows(image)
    projection, projection_facts = upper_projection(image)
    need(job_rows[13]['state_offset'] == hex(0x1c58), 'selected freeze capture moved')
    need(job_rows[26]['state_offset'] == hex(0x1c68), 'selected neighboring capture moved')
    summary = {'binary_sha256': DIGEST, 'target': 'node115',
               'selected_fdes': len(functions), 'selected_windows': len(windows),
               'selected_transfers': len(edges), 'capture_pointers': len(capture_rows),
               'descriptor_pairs': len(job_rows),
               'unique_descriptors': len({r['descriptor_va'] for r in job_rows}),
               'locations': len(locs), 'projection_instructions': len(projection),
               'scope': 'selected static path; not a component or whole-node denominator'}
    return {'functions.json': functions, 'windows.json': windows, 'transfers.tsv': edges,
            'captures.tsv': capture_rows, 'jobs.tsv': job_rows, 'locations.tsv': locs,
            'constants.json': facts, 'projection.tsv': projection, 'projection.json': projection_facts,
            'summary.json': summary}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    records = extract(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in records.items():
        if name.endswith('.json'):
            write_json(args.out / name, content)
        else:
            write_tsv(args.out / name, content)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print('abci_block_root115: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
