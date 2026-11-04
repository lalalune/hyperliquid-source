#!/usr/bin/env python3
"""Pin the readers of the RE-015 second structure and the fate of the
phase-2 collect vector at [rsp+0x90] in node 115.

Question 1: what do the second structure's readers do with the two
payload kinds -- the 0x30-byte record under tag 0x63ffbf8 versus the
0x70-byte record under tag 0x63ffc70?  The packet identifies the
structure (a byte-keyed B-tree owned by the large consumer
0x15a3b90..0x15a6509, handle at [rsp+0x1b8]), enumerates its readers,
and pins how each reader treats the payloads.  Question 2: who
consumes the {capacity, buffer, count} vector the collect call leaves
at [rsp+0x90] after phase 2?  The packet pins the slot census of the
whole consumer body and the exact overwrite / forwarding / reset
points.  Static evidence only; no captured code is executed.
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

TAG_A = 0x63ffbf8          # descriptor of the 0x30-byte record
TAG_B = 0x63ffc70          # descriptor of the 0x70-byte snapshot
TAG_REC = 0x63ffbd0        # descriptor of the boxed second record
SENTINEL = 0x8000000000000000

OWNERS = {
    'large_consumer': (CONSUMER, CONSUMER_END, CONSUMER_SHA),
    'entry_take': (
        0x156edc0, 0x156eea9,
        'b17233bfd018fa2c5f0243a29cc392b995b77617e7ad2f0da834a5615f7142c7'),
    'second_tree_drop': (
        0x1542870, 0x15429b2,
        '1112794f86fd4eb9eb110927bb2f59d6da9dd87d7aa4ffa966cc725791abb218'),
    'second_tree_iterator': (
        0x153c5b0, 0x153c96e,
        'c4ae9a2d1e327692d764f385adac7980a4d47fbf4b16294a38b794db798ece22'),
    'payload_drop_30': (
        0x15ac880, 0x15ac904,
        'fe9e166c34d907122fd4f6d01a465639b7c3e4eda4be064eb18aa638c358dc7d'),
    'payload_drop_70': (
        0x15acde0, 0x15acfa5,
        '855c12f2077cd2b57f498096d0649d36b5328d45e23dcdeeba962e99065040ee'),
    'second_record_drop': (
        0x15ac780, 0x15ac872,
        '3ed26c922f030453313ed5dbbda85051eccdcf5482d448c34d7a67892af2dd7c'),
}
BOUNDARIES = {
    'remove_core': (
        0x149e250, 0x149e4b0,
        'e5ddd053172645ada2d11b2c428ee497d39a3b4628f2e6526d3091272e662735'),
    'remove_extract': (
        0x149ca30, 0x149d54e,
        'b0f6bdbbe07571bb652b6348755728d4390fc0e2651944a53332585b782deddc'),
    'tree_insert': (
        0x1497040, 0x1497c54,
        'e5bff7414cd63e3f4e74c81467ee0d344f5cfbee64df648d7ee2ab0454191b26'),
    'element_drop': (
        0x1538bf0, 0x1538ca7,
        'd6c8417424770fcfc18da7bfcf2d5be9974265850b17a3c600ffcdfdbe6bd33a'),
    'drop_b_vec_drain': (
        0x1533e80, 0x1533fda,
        'fd5bae463b4820dc5fc2014b24294ddee43883247220489f977e48f17f52f3f8'),
    'drop_b_vec_finish': (
        0x1538380, 0x1538451,
        'b703177f982529759a33effc05a043d1cf0d0e7071d9a90bd7a12ca0af8e1eb0'),
    'iterator_drop': (
        0x1537f70, 0x1538051,
        'd01645fe60547dee381ca0daa91af5bbea91728299ebf4f4d267cf7f33facfd7'),
    'descriptor_map_insert': (
        0x156f680, 0x15709e9,
        '7aaeefbdcb060aba7030de2292e09df0cc20dca32f20fca54689eea5940f2d6c'),
    'descriptor_emit': (
        0x473c130, 0x473c63f,
        '9b97c0e64ab18d276a48d9477ffba097ca349189c06a2f6d0da3478fb4571515'),
    'format_consumer': (
        0x141e3a0, 0x141e538,
        'aa4d4d0611c533e38c65e1577c0426b5163846c01225556743d4d4345cadd1fe'),
    'write_target': (
        0x1680500, 0x16806c0,
        '1d04ea71bff68d24b04f11ccfc52b1341ef49aabea0b199d73e0c2f7edd43561'),
    'alloc_fn': (
        0x6355830, 0x63558f2,
        '72c29274a75359df7c598d254d102cbab84f51d359256facb415bb90bffec5af'),
    'dealloc_fn': (
        0x635de30, 0x635ded5,
        '714fc5cdd28a2587427c9dac8a25685ec09695a3a21bc9af0eb09b29ae503f61'),
    'map1_drain_helper': (
        0x149e5b0, 0x149e70e,
        '341f372e53bbbca10894eb94e045628d3fb576e6e97824e4ce9cd28a4ce49e0c'),
    'tagged_destroy': (
        0x15a8dc0, 0x15a8e42,
        '1b0a1c17ac54864d04094d8e7265e28894507242ab54f38f9d96b830abd6e927'),
    'panic_entry': (
        0x1680c10, 0x1680c29,
        '6c62896561a5c8454ceb1945a882a798dcaefe52e78852cbbfee08835a16a81e'),
}
WINDOWS = [
    ('consumer_init', PHASE2_START, 0x15a4537),
    ('consumer_branch_a', 0x15a465c, 0x15a4748),
    ('consumer_replace', 0x15a4748, 0x15a4840),
    ('consumer_branch_b', 0x15a48b3, 0x15a4b8f),
    ('consumer_insert', 0x15a4b8f, POSTLOOP_START),
    ('consumer_postloop', POSTLOOP_START, DRAIN_START),
    ('consumer_tail', 0x15a6229, 0x15a63d1),
    ('remove_extract_head', 0x149ca30, 0x149cb10),
]
FULL_EXPORTS = [
    ('entry_take', 0x156edc0, 0x156eea9),
    ('second_tree_drop', 0x1542870, 0x15429b2),
    ('second_tree_iterator', 0x153c5b0, 0x153c96e),
    ('payload_drop_30', 0x15ac880, 0x15ac904),
    ('payload_drop_70', 0x15acde0, 0x15acfa5),
    ('second_record_drop', 0x15ac780, 0x15ac872),
]

CONSUMER_PINS = {
    'init_root_zero': (0x15a44e0, b'H\xc7\x84$\xb8\x01\x00\x00\x00\x00\x00\x00'),
    'init_size_zero': (0x15a44ec, b'H\xc7\x84$\xc8\x01\x00\x00\x00\x00\x00\x00'),
    'init_word_two': (0x15a44f8, b'H\xc7\x84$\xd8\x01\x00\x00\x02\x00\x00\x00'),
    'init_key_word': (0x15a4504, b'f\xc7\x84$\xe0\x01\x00\x00\x01\x00'),
    'probe_key_stage': (0x15a4555, b'\x88\x8c$P\x01\x00\x00'),
    'branch_a_header_load': (0x15a465c, b'\x0f\x10\x84$\x90\x00\x00\x00'),
    'branch_a_header_store': (0x15a4664, b'\x0f)\x84$\xc0\x00\x00\x00'),
    'branch_a_count_load': (0x15a466c, b'H\x8b\x8c$\xa0\x00\x00\x00'),
    'branch_a_count_store': (0x15a4674, b'H\x89\x8c$\xd0\x00\x00\x00'),
    'branch_a_box_alloc': (0x15a46a1, b'A\xff\xd7'),
    'branch_a_box_ptr': (0x15a46d0, b'H\x89\x84$\xc0\x00\x00\x00'),
    'branch_a_record_tag': (0x15a46d8, b'H\x8d\x05\xf1\xb4\xe5\x04'),
    'branch_a_desc_alloc': (0x15a4707, b'A\xff\xd7'),
    'branch_a_tag_lea': (0x15a4730, b'H\x8d\x1d\xc1\xb4\xe5\x04'),
    'tail_root_load_a': (0x15a4737, b'H\x8b\x84$\xb8\x01\x00\x00'),
    'tail_height_load': (0x15a4748, b'H\x8b\x8c$\xc0\x01\x00\x00'),
    'replace_old_payload': (0x15a47e0, b'L\x8bv\xf8'),
    'replace_old_tag': (0x15a47e4, b'L\x8b.'),
    'replace_store_payload': (0x15a47e7, b'L\x89~\xf8'),
    'replace_store_tag': (0x15a47eb, b'H\x89\x1e'),
    'replace_drop_word': (0x15a47ee, b'I\x8bE\x00'),
    'replace_drop_call': (0x15a47fa, b'\xff\xd0'),
    'replace_align_word': (0x15a4810, b'I\x8bE\x10'),
    'branch_b_header_load': (0x15a48b3, b'\x0f\x10\x84$\x90\x00\x00\x00'),
    'branch_b_header_store': (0x15a48bb, b'\x0f)\x84$\xc0\x00\x00\x00'),
    'branch_b_count_load': (0x15a48c3, b'H\x8b\x8c$\xa0\x00\x00\x00'),
    'branch_b_count_store': (0x15a48cb, b'H\x89\x8c$\xd0\x00\x00\x00'),
    'branch_b_box_alloc': (0x15a48f8, b'A\xff\xd7'),
    'branch_b_box_ptr': (0x15a4904, b'I\x89\xc7'),
    'branch_b_slot_ptr': (0x15a492a, b'H\x89\x84$\x90\x00\x00\x00'),
    'branch_b_slot_tag_lea': (0x15a4932, b'H\x8d\x05\x97\xb2\xe5\x04'),
    'branch_b_slot_tag': (0x15a4939, b'H\x89\x84$\x98\x00\x00\x00'),
    'branch_b_slot_flag': (0x15a4941, b'\xc6\x84$\xa0\x00\x00\x00\x01'),
    'branch_b_format_arg': (0x15a4974, b'H\x8d\xbc$\xc0\x00\x00\x00'),
    'insert_record_word0': (0x15a4a47, b'L\x89d$ '),
    'insert_record_tag1': (0x15a4a4c, b'H\x8d\re\xb2\xe5\x04'),
    'insert_record_tag2': (0x15a4a5d, b'H\x8d\x05\x84\xb2\xe5\x04'),
    'insert_arg_record': (0x15a4a8f, b'L\x89\xef'),
    'insert_arg_slot': (0x15a4a92, b'L\x8d\xa4$\x90\x00\x00\x00'),
    'insert_arg_value': (0x15a4a9a, b'L\x89\xe6'),
    'insert_value_tag': (0x15a4aa3, b'L\x8d\x05~\xb1\xe5\x04'),
    'snapshot_stage_first': (0x15a4acb, b'\x0f\x10\x84$\x80\x00\x00\x00'),
    'snapshot_alloc_size': (0x15a4b29, b'\xbfp\x00\x00\x00'),
    'branch_b_tag_lea': (0x15a4b8f, b'H\x8d\x1d\xda\xb0\xe5\x04'),
    'tail_root_load_b': (0x15a4b96, b'H\x8b\x84$\xb8\x01\x00\x00'),
    'empty_height_store': (0x15a4bf4, b'H\xc7\x84$\xc0\x01\x00\x00\x00\x00\x00\x00'),
    'empty_count_one': (0x15a4c00, b'f\xc7\x80\xba\x00\x00\x00\x01\x00'),
    'empty_size_inc': (0x15a4c17, b'I\xffF\x10'),
    'lookup_handle_ptr': (0x15a4cc0, b'L\x8d\xb4$\xb8\x01\x00\x00'),
    'lookup1_keybyte': (0x15a4cfa, b'D\x0f\xb6\x84\x10\xbd\x00\x00\x00'),
    'lookup1_neg': (0x15a4d03, b'I\xf7\xd8'),
    'lookup1_cursor_node': (0x15a4d50, b'H\x89D$ '),
    'take_kind_cmp_1': (0x15a4d74, b'\x80\xbc$\xc0\x00\x00\x00\x04'),
    'take_word_a_store_1': (0x15a4d8a, b'H\x89\x84$\x10\x02\x00\x00'),
    'take_word_a_null_1': (0x15a4d92, b'H\x85\xc0'),
    'take_word_b_store_1': (0x15a4da3, b'H\x89\x84$\x08\x02\x00\x00'),
    'lookup2_root': (0x15a4dab, b'H\x8b\x84$\xb8\x01\x00\x00'),
    'lookup2_keybyte': (0x15a4dea, b'D\x0f\xb6\x84\x10\xbd\x00\x00\x00'),
    'take_kind_cmp_2': (0x15a4e64, b'\x80\xbc$\xc0\x00\x00\x00\x04'),
    'take_word_a_store_2': (0x15a4e7a, b'H\x89\x84$ \x02\x00\x00'),
    'take_word_b_store_2': (0x15a4e93, b'H\x89\x84$\x18\x02\x00\x00'),
    'select_byte_load': (0x15a4f5b, b'\x0f\xb6D$\x17'),
    'overwrite_word0': (0x15a4f79, b'H\x89\x8c$\x90\x00\x00\x00'),
    'overwrite_word1': (0x15a4f81, b'H\x89\x84$\x98\x00\x00\x00'),
    'write_arg_word0': (0x15a4f89, b'L\x89\xa4$\xc0\x00\x00\x00'),
    'vec_reset_0': (0x15a5019, b'H\xc7\x84$\x90\x00\x00\x00\x00\x00\x00\x00'),
    'vec_reset_8': (0x15a5025, b'H\xc7\x84$\x98\x00\x00\x00\x08\x00\x00\x00'),
    'vec_reset_10': (0x15a5031, b'H\xc7\x84$\xa0\x00\x00\x00\x00\x00\x00\x00'),
    'assembled_copy_a1': (0x15a5129, b'H\x89D$P'),
    'assembled_copy_b1': (0x15a5136, b'H\x89D$X'),
    'assembled_copy_a2': (0x15a5269, b'H\x89D$P'),
    'assembled_copy_b2': (0x15a5276, b'H\x89D$X'),
    'unwind_drop_b_arg': (0x15a622c, b'H\x8d\xbc$\xc0\x00\x00\x00'),
    'unwind_drop_rec_arg': (0x15a62cb, b'L\x89\xff'),
    'unwind_drop_rec2_arg': (0x15a639c, b'H\x8d\xbc$\xc0\x00\x00\x00'),
    'unwind_drop_rec3_arg': (0x15a63b4, b'H\x8d\xbc$\xc0\x00\x00\x00'),
    'tail_handle_arg': (0x15a63c4, b'H\x8d\xbc$\xb8\x01\x00\x00'),
}
SLOT_CALL_PINS = {
    'branch_a_bind_call': (0x15a46fc, 0x64e1458),
    'replace_dealloc_call': (0x15a4830, 0x64df4a0),
    'branch_b_format_call': (0x15a498b, 0x64df6e8),
    'branch_b_emit_call': (0x15a49b1, 0x64e1460),
    'branch_b_buffer_free': (0x15a49f5, 0x64df4a0),
    'write_call': (0x15a4fb4, 0x64df6f0),
}
LEA_TARGET_PINS = {
    'branch_a_record_tag': TAG_REC,
    'branch_a_tag_lea': TAG_A,
    'branch_b_slot_tag_lea': TAG_REC,
    'branch_b_tag_lea': TAG_B,
    'insert_record_tag1': 0x63ffcb8,
    'insert_record_tag2': 0x63ffce8,
    'insert_value_tag': 0x63ffc28,
}
TAKE_PINS = {
    'cursor_handle_load': (0x156eded, b'I\x8bF\x18'),
    'size_dec': (0x156edf1, b'H\xffH\x10'),
    'remove_core_call': (0x156edde, b'\xe8m\xf4\xf2\xff'),
    'root_flag_test': (0x156edf5, b'\x80|$\x0f\x01'),
    'local_word0_load': (0x156ede3, b'L\x8b|$ '),
    'local_pair_load': (0x156ede8, b'\x0f\x10D$('),
    'root_child_load': (0x156ee12, b'H\x8b\x97\xc8\x00\x00\x00'),
    'root_store': (0x156ee19, b'H\x89\x10'),
    'new_root_link_clear': (0x156ee23, b'H\xc7\x82\xb0\x00\x00\x00\x00\x00\x00\x00'),
    'old_node_size': (0x156ee2e, b'\xbe(\x01\x00\x00'),
    'out_word0_store': (0x156ee40, b'L\x89;'),
    'out_pair_store': (0x156ee43, b'\x0f\x11C\x08'),
}
TREE_DROP_PINS = {
    'handle_root_load': (0x154287e, b'H\x8b\x0f'),
    'handle_height_load': (0x1542886, b'H\x8bW\x08'),
    'handle_size_load': (0x154288a, b'H\x8bG\x10'),
    'cursor_a_root': (0x1542897, b'H\x89L$0'),
    'cursor_b_root': (0x15428aa, b'H\x89L$P'),
    'cursor_size': (0x15428c9, b'H\x89D$`'),
    'iterator_call_first': (0x15428d8, b'\xe8\xd3\x9c\xff\xff'),
    'yield_node_load': (0x15428dd, b'H\x8bD$\x08'),
    'yield_index_load': (0x1542915, b'H\x8bL$\x18'),
    'value_payload_load': (0x154291e, b'L\x8b<\x08'),
    'value_tag_load': (0x1542922, b'L\x8bl\x08\x08'),
    'descriptor_drop_word': (0x1542927, b'I\x8bE\x00'),
    'descriptor_drop_call': (0x1542933, b'\xff\xd0'),
    'descriptor_size_load': (0x1542935, b'I\x8bu\x08'),
    'descriptor_align_load': (0x154293e, b'I\x8bE\x10'),
    'iterator_call_next': (0x1542906, b'\xe8\xa5\x9c\xff\xff'),
    'iterator_drop_call': (0x154299f, b'\xe8\xccU\xff\xff'),
}
ITERATOR_PINS = {
    'countdown_load': (0x153c5be, b'H\x8bF@'),
    'child_descent': (0x153c610, b'H\x8b\xbf\xc8\x00\x00\x00'),
    'dealloc_site_c': (0x153c91a, b'\xff\x15\x80+\xfa\x04'),
    'dealloc_site_d': (0x153c94a, b'\xff\x15P+\xfa\x04'),
}
DROP_A_PINS = {
    'second_record_ptr': (0x15ac885, b'H\x8b_\x18'),
    'second_record_tag': (0x15ac889, b'L\x8b\x7f '),
    'second_record_drop_word': (0x15ac88d, b'I\x8b\x07'),
    'second_record_drop_call': (0x15ac898, b'\xff\xd0'),
    'second_record_size': (0x15ac89a, b'I\x8bw\x08'),
    'second_record_align': (0x15ac8a3, b'I\x8bG\x10'),
}
DROP_B_PINS = {
    'word40_load': (0x15acdeb, b'H\x8bw@'),
    'word40_neg': (0x15acdf2, b'H\xf7\xd8'),
    'byte58_gate': (0x15acdf7, b'\x80{\x58\x00'),
    'vec_addr': (0x15acdfd, b'L\x8d{@'),
    'vec_drain_call': (0x15ace04, b'\xe8wp\xf8\xff'),
    'vec_finish_call': (0x15ace15, b'\xe8f\xb5\xf8\xff'),
    'buf_ptr_load': (0x15ace22, b'H\x8b{H'),
    'buf_dealloc': (0x15ace28, b'\xff\x15r&\xf3\x04'),
    'fd_load': (0x15ace2e, b'\x8b{\x5c'),
    'pair0_size_load': (0x15ace37, b'H\x8b3'),
    'pair0_ptr_load': (0x15ace3f, b'H\x8b{\x08'),
    'pair0_dealloc': (0x15ace45, b'\xff\x15U&\xf3\x04'),
    'tagged1_data': (0x15ace4b, b'L\x8b{\x18'),
    'tagged1_tag': (0x15ace4f, b'L\x8bc '),
    'tagged1_drop_call': (0x15ace5f, b'\xff\xd0'),
    'tagged2_data': (0x15ace8d, b'L\x8b{('),
    'tagged2_tag': (0x15ace91, b'H\x8b[\x30'),
    'tagged2_drop_call': (0x15acea0, b'\xff\xd0'),
}
DROP_REC_PINS = {
    'vec_buffer': (0x15ac78e, b'L\x8bw\x08'),
    'vec_count': (0x15ac792, b'L\x8bo\x10'),
    'elem_step': (0x15ac7a6, b'L\x8dgX'),
    'element_drop_call': (0x15ac7ad, b'\xe8>\xc4\xf8\xff'),
    'element_drop_call_unwind': (0x15ac81d, b'\xe8\xce\xc3\xf8\xff'),
    'buffer_cap': (0x15ac7b7, b'H\x8b\x03'),
    'buffer_size': (0x15ac7bf, b'H\x6b\xf0X'),
    'buffer_free': (0x15ac7c8, b'\xff\x15\xd2,\xf3\x04'),
    'string_len': (0x15ac7ce, b'H\x8bs\x18'),
    'string_ptr': (0x15ac7d7, b'H\x8b{ '),
    'string_free': (0x15ac7eb, b'\xff%\xaf,\xf3\x04'),
}
REMOVE_EXTRACT_PINS = {
    'extract_key_byte': (0x149ca66, b'B\x0f\xb6\x845\xbc\x00\x00\x00'),
    'extract_pair_save': (0x149caa9, b'\x0f)\x84$\x90\x00\x00\x00'),
    'extract_count_store': (0x149caca, b'f\x89\xbd\xba\x00\x00\x00'),
}
HELPER_PIN_TABLES = {
    'entry_take': TAKE_PINS,
    'second_tree_drop': TREE_DROP_PINS,
    'second_tree_iterator': ITERATOR_PINS,
    'payload_drop_30': DROP_A_PINS,
    'payload_drop_70': DROP_B_PINS,
    'second_record_drop': DROP_REC_PINS,
}
DESCRIPTORS = [TAG_A, TAG_B, TAG_REC, 0x63ffcb8, 0x63ffce8, 0x63ffb78,
               0x63ffc28]
PANIC_STATICS = [0x63ffb48, 0x63ffb60]
CALL_CENSUS_EXPECTED = {
    'second_tree_drop': ['0x15a54fc', '0x15a63cc'],
    'entry_take': ['0x15a4d6f', '0x15a4e5f'],
    'remove_core': ['0x156edde'],
    'remove_extract': ['0x149e365', '0x149e42a'],
    'tree_insert': ['0x15a4c88'],
    'second_tree_iterator': ['0x1537f87', '0x1537fb6', '0x15428d8',
                             '0x1542906'],
    'payload_drop_30': [],
    'payload_drop_70': ['0x15a6234'],
    'second_record_drop': ['0x15a62ce', '0x15a63a4', '0x15a63bc'],
    'element_drop': ['0x153957d', '0x15395cd', '0x156aaed', '0x156ab5d',
                     '0x15ac7ad', '0x15ac81d'],
    'iterator_drop': ['0x154299f'],
    'descriptor_map_insert': ['0x15a4ab4'],
}
CALL_CENSUS_TARGETS = {
    'second_tree_drop': 0x1542870, 'entry_take': 0x156edc0,
    'remove_core': 0x149e250, 'remove_extract': 0x149ca30,
    'tree_insert': 0x1497040, 'second_tree_iterator': 0x153c5b0,
    'payload_drop_30': 0x15ac880, 'payload_drop_70': 0x15acde0,
    'second_record_drop': 0x15ac780, 'element_drop': 0x1538bf0,
    'iterator_drop': 0x1537f70, 'descriptor_map_insert': 0x156f680,
}


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


def _rip_target(data, site, insn_len):
    raw = read(data, site, insn_len)[1]
    disp = struct.unpack('<i', raw[-4:])[0]
    return site + insn_len + disp


def _slot_call(data, site, slot, label):
    raw = read(data, site, 6)[1]
    require(raw[:2] == b'\xff\x15', f'{label} is not a slot call')
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
    dstr = next((s for s in sections(data) if s['name'] == '.dynstr'), None)
    require(ds is not None, 'missing.dynsym section')
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
        'alloc': 0x64df480, 'dealloc': 0x64df4a0, 'panic': 0x64df830,
        'write': 0x64df6f0, 'format_consumer': 0x64df6e8,
        'descriptor_bind': 0x64e1458, 'descriptor_emit': 0x64e1460,
        'grow_474e500': 0x64e1468, 'grow_474e420_a': 0x64e1470,
        'grow_474e420_b': 0x64e1478, 'grow_5c8b150': 0x64e0c10,
        'memmove': 0x64df568, 'close': 0x64dfe78,
    }
    out = {}
    for name, slot in wanted.items():
        require(slot in rel, f'missing relocation for slot {slot:#x}')
        entry = rel[slot]
        row = {'slot': hex(slot), 'type': entry['type'],
               'addend': hex(entry['addend'])}
        if entry['type'] == 6:
            row['symbol'] = _dynsym_name(data, entry['symbol'])
        out[name] = row
    return out


def descriptors(data):
    rel = _relocations(data)
    out = {}
    for va in DESCRIPTORS:
        words = struct.unpack('<QQQ', read(data, va, 0x18)[1])
        entry = rel.get(va)
        drop = entry['addend'] if entry and entry['type'] == 8 \
            else words[0]
        out[hex(va)] = {
            'file_drop_word': hex(words[0]),
            'drop': hex(drop),
            'drop_source': 'rela_relative' if entry else 'file_word',
            'size': hex(words[1]), 'align': hex(words[2])}
    for va in PANIC_STATICS:
        words = struct.unpack('<QQQ', read(data, va, 0x18)[1])
        entry = rel.get(va)
        out[hex(va)] = {
            'kind': 'panic_location',
            'file_word': hex(words[0]),
            'file_target': hex(entry['addend']) if entry else None,
            'path_len': hex(words[1]),
            'line_col': hex(words[2])}
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


def _access_kind(text):
    if text.startswith('lea'):
        return 'address'
    import re
    if re.match(r'(mov|movups|movaps|movzx|movsx|cmp|test|inc|dec)\s+'
                r'(QWORD PTR|XMMWORD PTR|BYTE PTR|WORD PTR|DWORD PTR) '
                r'\[rsp', text):
        return 'store_or_test'
    return 'load'


def stack_census(textmap):
    handle_slots = ['0x1b8', '0x1c0', '0x1c8', '0x1d8']
    vec_slots = ['0x90', '0x98', '0xa0']
    handle, vec = {}, {}
    for slot in handle_slots:
        rows = [{'site': hex(s), 'region': _region(s),
                 'kind': _access_kind(t), 'text': t}
                for s, (_, t) in sorted(textmap.items())
                if f'[rsp+{slot}]' in t]
        handle[slot] = rows
    for slot in vec_slots:
        rows = [{'site': hex(s), 'region': _region(s),
                 'kind': _access_kind(t), 'text': t}
                for s, (_, t) in sorted(textmap.items())
                if f'[rsp+{slot}]' in t]
        vec[slot] = rows
    return {'handle': handle, 'collect_vector': vec}


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


def rip_ref_census(data):
    """Binary-wide RIP-relative reference census for the three tags.

    Every 4-byte field in .text whose value, read as a disp32 ending
    0, 1 or 4 bytes before an instruction end, names the tag is a
    candidate; candidates are validated against the consumer's
    instruction map by the caller.  Absolute imm64 occurrences are
    counted separately.
    """
    sec = next((s for s in sections(data) if s['name'] == '.text'), None)
    require(sec is not None, 'missing.text section')
    base, off, size = sec['address'], sec['offset'], sec['size']
    raw = bytes(data[off:off + size])
    tags = (TAG_A, TAG_B, TAG_REC)
    tag_set = frozenset(tags)
    by_key = {(tag, delta): [] for tag in tags for delta in (0, 1, 4)}
    unpack_from = struct.unpack_from
    # Standard-library-only scan: the disp32 at each position is read
    # as a signed little-endian word, exactly as the previous
    # vectorised computation did (its int32 arithmetic wraps to the signed value,
    # and a wrapped sum can never equal one of the small positive tags
    # unless the unwrapped sum does, so plain integer comparison here
    # yields the same candidate set).
    for i in range(max(size - 3, 0)):
        disp = unpack_from('<i', raw, i)[0]
        target = base + i + 4 + disp
        if target in tag_set:
            by_key[(target, 0)].append({'disp_field': hex(base + i),
                                        'end_delta': 0})
        if target + 1 in tag_set:
            by_key[(target + 1, 1)].append({'disp_field': hex(base + i),
                                            'end_delta': 1})
        if target + 4 in tag_set:
            by_key[(target + 4, 4)].append({'disp_field': hex(base + i),
                                            'end_delta': 4})
    out = {}
    for tag in tags:
        rows = []
        for delta in (0, 1, 4):
            rows.extend(by_key[(tag, delta)])
        imm = []
        pat = struct.pack('<Q', tag)
        i = raw.find(pat)
        while i != -1:
            imm.append(hex(base + i))
            i = raw.find(pat, i + 1)
        out[hex(tag)] = {'rip_candidates': rows, 'imm64_sites': imm}
    return out


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
    desc = descriptors(data)
    # Cheap byte-exact checks first, so counterfactual mutations are
    # rejected before the binary-wide censuses run.
    _pins(data, CONSUMER_PINS, 'consumer')
    for label, (site, slot) in SLOT_CALL_PINS.items():
        _slot_call(data, site, slot, f'consumer {label}')
    for label, target in LEA_TARGET_PINS.items():
        site, raw = CONSUMER_PINS[label]
        if _rip_target(data, site, len(raw)) != target:
            raise ValueError(f'consumer lea target changed for {label}')
    for role, table in HELPER_PIN_TABLES.items():
        _pins(data, table, role)
    _pins(data, REMOVE_EXTRACT_PINS, 'remove_extract')
    if desc[hex(TAG_A)]['size'] != '0x30' or \
            desc[hex(TAG_A)]['drop'] != '0x15ac880':
        raise ValueError('tag A descriptor changed')
    if desc[hex(TAG_B)]['size'] != '0x70' or \
            desc[hex(TAG_B)]['drop'] != '0x15acde0':
        raise ValueError('tag B descriptor changed')
    if desc[hex(TAG_REC)]['size'] != '0x30' or \
            desc[hex(TAG_REC)]['drop'] != '0x15ac780':
        raise ValueError('second-record descriptor changed')
    if bindings['close'].get('symbol') != 'close':
        raise ValueError('close slot binding changed')
    if bindings['memmove'].get('symbol') != 'memmove':
        raise ValueError('memmove slot binding changed')
    census = direct_call_census(data)
    for name, expected in CALL_CENSUS_EXPECTED.items():
        if census[name]['sites'] != expected:
            raise ValueError(f'direct call census changed for {name}')
    rip = rip_ref_census(data)
    textmap = consumer_textmap(data)
    stacks = stack_census(textmap)
    # RIP census candidates must all be genuine instruction ends
    # inside the large consumer.
    ins_ends = {}
    for site, (raw, text) in textmap.items():
        ins_ends.setdefault(site + len(raw), site)
    for tag, row in rip.items():
        if row['imm64_sites']:
            raise ValueError(f'imm64 reference to {tag}')
        for cand in row['rip_candidates']:
            field = int(cand['disp_field'], 16)
            if cand['end_delta'] == 0:
                start = ins_ends.get(field + 4)
                if start is None or not (CONSUMER <= start < CONSUMER_END):
                    raise ValueError(f'unvalidated RIP candidate for {tag}')
                cand['instruction'] = hex(start)
    if [c['instruction'] for c in rip[hex(TAG_A)]['rip_candidates']] != \
            ['0x15a4730']:
        raise ValueError('tag A reference census changed')
    if [c['instruction'] for c in rip[hex(TAG_B)]['rip_candidates']] != \
            ['0x15a4b8f']:
        raise ValueError('tag B reference census changed')
    if [c['instruction'] for c in rip[hex(TAG_REC)]['rip_candidates']] != \
            ['0x15a46d8', '0x15a4932']:
        raise ValueError('second-record tag reference census changed')
    # Stack census negatives for question 2.
    vec = stacks['collect_vector']
    for slot, rows in vec.items():
        post = [r for r in rows if r['region'] == 'postloop']
        if any(int(r['site'], 16) < 0x15a4f79 for r in post):
            raise ValueError(f'post-loop access to [rsp+{slot}] before '
                             'the overwrite point')
        loads = [int(r['site'], 16) for r in post if r['kind'] == 'load']
        if loads and min(loads) < 0x15a505b:
            raise ValueError(f'post-loop load of [rsp+{slot}] before '
                             'the reset reuse')
    if any(r['region'] == 'postloop' and int(r['site'], 16) < 0x15a5031
           for r in vec['0xa0']):
        raise ValueError('count word touched between overwrite and reset')
    handle = stacks['handle']
    if [r['site'] for r in handle['0x1d8']] != ['0x15a44f8']:
        raise ValueError('handle +0x20 word access census changed')
    if [r['site'] for r in handle['0x1c8']] != ['0x15a44ec']:
        raise ValueError('handle size word direct access census changed')
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}

    def frame_records(a, b, sha, role):
        if (a, b) not in fdes:
            raise ValueError(f'{role} scope FDE changed')
        offset, raw = read(data, a, b - a)
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError(f'{role} body changed')
        records = {}
        for kind in ['fde', 'cie']:
            va = fdes[(a, b)][kind]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            records[kind] = {'va': hex(va),
                             'bytes_hex': read(data, va, n)[1].hex()}
        return {'role': role, 'start': hex(a), 'end': hex(b),
                'file_offset': hex(offset), 'bytes': b - a,
                'sha256': sha, 'frames': records}

    owners = [frame_records(a, b, sha, role)
              for role, (a, b, sha) in OWNERS.items()]
    boundaries = [frame_records(a, b, sha, role)
                  for role, (a, b, sha) in BOUNDARIES.items()]
    return {
        'target_sha256': SHA, 'owners': owners, 'boundaries': boundaries,
        'slot_bindings': bindings, 'descriptors': desc,
        'direct_calls': census, 'rip_references': rip,
        'stack_census': stacks,
        'structure': {
            'owner': 'large consumer 0x15a3b90..0x15a6509, one instance '
                     'per field-loop iteration',
            'handle': '[rsp+0x1b8] {root +0x0, height +0x8 at '
                      '[rsp+0x1c0], size +0x10 at [rsp+0x1c8]}; born '
                      'empty in the phase-2 init (root and size stored '
                      'zero; the height word is first stored by the '
                      'first-node creation path)',
            'keying': 'single byte keys staged from the key-byte '
                      'buffer at [rsp+0x1e0] (init word 1: bytes '
                      '{0x01, 0x00}); node count word at +0xba, key '
                      'bytes at +0xbc, value pairs {payload, tag} at '
                      'node + index*0x10, children at +0xc8',
            'writers': 'insert-or-replace in the shared phase-2 tail '
                       '(replace in place on a hit, tree insert '
                       '0x1497040 on a non-empty miss, inline '
                       'first-node creation on an empty tree)'},
        'readers_verdict':
            'Retrieval is keyed, never tag-dispatched.  (1) Two '
            'post-loop lookups walk the tree for byte keys 0 and 1; '
            'on a hit each builds a cursor {node, height, index, '
            'handle} and calls the take helper 0x156edc0, which '
            'decrements the handle size word and returns the removed '
            'entry through the remove core 0x149e250.  The consumer '
            'tests the returned record\'s first byte against 4 and '
            'its +0x8 word against zero -- both failures branch to '
            'panic arms (location statics 0x63ffb48 / 0x63ffb60, '
            'base/src/log/handle.rs lines 144/145) -- and otherwise '
            'copies the +0x8 / +0x10 words opaquely into the '
            'assembled records; neither word is dereferenced in the '
            'consumer and no tag address is ever compared.  Empty '
            'tree and descent underflow take the same panic arms.  '
            '(2) The replace arm of the phase-2 tail reads the old '
            'entry\'s tag descriptor: it calls descriptor word 0 '
            '(drop) on the old payload when non-null and frees the '
            'old payload through the dealloc slot with the class '
            'from descriptor words +0x8/+0x10.  (3) The tree drop '
            '0x1542870 (called at the end of post-loop processing '
            'and on the unwind tail) drives the consuming iterator '
            '0x153c5b0 and destroys every remaining entry the same '
            'descriptor-driven way; the iterator frees the nodes '
            'through the dealloc slot.  Payload field use happens '
            'only inside the two drop functions: drop 0x15ac880 '
            '(tag 0x63ffbf8) reads only payload +0x18 (boxed '
            'second-record pointer) and +0x20 (its tag descriptor), '
            'dropping the boxed record through descriptor '
            '0x63ffbd0 and freeing it with that descriptor\'s size '
            'word; the 0x30 record\'s configuration words and flag '
            'byte are never read.  Drop 0x15acde0 (tag 0x63ffc70) '
            'sentinel-tests the word at +0x40 (0x8000000000000000 '
            'skips the vector drain, the buffer free and the close '
            'call), gates an element drain of the vector at +0x40 '
            'on the byte at +0x58, frees (+0x48, +0x40) and '
            '(+0x8, +0x0) through the dealloc slot, passes the '
            'dword at +0x5c to close, and destroys the tagged pairs '
            '{+0x18, +0x20} and {+0x28, +0x30} through their '
            'descriptors.  The boxed second record\'s drop '
            '0x15ac780 drops its 0x58-byte elements backwards '
            'through 0x1538bf0, frees the buffer with size '
            'capacity * 0x58, and frees the boxed string {length '
            '+0x18, pointer +0x20}.  The consumer tail also calls '
            'drop 0x15acde0 once and drop 0x15ac780 three times '
            'directly on stack/heap copies on unwind paths.  '
            'Binary-wide censuses close the reader set: the three '
            'tag descriptors are referenced by RIP-relative '
            'instructions only at the four store-side lea sites in '
            'the consumer, the drop function for tag 0x63ffbf8 has '
            'zero direct call sites (descriptor-only reach), and '
            'every direct call to the take/tree-drop/iterator '
            'helpers is inside the consumer or its own helper '
            'chain.',
        'vector_verdict':
            'After phase 2 the [rsp+0x90] header words are never '
            'read again inside the consumer.  In the sentinel '
            'branch they survive only as the copies the branch made '
            'into the boxed second record inside phase 2 (#2490); '
            'in the non-sentinel branch the slot itself is '
            'overwritten within phase 2 with {boxed second-record '
            'pointer, tag 0x63ffbd0, flag byte 1} and forwarded by '
            'pointer (rsi = &[rsp+0x90]) as the value argument of '
            'the descriptor map insert 0x156f680.  The post-loop '
            'census is empty for all three slots until 0x15a4f79, '
            'where a table pair selected by the byte at [rsp+0x17] '
            'overwrites +0x0/+0x8; the count word at +0x10 is not '
            'touched at all between phase 2 and the reset.  The '
            'slot address is forwarded once more as word 0 of the '
            'format-argument record for the write call through '
            'slot 0x64df6f0 (target 0x1680500, #2424).  At '
            '0x15a5019..0x15a503d the slot is reset to {0, 8, 0} '
            'and reused as a fresh vector; every later load belongs '
            'to that new vector, and the drain region reuses the '
            'slot a third time (#2479).  The collect vector\'s '
            'element records are therefore consumed only through '
            'the second record (boxed copy) and, on the destroy '
            'path, by the second record\'s drop; no element is read '
            'through the [rsp+0x90] header after phase 2.',
        'limits':
            'Static trace only.  The remove core 0x149e250 (608 '
            'bytes) and remove extract 0x149ca30 (2,846 bytes; head '
            'window exported) are hash-pinned boundaries: the '
            'extraction of {key byte, value pair} and the node '
            'count decrement are pinned at the head window, the '
            'promotion/rebalancing internals are not traced, and '
            'the exact provenance of the take record\'s first byte '
            '(compared against 4 by the consumer) is asserted only '
            'at the consumer\'s compare pins.  The tree insert '
            '0x1497040, the snapshot element drain helpers '
            '0x1533e80 / 0x1538380, the element drop 0x1538bf0, the '
            'iterator drop 0x1537f70, the descriptor map insert '
            '0x156f680, the emit function 0x473c130, the tagged '
            'destroy 0x15a8dc0 and the panic entry 0x1680c10 are '
            'hash-pinned boundaries.  The descriptor behind slot '
            '0x64e1458 and the collect function are #2490/#2479 '
            'owners; the format consumer is the #2408 owner; the '
            'write target is the #2424 owner.  What the iterator '
            '0x153c5b0 does beyond yielding (node, index) pairs and '
            'freeing exhausted nodes through the dealloc slot -- '
            'its exact traversal state machine -- is not traced.  '
            'The handle word at [rsp+0x1d8] (stored 2 at init) is '
            'never read anywhere in the consumer body (stack '
            'census); its role belongs to the frame layout outside '
            'the traced regions.  The 0x70 snapshot\'s fields are '
            'claimed only at the offsets drop 0x15acde0 loads; no '
            'semantic identity is asserted for snapshot fields the '
            'drop does not read.  No captured code executed, no '
            'runtime value or reconstruction gate is claimed.',
        'next_question':
            'Who reads the two assembled 0x40-byte records the '
            'post-loop region appends (carrying the taken entries\' '
            '+0x8/+0x10 words at their +0x8/+0x10 slots) once the '
            'drain region (0x15a5501..0x15a5861) and the consumer '
            'tail take over -- in particular the role of the '
            'map-#1 drain helper 0x149e5b0 (examined here only to '
            'exclude it: it walks map-#1 node offsets '
            '+0x112/+0x120) and the final disposition of the '
            'extracted words.'}


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
        # Every pinned consumer site must be a native instruction
        # start in the full owner body.
        asm = _objdump(snapshot, CONSUMER, CONSUMER_END)
        ins = decode_export(asm, CONSUMER, CONSUMER_END,
                            read(data, CONSUMER,
                                 CONSUMER_END - CONSUMER)[1])
        sites = {site for site, _ in CONSUMER_PINS.values()}
        sites |= {site for site, _ in SLOT_CALL_PINS.values()}
        sites |= {int(row['site'], 16)
                  for name in ('second_tree_drop', 'entry_take',
                               'payload_drop_70', 'second_record_drop')
                  for row in report['direct_calls'][name]['rows']
                  if row['owner_fde'] == [hex(CONSUMER),
                                          hex(CONSUMER_END)]}
        if not sites <= set(ins):
            raise ValueError('consumer evidence site not native '
                             'instruction start')
        for name, wa, wb in WINDOWS:
            wasm = _objdump(snapshot, wa, wb)
            decode_export(wasm, wa, wb, read(data, wa, wb - wa)[1])
            (output / f'{name}_window_{wa:x}_{wb:x}_objdump.txt'
             ).write_bytes(wasm.replace(
                 str(snapshot), '<authenticated-node115>').encode('utf-8'))
        # Full exports for the smaller owners, with every pinned
        # site validated as an instruction start.
        for name, a, b in FULL_EXPORTS:
            easm = _objdump(snapshot, a, b)
            eins = decode_export(easm, a, b, read(data, a, b - a)[1])
            esites = {site for site, _ in HELPER_PIN_TABLES[name].values()}
            if not esites <= set(eins):
                raise ValueError(f'{name} evidence site not native '
                                 'instruction start')
            (output / f'{name}_objdump.txt').write_bytes(
                easm.replace(str(snapshot),
                             '<authenticated-node115>').encode('utf-8'))
        # Boundary call sites pinned by the census must be native
        # instruction starts in their boundary bodies.
        for role, sites_wanted in (
                ('remove_core', {0x149e365, 0x149e42a}),
                ('iterator_drop', {0x1537f87, 0x1537fb6})):
            a, b, _ = BOUNDARIES[role]
            basm = _objdump(snapshot, a, b)
            bins = decode_export(basm, a, b, read(data, a, b - a)[1])
            if not sites_wanted <= set(bins):
                raise ValueError(f'{role} census site not native '
                                 'instruction start')
    (output / 'frames.txt').write_bytes(
        ('\n'.join(lines) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes(
        (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--output', type=Path,
                   default=ROOT / 'work/second-structure-readers115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
