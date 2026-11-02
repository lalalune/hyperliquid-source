#!/usr/bin/env python3
"""Reproduce selected node 94 sub-account state codec evidence from ELF bytes."""
import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Starts are selected by the bounded question; ends and FDE addresses come from
# the shared parsers. A direct-call target is not automatically part of scope.
STARTS = (
    ('msg_tracker_write', 0x21f97b0), ('json_tracker_write', 0x21f94d0),
    ('msg_user_map_write', 0x202c4e0), ('msg_master_map_write', 0x20297e0),
    ('json_user_map_write', 0x202b9a0), ('json_master_map_write', 0x20287f0),
    ('msg_user_entries_write', 0x1e1d7f0), ('msg_master_entries_write', 0x1e31770),
    ('msg_user_pair_write', 0x1de9940), ('msg_master_pair_write', 0x1dee610),
    ('msg_row_write', 0x21f92b0), ('msg_row_write_fast', 0x21f9000),
    ('json_tracker_read', 0x1c85e60), ('json_user_map_read', 0x25a4940),
    ('json_master_map_read', 0x25a0200), ('json_user_entries_read', 0x265f5d0),
    ('json_master_entries_read', 0x2687250), ('json_user_pair_read', 0x1b8e4a0),
    ('json_master_pair_read', 0x1ba52f0), ('json_user_row_list_read', 0x1bdf3f0),
    ('json_user_row_vector_read', 0x24e4050), ('json_row_entry_read', 0x1b91730),
    ('json_row_read', 0x1c5a170), ('json_row_name_classify', 0x21e6620),
    ('msg_tracker_read', 0x173feb0), ('msg_user_map_read', 0x1905bf0),
    ('msg_master_map_read', 0x17ecc80), ('msg_tracker_name_classify', 0x21e6ed0),
    ('msg_user_object_read', 0x2635e00), ('msg_master_object_read', 0x2657200),
    ('msg_user_array_read', 0x26797e0), ('msg_master_array_read', 0x269d9b0),
    ('json_user_entries_write', 0x290c170), ('json_master_entries_write', 0x292f640),
    ('json_row_write', 0x21f8cc0),
    ('msg_user_pair_read', 0x176d4b0), ('msg_user_row_list_read', 0x19241a0),
    ('msg_user_row_vector_read', 0x24e00e0), ('msg_row_read', 0x1a3c150),
    ('msg_row_name_classify', 0x21e6580), ('msg_master_pair_read', 0x196a800),
    ('user_entry_sort', 0x1fe9710), ('master_entry_sort', 0x1fe3bb0),
)

# Fixed byte patterns are selected instructions or complete classifier code,
# not an x86 disassembler. Tests mutate these and the relative edges separately.
ANCHORS = (
    ('msg_tracker_header', 0x21f97d0, '807a0b007432488d7c24084c89f6ba02000000'),
    ('msg_tracker_field_mode', 0x21f9825, '41807e0b01751a'),
    ('msg_tracker_second_slot', 0x21f9883, '4983c730'),
    ('msg_row_header', 0x21f92d1, '807a0b00742f4889e74c89feba03000000'),
    ('msg_row_fast_header', 0x21f9017, '0fb66a1b488b72104080f50140c0e5044080cd83'),
    ('msg_row_fast_n_marker', 0x21f905e, 'c60431a1'),
    ('msg_row_fast_n', 0x21f9072, 'c604316e'),
    ('msg_row_fast_s_marker', 0x21f90bb, 'c60431a1'),
    ('msg_row_fast_s', 0x21f90cf, 'c6043173'),
    ('msg_row_fast_m_marker', 0x21f9116, 'c60431a1'),
    ('msg_row_fast_m', 0x21f912a, 'c604316d'),
    ('row_name_pointer_length', 0x21f9320, '4d8b66084d8b6e10'),
    ('row_s_offset', 0x21f9386, '4d8d4618'),
    ('row_m_offset', 0x21f93cc, '4983c62c'),
    ('user_pair_count', 0x1de99a9, 'ba02000000'),
    ('master_pair_count', 0x1dee66e, 'ba02000000'),
    ('json_tracker_open', 0x1c85ef1, '83ff5b0f841704000083ff7b0f85190e0000'),
    ('json_user_write_array_open', 0x290c1b9, '42c604385b'),
    ('json_user_write_pair_open', 0x290c318, '42c604305b'),
    ('json_user_write_array_close', 0x290c9a5, '42c604385d'),
    ('json_master_write_array_open', 0x292f684, '42c604385b'),
    ('json_master_write_pair_open', 0x292f7f7, '42c604385b'),
    ('json_master_write_array_close', 0x292fbb5, '42c604385d'),
    ('json_row_write_open', 0x21f8cfe, 'c604017b'),
    ('json_row_write_s_offset', 0x21f8d5c, '488d5318'),
    ('json_row_write_m_offset', 0x21f8de3, '4883c32c'),
    ('json_row_write_s_widths', 0x21f8da5, 'be2a000000b914000000'),
    ('json_row_write_m_widths', 0x21f8e2c, 'be2a000000b914000000'),
    ('json_tracker_sequence_empty', 0x1c86396, '83fa5d0f845d060000'),
    ('json_tracker_key_lengths', 0x1c86040, '4883f9154c8b4424104c8b6424080f849c0000004883f914'),
    ('json_tracker_user_compare', 0x1c86066, 'f30f6f00f30f6f0d3e0b75fe660f74c8660f6e4010660f6e153d0b75fe660f74d0660fdbd1660fd7c23dffff0000'),
    ('json_tracker_master_compare', 0x1c860f0, 'f30f6f05cc0a75fef30f6f08660f74c8f30f6f4005f30f6f15bc0a75fe660f74d0660fdbd1660fd7c23dffff0000'),
    ('json_tracker_required', 0x1c86895, '4885ed0f84990100004d85c90f84fd010000'),
    ('json_user_container_dispatch', 0x25a49c1, '448d47a54183f8200f87e8000000'),
    ('json_master_container_dispatch', 0x25a0294, '448d47a54183f8200f879b000000'),
    ('json_user_insert_check', 0x25a4cc5, '4c8b6c24384d39fd0f84d5feffff'),
    ('json_master_insert_check', 0x25a052f, '807c2440010f8506ffffff'),
    ('json_user_array_insert_check', 0x265f6e3, '488b5c24104c39e30f845fffffff'),
    ('json_master_array_insert_check', 0x2687361, '807c2430010f8564ffffff'),
    ('json_row_vector_stride', 0x24e40a8, '48c1e106'),
    ('json_row_dispatch', 0x1c5a363, '0fb6442429488d0dbdc075fe486304814801c8ffe0'),
    ('json_row_n_guard', 0x1c5a378, '4d39ef488b942490000000488d7c24280f85f40a0000'),
    ('json_row_m_guard', 0x1c5a3da, 'f684249800000001488b942490000000488d7c24280f85510a0000'),
    ('json_row_s_guard', 0x1c5a495, 'f68424a000000001488b942490000000488d7c24280f855a090000'),
    ('json_row_required_n', 0x1c5aa2a, '4d39ef0f85cd000000'),
    ('json_row_required_sm', 0x1c5ab00, 'f68424a0000000010f8409010000f6842498000000010f8434010000'),
    ('msg_tracker_sequence_count', 0x1740585, '83fd020f850b010000'),
    ('msg_tracker_sequence_empty', 0x174039b, '85ed0f84d7020000'),
    ('msg_tracker_sequence_one', 0x17403f6, '83fd017561'),
    ('msg_tracker_field_switch', 0x1741850, '83f8020f84a900000083f8010f85260100004d85ed0f857c040000'),
    ('msg_tracker_first_guard', 0x1741990, '4885c00f85af020000'),
    ('msg_row_vector_stride', 0x24e0168, '48c1e106'),
    ('msg_row_initial_reservation', 0x24e00fb, '448b6e084181fd0040000041be00400000450f42f54585ed0f84220100004489f3c1e3064889df'),
    ('msg_row_reservation_growth', 0x24e021b, '4c8b7424184c3b7424080f8535ffffff488d7c2408ff1542422903e925ffffff'),
    ('msg_row_allocation_failure', 0x24e0128, '4885c00f84d9010000'),
    ('msg_row_sequence_count_zero', 0x1a3c728, '85ed0f84b6050000'),
    ('msg_row_sequence_count_one', 0x1a3c7ba, '83fd010f8521020000'),
    ('msg_row_sequence_count_two', 0x1a3ca6e, '83fd020f85c7000000'),
    ('msg_row_sequence_count_three', 0x1a3cbb6, '83fd030f8551030000'),
    ('msg_pair_count_zero', 0x176d9ef, '85ed0f8467050000'),
    ('msg_pair_count_one', 0x176db87, '83fd010f8445040000'),
    ('msg_pair_count_two', 0x176dd81, '83fd020f8546010000'),
    ('msg_master_pair_count_zero', 0x196ad28, '85c90f8418040000'),
    ('msg_master_pair_count_one', 0x196ae98, '837c2438010f8414030000'),
    ('msg_master_pair_count_two', 0x196af10, '837c2438020f85bb010000'),
    ('msg_row_dispatch', 0x1a3deba, '0fb66c24204080fd090f857e0300000fb6442421488d0dc76b96fe486304814801c8ffe0'),
    ('msg_row_n_guard', 0x1a3dede, '48b80000000000000080488b4c24704839c10f8579040000'),
    ('msg_row_m_guard', 0x1a3df9a, 'f68424f0000000010f8514040000'),
    ('msg_row_s_guard', 0x1a3e071, 'f68424a8000000010f859e020000'),
    ('msg_user_marker_map', 0x1905f88, '80f9900f83a401000080e10f'),
    ('msg_user_marker_array', 0x1906135, '80f9a00f836a01000080e10f'),
    ('msg_master_marker_map', 0x17ed018, '80f9900f83a401000080e10f'),
    ('msg_master_marker_array', 0x17ed1c5, '80f9a00f836a01000080e10f'),
    ('msg_user_object_insert', 0x2635f6f, '488b2c2448b800000000000000804839c50f85cc000000'),
    ('msg_master_object_insert', 0x26573b7, '807c2410010f840e010000'),
    ('msg_user_array_insert', 0x2679907, '4c8bac248800000048b800000000000000804939c57557'),
    ('msg_master_array_insert', 0x269da9b, '807c2440017448'),
    ('user_sort_count_gates',0x1fe972c,'4883fe1548897c24080f83f90000004883fd020f82a6060000'),
    ('user_sort_compare_next',0x1fe9784,'49ffce4d89f549c1e5044889d84a8b1c2b4a8b7c2810ba140000004889deff15e04c780385c079c6'),
    ('user_sort_shift_pair',0x1fe97c8,'410f1045000f11004883fd02748a488b7820ba140000004889deff15a04c78034c89'),
    ('user_sort_compare_loop',0x1fe9818,'4b8b7c2f10ba140000004889deff155d4c780385c078d1'),
    ('master_sort_count_gates',0x1fe3bcc,'4883fe1548897c24080f83f90000004883fd020f82a6060000'),
    ('master_sort_compare_next',0x1fe3c24,'49ffce4d89f549c1e5044889d84a8b1c2b4a8b7c2810ba140000004889deff1540a8780385c079c6'),
    ('master_sort_shift_pair',0x1fe3c68,'410f1045000f11004883fd02748a488b7820ba140000004889deff1500a878034c89'),
    ('master_sort_compare_loop',0x1fe3cb8,'4b8b7c2f10ba140000004889deff15bda7780385c078d1'),
    ('msg_tracker_name_classifier', 0x21e6ed0,
     '4889f84883fa1574384883fa14755bf30f6f06660f6e4e10660f740dd01d02fe660f7405c80702fe660fdbc1660fd7c881f9ffff0000753231c9884801c60009c3f30f6f06f30f6f4e05660f740deedc01fe660f7405461a02fe660fdbc1660fd7c881f9ffff00007409b102884801c60009c3b101884801c60009c3'),
    ('msg_row_name_classifier', 0x21e6580,
     '4889f848ffca4883fa0f7779488d0d59e01efe486314914801caffe20fb60e80c19380f907735ec0e10348ba020003030303010048d3ea885001c60009c3b96d617374330e0fb7560481f26572000009ca7532b202885001c60009c3813e6e616d65752131d2885001c60009c3f30f6f06660f7405a7fb01fe660fd7c881f9ffff00007409b203885001c60009c3b201885001c60009c3'),
    ('row_name_classifier', 0x21e6620,
     '4889f848ffca4883fa0f7779488d0df9df1efe486314914801caffe20fb60e80c19380f907735ec0e10348ba020003030303010048d3ea885001c60000c3b96d617374330e0fb7560481f26572000009ca7532b202885001c60000c3813e6e616d65752131d2885001c60000c3f30f6f06660f740507fb01fe660fd7c881f9ffff00007409b203885001c60000c3b201885001c60000c3'),
)

# (meaning, rel32 call instruction, expected target). Edges are extracted and
# checked, not constructed from a disassembler's version-dependent text.
CALLS = (
    ('msg_outer_map_header',0x21f97e3,0x25a8f80), ('msg_outer_array_header',0x21f9815,0x25a9bd0),
    ('msg_outer_first_name',0x21f983b,0x25aa7f0), ('msg_outer_first_value',0x21f9851,0x202c4e0),
    ('msg_outer_second_name',0x21f9878,0x25aa7f0), ('msg_outer_second_value',0x21f9892,0x20297e0),
    ('json_outer_first_value',0x21f957a,0x202b9a0), ('json_outer_second_value',0x21f95e6,0x20287f0),
    ('msg_user_collect',0x202c530,0x2570810), ('msg_user_prepare',0x202c545,0x1fe9710),
    ('msg_user_entries',0x202c568,0x1e1d7f0), ('msg_master_collect',0x2029830,0x2577820),
    ('msg_master_prepare',0x2029845,0x1fe3bb0), ('msg_master_entries',0x2029868,0x1e31770),
    ('json_user_collect',0x202b9eb,0x2570810), ('json_user_prepare',0x202ba00,0x1fe9710),
    ('json_user_entries',0x202ba20,0x290c170), ('json_master_collect',0x202883b,0x2577820),
    ('json_master_prepare',0x2028850,0x1fe3bb0), ('json_master_entries',0x2028870,0x292f640),
    ('msg_user_entries_header',0x1e1d857,0x25a9bd0), ('msg_user_pair_loop',0x1e1d8af,0x1de9940),
    ('msg_user_pair_loop_alt',0x1e1d9de,0x1de9940), ('msg_master_entries_header',0x1e317d7,0x25a9bd0),
    ('msg_master_pair_loop',0x1e3182f,0x1dee610), ('msg_master_pair_loop_alt',0x1e3195e,0x1dee610),
    ('msg_user_pair_header',0x1de99ae,0x25a9bd0), ('msg_user_pair_row_fast',0x1de9dd3,0x21f9000),
    ('msg_user_pair_row',0x1de9e5d,0x21f92b0), ('msg_master_pair_header',0x1dee673,0x25a9bd0),
    ('msg_master_pair_first',0x1dee6c0,0x1e0d0a0), ('msg_master_pair_second',0x1dee6d9,0x1e0d0a0),
    ('msg_row_map_header',0x21f92e2,0x25a8f80), ('msg_row_array_header',0x21f9311,0x25a9bd0),
    ('msg_row_n_key',0x21f933e,0x25aa7f0), ('msg_row_n_value',0x21f9356,0x25aa7f0),
    ('msg_row_s_key',0x21f937b,0x25aa7f0), ('msg_row_s_value',0x21f939c,0x1e52130),
    ('msg_row_m_key',0x21f93c1,0x25aa7f0), ('msg_row_m_value',0x21f93e5,0x1e52130),
    ('json_outer_object_first',0x1c86252,0x25a4940), ('json_outer_object_second',0x1c862c0,0x25a0200),
    ('json_outer_sequence_first',0x1c863aa,0x25a4940), ('json_outer_sequence_second',0x1c86b46,0x25a0200),
    ('json_user_array',0x25a4a1b,0x265f5d0), ('json_user_object_key',0x25a4bb8,0x1b6eb60),
    ('json_user_object_value',0x25a4c4c,0x1bdf3f0), ('json_user_object_insert',0x25a4cc0,0x27ca400),
    ('json_master_array',0x25a02ee,0x2687250), ('json_master_object_key',0x25a044b,0x1b6eb60),
    ('json_master_object_value',0x25a0477,0x1b73070), ('json_master_object_insert',0x25a052a,0x27c6160),
    ('json_user_array_pair',0x265f65b,0x1b8e4a0), ('json_user_array_insert',0x265f6de,0x27ca400),
    ('json_master_array_pair',0x26872d6,0x1ba52f0), ('json_master_array_insert',0x268735c,0x27c6160),
    ('json_user_pair_key',0x1b8e633,0x1b9cca0), ('json_user_pair_rows',0x1b8e75f,0x1bdf3f0),
    ('json_master_pair_key',0x1ba545c,0x1b9cca0), ('json_master_pair_value',0x1ba54aa,0x1b9cca0),
    ('json_user_row_list',0x1bdf4ab,0x24e4050), ('json_row_vector_entry',0x24e40dd,0x1b91730),
    ('json_row_entry',0x1b91856,0x1c5a170), ('json_row_classify',0x1c5a353,0x21e6620),
    ('json_row_unknown',0x1c5a516,0x1b2dd60), ('msg_outer_sequence_first',0x17403b0,0x1905bf0),
    ('msg_outer_sequence_second',0x1740469,0x17ecc80), ('msg_outer_object_second',0x174187e,0x17ecc80),
    ('msg_outer_unknown',0x1741912,0x19682d0), ('msg_outer_object_first',0x17419a9,0x1905bf0),
    ('msg_outer_classify_name',0x17416b5,0x21e6ed0),
    ('msg_user_map_input',0x1905fd3,0x2635e00), ('msg_user_array_input',0x1906180,0x26797e0),
    ('msg_master_map_input',0x17ed063,0x2657200), ('msg_master_array_input',0x17ed210,0x269d9b0),
    ('msg_user_map_key',0x2635e88,0x1699080), ('msg_user_map_rows',0x2635ecc,0x19241a0),
    ('msg_master_map_key',0x26572a0,0x1699080), ('msg_master_map_value',0x2657305,0x1699080),
    ('msg_user_array_pair',0x267985c,0x176d4b0), ('msg_master_array_pair',0x269da3c,0x196a800),
    ('msg_user_map_insert',0x2635f6a,0x27ca400), ('msg_master_map_insert',0x26573b2,0x27c6160),
    ('msg_user_array_insert',0x2679902,0x27ca400), ('msg_master_array_insert',0x269da96,0x27c6160),
    ('json_user_entries_row',0x290c5eb,0x21f8cc0),
    ('json_row_write_name',0x21f8d26,0x295b560), ('json_row_write_s_key',0x21f8d4d,0x2974190),
    ('json_row_write_m_key',0x21f8dd4,0x2974190),
    ('json_row_write_s_value',0x21f8db2,0x27e2690), ('json_row_write_m_value',0x21f8e3c,0x27e2690),
    ('msg_user_pair_rows',0x176dbaf,0x19241a0), ('msg_user_rows_vector',0x192467e,0x24e00e0),
    ('msg_row_vector_entry',0x24e01bb,0x1a3c150), ('msg_row_classify',0x1a3dd9b,0x21e6580),
    ('msg_row_read_n',0x1a3df06,0x19822a0), ('msg_row_read_s',0x1a3e0c9,0x190f5b0),
    ('msg_row_read_m',0x1a3dff2,0x190f5b0), ('msg_row_unknown',0x1a3e059,0x19682d0),
    ('msg_master_pair_first',0x196ad89,0x190f5b0), ('msg_master_pair_second',0x196aeb0,0x1e882f0),
    ('msg_row_sequence_first',0x1a3c740,0x19822a0),
    ('msg_row_sequence_second',0x1a3c9f1,0x1e882f0), ('msg_row_sequence_third',0x1a3cb49,0x1e882f0),
)

# Branch targets are decoded from the instruction and checked. Conditions are
# observations about the immediately preceding pinned comparison or test.
BRANCHES = (
    ('json_outer_duplicate_user',0x1c8609d,0x1c86f7d,'present != 0'),
    ('json_outer_duplicate_master',0x1c861dd,0x1c86edf,'present != 0'),
    ('json_outer_missing_user',0x1c86898,0x1c86a37,'present == 0'),
    ('json_outer_missing_master',0x1c868a1,0x1c86aa4,'present == 0'),
    ('json_row_duplicate_n',0x1c5a388,0x1c5ae82,'present != 0'),
    ('json_row_duplicate_s',0x1c5a4aa,0x1c5ae0a,'present != 0'),
    ('json_row_duplicate_m',0x1c5a3ef,0x1c5ae46,'present != 0'),
    ('json_row_present_n',0x1c5aa2d,0x1c5ab00,'present != 0'),
    ('json_row_missing_s',0x1c5ab08,0x1c5ac17,'present == 0'),
    ('json_row_missing_m',0x1c5ab16,0x1c5ac50,'present == 0'),
    ('msg_outer_duplicate_user',0x1741993,0x1741c48,'present != 0'),
    ('msg_outer_duplicate_master',0x1741865,0x1741ce7,'present != 0'),
    ('msg_outer_sequence_wrong_count',0x1740588,0x1740699,'count != 2'),
    ('msg_outer_sequence_empty',0x174039d,0x174067a,'count == 0'),
    ('msg_outer_sequence_more_than_one',0x17403f9,0x174045c,'count != 1'),
    ('json_outer_sequence_empty',0x1c86399,0x1c869fc,'first element is closing bracket'),
    ('msg_outer_missing_user',0x1740b64,0x1740a9e,'present == 0'),
    ('msg_outer_missing_master',0x1740bd1,0x1740d18,'present == 0'),
    ('json_user_object_insert_new',0x25a4ccd,0x25a4ba8,'insert returns sentinel'),
    ('json_master_object_insert_new',0x25a0534,0x25a0440,'insert returns success'),
    ('json_user_array_insert_new',0x265f6eb,0x265f650,'insert returns sentinel'),
    ('json_master_array_insert_new',0x2687366,0x26872d0,'insert returns success'),
    ('msg_user_map_insert_duplicate',0x2635f80,0x2636052,'insert returns previous value'),
    ('msg_master_map_insert_duplicate',0x26573bc,0x26574d0,'insert returns previous value'),
    ('msg_user_array_insert_duplicate',0x267991c,0x2679975,'insert returns previous value'),
    ('msg_master_array_insert_duplicate',0x269daa0,0x269daea,'insert returns previous value'),
    ('msg_row_duplicate_n',0x1a3def0,0x1a3e36f,'present != sentinel'),
    ('msg_row_duplicate_s',0x1a3e079,0x1a3e31d,'present != 0'),
    ('msg_row_duplicate_m',0x1a3dfa2,0x1a3e3bc,'present != 0'),
    ('msg_row_missing_n',0x1a3d7ef,0x1a3c59d,'present == sentinel'),
    ('msg_row_present_s',0x1a3d84f,0x1a3c636,'present != 0'),
    ('msg_row_present_m',0x1a3d47b,0x1a3d538,'present != 0'),
    ('msg_row_sequence_empty',0x1a3c72a,0x1a3cce6,'count == 0'),
    ('msg_row_sequence_not_one',0x1a3c7bd,0x1a3c9e4,'count != 1'),
    ('msg_row_sequence_not_two',0x1a3ca71,0x1a3cb3e,'count != 2'),
    ('msg_row_sequence_wrong_count',0x1a3cbb9,0x1a3cf10,'count != 3'),
    ('msg_user_pair_empty',0x176d9f1,0x176df5e,'count == 0'),
    ('msg_user_pair_one',0x176db8a,0x176dfd5,'count == 1'),
    ('msg_user_pair_wrong_count',0x176dd84,0x176ded0,'count != 2'),
    ('msg_master_pair_empty',0x196ad2a,0x196b148,'count == 0'),
    ('msg_master_pair_one',0x196ae9d,0x196b1b7,'count == 1'),
    ('msg_master_pair_wrong_count',0x196af15,0x196b0d6,'count != 2'),
    ('msg_row_sequence_first_error',0x1a3c74b,0x1a3c902,'child status != 9'),
    ('msg_row_sequence_second_error',0x1a3ca5c,0x1a3ca97,'child status != 9'),
    ('msg_row_sequence_third_error',0x1a3cb9b,0x1a3cda7,'child status != 9'),
    ('json_row_write_s_error',0x21f8dba,0x21f8f1f,'child result != 0'),
    ('json_row_write_m_error',0x21f8e44,0x21f8f1f,'child result != 0'),
    ('msg_row_vector_empty',0x24e0113,0x24e023b,'count == 0'),
    ('msg_row_vector_alloc_failure',0x24e012b,0x24e030a,'allocation result == 0'),
    ('msg_row_vector_has_capacity',0x24e0225,0x24e0160,'length != capacity'),
    ('user_sort_large_path',0x1fe9735,0x1fe9834,'count >= 21'),
    ('user_sort_trivial_path',0x1fe973f,0x1fe9deb,'count < 2'),
    ('user_sort_next_not_less',0x1fe97aa,0x1fe9772,'memcmp result >= 0'),
    ('user_sort_insert_stop',0x1fe97ed,0x1fe9760,'memcmp result >= 0'),
    ('user_sort_insert_continue',0x1fe982d,0x1fe9800,'memcmp result < 0'),
    ('master_sort_large_path',0x1fe3bd5,0x1fe3cd4,'count >= 21'),
    ('master_sort_trivial_path',0x1fe3bdf,0x1fe428b,'count < 2'),
    ('master_sort_next_not_less',0x1fe3c4a,0x1fe3c12,'memcmp result >= 0'),
    ('master_sort_insert_stop',0x1fe3c8d,0x1fe3c00,'memcmp result >= 0'),
    ('master_sort_insert_continue',0x1fe3ccd,0x1fe3ca0,'memcmp result < 0'),
)

# These sites are indirect calls through one dynamically relocated GOT slot.
SORT_COMPARISONS = (
    ('user_adjacent',0x1fe97a2), ('user_insert_first',0x1fe97e2), ('user_insert_loop',0x1fe9825),
    ('master_adjacent',0x1fe3c42), ('master_insert_first',0x1fe3c82), ('master_insert_loop',0x1fe3cc5),
)

# A narrow xref from a previously studied app-hash closure. Its containing
# FDE is deliberately not one of this packet's selected function ranges.
HASH_CONTEXT_SITE=0x2818e65
HASH_CONTEXT_BYTES='c744240800040001c644240c00488b36488dbc24080100004889e2e82b099eff'


def checked_image(path=BINARY):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('node 94 SHA-256 mismatch')
    return data


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)

    def offset(self, va, length=1, executable=False):
        if va < 0 or length <= 0:
            raise ValueError('negative or empty byte range')
        matches = [s for s in self.secs if s['type'] != 8 and
                   (not executable or s['flags'] & 4) and
                   s['address'] <= va and va + length <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('range is not uniquely backed by file bytes')
        sec = matches[0]
        offset = sec['offset'] + va - sec['address']
        if offset + length > len(self.data):
            raise ValueError('range extends beyond file')
        return offset

    def read(self, va, length, executable=False):
        off = self.offset(va, length, executable)
        return self.data[off:off + length]

    def expect(self, va, hexbytes):
        expected = bytes.fromhex(hexbytes)
        actual = self.read(va, len(expected), True)
        if actual != expected:
            raise ValueError(f'instruction pattern mismatch at {va:#x}')
        return actual

    def rip_target(self, va, prefix):
        raw = self.read(va, len(prefix) + 4, True)
        if not raw.startswith(prefix):
            raise ValueError(f'RIP-relative opcode mismatch at {va:#x}')
        return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]

    def rel_target(self, va, expected=None, call=False):
        first = self.read(va, 2, True)
        if first[0] == 0xe8 and call:
            n, disp_offset, encoding = 5, 1, 'call_rel32'
        elif not call and first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
            n, disp_offset, encoding = 6, 2, f'jcc_{first[1]:02x}_rel32'
        elif not call and 0x70 <= first[0] <= 0x7f:
            n, disp_offset, encoding = 2, 1, f'jcc_{first[0]:02x}_rel8'
        else:
            raise ValueError(f'relative opcode mismatch at {va:#x}')
        raw = self.read(va, n, True)
        disp = struct.unpack_from('<b' if n == 2 else '<i', raw, disp_offset)[0]
        target = va + n + disp
        if expected is not None and target != expected:
            raise ValueError(f'relative target mismatch at {va:#x}')
        return target, encoding, raw


def extract_classifier(image, start=0x21e6620):
    if start not in (0x21e6620,0x21e6580):
        raise ValueError('unsupported row classifier')
    image.expect(start, dict((va, code) for _, va, code in ANCHORS)[start])
    delta=start-0x21e6620
    packed = image.read(0x21e664c+delta, 8, True)
    names = (image.read(0x21e667e+delta,4,True),
             image.read(image.rip_target(0x21e6691+delta, bytes.fromhex('660f7405')),16),
             image.read(0x21e665f+delta,4,True) + image.read(0x21e666b+delta,2,True))
    if names != (b'name', b'sub_account_user', b'master'):
        raise ValueError('row name constants mismatch')
    return {'packed': packed, 'long': names, 'unknown': image.read(0x21e66a6+delta,1,True)[0],
            'add': image.read(0x21e6641+delta,1,True)[0], 'bound': image.read(0x21e6644+delta,1,True)[0]}


def outer_name_sources(image):
    """Join overlapping SIMD comparison constants from two independent readers."""
    defs = (
        ('user_to_sub_accounts', 0x21f982c, 0x21f9833,
         0x1c8606a, 'f30f6f0d', 0x1c8607b, '660f6e15',
         0x21e6ef0, '660f7405', 0x21e6ee8, '660f740d', 16, 4),
        ('sub_account_to_master', 0x21f9869, 0x21f9870,
         0x1c860f0, 'f30f6f05', 0x1c86105, 'f30f6f15',
         0x21e6f22, '660f7405', 0x21e6f1a, '660f740d', 5, 16),
    )
    result=[]
    for index,(label,wlea,wlen,jhead,jhp,jtail,jtp,mhead,mhp,mtail,mtp,tail_offset,tail_size) in enumerate(defs):
        nraw=image.read(wlen,5,True)
        if nraw[0] != 0xba:
            raise ValueError('writer field length opcode mismatch')
        length=struct.unpack_from('<I',nraw,1)[0]
        wva=image.rip_target(wlea,bytes.fromhex('488d35'))
        writer=image.read(wva,length)
        json_writer_va=image.rip_target((0x21f9525,0x21f958d)[index],bytes.fromhex('488d35'))
        if image.read(json_writer_va,length) != writer:
            raise ValueError('JSON and MessagePack writer field names differ')
        locations=[image.rip_target(site,bytes.fromhex(prefix)) for site,prefix in
                   ((jhead,jhp),(jtail,jtp),(mhead,mhp),(mtail,mtp))]
        combined=[]
        for head_va,tail_va in (locations[:2],locations[2:]):
            head=image.read(head_va,16)
            tail=image.read(tail_va,tail_size)
            overlap=16-tail_offset
            if overlap and head[tail_offset:] != tail[:overlap]:
                raise ValueError('reader name comparison windows disagree')
            combined.append(head[:tail_offset]+tail)
        if writer != label.encode('ascii') or combined != [writer,writer]:
            raise ValueError('writer and reader field names differ')
        result.append((label,wva,length,*locations,json_writer_va))
    return result


def classify_outer_key(key, names):
    for tag, name in enumerate(names):
        if key == name:
            return tag
    return 2


def classify_row_key(key, spec):
    """Interpret only the pinned classifier decisions; no target code executes."""
    if len(key) == 1:
        index = (key[0] + spec['add']) & 0xff
        return spec['packed'][index] if index < spec['bound'] else spec['unknown']
    if len(key) in (4, 6, 16):
        for tag, value in enumerate(spec['long']):
            if key == value:
                return tag
    return spec['unknown']


def known_field_outcome(keys, spec):
    """Presence-only model, conditional on well-formed keys and successful values."""
    seen = set()
    for key in keys:
        tag = classify_row_key(key, spec)
        if tag == spec['unknown']:
            return 'unknown-handling-unresolved'
        if tag in seen:
            return f'duplicate:{tag}'
        seen.add(tag)
    for tag in range(len(spec['long'])):
        if tag not in seen:
            return f'missing:{tag}'
    return 'all-present'


def sequence_arity_outcome(count, arity):
    """Count gates only, assuming every available child decodes successfully."""
    if not isinstance(count,int) or not isinstance(arity,int) or count < 0 or arity < 0:
        raise ValueError('counts must be nonnegative integers')
    if count < arity:
        return f'missing-index:{count}'
    if count > arity:
        return 'excess-elements'
    return 'count-accepted'


def initial_reservation(count, limit, shift):
    """Model the selected unsigned 32-bit preallocation, not an input limit."""
    if not isinstance(count,int) or count < 0 or count > 0xffffffff:
        raise ValueError('count outside unsigned 32-bit range')
    rows=min(count,limit)
    return rows,rows << shift


def fast_row_header(flag, xor_value, shift, marker):
    """Model the fast row writer for its two established flag values."""
    if flag not in (0,1):
        raise ValueError('row writer flag outside analyzed values')
    return (((flag ^ xor_value) << shift) | marker) & 0xff


def small_entry_order(keys, threshold, width):
    """Model the selected backward insertion path under ordinary memcmp semantics."""
    if len(keys) >= threshold or any(len(key) != width for key in keys):
        raise ValueError('keys outside the selected small-entry path')
    ordered=list(keys)
    for start in range(len(ordered)-2,-1,-1):
        current=ordered[start]
        cursor=start
        while cursor+1 < len(ordered) and ordered[cursor+1] < current:
            ordered[cursor]=ordered[cursor+1]
            cursor+=1
        ordered[cursor]=current
    return ordered


def memcmp_import(image, slot):
    """Resolve one ELF64 RELA entry and its dynamic symbol through shared sections."""
    wanted={'.rela.dyn':4,'.dynsym':11,'.dynstr':3}
    found={}
    for sec in image.secs:
        if sec['name'] in wanted:
            if sec['name'] in found or sec['type'] != wanted[sec['name']]:
                raise ValueError('ambiguous or invalid dynamic symbol section')
            found[sec['name']]=sec
    if set(found) != set(wanted):
        raise ValueError('missing dynamic symbol section')
    rela=found['.rela.dyn']
    if rela['size'] % 24:
        raise ValueError('misaligned RELA section')
    matches=[]
    for off in range(rela['offset'],rela['offset']+rela['size'],24):
        address,info,addend=struct.unpack_from('<QQq',image.data,off)
        if address == slot:
            matches.append((off,info,addend))
    if len(matches) != 1:
        raise ValueError('slot does not have a unique dynamic relocation')
    off,info,addend=matches[0]
    index,kind=info >> 32,info & 0xffffffff
    dynsym,dynstr=found['.dynsym'],found['.dynstr']
    if kind != 6 or addend != 0 or dynsym['size'] % 24 or index >= dynsym['size']//24:
        raise ValueError('unexpected comparison-slot relocation')
    symbol_offset=dynsym['offset']+index*24
    name_offset=struct.unpack_from('<I',image.data,symbol_offset)[0]
    if name_offset >= dynstr['size']:
        raise ValueError('dynamic symbol name outside string table')
    name_start=dynstr['offset']+name_offset
    name_end=image.data.find(b'\0',name_start,dynstr['offset']+dynstr['size'])
    if name_end < 0:
        raise ValueError('unterminated dynamic symbol name')
    name=bytes(image.data[name_start:name_end])
    if name != b'memcmp':
        raise ValueError('comparison slot is not the expected memcmp import')
    return {'slot':slot,'relocation_va':rela['address']+off-rela['offset'],
            'symbol_index':index,'relocation_type':kind,
            'symbol_va':dynsym['address']+index*24,
            'name_va':dynstr['address']+name_offset,'name':name.decode('ascii')}


def hash_writer_context(image):
    """Check only the prior closure's writer configuration and call boundary."""
    raw=image.expect(HASH_CONTEXT_SITE,HASH_CONTEXT_BYTES)
    target,_,call=image.rel_target(0x2818e80,0x21f97b0,call=True)
    config=raw[4:8]
    flag=config[3]  # byte +0xb of the serializer passed in rdx
    if flag != 1:
        raise ValueError('prior closure writer flag mismatch')
    return {'config_va':HASH_CONTEXT_SITE,'config_bytes':config.hex(),
            'window_bytes':raw.hex(),'call_va':0x2818e80,'call_bytes':call.hex(),
            'target_va':target,'mode_byte':flag}


def selected_fdes(data, image):
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    selected = {start: name for name, start in STARTS}
    matching = [fde for fde in fdes if fde['start'] in selected]
    if len(matching) != len(STARTS) or len({fde['start'] for fde in matching}) != len(STARTS):
        raise ValueError('selected starts do not each have one FDE')
    index_by_start = {row['start']: row for row in index}
    results = []
    for fde in matching:
        start, end = fde['start'], fde['end']
        entry = index_by_start.get(start)
        if entry is None or entry['fde'] != fde['fde'] or end <= start:
            raise ValueError('unwind header and FDE disagree')
        body = image.read(start, end - start, True)
        results.append({'name':selected[start], 'start':start, 'end':end, 'fde':fde['fde'],
                        'cie':fde['cie'], 'file_offset':image.offset(start, len(body), True),
                        'size':len(body), 'body_sha256':hashlib.sha256(body).hexdigest()})
    return sorted(results, key=lambda row: row['start'])


def owner(rows, va):
    matches = [row for row in rows if row['start'] <= va < row['end']]
    if len(matches) != 1:
        raise ValueError(f'site has no unique selected FDE: {va:#x}')
    return matches[0]['name']


def rel_table(image, lea, prefix, count, low, high, expected):
    base = image.rip_target(lea, prefix)
    data = image.read(base, count * 4)
    targets = [base + x[0] for x in struct.iter_unpack('<i', data)]
    if any(not low <= a < high for a in targets):
        raise ValueError('table target outside selected unwind extent')
    for idx, target in expected.items():
        if targets[idx] != target:
            raise ValueError('table target mismatch')
    return base, targets


def extract_duplicate_key(image, first, second):
    # Two 8-byte mov-immediates are stored at offsets 5 and 0 respectively.
    tail = image.read(first, 10, True)
    head = image.read(second, 10, True)
    if tail[:2] != b'\x48\xb9' or head[:2] != b'\x48\xb9':
        raise ValueError('duplicate-key immediate opcode mismatch')
    a, b = head[2:], tail[2:]
    if a[5:] != b[:3] or a[:5] + b != b'duplicate key':
        raise ValueError('duplicate-key immediate mismatch')
    return a[:5] + b


def field_errors(image):
    # The name and formatting prefix are both PC-relative references in each
    # error block. Read only the length-delimited field bytes, not C strings.
    specs=(
        ('json_outer_missing_user','user_to_sub_accounts',0x1c86a3c,0x1c86a7f,'3d','missing'),
        ('json_outer_missing_master','sub_account_to_master',0x1c86aae,0x1c86ae8,'3d','missing'),
        ('json_outer_duplicate_user','user_to_sub_accounts',0x1c86f95,0x1c86fd5,'3d','duplicate'),
        ('json_outer_duplicate_master','sub_account_to_master',0x1c86ef7,0x1c86f37,'3d','duplicate'),
        ('msg_outer_missing_user','user_to_sub_accounts',0x1740aa6,0x1740ae3,'35','missing'),
        ('msg_outer_missing_master','sub_account_to_master',0x1740d20,0x1740d5a,'35','missing'),
        ('msg_outer_duplicate_user','user_to_sub_accounts',0x1741c80,0x1741cbd,'35','duplicate'),
        ('msg_outer_duplicate_master','sub_account_to_master',0x1741d1f,0x1741d5c,'35','duplicate'),
        ('json_row_missing_n','n',0x1c5aa33,0x1c5aa59,'3d','missing'),
        ('json_row_missing_s','s',0x1c5ac17,0x1c5ac3d,'3d','missing'),
        ('json_row_missing_m','m',0x1c5ac50,0x1c5ac76,'3d','missing'),
        ('json_row_duplicate_n','n',0x1c5ae82,0x1c5aea8,'3d','duplicate'),
        ('json_row_duplicate_s','s',0x1c5ae0a,0x1c5ae30,'3d','duplicate'),
        ('json_row_duplicate_m','m',0x1c5ae46,0x1c5ae6c,'3d','duplicate'),
        ('msg_row_missing_n','n',0x1a3c59d,0x1a3c5ce,'35','missing'),
        ('msg_row_missing_s','s',0x1a3d3e3,0x1a3d414,'35','missing'),
        ('msg_row_missing_m','m',0x1a3d494,0x1a3d4c5,'35','missing'),
        ('msg_row_duplicate_n','n',0x1a3e36f,0x1a3e3a0,'35','duplicate'),
        ('msg_row_duplicate_s','s',0x1a3e31d,0x1a3e34e,'35','duplicate'),
        ('msg_row_duplicate_m','m',0x1a3e3bc,0x1a3e3ed,'35','duplicate'),
    )
    result=[]
    for label,field,nsite,tsite,modrm,kind in specs:
        name_va=image.rip_target(nsite,bytes.fromhex('488d05'))
        template_va=image.rip_target(tsite,bytes.fromhex('488d'+modrm))
        name=image.read(name_va,len(field)).decode('ascii')
        size=image.read(template_va,1)[0]
        prefix=image.read(template_va+1,size).decode('ascii')
        if name != field or prefix != kind+' field `':
            raise ValueError('field error literal mismatch')
        result.append((label,hex(nsite),hex(name_va),name,hex(tsite),hex(template_va),prefix))
    return result


def tsv(out, name, header, rows):
    with (out / name).open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(data, out):
    image = Image(data)
    for _, va, code in ANCHORS:
        image.expect(va, code)
    hash_context=hash_writer_context(image)
    fdes = selected_fdes(data, image)
    by_name = {r['name']:r for r in fdes}
    edges = []
    for name, va, expected in CALLS:
        target, kind, raw = image.rel_target(va, expected, call=True)
        edges.append((name, owner(fdes, va), hex(va), kind, hex(target), raw.hex(), 'direct call'))
    for name, va, expected, condition in BRANCHES:
        target, kind, raw = image.rel_target(va, expected)
        if owner(fdes, va) != owner(fdes, target):
            raise ValueError('branch leaves selected FDE')
        edges.append((name, owner(fdes, va), hex(va), kind, hex(target), raw.hex(), condition))
    indirect=[]
    resolved=None
    for name,va in SORT_COMPARISONS:
        slot=image.rip_target(va,bytes.fromhex('ff15'))
        if slot != 0x576e488:
            raise ValueError('comparison slot mismatch')
        if resolved is None:
            resolved=memcmp_import(image,slot)
        indirect.append((name,owner(fdes,va),hex(va),image.read(va,6,True).hex(),
                         hex(slot),hex(resolved['relocation_va']),resolved['relocation_type'],
                         resolved['symbol_index'],hex(resolved['symbol_va']),
                         hex(resolved['name_va']),resolved['name']))

    table_specs = (
        ('row_key_length',0x21e662c,bytes.fromhex('488d0d'),16,'json_row_name_classify',
         {0:0x21e663c,3:0x21e667c,5:0x21e665e,15:0x21e668d}),
        ('row_key_tag',0x1c5a368,bytes.fromhex('488d0d'),4,'json_row_read',
         {0:0x1c5a378,1:0x1c5a495,2:0x1c5a3da,3:0x1c5a441}),
        ('msg_row_key_length',0x21e658c,bytes.fromhex('488d0d'),16,'msg_row_name_classify',
         {0:0x21e659c,3:0x21e65dc,5:0x21e65be,15:0x21e65ed}),
        ('msg_row_key_tag',0x1a3dece,bytes.fromhex('488d0d'),4,'msg_row_read',
         {0:0x1a3dede,1:0x1a3e071,2:0x1a3df9a,3:0x1a3e04e}),
        ('json_user_open_byte_minus_5b',0x25a49cf,bytes.fromhex('488d35'),33,'json_user_map_read',
         {0:0x25a49e0,32:0x25a4b1c}),
        ('json_master_open_byte_minus_5b',0x25a02a2,bytes.fromhex('488d35'),33,'json_master_map_read',
         {0:0x25a02b3,32:0x25a03a2}),
    )
    tables=[]
    for name, lea, prefix, count, func, expected in table_specs:
        selected=by_name[func]
        base, targets=rel_table(image,lea,prefix,count,selected['start'],selected['end'],expected)
        for index, target in enumerate(targets):
            tables.append((name, hex(lea), hex(base), index, hex(base+4*index), hex(target)))

    spec = extract_classifier(image)
    msg_spec = extract_classifier(image,0x21e6580)
    if msg_spec != spec:
        raise ValueError('JSON and MessagePack row classifiers disagree')
    names=outer_name_sources(image)
    tracker=[]
    for entry, slot, child in zip(names, (0,image.read(0x21f9886,1,True)[0]),
                                  ('msg_user_map_write','msg_master_map_write')):
        name,at,length,*_=entry
        tracker.append((name,hex(at),length,hex(slot),child))
    address_lit_1=image.rip_target(0x21f938a,bytes.fromhex('488d15'))
    address_lit_2=image.rip_target(0x21f93d0,bytes.fromhex('488d15'))
    if image.read(address_lit_1,7) != b'Address' or image.read(address_lit_2,7) != b'Address':
        raise ValueError('row type-name literal mismatch')
    input_width=struct.unpack('<I',image.read(0x21f8dab,4,True))[0]
    if input_width != struct.unpack('<I',image.read(0x21f8e32,4,True))[0]:
        raise ValueError('row address input widths disagree')
    fields=[]
    for tag, key_site, json_key_site, expected_short, offset in (
        (0,0x21f932f,0x21f8d14,b'n',None),
        (1,0x21f936c,0x21f8d3e,b's',image.read(0x21f9389,1,True)[0]),
        (2,0x21f93b2,0x21f8dc5,b'm',image.read(0x21f93cf,1,True)[0])):
        pos=image.rip_target(key_site,bytes.fromhex('488d35'))
        json_pos=image.rip_target(json_key_site,bytes.fromhex('488d35'))
        short=image.read(pos,1)
        if short != expected_short or image.read(json_pos,1) != short or classify_row_key(short,spec) != tag:
            raise ValueError('row key and classifier disagree')
        fields.append((tag,short.decode(),spec['long'][tag].decode(),hex(pos),hex(json_pos),
                       'string_pointer_and_length' if offset is None else hex(offset),
                       '-' if offset is None else input_width,
                       '-' if offset is None else hex(address_lit_1 if tag == 1 else address_lit_2)))
    diagnostics=[]
    for label, a, b in (
        ('user_object',0x25a4d0a,0x25a4d18), ('master_object',0x25a054e,0x25a055c),
        ('user_array',0x265f780,0x265f78e), ('master_array',0x2687380,0x268738e),
        ('msg_user_map',0x26360bc,0x26360ca), ('msg_master_map',0x26574e9,0x26574f7),
        ('msg_user_array',0x26799e7,0x26799f5), ('msg_master_array',0x269dafe,0x269db0c)):
        msg=extract_duplicate_key(image,a,b)
        diagnostics.append((label,hex(a),hex(b),msg.decode('ascii')))
    field_diagnostics=field_errors(image)

    out=Path(out)
    out.mkdir(parents=True,exist_ok=True)
    tsv(out,'functions.tsv',('role','start_va','end_exclusive_va','fde_va','cie_va','file_offset','size_bytes','body_sha256'),
        ((r['name'],hex(r['start']),hex(r['end']),hex(r['fde']),hex(r['cie']),hex(r['file_offset']),r['size'],r['body_sha256']) for r in fdes))
    tsv(out,'edges.tsv',('role','caller_fde','instruction_va','encoding','target_va','bytes','condition'),edges)
    tsv(out,'sort-comparisons.tsv',('role','caller_fde','instruction_va','bytes','slot_va',
        'rela_va','rela_type','symbol_index','symbol_va','name_va','symbol_name'),indirect)
    tsv(out,'hash-context.tsv',('config_store_va','window_bytes','config_bytes','mode_offset',
        'mode_byte','prior_closure_call_va','call_bytes','target_va'),
        [(hex(hash_context['config_va']),hash_context['window_bytes'],hash_context['config_bytes'],
          hex(image.read(0x21f97d2,1,True)[0]),hash_context['mode_byte'],
          hex(hash_context['call_va']),hash_context['call_bytes'],hex(hash_context['target_va']))])
    tsv(out,'tables.tsv',('role','lea_va','table_va','index','entry_va','target_va'),tables)
    tsv(out,'tracker-fields.tsv',('field','literal_va','utf8_length','tracker_offset','msg_child'),tracker)
    tsv(out,'outer-name-sources.tsv',('field','msg_writer_literal_va','length','json_head_va',
        'json_tail_va','msg_head_va','msg_tail_va','json_writer_literal_va'),
        ((x[0],hex(x[1]),x[2],*(hex(v) for v in x[3:])) for x in names))
    tsv(out,'row-fields.tsv',('tag','writer_key','reader_long_alias','msg_literal_va','json_literal_va',
        'value_location','json_input_width','msg_type_literal_va'),fields)
    tsv(out,'duplicate-key.tsv',('input_path','tail_mov_va','head_mov_va','reconstructed_message'),diagnostics)
    tsv(out,'field-errors.tsv',('role','name_lea_va','name_va','field_name',
        'template_lea_va','template_va','template_prefix'),field_diagnostics)
    tsv(out,'anchors.tsv',('role','instruction_va','bytes'),
        ((name,hex(va),image.read(va,len(bytes.fromhex(code)),True).hex()) for name,va,code in ANCHORS))
    cases=[]
    for value in range(256):
        key=bytes([value]); cases.append(('one_byte',key.hex(),classify_row_key(key,spec),classify_row_key(key,msg_spec)))
    for alias in spec['long']:
        cases.append(('long_alias',alias.hex(),classify_row_key(alias,spec),classify_row_key(alias,msg_spec)))
        for i in range(len(alias)):
            altered=alias[:i]+bytes([alias[i]^1])+alias[i+1:]
            cases.append(('long_one_bit_change',altered.hex(),classify_row_key(altered,spec),classify_row_key(altered,msg_spec)))
    for n in (0,2,3,5,7,8,9,10,11,12,13,14,15,17):
        key=b'x'*n; cases.append(('other_length',key.hex(),classify_row_key(key,spec),classify_row_key(key,msg_spec)))
    tsv(out,'classifier-cases.tsv',('case','key_hex','json_model_tag','msg_model_tag'),cases)
    outer_names=tuple(x[0].encode('ascii') for x in names)
    outer_cases=[]
    for value in outer_names:
        outer_cases.append(('field',value.hex(),classify_outer_key(value,outer_names)))
        for i in range(len(value)):
            changed=value[:i]+bytes([value[i]^1])+value[i+1:]
            outer_cases.append(('one_bit_change',changed.hex(),classify_outer_key(changed,outer_names)))
    for n in (0,1,19,22):
        key=b'x'*n
        outer_cases.append(('other_length',key.hex(),classify_outer_key(key,outer_names)))
    tsv(out,'outer-classifier-cases.tsv',('case','key_hex','model_tag'),outer_cases)
    variants=((b'n',spec['long'][0]),(b's',spec['long'][1]),(b'm',spec['long'][2]))
    presence=[]
    for choices in itertools.product(range(4),repeat=3):
        keys=[]
        for choice,pair in zip(choices,variants):
            if choice == 0: keys.append(pair[0])
            elif choice == 1: keys.append(pair[1])
            elif choice == 2: keys.extend(pair)
        presence.append((''.join(map(str,choices)),','.join(key.decode() for key in keys),known_field_outcome(keys,spec)))
    tsv(out,'presence-cases.tsv',('choices_short_long_both_absent','input_keys_in_order','presence_model_result'),presence)
    arities=(('tracker',image.read(0x1740587,1,True)[0]),
             ('user_pair',image.read(0x176dd83,1,True)[0]),
             ('master_pair',image.read(0x196af14,1,True)[0]),
             ('row',image.read(0x1a3cbb8,1,True)[0]))
    arity_cases=[]
    for label,arity in arities:
        for count in (*range(arity+3), 0xffffffff):
            arity_cases.append((label,arity,count,sequence_arity_outcome(count,arity)))
    tsv(out,'arity-cases.tsv',('sequence','required_count','input_count','count_model_result'),arity_cases)
    reserve_limit=struct.unpack('<I',image.read(0x24e0102,4,True))[0]
    reserve_shift=image.read(0x24e011e,1,True)[0]
    reserve_cases=[]
    for count in (0,1,reserve_limit-1,reserve_limit,reserve_limit+1,reserve_limit*2,0xffffffff):
        rows,size=initial_reservation(count,reserve_limit,reserve_shift)
        reserve_cases.append((count,rows,size))
    tsv(out,'reservation-cases.tsv',('input_count','initial_rows_model','initial_bytes_model'),reserve_cases)
    mode_xor=image.read(0x21f9022,1,True)[0]
    mode_shift=image.read(0x21f9026,1,True)[0]
    row_marker=image.read(0x21f902a,1,True)[0]
    prefix=image.read(0x21f9061,1,True)[0]
    keys=tuple(image.read(pos,1,True)[0] for pos in (0x21f9075,0x21f90d2,0x21f912d))
    row_headers=[]
    for flag,form in ((0,'positional'),(1,'named')):
        marker=fast_row_header(flag,mode_xor,mode_shift,row_marker)
        tokens=','.join(bytes((prefix,key)).hex() for key in keys) if flag == 1 else '-'
        row_headers.append((flag,form,f'{marker:02x}',tokens))
    tsv(out,'row-header-cases.tsv',('flag','model_form','header_hex','key_tokens_hex'),row_headers)
    threshold=image.read(0x1fe972f,1,True)[0]
    width=struct.unpack('<I',image.read(0x1fe979b,4,True))[0]
    sort_keys=[bytes([prefix])+bytes(width-1) for prefix in (0x80,0x00,0x7f,0x01)]
    sort_cases=[]
    for values in itertools.permutations(sort_keys):
        result=small_entry_order(values,threshold,width)
        sort_cases.append((','.join(value.hex() for value in values),
                           ','.join(value.hex() for value in result)))
    tsv(out,'small-sort-cases.tsv',('input_keys_hex','model_result_keys_hex'),sort_cases)
    summary={'artifact_sha256':SHA256, 'coordinate_system':'linked ELF virtual addresses; FDE end is exclusive',
             'selected_fde_count':len(fdes), 'direct_call_count':len(CALLS), 'branch_count':len(BRANCHES),
             'table_entries':len(tables), 'classifier_cases':len(cases), 'presence_cases':len(presence),
             'outer_classifier_cases':len(outer_cases),
             'arity_cases':len(arity_cases),
             'reservation_cases':len(reserve_cases),
             'row_header_cases':len(row_headers),
             'selected_indirect_comparisons':len(indirect), 'small_sort_cases':len(sort_cases),
             'prior_hash_context_calls':len((hash_context,)),
             'outer_field_count':len(tracker), 'row_field_count':len(fields),
             'duplicate_key_sites':len(diagnostics),
             'field_error_sites':len(field_diagnostics),
             'scope':'Selected codec copies and edges only; no target execution, state root algorithm, runtime format selection or full parser equivalence.'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    data=checked_image()
    summary=generate(data,args.out)
    print(json.dumps(summary,sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print(f'subaccount_state94: {exc}',file=sys.stderr)
        raise SystemExit(1)
