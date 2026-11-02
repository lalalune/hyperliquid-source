#!/usr/bin/env python3
"""Reproduce selected node 115 precompile lookup evidence without executing code."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SENTINEL = 0x8000000000000013
MASK64 = (1 << 64) - 1

# These are selected evidence intervals, not an inventory or function census.
FUNCTIONS = (
    (0x29a1290, 'context-and-mode-selection'),
    (0x5be7910, 'default-context-constructor'),
    (0x5bee318, 'registry-once-adapter'),
    (0x5bee230, 'registry-initializer-closure'),
    (0x5c18c60, 'mode-registry-builder'),
    (0x5c1a260, 'empty-registry-and-direct-array'),
    (0x5c184e0, 'four-record-extension'),
    (0x5c17bd0, 'one-record-extension'),
    (0x5c06830, 'key-value-map-insertion'),
    (0x296e2b0, 'frame-checkpoint-and-handoff'),
    (0x2a6bc40, 'precompile-invoke-and-result'),
    (0x2a6c360, 'precompile-value-lookup'),
    (0x5be6a80, 'callback-result-to-frame-status'),
    (0x5c165b0, 'address09-result-adapter'),
    (0x5c16650, 'address09-input-and-gas'),
    (0x5bee2d3, 'provider-once-adapter'),
    (0x5bee2a0, 'default-provider-initializer'),
    (0x5bebac0, 'provider-feature-dispatch'),
    (0x5c38870, 'scalar-compression-candidate'),
    (0x5c37750, 'vector-compression-candidate'),
    (0x29710e0, 'checkpoint-revert-helper'),
    (0x5be3400, 'journal-entry-revert-dispatch'),
)

# Each selected block is an uninterrupted run of RIP-relative loads followed by
# stack stores. The final two columns are the expected stack and record bases;
# neither these ranges nor the resulting records constitute an ELF-wide census.
COPY_GROUPS = (
    ('base', 0x5c18c87, 0x5c18d79, 0x1e0, 0x64c04c8, 4),
    ('mode1', 0x5c18d92, 0x5c18e84, 0x1e0, 0x64c05a8, 4),
    ('mode2', 0x5c18ea3, 0x5c18f95, 0x1e0, 0x64c0688, 4),
    ('mode5', 0x5c18fff, 0x5c191a5, 0x1e0, 0x64c07d8, 7),
    ('mode6', 0x5c197b2, 0x5c1982a, 0x520, 0x64c0960, 2),
)

SCALAR_IMMEDIATES = (
    ('iv0', 0x5c3896b, '48b8', 0x6a09e667f3bcc908),
    ('iv1', 0x5c38883, '49bd', 0xbb67ae8584caa73b),
    ('iv2', 0x5c3895c, '48b8', 0x3c6ef372fe94f82b),
    ('iv3', 0x5c3888d, '48b8', 0xa54ff53a5f1d36f1),
    ('iv4', 0x5c388a9, '49bc', 0x510e527fade682d1),
    ('iv5', 0x5c388ba, '48b8', 0x9b05688c2b3e6c1f),
    ('iv6', 0x5c388de, '48b9', 0x1f83d9abfb41bd6b),
    ('iv7', 0x5c3889c, '49ba', 0x5be0cd19137e2179),
    ('not-iv6', 0x5c388d4, '48b8', 0xe07c265404be4294),
)

# Each label is an interpretation of these bytes, checked against exact patterns.
PINS = (
    ('mode_table_and_slot', 0x29a16eb, '488d055616c6fd0fb6440500888424100b0000488d0440c1e005488d0d64c9b5034c8d24018b44085885c00f857c3b0000'),
    ('context_constructor_call', 0x29a12b0, '4989d54989f74889bc2408010000488dbc24100b0000ff15045ab403488dbc2430020000e8270bfdff4c89bc2458030000'),
    ('context_mode_read', 0x29a12e1, '0fb6ac24780d00004088ac2456030000'),
    ('context_mode_narrow', 0x29a15d1, '40886c2428400fb6ed'),
    ('default_context_mode_constant', 0x5be792e, 'c64424700d'),
    ('default_context_mode_copy', 0x5be7ce0, '0f104424680f118360020000'),
    ('default_context_input_failure', 0x5be7ad1, '3dffff00000f8440020000'),
    ('default_context_allocation_one', 0x5be7b6a, 'bf00100000ff150b798f004885c00f84e9010000'),
    ('default_context_allocation_two', 0x5be7b81, 'bf30000000ff15f4788f004885c00f84c0010000'),
    ('context_registry_pointer', 0x29a1805, '4c89a424000f0000'),
    ('frame_call', 0x29a31c3, '488dbc2430020000488db424100b0000488d942450090000e8d0b0fcff'),
    ('frame_registry_field', 0x296e900, '410f10475831c0498db6f0030000'),
    ('frame_precompile_call', 0x296e9b2, '488dbc24c00100004c89f24c89f9e87bd20f00'),
    ('once_state', 0x5bee318, '8b475885c07501c3'),
    ('once_descriptor', 0x5bee345, '488d0dd41c8d004c8d05f51c8d006a015e'),
    ('closure_mode', 0x5bee24b, '0fb630488d7c2408e808aa0200'),
    ('builder_exit_mode0', 0x5c18d84, 'e857f7ffff4084ed0f841d110000'),
    ('builder_exit_mode1', 0x5c18e94, 'e847f6ffff4080fd010f840c100000'),
    ('record09_copy', 0x5c18f57, '488b0502788a0048898424b80200000f1005e3778a000f118424a80200000f1005c4778a000f11842498020000f30f6f05a4778a00f30f7f842488020000'),
    ('builder_exit_mode2', 0x5c18fa5, 'e836f5ffff4080fd020f86fb0e0000'),
    ('builder_exit_mode3', 0x5c18fc3, 'e808ecffff4080fd030f84dd0e0000'),
    ('builder_exit_mode4', 0x5c18fe1, 'e8eaebffff4080fd040f86bf0e0000'),
    ('builder_exit_mode5', 0x5c1979c, '80bc24d000000005488b9c24400100000f84fd060000'),
    ('four_record_copy_size', 0x5c18514, 'bae00000004c89f7'),
    ('record_stride_and_sentinel', 0x5c18574, '49bc1300000000000080488d480148898c24f0000000486bc038'),
    ('record_fields', 0x5c18600, '488b6808488b58104c8b4818440fb640300fb678310fb750328b4834f30f6f5020660f6fc2660fefc9660f74c1'),
    ('small_key_guards', 0x5c1866c, '0f85320200004584c00f85290200004084ff0f852002000089d066c1c008440fb7f04181fe2b0100000f8709020000'),
    ('direct_slot_location', 0x5c18810, '498b4750496bde38488b3418483bb424b0000000'),
    ('direct_slot_write', 0x5c1886e, '4c891418488b8c248000000048894c1808488b4c247848894c18104c894c1818660fefc0f30f7f44182066c744183000006689541832'),
    ('full_map_insert', 0x5c18a77, '488dbc24e0010000488bb424b8000000488d54242c488d4c2440e89addfeff'),
    ('empty_slots_constants', 0x5c1a36e, '0f10057b85d2fa0f100d6485d2fa0f10154d85d2fa'),
    ('empty_slots_allocation', 0x5c1a417, '4805e0000000483da04100000f8567ffffffbfa0410000ff154c508c004885c0'),
    ('publish_array_pointer', 0x5c1a449, 'ff15b9508c00488b442420488943200f2804240f284c24100f114b100f11030f284424300f284c24400f114b38488b442450488943480f1143284c897350'),
    ('map_candidates', 0x5c068e0, '4921d5f3420f6f1428660f6fda660f74d866440fd7cb4585c97465'),
    ('map_key_comparison', 0x5c06906, '49f7da4f8d149249c1e204f3410f6f1c24f3420f6f6410b0660f74e366410f6e5c241066420f6e6c10c0660f74eb660fdbec66440fd7dd4181fbffff0000745b'),
    ('map_control_writes', 0x5c06a30, '4080e7014c8d46f04921d0880c3042884c0010'),
    ('lookup_direct', 0x2a6c360, 'f30f6f06660fefc9660f74c8660fd7c135ffff0000753f807e10007539807e110075330fb7461266c1c0080fb7c03d2c0100007321488b4f50486bd038488d341131c048bf130000000000008048393c11480f45c6c3'),
    ('lookup_hash', 0x2a6c3b6, '48837f18000f84ed000000488b0e488b05ad36a7034c8b00448b4e1048334f20488b46084c31c048f7e14931d14c31c849f7e04831c2'),
    ('lookup_full_comparison', 0x2a6c42d, 'f3450fbcc84901d14921c149f7d94f8d0c8949c1e104f30f6f1ef3420f6f6409b0660f74e3660f6e5e1066420f6e6c09c0660f74eb660fdbec66440fd7d54181faffff0000742b458d48ff664521c14589c875ac'),
    ('lookup_miss_or_return', 0x2a6c481, '660f74d166440fd7c24585c075224801fa4883c2104883c710e974ffffff4c01c9488d41c84885c9480f44c1c331c0c331c9488d41c84885c9480f44c1c3'),
    ('call_lookup', 0x2a6bc5a, '488b3e488db190000000e8f70600004885c07420'),
    ('call_returned_callback', 0x2a6bcea, '498b8e800000004d8b8688000000488d7c2470ff5018'),
    ('adapter_call', 0x5c165bd, '488d7c2408ff1520498d00488b4424084885c074'),
    ('length_gas_flag', 0x5c1665d, '4881fad500000075158b1e0fcb4839d9733548b80100000000000080eb0d48b8010000000000008048ffc04889470848c707000000004889f84881c4180100005b415e415f5dc30fb6aed40000004080fd020f8372010000'),
    ('provider_arguments_and_call', 0x5c16771, '440fb6cd488d542410488d8c24900000004c8d84248000000089deff5058'),
    ('output_allocation', 0x5c167bb, 'ff15bf8c8c004885c00f8489000000'),
    ('output64_and_cost', 0x5c16808, '4c89f74989460849c746104000000049894e1849891649895e20e96cfeffff'),
    ('invalid_flag', 0x5c16827, '48b801000000000000804883c802e94efeffff'),
    ('provider_lazy_call', 0x5c1683a, '488b3d175b8d000f290424e8897afdff0f280424e90fffffff'),
    ('provider_once', 0x5bee2d3, '8b471085c07501c3'),
    ('provider_descriptor', 0x5bee2fc, '488d0d851d8d004c8d053e1d8d006a015eff15dd168f004883c428c3'),
    ('provider_initializer', 0x5bee2a0, '488b0f488b0148c701000000004885c0741348c70001000000488d0da01c8d0048894808c3'),
    ('cpu_dispatch', 0x5bebacd, '488b058c3f8f00488b004885c0742c450fb6c14889d64889ca4889d96685c0'),
    ('scalar_jump', 0x5bebaf6, 'e975cd0400'),
    ('vector_jump', 0x5bebb03, 'e948bc0400'),
    ('scalar_final_flag', 0x5c388d1, '4585c048b89442be0454267ce048b96bbd41fbabd9831f480f45c8'),
    ('scalar_rounds_zero', 0x5c38905, '85ff48891424'),
    ('scalar_rol32', 0x5c38a58, '49c1c420'),
    ('scalar_rol40', 0x5c38a6c, '48c1c528'),
    ('scalar_rol48', 0x5c38aa8, '49c1c730'),
    ('scalar_rol1', 0x5c38acf, '49d1c0'),
    ('scalar_state_writes', 0x5c38cf3, '488b4424084889304c336c24e04c8968084c335c24d84c89581048335424c84889501848336c24d04c31e5488968204c334424e84c334424804c89402848334c24f0488948304c335424f84c895038'),
    ('frame_variant', 0x296e390, '4883fa0174644883fa020f8557170000'),
    ('frame_depth_guard', 0x296e442, '4981fd010400008844240f48894c24680f8295000000'),
    ('frame_depth_failure', 0x296e478, '410f1047700f298424b00300000f57c00f298424c0000000b01189442420'),
    ('frame_checkpoint', 0x296e4ed, '498b9680020000498b8698020000498b8eb00200004889142448899424e800000048898424f000000048898c24f8000000'),
    ('frame_depth_increment', 0x296e51e, '498b86880300004883f8ff0f84281700004d8da67002000048ffc049898688030000'),
    ('frame_handoff_choice', 0x296e621, '498b47504885c00f84d2020000'),
    ('frame_status_and_depth', 0x296eb3b, '807c2420050f83e0040000'),
    ('frame_depth_release', 0x296eb4e, '498b86880300004883f8014883d0ff49898688030000'),
    ('frame_revert_call', 0x296f084, '488db424e80000004c89e7e84c200000'),
    ('input_span_and_bounds', 0x2a6bc97, '498b8fb8030000488b7910488d75ff4839f70f8315060000498b76584c8d49104c8d47014c8941104989d04929f04c890c247212483b5128770c480371204531e44c89c2eb0d498939be0100000041b40131d2'),
    ('result_diagnostic_gate', 0x2a6be0e, '488d4d244839c80f83fb030000488d4d014839c80f84ee0300004983bf88030000010f85e0030000'),
    ('result_diagnostic_index', 0x2a6be48, '488d0c2848ffc94839e841bc23000000490f46cc48c784248000000000000000488d054573b9fd48630c884801c1ffe1'),
    ('result_diagnostic_state', 0x2a6c1cf, '4d8da7a00300000f104424700f294424104c896c2420498b34244839ee74144885f6740f498bbfa803000031d2ff159e32a703488b4424204989442410'),
    ('result_converter_call', 0x2a6c273, '498b9680000000488d7424704889dfff15c8aea703'),
    ('result_tag_classification', 0x5be6a91, '49bfdcffffffffffff7f488b364a8d043e498d4f474839ceb902000000480f47c8'),
    ('result_mode_selection', 0x5be6abc, '4883f9024c8d25398f8d004d8b46184d0f44c4b801000000490f4546207406'),
    ('result_error_status', 0x5be6b20, '48c744244000000000498d47254839c6b823000000bd310000000f44e84983c7484c39fe0f9cc04885f60f94c108c1750c498b7e0831d2ff1543898f0040886c2460'),
    ('result_status_copy', 0x5be6b97, '0fb6442460884358'),
    ('result_gas_subtract', 0x5be6bcf, '492b56380f83c1000000'),
    ('result_success_status', 0x5be6c9a, '4885c9b802000000b9100000000f44c84889542440884c2460'),
    ('revert_counter_and_bounds', 0x29710f7, '0fb6872601000088442407488b87180100004883f8014883d0ff4c8b671048898718010000488b064c39e00f86ed000000'),
    ('revert_snapshots', 0x2971128, '498b4610483b4340770448894340498b4e08488b43284839c10f83bc0000004c8db3c80000004c8dbbf0000000488d531848894b28488b73204c6be158'),
    ('revert_journal_tag', 0x29711a0, '410fb645003c0c745a31c9807c2407030f93c1'),
    ('revert_journal_loop', 0x29711ec, '488d7c24304c89f64c89faffd34983c5a84983c458759d'),
    ('journal_dispatch', 0x5be3411, '4889f30fb607488d352aeed5fa486304864801f0ffe0'),
    ('journal_tag0_flag', 0x5be344c, '80888c00000010'),
    ('journal_tag1_flag_and_add', 0x5be3980, '20888c0000004c0170284c1178304c1160384c116840'),
    ('journal_tag2_flag', 0x5be35d0, '80a08c000000fb'),
    ('journal_tag3_words', 0x5be3602, 'f3410f6f4618f3410f6f4e28f30f7f4838f30f7f4028'),
    ('journal_tag4_add', 0x5be3505, '4c0170284c1178304c1160384c116840'),
    ('journal_tag4_subtract', 0x5be39d4, '4c2970284c1978304c1960384c196840'),
    ('journal_tag5_restore', 0x5be36e8, '4c897068'),
    ('journal_tag6_decrement', 0x5be3716, '488b48684883f9014883d1ff48894868'),
    ('journal_tag7_fields', 0x5be3646, '4080f57f4020a88c00000048c7406800000000'),
    ('journal_tag8_fields', 0x5be3963, '4983c638f3410f6f06f3410f6f4e10f30f7f4830f30f7f4020'),
    ('journal_tag9_flag', 0x5be3585, 'c6404401'),
    ('journal_tag10_gate', 0x5be376f, '4885d20f846c020000660f6f8424b0000000660feb8424c0000000660fefc9660f76c80f50c183f00f0f845802'),
    ('journal_tag11_fields', 0x5be347e, '0f10052b5187fa0f114358f30f6f050f5187faf30f7f43484883c370488b40704885c0740ff048ff0875094889dfff15f61a900048c70300000000'),
)

# Fixed opcode family and expected destination; displacement is read from the ELF.
EDGES = (
    ('context_needs_initializer', 0x29a1716, '0f85', 0x29a5298),
    ('context_initialize', 0x29a52a3, 'e8', 0x5bee318),
    ('context_after_initialize', 0x29a52a8, 'e9', 0x29a171c),
    ('context_call_frame', 0x29a31db, 'e8', 0x296e2b0),
    ('default_context_auxiliary_initialization', 0x29a12d4, 'e8', 0x2971e00),
    ('default_context_invalid_branch', 0x5be7ad6, '0f84', 0x5be7d1c),
    ('default_context_first_allocation_failure', 0x5be7b78, '0f84', 0x5be7d67),
    ('default_context_second_allocation_failure', 0x5be7b8f, '0f84', 0x5be7d55),
    ('frame_variant_one', 0x296e394, '74', 0x296e3fa),
    ('frame_depth_at_most_1024', 0x296e452, '0f82', 0x296e4ed),
    ('frame_depth_overflow', 0x296e529, '0f84', 0x296fc57),
    ('frame_handoff_without_indirect_input', 0x296e628, '0f84', 0x296e900),
    ('frame_handoff_after_indirect_input', 0x296e65c, 'e9', 0x296e907),
    ('frame_call_precompile', 0x296e9c0, 'e8', 0x2a6bc40),
    ('frame_status_test', 0x296e9ed, '75', 0x296ea31),
    ('frame_lookup_miss', 0x296ea8e, '0f84', 0x296ee97),
    ('frame_revert_if_status_high', 0x296eb40, '0f83', 0x296f026),
    ('frame_revert_helper', 0x296f08f, 'e8', 0x29710e0),
    ('once_initialization_needed', 0x5bee31d, '75', 0x5bee320),
    ('closure_build', 0x5bee253, 'e8', 0x5c18c60),
    ('mode_zero_exit', 0x5c18d8c, '0f84', 0x5c19eaf),
    ('mode_one_exit', 0x5c18e9d, '0f84', 0x5c19eaf),
    ('mode_two_extension', 0x5c18fa5, 'e8', 0x5c184e0),
    ('mode_two_exit', 0x5c18fae, '0f86', 0x5c19eaf),
    ('mode_three_extension', 0x5c18fc3, 'e8', 0x5c17bd0),
    ('mode_three_exit', 0x5c18fcc, '0f84', 0x5c19eaf),
    ('mode_four_extension', 0x5c18fe1, 'e8', 0x5c17bd0),
    ('mode_four_exit', 0x5c18fea, '0f86', 0x5c19eaf),
    ('mode_five_exit', 0x5c197ac, '0f84', 0x5c19eaf),
    ('reserve_set', 0x5c18533, '0f86', 0x5c18b75),
    ('reserve_map', 0x5c1853e, '0f86', 0x5c18b92),
    ('invalid_small_prefix', 0x5c1866c, '0f85', 0x5c188a4),
    ('invalid_small_byte16', 0x5c18675, '0f85', 0x5c188a4),
    ('invalid_small_byte17', 0x5c1867e, '0f85', 0x5c188a4),
    ('small_address_above_299', 0x5c18695, '0f87', 0x5c188a4),
    ('map_insert', 0x5c18a91, 'e8', 0x5c06830),
    ('fill_direct_array_loop', 0x5c1a423, '0f85', 0x5c1a390),
    ('direct_array_allocation_failed', 0x5c1a437, '74', 0x5c1a4b2),
    ('lookup_from_frame', 0x2a6bc64, 'e8', 0x2a6c360),
    ('lookup_miss', 0x2a6bc6c, '74', 0x2a6bc8e),
    ('input_uses_context_buffer', 0x2a6bc83, '74', 0x2a6bc97),
    ('input_counter_saturated', 0x2a6bca9, '0f83', 0x2a6c2c4),
    ('input_range_underflow', 0x2a6bcc9, '72', 0x2a6bcdd),
    ('input_range_overrun', 0x2a6bccf, '77', 0x2a6bcdd),
    ('skip_diagnostic_on_success_tag', 0x2a6be15, '0f83', 0x2a6c216),
    ('skip_diagnostic_on_gas_error', 0x2a6be22, '0f84', 0x2a6c216),
    ('skip_diagnostic_beyond_first_depth', 0x2a6be30, '0f85', 0x2a6c216),
    ('length_diagnostic_join', 0x2a6c086, 'e9', 0x2a6c191),
    ('flag_diagnostic_join', 0x2a6c03e, 'e9', 0x2a6c191),
    ('lookup_prefix_nonzero', 0x2a6c375, '75', 0x2a6c3b6),
    ('lookup_byte16_nonzero', 0x2a6c37b, '75', 0x2a6c3b6),
    ('lookup_byte17_nonzero', 0x2a6c381, '75', 0x2a6c3b6),
    ('lookup_address_at_least_300', 0x2a6c393, '73', 0x2a6c3b6),
    ('lookup_empty_map', 0x2a6c3bb, '0f84', 0x2a6c4ae),
    ('lookup_match', 0x2a6c472, '74', 0x2a6c49f),
    ('lookup_candidate_loop', 0x2a6c47f, '75', 0x2a6c42d),
    ('lookup_empty_control', 0x2a6c48d, '75', 0x2a6c4b1),
    ('lookup_next_group', 0x2a6c49a, 'e9', 0x2a6c413),
    ('adapter_result_is_error', 0x5c165d0, '74', 0x5c165ed),
    ('result_conversion_success', 0x5be6b1a, '0f85', 0x5be6bcf),
    ('result_gas_subtraction_no_borrow', 0x5be6bd3, '0f83', 0x5be6c9a),
    ('revert_record_stop', 0x29711a7, '74', 0x2971203),
    ('revert_record_loop', 0x2971201, '75', 0x29711a0),
    ('journal_tag0_missing', 0x5be3446, '0f84', 0x5be3a74),
    ('journal_tag1_missing', 0x5be36a1, '0f84', 0x5be3a81),
    ('journal_tag2_missing', 0x5be35ca, '0f84', 0x5be3acf),
    ('journal_tag3_missing', 0x5be35fc, '0f84', 0x5be3a5a),
    ('journal_tag4_first_missing', 0x5be34ff, '0f84', 0x5be3a40),
    ('journal_tag5_missing', 0x5be36e2, '0f84', 0x5be3a8e),
    ('journal_tag6_missing', 0x5be3710, '0f84', 0x5be3a9b),
    ('journal_tag7_missing', 0x5be3640, '0f84', 0x5be3a67),
    ('journal_tag8_account_missing', 0x5be3949, '0f84', 0x5be3aa8),
    ('journal_tag8_slot_missing', 0x5be395d, '0f84', 0x5be3ac2),
    ('journal_tag9_account_missing', 0x5be356b, '0f84', 0x5be3a4d),
    ('journal_tag9_slot_missing', 0x5be357f, '0f84', 0x5be3ab5),
    ('journal_tag10_no_context', 0x5be3772, '0f84', 0x5be39e4),
    ('journal_tag10_zero_value', 0x5be3798, '0f84', 0x5be39f6),
    ('journal_tag11_missing', 0x5be3475, '0f84', 0x5be3a33),
    ('length_not_213', 0x5c16664, '75', 0x5c1667b),
    ('gas_at_least_rounds', 0x5c1666d, '73', 0x5c166a4),
    ('flag_at_least_two', 0x5c166af, '0f83', 0x5c16827),
    ('provider_needs_initialization', 0x5c1675c, '0f85', 0x5c1683a),
    ('output_allocation_failed', 0x5c167c4, '0f84', 0x5c16853),
    ('flag_error_return', 0x5c16835, 'e9', 0x5c16688),
    ('provider_initialize', 0x5c16845, 'e8', 0x5bee2d3),
    ('provider_once_needs_work', 0x5bee2d8, '75', 0x5bee2db),
    ('cpu_features_uninitialized', 0x5bebada, '74', 0x5bebb08),
    ('vector_feature_set', 0x5bebaec, '78', 0x5bebafb),
    ('scalar_backend', 0x5bebaf6, 'e9', 0x5c38870),
    ('vector_backend', 0x5bebb03, 'e9', 0x5c37750),
    ('scalar_zero_rounds', 0x5c3892e, '0f84', 0x5c38c9e),
)

RIP = (
    ('default-context-constructor-slot', 0x29a12c6, 'ff15', 0x64e6cd0),
    ('mode-byte-map', 0x29a16eb, '488d05', 0x602d48),
    ('mode-slots', 0x29a1705, '488d0d', 0x64fe070),
    ('registry-closure-vtable', 0x5bee345, '488d0d', 0x64c0020),
    ('registry-constructor-slot', 0x5c18c81, 'ff15', 0x64ec3c0),
    ('record09-word48', 0x5c18f57, '488b05', 0x64c0760),
    ('record09-bytes32', 0x5c18f66, '0f1005', 0x64c0750),
    ('record09-bytes16', 0x5c18f75, '0f1005', 0x64c0740),
    ('record09-bytes0', 0x5c18f84, 'f30f6f05', 0x64c0730),
    ('mode3-single-record', 0x5c18fb4, '488d35', 0x64c0768),
    ('mode4-single-record', 0x5c18fd2, '488d35', 0x64c07a0),
    ('value-jump-table', 0x5c186b4, '488d0d', 0x942740),
    ('array-initial-sentinel', 0x5c1a37c, '0f1015', 0x9428d0),
    ('global-hash-secret-slot', 0x2a6c3c4, '488b05', 0x64dfa78),
    ('adapter-inner-slot', 0x5c165c2, 'ff15', 0x64eaee8),
    ('result-converter-slot', 0x2a6c282, 'ff15', 0x64e7150),
    ('result-diagnostic-table', 0x2a6be68, '488d05', 0x6031b4),
    ('provider-object-slot', 0x5c1674f, '4c8b3d', 0x64ec358),
    ('provider-once-vtable', 0x5bee2fc, '488d0d', 0x64c0088),
    ('default-provider-vtable', 0x5bee2b9, '488d0d', 0x64bff60),
    ('feature-word-slot', 0x5bebacd, '488b05', 0x64dfa60),
    ('scalar-round-table-pointer', 0x5c3893b, '488d35', 0x943c33),
    ('rollback-dispatch-slot', 0x2971195, '488b1d', 0x64e6d68),
    ('rollback-journal-table', 0x5be3417, '488d35', 0x942248),
    ('rollback-constant-first-half', 0x5be3489, 'f30f6f05', 0x4585a0),
    ('rollback-constant-second-half', 0x5be347e, '0f1005', 0x4585b0),
    ('frame-source-location', 0x29a54d1, '4c8d0d', 0x6441e20),
)

# RELA slots relevant to the selected path. Unspecified runtime values remain unknown.
RELOCS = (
    (0x64e6cd0, 0x5be7910),
    (0x64c0040, 0x5bee230),
    (0x64ec3c0, 0x5c1a260),
    (0x64c0748, 0x5c165b0),
    (0x64eaee8, 0x5c16650),
    (0x64ec358, 0x64fe3d8),
    (0x64c00a8, 0x5bee2a0),
    (0x64bffb8, 0x5bebac0),
    (0x64dfa60, 0x6500098),
    (0x64dfa78, 0x64ffe90),
    (0x64e7150, 0x5be6a80),
    (0x64e6d68, 0x5be3400),
    (0x6441e20, 0x43491a),
    (0x64c0cd8, 0x44a0dc),
)


def digest_checked(data, expected=SHA256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('target SHA-256 mismatch')
    return actual


def read_va(data, secs, va, size, *, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid address or size')
    if va + size > (1 << 64):
        raise ValueError('address overflow')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address is not uniquely file-backed')
    sec = matches[0]
    off = sec['offset'] + va - sec['address']
    if off < 0 or off + size > len(data):
        raise ValueError('section bytes outside file')
    return data[off:off + size], off, sec['name']


def check_pin(data, secs, va, expected):
    expected = bytes.fromhex(expected) if isinstance(expected, str) else expected
    actual, off, name = read_va(data, secs, va, len(expected), executable=True)
    if actual != expected:
        raise ValueError('instruction predicate mismatch at ' + hex(va))
    return {'va': hex(va), 'file_offset': hex(off), 'section': name, 'bytes': actual.hex()}


def rel32_or_rel8(data, secs, va, prefix):
    op = bytes.fromhex(prefix)
    if len(op) == 1 and op[0] in (0xe8, 0xe9):
        n = 4
    elif len(op) == 2 and op[0] == 0x0f and 0x80 <= op[1] <= 0x8f:
        n = 4
    elif len(op) == 1 and (0x70 <= op[0] <= 0x7f or op[0] == 0xeb):
        n = 1
    else:
        raise ValueError('unsupported relative edge')
    raw, off, _ = read_va(data, secs, va, len(op) + n, executable=True)
    if not raw.startswith(op):
        raise ValueError('unexpected relative opcode at ' + hex(va))
    delta = int.from_bytes(raw[len(op):], 'little', signed=True)
    target = va + len(raw) + delta
    read_va(data, secs, target, 1, executable=True)
    return {'site_va': hex(va), 'file_offset': hex(off), 'bytes': raw.hex(),
            'target_va': hex(target)}


def rip_relative(data, secs, va, prefix):
    op = bytes.fromhex(prefix)
    raw, off, _ = read_va(data, secs, va, len(op) + 4, executable=True)
    if not raw.startswith(op):
        raise ValueError('unexpected RIP opcode at ' + hex(va))
    target = va + len(raw) + int.from_bytes(raw[len(op):], 'little', signed=True)
    return {'site_va': hex(va), 'file_offset': hex(off), 'bytes': raw.hex(),
            'target_va': hex(target)}


def movabs_immediate(data, secs, va, prefix, expected):
    op = bytes.fromhex(prefix)
    raw, off, _ = read_va(data, secs, va, len(op) + 8, executable=True)
    if not raw.startswith(op):
        raise ValueError('unexpected immediate opcode at ' + hex(va))
    value = int.from_bytes(raw[len(op):], 'little')
    if value != expected:
        raise ValueError('immediate mismatch at ' + hex(va))
    return {'va': hex(va), 'file_offset': hex(off), 'bytes': raw.hex(), 'value': hex(value)}


def relocations(data, secs):
    found = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(found) != 1 or found[0]['size'] % 24:
        raise ValueError('invalid dynamic RELA section')
    sec = found[0]
    result = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', data, off)
        if target in result:
            raise ValueError('duplicate dynamic relocation')
        result[target] = (info, addend, off)
    return result


def relative_reloc(rows, slot, expected=None):
    if slot not in rows:
        raise ValueError('missing relocation at ' + hex(slot))
    info, addend, off = rows[slot]
    if info != 8 or addend < 0 or (expected is not None and addend != expected):
        raise ValueError('unexpected relocation at ' + hex(slot))
    return {'slot_va': hex(slot), 'type': info, 'addend_va': hex(addend),
            'entry_file_offset': hex(off)}


def conversion_entries(data, secs, base, count, lower, upper):
    if count <= 0 or lower >= upper:
        raise ValueError('invalid conversion table bounds')
    result = []
    for i in range(count):
        raw, off, _ = read_va(data, secs, base + 4 * i, 4)
        target = base + struct.unpack('<i', raw)[0]
        if not lower <= target < upper:
            raise ValueError('jump-table entry outside selected FDE')
        case_bytes, _, _ = read_va(data, secs, target, 5, executable=True)
        result.append({'index': i, 'entry_va': hex(base + 4 * i), 'file_offset': hex(off),
                       'entry_bytes': raw.hex(), 'target_va': hex(target),
                       'target_prefix': case_bytes.hex()})
    return result


def diagnostic_entry(data, secs, index):
    if index not in (1, 2):
        raise ValueError('unsupported diagnostic index')
    base = 0x6031b4
    raw, table_off, _ = read_va(data, secs, base + 4 * index, 4)
    target = base + struct.unpack('<i', raw)[0]
    if not 0x2a6bc40 <= target < 0x2a6c35e:
        raise ValueError('diagnostic case outside selected FDE')
    code, code_off, _ = read_va(data, secs, target, 6, executable=True)
    if not code.startswith(bytes.fromhex('41bc')):
        raise ValueError('unexpected diagnostic length opcode')
    length = int.from_bytes(code[2:], 'little')
    if not 0 < length <= 128:
        raise ValueError('unexpected diagnostic length')
    pointer = rip_relative(data, secs, target + 6, '488d05')
    text_va = int(pointer['target_va'], 16)
    literal, text_off, _ = read_va(data, secs, text_va, length)
    if any(c < 0x20 or c > 0x7e for c in literal):
        raise ValueError('diagnostic is not printable ASCII')
    return {'index': index, 'entry_va': hex(base + 4 * index),
            'entry_file_offset': hex(table_off), 'entry_bytes': raw.hex(),
            'case_va': hex(target), 'case_file_offset': hex(code_off),
            'length_opcode': code.hex(), 'length': length,
            'pointer_instruction': pointer, 'literal_va': hex(text_va),
            'literal_file_offset': hex(text_off), 'literal': literal.decode('ascii')}


def default_selector(data, secs):
    """Recover the selected constructor's local default and caller stack offsets."""
    init = bytes.fromhex(check_pin(data, secs, 0x5be792e, 'c64424700d')['bytes'])
    copy = bytes.fromhex(check_pin(data, secs, 0x5be7ce0, '0f104424680f118360020000')['bytes'])
    base = bytes.fromhex(check_pin(data, secs, 0x29a12be, '488dbc24100b0000')['bytes'])
    load = bytes.fromhex(check_pin(data, secs, 0x29a12e1, '0fb6ac24780d0000')['bytes'])
    field = int.from_bytes(copy[8:12], 'little') + init[3] - copy[4]
    caller_base = int.from_bytes(base[4:8], 'little')
    caller_load = int.from_bytes(load[4:8], 'little')
    if field != caller_load - caller_base or init[4] >= 15:
        raise ValueError('default selector offsets do not agree')
    mapped, off, _ = read_va(data, secs, 0x602d48 + init[4], 1)
    return {'constructor_store_va': '0x5be792e', 'constructor_store_bytes': init.hex(),
            'copy_va': '0x5be7ce0', 'copy_bytes': copy.hex(),
            'caller_base_va': '0x29a12be', 'caller_load_va': '0x29a12e1',
            'context_field_offset': hex(field), 'selector_byte': init[4],
            'mapping_va': hex(0x602d48 + init[4]), 'mapping_file_offset': hex(off),
            'builder_mode': mapped[0],
            'qualification': 'conditional on normal constructor and intervening helper returns and no mutation of the byte'}


def one_fde(fdes, start):
    rows = [f for f in fdes if f['start'] == start]
    if len(rows) != 1 or rows[0]['end'] <= start:
        raise ValueError('missing or duplicate FDE')
    return rows[0]


def record(data, secs, rows, address):
    raw, off, sec = read_va(data, secs, address, 56)
    tag = struct.unpack_from('<Q', raw)[0]
    key = raw[32:52]
    callback = relative_reloc(rows, address + 24)
    if tag >> 63 != 1 or raw[52:] != b'\0' * 4:
        raise ValueError('unexpected record layout')
    return {'record_va': hex(address), 'file_offset': hex(off), 'section': sec,
            'tag': hex(tag), 'key_hex': key.hex(), 'record_bytes': raw.hex(),
            'callback_slot_va': callback['slot_va'], 'callback_va': callback['addend_va']}


def copy_group(data, secs, name, start, end, stack_base, record_base, record_count):
    """Decode only the adjacent load/store shapes in one selected copy run."""
    if end <= start or record_count <= 0:
        raise ValueError('invalid copy range')
    size = 56 * record_count
    reconstructed = bytearray(size)
    written = bytearray(size)
    source_all, _, _ = read_va(data, secs, record_base, size)
    rows = []
    pos = start
    while pos < end:
        head, _, _ = read_va(data, secs, pos, min(4, end - pos), executable=True)
        if head.startswith(bytes.fromhex('488b05')):
            load, stores, width = bytes.fromhex('488b05'), (bytes.fromhex('48898424'),), 8
        elif head.startswith(bytes.fromhex('0f1005')):
            load = bytes.fromhex('0f1005')
            stores = (bytes.fromhex('0f118424'), bytes.fromhex('0f298424'))
            width = 16
        elif head.startswith(bytes.fromhex('f30f6f05')):
            load = bytes.fromhex('f30f6f05')
            stores = (bytes.fromhex('f30f7f8424'), bytes.fromhex('660f7f8424'))
            width = 16
        else:
            raise ValueError('unsupported copy load at ' + hex(pos))
        raw_load, code_off, _ = read_va(data, secs, pos, len(load) + 4, executable=True)
        src = pos + len(raw_load) + int.from_bytes(raw_load[len(load):], 'little', signed=True)
        store_va = pos + len(raw_load)
        store_head, _, _ = read_va(data, secs, store_va, max(map(len, stores)), executable=True)
        chosen = next((s for s in stores if store_head.startswith(s)), None)
        if chosen is None:
            raise ValueError('unsupported copy store at ' + hex(store_va))
        raw_store, _, _ = read_va(data, secs, store_va, len(chosen) + 4, executable=True)
        dest = int.from_bytes(raw_store[len(chosen):], 'little')
        index = dest - stack_base
        if index < 0 or index + width > size or src != record_base + index:
            raise ValueError('copy source or destination outside expected record')
        if index // 56 != (index + width - 1) // 56 or any(written[index:index + width]):
            raise ValueError('copy overlaps or crosses a record')
        content, source_off, _ = read_va(data, secs, src, width)
        reconstructed[index:index + width] = content
        written[index:index + width] = b'\x01' * width
        rows.append({'group': name, 'load_va': hex(pos), 'code_file_offset': hex(code_off),
                     'instruction_bytes': (raw_load + raw_store).hex(), 'source_va': hex(src),
                     'source_file_offset': hex(source_off), 'stack_offset': hex(dest),
                     'width': width, 'content_bytes': content.hex()})
        pos = store_va + len(raw_store)
    if pos != end or not all(written) or reconstructed != source_all:
        raise ValueError('incomplete record copy group')
    return rows


def fold64(a, b):
    product = (a & MASK64) * (b & MASK64)
    return ((product & MASK64) ^ (product >> 64)) & MASK64


def key_hash(key, map_seed, process_word):
    if len(key) != 20 or not 0 <= map_seed <= MASK64 or not 0 <= process_word <= MASK64:
        raise ValueError('invalid hash input')
    first = int.from_bytes(key[0:8], 'little') ^ map_seed
    second = int.from_bytes(key[8:16], 'little') ^ process_word
    last = int.from_bytes(key[16:20], 'little')
    return fold64(fold64(first, second) ^ last, process_word)


def direct_index(key, limit=300):
    if len(key) != 20:
        raise ValueError('address must have exactly twenty bytes')
    n = int.from_bytes(key[18:20], 'big')
    return n if key[:18] == bytes(18) and n < limit else None


def model_lookup(key, direct, controls, buckets, map_seed, process_word, *, entry_count=None):
    """Model selected lookup logic over synthetic values; never execute machine code."""
    idx = direct_index(key)
    if idx is not None:
        if len(direct) != 300:
            raise ValueError('direct table has wrong length')
        return direct[idx]
    if entry_count is not None:
        if not isinstance(entry_count, int) or entry_count < 0:
            raise ValueError('invalid map entry count')
        if entry_count == 0:
            return None
    count = len(controls)
    if count < 16 or count & (count - 1) or len(buckets) != count:
        raise ValueError('invalid synthetic hash table')
    if any(not 0 <= c <= 255 for c in controls):
        raise ValueError('invalid control byte')
    mask = count - 1
    h = key_hash(key, map_seed, process_word)
    pos = h & mask
    step = 0
    for _ in range(count // 16 + 1):
        indices = [(pos + i) & mask for i in range(16)]
        for i in indices:
            if controls[i] == h >> 57:
                item = buckets[i]
                if item is not None and len(item[0]) == 20 and item[0] == key:
                    return item[1]
        if any(controls[i] == 0xff for i in indices):
            return None
        step += 16
        pos = (pos + step) & mask
    raise ValueError('synthetic table has no terminating empty control')


def input_decision(payload, gas):
    if not isinstance(gas, int) or not 0 <= gas <= MASK64:
        raise ValueError('gas must be an unsigned 64-bit integer')
    if len(payload) != 213:
        return {'result': 'length-error', 'word': hex(0x8000000000000002)}
    rounds = int.from_bytes(payload[:4], 'big')
    if gas < rounds:
        return {'result': 'gas-error', 'word': hex(0x8000000000000001), 'rounds': rounds}
    if payload[212] >= 2:
        return {'result': 'flag-error', 'word': hex(0x8000000000000003), 'rounds': rounds}
    return {'result': 'provider-call', 'rounds': rounds, 'flag': payload[212]}


def frame_status(decision, gas):
    """Model only the four observed adapter results under normal returns."""
    if not isinstance(gas, int) or not 0 <= gas <= MASK64:
        raise ValueError('invalid synthetic gas')
    kind = decision['result']
    if kind == 'gas-error':
        return 0x23
    if kind in ('length-error', 'flag-error'):
        return 0x31
    if kind != 'provider-call':
        raise ValueError('unsupported synthetic result')
    return 2 if gas >= decision['rounds'] else 0x23


def saturating_decrement(value):
    if not isinstance(value, int) or not 0 <= value <= MASK64:
        raise ValueError('counter must be an unsigned 64-bit integer')
    return max(0, value - 1)


def synthetic_cases():
    direct = [None] * 300
    direct[9] = 'address09-callback'
    k9 = bytes(19) + b'\x09'
    generic = b'\x01' + bytes(19)
    missing = b'\x02' + bytes(19)
    seed, secret = 0x0123456789abcdef, 0xfedcba9876543210
    h = key_hash(generic, seed, secret)
    controls = [0xff] * 32
    buckets = [None] * 32
    at = h & 31
    controls[at] = h >> 57
    buckets[at] = (generic, 'generic-hit')
    def payload(rounds, flag, length=213):
        p = bytearray(length)
        if length >= 4:
            p[:4] = rounds.to_bytes(4, 'big')
        if length >= 213:
            p[212] = flag
        return bytes(p)
    cases = []
    for name, rnd, gas, flag, length in (
        ('short', 0, 0, 0, 212), ('long', 0, 0, 0, 214),
        ('zero-round-zero-gas', 0, 0, 0, 213), ('equal-gas-flag-one', 1, 1, 1, 213),
        ('underfunded-before-bad-flag', 1, 0, 2, 213), ('bad-flag', 1, 1, 2, 213),
        ('max-rounds-equal-gas', 0xffffffff, 0xffffffff, 0, 213),
        ('max-rounds-one-less', 0xffffffff, 0xfffffffe, 1, 213),
    ):
        decision = input_decision(payload(rnd, flag, length), gas)
        status = frame_status(decision, gas)
        cases.append({'name': name, 'input_length': length, 'rounds_argument': rnd,
                      'gas': gas, 'flag_argument': flag, 'decision': decision,
                      'conditional_frame_status': status,
                      'conditional_checkpoint_action': 'revert' if status >= 5 else 'release-depth'})
    return {'qualification': 'synthetic arithmetic and lookup models; not execution or runtime fixtures',
            'lookup': {'key09_direct_index': direct_index(k9),
                       'key09_result': model_lookup(k9, direct, controls, buckets, seed, secret),
                       'generic_hash': hex(h), 'generic_result': model_lookup(generic, direct, controls, buckets, seed, secret),
                       'generic_miss': model_lookup(missing, direct, controls, buckets, seed, secret),
                       'map_seed': hex(seed), 'process_word': hex(secret)},
            'input_cases': cases,
            'counter_cases': [{'before': hex(n), 'after': hex(saturating_decrement(n))}
                              for n in (0, 1, 2, MASK64)]}


def derive_mode_records(records):
    """Model the selected builder's ordered direct-slot updates, not live state."""
    if len(records) != 23:
        raise ValueError('unexpected source record count')
    ranges = ((0, 4), (4, 8), (8, 12), (12, 13), (13, 14), (14, 21), (21, 23))
    active = {}
    result = []
    for mode, (first, end) in enumerate(ranges):
        updates = records[first:end]
        for item in updates:
            active[item['key_hex']] = item['callback_va']
        result.append({'mode': mode,
                       'updated_record_vas': [item['record_va'] for item in updates],
                       'derived_entries': [{'key_hex': key, 'callback_va': active[key]}
                                           for key in sorted(active)]})
    return result


def collect(data):
    digest = digest_checked(data)
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    rels = relocations(data, secs)
    functions = []
    for start, role in FUNCTIONS:
        fde = one_fde(fdes, start)
        raw, off, sec = read_va(data, secs, start, fde['end'] - start, executable=True)
        functions.append({'role': role, 'start_va': hex(start), 'end_va': hex(fde['end']),
                          'file_offset': hex(off), 'section': sec, 'fde_va': hex(fde['fde']),
                          'cie_va': hex(fde['cie']), 'lsda_va': hex(fde['lsda']) if fde['lsda'] is not None else None,
                          'length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': raw.hex()})
    pins = []
    for name, va, expected in PINS:
        pins.append({'name': name, **check_pin(data, secs, va, expected)})
    edges = []
    for name, va, op, expected in EDGES:
        row = rel32_or_rel8(data, secs, va, op)
        if int(row['target_va'], 16) != expected:
            raise ValueError('edge target mismatch at ' + hex(va))
        edges.append({'name': name, **row})
    refs = []
    for name, va, op, expected in RIP:
        row = rip_relative(data, secs, va, op)
        if int(row['target_va'], 16) != expected:
            raise ValueError('RIP target mismatch at ' + hex(va))
        refs.append({'name': name, **row})
    immediates = [{'name': name, **movabs_immediate(data, secs, va, op, expected)}
                  for name, va, op, expected in SCALAR_IMMEDIATES]
    rel_rows = [relative_reloc(rels, slot, addend) for slot, addend in RELOCS]
    records = [record(data, secs, rels, 0x64c04c8 + 56 * i) for i in range(23)]
    if records[11]['key_hex'] != (bytes(19) + b'\x09').hex() or records[11]['callback_va'] != '0x5c165b0':
        raise ValueError('address09 record mismatch')
    copies = []
    for group in COPY_GROUPS:
        copies.extend(copy_group(data, secs, *group))
    modes = []
    mode_bytes, map_off, _ = read_va(data, secs, 0x602d48, 15)
    for i, value in enumerate(mode_bytes):
        modes.append({'input_index': i, 'byte_va': hex(0x602d48 + i), 'file_offset': hex(map_off + i), 'builder_mode': value})
    default_mode = default_selector(data, secs)
    # Relative offsets at this one observed table are 19 signed dwords; bounds are
    # limited by the checked clamp in the selected instruction sequence.
    switch = conversion_entries(data, secs, 0x942740, 19, 0x5c184e0, 0x5c18c52)
    if switch[8]['target_va'] != '0x5c18803' or switch[8]['target_prefix'] != '4d8d5424f6':
        raise ValueError('address09 value conversion changed')
    journal_cases = conversion_entries(data, secs, 0x942248, 12, 0x5be3400, 0x5be3b49)
    diagnostics = [diagnostic_entry(data, secs, index) for index in (1, 2)]
    if [row['literal'] for row in diagnostics] != [
            'wrong input length for blake2', 'wrong final indicator flag for blake2']:
        raise ValueError('unexpected selected BLAKE2 diagnostics')
    literals = []
    for name, va, size in (('direct-slot-sentinel', 0x9428d0, 16),
                           ('journal-tag11-constant', 0x4585a0, 32)):
        raw, off, sec = read_va(data, secs, va, size)
        literals.append({'name': name, 'va': hex(va), 'file_offset': hex(off),
                         'section': sec, 'bytes': raw.hex()})
    if int.from_bytes(bytes.fromhex(literals[0]['bytes'])[:8], 'little') != SENTINEL:
        raise ValueError('direct table sentinel mismatch')
    # Source location descriptors contain a relocation, a length and line/column.
    sources = []
    for label, desc, suffix in (
        ('frame diagnostic', 0x6441e20, b'z_vendor/revm-handler/src/frame.rs'),
        ('precompile library diagnostic', 0x64c0cd8, b'z_forks/revm-precompile/src/lib.rs'),
    ):
        reloc = relative_reloc(rels, desc)
        raw, off, _ = read_va(data, secs, desc, 24)
        length, line, column = struct.unpack_from('<QII', raw, 8)
        path_va = int(reloc['addend_va'], 16)
        path_bytes, _, _ = read_va(data, secs, path_va, length)
        if not path_bytes.endswith(suffix):
            raise ValueError('source location suffix mismatch')
        sources.append({'kind': label, 'descriptor_va': hex(desc), 'descriptor_file_offset': hex(off),
                        'string_va': hex(path_va), 'string_length': length,
                        'relative_suffix': suffix.decode('ascii'), 'line': line, 'column': column})
    return {'target_sha256': digest, 'functions': functions, 'pins': pins,
            'edges': edges, 'rip_references': refs, 'scalar_immediates': immediates,
            'relocations': rel_rows,
            'records': records, 'record_copies': copies,
            'derived_mode_records': derive_mode_records(records),
            'inspected_mode_bytes': modes, 'conversion_table': switch,
            'journal_cases': journal_cases,
            'diagnostic_cases': diagnostics,
            'default_selector': default_mode,
            'data_literals': literals,
            'source_locations': sources, 'synthetic': synthetic_cases()}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + '\n', encoding='ascii')


def write_tsv(path, rows, fields):
    with path.open('w', encoding='ascii', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def emit(data, out):
    result = collect(data)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / 'functions.json', result['functions'])
    write_json(out / 'records.json', result['records'])
    write_json(out / 'mode-lineage.json', result['derived_mode_records'])
    write_json(out / 'diagnostic-cases.json', result['diagnostic_cases'])
    write_json(out / 'default-selector.json', result['default_selector'])
    write_json(out / 'data-literals.json', result['data_literals'])
    write_json(out / 'modes-and-cases.json', {
        'inspected_mode_bytes': result['inspected_mode_bytes'],
        'synthetic': result['synthetic'],
        'source_locations': result['source_locations'],
    })
    write_tsv(out / 'windows.tsv', result['pins'], ('name', 'va', 'file_offset', 'section', 'bytes'))
    write_tsv(out / 'edges.tsv', result['edges'], ('name', 'site_va', 'file_offset', 'bytes', 'target_va'))
    write_tsv(out / 'rip-references.tsv', result['rip_references'], ('name', 'site_va', 'file_offset', 'bytes', 'target_va'))
    write_tsv(out / 'scalar-immediates.tsv', result['scalar_immediates'],
              ('name', 'va', 'file_offset', 'bytes', 'value'))
    write_tsv(out / 'record-copies.tsv', result['record_copies'],
              ('group', 'load_va', 'code_file_offset', 'instruction_bytes', 'source_va',
               'source_file_offset', 'stack_offset', 'width', 'content_bytes'))
    write_tsv(out / 'relocations.tsv', result['relocations'], ('slot_va', 'type', 'addend_va', 'entry_file_offset'))
    write_tsv(out / 'conversion-table.tsv', result['conversion_table'], ('index', 'entry_va', 'file_offset', 'entry_bytes', 'target_va', 'target_prefix'))
    write_tsv(out / 'journal-cases.tsv', result['journal_cases'],
              ('index', 'entry_va', 'file_offset', 'entry_bytes', 'target_va', 'target_prefix'))
    write_json(out / 'summary.json', {
        'target_sha256': result['target_sha256'],
        'selected_fde_intervals': len(result['functions']),
        'selected_fde_bytes': sum(r['length'] for r in result['functions']),
        'selected_byte_predicates': len(result['pins']),
        'selected_relative_edges': len(result['edges']),
        'selected_rip_references': len(result['rip_references']),
        'selected_scalar_immediates': len(result['scalar_immediates']),
        'selected_relocations': len(result['relocations']),
        'selected_static_records': len(result['records']),
        'decoded_record_copy_pairs': len(result['record_copies']),
        'selected_conversion_entries': len(result['conversion_table']),
        'selected_journal_cases': len(result['journal_cases']),
        'selected_diagnostic_cases': len(result['diagnostic_cases']),
        'inspected_mode_bytes': len(result['inspected_mode_bytes']),
        'limitations': 'Selected FDE extents, fixed byte predicates and synthetic models are not complete control-flow, runtime behavior, source recovery or whole-node coverage.',
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    emit(TARGET.read_bytes(), args.out)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print('re21_blake2b_lookup115: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
