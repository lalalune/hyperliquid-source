#!/usr/bin/env python3
"""Reproduce selected node-115 DB-root and open-path observations from ELF bytes."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OLD_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are selected unwind-described ranges, not an exhaustive function census.
FUNCTIONS = (
    ('upstream_caller', 0x51cf360, 0x51d0f70, 'df61191b135be90414b94836bce7d4474eef92cd6e95913d99b8a3ab265c83be'),
    ('path_map_constructor', 0x57c4420, 0x57c461c, '81d552b736b4d5b5a7fe05450d62d9531017c54996ed9e7d75fd1b5360205476'),
    ('path_map_collection', 0x5168300, 0x5168472, 'b92251c38e79933b973d96614a8f9fa6188ecda815f8867524936714bcd3d894'),
    ('path_row_loop', 0x5b80150, 0x5b802e0, '42fc914373cfb0a862bc9932a48d1a1af93e425e7e9fa7c5ce9fbb39a57ad0ce'),
    ('root_display_callback', 0x543c610, 0x543c624, '6851c5b0b7be1a3db6382ff2fab82e0728b1f9cf512b56647a5fa2fc6b05550b'),
    ('key_display_callback', 0x1696db0, 0x1696dfe, '757e8deed086c2d7fd4354f596a248f49742263d31c19456ab704a28b43fab35'),
    ('formatted_path_object', 0x16961b0, 0x1696729, 'c58bd3b6c262791a5cbc0fcc2faf9a97c5da8e092c72a398d9bb495259430513'),
    ('path_map_insert', 0x4d0be50, 0x4d0c515, '907dc99d2c4339bf6b817eef6788736be7cac92681ed6a1b83f5393459c13779'),
    ('configuration_entry', 0x4e33ef0, 0x4e342a5, '32a24e3f78903ddda834b8912a1cbf0733889fae92dcfd2773ed068d3c00d783'),
    ('collection_constructor', 0x5165970, 0x5165ae2, 'f518dd95e9a9042d3eccdfbd6d1b59cb834662d0be3cf19e312e50191c69675f'),
    ('outer_allocation', 0x5b77f30, 0x5b7801d, '03e9c09e52c96c867dec9e33e87ec41569515b6c9542a86443dffcea445dea95'),
    ('entry_loop', 0x543e5b0, 0x543e773, '7501e05acf6ef01099f4a6b141cecb51600c35b349411adc6709d72a161d6eef'),
    ('selected_entry', 0x57c6530, 0x57c70b4, 'a1ace7e2946a8fcdfd8ad948615eeb3e45dbda9b10b54c03697edd0e0245e412'),
    ('root_guard', 0x5a007c0, 0x5a00af9, '8ac995416f7f0ddad669d8c30f815bde564089fab67f5d6a2ebc73c43aaf90e3'),
    ('byte_search_boundary', 0x59dbff0, 0x59dc975, 'fe09b6074795a39f9bbc86c2efefb8f46f67ab205f8e18b4217bf96d7f99b009'),
    ('open_result_adapter', 0x5828940, 0x5828a2e, 'f30ad863f01aa698dc431abd7efe2566589ef9b23e34bb932e6b32bb84fd7dec'),
    ('native_open_wrapper', 0x5d33cb0, 0x5d33da7, '0fe05c6484d2821c18dfcdcc129843c7144f1a7f18e8ce432d98f56d39c2f1e7'),
    ('native_error_writer', 0x5d2e0e0, 0x5d2e150, 'ccb4618414ca0f72f3142f87abc6f1546e7969a948fa97fdb80c1e28ea61202b'),
    ('size_builder', 0x5d35250, 0x5d35325, '9dae8cc450fabec632e2993b232ea84f4a062bee9597f7d695b1ad9a4fc574fa'),
    ('size_factory_adapter', 0x5d3db50, 0x5d3dd0e, '63c153c7b52a54708fb4258925286a5e62f85bf2e97497ee9eb81bf97ae0445d'),
    ('size_reference_setter', 0x5d35ae0, 0x5d35b43, '7e9820dc89f5fbac5391931981d31618a0f12e5de4e85c9ef0b010718ee4c400'),
    ('options_attachment', 0x5d356e0, 0x5d3576d, 'ca2e448b19f4ab9db491705aa6a72dd9350c9f79efd5f9b26a59b8342d64411f'),
    ('options_a_builder', 0x5d34b20, 0x5d34c37, '37fc6951ca24e7cbec14881be9022c5029cea338cb8d98cecc97df0e118354a9'),
    ('options_a_setter', 0x5d34c40, 0x5d34c49, '4e6b92f50cf4c3b284c93d9a9702a42304a9fae23b3e20a75b873495fef415b4'),
    ('options_b_flag_setter', 0x5d34c50, 0x5d34c5b, 'a338c340a32d135ab8f3df4f6010521eaf2b7be8e0d3dceca2a1c33c1b649f07'),
    ('options_b_size_setter', 0x5d34c60, 0x5d34c6c, '090c1f2addc809e1432fcd3d2ca200765b41e880678ae3e0c65acb94cda54b75'),
)

# label, instruction VA, exact branch bytes, expected target; only these sites are interpreted.
BRANCHES = (
    ('upstream_constructor_path',0x51d0493,'0f844b020000',0x51d06e4),
    ('constructor_word_not_signed_min',0x57c444f,'7148',0x57c4499),
    ('constructor_global_once_needed',0x57c445e,'0f8529010000',0x57c458d),
    ('constructor_format_failed',0x57c44d4,'0f858c000000',0x57c4566),
    ('path_collection_empty',0x5168320,'0f84a7000000',0x51683cd),
    ('path_collection_not_single',0x5168339,'0f85c7000000',0x5168406),
    ('path_collection_allocation_failed',0x516835c,'0f84be000000',0x5168420),
    ('path_collection_large',0x516840a,'7326',0x5168432),
    ('path_rows_size_ok',0x5b8018c,'740b',0x5b80199),
    ('path_rows_empty',0x5b8019c,'7423',0x5b801c1),
    ('path_rows_allocation_failed',0x5b801b0,'0f84fc000000',0x5b802b2),
    ('path_rows_have_input',0x5b801fa,'7507',0x5b80203),
    ('path_rows_more',0x5b80288,'7596',0x5b80220),
    ('key_zero',0x1696db8,'741a',0x1696dd4),
    ('key_not_one',0x1696dbd,'752a',0x1696de9),
    ('path_object_short',0x16961d0,'7645',0x1696217),
    ('path_object_long',0x16961d6,'0f8792000000',0x169626e),
    ('path_object_scalar_match',0x1696204,'7439',0x169623f),
    ('path_object_exact_mismatch',0x1696239,'0f8517010000',0x1696356),
    ('path_map_node_full',0x4d0bfc6,'731a',0x4d0bfe2),
    ('parent_once_needed',0x4e33f19,'0f852a020000',0x4e34149),
    ('parent_word_not_signed_min',0x4e33f3f,'7148',0x4e33f89),
    ('parent_global_once_needed',0x4e33f4e,'0f8588020000',0x4e341dc),
    ('parent_root_format_failure',0x4e33fc4,'0f85bf010000',0x4e34189),
    ('parent_root_check_failure',0x4e33fe5,'0f85c5010000',0x4e341b0),
    ('parent_input_not_signed_min',0x4e3402f,'7505',0x4e34036),
    ('parent_copy_empty',0x4e3403d,'7434',0x4e34073),
    ('parent_copy_allocation_failure',0x4e34054,'0f84b8010000',0x4e34212),
    ('parent_output_allocation_failure',0x4e340bf,'7473',0x4e34134),
    ('collection_empty',0x5165990,'0f84a7000000',0x5165a3d),
    ('collection_not_single',0x51659a9,'0f85c7000000',0x5165a76),
    ('collection_allocation_failure',0x51659cc,'0f84be000000',0x5165a90),
    ('collection_release_empty',0x5165a54,'7411',0x5165a67),
    ('collection_large',0x5165a7a,'7326',0x5165aa2),
    ('outer_size_ok',0x5b77f66,'740b',0x5b77f73),
    ('outer_empty',0x5b77f79,'7416',0x5b77f91),
    ('outer_allocation_failed',0x5b77f8a,'7468',0x5b77ff4),
    ('loop_empty',0x543e5f1,'0f841a010000',0x543e711),
    ('loop_allocation_failed',0x543e6af,'747a',0x543e72b),
    ('loop_more',0x543e70b,'0f850fffffff',0x543e620),
    ('map_empty',0x57c6548,'0f8487060000',0x57c6bd5),
    ('map_match',0x57c659e,'7424',0x57c65c4),
    ('map_depth_exhausted',0x57c65b7,'0f8218060000',0x57c6bd5),
    ('reference_increment_nonpositive',0x57c65ce,'0f8e75080000',0x57c6e49),
    ('options_a_null',0x57c65f2,'0f8455050000',0x57c6b4d),
    ('size_high_bits',0x57c6631,'0f8567050000',0x57c6b9e),
    ('size_shift_overflow',0x57c6639,'0f8569050000',0x57c6ba8),
    ('sized_builder_null',0x57c6651,'0f846c050000',0x57c6bc3),
    ('options_b_null',0x57c66e3,'0f8497040000',0x57c6b80),
    ('converted_path_non_sentinel',0x57c6883,'711c',0x57c68a1),
    ('path_intermediate_non_sentinel',0x57c6951,'0f8597020000',0x57c6bee),
    ('create_error',0x57c6981,'0f8594020000',0x57c6c1b),
    ('open_error_result',0x57c69cc,'0f85b3020000',0x57c6c85),
    ('open_null_handle',0x57c69d5,'0f84b9020000',0x57c6c94),
    ('output_path_sentinel',0x57c6a9e,'0f84a7030000',0x57c6e4b),
    ('saturated_builder_nonnull',0x57c6bbd,'0f8594faffff',0x57c6657),
    ('root_word_not_signed_min',0x5a007ee,'7147',0x5a00837),
    ('global_once_needed',0x5a007fc,'0f851b020000',0x5a00a1d),
    ('root_format_failed',0x5a00872,'0f857e010000',0x5a009f6),
    ('first_label_write_failed',0x5a008e4,'0f85e2000000',0x5a009cc),
    ('first_search_nonzero',0x5a00909,'0f8544010000',0x5a00a53),
    ('second_label_write_failed',0x5a0096e,'755c',0x5a009cc),
    ('second_search_nonzero',0x5a0098f,'0f85be000000',0x5a00a53),
    ('search_empty_needle',0x59dc006,'0f8440040000',0x59dc44c),
    ('search_needle_at_least_haystack',0x59dc01b,'733a',0x59dc057),
    ('search_needle_larger',0x59dc057,'0f8543030000',0x59dc3a0),
    ('search_repeated_needle_end',0x59dc153,'7354',0x59dc1a9),
    ('search_matching_needle_bytes',0x59dc16d,'74e1',0x59dc150),
    ('search_vector_threshold',0x59dc176,'0f83e6020000',0x59dc462),
    ('search_scalar_equal',0x59dc191,'0f84b5020000',0x59dc44c),
    ('search_scalar_next',0x59dc1a2,'76dc',0x59dc180),
    ('native_error_pointer_null',0x582897b,'7436',0x58289b3),
    ('error_conversion_non_sentinel',0x582899c,'751e',0x58289bc),
    ('error_length_nonnegative',0x58289a6,'7927',0x58289cf),
    ('error_copy_allocation_null',0x58289e2,'743c',0x5828a20),
    ('native_status_byte_zero',0x5d33cfe,'7450',0x5d33d50),
    ('native_error_buffer_null',0x5d33d15,'7405',0x5d33d1c),
    ('native_error_writer_return_zero',0x5d33d29,'743c',0x5d33d67),
    ('native_success_buffer_null',0x5d33d58,'7426',0x5d33d80),
    ('error_old_pointer_null',0x5d2e104,'7405',0x5d2e10b),
    ('size_builder_old_result_null',0x5d352d6,'7413',0x5d352eb),
    ('size_builder_temporary_null',0x5d352e4,'7405',0x5d352eb),
    ('size_factory_reference_null',0x5d3db8d,'7414',0x5d3dba3),
    ('size_factory_atomic_increment',0x5d3db99,'0f84c9000000',0x5d3dc68),
    ('size_factory_reference_release_skipped',0x5d3dbc4,'743d',0x5d3dc03),
    ('size_factory_unique_release',0x5d3dbdb,'0f8497000000',0x5d3dc78),
    ('size_reference_input_null',0x5d35ae7,'7447',0x5d35b30),
    ('size_reference_unchanged',0x5d35b04,'7423',0x5d35b29),
    ('size_reference_new_null',0x5d35b09,'7410',0x5d35b1b),
    ('size_reference_atomic_increment',0x5d35b15,'7421',0x5d35b38),
    ('size_reference_old_null',0x5d35b1e,'7405',0x5d35b25),
    ('options_attachment_input_null',0x5d356e7,'7477',0x5d35760),
    ('options_attachment_old_null',0x5d3573c,'7412',0x5d35750),
)

# Explicitly selected direct calls. The byte displacements are decoded, not parsed from disassembly.
DIRECT_CALLS = (
    ('upstream_to_path_constructor',0x51d04b1,0x57c4420),
    ('upstream_to_configuration_entry',0x51d04c0,0x4e33ef0),
    ('path_constructor_to_collection',0x57c451b,0x5168300),
    ('path_collection_to_rows',0x5168313,0x5b80150),
    ('path_collection_insert_boundary',0x51683b5,0x4d0be50),
    ('parent_to_collection',0x4e3401d,0x5165970),
    ('collection_to_outer',0x5165983,0x5b77f30),
    ('collection_build_boundary',0x5165a25,0x4ce0120),
    ('collection_small_boundary',0x5165a86,0x53ea0e0),
    ('outer_to_loop',0x5b77fcf,0x543e5b0),
    ('loop_to_entry',0x543e63e,0x57c6530),
    ('entry_to_root_guard',0x57c65df,0x5a007c0),
    ('first_label_search',0x5a00902,0x59dbff0),
    ('second_label_search',0x5a00988,0x59dbff0),
    ('entry_to_open_adapter',0x57c69b4,0x5828940),
    ('native_make_path',0x5d33ce1,0x5d32940),
    ('native_open_engine_boundary',0x5d33cf4,0x5e65530),
    ('native_error_writer',0x5d33d06,0x5d2e0e0),
    ('native_wrapper_allocate',0x5d33d6c,0x63f0dd0),
    ('error_free_old',0x5d2e106,0x63f0b50),
    ('error_string_conversion_boundary',0x5d2e114,0x61cfed0),
    ('error_strdup',0x5d2e11d,0x63f0da0),
    ('size_builder_allocate',0x5d35276,0x63f0dd0),
    ('size_builder_to_factory',0x5d352b8,0x5d3db50),
    ('size_factory_to_engine_boundary',0x5d3dbb6,0x5d3d550),
    ('size_reference_release_boundary',0x5d35b20,0x5d350c0),
    ('options_copy_boundary',0x5d356f5,0x60dbd80),
    ('options_attachment_allocate',0x5d35702,0x63f0dd0),
)
INDIRECT_CALLS = (
    ('path_row_formatter',0x5b80260,0x64df6e8),
    ('path_row_object',0x5b80269,0x64e20c0),
    ('parent_root_check_boundary',0x4e33fdc,0x64e0028),
    ('collection_large_boundary',0x5165aa7,0x64eba90),
    ('initial_options',0x57c65e9,0x64eab28),
    ('normal_size_builder',0x57c6643,0x64eab30),
    ('saturated_size_builder',0x57c6baf,0x64eab30),
    ('second_options',0x57c66d1,0x64e6c58),
    ('set_options_a',0x57c6691,0x64eab38),
    ('set_options_b',0x57c66cb,0x64eab40),
    ('set_options_flag',0x57c670d,0x64e7378),
    ('set_options_c',0x57c6720,0x64eab48),
    ('set_options_d',0x57c6733,0x64eab50),
    ('create_directory_boundary',0x57c6978,0x64e0940),
    ('native_open_boundary',0x582896e,0x64e6f90),
    ('error_strlen',0x5828980,0x64df698),
    ('free_error_pointer',0x5828a0c,0x64e20d8),
    ('first_label_output',0x5a008dc,0x64df720),
    ('second_label_output',0x5a00966,0x64df720),
    ('equal_length_compare',0x59dc066,0x64df9f8),
    ('scalar_search_compare',0x59dc189,0x64df9f8),
)

# label, instruction site, target VA. LEA/MOV must have x86 RIP-relative disp32 form.
REFERENCES = (
    ('constructor_default_entry',0x57c4480,0x443e39),
    ('constructor_ordinary_entry',0x57c44bb,0x43b857),
    ('path_root_callback',0x5b8022f,0x543c610),
    ('path_key_callback_slot',0x5b80245,0x64e2078),
    ('path_join_entry',0x5b80254,0x43aa84),
    ('key_one_entry',0x1696dbf,0x47b428),
    ('key_zero_entry',0x1696dd4,0x4595c0),
    ('key_other_entry',0x1696de9,0x459a58),
    ('path_object_rejection',0x1696250,0x447e28),
    ('parent_configuration_slot',0x4e33f41,0x64e0918),
    ('parent_default_root_entry',0x4e33f70,0x443e39),
    ('parent_ordinary_root_entry',0x4e33fab,0x43b857),
    ('configuration_slot',0x5a007f0,0x64e0918),
    ('default_root_entry',0x5a0081e,0x443e39),
    ('ordinary_root_entry',0x5a00859,0x43b857),
    ('first_label',0x5a008cb,0x4595c0),
    ('second_label',0x5a00955,0x47b428),
    ('root_rejection_entry',0x5a00a7c,0x44dbf5),
    ('path_conversion_entry',0x57c68da,0x432965),
    ('options_a_diagnostic',0x57c6b4d,0x944435),
    ('options_b_diagnostic',0x57c6b80,0x4578e0),
    ('missing_key_diagnostic',0x57c6bd5,0x9360f2),
)
# label, VA, bytes. Each entry is read afresh from the target and fails closed on a mismatch.
ENTRIES = (
    ('path_join_template',0x43aa84,b'\xc0\x01/\xc0\x00'),
    ('other_key_label',0x459a58,b'EvmState'),
    ('path_object_rejection_template',0x447e28,b'\x17OwnedDbDir invalid dir \xc0\x00'),
    ('root_template',0x443e39,b'\xc0\x18/hyperliquid_data/db_hub\x00'),
    ('ordinary_template',0x43b857,b'\xc0\x00'),
    ('first_label',0x4595c0,b'Exchange'),
    ('second_label',0x47b428,b'Rpc'),
    ('root_rejection_template',0x44dbf5,b'\x24db_home contains db_bundle in path: \xc0\x00'),
    ('path_conversion_prefix',0x432965,b'\x23Failed to convert path to CString'),
    ('options_a_diagnostic',0x944435,b'Could not create RocksDB block based options'),
    ('options_b_diagnostic',0x4578e0,b'Could not create RocksDB options'),
    ('missing_key_diagnostic',0x9360f2,b'no entry found for key'),
    ('historical_cham_anchor',0x44ab69,b'\xc0\x05/cham\x00'),
    ('historical_static_anchor',0x4401ef,b'\xc0\x0e/static_config\x00'),
    ('nv_name',0x464716,b'NvTestnet'),
)

# Half-open raw byte spans selected for register flow, stores and local failure paths.
WINDOWS = (
    ('upstream_constructor_to_open',0x51d0490,0x51d04c8),
    ('constructor_root_selector',0x57c444a,0x57c44d2),
    ('constructor_keys_and_map_call',0x57c44ee,0x57c4520),
    ('constructor_object_publication',0x57c4520,0x57c4542),
    ('path_collection_handoff',0x5168300,0x5168326),
    ('path_collection_insertion',0x5168386,0x51683cb),
    ('path_rows_setup',0x5b801c9,0x5b80220),
    ('path_rows_format_and_publish',0x5b80220,0x5b8028a),
    ('root_display_callback_body',0x543c610,0x543c624),
    ('key_display_callback_body',0x1696db0,0x1696dfe),
    ('path_object_copy_input',0x1696376,0x169638d),
    ('path_object_make_box',0x16963c3,0x1696466),
    ('path_object_short_rejection',0x16961c1,0x169626e),
    ('path_object_rejection_trap',0x16966de,0x16966f5),
    ('path_map_load_rows',0x4d0bf80,0x4d0bfb8),
    ('path_map_insert_leaf',0x4d0bfb8,0x4d0bfe2),
    ('parent_input_and_once',0x4e33ef0,0x4e33f1f),
    ('parent_root_selection',0x4e33f3a,0x4e33fc2),
    ('parent_root_check',0x4e33fc2,0x4e33feb),
    ('parent_collection_handoff',0x4e33ffd,0x4e34022),
    ('parent_result_publication',0x4e3407c,0x4e34124),
    ('parent_failure_paths',0x4e34134,0x4e341dc),
    ('collection_outer_and_empty',0x5165970,0x51659af),
    ('collection_result',0x51659af,0x5165a76),
    ('collection_cardinality_branches',0x5165a76,0x5165ab2),
    ('allocation_size_and_overflow',0x5b77f3b,0x5b77f73),
    ('outer_preserve_input',0x5b77f73,0x5b77f99),
    ('outer_handoff_and_result',0x5b77fc4,0x5b77fe5),
    ('loop_byte_and_handoff',0x543e620,0x543e643),
    ('loop_load_root_input',0x543e5f7,0x543e603),
    ('loop_element_publication',0x543e6e9,0x543e711),
    ('loop_final_count',0x543e711,0x543e719),
    ('loop_allocation_failure',0x543e72b,0x543e73d),
    ('entry_map_key_and_root',0x57c6541,0x57c6570),
    ('entry_map_compare_and_descent',0x57c6570,0x57c65c4),
    ('entry_root_guard_call',0x57c65c4,0x57c65e4),
    ('entry_size_calculation',0x57c65fd,0x57c6649),
    ('entry_overflow_alternative',0x57c6b9e,0x57c6bc3),
    ('entry_reference_fields',0x57c665a,0x57c6697),
    ('entry_first_option_override',0x57c66bc,0x57c66d1),
    ('entry_option_settings',0x57c6705,0x57c6739),
    ('entry_selected_path_load',0x57c6787,0x57c6791),
    ('entry_path_conversion',0x57c6840,0x57c6885),
    ('entry_create_arguments',0x57c694e,0x57c6987),
    ('entry_open_call_and_result',0x57c699f,0x57c69db),
    ('entry_success_publication',0x57c6aa4,0x57c6ae4),
    ('entry_missing_key_error',0x57c6bd5,0x57c6bee),
    ('entry_create_error',0x57c6c1b,0x57c6c85),
    ('entry_open_error_and_null_box',0x57c6c85,0x57c6cfe),
    ('guard_root_selection',0x5a007e9,0x5a00835),
    ('guard_ordinary_root',0x5a00837,0x5a00870),
    ('guard_first_label',0x5a008cb,0x5a0090f),
    ('guard_second_label',0x5a00955,0x5a00995),
    ('guard_error_entry',0x5a00a66,0x5a00a97),
    ('guard_format_and_label_errors',0x5a009cc,0x5a00a1d),
    ('search_prefix',0x59dbff0,0x59dc076),
    ('search_needle_filter',0x59dc13e,0x59dc180),
    ('search_scalar_loop',0x59dc180,0x59dc1a9),
    ('search_false_return',0x59dc3a0,0x59dc3a7),
    ('search_success_return',0x59dc44c,0x59dc462),
    ('adapter_native_call',0x5828949,0x582897d),
    ('adapter_failure_and_return',0x582897d,0x58289cf),
    ('adapter_copy_and_free',0x58289cf,0x5828a20),
    ('native_engine_status_test',0x5d33ce6,0x5d33d0b),
    ('native_status_nonzero_return',0x5d33d0b,0x5d33d2b),
    ('native_success_box',0x5d33d50,0x5d33d7b),
    ('error_writer_dispose_and_duplicate',0x5d2e0ee,0x5d2e12d),
    ('error_writer_return',0x5d2e13d,0x5d2e14b),
    ('size_builder_save_argument',0x5d35250,0x5d3527f),
    ('size_builder_factory_arguments',0x5d35283,0x5d352bd),
    ('size_builder_box_result',0x5d352bd,0x5d352d8),
    ('size_factory_forward_argument',0x5d3dba3,0x5d3dbbb),
    ('size_reference_transfer_and_replace',0x5d35ae0,0x5d35b30),
    ('options_copy_and_attachment',0x5d356e0,0x5d3573e),
    ('options_a_initial_field',0x5d34b90,0x5d34b98),
    ('options_a_setter_body',0x5d34c40,0x5d34c49),
    ('options_b_flag_setter_body',0x5d34c50,0x5d34c5b),
    ('options_b_size_setter_body',0x5d34c60,0x5d34c6c),
)

# Address, relocation type, symbol index (None = dynamic lookup), expected addend/name.
RELOCATIONS = (
    ('path_key_callback',0x64e2078,8,0,0x1696db0,''),
    ('path_object_constructor',0x64e20c0,8,0,0x16961b0,''),
    ('parent_root_check',0x64e0028,8,0,0x15020f0,''),
    ('collection_large_handler',0x64eba90,8,0,0x4f3d760,''),
    ('configuration_pointer',0x64e0918,8,0,0x64f06c0,''),
    ('nv_descriptor',0x63f8998,8,0,0x464716,''),
    ('options_builder',0x64eab28,8,0,0x5d34b20,''),
    ('size_builder',0x64eab30,8,0,0x5d35250,''),
    ('size_reference_setter',0x64eab38,8,0,0x5d35ae0,''),
    ('options_a_setter',0x64eab40,8,0,0x5d34c40,''),
    ('options_b_flag_setter',0x64e7378,8,0,0x5d34c50,''),
    ('options_b_size_setter',0x64eab48,8,0,0x5d34c60,''),
    ('options_attachment',0x64eab50,8,0,0x5d356e0,''),
    ('native_open',0x64e6f90,8,0,0x5d33cb0,''),
    ('equal_length_bcmp',0x64df9f8,6,None,0,'bcmp'),
    ('free_error_pointer',0x64e20d8,6,None,0,'free'),
    ('error_strlen',0x64df698,6,None,0,'strlen'),
)
PLT_LINKS = (
    ('free',0x63f0b50,0x64ee1f8,'free'),
    ('strdup',0x63f0da0,0x64ee320,'strdup'),
    ('operator_new',0x63f0dd0,0x64ee338,'_Znwm'),
)

class EvidenceError(ValueError):
    pass

def need(ok, message):
    if not ok:
        raise EvidenceError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def check_identity(data, expected=TARGET_SHA256):
    need(digest(data) == expected, 'input SHA-256 mismatch')

def hx(value):
    return hex(value)

class Image:
    def __init__(self, data, frames=True):
        self.data = data
        self.sections = sections(data)
        self.functions = {}
        if frames:
            _, table = unwind_index(data)
            indexed = {r['start']: r for r in table if r['start'] in {x[1] for x in FUNCTIONS}}
            _, fdes = eh_frame_records(data, self.sections)
            selected = {f['start']: f for f in fdes if f['start'] in indexed}
            need(len(indexed) == len(FUNCTIONS) == len(selected), 'missing selected FDE')
            for label, start, end, body_hash in FUNCTIONS:
                frame = selected[start]
                need(frame['end'] == end and frame['fde'] == indexed[start]['fde'], 'FDE range or index mismatch')
                validate_body(self,start,end,body_hash,label)
                self.functions[start] = frame

    def offset(self, address, size, executable=False):
        need(isinstance(address,int) and isinstance(size,int) and address >= 0 and size > 0, 'invalid address or size')
        selected = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2 and s['size'] and
                    (not executable or s['flags'] & 4) and s['address'] <= address and
                    address + size <= s['address'] + s['size']]
        need(len(selected) == 1, 'address is not uniquely file-backed')
        sec = selected[0]
        off = sec['offset'] + address - sec['address']
        need(off + size <= len(self.data), 'file span outside image')
        return off, sec['name']

    def read(self, address, size, executable=False):
        off, _ = self.offset(address, size, executable)
        return bytes(self.data[off:off+size])

    def section(self, name):
        found = [s for s in self.sections if s['name'] == name and s['type'] != 8]
        need(len(found) == 1, 'missing or duplicated file-backed section ' + name)
        return found[0]

    def relocations(self, slots, section_name='.rela.dyn'):
        sec = self.section(section_name)
        need(sec['size'] % 24 == 0, 'unaligned relocation section')
        slots = set(slots)
        result = {}
        for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
            dest, info, addend = struct.unpack_from('<QQq', self.data, pos)
            if dest in slots:
                need(dest not in result, 'duplicate relocation')
                result[dest] = (info & 0xffffffff, info >> 32, addend, pos)
        need(set(result) == slots, 'missing relocation')
        return result

    def plt_link(self, site, expected_slot, expected_symbol):
        raw = self.read(site,6,True)
        need(raw[:2] == b'\xff\x25', 'unsupported PLT jump')
        slot = site + 6 + struct.unpack('<i',raw[2:])[0]
        need(slot == expected_slot, 'PLT target differs')
        self.offset(slot,8)
        kind,index,addend,record = self.relocations([slot],'.rela.plt')[slot]
        need(kind == 7 and addend == 0, 'PLT relocation differs')
        need(self.symbol_name(index) == expected_symbol, 'PLT symbol differs')
        return raw,slot,record,index

    def symbol_name(self, index):
        sym, strings = self.section('.dynsym'), self.section('.dynstr')
        need(index >= 0 and (index + 1)*24 <= sym['size'], 'symbol index out of bounds')
        name_off = struct.unpack_from('<I',self.data,sym['offset']+24*index)[0]
        need(name_off < strings['size'], 'symbol name out of bounds')
        start = strings['offset'] + name_off
        end = self.data.find(b'\x00',start,strings['offset']+strings['size'])
        need(end >= 0, 'unterminated dynamic symbol')
        return bytes(self.data[start:end]).decode('ascii')

    def branch(self, site, expected_bytes, target):
        expected = bytes.fromhex(expected_bytes)
        raw = self.read(site,len(expected),True)
        need(raw == expected, 'branch bytes changed')
        if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
            disp = struct.unpack('<b',raw[1:])[0]; opcode = raw[0] & 15
        elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
            disp = struct.unpack('<i',raw[2:])[0]; opcode = raw[1] & 15
        else:
            raise EvidenceError('unsupported branch encoding')
        actual = site + len(raw) + disp
        need(actual == target, 'branch target differs')
        self.offset(actual,1,True)
        return raw, actual, opcode

    def rip(self, site, target, call=False):
        raw = self.read(site,6 if call else 7,True)
        if call:
            need(raw[:2] == b'\xff\x15', 'unsupported indirect call')
            displacement = struct.unpack('<i',raw[2:])[0]
        else:
            need(0x48 <= raw[0] <= 0x4f and raw[1] in (0x8b,0x8d) and raw[2] & 0xc7 == 5,
                 'unsupported RIP-relative instruction')
            displacement = struct.unpack('<i',raw[3:])[0]
        actual = site + len(raw) + displacement
        need(actual == target, 'RIP target differs')
        self.offset(target,1)
        return raw

    def direct(self, site, target):
        raw = self.read(site,5,True)
        need(raw[0] == 0xe8, 'expected direct call')
        need(site + 5 + struct.unpack('<i',raw[1:])[0] == target, 'direct call target differs')
        self.offset(target,1,True)
        return raw

    def entry(self, address, expected):
        actual = self.read(address,len(expected))
        need(actual == expected, 'selected data entry differs')
        return actual

def find_offsets(data, needle):
    need(bool(needle), 'empty byte-search pattern')
    found = []
    position = 0
    while True:
        at = data.find(needle,position)
        if at < 0:
            return found
        found.append(at)
        position = at + 1

def tsv(header, rows):
    out = io.StringIO(newline='')
    w = csv.writer(out, delimiter='\t', lineterminator='\n')
    w.writerow(header)
    w.writerows(rows)
    return out.getvalue().encode('utf-8')

def validate_body(image,start,end,expected,label):
    body = image.read(start,end-start,executable=True)
    need(digest(body) == expected, 'FDE bytes differ for ' + label)
    return body

def selected_relocations(image):
    reloc = image.relocations([r[1] for r in RELOCATIONS])
    rows = []
    for label,slot,kind,index,addend,name in RELOCATIONS:
        got_kind,got_index,got_addend,record_off = reloc[slot]
        need(got_kind == kind and got_addend == addend, 'relocation differs for '+label)
        need(index is None or got_index == index, 'relocation symbol index differs')
        symbol = image.symbol_name(got_index) if got_index else ''
        need(symbol == name, 'dynamic symbol differs')
        rows.append((label,hx(slot),hx(image.offset(slot,8)[0]),hx(record_off),got_kind,got_index,hx(got_addend),symbol))
    return rows

def verify_name_descriptor(image):
    nv_slot = 0x63f8998
    nv_len = struct.unpack('<Q',image.read(nv_slot+8,8))[0]
    need(nv_len == len(b'NvTestnet'), 'NvTestnet length differs')
    image.entry(0x464716,b'NvTestnet')
    return nv_len

def number_parameters(image):
    def instruction(site, prefix, size):
        value = image.read(site,size,True)
        need(value.startswith(prefix), 'size calculation instruction changed')
        return value
    high = instruction(0x57c660d,b'\x48\xc1\xe8',4)[3]
    left = instruction(0x57c6614,b'\x49\xc1\xe7',4)[3]
    default = struct.unpack('<I',instruction(0x57c661b,b'\xbf',5)[1:])[0]
    check = instruction(0x57c6627,b'\x48\xc1\xe8',4)[3]
    final = instruction(0x57c663f,b'\x48\xc1\xe7',4)[3]
    saturated = instruction(0x57c6ba8,b'\x48\xc7\xc7',7)[3:]
    need(saturated == b'\xff'*4, 'saturated immediate changed')
    need((high,left,default,check,final) == (54,10,0x4000,44,20), 'size parameters changed')
    return high,left,default,check,final

def capacity_model(flag,value,params):
    need(type(flag) is int and type(value) is int and 0 <= flag < 256 and 0 <= value < 1<<64, 'invalid model input')
    high,left,default,check,final = params
    mask = (1<<64)-1
    selected = ((value << left) & mask) if flag & 1 else default
    saturated = bool((flag & 1) and value >> high) or bool(selected >> check)
    return mask if saturated else (selected << final) & mask

def option_values(image):
    checks = (
        (0x5d34b90,bytes.fromhex('48c7405800100000')),
        (0x5d34c40,bytes.fromhex('f30f1efa48897758c3')),
        (0x5d34c50,bytes.fromhex('f30f1efa4084f60f9507c3')),
        (0x5d34c60,bytes.fromhex('f30f1efa4889b7a8040000c3')),
    )
    for address,expected in checks:
        need(image.read(address,len(expected),True) == expected, 'option setter bytes changed')
    initial = struct.unpack('<I',image.read(0x5d34b94,4,True))[0]
    def imm(site):
        raw=image.read(site,5,True)
        need(raw[0] == 0xbe, 'option argument instruction changed')
        return struct.unpack('<I',raw[1:])[0]
    changed,flag,size=imm(0x57c66c6),imm(0x57c6708),imm(0x57c671b)
    need((initial,changed,flag,size) == (0x1000,0x8000,1,0x8000000), 'option value changed')
    return (('options_a_initial',0x5d34b90,0x58,initial),
            ('options_a_override',0x57c66c6,0x58,changed),
            ('options_b_flag',0x57c6708,0,flag),
            ('options_b_field',0x57c671b,0x4a8,size))

def binding_fields(image):
    specifications = (
        ('options_a_size_pointer',0x5d35af9,b'\x48\x89\x47',1,0x38,'source_pair_first_word'),
        ('options_a_control_pointer',0x5d35b25,b'\x48\x89\x6b',1,0x40,'source_pair_second_word'),
        ('options_b_copy_pointer',0x5d35719,b'\x48\x89\xab',4,0x548,'copy_result'),
        ('options_b_control_pointer',0x5d3572b,b'\x48\x89\x83',4,0x550,'new_control_object'),
    )
    result = []
    for label,site,prefix,width,expected,source in specifications:
        raw = image.read(site,len(prefix)+width,True)
        need(raw.startswith(prefix), 'binding store opcode differs')
        offset = int.from_bytes(raw[len(prefix):],'little')
        need(offset == expected, 'binding field offset differs')
        result.append((label,hx(site),hx(offset),source,raw.hex()))
    return result

def scalar_search_limit(image):
    raw = image.read(0x59dc16f,4,True)
    need(raw[:3] == b'\x49\x8d\x57' and raw[3] == 15, 'search threshold instruction changed')
    return raw[3]

def scalar_search_model(needle,haystack,limit):
    need(isinstance(needle,bytes) and isinstance(haystack,bytes) and len(needle) in (3,8), 'unsupported needle')
    need(needle[0] != needle[-1] and limit == 15, 'unsupported needle or threshold')
    need(len(haystack) < len(needle)+limit, 'vector search outside model')
    if len(needle) > len(haystack):
        return False
    for i in range(len(haystack)-len(needle)+1):
        if haystack[i:i+len(needle)] == needle:
            return True
    return False

def root_model(word):
    need(type(word) is int and 0 <= word < 1<<64, 'invalid root word')
    return 'global_template' if word == 1<<63 else 'input_template'

def outcome_model(format_error, first_write_error, first_search, second_write_error, second_search):
    need(all(x in (0,1) and type(x) is int for x in (format_error,first_write_error,first_search,second_write_error,second_search)), 'invalid outcome input')
    if format_error: return 'root_format_error'
    if first_write_error: return 'first_label_error'
    if first_search: return 'first_search_nonzero'
    if second_write_error: return 'second_label_error'
    if second_search: return 'second_search_nonzero'
    return 'normal_return'

def native_outcome_model(status_byte, duplicate_nonnull):
    """Normal-return control flow only; the duplication outcome is an input."""
    need(type(status_byte) is int and 0 <= status_byte < 256, 'invalid status byte')
    if status_byte == 0:
        need(duplicate_nonnull is None, 'zero status does not duplicate an error')
        return 'allocated_box', 'signed_min_and_box'
    need(type(duplicate_nonnull) is int and duplicate_nonnull in (0,1), 'invalid duplication outcome')
    if duplicate_nonnull:
        return 'null', 'error_pointer_nonzero'
    return 'null', 'signed_min_and_null'

def input_flow(image):
    # Local register/stack handoffs; the full selected FDE hashes cover the gaps.
    sites = (
        ('parent_input_to_saved_register',0x4e33f01,'4889fb'),
        ('parent_saved_pointer_to_argument',0x4e34004,'48895c2428'),
        ('parent_argument_address',0x4e34018,'488d742428'),
        ('collection_preserves_input_register',0x516597e,'488d7c2408'),
        ('outer_input_to_loop_argument',0x5b77fc9,'4889f7'),
        ('loop_loads_first_argument_field',0x543e5f7,'488b07'),
        ('loop_saves_root_pointer',0x543e5fa,'4889442410'),
        ('loop_passes_root_pointer',0x543e639,'488b742410'),
        ('entry_passes_root_to_guard',0x57c65dc,'4889f7'),
    )
    rows=[]
    for label,site,expected in sites:
        raw=image.read(site,len(bytes.fromhex(expected)),True)
        need(raw.hex() == expected, 'input flow instruction differs')
        rows.append((label,hx(site),hx(image.offset(site,len(raw),True)[0]),raw.hex()))
    return rows

def parent_keys(image):
    start_insn=image.read(0x4e33feb,9,True)
    end_insn=image.read(0x4e33ff4,9,True)
    bytes_insn=image.read(0x4e33ffd,7,True)
    need(start_insn[:5] == bytes.fromhex('48c7442438') and
         end_insn[:5] == bytes.fromhex('48c7442440') and
         bytes_insn[:5] == bytes.fromhex('66c7442448'), 'parent key setup opcode differs')
    start=struct.unpack('<i',start_insn[5:])[0]
    end=struct.unpack('<i',end_insn[5:])[0]
    keys=bytes_insn[5:]
    need((start,end,keys) == (0,2,b'\x00\x01'), 'parent key setup values differ')
    return [(i,hx(value),hx(0x4e33ffd),bytes_insn.hex()) for i,value in enumerate(keys[start:end],start)]

def constructor_keys(image):
    start_insn=image.read(0x57c44ee,9,True)
    end_insn=image.read(0x57c44f7,9,True)
    bytes_insn=image.read(0x57c4500,7,True)
    need(start_insn[:5] == bytes.fromhex('48c7442440') and
         end_insn[:5] == bytes.fromhex('48c7442448') and
         bytes_insn[:5] == bytes.fromhex('66c7442450'), 'constructor key setup opcode differs')
    start=struct.unpack('<i',start_insn[5:])[0]
    end=struct.unpack('<i',end_insn[5:])[0]
    keys=bytes_insn[5:]
    need((start,end,keys) == (0,2,b'\x00\x01'), 'constructor key setup values differ')
    return [(i,hx(value),hx(0x57c4500),bytes_insn.hex()) for i,value in enumerate(keys[start:end],start)]

def key_label(image,key):
    need(type(key) is int and 0 <= key < 256, 'invalid key byte')
    need(image.read(0x1696db3,12,True) == bytes.fromhex('0fb60f85c9741a83f901752a'),
         'key display comparisons differ')
    labels=(image.entry(0x4595c0,b'Exchange'),image.entry(0x47b428,b'Rpc'),
            image.entry(0x459a58,b'EvmState'))
    return labels[key if key < 2 else 2]

def path_guard_pattern(image):
    first=image.read(0x16961dc,10,True)
    last=image.read(0x16961fa,7,True)
    need(first[:2] == bytes.fromhex('48b8') and last[:3] == bytes.fromhex('4881f7'),
         'path guard comparison opcode differs')
    need(last[5:] == b'\x00\x00', 'path guard immediate high bytes differ')
    pattern=first[2:]+last[3:5]
    need(pattern == b'checkpoint', 'path guard pattern differs')
    return pattern

def bounded_path_guard(value,pattern):
    need(isinstance(value,bytes) and pattern == b'checkpoint', 'invalid path guard input')
    need(len(value) <= 24, 'long path search outside model')
    return any(value[i:i+len(pattern)] == pattern for i in range(len(value)-len(pattern)+1))

def collection_limits(image):
    small=image.read(0x51659a5,4,True)
    large=image.read(0x5165a76,4,True)
    need(small[:3] == b'\x48\x83\xfe' and large[:3] == b'\x48\x83\xfe', 'collection comparison changed')
    need(small[3] == 1 and large[3] == 21, 'collection thresholds changed')
    return small[3],large[3]

def collection_model(count, limits):
    need(type(count) is int and 0 <= count < 1<<64, 'invalid collection count')
    single,large=limits
    if count == 0: return 'empty'
    if count == single: return 'single'
    return 'large_boundary' if count >= large else 'small_boundary'

def build(data):
    check_identity(data)
    image = Image(data)
    functions = []
    bodies = []
    for label,start,end,_ in FUNCTIONS:
        f = image.functions[start]
        body = image.read(start,end-start,True)
        off, sec = image.offset(start,len(body),True)
        functions.append((label,hx(start),hx(end),end-start,hx(off),sec,hx(f['fde']),hx(f['cie']),'' if f['lsda'] is None else hx(f['lsda']),digest(body)))
        bodies.append((label,hx(start),body.hex()))
    branches = []
    for label,site,expected,target in BRANCHES:
        raw,dest,op = image.branch(site,expected,target)
        branches.append((label,hx(site),hx(image.offset(site,len(raw),True)[0]),raw.hex(),hx(site+len(raw)),hx(dest),hx(op)))
    calls = []
    for label,site,target in DIRECT_CALLS:
        raw = image.direct(site,target)
        calls.append((label,'direct',hx(site),hx(image.offset(site,len(raw),True)[0]),raw.hex(),hx(target)))
    for label,site,slot in INDIRECT_CALLS:
        raw = image.rip(site,slot,call=True)
        calls.append((label,'indirect_slot',hx(site),hx(image.offset(site,len(raw),True)[0]),raw.hex(),hx(slot)))
    references = []
    for label,site,target in REFERENCES:
        raw = image.rip(site,target)
        references.append((label,hx(site),hx(image.offset(site,len(raw),True)[0]),raw.hex(),hx(target)))
    entries = []
    for label,address,expected in ENTRIES:
        raw = image.entry(address,expected)
        off,section = image.offset(address,len(raw))
        entries.append((label,hx(address),hx(off),section,len(raw),raw.hex()))
    reloc_rows = selected_relocations(image)
    plt_rows = []
    for label,site,slot,name in PLT_LINKS:
        raw,got,record,index = image.plt_link(site,slot,name)
        plt_rows.append((label,hx(site),hx(image.offset(site,len(raw),True)[0]),raw.hex(),
                         hx(got),hx(record),index,name))
    nv_len = verify_name_descriptor(image)
    win = []
    for label,start,end in WINDOWS:
        need(any(fstart <= start < end <= fend for _,fstart,fend,_ in FUNCTIONS), 'window outside selected FDEs')
        raw = image.read(start,end-start,True)
        win.append((label,hx(start),hx(end),hx(image.offset(start,len(raw),True)[0]),raw.hex()))
    options = option_values(image)
    bindings = binding_fields(image)
    flow = input_flow(image)
    parent_key_rows = parent_keys(image)
    constructor_key_rows = constructor_keys(image)
    key_cases = [(hx(k),key_label(image,k).decode('ascii')) for k in (0,1,2,255)]
    path_pattern=path_guard_pattern(image)
    path_probes=[]
    for label,value in (('empty',b''),('short',b'checkpoin'),('exact',path_pattern),
                        ('prefix',path_pattern+b'x'),('suffix',b'x'+path_pattern),
                        ('late',b'x'*14+path_pattern),('absent',b'x'*24)):
        path_probes.append((label,len(value),value.hex(),int(bounded_path_guard(value,path_pattern))))
    path_probes.append(('long_boundary',25,'','not_modelled'))
    collection_thresholds = collection_limits(image)
    collection_cases = [(hx(n),collection_model(n,collection_thresholds))
                        for n in (0,1,2,20,21,(1<<64)-1)]
    params = number_parameters(image)
    high,left,default,check,final = params
    points = (0,1,(1 << (check-left))-1,1 << (check-left),(1 << high)-1,1 << high,(1<<64)-1)
    capacity = [(flag,hx(value),hx(capacity_model(flag,value,params))) for flag in (0,1) for value in points]
    roots = [(hx(word),root_model(word)) for word in (0,(1<<63)-1,1<<63,(1<<63)+1,(1<<64)-1)]
    outcomes = []
    for bits in range(32):
        b = tuple((bits >> shift)&1 for shift in (4,3,2,1,0))
        outcomes.append((*b,outcome_model(*b)))
    native_cases = []
    for status,duplicate in ((0,None),(1,0),(1,1),(255,0),(255,1)):
        wrapper,adapter = native_outcome_model(status,duplicate)
        native_cases.append((status,'not_called' if duplicate is None else duplicate,wrapper,adapter))
    search_limit = scalar_search_limit(image)
    probes = []
    for label,address,expected in ENTRIES:
        if label not in ('first_label','second_label'):
            continue
        pattern = image.entry(address,expected)
        need(pattern[0] != pattern[-1], 'needle filter precondition failed')
        for n in (0,len(pattern)-1):
            sample = b'x'*n
            probes.append((label,n,'short',sample.hex(),int(scalar_search_model(pattern,sample,search_limit))))
        for n in range(len(pattern),len(pattern)+search_limit):
            empty = b'x'*n
            for description,sample in (('absent',empty),
                                       ('first',pattern+empty[len(pattern):]),
                                       ('last',empty[:-len(pattern)]+pattern)):
                probes.append((label,n,description,sample.hex(),int(scalar_search_model(pattern,sample,search_limit))))
        probes.append((label,len(pattern)+search_limit,'vector_boundary','','not_modelled'))
    searches = []
    for label,needle in (('legacy_no_db_hub_suffix',b'/no_db_hub'),
                         ('db_hub_format_entry',b'\xc0\x18/hyperliquid_data/db_hub\x00')):
        matches = find_offsets(data,needle)
        searches.append((label,needle.hex(),len(matches),','.join(hx(x) for x in matches)))
    need(searches[0][2] == 0 and searches[1][2] == 1, 'target byte-search differs')
    summary = {
        'target':'Linux x86-64 node #115', 'sha256':digest(data),
        'coordinate_system':'linked ELF virtual addresses; explicitly marked file offsets',
        'counts':{'selected_fdes':len(functions),'selected_body_bytes':sum(x[3] for x in functions),
                  'branches':len(branches),'direct_calls':len(DIRECT_CALLS),'indirect_call_sites':len(INDIRECT_CALLS),
                  'rip_references':len(references),'data_entries':len(entries),'relocations':len(reloc_rows),
                  'windows':len(win),'option_values':len(options),'binding_fields':len(bindings),'file_byte_searches':len(searches),'size_cases':len(capacity),'root_cases':len(roots),
                  'plt_links':len(plt_rows),'native_cases':len(native_cases),
                  'input_flow_sites':len(flow),'parent_keys':len(parent_key_rows),'constructor_keys':len(constructor_key_rows),
                  'key_label_cases':len(key_cases),'path_guard_cases':len(path_probes),'collection_cases':len(collection_cases),
                  'guard_cases':len(outcomes),'bounded_search_probes':len(probes)},
        'size_parameters':{'high_shift':high,'input_shift':left,'default_before_final_shift':default,
                           'overflow_shift':check,'final_shift':final,'nv_descriptor_length':nv_len,'search_vector_delta':search_limit},
        'limitations':['FDE extents do not establish a full function census.',
                       'Only named sites and normal-return paths are interpreted.',
                       'Models use supplied external outcomes and do not execute the node.',
                       'Vector search, indirect callees, exception actions and concurrency are boundaries.']}
    return {
        'functions.tsv':tsv(('role','start_va','end_va_exclusive','size','file_offset','section','fde_va','cie_va','lsda_va','body_sha256'),functions),
        'bodies.tsv':tsv(('role','start_va','bytes_hex'),bodies),
        'branches.tsv':tsv(('label','site_va','file_offset','bytes_hex','fallthrough_va','taken_va','condition_opcode_low_nibble'),branches),
        'calls.tsv':tsv(('label','kind','site_va','file_offset','bytes_hex','target_or_slot_va'),calls),
        'references.tsv':tsv(('label','site_va','file_offset','bytes_hex','target_va'),references),
        'file-byte-searches.tsv':tsv(('label','needle_hex','count','file_offsets'),searches),
        'entries.tsv':tsv(('label','va','file_offset','section','length','bytes_hex'),entries),
        'relocations.tsv':tsv(('label','slot_va','slot_file_offset','record_file_offset','type','symbol_index','addend','symbol'),reloc_rows),
        'plt-links.tsv':tsv(('label','plt_va','plt_file_offset','jump_bytes_hex','slot_va','relocation_file_offset','symbol_index','symbol'),plt_rows),
        'windows.tsv':tsv(('label','start_va','end_va_exclusive','file_offset','bytes_hex'),win),
        'option-values.tsv':tsv(('label','site_va','field_offset','value'),[(label,hx(site),hx(field),hx(value)) for label,site,field,value in options]),
        'binding-fields.tsv':tsv(('label','site_va','field_offset','source','bytes_hex'),bindings),
        'input-flow.tsv':tsv(('label','site_va','file_offset','bytes_hex'),flow),
        'parent-keys.tsv':tsv(('ordinal','key_byte','setup_site_va','setup_instruction_hex'),parent_key_rows),
        'constructor-keys.tsv':tsv(('ordinal','key_byte','setup_site_va','setup_instruction_hex'),constructor_key_rows),
        'key-label-cases.tsv':tsv(('key_byte','output_label_bytes'),key_cases),
        'path-guard-cases.tsv':tsv(('case','input_length','input_hex','match_or_boundary'),path_probes),
        'collection-cases.tsv':tsv(('input_count','selected_local_path'),collection_cases),
        'size-cases.tsv':tsv(('input_flag','input_u64','builder_argument_u64'),capacity),
        'root-cases.tsv':tsv(('first_word_u64','selected_entry'),roots),
        'guard-cases.tsv':tsv(('root_format_error','first_write_error','first_search_nonzero','second_write_error','second_search_nonzero','selected_local_exit'),outcomes),
        'native-cases.tsv':tsv(('status_byte','duplicated_error_nonnull','native_wrapper_return','adapter_entry_case'),native_cases),
        'bounded-search-probes.tsv':tsv(('label','sample_length','case','sample_hex','contains_or_boundary'),probes),
        'summary.json':(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode(),
    }

def compare_old(new_data, old_data):
    check_identity(new_data)
    check_identity(old_data,OLD_SHA256)
    new,old = Image(new_data,False),Image(old_data,False)
    anchors = (
        ('cham',0x1fc0ec,0x44ab69,b'\xc0\x05/cham\x00'),
        ('static_config',0x1ef5f5,0x4401ef,b'\xc0\x0e/static_config\x00'),
        ('db_hub',0x1f3db9,0x443e39,b'\xc0\x18/hyperliquid_data/db_hub\x00'),
    )
    rows=[]
    for label,old_va,new_va,expected in anchors:
        old.entry(old_va,expected);new.entry(new_va,expected)
        rows.append({'name':label,'node94_va':hx(old_va),'node115_va':hx(new_va),'bytes_hex':expected.hex()})
    legacy = b'\xc0\x1b/hyperliquid_data/no_db_hub\x00'
    old.entry(0x1ea808,legacy)
    old.rip(0x158621e,0x1ea808)
    old_selector=bytes.fromhex('48f7d9704548b901000000000000804839c8756c')
    need(old.read(0x15861dd,len(old_selector),True) == old_selector, 'historical selector bytes differ')
    old.rip(0x1586254,0x1f3db9)
    need(len(find_offsets(new_data,b'/no_db_hub')) == 0, 'legacy suffix unexpectedly present')
    for site,target in ((0x164f840,0x1fc0ec),(0x164fbae,0x1ef5f5)):
        old.rip(site,target)
    old_slot,new_slot=0x5668488,0x63f8998
    old_rela=old.relocations([old_slot])[old_slot];new_rela=new.relocations([new_slot])[new_slot]
    for im,slot,rel,ptr in ((old,old_slot,old_rela,0x2180ff),(new,new_slot,new_rela,0x464716)):
        need(rel[:3] == (8,0,ptr), 'historical name relocation differs')
        need(struct.unpack('<Q',im.read(slot+8,8))[0] == 9, 'historical name length differs')
        im.entry(ptr,b'NvTestnet')
    return {'node94_sha256':OLD_SHA256,'node115_sha256':TARGET_SHA256,'anchors':rows,
            'node94_code_references':[{'site':hx(s),'target':hx(t)} for s,t in ((0x164f840,0x1fc0ec),(0x164fbae,0x1ef5f5))],
            'legacy_no_db_hub':{'node94_entry':hx(0x1ea808),'node94_lea':hx(0x158621e),
                                'node94_selector_va':hx(0x15861dd),'node94_selector_bytes':old_selector.hex(),
                                'node94_file_offsets':[hx(x) for x in find_offsets(old_data,b'/no_db_hub')],
                                'node115_file_occurrences':len(find_offsets(new_data,b'/no_db_hub'))},
            'nv_testnet':{'node94_slot':hx(old_slot),'node94_index':(old_slot-0x5668288)//16,
                          'node115_slot':hx(new_slot),'node115_index':(new_slot-0x63f8788)//16}}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--compare-94',type=Path)
    args = p.parse_args()
    data = TARGET.read_bytes()
    generated = build(data)
    comparison = compare_old(data,args.compare_94.read_bytes()) if args.compare_94 else None
    args.out.mkdir(parents=True,exist_ok=True)
    for name,content in generated.items():
        (args.out/name).write_bytes(content)
    if comparison is not None:
        print(json.dumps(comparison,indent=2,sort_keys=True))
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError,ValueError,struct.error) as exc:
        print('evidence error:',exc,file=sys.stderr)
        raise SystemExit(1)
