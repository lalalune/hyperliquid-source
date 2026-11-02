#!/usr/bin/env python3
"""Extract the bounded node #94 vtg MessagePack route from ELF bytes.

This is a static evidence extractor. It does not execute or emulate the target,
and its selected branches are not a complete decoder or function census.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import unwind_index
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/94/hl-node'
EXPECTED_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# FDE extents are exclusive upper bounds from unwind metadata. The labels are
# analytical names, not recovered symbols. Hashes cover unnormalized bytes.
FUNCTIONS = [
    ('vtg_field_writer', 0x27b2a80, 0x27b2adc, '22749b5a61f231e24691824c11cf65d9aa0332112098766f41e6dd1fab5c7ec0'),
    ('tracker_writer', 0x2326ba0, 0x2326d16, '4c679504ad6c6c1a1412910c4fdd5f459fa8ea5d2f61dd30fe2c7193694a20f9'),
    ('i_container_adapter', 0x25eab80, 0x25eac49, '9a981e84e5831f9b4eb5fad4b6fd75cd96b43b1939a1c6ee5c86aeab1d296711'),
    ('i_array_writer', 0x1e33970, 0x1e33bf7, 'ddcf7de316eac0ed9a42110e09ef9cfc0cfaaf6a7bfb0cb1ae638eab7b748d13'),
    ('i_pair_writer', 0x1de7cb0, 0x1de81e6, '8fff82f205e642c81e53093a3959da4bdf8b6086b71a9caa94086634ad651158'),
    ('unit_writer', 0x1e100c0, 0x1e10284, '60bb315cbf090b4067b2133c4690d9529a323a8c22f404a3cb73b27fae16ffb5'),
    ('row_writer', 0x2321230, 0x232153b, 'a7e5dd0f0763ba2ecf472df7f056d4acd531956d4d0b9b736fe871f08e612d88'),
    ('tracker_reader', 0x169d700, 0x169f2eb, 'fea3c548693132e89031ee41e8a04a848b678c117c0d5e8f7500150b633b7486'),
    ('tracker_key_classifier', 0x16f9d10, 0x16fa4ed, 'df3296ce1cd252671d187cf304d68728a8eed5bdeb3242ecd86ccde2260ec33f'),
    ('hsc_reader', 0x168eda0, 0x168f56d, '27ccdd98e3a5c91abb9abe439c316471a46a4049f75439ffb21110e27746909c'),
    ('i_reader', 0x18caa40, 0x18cb1d9, 'f2321eed644f2bea8daff82e71e44ed5ae1717afb8a2b4aa23446ca3fd7d7c06'),
    ('i_map_visitor', 0x263f590, 0x263f974, 'c6d5cdfb068f821620831121c712f5ac7920511ce5b2e30f8ea77e29d2546658'),
    ('i_sequence_visitor', 0x2664790, 0x2664ac6, 'bd6ab7a1883e5fa91d015b7c568c717321e3f61960bf64e863f9b519e332260d'),
    ('i_pair_reader', 0x183a210, 0x183aca7, 'a07968463072a443f4caca58e3e2a8619fa948d81c29e83deab23c46a02315f3'),
    ('unit_reader', 0x1968910, 0x1968ff2, 'ccdd31e6e3b338baf83b5e86c3283cc8d762a796abed6df92f029a38819a0587'),
    ('unit_marker_visitor', 0x2ea2950, 0x2ea2c05, '9817353b35763b1d2760417d27ad64f5b33a1de4bfcac4c92ed43a47b1fe4d03'),
    ('row_reader', 0x17c2a60, 0x17c4331, '1e44107ed0d6b86a8ddb28f8c1a56752efa6978c286f7f7b63c48301c9ad06db'),
    ('i_materializer', 0x256a2c0, 0x256a5b0, '1cdd17634adc33c877232426b4f62bbf747ba547dc38c1af97dcc1e06825ed2a'),
    ('vts_container_adapter', 0x25e8ca0, 0x25e8d69, '9df4af9d4c9b51a07c3ed6e65c7666282d2c0beadc8301a5f34366f7d4e8e5d2'),
    ('vts_array_writer', 0x1e2a840, 0x1e2aacb, 'd41a30dc775e43e6aadb5811789869db2dd926a1aaae7aef15f2fe5645e4d211'),
    ('vts_pair_writer', 0x1dd5ac0, 0x1dd5c45, '702900a5f04542e68bd8859ddb36202524f764384574cd47d52296fdfe7fc431'),
    ('vts_value_writer', 0x231d2c0, 0x231d3ed, 'a28071a9016881e1f16dd6aa61d23d3b12ea7a3b4889341e6e16dd6d28fccc9f'),
    ('vote_action_writer', 0x236b260, 0x236d0b8, '0361748be68362fef49588462d161602c1a9816456337dc5268a8ba89942e0c0'),
    ('row_key_classifier', 0x16fca30, 0x16fd201, 'f3a1ba77bc0158a0fc88f98cfd0e20fdf5f0cbf409e1da39a61c050ac13daecf'),
    ('qst_reader', 0x1684b00, 0x1684d44, '394e6120c8650b3c03a45b621b22f084305d71d46fc332aba8d9bbc01c562e9d'),
    ('qst_map_entry_reader', 0x2302f30, 0x2303083, '2a5c47daae1648ab5e7aaa76b17f996e59786192adcf06ee2aeaa36fb2b0ec22'),
    ('qst_marker_reader', 0x19054d0, 0x1905bf0, '1471f1da87ab16bac989114f1c5aefa92ae7098895d3941b6adf27e2bcced76f'),
    ('qst_key_classifier', 0x2301760, 0x230182b, '65383dd42d24f3b19608717b5b3cd197f208b9c69b48f8f171a50290bf998f8f'),
    ('qst_bare_error_builder', 0x1705920, 0x1705996, 'b5253babd34323c8b2774c025ab89290c37a39757e112859c2fdaf8a1ce01e95'),
]

# Selected exact instruction bytes; these are anchors for the limited claims,
# not a disassembler. No operand or relocation bytes are masked.
WINDOWS = [
    ('outer_source_offset', 0x275b413, '498d9610350000'),
    ('outer_writer_mode', 0x27b2a8b, '807e0b00'),
    ('outer_key_length', 0x27b2a98, 'ba03000000'),
    ('outer_writer_error_tag', 0x27b2ac1, '48b90000000000000080'),
    ('parent_reader_seen', 0x16dacdd, '4c39a424d0050000'),
    ('parent_reader_name_length', 0x16dacfa, 'b90b000000'),
    ('body_mode', 0x2326bc1, '807a0b00'),
    ('body_map_count', 0x2326bcd, 'ba03000000'),
    ('body_array_count', 0x2326bfc, 'ba03000000'),
    ('body_name_ptr_length', 0x2326c10, '4d8b67084d8b6f10'),
    ('body_name_key_length', 0x2326c26, 'ba04000000'),
    ('body_hsc_key_length', 0x2326c5f, 'ba03000000'),
    ('body_hsc_zero', 0x2326c78, '31d2'),
    ('body_i_key_length', 0x2326c97, 'ba01000000'),
    ('body_i_offset', 0x2326caa, '4983c718'),
    ('body_child_success_tag', 0x2326cbc, '4883c50448392c24'),
    ('container_root_words', 0x25eab8f, '488b0e4885c97435488b5608488b4610'),
    ('container_zero_root', 0x25eabcc, '31c931c0'),
    ('array_count_argument', 0x1e339d4, '4489f2'),
    ('array_count_upper', 0x1e33991, '4c89f048c1e820'),
    ('array_zero_test', 0x1e33b20, '49c1e6044d01f54c39ed'),
    ('array_pointer_stride', 0x1e33b6d, '4883c510'),
    ('pair_length', 0x1de7d0f, 'ba02000000'),
    ('pair_buffer_init', 0x1de7d28, '4c896c24484c89f0488944247848c7842480000000010000'),
    ('pair_direct_marker', 0x1de7e6a, 'c6040192'),
    ('unit_write_marker', 0x1e101a6, 'c60430c0'),
    ('unit_write_result', 0x1e101ae, '4983c4044c8923'),
    ('row_field_count_map', 0x232125f, 'ba03000000'),
    ('row_field_count_array', 0x2321291, 'ba03000000'),
    ('row_arq_offset', 0x23212a6, '450fb6bc2408010000'),
    ('row_arq_bool', 0x23212ee, '4180cfc2'),
    ('row_qst_compare', 0x232133f, '41837d0074'),
    ('row_qst_nested_count', 0x2321393, 'ba01000000'),
    ('row_vts_offset', 0x2321437, '4981c5f0000000'),
    ('field_error_success_tag', 0x169ddf0, '4180fc09'),
    ('field_unknown_selector', 0x169ddff, '83f803'),
    ('field_seen_name', 0x169de3b, '4c396c2430'),
    ('field_seen_hsc', 0x169de93, 'f684241001000001'),
    ('field_seen_i', 0x169eaa7, '48c78424c000000001000000'),
    ('field_name_missing_test', 0x169df80, '4c39ef'),
    ('field_i_missing_test', 0x169e1d5, '4885ed'),
    ('field_name_missing_length', 0x169dfad, '48c784246801000004000000'),
    ('field_i_missing_length', 0x169e205, '48c784246801000001000000'),
    ('field_name_duplicate_length', 0x169efed, '48c784246801000004000000'),
    ('field_hsc_duplicate_length', 0x169ef55, '48c784246801000003000000'),
    ('cached_hsc_nil_compare', 0x168edb6, '81fac0000000'),
    ('cached_hsc_array_compare', 0x168edc2, '81fa90000000'),
    ('cached_hsc_length_test', 0x168ef0c, '84c0'),
    ('cached_hsc_success', 0x168f24b, 'c60709'),
    ('imap_raw_load', 0x18cac14, '488b461049ffc80fb60848ffc0488946104c894618'),
    ('imap_high_ceiling', 0x18cadcb, '80f9df'),
    ('imap_sequence_cutoff', 0x18cadd4, '80f990'),
    ('imap_length_mask', 0x18caddd, '80e10f'),
    ('imap_array_ceiling', 0x18caf18, '80f9a0'),
    ('imap_array_mask', 0x18caf21, '80e10f'),
    ('imap_depth_test', 0x18cade3, '0fb746226685c0'),
    ('imap_map_success', 0x18cae74, 'c6042409'),
    ('map_count_load_test', 0x263f5bc, '448b66084585e4'),
    ('map_count_dec', 0x263f656, '41ffcc488b4424284489'),
    ('map_key_success_tag', 0x263f67b, '4180fe09'),
    ('map_value_error_tag', 0x263f6c5, '4883fd75'),
    ('map_first_root_test', 0x263f718, '488b5c24084885db'),
    ('map_old_slot_test', 0x263f722, '6683bbba0b000000'),
    ('map_old_value_test', 0x263f636, '4883f875'),
    ('map_success_tag', 0x263f80e, 'c60309'),
    ('seq_count_load_test', 0x26647b7, '8b6e0885ed'),
    ('seq_count_dec', 0x266483e, 'ffcd41896e08'),
    ('seq_value_error_tag', 0x2664871, '4983fd75'),
    ('seq_old_value_test', 0x266482c, '4883f875'),
    ('seq_root_test', 0x26648ca, '4c8b6424084d85e4'),
    ('seq_old_slot_test', 0x26648d4, '664183bc24ba0b000000'),
    ('seq_success_tag', 0x266499c, 'c60309'),
    ('pair_count_zero_test', 0x183a778, '85ed'),
    ('pair_key_success_tag', 0x183a79d, '3c09'),
    ('pair_count_one_test', 0x183a7a1, '83fd01'),
    ('pair_value_error_tag', 0x183a7de, '4983ff75'),
    ('pair_exact_count_test', 0x183a8f8, '83fd02'),
    ('pair_extra_error_tag', 0x183a92d, '48c784248003000075000000'),
    ('unit_initial_marker_state', 0x196891a, '440fb64e200fb64e21450fb6c1c6462001'),
    ('unit_raw_load', 0x1968acd, '488b461049ffc80fb60848ffc0488946104c894618'),
    ('unit_raw_sign_test', 0x1968ae2, '84c9'),
    ('unit_raw_df_compare', 0x1968c84, '80f9df'),
    ('unit_raw_90_compare', 0x1968c8d, '80f990'),
    ('unit_raw_a0_compare', 0x1968d5b, '80f9a0'),
    ('unit_raw_c0_compare', 0x1968e39, '80f9c0'),
    ('unit_raw_table_index', 0x1968eb4, '440fb6c94181c140ffffff'),
    ('unit_indirect_call', 0x1968946, 'ff15ec9ce003'),
    ('unit_target_table_index', 0x2ea2951, '440fb6c2418d8040ffffff83f820'),
    ('unit_target_success', 0x2ea2975, 'c60709'),
    ('hsc_cached_or_uncached', 0x168edce, '83fa01'),
    ('hsc_raw_load', 0x168eddc, '488b461048ffc9440fb60048ffc04889461048894e18'),
    ('hsc_raw_sign', 0x168edf2, '4584c0'),
    ('hsc_raw_df_compare', 0x168ee1c, '4180f8df'),
    ('hsc_raw_90_compare', 0x168ee91, '4180f890'),
    ('hsc_raw_a0_compare', 0x168eeff, '4180f8a0'),
    ('hsc_raw_mask', 0x168ef05, '4180e00f'),
    ('hsc_raw_c0_compare', 0x168ef76, '4180f8c0'),
    ('hsc_raw_table_index', 0x168f224, '410fb6d081c240ffffff'),
    ('pair_raw_sign', 0x183a3f5, '84c9'),
    ('pair_raw_df_compare', 0x183a59b, '80f9df'),
    ('pair_raw_90_compare', 0x183a5a4, '80f990'),
    ('pair_raw_a0_compare', 0x183a74c, '80f9a0'),
    ('pair_raw_length_mask', 0x183a755, '80e10f0fb6e9'),
    ('pair_depth_test', 0x183a75b, '0fb746226685c0'),
    ('materialize_count', 0x256a2c8, '4c8b66404d89e749c1e7044c89e048'),
    ('materialize_overflow_shift', 0x256a2d3, '4c89e048c1e83c0f95c0'),
    ('materialize_row_stride', 0x256a371, '4869d210010000'),
    ('materialize_pair_pointers', 0x256a37e, '49c1e1044e89140b4a89540b08'),
    ('vts_adapter_root', 0x25e8caf, '488b0e4885c97435488b5608488b4610'),
    ('vts_adapter_empty', 0x25e8cec, '31c931c0'),
    ('vts_array_count', 0x1e2a8a4, '4489f2'),
    ('vts_array_loop_test', 0x1e2a9f3, '49c1e6044d01f54c39ed'),
    ('vts_array_pair_load', 0x1e2aa20, '488b5500488b4d08'),
    ('vts_array_stride', 0x1e2aa41, '4883c510'),
    ('vts_pair_count', 0x1dd5b01, 'ba02000000'),
    ('vts_pair_child_success', 0x1dd5bb2, '4d8d7d044c397c2408'),
    ('vote_value_map_count', 0x231d2ee, 'ba02000000'),
    ('vote_value_array_count', 0x231d320, 'ba02000000'),
    ('vote_value_vks_len', 0x231d343, 'ba03000000'),
    ('vote_value_hvs_len', 0x231d380, 'ba03000000'),
    ('vote_value_hvs_offset', 0x231d393, '4983c718'),
    ('enum_dispatch_cmp', 0x236b26e, '488b06488d48ee4883f812b84e000000480f43c14889fb'),
    ('enum_name_length', 0x236b2a7, 'b910000000'),
    ('enum_fallback_tag', 0x236cecc, '41b84e000000'),
    ('rowkey_len_three', 0x16fcb6e, '4883fa03'),
    ('rowkey_first_a', 0x16fcb7b, '83f861'),
    ('rowkey_first_q', 0x16fcb84, '83f871'),
    ('rowkey_first_v', 0x16fcb8d, '83f876'),
    ('rowkey_v_second', 0x16fcb96, '80790174'),
    ('rowkey_v_third', 0x16fcba2, '80790273'),
    ('rowkey_q_second', 0x16fcf0b, '80790173'),
    ('rowkey_q_third', 0x16fcf13, '80790274'),
    ('rowkey_a_second', 0x16fcf1f, '80790172'),
    ('rowkey_a_third', 0x16fcf25, '80790271'),
    ('rowkey_a_selector', 0x16fcf2b, '31c0'),
    ('rowkey_q_selector', 0x16fcf11, 'b001'),
    ('rowkey_v_selector', 0x16fcba0, 'b002'),
    ('pair_stream_sentinel', 0x1de7cca, '49be0000000000000080'),
    ('pair_stream_state', 0x1de7cd4, '488b364889f048f7d8'),
    ('pair_stream_mode', 0x1de7ce4, '41807f0c02'),
    ('nil_stream_sentinel', 0x1e100d4, '49bc0000000000000080'),
    ('nil_stream_state', 0x1e100de, '4c8b2e4c89e848f7d8'),
    ('materialize_shift', 0x256a2cf, '49c1e704'),
    ('materialize_high_shift', 0x256a2d6, '48c1e83c'),
    ('materialize_limit', 0x256a2dd, '48b9f8ffffffffffff7f'),
    ('materialize_limit_compare', 0x256a2e7, '4939cf0f97c1'),
    ('materialize_guard_merge', 0x256a2ed, '08c1'),
    ('materialize_failure_call', 0x256a2f6, 'ff15bc3c2003'),
    ('qst_marker_state', 0x1684b0c, '0fb64e2080f901'),
    ('qst_map_count_test', 0x1684b65, '0fb6c083f801'),
    ('qst_map_bad_count_error', 0x1684bdb, 'c643080489430c48c70375000000'),
    ('qst_key_success_test', 0x1684c58, '80f9097511a801'),
    ('qst_n_sentinel', 0x1684c65, '48c70374000000'),
    ('qst_map_key_success', 0x2302f59, '80f9097537a801'),
    ('qst_map_nil_compare', 0x2303043, '3cc0'),
    ('qst_map_nil_sentinel', 0x2303051, '48c70374000000'),
    ('qst_key_length', 0x230176a, '4883fa01'),
    ('qst_key_n_compare', 0x2301773, '83f94e'),
    ('qst_key_q_compare', 0x2301778, '83f951'),
    ('qst_key_q_result', 0x230177d, '66c7000900'),
    ('qst_key_n_result', 0x230178a, '66c7000901'),
    ('qst_bare_builder_error', 0x1705986, '48c70374000000'),
    ('qst_bare_builder_result_test', 0x1684cf3, '837c240874'),
    ('qst_bare_error_result', 0x1684ca3, '48c70375000000'),

]

# Conditional branches are checked as encoded instructions and signed relative
# displacements. Labels describe the taken edge, under the preceding comparison.
BRANCHES = [
    ('parent_vtg_duplicate', 0x16dace5, '0f85', 0x16de54b),
    ('outer_omit_key_on_zero_mode', 0x27b2a8f, '74', 0x27b2ab1),
    ('outer_key_error', 0x27b2aaf, '75', 0x27b2ac1),
    ('writer_array_mode', 0x2326bc5, '74', 0x2326bf6),
    ('writer_map_header_ok', 0x2326bdf, '74', 0x2326c10),
    ('writer_array_header_error', 0x2326c0e, '75', 0x2326be1),
    ('writer_name_skip_key', 0x2326c1d, '75', 0x2326c3d),
    ('writer_name_key_error', 0x2326c37, '0f85', 0x2326cd0),
    ('writer_name_value_error', 0x2326c4f, '75', 0x2326cd0),
    ('writer_hsc_skip_key', 0x2326c56, '75', 0x2326c72),
    ('writer_hsc_key_error', 0x2326c70, '75', 0x2326cd0),
    ('writer_hsc_header_error', 0x2326c87, '75', 0x2326ccb),
    ('writer_i_skip_key', 0x2326c8e, '75', 0x2326caa),
    ('writer_i_key_error', 0x2326ca8, '75', 0x2326ced),
    ('writer_i_child_error', 0x2326cc4, '75', 0x2326cfb),
    ('array_header_error', 0x1e339e5, '0f85', 0x1e33a9b),
    ('array_zero_items', 0x1e33b2a, '74', 0x1e33b76),
    ('array_item_error', 0x1e33b67, '0f85', 0x1e33a4d),
    ('array_continue', 0x1e33b74, '75', 0x1e33b50),
    ('pair_header_error', 0x1de7d22, '0f85', 0x1de802f),
    ('pair_nil_error', 0x1de7d78, '0f85', 0x1de8003),
    ('pair_value_streaming', 0x1de7d8e, '0f84', 0x1de7e28),
    ('pair_value_error', 0x1de7e3f, '0f85', 0x1de80ff),
    ('nil_writer_grow', 0x1e10197, '74', 0x1e101f6),
    ('row_qst_other', 0x232134e, '75', 0x232138b),
    ('row_qst_name_error', 0x2321368, '0f85', 0x23213fa),
    ('field_key_error', 0x169ddf4, '0f85', 0x169decf),
    ('field_known_switch', 0x169de02, '75', 0x169de29),
    ('field_unknown_skip_success', 0x169de22, '74', 0x169dde0),
    ('field_duplicate_name', 0x169de40, '0f85', 0x169efa1),
    ('field_name_error', 0x169de64, '0f85', 0x169ee4b),
    ('field_duplicate_hsc', 0x169de9b, '0f85', 0x169ef09),
    ('field_hsc_error', 0x169deba, '0f85', 0x169ee85),
    ('field_i_error', 0x169e03a, '0f85', 0x169e356),
    ('field_second_known_switch', 0x169e091, '75', 0x169e0b8),
    ('field_name_present', 0x169df93, '0f85', 0x169e1cf),
    ('field_i_present', 0x169e1d8, '0f85', 0x169e28d),
    ('hsc_nil_success', 0x168edbc, '0f84', 0x168f24b),
    ('hsc_sequence', 0x168edc8, '0f84', 0x168ef0c),
    ('hsc_empty_success', 0x168ef0e, '0f84', 0x168f24b),
    ('imap_raw_negative', 0x18cac2b, '0f88', 0x18cadc8),
    ('imap_above_df', 0x18cadce, '0f87', 0x18caa6e),
    ('imap_array_or_higher', 0x18cadd7, '0f83', 0x18caf18),
    ('imap_map_zero_depth', 0x18cadea, '0f84', 0x18cb130),
    ('imap_map_last_depth', 0x18cadf7, '0f84', 0x18cb0c5),
    ('imap_array_a0_or_higher', 0x18caf1b, '0f83', 0x18cb05f),
    ('imap_array_zero_depth', 0x18caf2e, '0f84', 0x18cb13d),
    ('imap_array_last_depth', 0x18caf3b, '0f84', 0x18cb0c5),
    ('imap_map_visitor_error', 0x18cae22, '0f85', 0x18cafa0),
    ('imap_seq_visitor_error', 0x18caf66, '75', 0x18cafa0),
    ('map_empty', 0x263f5c3, '0f84', 0x263f7ef),
    ('map_unit_key_error', 0x263f67f, '0f85', 0x263f816),
    ('map_row_error', 0x263f6c9, '0f84', 0x263f839),
    ('map_new_root', 0x263f720, '74', 0x263f760),
    ('map_existing_slot', 0x263f72a, '0f85', 0x263f5e0),
    ('map_duplicate_error', 0x263f647, '0f85', 0x263f86f),
    ('seq_empty', 0x26647bc, '0f84', 0x266497d),
    ('seq_row_error', 0x2664875, '0f84', 0x26649a4),
    ('seq_new_root', 0x26648d2, '74', 0x2664910),
    ('seq_existing_slot', 0x26648de, '0f85', 0x26647e0),
    ('seq_duplicate_error', 0x2664830, '0f85', 0x26649c1),
    ('pair_missing_key', 0x183a77a, '0f84', 0x183a969),
    ('pair_key_error', 0x183a79f, '75', 0x183a80a),
    ('pair_missing_value', 0x183a7a4, '0f84', 0x183a9cd),
    ('pair_value_success', 0x183a7e2, '75', 0x183a85f),
    ('pair_too_many', 0x183a8fb, '75', 0x183a91a),
    ('unit_input_empty', 0x1968ac7, '0f84', 0x1968c5b),
    ('unit_signed_marker', 0x1968ae4, '0f88', 0x1968c81),
    ('unit_marker_above_df', 0x1968c87, '0f87', 0x196893c),
    ('unit_marker_ge_90', 0x1968c90, '0f83', 0x1968d5b),
    ('unit_marker_ge_a0', 0x1968d5e, '0f83', 0x1968e39),
    ('unit_marker_ge_c0', 0x1968e3c, '73', 0x1968eb4),
    ('unit_target_outside_span', 0x2ea295f, '0f87', 0x2ea2b71),
    ('key_len1', 0x16fa0ba, '0f84', 0x16fa23b),
    ('key_len3', 0x16fa0c7, '0f84', 0x16fa226),
    ('key_other_length', 0x16fa0d1, '0f85', 0x16fa245),
    ('key_name_0_mismatch', 0x16fa0da, '0f85', 0x16fa245),
    ('key_name_1_mismatch', 0x16fa0e4, '0f85', 0x16fa245),
    ('key_name_2_mismatch', 0x16fa0ee, '0f85', 0x16fa245),
    ('key_name_3_mismatch', 0x16fa0f8, '0f85', 0x16fa245),
    ('key_hsc_0_mismatch', 0x16fa229, '75', 0x16fa245),
    ('key_hsc_1_mismatch', 0x16fa22f, '75', 0x16fa245),
    ('key_hsc_2_mismatch', 0x16fa237, '75', 0x16fa245),
    ('key_i_match', 0x16fa243, '74', 0x16fa247),
    ('hsc_no_raw_byte', 0x168edda, '74', 0x168ee12),
    ('hsc_raw_signed', 0x168edf5, '78', 0x168ee1a),
    ('hsc_raw_le_df', 0x168ee20, '76', 0x168ee91),
    ('hsc_raw_ge_90', 0x168ee95, '73', 0x168eeff),
    ('hsc_raw_ge_a0', 0x168ef03, '73', 0x168ef76),
    ('hsc_raw_ge_c0', 0x168ef7a, '0f83', 0x168f224),
    ('pair_raw_signed', 0x183a3f7, '0f88', 0x183a598),
    ('pair_raw_gt_df', 0x183a59e, '0f87', 0x183a243),
    ('pair_raw_ge_90', 0x183a5a7, '0f83', 0x183a74c),
    ('pair_raw_ge_a0', 0x183a74f, '0f83', 0x183a9ed),
    ('pair_zero_depth', 0x183a762, '0f84', 0x183ac2b),
    ('pair_last_depth', 0x183a76f, '0f84', 0x183aaf3),
    ('materialize_no_overflow', 0x256a2ef, '74', 0x256a2fc),
    ('materialize_zero', 0x256a2ff, '74', 0x256a32f),
    ('vts_adapter_empty_root', 0x25e8cb5, '74', 0x25e8cec),
    ('vts_array_header_error', 0x1e2a8b5, '0f85', 0x1e2a96e),
    ('vts_array_empty', 0x1e2a9fd, '74', 0x1e2aa4a),
    ('vts_array_pair_error', 0x1e2aa3b, '0f85', 0x1e2a920),
    ('vts_array_continue', 0x1e2aa48, '75', 0x1e2aa20),
    ('vts_pair_header_ok', 0x1dd5b14, '0f84', 0x1dd5ba2),
    ('vts_pair_key_error', 0x1dd5bbb, '75', 0x1dd5c07),
    ('vts_pair_value_error', 0x1dd5bd2, '75', 0x1dd5c07),
    ('vote_value_array_mode', 0x231d2e4, '74', 0x231d318),
    ('vote_value_header_ok', 0x231d301, '74', 0x231d335),
    ('vote_value_array_header_error', 0x231d333, '75', 0x231d303),
    ('vote_value_vks_key_error', 0x231d354, '75', 0x231d3b3),
    ('vote_value_vks_child_error', 0x231d370, '75', 0x231d3c2),
    ('vote_value_hvs_key_error', 0x231d391, '75', 0x231d3b3),
    ('vote_value_hvs_child_error', 0x231d3ac, '75', 0x231d3c2),
    ('row_reader_key_error', 0x17c2ee1, '0f85', 0x17c3a2f),
    ('row_reader_duplicate_qst', 0x17c2f01, '0f85', 0x17c3ff7),
    ('row_reader_qst_error', 0x17c2f52, '0f84', 0x17c3c9d),
    ('row_reader_duplicate_arq', 0x17c2fc7, '0f85', 0x17c40a2),
    ('row_reader_arq_error', 0x17c2fe7, '0f85', 0x17c3c69),
    ('row_reader_vts_error', 0x17c30cf, '0f85', 0x17c3340),
    ('pair_buffered_alternative', 0x1de7cdd, '71', 0x1de7cf4),
    ('pair_stream_array_header', 0x1de7ce9, '75', 0x1de7d07),
    ('unit_buffered_alternative', 0x1e100e7, '71', 0x1e100f2),
    ('rowkey_other_length', 0x16fcb72, '0f85', 0x16fcf32),
    ('rowkey_first_a', 0x16fcb7e, '0f84', 0x16fcf1f),
    ('rowkey_first_q', 0x16fcb87, '0f84', 0x16fcf0b),
    ('rowkey_first_v_other', 0x16fcb90, '0f85', 0x16fcf32),
    ('rowkey_v_second_other', 0x16fcb9a, '0f85', 0x16fcf32),
    ('rowkey_v_match', 0x16fcba6, '0f84', 0x16fca92),
    ('rowkey_q_second_other', 0x16fcf0f, '75', 0x16fcf32),
    ('rowkey_q_match', 0x16fcf17, '0f84', 0x16fca92),
    ('rowkey_a_second_other', 0x16fcf23, '75', 0x16fcf32),
    ('rowkey_a_third_other', 0x16fcf29, '75', 0x16fcf32),
    ('qst_no_input', 0x1684b1c, '74', 0x1684b9b),
    ('qst_cached_map32', 0x1684b45, '0f84', 0x1684c1b),
    ('qst_cached_map16', 0x1684b54, '74', 0x1684b81),
    ('qst_unexpected_map_marker', 0x1684b5f, '0f85', 0x1684c3f),
    ('qst_map_bad_count', 0x1684b6b, '75', 0x1684bdb),
    ('qst_map16_one', 0x1684bd9, '74', 0x1684b6d),
    ('qst_direct_key_error', 0x1684c5b, '75', 0x1684c6e),
    ('qst_bare_q_error', 0x1684c5f, '0f84', 0x1684ce9),
    ('qst_map_key_error', 0x2302f5c, '75', 0x2302f95),
    ('qst_map_q_payload', 0x2302f60, '74', 0x2302fcf),
    ('qst_map_n_missing_nil', 0x2302f69, '0f84', 0x2303025),
    ('qst_map_n_not_nil', 0x230304f, '75', 0x230305a),
    ('qst_key_bad_length', 0x230176e, '75', 0x2301797),
    ('qst_key_is_n', 0x2301776, '74', 0x230178a),
    ('qst_key_not_q', 0x230177b, '75', 0x2301797),
    ('qst_bare_builder_nonerror', 0x1684cf8, '75', 0x1684d0e),
]

# Selected direct calls/jumps. 'context' refers to previously studied parent
# code, and 'helper' to a callee whose implementation is outside this packet.
EDGES = [
    ('parent_to_field_writer', 0x275b420, 'call', 0x27b2a80, 'context'),
    ('field_writer_to_string_helper', 0x27b2aa3, 'call', 0x25aa7f0, 'helper'),
    ('field_writer_to_tracker_writer', 0x27b2abc, 'jump', 0x2326ba0, 'selected'),
    ('tracker_map_header', 0x2326bd2, 'call', 0x25a8f80, 'helper'),
    ('tracker_array_header', 0x2326c01, 'call', 0x25a9bd0, 'helper'),
    ('tracker_name_key', 0x2326c2e, 'call', 0x25aa7f0, 'helper'),
    ('tracker_name_value', 0x2326c46, 'call', 0x25aa7f0, 'helper'),
    ('tracker_hsc_key', 0x2326c67, 'call', 0x25aa7f0, 'helper'),
    ('tracker_hsc_empty_array', 0x2326c7a, 'call', 0x25a9bd0, 'helper'),
    ('tracker_i_key', 0x2326c9f, 'call', 0x25aa7f0, 'helper'),
    ('tracker_i_adapter', 0x2326cb7, 'call', 0x25eab80, 'selected'),
    ('adapter_materialize', 0x25eabea, 'call', 0x256a2c0, 'selected'),
    ('adapter_array_writer', 0x25eabf8, 'call', 0x1e33970, 'selected'),
    ('array_header_writer', 0x1e339d7, 'call', 0x25a9bd0, 'helper'),
    ('array_first_pair', 0x1e33a2c, 'call', 0x1de7cb0, 'selected'),
    ('array_pair_loop', 0x1e33b5a, 'call', 0x1de7cb0, 'selected'),
    ('pair_header_writer', 0x1de7d14, 'call', 0x25a9bd0, 'helper'),
    ('pair_unit_writer', 0x1de7d6a, 'call', 0x1e100c0, 'selected'),
    ('pair_row_writer', 0x1de7e35, 'call', 0x2321230, 'selected'),
    ('row_map_header', 0x2321264, 'call', 0x25a8f80, 'helper'),
    ('row_array_header', 0x2321296, 'call', 0x25a9bd0, 'helper'),
    ('row_arq_key', 0x23212c5, 'call', 0x25aa7f0, 'helper'),
    ('row_arq_marker', 0x23212f6, 'call', 0x25acc20, 'helper'),
    ('row_qst_key', 0x232132b, 'call', 0x25aa7f0, 'helper'),
    ('row_qst_unit', 0x232135f, 'call', 0x25aa7f0, 'helper'),
    ('row_qst_payload_header', 0x2321398, 'call', 0x25a8f80, 'helper'),
    ('row_qst_payload_key', 0x23213bb, 'call', 0x25aa7f0, 'helper'),
    ('row_vts_key', 0x232142c, 'call', 0x25aa7f0, 'helper'),
    ('row_qst_payload_writer', 0x23213d5, 'call', 0x236b260, 'selected'),
    ('row_vts_writer', 0x2321449, 'call', 0x25e8ca0, 'selected'),
    ('vts_materialize', 0x25e8d0a, 'call', 0x2574ec0, 'helper'),
    ('vts_array_writer', 0x25e8d18, 'call', 0x1e2a840, 'selected'),
    ('vts_array_header', 0x1e2a8a7, 'call', 0x25a9bd0, 'helper'),
    ('vts_first_pair', 0x1e2a8ff, 'call', 0x1dd5ac0, 'selected'),
    ('vts_pair_loop', 0x1e2aa2e, 'call', 0x1dd5ac0, 'selected'),
    ('vts_pair_header', 0x1dd5b06, 'call', 0x25a9bd0, 'helper'),
    ('vts_pair_key_writer', 0x1dd5bad, 'call', 0x236b260, 'selected'),
    ('vts_pair_value_writer', 0x1dd5bc8, 'call', 0x231d2c0, 'selected'),
    ('vote_value_map_header', 0x231d2f3, 'call', 0x25a8f80, 'helper'),
    ('vote_value_array_header', 0x231d325, 'call', 0x25a9bd0, 'helper'),
    ('vote_value_vks_key', 0x231d34b, 'call', 0x25aa7f0, 'helper'),
    ('vote_value_vks_child', 0x231d361, 'call', 0x25eb850, 'helper'),
    ('vote_value_hvs_key', 0x231d388, 'call', 0x25aa7f0, 'helper'),
    ('vote_value_hvs_child', 0x231d3a2, 'call', 0x25e78c0, 'helper'),
    ('row_key_reader', 0x17c2ecf, 'call', 0x16fca30, 'selected'),
    ('row_arq_reader', 0x17c2fd5, 'call', 0x1684650, 'helper'),
    ('row_qst_reader', 0x17c2f0f, 'call', 0x1684b00, 'selected'),
    ('row_vts_reader', 0x17c30bd, 'call', 0x1965cf0, 'helper'),
    ('qst_map_entry', 0x1684b77, 'call', 0x2302f30, 'selected'),
    ('qst_direct_key', 0x1684c49, 'call', 0x19054d0, 'selected'),
    ('qst_bare_q_error_helper', 0x1684cee, 'call', 0x1705920, 'selected'),
    ('qst_map_key', 0x2302f4a, 'call', 0x19054d0, 'selected'),
    ('qst_map_action_reader', 0x2302ff0, 'call', 0x1687210, 'helper'),
    ('qst_key_classifier_borrowed', 0x19055ef, 'call', 0x2301760, 'selected'),
    ('qst_key_classifier_owned', 0x190572c, 'call', 0x2301760, 'selected'),
    ('parent_to_tracker_reader', 0x16dad02, 'call', 0x169d700, 'context'),
    ('tracker_first_key', 0x169dde6, 'call', 0x16f9d10, 'selected'),
    ('tracker_next_key', 0x169e075, 'call', 0x16f9d10, 'selected'),
    ('tracker_unknown_value', 0x169de14, 'call', 0x19682d0, 'helper'),
    ('tracker_name_reader', 0x169de56, 'call', 0x19822a0, 'helper'),
    ('tracker_hsc_reader', 0x169deac, 'call', 0x168eda0, 'selected'),
    ('tracker_i_reader', 0x169e02c, 'call', 0x18caa40, 'selected'),
    ('i_map_visitor', 0x18cae16, 'call', 0x263f590, 'selected'),
    ('i_seq_visitor', 0x18caf5a, 'call', 0x2664790, 'selected'),
    ('map_unit_reader', 0x263f66d, 'call', 0x1968910, 'selected'),
    ('map_row_reader', 0x263f68d, 'call', 0x17c2a60, 'selected'),
    ('map_insert', 0x263f7e0, 'call', 0x2879910, 'helper'),
    ('sequence_pair_reader', 0x2664853, 'call', 0x183a210, 'selected'),
    ('sequence_insert', 0x2664973, 'call', 0x2879910, 'helper'),
    ('pair_unit_reader', 0x183a790, 'call', 0x1968910, 'selected'),
    ('pair_row_reader', 0x183a7b7, 'call', 0x17c2a60, 'selected'),
]

# RIP-relative literal references: label, instruction, opcode, expected bytes.
LITERAL_SPECS = [
    ('outer_field', 0x27b2a91, '488d35', b'vtg'),
    ('parent_duplicate_field', 0x16de54b, '488d05', b'vtg'),
    ('parent_tracker_name', 0x16daceb, '488d15', b'VoteTracker'),
    ('tracker_name', 0x2326c1f, '488d35', b'name'),
    ('tracker_hsc', 0x2326c58, '488d35', b'hsc'),
    ('tracker_i', 0x2326c90, '488d35', b'i'),
    ('reader_missing_name', 0x169df9e, '488d05', b'name'),
    ('reader_missing_i', 0x169e1f6, '488d05', b'i'),
    ('reader_duplicate_name', 0x169efde, '488d05', b'name'),
    ('reader_duplicate_hsc', 0x169ef46, '488d05', b'hsc'),
    ('reader_duplicate_i', 0x169eae0, '488d05', b'i'),
    ('reader_missing_template', 0x169dfd8, '488d35', b'\x0fmissing field `'),
    ('reader_duplicate_template', 0x169ef80, '488d35', b'\x11duplicate field `'),
    ('reader_duplicate_i_template', 0x169eb1f, '488d35', b'\x11duplicate field `'),
    ('row_writer_arq', 0x23212b6, '488d35', b'arq'),
    ('row_writer_qst', 0x232131c, '488d35', b'qst'),
    ('row_writer_vts', 0x232141d, '488d35', b'vts'),
    ('row_qst_unit', 0x2321350, '488d35', b'N'),
    ('row_qst_payload', 0x23213ac, '488d35', b'Q'),
    ('row_reader_arq_diagnostic', 0x17c3016, '488d05', b'arq'),
    ('row_reader_qst_diagnostic', 0x17c4001, '488d05', b'qst'),
    ('row_reader_vts_diagnostic', 0x17c3bc5, '488d05', b'vts'),
    ('vote_value_vks', 0x231d33c, '488d35', b'vks'),
    ('vote_value_hvs', 0x231d379, '488d35', b'hvs'),
    ('enum_type_name', 0x236b299, '488d05', b'VoteGlobalAction'),
    ('enum_first_tag', 0x236b2a0, '4c8d0d', b'a'),
    ('enum_fallback_tag', 0x236ceb7, '4c8d0d', b'DD'),
]

# Each comparison is the valid decoded-string path's indexed byte comparison.
# The first index has a shorter addressing instruction than subsequent indices.
KEY_COMPARISONS = [
    ('name', [(0x16fa0d7, '803b'), (0x16fa0e0, '807b01'),
              (0x16fa0ea, '807b02'), (0x16fa0f4, '807b03')]),
    ('hsc', [(0x16fa226, '803b'), (0x16fa22b, '807b01'), (0x16fa233, '807b02')]),
    ('i', [(0x16fa23d, '803b')]),
]

TABLES = [
    ('tracker_before_i', 0x169de2b, '488d0d', 0x286384,
     [(0, 0x169de3b), (1, 0x169de93), (2, 0x169e01d)]),
    ('tracker_after_i', 0x169e0ba, '488d0d', 0x286398,
     [(0, 0x169e0ca), (1, 0x169e122), (2, 0x169eaa7)]),
    ('hsc_raw_c0_marker', 0x168f22e, '4c8d0d', 0x2808bc,
     [(0, 0x168f24b)]),
    ('i_uncached_marker', 0x18caa5d, '488d05', 0x32d2bc,
     [(1, 0x18cac07)]),
    ('unit_uncached_marker', 0x196892b, '488d05', 0x362fc8,
     [(1, 0x1968ac0)]),
    ('unit_raw_c0_marker', 0x1968ebf, '4c8d15', 0x363394,
     [(0, 0x196893c)]),
    ('unit_visitor_c0_marker', 0x2ea2965, '4c8d05', 0x563a30,
     [(0, 0x2ea2975)]),
    ('row_named_fields', 0x17c2e75, '4c8d2d', 0x2d5344,
     [(0, 0x17c2fc2), (1, 0x17c2ef9), (2, 0x17c30ac), (3, 0x17c2f98)]),
]


def authenticate(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError('node #94 SHA-256 mismatch')
    return digest


class Image:
    def __init__(self, data, secs):
        self.data = data
        self.sections = secs

    def location(self, va, size, executable=False):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise ValueError('invalid virtual address or size')
        matches = [s for s in self.sections
                   if s['type'] != 8 and s['flags'] & 2
                   and (not executable or s['flags'] & 4)
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('address is outside one unambiguous file-backed section')
        section = matches[0]
        offset = section['offset'] + va - section['address']
        if offset < 0 or offset + size > len(self.data):
            raise ValueError('address exceeds file bytes')
        return section['name'], offset

    def read(self, va, size, executable=False):
        _, offset = self.location(va, size, executable)
        return bytes(self.data[offset:offset + size])


def check_window(image, label, va, expected):
    expected = bytes.fromhex(expected)
    section, offset = image.location(va, len(expected), executable=True)
    raw = image.read(va, len(expected), executable=True)
    if raw != expected:
        raise ValueError(f'changed instruction window: {label}')
    return {'label': label, 'va': hex(va), 'file_offset': hex(offset),
            'section': section, 'bytes': raw.hex()}


def branch(image, label, va, opcode_hex, expected_target):
    opcode = bytes.fromhex(opcode_hex)
    if len(opcode) == 1 and 0x70 <= opcode[0] <= 0x7f:
        size, fmt = 2, '<b'
    elif len(opcode) == 2 and opcode[0] == 0x0f and 0x80 <= opcode[1] <= 0x8f:
        size, fmt = 6, '<i'
    else:
        raise ValueError('unsupported conditional opcode')
    section, offset = image.location(va, size, executable=True)
    raw = image.read(va, size, executable=True)
    if raw[:len(opcode)] != opcode:
        raise ValueError(f'changed conditional opcode: {label}')
    displacement = struct.unpack(fmt, raw[len(opcode):])[0]
    target = va + size + displacement
    if target != expected_target:
        raise ValueError(f'changed conditional target: {label}')
    image.location(target, 1, executable=True)
    return {'label': label, 'va': hex(va), 'file_offset': hex(offset),
            'section': section, 'bytes': raw.hex(), 'target_va': hex(target)}


def edge(image, label, va, kind, expected_target, category):
    if kind not in ('call', 'jump'):
        raise ValueError('unsupported edge kind')
    section, offset = image.location(va, 5, executable=True)
    raw = image.read(va, 5, executable=True)
    if raw[0] != {'call': 0xe8, 'jump': 0xe9}[kind]:
        raise ValueError(f'changed edge opcode: {label}')
    target = va + 5 + struct.unpack('<i', raw[1:])[0]
    if target != expected_target:
        raise ValueError(f'changed edge target: {label}')
    image.location(target, 1, executable=True)
    return {'label': label, 'va': hex(va), 'file_offset': hex(offset),
            'section': section, 'bytes': raw.hex(), 'target_va': hex(target),
            'kind': kind, 'category': category}


def rip_target(image, va, prefix_hex):
    prefix = bytes.fromhex(prefix_hex)
    if len(prefix) != 3:
        raise ValueError('unsupported RIP-relative prefix')
    raw = image.read(va, 7, executable=True)
    if raw[:3] != prefix:
        raise ValueError('changed RIP-relative opcode')
    return va + 7 + struct.unpack('<i', raw[3:])[0]


def literal(image, label, va, prefix_hex, expected):
    address = rip_target(image, va, prefix_hex)
    section, offset = image.location(address, len(expected))
    raw = image.read(address, len(expected))
    if raw != expected:
        raise ValueError(f'changed referenced bytes: {label}')
    return {'label': label, 'instruction_va': hex(va),
            'instruction_bytes': image.read(va, 7, True).hex(),
            'data_va': hex(address), 'data_file_offset': hex(offset),
            'data_section': section, 'bytes': raw.hex(),
            'ascii': raw.decode('ascii')}


def field_keys(image):
    # Verify the dispatch length tests and the selector assignments as well as
    # the byte comparisons. Return an observational classifier model.
    for label, va, expected in [
        ('key_len_1', 0x16fa0b6, '4983fe01'),
        ('key_len_3', 0x16fa0c0, '4183fe03'),
        ('key_len_4', 0x16fa0cd, '4183fe04'),
        ('key_selector_name', 0x16fa0fe, '31c0'),
        ('key_selector_hsc', 0x16fa231, 'b001'),
        ('key_selector_i', 0x16fa23b, 'b002'),
        ('key_selector_other', 0x16fa245, 'b003'),
    ]:
        check_window(image, label, va, expected)
    result = []
    for selector, (label, comparisons) in enumerate(KEY_COMPARISONS):
        buf, sites = bytearray(), []
        for va, prefix_hex in comparisons:
            prefix = bytes.fromhex(prefix_hex)
            raw = image.read(va, len(prefix) + 1, executable=True)
            if raw[:-1] != prefix:
                raise ValueError('changed key byte comparison')
            buf.append(raw[-1])
            sites.append({'va': hex(va), 'bytes': raw.hex()})
        expected = {'name': b'name', 'hsc': b'hsc', 'i': b'i'}[label]
        if bytes(buf) != expected:
            raise ValueError('changed key comparison immediate')
        result.append({'name': label, 'ascii': bytes(buf).decode('ascii'),
                       'selector': selector, 'length': len(buf), 'comparisons': sites})
    return result


def classify_key(image, key):
    if not isinstance(key, bytes):
        raise ValueError('key must be bytes')
    for row in field_keys(image):
        if key == row['ascii'].encode('ascii'):
            return row['selector']
    return 3


def qst_key(image, key):
    """Model only the decoded one-byte Q/N name comparisons."""
    if not isinstance(key, bytes):
        raise ValueError('key must be bytes')
    length = check_window(image, 'qst_length', 0x230176a, '4883fa01')
    n = check_window(image, 'qst_n', 0x2301773, '83f94e')
    q = check_window(image, 'qst_q', 0x2301778, '83f951')
    check_window(image, 'qst_q_tag', 0x230177d, '66c7000900')
    check_window(image, 'qst_n_tag', 0x230178a, '66c7000901')
    if len(key) != bytes.fromhex(length['bytes'])[-1]:
        return 'other'
    if key[0] == bytes.fromhex(n['bytes'])[-1]:
        return 'N'
    if key[0] == bytes.fromhex(q['bytes'])[-1]:
        return 'Q'
    return 'other'


def classify_fixed_header(image, marker):
    """Model only the uncached fixed-map/fixed-array marker partition."""
    if not isinstance(marker, int) or isinstance(marker, bool) or not 0 <= marker <= 255:
        raise ValueError('marker must be one byte')
    cutoff = check_window(image, 'cutoff', 0x18cadd4, '80f990')
    upper = check_window(image, 'upper', 0x18caf18, '80f9a0')
    mask = check_window(image, 'mask', 0x18caddd, '80e10f')
    boundary = bytes.fromhex(cutoff['bytes'])[-1]
    high = bytes.fromhex(upper['bytes'])[-1]
    count_mask = bytes.fromhex(mask['bytes'])[-1]
    if marker & 0x80 and marker < boundary:
        return ('map', marker & count_mask)
    if boundary <= marker < high:
        return ('array', marker & count_mask)
    return ('other', None)


def pair_arity(image, count):
    """Model the fixarray arity branches, conditional on earlier children."""
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 15:
        raise ValueError('fixed-array length must be in 0..15')
    check_window(image, 'pair_count_zero', 0x183a778, '85ed')
    one = check_window(image, 'pair_count_one', 0x183a7a1, '83fd01')
    two = check_window(image, 'pair_count_two', 0x183a8f8, '83fd02')
    if count == 0:
        return 'missing_key'
    if count == bytes.fromhex(one['bytes'])[-1]:
        return 'missing_value_after_key'
    if count == bytes.fromhex(two['bytes'])[-1]:
        return 'two_children_required'
    return 'extra_after_two_children'


def relative_table(image, label, lea, prefix, base, expected):
    if rip_target(image, lea, prefix) != base:
        raise ValueError(f'changed table base: {label}')
    entries = []
    for index, target in expected:
        va = base + 4 * index
        section, offset = image.location(va, 4)
        raw = image.read(va, 4)
        actual = base + struct.unpack('<i', raw)[0]
        if actual != target:
            raise ValueError(f'changed table entry: {label}')
        image.location(actual, 1, executable=True)
        entries.append({'index': index, 'entry_va': hex(va), 'file_offset': hex(offset),
                        'section': section, 'bytes': raw.hex(), 'target_va': hex(actual)})
    return {'label': label, 'lea_va': hex(lea), 'lea_bytes': image.read(lea, 7, True).hex(),
            'base_va': hex(base), 'entries': entries}


def materialization_guard(image):
    shift_bytes = bytes.fromhex(check_window(image, 'stride_shift', 0x256a2cf, '49c1e704')['bytes'])
    high_bytes = bytes.fromhex(check_window(image, 'overflow_shift', 0x256a2d6, '48c1e83c')['bytes'])
    limit_bytes = bytes.fromhex(check_window(image, 'byte_limit', 0x256a2dd, '48b9f8ffffffffffff7f')['bytes'])
    check_window(image, 'unsigned_limit_comparison', 0x256a2e7, '4939cf0f97c1')
    check_window(image, 'combine_guard_flags', 0x256a2ed, '08c1')
    branch(image, 'valid_size', 0x256a2ef, '74', 0x256a2fc)
    shift, high_shift = shift_bytes[-1], high_bytes[-1]
    limit = struct.unpack('<Q', limit_bytes[2:])[0]
    max_without_branch = min(limit >> shift, (1 << high_shift) - 1)
    return {'count_shift': shift, 'high_bits_shift': high_shift, 'byte_limit': hex(limit),
            'max_count_without_guard_call': hex(max_without_branch)}


def guard_takes_call(image, count):
    """Model only the unsigned allocation-size condition, not the callee."""
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count < 1 << 64:
        raise ValueError('count must fit in an unsigned 64-bit word')
    guard = materialization_guard(image)
    shifted = (count << guard['count_shift']) & ((1 << 64) - 1)
    return bool((count >> guard['high_bits_shift']) or shifted > int(guard['byte_limit'], 16))


def action_dispatch(image):
    """Read the bounded jump-table span reached by the shared action writer.

    The fallback slot bounds this selected span; it does not prove which input
    discriminants are constructible or describe out-of-range machine behavior.
    """
    raw = image.read(0x236b26e, 23, executable=True)
    expected = '488b06488d48ee4883f812b84e000000480f43c14889fb'
    if raw.hex() != expected:
        raise ValueError('changed action selector')
    bias = struct.unpack('<b', raw[6:7])[0]
    lower = raw[10]
    fallback = struct.unpack('<I', raw[12:16])[0]
    if bias != -lower or lower != 0x12 or fallback != 0x4e:
        raise ValueError('unsupported action selector')
    base = rip_target(image, 0x236b285, '488d0d')
    if base != 0x3dd85c:
        raise ValueError('changed action table base')
    count = fallback + 1
    table_bytes = image.read(base, count * 4)
    digest = hashlib.sha256(table_bytes).hexdigest()
    if digest != '3750670818a679f0b29be687a22f44c1b9c48b00ee7655b9de9231eb86224de3':
        raise ValueError('changed action table bytes')
    entries = []
    for index in range(count):
        va = base + index * 4
        section, offset = image.location(va, 4)
        entry = image.read(va, 4)
        target = base + struct.unpack('<i', entry)[0]
        if not 0x236b260 <= target < 0x236d0b8:
            raise ValueError('action table target outside selected FDE')
        image.location(target, 1, executable=True)
        entries.append({'index': index, 'example_discriminant': lower + index,
                        'entry_va': hex(va), 'file_offset': hex(offset), 'section': section,
                        'bytes': entry.hex(), 'target_va': hex(target),
                        'is_fallback_slot': index == fallback})
    return {'selector_va': hex(0x236b26e), 'selector_bytes': raw.hex(),
            'table_lea_va': hex(0x236b285), 'table_va': hex(base),
            'lower_bound': lower, 'fallback_index': fallback,
            'table_sha256': digest, 'entries': entries}


def action_index(image, value):
    """Model the bounded selector span only, not unbounded target behavior."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError('discriminant must be an integer')
    table = action_dispatch(image)
    lower, fallback = table['lower_bound'], table['fallback_index']
    if not 0 <= value <= lower + fallback:
        raise ValueError('discriminant outside the selected table span')
    return value - lower if value >= lower else fallback


def relative_relocation(image, slot, expected_addend, label):
    matches = [s for s in image.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(matches) != 1:
        raise ValueError('missing or ambiguous dynamic relocation section')
    sec = matches[0]
    if sec['size'] % 24:
        raise ValueError('invalid dynamic relocation section size')
    rows = []
    for offset in range(sec['offset'], sec['offset'] + sec['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', image.data, offset)
        if address == slot:
            rows.append((offset, info, addend))
    if len(rows) != 1:
        raise ValueError('missing or ambiguous relocation slot')
    offset, info, addend = rows[0]
    if info != 8 or addend != expected_addend:
        raise ValueError('changed relative relocation')
    slot_section, slot_offset = image.location(slot, 8)
    return {'label': label, 'slot_va': hex(slot), 'slot_section': slot_section,
            'slot_file_offset': hex(slot_offset), 'slot_bytes': image.read(slot, 8).hex(),
            'relocation_section': sec['name'], 'relocation_file_offset': hex(offset),
            'relocation_bytes': bytes(image.data[offset:offset + 24]).hex(),
            'type': info & 0xffffffff, 'symbol_index': info >> 32, 'addend': hex(addend)}


def duplicate_literal(image, label, first, second):
    # The program writes overlapping qwords at buffer offsets 5 and 0.
    a = image.read(first, 14, executable=True)
    b = image.read(second, 13, executable=True)
    if a[:2] != b'\x48\xb9' or a[10:] != b'\x48\x89\x48\x05':
        raise ValueError('changed first diagnostic immediate or store')
    if b[:2] != b'\x48\xb9' or b[10:] != b'\x48\x89\x08':
        raise ValueError('changed second diagnostic immediate or store')
    message = bytearray(13)
    message[5:13] = a[2:10]
    message[0:8] = b[2:10]
    if bytes(message) != b'duplicate key':
        raise ValueError('changed duplicate key diagnostic')
    return {'label': label, 'first_va': hex(first), 'first_bytes': a.hex(),
            'second_va': hex(second), 'second_bytes': b.hex(),
            'ascii': bytes(message).decode('ascii')}


def function_records(image, index):
    _, fdes = eh_frame_records(image.data, image.sections)
    records = []
    for label, start, end, expected_hash in FUNCTIONS:
        entries = [row for row in index if row['start'] == start]
        frames = [row for row in fdes if row['start'] == start]
        if len(entries) != 1 or len(frames) != 1:
            raise ValueError(f'missing or duplicate selected FDE: {label}')
        entry, frame = entries[0], frames[0]
        if entry['fde'] != frame['fde'] or frame['end'] != end:
            raise ValueError(f'unwind index/FDE mismatch: {label}')
        section, offset = image.location(start, end - start, executable=True)
        body_hash = hashlib.sha256(image.read(start, end - start, True)).hexdigest()
        if body_hash != expected_hash:
            raise ValueError(f'changed FDE body: {label}')
        records.append({'label': label, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                        'size': end - start, 'section': section, 'file_offset': hex(offset),
                        'fde_va': hex(frame['fde']), 'cie_va': hex(frame['cie']),
                        'index': entry['index'], 'body_sha256': body_hash})
    return records


def analyze(data):
    digest = authenticate(data)
    secs, index = unwind_index(data)
    image = Image(data, secs)
    functions = function_records(image, index)
    windows = [check_window(image, *spec) for spec in WINDOWS]
    branches = [branch(image, *spec) for spec in BRANCHES]
    edges = [edge(image, *spec) for spec in EDGES]
    literals = [literal(image, *spec) for spec in LITERAL_SPECS]
    keys = field_keys(image)
    tables = [relative_table(image, *spec) for spec in TABLES]
    action_table = action_dispatch(image)
    guard = materialization_guard(image)
    guard_max = int(guard['max_count_without_guard_call'], 16)
    guard_cases = [{'count': hex(n), 'takes_guard_call': guard_takes_call(image, n)}
                   for n in (0, 1, guard_max, guard_max + 1, 1 << guard['high_bits_shift'], (1 << 64) - 1)]
    diagnostics = [duplicate_literal(image, 'map_duplicate', 0x263f8a7, 0x263f8b5),
                   duplicate_literal(image, 'sequence_duplicate', 0x26649f9, 0x2664a07)]
    # Indirect unit visitor and the row-reader's diagnostic descriptor each
    # have one R_X86_64_RELATIVE relocation in the captured ELF.
    indirect = image.read(0x1968946, 6, True)
    if indirect[:2] != b'\xff\x15':
        raise ValueError('changed indirect call opcode')
    indirect_slot = 0x1968946 + 6 + struct.unpack('<i', indirect[2:])[0]
    if indirect_slot != 0x5772638:
        raise ValueError('changed indirect call slot')
    if rip_target(image, 0x17c3936, '488d15') != 0x56880a8:
        raise ValueError('changed row diagnostic descriptor reference')
    relocations = [relative_relocation(image, indirect_slot, 0x2ea2950, 'unit_visitor'),
                   relative_relocation(image, 0x56880a8, 0x3b3719, 'row_descriptor')]
    descriptor_length = struct.unpack('<Q', image.read(0x56880b0, 8))[0]
    descriptor = image.read(0x3b3719, descriptor_length)
    if descriptor != b'struct UniqueKeyState with 3 elements':
        raise ValueError('changed row descriptor text')
    file_map = {row['label']: row['ascii'] for row in literals}
    if [row['ascii'] for row in keys] != [file_map['tracker_name'], file_map['tracker_hsc'], file_map['tracker_i']]:
        raise ValueError('writer literals differ from reader key comparisons')
    for field in ('arq', 'qst', 'vts'):
        if file_map['row_writer_' + field] != file_map['row_reader_' + field + '_diagnostic']:
            raise ValueError('row writer and diagnostic names differ')
    return {'schema': 'node94-vtg-messagepack-static-v1',
            'target': 'artifacts/node/94/hl-node', 'sha256': digest,
            'coordinate_system': 'linked ELF virtual addresses; FDE ends exclusive',
            'claim_scope': 'selected bytes and bounded static branches; not target execution',
            'functions': functions, 'windows': windows, 'branches': branches, 'edges': edges,
            'literals': literals, 'field_classifier': keys, 'relative_tables': tables,
            'action_dispatch': action_table, 'materialization_guard': guard, 'guard_cases': guard_cases,
            'indirect_call': {'va': hex(0x1968946), 'bytes': indirect.hex(), 'slot_va': hex(indirect_slot)},
            'row_descriptor': {'reference_va': hex(0x17c3936), 'reference_bytes': image.read(0x17c3936, 7, True).hex(),
                               'slot_va': hex(0x56880a8), 'length': descriptor_length,
                               'text': descriptor.decode('ascii')},
            'relocations': relocations, 'duplicate_diagnostics': diagnostics}


def tsv(rows, columns):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row[column] for column in columns])
    return out.getvalue().encode('utf-8')


def generate(data, out):
    result = analyze(data)
    files = {
        'records.json': (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('utf-8'),
        'functions.tsv': tsv(result['functions'], ['label', 'start_va', 'end_va_exclusive', 'size', 'section',
                                                   'file_offset', 'fde_va', 'cie_va', 'index', 'body_sha256']),
        'edges.tsv': tsv(result['edges'], ['label', 'va', 'file_offset', 'section', 'bytes', 'target_va',
                                           'kind', 'category']),
        'branches.tsv': tsv(result['branches'], ['label', 'va', 'file_offset', 'section', 'bytes', 'target_va']),
        'materialize-guard.tsv': tsv(result['guard_cases'], ['count', 'takes_guard_call']),
        'action-dispatch.tsv': tsv(result['action_dispatch']['entries'], ['index', 'example_discriminant',
                                                    'entry_va', 'file_offset', 'section', 'bytes', 'target_va',
                                                    'is_fallback_slot']),
    }
    out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (out / name).write_bytes(files[name])
    return {name: hashlib.sha256(content).hexdigest() for name, content in sorted(files.items())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    hashes = generate(TARGET.read_bytes(), args.out)
    print(json.dumps(hashes, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print(f'vote_tracker_state: {error}', file=sys.stderr)
        raise SystemExit(1)
