#!/usr/bin/env python3
"""Reproduce selected node-94 config-gated storage-read evidence from ELF bytes.

This collector never executes the captured program. It admits only the explicitly
selected x86 byte patterns and does not perform general disassembly.
"""
import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
TARGET = ROOT / 'artifacts/node/94/hl-node'

# FDE ends are half-open unwind extents, not independently established function
# boundaries. The body hashes make a changed selected byte a hard failure even
# when a caller supplies bytes without using the complete-artifact authenticator.
BODIES = (
    ('object_wrapper', 0x1b2c750, 0x1b2c865, '107f61c7313bd599590c1f4fe875494971268d946f783024989399214e31134f'),
    ('object_reader', 0x1c35e70, 0x1c36d90, '116fd38097cf07b19ac850c80121bfc321bca9e5d3b84e2d182740affc78a5f4'),
    ('id_writer', 0x1e6ad10, 0x1e6adc8, '3219d3470fed094bbcdc5055d25f072ef90b52b80057a254d45d4b3b4b088678'),
    ('request_callback', 0x1f704b0, 0x1f70c57, '951bb69d7ba606a164c738290bfdbaf612faf9f7df5a1f66d5b7b94ec37b2137'),
    ('callback_adapter', 0x1f9b4b0, 0x1f9b543, '3b4bb2a07a50fae3c1d4864d98a777b6f77ee624ef27d1c1fbdefb68144233de'),
    ('response_builder', 0x24c94f0, 0x24c9fdd, '8c5bfa016bfe5d311c9bd8cd0eba40863af732de20db31b6d244d4feaa679929'),
    ('nullable_block_reader', 0x251f4a0, 0x251f601, 'd8d6d73c15951de35045032a838533dbb80b92cd8e38e938d5e2cb981d63a8e4'),
    ('storage_query', 0x27b6080, 0x27b6539, '2e620d65058b3b92ee9e14172aeed174c2ed26f2478d3be775934a338756e12b'),
    ('missing_index_error', 0x27e3910, 0x27e3956, 'b7cfddc844ac1799ff378cc34f7be51d47288b0b44368ef3d6610af8d0ae7955'),
    ('index_reader', 0x27e3960, 0x27e3b02, 'f33fc96e3a4a68eadd5210fb2e28bbb49d85759b89d8d1a90a1ebe7b88b62cdb'),
    ('hex_writer', 0x2806800, 0x28068ef, 'd406a4e89ea75112e4be6d1e6c83bd242d9f425f1c6e3df6c66f6baaa08db5aa'),
    ('response_writer', 0x2976bd0, 0x2976db9, '537272c121a982235b8fca317a261b98129ca28d2cd009a77a3bd6fde64b6e0d'),
    ('error_writer', 0x2979660, 0x29798e8, '9b29f78d894e1d481c59c1780ce97cc705688bd85b2450560b5d526de17caee6'),
)
WITNESSES = (
    ('route_literal_site', 0x27ab959, '488d15f07fa5fd'),
    ('route_literal_length', 0x27ab968, 'b910000000'),
    ('route_constructor_call', 0x27ab96d, 'e8ae1b7cff'),
    ('constructor_vtable_site', 0x1f6d588, '488d0541437203'),
    ('callback_object_lead', 0x1f704ea, '48b901000000000000804939cc0f94c24885c0400f94c64008d674154939cc0f85f600000031c0b901000000e90501000041807d007b0f85df0000'),
    ('callback_object_call', 0x1f70551, '488dbc2480000000488db42430010000e8eac1bbff80bc2480000000020f85b1030000'),
    ('callback_positionals', 0x1f70630, '488d7c2410488db42420010000e87e7fefff488b6c24104883fd030f85a9030000'),
    ('callback_input_handoff', 0x1f70741, '4883c310488dbc2480000000488d942460010000488d8c24800100004c8d8424300100004889dee813598400488bac2480'),
    ('callback_query_result_tag', 0x1f7076d, '488bac24800000004883fd037533488d'),
    ('callback_output_handoff', 0x1f70880, '488dbc2480000000488d742410488d9424b0010000488b8c2478010000e84e8c5500'),
    ('wrapper_depth_seed', 0x1b2c78d, 'c644245080'),
    ('wrapper_parse_call', 0x1b2c792, '488d742408e8d4961000'),
    ('wrapper_trailing_mask', 0x1b2c7bb, '48be0026000001000000'),
    ('wrapper_trailing_error', 0x1b2c816, '48c744245816000000488d7c2408488d742458e85213000048894308c60302488b74'),
    ('object_initial_state', 0x1c35f31, 'b201c644240e03c684249000000002c744241000000000'),
    ('key_length_dispatch', 0x1c36047, '488b4424284883f8050f84b20000004883f80874444883f8070f85c2000000'),
    ('key_address_compare', 0x1c36066, '418b450033059a987bfe418b4d03330d93987bfe09c10f8407020000'),
    ('key_blockid_compare', 0x1c36082, '418b4500330585987bfe418b4d03330d7e987bfe09c10f858a000000eb0d'),
    ('key_block_id_compare', 0x1c360a0, '498b4500483b05ad505dfe757b807c240e030f85a30b0000'),
    ('key_index_compare', 0x1c36108, '418b450033052c907bfe410fb64d04320d25907bfe0fb6c909c10f8407010000'),
    ('unknown_key_skip', 0x1c36193, '498946284c89f7e8c17befff4885c00f852a050000'),
    ('block_value_handoff', 0x1c361d3, '498946284c89ef4c89f6e8be928e000fb64424188844240e3c030f8434030000'),
    ('index_value_handoff', 0x1c362f7, '498946284c89ef4c89f6e85ad6ba000fb6442418888424900000003c020f840d020000'),
    ('address_value_handoff', 0x1c36369, '498946284c89ef4c89f6e8380dbd00807c2418010f84a4010000'),
    ('missing_required_paths', 0x1c364dc, 'f6442410010f84fe0500000fb694249000000080fa020f85a9000000488d356e1c78fe488d7c2418ba05000000e802d4ba000fb654241880fa02440fb664240e0fb66c240f0f8504010000'),
    ('missing_block_default', 0x1c365ea, '4180fc03757641b402e9a4'),
    ('duplicate_names_a', 0x1c36c5b, '488d05f6445dfe488944245048c744245808000000'),
    ('duplicate_names_b', 0x1c36c8a, '488d05dc1478fe488944245048c744245805000000eb15488d05e20d78fe488944245048c744245807000000'),
    ('nullable_null_checks', 0x251f50c, '4183f96e75734883f8030f84d8000000488d78fd48897e284839cf0f83a1000000488d78fe440fb64402fd48897e284180f8750f85a40000004839cf0f8380000000488d78ff440fb64402fe48897e284180f86c0f85830000004839cf73630fb64c02ff4889462880f96c7570c60302'),
    ('nullable_fallback', 0x251f585, '488d7c2408e811de3600807c2408027515488b44241048894308'),
    ('index_variant_failure', 0x27e3aa3, '488d3d7effc0fdbe3e000000e83c6f6dff48894308c60302'),
    ('index_two_attempts', 0x27e3972, '0fb604243c167511488b44240848894308c60302e93a0100008b4c24018b5424048954242c894c2429488b4c24080f104424100f114424388844242848894c24304889e7488d742428e8d0609bff'),
    ('missing_index_result', 0x27e3941, 'e89a756dff48894308c60302'),
    ('query_lock_setup', 0x27b60c1, '4d8db42478050000498b84247805000089c183e108c1e9034883f8f00f93c208ca74124c89f731f6b900ca9a3bff15f494fb02eb0b488d4810f0490fb10e75e3'),
    ('query_account_check', 0x27b61cb, '418b45108944244066410f104500660f29442430488d7c2478488d542430e8c2ad010148837c2478000f84fb000000490fcf480fcd'),
    ('query_storage_check', 0x27b6244, '488d7c2430488d5424784c89e6e87aaf0101660fefe4837c243001660f57c00fb65c240f488b7c24108b6c241c756cf30f6f442438f30f6f4c'),
    ('query_success_shuffle', 0x27b6273, 'f30f6f442438f30f6f4c2448660f57d2660f6fd9660f60da660f70db4ef20f70db1bf30f70db1b660f68ca660f70c94ef20f70c91bf30f70e11b660f67e3660f6fc8660f60ca660f70c94ef20f70c91bf30f70c91b660f68c2660f70c04ef20f70c01bf30f70c01b660f67c1'),
    ('query_missing_account_zero', 0x27b62f5, '660f57c0660f29442420660f298424d0000000'),
    ('query_unlock', 0x27b631b, '48c7c0f0fffffff0480fc1074883e0f24883f8124c8bbc24c80000000f840701'),
    ('query_config_gate', 0x27b63dc, '660f2e05d446a5fd0f28442420762b488b1d3685fb028b435085c075560fb6434883f81f7714b900603c800fa3c1730a8b058647fc0285c07579410f1147080f288424d0000000410f11471849c70703000000'),
    ('query_publish_32', 0x27b6416, '410f1147080f288424d0000000410f11471849c70703000000'),
    ('query_config_slow', 0x27b644f, '48895c24304c89742478488d7b50488d0dac4dec024c8d05cd4dec02488d542478be01000000ff153d84fb020f284424200fb6434883f81f0f8675ffffffeb87'),
    ('query_build_slow', 0x27b648f, '488d05ea46fc0248894424304c89742478488d3df146fc02488d0dba3aeb024c8d059b3aeb02488d542478be01000000ff15f383fb020f28442420e947ffffff'),
    ('query_unwind_release', 0x27b6500, '48c7c1f0ffffff488b542410f0480fc10a4889c34883e1f24883f9127408'),
    ('response_unwind_buffer', 0x24c9f51, '4989c7488b7424584885f6740d488b7c246031d2ff15a5402a03'),
    ('reply_allocation', 0x24c9515, 'bf80000000ff15b84a2a034885c00f84d707000048895c247048c744245880000000488944246048c7'),
    ('reply_result_or_error', 0x24c9545, '837d10037565c7442448'),
    ('reply_writer_call', 0x24c964c, '488dbc2400010000488d742478e872d54a004989c54885c00f84f6000000'),
    ('reply_allocation_failure', 0x24c9d00, 'bf01000000be80000000ff15a8422a03e9be000000'),
    ('result_writer_tag_branch', 0x2976cd7, '41833e037560488d353ff3'),
    ('result_writer_call', 0x2976d6e, '4983c6094c89f74889dee883fae8ff4885c00f85'),
    ('error_writer_table', 0x2979745, '4489f8488d0d4dc6a7fd486304814801c8ffe0'),
    ('error_writer_code_arms', 0x2979758, 'bd4480ffffeb28bda780ffffeb21bdf982ffffeb1abda880ffffeb13bda580ffffeb0cbdf782ffffeb05bda680ffff'),
    ('hex_prefix', 0x2806821, '66c74424063078'),
    ('hex_scalar_alphabet', 0x2806843, '488d0dd61da0fd'),
    ('hex_scalar_loop', 0x2806850, '0fb65407ff89d683e60f0fb6340ec1ea040fb6140a8854440640887444070fb6140789d683e60f0fb6340ec1ea040fb6140a8854440840887444094883c0024883f82175bbeb22'),
    ('hex_simd_boundary', 0x28068aa, '488d542408be20000000e8b73076ff'),
    ('hex_output_length', 0x28068b9, '488d7308488d542406b9420000004889dfe821e60b004885c075'),
    ('id_null', 0x1e6ad69, '488d35e4f039feba040000004889dfe8831f7400'),
)

# These are selected, manually reviewed sites, not a census of instructions.
# The first route edge is prior-work context; its containing FDE is not selected.
TRANSFERS = (
    ('route_to_constructor', 0x27ab96d, 0x1f6d520),
    ('adapter_to_callback', 0x1f9b500, 0x1f704b0),
    ('callback_object_parse', 0x1f70561, 0x1b2c750),
    ('object_wrapper_to_reader', 0x1b2c797, 0x1c35e70),
    ('object_block_value', 0x1c361dd, 0x251f4a0),
    ('object_index_value', 0x1c36301, 0x27e3960),
    ('object_address_value_boundary', 0x1c36373, 0x28070b0),
    ('object_unknown_value_boundary', 0x1c3619a, 0x1b2dd60),
    ('object_missing_index', 0x1c36509, 0x27e3910),
    ('missing_index_error_boundary', 0x27e3941, 0x1ebaee0),
    ('nullable_other_value_boundary', 0x251f58a, 0x288d3a0),
    ('index_input_reader_boundary', 0x27e396d, 0x1b54e50),
    ('index_first_conversion_boundary', 0x27e39bb, 0x2199a90),
    ('index_second_conversion_boundary', 0x27e3a39, 0x21997d0),
    ('index_diagnostic_boundary', 0x27e3aaf, 0x1eba9f0),
    ('callback_positional_boundary', 0x1f7063d, 0x1e685c0),
    ('callback_to_query', 0x1f70768, 0x27b6080),
    ('query_account_lookup_boundary', 0x27b61e9, 0x37d0fb0),
    ('query_storage_lookup_boundary', 0x27b6251, 0x37d11d0),
    ('callback_to_response', 0x1f7089d, 0x24c94f0),
    ('response_to_writer', 0x24c9659, 0x2976bd0),
    ('writer_id', 0x2976cc5, 0x1e6ad10),
    ('writer_error', 0x2976d45, 0x2979660),
    ('writer_hex_result', 0x2976d78, 0x2806800),
    ('hex_vector_boundary', 0x28068b4, 0x1f69970),
    ('callback_non_object', 0x1f70520, 0x1f70605),
    ('callback_object_ok', 0x1f7056e, 0x1f70925),
    ('callback_positional_first_error', 0x1f7064b, 0x1f709fa),
    ('callback_positional_second_error', 0x1f70684, 0x1f70a59),
    ('callback_query_nonstandard_tag', 0x1f70779, 0x1f707ae),
    ('wrapper_parser_error', 0x1b2c79f, 0x1b2c7f6),
    ('wrapper_trailing_nonspace', 0x1b2c7d9, 0x1b2c816),
    ('object_array_entry', 0x1c35ef3, 0x1c363d5),
    ('object_wrong_entry', 0x1c35efc, 0x1c36bd3),
    ('key_len_five', 0x1c36050, 0x1c36108),
    ('key_len_eight', 0x1c3605a, 0x1c360a0),
    ('key_wrong_length', 0x1c36060, 0x1c36128),
    ('address_match', 0x1c3607c, 0x1c36289),
    ('block_camel_miss', 0x1c36098, 0x1c36128),
    ('block_snake_miss', 0x1c360ab, 0x1c36128),
    ('block_duplicate', 0x1c360b2, 0x1c36c5b),
    ('index_match', 0x1c36122, 0x1c3622f),
    ('unknown_value_error', 0x1c361a2, 0x1c366d2),
    ('block_missing_colon', 0x1c361c4, 0x1c36c48),
    ('block_value_error', 0x1c361ed, 0x1c36527),
    ('index_duplicate', 0x1c36237, 0x1c36c8a),
    ('address_duplicate', 0x1c3628e, 0x1c36ca1),
    ('index_value_error', 0x1c36314, 0x1c36527),
    ('address_value_error', 0x1c3637d, 0x1c36527),
    ('address_missing', 0x1c364e1, 0x1c36ae5),
    ('index_present', 0x1c364f2, 0x1c365a1),
    ('missing_index_result_branch', 0x1c36521, 0x1c3662b),
    ('nullable_not_n', 0x251f510, 0x251f585),
    ('nullable_bad_u', 0x251f53f, 0x251f5e9),
    ('nullable_bad_l1', 0x251f560, 0x251f5e9),
    ('nullable_bad_l2', 0x251f577, 0x251f5e9),
    ('nullable_truncated', 0x251f527, 0x251f5ce),
    ('index_first_parser_value', 0x27e3978, 0x27e398b),
    ('index_first_conversion_ok', 0x27e39c4, 0x27e39f0),
    ('index_second_conversion_ok', 0x27e3a47, 0x27e3a6e),
    ('query_lock_fast', 0x27b60e2, 0x27b60f6),
    ('query_lock_contended', 0x27b60ff, 0x27b60e4),
    ('query_account_missing', 0x27b61f4, 0x27b62f5),
    ('query_slot_not_tag_one', 0x27b6271, 0x27b62df),
    ('query_value_join', 0x27b62f3, 0x27b631b),
    ('query_unlock_contended', 0x27b6337, 0x27b6444),
    ('query_unlock_resume', 0x27b644a, 0x27b633d),
    ('query_unwind_needs_wake', 0x27b651c, 0x27b6526),
    ('query_unwind_resume', 0x27b6521, 0x5660110),
    ('config_float_le_or_unordered', 0x27b63e9, 0x27b6416),
    ('config_cell_slow', 0x27b63f7, 0x27b644f),
    ('config_name_above_bound', 0x27b6400, 0x27b6416),
    ('config_mask_clear', 0x27b640a, 0x27b6416),
    ('config_build_cell_slow', 0x27b6414, 0x27b648f),
    ('config_slow_name_in_range', 0x27b6487, 0x27b6402),
    ('config_slow_name_out_of_range', 0x27b648d, 0x27b6416),
    ('config_build_slow_join', 0x27b64ca, 0x27b6416),
    ('response_alloc_failure', 0x24c9523, 0x24c9d00),
    ('response_error_variant', 0x24c9549, 0x24c95b0),
    ('response_write_ok', 0x24c9664, 0x24c9760),
    ('response_unwind_empty_buffer', 0x24c9f5c, 0x24c9f6b),
    ('response_unwind_cleanup_boundary', 0x24c9f73, 0x24ffba0),
    ('response_unwind_resume', 0x24c9fd2, 0x5660110),
    ('writer_no_version_field', 0x2976c09, 0x2976c7f),
    ('writer_error_variant', 0x2976cdb, 0x2976d3d),
    ('writer_inline_result', 0x2976d35, 0x2976d6e),
    ('writer_error_output_failure', 0x2976d4d, 0x2976ccf),
    ('writer_value_output_failure', 0x2976d80, 0x2976ccf),
    ('hex_feature_uninitialized', 0x2806835, 0x2806897),
    ('hex_vector_select', 0x280683c, 0x28068aa),
    ('hex_scalar_loop', 0x2806893, 0x2806850),
    ('hex_writer_failure', 0x28068d2, 0x28068de),
    ('error_writer_bad_state', 0x2979671, 0x29798af),
    ('error_writer_no_data', 0x297981f, 0x2979885),
)

# Only the stated encodings are admitted. RIP displacement always follows the
# fixed prefix; no scan or external disassembler is used for these records.
RIP_REFERENCES = (
    ('route_method', 0x27ab959, '488d15', 0x203950),
    ('constructor_callback_vtable', 0x1f6d588, '488d05', 0x56918d0),
    ('address_prefix', 0x1c3606a, '3305', 0x3ef90a),
    ('address_suffix', 0x1c36074, '330d', 0x3ef90d),
    ('block_camel_prefix', 0x1c36086, '3305', 0x3ef911),
    ('block_camel_suffix', 0x1c36090, '330d', 0x3ef914),
    ('block_snake', 0x1c360a4, '483b05', 0x20b158),
    ('index_prefix', 0x1c3610c, '3305', 0x3ef13e),
    ('index_suffix', 0x1c36117, '320d', 0x3ef142),
    ('index_diagnostic', 0x27e3aa3, '488d3d', 0x3f3a28),
    ('query_threshold', 0x27b63dc, '660f2e05', 0x20aab8),
    ('query_config_slot', 0x27b63eb, '488b1d', 0x576e928),
    ('query_build_once_state', 0x27b640c, '8b05', 0x577ab98),
    ('query_build_once_cell', 0x27b648f, '488d05', 0x577ab80),
    ('query_build_once_state_arg', 0x27b64a0, '488d3d', 0x577ab98),
    ('query_build_once_call_slot', 0x27b64bf, 'ff15', 0x576e8b8),
    ('result_hex_alphabet', 0x2806843, '488d0d', 0x208620),
    ('response_jsonrpc_field', 0x2976c0b, '488d15', 0x3f6e69),
    ('response_jsonrpc_version', 0x2976c45, '488d15', 0x3c274b),
    ('response_id_field', 0x2976c84, '488d15', 0x3f6254),
    ('response_result_field', 0x2976cfa, '488d15', 0x3f6e70),
    ('error_code_table', 0x2979748, '488d0d', 0x3f5d9c),
    ('error_field', 0x29796a9, '488d15', 0x3f6e76),
    ('error_code_field', 0x297970b, '488d15', 0x209d84),
    ('error_message_field', 0x29797ca, '488d15', 0x3f652c),
    ('error_data_field', 0x297983e, '488d15', 0x20a08c),
    ('id_null_literal', 0x1e6ad69, '488d35', 0x209e54),
    ('missing_address_name', 0x1c36ae5, '488d05', 0x3b7a8a),
    ('missing_address_format', 0x1c36b10, '488d3d', 0x1df8f3),
    ('missing_index_name', 0x1c364f8, '488d35', 0x3b816d),
    ('missing_index_format', 0x27e3935, '488d3d', 0x1df8f3),
    ('duplicate_block_name', 0x1c36c5b, '488d05', 0x20b158),
    ('duplicate_index_name', 0x1c36c8a, '488d05', 0x3b816d),
    ('duplicate_address_name', 0x1c36ca1, '488d05', 0x3b7a8a),
    ('duplicate_field_format', 0x1c36ccc, '488d3d', 0x1e0fd5),
)

RELOCATIONS = {
    0x56918d0: 0x1f9b760,
    0x56918e8: 0x1f9b4b0,
    0x56918f0: 0x1f704b0,
    0x56918f8: 0x1f704b0,
    0x576e928: 0x577b288,
    0x577b288: 0x164ff00,
    0x577ab80: 0x143ef30,
    0x576e8b8: 0x4ee3b20,
    0x5770950: 0x2a484d0,
    **{0x5668288 + 16 * i: p for i, p in (
        (13, 0x21806b), (14, 0x218077), (18, 0x218089),
        (19, 0x218094), (20, 0x21809f), (21, 0x2180ac),
        (31, 0x2180f4), (32, 0x2180ff),
    )},
}


class EvidenceError(ValueError):
    """A required identity, file mapping, operand or target is inconsistent."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def authenticate(data):
    require(len(data) == SIZE, 'target size mismatch')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'target SHA-256 mismatch')


def map_span(data, secs, va, size):
    """Return a unique file-backed section and offset for a nonempty VA span."""
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
            'invalid address or span')
    found = [s for s in secs if s['type'] != 8 and s['size'] > 0
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(found) == 1, 'span lacks a unique file-backed section')
    sec = found[0]
    off = sec['offset'] + va - sec['address']
    require(0 <= off and off + size <= len(data), 'span leaves file')
    return sec, off


def read_va(data, secs, va, size):
    sec, offset = map_span(data, secs, va, size)
    return bytes(data[offset:offset + size])


def exact_bytes(data, secs, va, expected):
    if isinstance(expected, str):
        expected = bytes.fromhex(expected)
    actual = read_va(data, secs, va, len(expected))
    require(actual == expected, f'byte mismatch at {va:#x}')
    return actual


def validate_body(raw, expected):
    require(hashlib.sha256(raw).hexdigest() == expected, 'selected body hash mismatch')


def decode_relative(raw, site):
    """Decode only E8/E9, EB, 70-7F and 0F80-0F8F with full operands."""
    require(len(raw) >= 2, 'truncated relative instruction')
    if raw[0] in (0xe8, 0xe9):
        require(len(raw) == 5, 'invalid rel32 length')
        name = 'call' if raw[0] == 0xe8 else 'jump'
        disp = struct.unpack_from('<i', raw, 1)[0]
    elif raw[0] == 0xeb:
        require(len(raw) == 2, 'invalid short jump length')
        name, disp = 'jump', struct.unpack_from('<b', raw, 1)[0]
    elif 0x70 <= raw[0] <= 0x7f:
        require(len(raw) == 2, 'invalid short condition length')
        name, disp = f'jcc-{raw[0] & 15:x}', struct.unpack_from('<b', raw, 1)[0]
    else:
        require(len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f,
                'unsupported relative opcode')
        name, disp = f'jcc-{raw[1] & 15:x}', struct.unpack_from('<i', raw, 2)[0]
    return name, site + len(raw) + disp


def transfer(data, secs, site, expected_target):
    first = read_va(data, secs, site, 2)
    if first[0] in (0xe8, 0xe9):
        length = 5
    elif first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
        length = 6
    elif first[0] == 0xeb or 0x70 <= first[0] <= 0x7f:
        length = 2
    else:
        raise EvidenceError(f'unsupported transfer at {site:#x}')
    raw = read_va(data, secs, site, length)
    kind, target = decode_relative(raw, site)
    require(target == expected_target, f'changed transfer target at {site:#x}')
    return kind, target, raw


def rip_reference(data, secs, site, prefix, expected):
    prefix = bytes.fromhex(prefix) if isinstance(prefix, str) else prefix
    raw = read_va(data, secs, site, len(prefix) + 4)
    require(raw.startswith(prefix), f'changed RIP opcode at {site:#x}')
    target = site + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]
    require(target == expected, f'changed RIP target at {site:#x}')
    return raw, target


def selected_relocations(data, sec, wanted):
    """Parse selected ELF64 RELA entries from a shared-reader section record."""
    require(sec['type'] == 4 and sec['type'] != 8 and sec['size'] % 24 == 0,
            'expected complete SHT_RELA entries')
    start, end = sec['offset'], sec['offset'] + sec['size']
    require(0 <= start <= end <= len(data), 'relocation section leaves file')
    result = {}
    for off in range(start, end, 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        require(slot not in result, f'duplicate relocation at {slot:#x}')
        require(info == 8, f'non-relative relocation at {slot:#x}')
        require(addend == wanted[slot], f'changed relocation addend at {slot:#x}')
        result[slot] = {'slot_va': hex(slot), 'type': 'R_X86_64_RELATIVE',
                        'addend_va': hex(addend), 'rela_file_offset': hex(off)}
    require(set(result) == set(wanted), 'missing selected relocation')
    return result


def select_fields(value, literals):
    """Abstract only the four byte/length comparisons established in the reader."""
    if value == literals['address']:
        return 'address'
    if value == literals['index']:
        return 'index'
    if value in (literals['blockId'], literals['block_id']):
        return 'block'
    return 'unknown'


def name_gate(name, elapsed_sum, bound, mask, threshold):
    """Model the local ordered comparison and unsigned name/bit predicates."""
    require(isinstance(name, int) and not isinstance(name, bool) and 0 <= name <= 255,
            'model expects a byte')
    return not math.isnan(elapsed_sum) and elapsed_sum > threshold and name <= bound and bool((mask >> name) & 1)


def nullable_model(value, whitespace_mask, letters):
    """Bounded model of the local null prefix, including cursor movement."""
    require(isinstance(value, bytes) and letters == b'null', 'invalid nullable model')
    pos = 0
    while pos < len(value) and value[pos] <= 32 and ((whitespace_mask >> value[pos]) & 1):
        pos += 1
    if pos == len(value) or value[pos] != letters[0]:
        return 'delegate', pos
    for expected in letters:
        if pos == len(value):
            return 'truncated', pos
        byte = value[pos]
        pos += 1
        if byte != expected:
            return 'bad-literal', pos
    return 'tag-2', pos


def scalar_hex(data, alphabet):
    """Model the selected scalar nibble loop only, not the vector helper."""
    require(len(data) == 32 and len(alphabet) == 16 and len(set(alphabet)) == 16,
            'invalid scalar model input')
    out = bytearray(b'0x')
    for value in data:
        out.extend((alphabet[value >> 4], alphabet[value & 15]))
    return bytes(out)


def shuffle_storage_word(raw):
    """Model only the observed unpack/shuffle/pack sequence on 32 input bytes."""
    require(len(raw) == 32, 'storage shuffle requires 32 bytes')
    def half(chunk):
        def lane(values):
            # pshufd 0x4e swaps pairs of pairs of 16-bit lanes; pshuflw/hw
            # 0x1b reverse the four lanes in each half. Unpacked lanes have
            # zero high bytes, so packuswb preserves each input byte.
            values = list(values)
            dwords = [values[i:i + 2] for i in range(0, 8, 2)]
            shuffled = sum((dwords[i] for i in (2, 3, 0, 1)), [])
            return shuffled[:4][::-1] + shuffled[4:][::-1]
        return bytes(lane(chunk[8:]) + lane(chunk[:8]))
    return half(raw[16:]) + half(raw[:16])


def table_error_rows(data, secs, base, end_va):
    """Read the explicitly selected eight words, plus the adjacent control."""
    rows = []
    for index in range(8):
        raw = read_va(data, secs, base + 4 * index, 4)
        target = base + struct.unpack('<i', raw)[0]
        require(0x2979660 <= target < end_va, 'selected error arm outside extent')
        if target == 0x2979787:
            code, code_bytes = 'inherited', ''
        else:
            body = read_va(data, secs, target, 5)
            require(body[0] == 0xbd, 'error arm is not mov ebp, imm32')
            code, code_bytes = str(struct.unpack('<i', body[1:])[0]), body.hex()
        rows.append((index, hex(base + 4 * index), raw.hex(), hex(target), code_bytes, code))
    adjacent_raw = read_va(data, secs, base + 32, 4)
    adjacent = base + struct.unpack('<i', adjacent_raw)[0]
    require(not 0x2979660 <= adjacent < end_va, 'adjacent control unexpectedly in error extent')
    return rows, {'slot_va': hex(base + 32), 'raw_le': adjacent_raw.hex(), 'target_va': hex(adjacent)}


def lsda_callsites(data, secs, fde, upper):
    """Read only the observed LSDA headers and ULEB call-site records.

    The next LSDA pointer bounds the read, but is not asserted to be this
    object's size. Action indexes are recorded without decoding action chains.
    Call-site and landing addresses are not independently decoded instructions.
    """
    address, begin, end = fde['lsda'], fde['start'], fde['end']
    require(address is not None and upper > address, 'invalid LSDA bound')
    sec, offset = map_span(data, secs, address, upper - address)
    require(sec['name'] == '.gcc_except_table', 'LSDA is outside exception section')
    raw = bytes(data[offset:offset + upper - address])
    require(len(raw) >= 4 and raw[0] == 0xff, 'unsupported LSDA landing base encoding')
    pos = 2
    if raw[1] == 0xff:
        type_base = len(raw)
    else:
        require(raw[1] == 0x9b, 'unsupported LSDA type encoding')
        distance, pos = uleb(raw, pos, len(raw))
        type_base = pos + distance
    require(pos < len(raw) and raw[pos] == 1, 'unsupported LSDA call-site encoding')
    pos += 1
    size, pos = uleb(raw, pos, len(raw))
    table_end = pos + size
    require(pos <= table_end <= type_base <= len(raw), 'LSDA table escapes its bound')
    header = raw[:pos]
    rows, previous = [], begin
    while pos < table_end:
        first = pos
        fields = []
        for _ in range(4):
            value, pos = uleb(raw, pos, table_end)
            fields.append(value)
        relative, length, pad, action = fields
        start, stop = begin + relative, begin + relative + length
        landing = begin + pad if pad else None
        require(begin <= start < stop <= end and start >= previous,
                'invalid or overlapping LSDA call-site range')
        require(landing is None or begin <= landing < end, 'LSDA landing outside FDE')
        rows.append((hex(address), hex(upper), header.hex(), hex(address + first),
                     hex(offset + first), raw[first:pos].hex(), hex(start), hex(stop),
                     '' if landing is None else hex(landing), action))
        previous = stop
    return rows


def text_tsv(header, rows):
    stream = io.StringIO(newline='')
    out = csv.writer(stream, delimiter='\t', lineterminator='\n')
    out.writerow(header)
    out.writerows(rows)
    return stream.getvalue().encode('utf-8')


def json_bytes(obj):
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('utf-8')


def collect(data):
    authenticate(data)
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    starts = {start for _, start, _, _ in BODIES}
    selected = [f for f in fdes if f['start'] in starts]
    require(len(selected) == len(BODIES), 'missing or duplicate selected FDE')
    by_start = {f['start']: f for f in selected}
    require(len(by_start) == len(BODIES), 'duplicate selected FDE start')

    bodies = []
    for role, start, end, digest in BODIES:
        fde = by_start[start]
        require(fde['end'] == end, f'changed FDE extent at {start:#x}')
        sec, offset = map_span(data, secs, start, end - start)
        require(sec['flags'] & 4, 'selected body is not executable')
        raw = read_va(data, secs, start, end - start)
        validate_body(raw, digest)
        bodies.append({'role': role, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                       'bytes': len(raw), 'file_offset': hex(offset), 'section': sec['name'],
                       'fde_va': hex(fde['fde']), 'cie_va': hex(fde['cie']),
                       'lsda_va': None if fde['lsda'] is None else hex(fde['lsda']),
                       'body_sha256': hashlib.sha256(raw).hexdigest(), 'body_hex': raw.hex()})

    witnesses = []
    for label, site, expected in WITNESSES:
        raw = exact_bytes(data, secs, site, expected)
        sec, offset = map_span(data, secs, site, len(raw))
        owner = next((role for role, start, end, _ in BODIES if start <= site and site + len(raw) <= end), None)
        witnesses.append((label, hex(site), hex(offset), sec['name'], owner or 'prior-work-context', raw.hex()))

    edges = []
    for label, site, expected_target in TRANSFERS:
        kind, target, raw = transfer(data, secs, site, expected_target)
        _, offset = map_span(data, secs, site, len(raw))
        edges.append((label, hex(site), hex(offset), raw.hex(), kind, hex(site + len(raw)), hex(target)))

    refs = []
    for label, site, prefix, expected in RIP_REFERENCES:
        raw, target = rip_reference(data, secs, site, prefix, expected)
        _, offset = map_span(data, secs, site, len(raw))
        refs.append((label, hex(site), hex(offset), raw.hex(), hex(target)))

    relsections = [s for s in secs if s['name'] == '.rela.dyn']
    require(len(relsections) == 1, 'missing or duplicate .rela.dyn')
    relocs = selected_relocations(data, relsections[0], RELOCATIONS)

    strings = {
        'address': (0x3ef90a, b'address'),
        'index': (0x3ef13e, b'index'),
        'blockId': (0x3ef911, b'blockId'),
        'block_id': (0x20b158, b'block_id'),
    }
    fields = []
    literals = {}
    compare_sites = {'address': '0x1c3606a,0x1c36074', 'index': '0x1c3610c,0x1c36117',
                     'blockId': '0x1c36086,0x1c36090', 'block_id': '0x1c360a4'}
    for name, (va, expected) in strings.items():
        raw = exact_bytes(data, secs, va, expected)
        literals[name] = raw
        fields.append((name, hex(va), len(raw), raw.hex(), compare_sites[name], select_fields(raw, {k: v[1] for k, v in strings.items()})))

    method = exact_bytes(data, secs, 0x203950, b'eth_getStorageAt')
    vtable_size, vtable_align = struct.unpack('<QQ', read_va(data, secs, 0x56918d8, 16))
    require((vtable_size, vtable_align) == (8, 8), 'changed callback vtable layout')
    initial_cell_word = struct.unpack('<I', read_va(data, secs, 0x577b2d8, 4))[0]
    require(initial_cell_word == 3, 'changed file-initial configuration cell word')
    initial_build_once_word = struct.unpack('<I', read_va(data, secs, 0x577ab98, 4))[0]
    require(initial_build_once_word == 3, 'changed file-initial build-mode cell word')
    templates = []
    for label, va, expected in (('static_config', 0x1ef5f5, b'\xc0\x0e/static_config\x00'),
                                ('cham', 0x1fc0ec, b'\xc0\x05/cham\x00')):
        raw = exact_bytes(data, secs, va, expected)
        _, off = map_span(data, secs, va, len(raw))
        templates.append({'label': label, 'va': hex(va), 'file_offset': hex(off), 'hex': raw.hex()})

    missing_fmt = exact_bytes(data, secs, 0x1df8f3, b'\x0fmissing field `\xc0\x01`\x00')
    duplicate_fmt = exact_bytes(data, secs, 0x1e0fd5, b'\x11duplicate field `\xc0\x01`\x00')
    exact_bytes(data, secs, 0x3b7a8a, b'address')
    exact_bytes(data, secs, 0x3b816d, b'index')

    writer_literals = []
    for label, va, value in (('jsonrpc', 0x3f6e69, b'jsonrpc'), ('version', 0x3c274b, b'2.0'), ('id', 0x3f6254, b'id'),
                             ('result', 0x3f6e70, b'result'), ('error', 0x3f6e76, b'error'),
                             ('code', 0x209d84, b'code'), ('message', 0x3f652c, b'message'),
                             ('data', 0x20a08c, b'data'), ('null', 0x209e54, b'null'),
                             ('index_error', 0x3f3a28, b'data did not match any variant of untagged enum JsonStorageKey')):
        raw = exact_bytes(data, secs, va, value)
        writer_literals.append({'label': label, 'va': hex(va), 'length': len(raw), 'hex': raw.hex()})

    alphabet = exact_bytes(data, secs, 0x208620, b'0123456789abcdef')
    require(exact_bytes(data, secs, 0x2806821, bytes.fromhex('66c74424063078'))[-2:] == b'0x',
            'changed hex prefix')
    require(exact_bytes(data, secs, 0x28068c2, bytes.fromhex('b942000000'))[1:] == b'\x42\0\0\0',
            'changed hex writer length')

    mask_instruction = exact_bytes(data, secs, 0x27b6402, bytes.fromhex('b900603c80'))
    mask = struct.unpack_from('<I', mask_instruction, 1)[0]
    cmp_instruction = exact_bytes(data, secs, 0x27b63fd, bytes.fromhex('83f81f'))
    bound = cmp_instruction[-1]
    raw_threshold = read_va(data, secs, 0x20aab8, 8)
    threshold = struct.unpack('<d', raw_threshold)[0]
    require(threshold == 3.0, 'changed floating threshold')
    descriptor_rows = []
    for i in (13, 14, 18, 19, 20, 21, 31, 32):
        slot = 0x5668288 + i * 16
        pointer = RELOCATIONS[slot]
        length = struct.unpack('<Q', read_va(data, secs, slot + 8, 8))[0]
        require(0 < length <= 32, 'invalid contextual name length')
        raw = read_va(data, secs, pointer, length)
        require(raw.isascii(), 'non-ASCII contextual descriptor')
        descriptor_rows.append((i, hex(slot), hex(pointer), length, raw.decode('ascii'),
                                int(name_gate(i, 4.0, bound, mask, threshold))))
    require(descriptor_rows[-1][4] == 'NvTestnet', 'contextual default name changed')

    whitespace_mask = struct.unpack_from('<Q', exact_bytes(data, secs, 0x251f4c7, bytes.fromhex('49b80026000001000000')), 2)[0]
    null_letters = bytes(read_va(data, secs, site, size)[-1] for site, size in ((0x251f50c, 4), (0x251f53b, 4), (0x251f55c, 4), (0x251f574, 3)))
    require(null_letters == b'null', 'changed null prefix comparisons')
    codes, adjacent = table_error_rows(data, secs, 0x3f5d9c, by_start[0x2979660]['end'])
    exception_sections = [sec for sec in secs if sec['name'] == '.gcc_except_table']
    require(len(exception_sections) == 1, 'missing or duplicate exception section')
    exception = exception_sections[0]
    exception_end = exception['address'] + exception['size']
    pointers = sorted({f['lsda'] for f in fdes if f['lsda'] is not None
                       and exception['address'] <= f['lsda'] < exception_end})
    unwind_rows = []
    for role, start, _, _ in BODIES:
        fde = by_start[start]
        if fde['lsda'] is None:
            continue
        following = next((p for p in pointers if p > fde['lsda']), exception_end)
        unwind_rows.extend((role, *row) for row in lsda_callsites(data, secs, fde, following))
    output = {
        'functions.json': json_bytes(bodies),
        'witnesses.tsv': text_tsv(('label', 'site_va', 'file_offset', 'section', 'selected_body_or_context', 'bytes_hex'), witnesses),
        'transfers.tsv': text_tsv(('label', 'site_va', 'file_offset', 'bytes_hex', 'kind', 'fallthrough_va', 'target_va'), edges),
        'references.tsv': text_tsv(('label', 'site_va', 'file_offset', 'bytes_hex', 'target_va'), refs),
        'fields.tsv': text_tsv(('literal', 'va', 'length', 'bytes_hex', 'comparison_sites', 'modeled_class'), fields),
        'name-context.tsv': text_tsv(('index', 'descriptor_va', 'literal_va', 'length', 'literal', 'gate_above_threshold'), descriptor_rows),
        'error-codes.tsv': text_tsv(('index', 'slot_va', 'relative_le', 'arm_va', 'arm_bytes_hex', 'signed_code_or_inherited'), codes),
        'unwind-callsites.tsv': text_tsv(('body_role', 'lsda_va', 'next_lsda_bound_va', 'header_hex',
                                          'entry_va', 'entry_file_offset', 'entry_hex', 'start_va',
                                          'end_va_exclusive', 'landing_va', 'raw_action_index'), unwind_rows),
        'relocations.json': json_bytes([relocs[k] for k in sorted(relocs)]),
        'data.json': json_bytes({'target_sha256': SHA256, 'target_size': len(data),
                                 'route_method_va': '0x203950', 'route_method_hex': method.hex(),
                                 'selected_writer_literals': writer_literals,
                                 'callback_vtable_size': vtable_size, 'callback_vtable_alignment': vtable_align,
                                 'configuration_cell_initial_file_word': initial_cell_word,
                                 'build_mode_cell_initial_file_word': initial_build_once_word,
                                 'selected_lsda_callsite_count': len(unwind_rows),
                                 'missing_field_template_hex': missing_fmt.hex(),
                                 'duplicate_field_template_hex': duplicate_fmt.hex(),
                                 'whitespace_mask_hex': hex(whitespace_mask),
                                 'nullable_compared_bytes_hex': null_letters.hex(),
                                 'prior_template_context': templates,
                                 'name_gate_bound': bound, 'name_gate_mask_hex': hex(mask),
                                 'threshold_va': '0x20aab8', 'threshold_bytes_le': raw_threshold.hex(),
                                 'threshold_value': threshold, 'hex_alphabet_va': '0x208620',
                                 'hex_alphabet': alphabet.decode('ascii'),
                                 'selected_error_table_base_va': '0x3f5d9c',
                                 'adjacent_table_word_control': adjacent,
                                 'limitations': 'Selected byte-backed static observations and synthetic local models; not target execution or a complete call graph.'}),
    }
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    result = collect(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(result):
        (args.out / name).write_bytes(result[name])
    print(f'Generated {len(result)} deterministic evidence files.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (EvidenceError, OSError, ValueError, struct.error) as exc:
        print(f'config_storage_read94: {exc}', file=sys.stderr)
        raise SystemExit(1)
