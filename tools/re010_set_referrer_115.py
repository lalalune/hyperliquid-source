"""Recover selected node-115 referral decode and mutation evidence without execution."""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

# The shared modules live beside this script both when run and when imported by tests.
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = TOOLS_DIR.parent
BINARY = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# The first-call handlers and shared routers are contextual cross-checks only.
# The selected FDEs below are the newly investigated bodies, with raw hashes.
FUNCTIONS = (
    ('outer_action_decoder', 0x3a01c70, 0x3a02f72, '47e6c39f2fb987fa157d80c5f3d86f3d66ec75e7bd3e1560b806b5fa72a2c6d4'),
    ('multi_party_envelope', 0x3a1f060, 0x3a200b6, '372648054257432ef6a3b41d84ddbdef15824a7fd51f0edb54642e323417183d'),
    ('boxed_decoder', 0x3b92540, 0x3b925ea, '0c6e20639d709facf50fb865efa27604da7226d39081bf2247ccea437f5c43d4'),
    ('action_decoder', 0x36b8c90, 0x36baeec, '8fd99fe26161fda2f0adca9ae67d510dbd0b43c5fd227ee0a570e573804e77e9'),
    ('action_envelope', 0x3960480, 0x39618bb, 'bf9512e2c89f515a68e46a32241b32352430496358ffc4349e0e05fed089ca23'),
    ('name_input_adapter', 0x3b68540, 0x3b68655, '2c928c3302d61c4a556c4c9e99fbe2b4cafc783e9f1fc9d636310ef97b9420c1'),
    ('referrer_payload_decoder', 0x39ef520, 0x39efd0d, 'a953b117098915f1eebc67d13136e12f5d96a60c5bf4997e024f78986085afef'),
    ('referrer_state_core', 0x3c17590, 0x3c17fb9, '0f8f19e89488c46ca8c968c2fc38722a6be424b50c3fe055c71e83d9ffdcf428'),
    ('compact_code_search', 0x455c290, 0x455c503, '6e52885f4f8fe23cdf3b255497eeaf5a83c880dba8438dcddf1746e62c6b661d'),
    ('compact_profile_search', 0x4556550, 0x4556717, 'c3ac0d0c96983bd3d5c218105eac47d55766337961e50d3957dbc124f5c4a797'),
    ('compact_history_search', 0x455a260, 0x455a42b, '604e67936f949b580c8306d540e061e99db0414895e6fb6caf55e3011d9ed271'),
    ('compact_history_insert', 0x4546480, 0x454657e, '5af968c785af53dc3b6d21880c0f77f695a30330014f75b25993dbffaf928fe0'),
    ('compact_history_shift', 0x456d220, 0x456d493, '4ac738e19f384356a781f31491ac96a4765c12bb135cbdc3101e9d8aa520fa9b'),
    ('tree_history_insert', 0x3705790, 0x37058d0, 'c4cfe6259485c9d5de8052901d7b7851a433738c0f3ca3a1739d874015af2192'),
    ('status_cleanup', 0x3d08df0, 0x3d0913a, 'c28adef5bcca72c59454a27e693d942fc962955ac9719ec2b4e8443118ee89e7'),
)

# Manually selected instruction-aligned raw windows; no disassembler text is read.
# End addresses are exclusive. The first group is already-known dispatch context.
WINDOWS = (
    ('context_serializer_switch', 0x2bce575, 0x2bce59a),
    ('context_serializer_name', 0x2bd08d6, 0x2bd08eb),
    ('context_direct_switch', 0x2bda82a, 0x2bda84c),
    ('context_nested_switch', 0x2bdbb0c, 0x2bdbb2f),
    ('context_direct_arm', 0x2bdb019, 0x2bdb02e),
    ('context_nested_arm', 0x2bdc781, 0x2bdc7ae),
    ('context_outer_direct_arm', 0x2bdb07a, 0x2bdb08f),
    ('context_outer_handler_entry', 0x2c126a1, 0x2c126ad),
    ('context_outer_handler_gates', 0x2c12944, 0x2c129fc),
    ('context_nested_load_action', 0x2bdbab1, 0x2bdbac2),
    ('context_wrapper_limit', 0x23853ca, 0x23853eb),
    ('context_wrapper_handoff', 0x23853eb, 0x2385417),
    ('context_direct_length', 0x2c1b63a, 0x2c1b657),
    ('context_direct_identity_reject', 0x2c1b57a, 0x2c1b58d),
    ('context_direct_gate_calls', 0x2c1b5a5, 0x2c1b607),
    ('context_direct_handoff', 0x2c1b6f7, 0x2c1b729),
    ('context_direct_error_tag', 0x2c1b775, 0x2c1b77d),
    ('context_nested_error_tag', 0x2385452, 0x2385459),
    ('context_name_matcher_length', 0x36616b5, 0x36616d6),
    ('context_name_matcher_comparisons', 0x3661efc, 0x3661f6f),
    ('context_name_matcher_ordinal', 0x36626a9, 0x36626af),
    ('context_name_matcher_success', 0x3662725, 0x366272f),
    ('context_name_matcher_unknown', 0x36624f2, 0x3662520),
    ('outer_input_kinds', 0x3a1f071, 0x3a1f095),
    ('outer_action_key_match', 0x3a1f43c, 0x3a1f46e),
    ('outer_select_field', 0x3a1f4eb, 0x3a1f504),
    ('outer_action_map_value', 0x3a1f630, 0x3a1f6d0),
    ('outer_action_sequence_value', 0x3a1fa38, 0x3a1faaf),
    ('outer_boxed_action_result', 0x3a1faf5, 0x3a1fb0a),
    ('outer_missing_action', 0x3a1fcce, 0x3a1fd24),
    ('outer_duplicate_action', 0x3a1fd56, 0x3a1fdb8),
    ('outer_variant_sequence_call', 0x3a029ba, 0x3a029dd),
    ('outer_variant_payload_key', 0x3a02093, 0x3a020bd),
    ('outer_variant_payload_select', 0x3a02117, 0x3a02132),
    ('outer_variant_map_call', 0x3a02280, 0x3a022ef),
    ('outer_variant_store_action', 0x3a02a1e, 0x3a02a4c),
    ('decoder_outer_variant', 0x36baa77, 0x36baaf6),
    ('name_adapter_switch', 0x3b68548, 0x3b68569),
    ('name_adapter_borrowed', 0x3b6856f, 0x3b6857e),
    ('name_adapter_owned', 0x3b685bf, 0x3b685eb),
    ('envelope_match_and_save', 0x3960c05, 0x3960c75),
    ('envelope_ordinal_output', 0x3960fa1, 0x3961001),
    ('decoder_ordinal_switch', 0x36b8ce3, 0x36b8d33),
    ('decoder_referrer_arm', 0x36ba91b, 0x36ba96a),
    ('decoder_result_tail', 0x36bada0, 0x36badbd),
    ('payload_input_kinds', 0x39ef531, 0x39ef54c),
    ('payload_missing_field', 0x39ef589, 0x39ef61f),
    ('payload_sequence_empty', 0x39ef644, 0x39ef6b3),
    ('payload_sequence_value', 0x39ef6dd, 0x39ef72f),
    ('payload_map_key_switch', 0x39ef7b0, 0x39ef7db),
    ('payload_field_compare', 0x39ef80e, 0x39ef831),
    ('payload_field_again', 0x39ef8a6, 0x39ef8bf),
    ('payload_missing_or_duplicate', 0x39ef8e7, 0x39ef914),
    ('payload_value_and_loop', 0x39ef92f, 0x39ef991),
    ('payload_sequence_length_check', 0x39ef9e3, 0x39efa55),
    ('payload_duplicate_field', 0x39efab4, 0x39efb14),
    ('payload_unexpected_value_and_kind', 0x39efb14, 0x39efb69),
    ('box_call_and_error', 0x3b92548, 0x3b92572),
    ('box_allocate_and_copy', 0x3b92572, 0x3b925cc),
    ('core_input_and_code_lookup', 0x3c175a1, 0x3c175d6),
    ('core_compact_code_lookup', 0x3c176bb, 0x3c17721),
    ('core_owner_equals_user', 0x3c17725, 0x3c1776f),
    ('core_binding_lookup', 0x3c1776f, 0x3c17865),
    ('core_profile_representation', 0x3c17865, 0x3c17891),
    ('core_profile_lookup', 0x3c1795a, 0x3c179c0),
    ('core_packed_year', 0x3c179c0, 0x3c17a0c),
    ('core_millisecond_arithmetic', 0x3c17a0c, 0x3c17a74),
    ('core_bucket_width', 0x3c179fe, 0x3c17a0c),
    ('core_bucket_divide', 0x3c17a74, 0x3c17aaf),
    ('core_bucket_reset_decrement', 0x3c17aaf, 0x3c17af0),
    ('core_tree_to_compact_guard', 0x3c17af0, 0x3c17b1c),
    ('core_compact_search_transition', 0x3c17c78, 0x3c17caf),
    ('core_compact_to_tree', 0x3c17caf, 0x3c17d11),
    ('core_compact_insert', 0x3c17d11, 0x3c17d68),
    ('core_tree_search', 0x3c17d93, 0x3c17e49),
    ('core_history_replace', 0x3c17e49, 0x3c17e67),
    ('core_history_tree_insert', 0x3c17e67, 0x3c17ee7),
    ('core_binding_write_return', 0x3c17ee7, 0x3c17f2d),
    ('core_bounds_failure', 0x3c17f2d, 0x3c17f7b),
    ('code_search_first_compare', 0x455c2d9, 0x455c311),
    ('code_search_binary_search', 0x455c380, 0x455c420),
    ('profile_search_key', 0x455661c, 0x455667f),
    ('history_search_key', 0x455a320, 0x455a38d),
    ('compact_insert_limit', 0x4546488, 0x45464b6),
    ('compact_insert_copy', 0x454653a, 0x4546565),
    ('compact_shift_memmove', 0x456d278, 0x456d2b8),
    ('tree_insert_empty', 0x3705804, 0x37058a7),
    ('tree_insert_failure', 0x37058a7, 0x37058d0),
    ('status_drop_switch', 0x3d08df5, 0x3d08e1d),
    ('status_drop_a5_return', 0x3d08faa, 0x3d08fb0),
)

# Sites are an explicitly selected set, discovered by manual instruction-boundary
# inspection; output opcodes and branch targets are always decoded from ELF bytes.
BRANCH_SITES = (
    ('outer_variant', 0x3a02097), ('outer_variant', 0x3a020ac),
    ('outer_variant', 0x3a02123), ('outer_variant', 0x3a0212c),
    ('outer_variant', 0x3a02283), ('outer_variant', 0x3a029d7),
    ('outer', 0x3a1f086), ('outer', 0x3a1f08f), ('outer', 0x3a1f440),
    ('outer', 0x3a1f45e), ('outer', 0x3a1f4fe), ('outer', 0x3a1f633),
    ('outer', 0x3a1f645), ('outer', 0x3a1f690), ('outer', 0x3a1fa4a),
    ('outer', 0x3a1faa9),
    ('decoder', 0x36ba948), ('decoder', 0x36ba965),
    ('envelope', 0x3960c17), ('envelope', 0x3960c50),
    ('envelope', 0x3960c6a), ('envelope', 0x3960c70), ('envelope', 0x3960fa9),
    ('name_adapter', 0x3b68553), ('name_adapter', 0x3b6857c),
    ('name_adapter', 0x3b685d6),
    ('context', 0x36616c0), ('context', 0x3661f21), ('context', 0x3661f45),
    ('context', 0x3661f69), ('context', 0x36626ad),
    ('payload', 0x39ef53d), ('payload', 0x39ef546), ('payload', 0x39ef5a0),
    ('payload', 0x39ef5b3), ('payload', 0x39ef68b), ('payload', 0x39ef69c),
    ('payload', 0x39ef724), ('payload', 0x39ef7b8), ('payload', 0x39ef812),
    ('payload', 0x39ef81c), ('payload', 0x39ef8aa), ('payload', 0x39ef8b9),
    ('payload', 0x39ef885), ('payload', 0x39ef8f6), ('payload', 0x39ef90e),
    ('payload', 0x39ef95e), ('payload', 0x39ef96c), ('payload', 0x39ef98b),
    ('payload', 0x39efa0b), ('payload', 0x39efa76),
    ('box', 0x3b9255a), ('box', 0x3b92596),
    ('core', 0x3c175bf), ('core', 0x3c175d0), ('core', 0x3c17623),
    ('core', 0x3c17675), ('core', 0x3c1767c), ('core', 0x3c1767e),
    ('core', 0x3c176a3), ('core', 0x3c176b6), ('core', 0x3c176d5),
    ('core', 0x3c176e8), ('core', 0x3c1771f), ('core', 0x3c17769),
    ('core', 0x3c177df), ('core', 0x3c177f3), ('core', 0x3c177fa),
    ('core', 0x3c17804), ('core', 0x3c1785f), ('core', 0x3c17876),
    ('core', 0x3c1788b), ('core', 0x3c178f3), ('core', 0x3c17921),
    ('core', 0x3c17928), ('core', 0x3c1792a), ('core', 0x3c17942),
    ('core', 0x3c17955), ('core', 0x3c17975), ('core', 0x3c17982),
    ('core', 0x3c179b5), ('core', 0x3c179da), ('core', 0x3c17a06),
    ('core', 0x3c17a87), ('core', 0x3c17a93), ('core', 0x3c17a9d),
    ('core', 0x3c17a9f), ('core', 0x3c17aad), ('core', 0x3c17b16),
    ('core', 0x3c17b3b), ('core', 0x3c17b68), ('core', 0x3c17b73),
    ('core', 0x3c17bb8), ('core', 0x3c17c01), ('core', 0x3c17c54),
    ('core', 0x3c17c7f), ('core', 0x3c17cad), ('core', 0x3c17d05),
    ('core', 0x3c17d0f), ('core', 0x3c17d18), ('core', 0x3c17d1c),
    ('core', 0x3c17d63), ('core', 0x3c17d6b), ('core', 0x3c17d9b),
    ('core', 0x3c17de8), ('core', 0x3c17e18), ('core', 0x3c17e1f),
    ('core', 0x3c17e21), ('core', 0x3c17e35), ('core', 0x3c17e44),
    ('core', 0x3c17e62), ('core', 0x3c17ed5), ('core', 0x3c17ee5),
    ('core', 0x3c17f30), ('core', 0x3c17f57), ('core', 0x3c17f60),
    ('compact_insert', 0x454648f), ('compact_insert', 0x45464a4),
    ('compact_insert', 0x45464c0), ('tree_insert', 0x37057a9),
    ('tree_insert', 0x3705815), ('tree_insert', 0x3705843),
    ('context', 0x23853d2), ('context', 0x2c1b642),
    ('context', 0x2c1b5c6), ('context', 0x2c1b601),
)

# Direct transfers are selected call sites, not a complete xref census.
DIRECT_CALLS = (
    ('context_outer_direct_arm_to_handler', 0x2bdb08a, 0x2c12690),
    ('context_outer_handler_initial_gate', 0x2c12954, 0x2bdb5b0),
    ('context_outer_handler_first_gate', 0x2c12998, 0x2c202b0),
    ('context_outer_handler_second_gate', 0x2c129d9, 0x2c206b0),
    ('context_outer_handler_to_nested_router', 0x2c129f7, 0x2bdbaa0),
    ('outer_variant_to_envelope_sequence', 0x3a029c7, 0x3a1f060),
    ('outer_variant_to_envelope_map', 0x3a022d1, 0x3a1f060),
    ('decoder_to_outer_variant', 0x36baa98, 0x3a01c70),
    ('outer_action_map_decoder', 0x3a1f680, 0x36b8c90),
    ('outer_action_sequence_box', 0x3a1fa9b, 0x3b92540),
    ('outer_missing_action_error', 0x3a1fd12, 0x46f32c0),
    ('outer_duplicate_action_error', 0x3a1fdae, 0x46f32c0),
    ('decoder_to_envelope', 0x36b8cde, 0x3960480),
    ('envelope_to_name_adapter', 0x3960c46, 0x3b68540),
    ('adapter_borrowed_to_matcher', 0x3b68577, 0x36616b0),
    ('adapter_owned_to_matcher', 0x3b685ce, 0x36616b0),
    ('decoder_to_payload', 0x36ba93c, 0x39ef520),
    ('box_to_decoder', 0x3b9254e, 0x36b8c90),
    ('payload_unknown_field', 0x39ef82a, 0x45a8ef0),
    ('payload_sequence_value', 0x39ef709, 0x3a9f2e0),
    ('payload_map_value', 0x39ef93d, 0x3a9f2e0),
    ('payload_missing_field', 0x39ef5fa, 0x46f32c0),
    ('payload_duplicate_field', 0x39efaf5, 0x46f32c0),
    ('payload_sequence_empty_error', 0x39ef6ae, 0x45a8f80),
    ('payload_sequence_extra_error', 0x39efa34, 0x45a8f80),
    ('payload_unsupported_kind', 0x39efb4d, 0x3b676e0),
    ('context_direct_arm_to_handler', 0x2bdb029, 0x2c1b320),
    ('context_nested_arm_to_wrapper', 0x2bdc7a4, 0x23853b0),
    ('context_first_gate', 0x2c1b5ba, 0x2c202b0),
    ('context_second_gate', 0x2c1b5f5, 0x2c206b0),
    ('core_code_lookup', 0x3c176c9, 0x455c290),
    ('core_binding_hash', 0x3c1778c, 0x4717440),
    ('core_binding_probe', 0x3c177d7, 0x3ee6280),
    ('core_binding_entry', 0x3c17849, 0x4717c50),
    ('core_profile_lookup', 0x3c17969, 0x4556550),
    ('core_drop_prior_status', 0x3c17ae6, 0x3d08df0),
    ('core_tree_to_compact_helper', 0x3c17b9b, 0x3dd5bb0),
    ('core_compact_history_lookup', 0x3c17c92, 0x455a260),
    ('core_compact_to_tree_helper', 0x3c17cf8, 0x387c8c0),
    ('core_compact_history_insert', 0x3c17d5b, 0x4546480),
    ('core_tree_history_insert', 0x3c17eca, 0x3705790),
    ('compact_shift_a', 0x45464f1, 0x456d220),
    ('compact_shift_b', 0x4546522, 0x456d220),
    ('tree_nonempty_insert', 0x37057eb, 0x34b2c50),
)
INDIRECT_CALLS = (
    ('nested_wrapper_state_core', 0x23853f9, 0x64e50b0),
    ('direct_wrapper_state_core', 0x2c1b715, 0x64e50b0),
    ('box_memcpy_1', 0x3b92582, 0x64df508),
    ('box_allocator', 0x3b9258d, 0x64df480),
    ('box_memcpy_2', 0x3b925a6, 0x64df508),
    ('box_allocation_failure', 0x3b925c4, 0x64df490),
    ('code_compare', 0x455c3ac, 0x64dfb50),
    ('profile_compare', 0x455662e, 0x64dfb50),
    ('history_compare', 0x455a366, 0x64dfb50),
    ('history_shift_a', 0x456d299, 0x64df568),
    ('history_shift_b', 0x456d2b2, 0x64df568),
    ('tree_allocator', 0x370580c, 0x64df480),
    ('tree_allocation_failure', 0x37058b1, 0x64df490),
    ('compact_growth', 0x45464a9, 0x64eabc0),
)

# Prefix then little-endian immediate. Locations refer to instruction starts.
CONSTANTS = (
    ('switch_bias', 0x2bce578, '482d', 'I'),
    ('switch_below_bias_index', 0x2bce57e, 'b9', 'I'),
    ('decoder_type_name_length', 0x36ba931, 'b9', 'I'),
    ('decoder_success_tag', 0x36ba960, 'b8', 'I'),
    ('decoder_error_tag', 0x36bada9, 'b8', 'I'),
    ('outer_variant_success_tag', 0x36baaec, 'b8', 'I'),
    ('outer_variant_type_length', 0x36baa8d, 'b9', 'I'),
    ('outer_variant_payload_field_length', 0x3a02093, '4883fa', 'B'),
    ('outer_variant_payload_field_index', 0x3a020b2, 'c6442421', 'B'),
    ('outer_variant_action_pointer_offset', 0x3a02a44, '488945', 'B'),
    ('nested_action_pointer_offset', 0x2bdbaba, '4c8b66', 'B'),
    ('outer_sequence_kind', 0x3a1f07a, '83fd', 'B'),
    ('outer_map_kind', 0x3a1f08c, '83fd', 'B'),
    ('outer_multi_user_field_length', 0x3a1f272, '4883fa', 'B'),
    ('outer_signer_field_length', 0x3a1f268, '4883fa', 'B'),
    ('outer_action_field_length', 0x3a1f43c, '4883fa', 'B'),
    ('payload_sequence_kind', 0x39ef53a, '83fb', 'B'),
    ('payload_map_kind', 0x39ef543, '83fb', 'B'),
    ('payload_end_sentinel', 0x39ef589, 'c6842490000000', 'B'),
    ('payload_key_kind_adjusted_max', 0x39ef7b5, '83f8', 'B'),
    ('payload_code_length', 0x39ef80e, '4883fe', 'B'),
    ('payload_map_order_panic_length', 0x39efb22, 'be', 'I'),
    ('matcher_length_bias', 0x36616b8, '488d4a', 'b'),
    ('matcher_adjusted_length_max', 0x36616bc, '4883f9', 'B'),
    ('matcher_name_ordinal', 0x36626a9, 'c64001', 'B'),
    ('adapter_adjusted_kind_max', 0x3b68550, '83f8', 'B'),
    ('box_copy_size', 0x3b9257d, 'ba', 'I'),
    ('wrapper_reject_length_at_least', 0x23853ce, '4983f8', 'B'),
    ('direct_wrapper_reject_length_at_least', 0x2c1b63e, '4983f8', 'B'),
    ('wrapper_length_error', 0x23853d4, '66c74310', 'H'),
    ('direct_wrapper_length_error', 0x2c1b648, '66c74310', 'H'),
    ('wrapper_inner_success', 0x23853ff, '66817c2410', 'H'),
    ('wrapper_success_tag', 0x2385408, 'c603', 'B'),
    ('wrapper_error_tag', 0x2385456, 'c603', 'B'),
    ('direct_wrapper_success_tag', 0x2c1b724, 'c603', 'B'),
    ('direct_wrapper_error_tag', 0x2c1b77a, 'c603', 'B'),
    ('direct_identity_error', 0x2c1b57f, '66c74010', 'H'),
    ('code_missing_status', 0x3c176ce, '6641ba', 'H'),
    ('self_key_status', 0x3c177f5, '6641ba', 'H'),
    ('already_set_status', 0x3c1784e, '6641ba', 'H'),
    ('profile_missing_success', 0x3c17883, '6641ba', 'H'),
    ('compared_key_bytes', 0x3c178f9, 'ba', 'I'),
    ('bucket_failure_status', 0x3c179fe, '6641ba', 'H'),
    ('packed_year_shift', 0x3c179d0, 'c1fe', 'B'),
    ('calendar_magic', 0x3c179e3, '4869f7', 'I'),
    ('calendar_cycle_shift', 0x3c179ea, '48c1ee', 'B'),
    ('calendar_cycle_years', 0x3c179f0, '69fe', 'I'),
    ('calendar_cycle_day_delta', 0x3c179f8, '69fe', 'i'),
    ('packed_ordinal_shift', 0x3c17a15, 'c1e8', 'B'),
    ('packed_ordinal_mask', 0x3c17a18, '25', 'I'),
    ('century_magic', 0x3c17a22, '4869fa', 'I'),
    ('century_shift', 0x3c17a30, '48c1ff', 'B'),
    ('calendar_year_scale', 0x3c17a39, '69d2', 'I'),
    ('calendar_year_scale_shift', 0x3c17a3f, 'c1fa', 'B'),
    ('calendar_century_quarter_shift', 0x3c17a44, 'c1ff', 'B'),
    ('calendar_epoch_day_bias', 0x3c17a4a, '05', 'i'),
    ('seconds_per_day', 0x3c17a51, '4869c0', 'I'),
    ('millis_per_second', 0x3c17a5b, '4869c0', 'I'),
    ('nanos_to_millis_magic', 0x3c17a66, '4869d2', 'I'),
    ('nanos_to_millis_shift', 0x3c17a6d, '48c1ea', 'B'),
    ('division_fast_path_bits', 0x3c17a83, '48c1ea', 'B'),
    ('bucket_reset_threshold', 0x3c17ab9, '483d', 'I'),
    ('bucket_reset_floor', 0x3c17abf, 'bb', 'I'),
    ('tree_to_compact_below', 0x3c17b0a, '4883f8', 'B'),
    ('compact_to_tree_at_least', 0x3c17ca2, '4883fe', 'B'),
    ('history_record_shift', 0x454653a, '48c1e3', 'B'),
    ('history_tree_alloc_bytes', 0x3705807, 'bf', 'I'),
    ('history_tree_node_limit', 0x370583f, '4883f9', 'B'),
    ('binding_flag_value', 0x3c17eec, 'c681c4000000', 'B'),
    ('binding_flag_offset', 0x3c17eec, 'c681', 'I'),
    ('binding_owner_offset', 0x3c17efb, '0f1181', 'I'),
)

# A small set of context patterns also guards the cross-check, independent of FDE hashes.
CONTEXT_PATTERNS = (
    (0x2bce578, '482d86000000b914000000480f43c8'),
    (0x2bda82d, '482d86000000b914000000480f43c8'),
    (0x2bdbb10, '482d86000000b914000000480f43c8'),
    (0x2bdb019, '4983c7084889e74c89ee4c89e24c89f9'),
    (0x2bdc781, '4983c408418b451089442410410f1045000f290424'),
    (0x23853ce, '4983f865720c66c743105801'),
    (0x2c1b63e, '4983f8650f82af00000066c743105801'),
    (0x3661f4b, '48bf736574526566657248333e49b852656665727265724c3346034909f8'),
    (0x36626a9, 'c640011aeb76'),
    (0x3662725, '31c988085b415e415fc3'),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def authenticate(data, expected=TARGET_SHA256):
    require(hashlib.sha256(data).hexdigest() == expected, 'node input SHA-256 mismatch')


def unique_section(secs, name):
    matches = [s for s in secs if s['name'] == name]
    require(len(matches) == 1, 'missing or duplicate section: ' + name)
    require(matches[0]['type'] != 8, 'section has no file bytes: ' + name)
    return matches[0]


def offset_for(secs, data_length, va, size, executable=False):
    require(type(va) is int and type(size) is int and va >= 0 and size > 0,
            'invalid VA or size')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] <= va and va + size <= s['address'] + s['size'] and
               (not executable or s['flags'] & 4)]
    require(len(matches) == 1, 'VA is outside or ambiguous among file-backed sections')
    sec = matches[0]
    off = sec['offset'] + va - sec['address']
    require(0 <= off and off + size <= data_length, 'VA maps outside file')
    return off


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)

    def offset(self, va, size, executable=False):
        return offset_for(self.secs, len(self.data), va, size, executable)

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return bytes(self.data[off:off + size])

    def expect(self, va, expected, executable=True):
        actual = self.read(va, len(expected), executable)
        require(actual == expected, 'unexpected pinned bytes at ' + hex(va))
        return actual

    def immediate(self, va, prefix, fmt):
        prefix = bytes.fromhex(prefix)
        raw = self.read(va, len(prefix) + struct.calcsize('<' + fmt), True)
        require(raw.startswith(prefix), 'unexpected immediate instruction at ' + hex(va))
        return struct.unpack_from('<' + fmt, raw, len(prefix))[0]

    def rip(self, va, prefix):
        prefix = bytes.fromhex(prefix)
        raw = self.read(va, len(prefix) + 4, True)
        require(raw.startswith(prefix), 'unexpected RIP-relative instruction at ' + hex(va))
        return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]

    def direct_call(self, va):
        raw = self.read(va, 5, True)
        require(raw[0] == 0xe8, 'expected rel32 call at ' + hex(va))
        return va + 5 + struct.unpack_from('<i', raw, 1)[0]

    def branch(self, va):
        first = self.read(va, 1, True)[0]
        if 0x70 <= first <= 0x7f:
            raw = self.read(va, 2, True)
            delta = struct.unpack_from('<b', raw, 1)[0]
            name = 'j' + CONDITIONS[first - 0x70]
        elif first == 0x0f:
            raw = self.read(va, 6, True)
            require(0x80 <= raw[1] <= 0x8f, 'not a supported conditional branch')
            delta = struct.unpack_from('<i', raw, 2)[0]
            name = 'j' + CONDITIONS[raw[1] - 0x80]
        elif first == 0xeb:
            raw = self.read(va, 2, True)
            delta = struct.unpack_from('<b', raw, 1)[0]
            name = 'jmp'
        elif first == 0xe9:
            raw = self.read(va, 5, True)
            delta = struct.unpack_from('<i', raw, 1)[0]
            name = 'jmp'
        else:
            raise ValueError('unsupported branch opcode at ' + hex(va))
        return name, raw, va + len(raw) + delta

    def table_entry(self, table, index, start, end):
        require(type(index) is int and index >= 0, 'negative table index')
        slot = table + 4 * index
        raw = self.read(slot, 4)
        target = table + struct.unpack('<i', raw)[0]
        require(start <= target < end, 'jump table target outside selected FDE')
        return slot, raw, target


CONDITIONS = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
              's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')


def collect_relocations(image, selected_slots):
    rel = unique_section(image.secs, '.rela.dyn')
    require(rel['type'] == 4 and rel['size'] % 24 == 0, 'invalid RELA section')
    require(rel['offset'] + rel['size'] <= len(image.data), 'truncated RELA section')
    selected = set(selected_slots)
    require(len(selected) == len(selected_slots), 'duplicate requested relocation')
    found = {}
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, off)
        if slot in selected:
            require(slot not in found, 'duplicate relocation slot')
            image.offset(slot, 8)
            found[slot] = {'slot': slot, 'entry_offset': off, 'type': info & 0xffffffff,
                           'symbol': info >> 32, 'addend': addend}
    require(set(found) == selected, 'selected relocation slot missing')
    return found


def dyn_name(image, index):
    sym = unique_section(image.secs, '.dynsym')
    strings = unique_section(image.secs, '.dynstr')
    require(sym['type'] == 11 and sym['size'] % 24 == 0, 'invalid dynamic symbols')
    require(0 <= index < sym['size'] // 24, 'dynamic symbol index out of range')
    nameoff = struct.unpack_from('<I', image.data, sym['offset'] + 24 * index)[0]
    require(nameoff < strings['size'], 'dynamic symbol name out of range')
    start = strings['offset'] + nameoff
    end = image.data.find(b'\0', start, strings['offset'] + strings['size'])
    require(end >= 0, 'unterminated dynamic symbol name')
    return bytes(image.data[start:end]).decode('ascii')


def checked_relocations(image):
    slots = sorted({slot for _, _, slot in INDIRECT_CALLS} | {0x648ae98})
    relocs = collect_relocations(image, slots)
    expected_relative = {0x64e50b0: 0x3c17590, 0x648ae98: 0x459e80,
                         0x64df480: 0x6355830, 0x64df490: 0x141e251, 0x64eabc0: 0x455fa10}
    expected_symbols = {0x64df508: 'memcpy', 0x64df568: 'memmove', 0x64dfb50: 'memcmp'}
    rows = [['slot_va', 'slot_file_offset', 'relocation_file_offset', 'type', 'symbol_index', 'symbol_name', 'addend']]
    for slot in slots:
        record = relocs[slot]
        symname = dyn_name(image, record['symbol']) if record['symbol'] else ''
        if slot in expected_relative:
            require(record['type'] == 8 and record['symbol'] == 0 and record['addend'] == expected_relative[slot], 'unexpected RELATIVE relocation')
        else:
            require(slot in expected_symbols and record['type'] == 6 and symname == expected_symbols[slot], 'unexpected imported relocation')
        rows.append([hex(slot), hex(image.offset(slot, 8)), hex(record['entry_offset']), record['type'], record['symbol'], symname, hex(record['addend'])])
    return relocs, rows


def selected_frames(image):
    secs, index = unwind_index(image.data)
    require(secs == image.secs, 'inconsistent section read')
    _, frames = eh_frame_records(image.data, secs)
    starts = {}
    for fde in frames:
        starts.setdefault(fde['start'], []).append(fde)
    index_by_start = {row['start']: row for row in index}
    require(len(index_by_start) == len(index), 'duplicate unwind start')
    out = []
    for role, start, expected_end, expected_hash in FUNCTIONS:
        matches = starts.get(start, [])
        require(len(matches) == 1 and start in index_by_start, 'missing or duplicate selected FDE')
        frame = matches[0]
        require(frame['fde'] == index_by_start[start]['fde'], 'FDE and unwind table disagree')
        require(frame['end'] == expected_end and expected_end > start, 'changed selected FDE extent')
        body = image.read(start, expected_end - start, True)
        digest = hashlib.sha256(body).hexdigest()
        require(digest == expected_hash, 'changed selected FDE bytes at ' + hex(start))
        out.append((role, frame, body, digest))
    return out


def read_constants(image):
    vals = {}
    rows = [['role', 'instruction_va', 'file_offset', 'instruction_hex', 'value_decimal', 'value_hex']]
    for name, va, prefix, fmt in CONSTANTS:
        value = image.immediate(va, prefix, fmt)
        size = len(bytes.fromhex(prefix)) + struct.calcsize('<' + fmt)
        vals[name] = value
        rows.append([name, hex(va), hex(image.offset(va, size, True)), image.read(va, size, True).hex(), value, hex(value)])
    require(vals['decoder_error_tag'] != vals['decoder_success_tag'], 'decoder tags overlap')
    require(vals['bucket_reset_threshold'] == vals['bucket_reset_floor'] + 1, 'reset threshold mismatch')
    require(vals['wrapper_inner_success'] == vals['profile_missing_success'], 'success markers differ')
    require(vals['wrapper_reject_length_at_least'] == vals['direct_wrapper_reject_length_at_least'],
            'wrapper length limits differ')
    require(vals['wrapper_length_error'] == vals['direct_wrapper_length_error'] and
            vals['wrapper_success_tag'] == vals['direct_wrapper_success_tag'] and
            vals['wrapper_error_tag'] == vals['direct_wrapper_error_tag'],
            'wrapper result representations differ')
    require(vals['calendar_magic'] == vals['century_magic'], 'calendar multipliers differ')
    require(vals['outer_variant_action_pointer_offset'] == vals['nested_action_pointer_offset'],
            'outer action pointer and nested dispatcher offsets differ')
    return vals, rows


def packed_day_number(values, packed):
    """Interpret the selected date arithmetic, before its later zero clamp."""
    require(type(packed) is int and 0 <= packed < 1 << 32, 'packed date outside u32')
    signed = packed if packed < 1 << 31 else packed - (1 << 32)
    year = signed >> values['packed_year_shift']
    ordinal = (packed >> values['packed_ordinal_shift']) & values['packed_ordinal_mask']
    adjusted = year - 1
    cycle_days = 0
    if year <= 0:
        cycles = (((1 - year) * values['calendar_magic']) >> values['calendar_cycle_shift']) + 1
        adjusted += values['calendar_cycle_years'] * cycles
        cycle_days = values['calendar_cycle_day_delta'] * cycles
    century = (adjusted * values['century_magic']) >> values['century_shift']
    return (ordinal + cycle_days - century +
            ((adjusted * values['calendar_year_scale']) >> values['calendar_year_scale_shift']) +
            (century >> values['calendar_century_quarter_shift']) + values['calendar_epoch_day_bias'])


def packed_millis(values, packed, seconds, nanos):
    """Synthetic arithmetic model; calendar validity is a caller precondition."""
    for number in (seconds, nanos):
        require(type(number) is int and 0 <= number < 1 << 32, 'time field outside u32')
    whole = packed_day_number(values, packed) * values['seconds_per_day'] + seconds
    fraction = (nanos * values['nanos_to_millis_magic']) >> values['nanos_to_millis_shift']
    return max(0, whole * values['millis_per_second'] + fraction)


def bucket_from_time(values, packed, seconds, nanos, width):
    require(type(width) is int and 0 < width < 1 << 64, 'bucket width outside nonzero u64')
    millis = packed_millis(values, packed, seconds, nanos)
    use_u32 = (millis | width) >> values['division_fast_path_bits'] == 0
    return millis // width, 'u32' if use_u32 else 'u64'


def normal_transition(values, *, code_found=True, same_key=False, already=False,
                      profile_found=True, width=1, bucket=0, stored_bucket=0,
                      remaining=1, configured=0):
    """Synthetic model of selected core predicates, not target execution."""
    for predicate in (code_found, same_key, already, profile_found):
        require(type(predicate) is bool, 'model predicate must be boolean')
    for number in (width, bucket, stored_bucket, remaining, configured):
        require(type(number) is int and 0 <= number < 1 << 64, 'model input outside u64')
    if not code_found:
        return values['code_missing_status'], False, False, stored_bucket, remaining
    if same_key:
        return values['self_key_status'], False, False, stored_bucket, remaining
    # The entry helper can have side effects even when later conditions fail.
    entry_called = True
    if already:
        return values['already_set_status'], entry_called, False, stored_bucket, remaining
    if not profile_found:
        return values['profile_missing_success'], entry_called, False, stored_bucket, remaining
    if width == 0:
        return values['bucket_failure_status'], entry_called, False, stored_bucket, remaining
    if bucket == stored_bucket:
        if remaining == 0:
            return values['bucket_failure_status'], entry_called, False, stored_bucket, remaining
        new_remaining = remaining - 1
    else:
        new_remaining = max(configured, values['bucket_reset_floor']) - 1
    return values['wrapper_inner_success'], entry_called, True, bucket, new_remaining


def selected_name_matches(raw, head, tail):
    """Interpret only the selected overlapping name comparisons."""
    require(len(head) == 8 and len(tail) == 8 and head[3:] == tail[:5],
            'inconsistent name comparison operands')
    return len(raw) == 11 and raw[:8] == head and raw[3:11] == tail


def selected_field_matches(raw, field):
    """Interpret only the selected length and field-byte comparisons."""
    return len(raw) == len(field) and raw == field


def table(data_rows):
    output = io.StringIO(newline='')
    csv.writer(output, delimiter='\t', lineterminator='\n').writerows(data_rows)
    return output.getvalue().encode('utf-8')


def collect(data):
    authenticate(data)
    image = Image(data)
    frames = selected_frames(image)
    for va, pattern in CONTEXT_PATTERNS:
        image.expect(va, bytes.fromhex(pattern))
    vals, constants_rows = read_constants(image)

    frame_map = {role: frame for role, frame, _, _ in frames}
    function_rows = [['role', 'start_va', 'end_va_exclusive', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'size', 'sha256', 'body_hex']]
    for role, frame, body, digest in frames:
        function_rows.append([role, hex(frame['start']), hex(frame['end']), hex(image.offset(frame['start'], len(body), True)),
                              hex(frame['fde']), hex(frame['cie']), '' if frame['lsda'] is None else hex(frame['lsda']),
                              len(body), digest, body.hex()])

    window_rows = [['role', 'start_va', 'end_va_exclusive', 'file_offset', 'size', 'sha256', 'bytes_hex']]
    for role, start, end in WINDOWS:
        raw = image.read(start, end - start, True)
        window_rows.append([role, hex(start), hex(end), hex(image.offset(start, len(raw), True)), len(raw), hashlib.sha256(raw).hexdigest(), raw.hex()])

    branch_rows = [['scope', 'site_va', 'file_offset', 'opcode_hex', 'condition', 'target_va']]
    group_to_frame = {'outer_variant': 'outer_action_decoder', 'outer': 'multi_party_envelope',
                      'decoder': 'action_decoder', 'payload': 'referrer_payload_decoder',
                      'envelope': 'action_envelope', 'name_adapter': 'name_input_adapter',
                      'box': 'boxed_decoder', 'core': 'referrer_state_core',
                      'compact_insert': 'compact_history_insert', 'tree_insert': 'tree_history_insert'}
    for group, va in BRANCH_SITES:
        name, raw, target = image.branch(va)
        if group in group_to_frame:
            frame = frame_map[group_to_frame[group]]
            require(frame['start'] <= va < frame['end'] and frame['start'] <= target < frame['end'],
                    'selected local branch outside FDE')
        else:
            image.offset(target, 1, True)
        branch_rows.append([group, hex(va), hex(image.offset(va, len(raw), True)), raw.hex(), name, hex(target)])

    edge_rows = [['kind', 'role', 'site_va', 'file_offset', 'bytes_hex', 'target_or_slot_va']]
    for role, site, expected_target in DIRECT_CALLS:
        target = image.direct_call(site)
        require(target == expected_target, 'direct call target changed at ' + hex(site))
        image.offset(target, 1, True)
        edge_rows.append(['rel32_call', role, hex(site), hex(image.offset(site, 5, True)), image.read(site, 5, True).hex(), hex(target)])
    for role, site, expected_slot in INDIRECT_CALLS:
        slot = image.rip(site, 'ff15')
        require(slot == expected_slot, 'indirect slot changed at ' + hex(site))
        edge_rows.append(['rip_slot_call', role, hex(site), hex(image.offset(site, 6, True)), image.read(site, 6, True).hex(), hex(slot)])

    relocs, relocation_rows = checked_relocations(image)

    # A name is observed in one serializer and one action-specific decoder.
    ordinal = vals['decoder_success_tag'] - vals['switch_bias']
    require(ordinal >= 0, 'tag below measured bias')
    decoder_table = image.rip(0x36b8d23, '488d0d')
    formatter_table = image.rip(0x2bce58a, '488d05')
    direct_table = image.rip(0x2bda83c, '488d05')
    nested_table = image.rip(0x2bdbb1f, '488d05')
    switches = (
        ('decoder', decoder_table, frame_map['action_decoder']['start'], frame_map['action_decoder']['end'], 0x36ba91b),
        ('context_formatter', formatter_table, 0x2bce570, 0x2bd0ee5, 0x2bd0893),
        ('context_direct_router', direct_table, 0x2bda7c0, 0x2bdb225, 0x2bdb019),
        ('context_nested_router', nested_table, 0x2bdbaa0, 0x2bdcb65, 0x2bdc781),
    )
    switch_rows = [['role', 'index_decimal', 'table_va', 'entry_va', 'entry_file_offset', 'entry_hex', 'signed_delta', 'arm_va']]
    for role, base, lower, upper, expected in switches:
        slot, raw, arm = image.table_entry(base, ordinal, lower, upper)
        require(arm == expected, 'selected switch arm changed')
        switch_rows.append([role, ordinal, hex(base), hex(slot), hex(image.offset(slot, 4)), raw.hex(), struct.unpack('<i', raw)[0], hex(arm)])
    outer_ordinal = vals['outer_variant_success_tag'] - vals['switch_bias']
    for role, base, lower, upper, expected in (
            ('outer_variant_decoder', decoder_table, frame_map['action_decoder']['start'],
             frame_map['action_decoder']['end'], 0x36baa77),
            ('context_outer_direct_router', direct_table, 0x2bda7c0, 0x2bdb225, 0x2bdb07a)):
        slot, raw, arm = image.table_entry(base, outer_ordinal, lower, upper)
        require(arm == expected, 'outer variant switch arm changed')
        switch_rows.append([role, outer_ordinal, hex(base), hex(slot), hex(image.offset(slot, 4)),
                            raw.hex(), struct.unpack('<i', raw)[0], hex(arm)])

    type_va = image.rip(0x36ba91b, '488d15')
    type_len = vals['decoder_type_name_length']
    type_raw = image.read(type_va, type_len)
    require(type_raw == b'SetReferrerAction', 'unexpected decoder type literal')
    name_va = image.rip(0x2bd08d6, '488d05')
    name_len = image.immediate(0x2bd08e2, '48c7442440', 'I')
    name_raw = image.read(name_va, name_len)
    require(name_raw == b'setReferrer', 'unexpected formatter name literal')
    field_slot = image.rip(0x36ba922, '4c8d05')
    require(field_slot == 0x648ae98, 'unexpected field descriptor')
    field_len = struct.unpack('<Q', image.read(field_slot + 8, 8))[0]
    field_va = relocs[field_slot]['addend']
    field_raw = image.read(field_va, field_len)
    require(field_raw == b'code', 'unexpected field literal')
    field_cmp_va = image.rip(0x39ef816, '3b05')
    require(field_cmp_va == field_va, 'field comparison and descriptor disagree')
    # For the selected length arm, the two overlapping eight-byte constants
    # cover all eleven name bytes and the success branch returns the ordinal.
    name_head = image.read(0x3661f4d, 8, True)
    name_tail = image.read(0x3661f5a, 8, True)
    require(name_head[3:] == name_tail[:5], 'overlapping name constants disagree')
    match_name = name_head + name_tail[5:]
    require(match_name == name_raw and vals['matcher_name_ordinal'] == ordinal,
            'name matcher, formatter and decoder disagree')
    # Two earlier length-11 comparisons precede the selected name. Recover
    # their literal operands, including the signed LEA displacement.
    image.expect(0x3661efc, bytes.fromhex('48b9'))
    image.expect(0x3661f06, bytes.fromhex('48bf'))
    image.expect(0x3661f13, bytes.fromhex('4c8d81'))
    first_head = image.read(0x3661f08, 8, True)
    first_seed = int.from_bytes(image.read(0x3661efe, 8, True), 'little')
    first_delta = struct.unpack('<i', image.read(0x3661f16, 4, True))[0]
    first_tail = ((first_seed + first_delta) & ((1 << 64) - 1)).to_bytes(8, 'little')
    image.expect(0x3661f27, bytes.fromhex('48bf'))
    image.expect(0x3661f34, bytes.fromhex('49b8'))
    second_head = image.read(0x3661f29, 8, True)
    second_tail = image.read(0x3661f36, 8, True)
    require(first_head[3:] == first_tail[:5] and second_head[3:] == second_tail[:5],
            'preceding name comparison windows do not overlap')
    first_name = first_head + first_tail[5:]
    second_name = second_head + second_tail[5:]
    require(match_name not in (first_name, second_name), 'prior comparison shadows selected name')
    matcher_table = image.rip(0x36616c6, '488d3d')
    matcher_index = len(match_name) + vals['matcher_length_bias']
    require(0 <= matcher_index <= vals['matcher_adjusted_length_max'], 'name length outside matcher switch')
    matcher_slot, matcher_raw, matcher_arm = image.table_entry(matcher_table, matcher_index, 0x36616b0, 0x366272f)
    require(matcher_arm == 0x3661efc and image.branch(0x3661f69)[2] == 0x36626a9,
            'selected name matcher path changed')
    switch_rows.append(['context_name_length', matcher_index, hex(matcher_table), hex(matcher_slot),
                        hex(image.offset(matcher_slot, 4)), matcher_raw.hex(),
                        struct.unpack('<i', matcher_raw)[0], hex(matcher_arm)])
    adapter_table = image.rip(0x3b68559, '488d0d')
    adapter_frame = frame_map['name_input_adapter']
    for kind, expected in ((12, 0x3b685bf), (13, 0x3b6856f)):
        index = kind - 1
        require(index <= vals['adapter_adjusted_kind_max'], 'input kind outside adapter switch')
        slot, raw, arm = image.table_entry(adapter_table, index, adapter_frame['start'], adapter_frame['end'])
        require(arm == expected, 'selected input kind arm changed')
        switch_rows.append(['name_adapter_kind_' + str(kind), index, hex(adapter_table), hex(slot),
                            hex(image.offset(slot, 4)), raw.hex(), struct.unpack('<i', raw)[0], hex(arm)])
    # The map field-name visitor has a separate switch. Record its entire
    # bounded domain, not just the two string-key cases.
    payload_table = image.rip(0x39ef7cb, '488d0d')
    payload_frame = frame_map['referrer_payload_decoder']
    key_rows = [['kind', 'index_decimal', 'table_va', 'entry_va', 'entry_file_offset',
                 'entry_hex', 'signed_delta', 'arm_va']]
    for index in range(vals['payload_key_kind_adjusted_max'] + 1):
        slot, raw, arm = image.table_entry(payload_table, index, payload_frame['start'], payload_frame['end'])
        key_rows.append([index + 1, index, hex(payload_table), hex(slot), hex(image.offset(slot, 4)),
                         raw.hex(), struct.unpack('<i', raw)[0], hex(arm)])
    require(key_rows[12][-1] == hex(0x39ef88c) and key_rows[13][-1] == hex(0x39ef80e),
            'selected field-name switch arms changed')
    missing_descriptor = image.rip(0x39ef5e4, '488d3d')
    duplicate_descriptor = image.rip(0x39efadf, '488d3d')
    missing_len = image.read(missing_descriptor, 1)[0]
    duplicate_len = image.read(duplicate_descriptor, 1)[0]
    missing_raw = image.read(missing_descriptor + 1, missing_len)
    duplicate_raw = image.read(duplicate_descriptor + 1, duplicate_len)
    panic_va = image.rip(0x39efb14, '488d3d')
    panic_raw = image.read(panic_va, vals['payload_map_order_panic_length'])
    require(missing_raw == b'missing field `' and duplicate_raw == b'duplicate field `',
            'field error descriptors changed')
    require(panic_raw == b'MapAccess::next_value called before next_key',
            'map order panic literal changed')
    outer_user_va = image.rip(0x3a1f27f, '483305')
    outer_signer_va = image.rip(0x3a1f3a0, '483305')
    outer_action_va = image.rip(0x3a1f448, '3305')
    outer_user = image.read(outer_user_va, vals['outer_multi_user_field_length'])
    outer_signer = image.read(outer_signer_va, vals['outer_signer_field_length'])
    outer_action = image.read(outer_action_va, vals['outer_action_field_length'])
    outer_type_va = image.rip(0x36baa77, '488d15')
    outer_type = image.read(outer_type_va, vals['outer_variant_type_length'])
    outer_payload_va = image.rip(0x3a0209b, '3305')
    outer_payload = image.read(outer_payload_va, vals['outer_variant_payload_field_length'])
    require((outer_user, outer_signer, outer_action) == (b'multiSigUser', b'outerSigner', b'action'),
            'outer action field names changed')
    require(outer_type == b'MultiSigAction', 'outer variant type name changed')
    require(outer_payload == b'payload' and vals['outer_variant_payload_field_index'] == 2,
            'outer variant payload selector changed')
    literal_rows = [['role', 'va', 'file_offset', 'size', 'bytes_hex', 'ascii']]
    for role, va, raw in (('decoder_type', type_va, type_raw), ('formatter_name', name_va, name_raw),
                          ('payload_field', field_va, field_raw),
                          ('payload_missing_prefix', missing_descriptor + 1, missing_raw),
                          ('payload_duplicate_prefix', duplicate_descriptor + 1, duplicate_raw),
                          ('payload_map_order_panic', panic_va, panic_raw),
                          ('outer_multi_user', outer_user_va, outer_user),
                          ('outer_signer', outer_signer_va, outer_signer),
                          ('outer_action', outer_action_va, outer_action),
                          ('outer_variant_payload', outer_payload_va, outer_payload),
                          ('outer_variant_type', outer_type_va, outer_type)):
        literal_rows.append([role, hex(va), hex(image.offset(va, len(raw))), len(raw), raw.hex(), raw.decode('ascii')])
    precedence_rows = [['order', 'head_va', 'head_hex', 'tail_operand_va', 'tail_hex', 'tail_adjustment', 'derived_name', 'branch_va', 'branch_target']]
    for order, head_va, head, tail_va, tail, delta, name, branch in (
            (1, 0x3661f08, first_head, 0x3661efe, first_tail, first_delta, first_name, 0x3661f21),
            (2, 0x3661f29, second_head, 0x3661f36, second_tail, 0, second_name, 0x3661f45),
            (3, 0x3661f4d, name_head, 0x3661f5a, name_tail, 0, match_name, 0x3661f69)):
        precedence_rows.append([order, hex(head_va), head.hex(), hex(tail_va), tail.hex(), delta,
                                name.decode('ascii'), hex(branch), hex(image.branch(branch)[2])])

    # For the temporary status 0xa5, the cleanup switch entry leads directly
    # to the return epilogue. This is scoped to that one input, not the helper.
    cleanup_input = vals['bucket_failure_status']
    first_limit = image.immediate(0x3d08df8, '3d', 'I')
    base_adjustment = image.immediate(0x3d08dff, '83c0', 'b')
    table_limit = image.immediate(0x3d08e02, '3d', 'I')
    cleanup_base = image.rip(0x3d08e0d, '488d0d')
    cleanup_index = cleanup_input + base_adjustment
    require(cleanup_input <= first_limit and 0 <= cleanup_index <= table_limit,
            'status is outside the selected cleanup switch')
    frame = frame_map['status_cleanup']
    slot, raw, cleanup_target = image.table_entry(cleanup_base, cleanup_index, frame['start'], frame['end'])
    image.expect(cleanup_target, bytes.fromhex('5b415e415fc3'))
    switch_rows.append(['temporary_status_cleanup', cleanup_index, hex(cleanup_base), hex(slot), hex(image.offset(slot, 4)), raw.hex(), struct.unpack('<i', raw)[0], hex(cleanup_target)])

    summary = {
        'target_sha256': hashlib.sha256(data).hexdigest(),
        'coordinate_system': 'linked ELF virtual address; zero-based file offset',
        'selected_function_fdes': len(frames),
        'selected_windows': len(window_rows) - 1,
        'selected_direct_calls': len(DIRECT_CALLS),
        'selected_indirect_calls': len(INDIRECT_CALLS),
        'selected_branches': len(BRANCH_SITES),
        'selected_relocations': len(relocation_rows) - 1,
        'selected_switch_entries': len(switch_rows) - 1,
        'selected_literals': len(literal_rows) - 1,
        'selected_name_comparisons': len(precedence_rows) - 1,
        'payload_key_switch_entries': len(key_rows) - 1,
        'ordinal_from_tag_and_bias': ordinal,
        'outer_ordinal_from_tag_and_bias': outer_ordinal,
        'constants': vals,
        'limitations': [
            'selected static observations, not captured execution or a complete control-flow graph',
            'context switches and wrappers were previously mapped and are not selected new FDEs',
            'the runtime decoder-to-dispatch transfer and external parser input ownership are unproved',
            'container invariant, growth failure, rollback and runtime relocation binding remain open',
        ],
    }
    outputs = {
        'functions.tsv': table(function_rows), 'windows.tsv': table(window_rows),
        'branches.tsv': table(branch_rows), 'calls.tsv': table(edge_rows),
        'relocations.tsv': table(relocation_rows), 'switches.tsv': table(switch_rows),
        'constants.tsv': table(constants_rows), 'literals.tsv': table(literal_rows),
        'name-precedence.tsv': table(precedence_rows),
        'payload-key-kinds.tsv': table(key_rows),
        'summary.json': (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode('utf-8'),
    }
    return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    outputs = collect(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(outputs.items()):
        (args.out / name).write_bytes(content)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error, UnicodeError) as error:
        print('re010_set_referrer_115: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
