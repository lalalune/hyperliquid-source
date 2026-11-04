#!/usr/bin/env python3
"""Extract selected RE-010 govVote evidence from the authenticated node ELF.

The fixed VAs select instruction-aligned windows examined during the research;
all bytes, targets, extents, immediates, relocations and output rows are read
from the input. This is a profile for one digest, not a general disassembler.
"""
import argparse
import hashlib
import io
import csv
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BINARY = ROOT / 'artifacts/node/115/hl-node'

# These starts were checked for overlap in existing work. Context functions
# used only to connect the action are deliberately excluded from this list.
FUNCTIONS = (
    ('outer_action_container_decoder', 0x20f00b0, 0x20f128a, 'ee919e57f4fd43b8a32050c15484a9b6c52cec96aa0affc37ce2ce3c0c5fbd9f'),
    ('action_decoder', 0x2b817d0, 0x2b84365, 'ab08c35f153b4b62eb2706fcf5d8d7caf7663e248cde7de653e91882ff7cd551'),
    ('action_content_envelope', 0x1fccd80, 0x1fcd7cb, 'a123a6dc8e249c2cf198ae1f853689f95accb164f6c6950c1953d237664acde4'),
    ('name_content_adapter', 0x21dfc90, 0x21dfda5, 'cda38be60e58bc81c031effa5a28b93c123ed3c82471d7724382e5bebc4d53a6'),
    ('primary_vote_payload_decoder', 0x20aedb0, 0x20aff95, '26ab157ca5548567750c1f61acbc626c29a80326d462ed44d2ddc151cc7b66d9'),
    ('vote_payload_decoder', 0x20ea750, 0x20ebd9c, '8cf6b85c8282dc09d796d877c9f3a7f7d5ca219df45e7e8a283ca3ec018401d8'),
    ('action_validation_router', 0x36c2050, 0x36c2f99, 'eaa2515d051afca85d5136bd3c53c7a6423abdb86d6832ef7b4d6132df182514'),
    ('vote_validation_body', 0x44f5650, 0x44f5787, '2095b2cd3bd00fa6682065269a4ed946264383a7750dc4c9f0ab90c34a27a7cd'),
    ('typed_data_digest_helper', 0x46e4ce0, 0x46e4f14, 'de15020d2ddf19e04e1cddf729247d0eb6e8ebb09d70eb07e8a4040c97dd997f'),
    ('signature_input_helper', 0x1536a90, 0x1536f6f, 'ac047dc176fdd876c26af3e448e1b391be9e71e9a922c906fba6ac51c5ff1c89'),
    ('vote_state_core', 0x3c33f10, 0x3c348ae, 'bea36c7f91bcc07a05620713e5ae426bfa3989a935b35ffcafcc66d4a098e580'),
    ('voter_amount_lookup', 0x4221a90, 0x4221c9b, '88c4fa5f2b438936fee4357d2687e772db39dba009707b47adcf6dba30d84172'),
    ('checked_amount_sum', 0x434f410, 0x434f57b, 'c5a3b133906064eeb9b431ec4d692ff68d95b7565a0350240d89c827c7d08864'),
    ('cursor_history_update', 0x4221ca0, 0x4221f3c, 'ff0c0799766054c61395725e9424b652a812dee7532ae72d05d4580d09c2e823'),
    ('tree_insert_root', 0x370a660, 0x370a7aa, 'fc02a8ca02cd0125c67f02f4c5185871b443dc7ee46dd6001a85126acf9de235'),
    ('tree_insert_nonempty', 0x3513d50, 0x35149c3, 'f9f78b51f0924df092e4aa9670b4e025539d6756ec16af79bb7bc8b5c65a0042'),
    ('compact_record_insert', 0x454c990, 0x454ca95, 'f218ffd6e7ee76d81f0e8ec6efd8cb46cc4c906eba3c4c52fe171d8b7dee79f9'),
)

# Selected raw windows; endpoints follow instruction boundaries in the
# independently inspected disassembly. Overlapping infrastructure windows are
# context, and are not counted as newly selected functions.
WINDOWS = (
 ('outer_container_entry', 0x20f00b0, 0x20f0132),
 ('outer_map_action_call', 0x20f0680, 0x20f06f1),
 ('outer_sequence_action_call', 0x20f0a0e, 0x20f0a3d),
 ('outer_missing_action_diagnostic', 0x20f08a7, 0x20f08ea),
 ('outer_duplicate_action_diagnostic', 0x20f0fe9, 0x20f106e),
 ('context_name_length_switch', 0x2ba0a79, 0x2ba0a96),
 ('context_name_length7_comparison', 0x2ba14f0, 0x2ba1527),
 ('name_content_adapter', 0x21dfc90, 0x21dfd23),
 ('content_input_selector', 0x1fccd80, 0x1fccda7),
 ('content_map_setup', 0x1fccdd3, 0x1fcce3d),
 ('content_map_key_and_loop', 0x1fccfa0, 0x1fcd100),
 ('content_map_name_match', 0x1fcd100, 0x1fcd165),
 ('content_map_ordinal_output', 0x1fcd165, 0x1fcd1ad),
 ('content_sequence_name_call', 0x1fcd333, 0x1fcd37f),
 ('content_duplicate_type_error', 0x1fcd5c6, 0x1fcd5f9),
 ('content_missing_type_error', 0x1fcd62f, 0x1fcd66c),
 ('action_envelope_call_and_switch', 0x2b817d0, 0x2b81881),
 ('action_vote_selected_arm', 0x2b81ad2, 0x2b81b4f),
 ('action_tag_and_box', 0x2b84278, 0x2b84335),
 ('primary_payload_kind', 0x20aedb0, 0x20aee38),
 ('primary_payload_field_table', 0x20af0d3, 0x20af0e3),
 ('primary_payload_duplicate_guards', 0x20af0e3, 0x20af103),
 ('primary_payload_missing_first_two', 0x20af5bf, 0x20af679),
 ('primary_payload_missing_id_choice', 0x20af6d5, 0x20af73a),
 ('primary_payload_missing_nonce_and_output', 0x20af874, 0x20af962),
 ('primary_payload_duplicate_messages', 0x20afb38, 0x20afcff),
 ('validation_router_switch', 0x36c2050, 0x36c20a3),
 ('validation_gov_vote_arm', 0x36c22a0, 0x36c2305),
 ('validation_generic_fallback', 0x36c2923, 0x36c2944),
 ('validation_vote_prefix', 0x44f5650, 0x44f5682),
 ('validation_vote_subcalls', 0x44f5682, 0x44f56e7),
 ('validation_vote_success_and_error', 0x44f5740, 0x44f5787),
 ('typed_data_digest_entry', 0x46e4ce0, 0x46e4d71),
 ('typed_data_digest_output_and_errors', 0x46e4d71, 0x46e4dd5),
 ('typed_data_digest_error_finish', 0x46e4dd5, 0x46e4e75),
 ('signature_input_and_selector', 0x1536a90, 0x1536b62),
 ('signature_first_backend_and_error', 0x1536b8a, 0x1536bb3),
 ('signature_second_backend_and_error', 0x1536cb2, 0x1536cc9),
 ('signature_error_result', 0x1536eff, 0x1536f29),
 ('prior_wrapper_core_call_context', 0x2457aac, 0x2457ab2),
 ('payload_kind_and_sequence', 0x20ea750, 0x20ea890),
 ('payload_field_table', 0x20eabbd, 0x20eabdf),
 ('payload_signature_id_route', 0x20eabdf, 0x20eac06),
 ('payload_id_route', 0x20eadaa, 0x20eadf5),
 ('payload_choice_route', 0x20eae3c, 0x20eaea8),
 ('payload_chain_route', 0x20eaea8, 0x20eaf1a),
 ('payload_missing_signature', 0x20eb0e4, 0x20eb159),
 ('payload_missing_chain', 0x20eb1c6, 0x20eb22f),
 ('payload_missing_id_choice_nonce', 0x20eb22f, 0x20eb314),
 ('payload_output_layout', 0x20eb314, 0x20eb373),
 ('payload_missing_id_builder', 0x20eb41e, 0x20eb489),
 ('payload_duplicate_choice', 0x20eb8d3, 0x20eb92c),
 ('payload_duplicate_chain', 0x20eb92c, 0x20eb985),
 ('payload_duplicate_id', 0x20eb985, 0x20eb9de),
 ('payload_duplicate_signature', 0x20eb9de, 0x20eba37),
 ('payload_duplicate_nonce', 0x20eba37, 0x20eba90),
 ('vote_core_lookup', 0x3c33f10, 0x3c3407d),
 ('vote_core_cursor_and_repeat', 0x3c3407d, 0x3c34100),
 ('vote_core_key_checks', 0x3c341a8, 0x3c34242),
 ('vote_core_missing_results', 0x3c3431e, 0x3c34339),
 ('vote_core_time_multiplier', 0x3c34391, 0x3c34411),
 ('vote_core_representation', 0x3c3454f, 0x3c3460b),
 ('vote_core_compact_insert', 0x3c3460b, 0x3c34663),
 ('vote_core_tree_update', 0x3c346a1, 0x3c3478f),
 ('vote_core_tree_insert_and_bounds', 0x3c3478f, 0x3c34864),
 ('amount_lookup_and_return', 0x4221c77, 0x4221c9b),
 ('amount_sum_fast', 0x434f444, 0x434f4d1),
 ('amount_sum_general', 0x434f4d1, 0x434f57b),
 ('history_update_comparison', 0x4221e94, 0x4221f3c),
 ('tree_root_insert', 0x370a675, 0x370a7aa),
 ('tree_nonempty_insert', 0x3513d50, 0x3513e93),
 ('compact_insert_and_failure', 0x454c990, 0x454ca95),
)

# Each site is an individually verified instruction start. This is an
# explicitly selected set, not a byte-scan function census or complete CFG.
BRANCH_SITES = (
 ('outer_sequence_kind', 0x20f00cf), ('outer_invalid_kind', 0x20f00d9),
 ('outer_duplicate_action', 0x20f0688), ('outer_map_action_error', 0x20f06dc),
 ('outer_sequence_action_error', 0x20f0a37), ('outer_action_missing', 0x20f08aa),
 ('context_name_length_range', 0x2ba0a80), ('context_name_preceding_match', 0x2ba1501),
 ('context_name_reject', 0x2ba1518), ('content_key_duplicate', 0x1fcd104),
 ('content_name_error', 0x1fcd154), ('content_missing_type', 0x1fcd169),
 ('content_sequence_name_result', 0x1fcd370), ('action_envelope_success', 0x2b81838),
 ('action_payload_error', 0x2b81afd), ('action_box_allocation_failure', 0x2b84303),
 ('primary_sequence_kind', 0x20aedd6), ('primary_invalid_kind', 0x20aeddf),
 ('primary_duplicate_signature', 0x20af0ec), ('primary_duplicate_chain', 0x20af3ad),
 ('primary_duplicate_id', 0x20af293), ('primary_duplicate_choice', 0x20af33d),
 ('primary_duplicate_nonce', 0x20af1fb), ('primary_signature_missing', 0x20af5df),
 ('primary_chain_present', 0x20af5ed), ('primary_id_missing', 0x20af6e2),
 ('primary_choice_present', 0x20af6f3), ('primary_nonce_present', 0x20af87c),
 ('validation_status_error', 0x36c22e2), ('validation_fallback_flag', 0x36c22ea),
 ('validation_chain_differs', 0x44f565a), ('validation_control_flag_set', 0x44f5664),
 ('validation_nonce_differs', 0x44f5672), ('validation_control_word_zero', 0x44f567c),
 ('validation_first_helper_error', 0x44f56a1), ('validation_second_helper_error', 0x44f56d3),
 ('digest_input_error', 0x46e4d00), ('digest_format_fallback', 0x46e4eb5),
 ('signature_selector_above_table', 0x1536b35), ('signature_selector_invalid_middle', 0x1536b52),
 ('signature_first_backend_failure', 0x1536bad), ('signature_second_backend_failure', 0x1536cc3),
 ('payload_is_sequence', 0x20ea773), ('payload_invalid_kind', 0x20ea77c),
 ('sequence_missing_first', 0x20ea850), ('sequence_sentinel_first', 0x20ea861),
 ('sequence_first_decode_error', 0x20ea944), ('sequence_first_length_over32', 0x20ea953),
 ('sequence_second_sentinel', 0x20ea9a8), ('map_key_kind_outside', 0x20eaa98),
 ('map_key_decode_error', 0x20eabc4), ('duplicate_signature', 0x20eabe8),
 ('signature_decode_error', 0x20eac80), ('signature_length_over32', 0x20eac8f),
 ('duplicate_nonce', 0x20ead14), ('duplicate_id', 0x20eadb2),
 ('id_value_error', 0x20eae0c), ('duplicate_choice', 0x20eae41),
 ('choice_value_error', 0x20eae94), ('duplicate_chain', 0x20eaeb0),
 ('chain_value_error', 0x20eaf03), ('signature_present', 0x20eb106),
 ('chain_present', 0x20eb1d1), ('chain_missing_error', 0x20eb229),
 ('id_missing', 0x20eb237), ('choice_present', 0x20eb240),
 ('choice_missing_error', 0x20eb29a), ('nonce_present', 0x20eb2aa),
 ('nonce_missing_error', 0x20eb2ff), ('payload_output_error_niche', 0x20eb36d),
 ('payload_trailing_result', 0x20eb38a),
 ('proposal_representation', 0x3c33f3e), ('proposal_tree_absent', 0x3c33f4e),
 ('proposal_tree_equal', 0x3c33fe8), ('proposal_tree_exhausted', 0x3c34003),
 ('proposal_compact_absent', 0x3c34030), ('proposal_compact_bounds', 0x3c34046),
 ('deadline_major_equal', 0x3c34085), ('deadline_minor_equal', 0x3c340b0),
 ('deadline_last_not_later', 0x3c340bc), ('deadline_later', 0x3c340c9),
 ('vote_representation', 0x3c340ea), ('vote_tree_empty', 0x3c340fa),
 ('vote_tree_duplicate', 0x3c34174), ('vote_compact_duplicate', 0x3c341bf),
 ('amount_absent_or_zero', 0x3c341f8), ('lock_representation', 0x3c34253),
 ('lock_tree_empty', 0x3c34263), ('lock_tree_equal', 0x3c342eb),
 ('lock_compact_absent', 0x3c3434a), ('lock_compact_bounds', 0x3c34357),
 ('lock_marker_zero', 0x3c3439e), ('lock_major_differs', 0x3c343a7),
 ('lock_minor_differs', 0x3c343b3), ('lock_final_earlier', 0x3c343bc),
 ('lock_not_earlier', 0x3c343c9), ('multiply_high_bits_nonzero', 0x3c343d7),
 ('tree_representation_threshold', 0x3c3440b), ('compact_capacity_threshold', 0x3c34586),
 ('tree_representation_selected', 0x3c3455c), ('compact_branch', 0x3c34605),
 ('tree_find_existing', 0x3c34731), ('tree_search_exhausted', 0x3c34748),
 ('tree_insert_result', 0x3c347f4), ('tree_insert_bounds', 0x3c3480e),
 ('compact_insert_bounds', 0x3c34819),
 ('amount_sum_carry_fast', 0x434f47a), ('amount_sum_carry_general', 0x434f550),
 ('amount_sum_fast_end', 0x434f486), ('amount_sum_tag', 0x434f451),
 ('history_major_differs', 0x4221efe), ('history_minor_differs', 0x4221f08),
 ('history_final_less', 0x4221f13), ('history_less', 0x4221f26),
 ('root_nonempty', 0x370a67a), ('root_allocation_failed', 0x370a6f0),
 ('root_slot_bounds', 0x370a722), ('tree_node_full', 0x3513d79),
 ('tree_insert_shift', 0x3513d95), ('tree_allocation_failed', 0x3513edf),
 ('compact_index_invalid', 0x454c99f), ('compact_grow', 0x454c9b4),
 ('compact_move_direction', 0x454c9d0),
)

# Calls/jumps through RIP slots are RELATIVE only if explicitly classified as
# such; external import slots are reported as slots, not invented callees.
CALL_SITES = (
 ('outer_map_action_decode', 0x20f06d3), ('outer_sequence_action_decode', 0x20f0a29),
 ('outer_missing_action', 0x20f08c7), ('outer_duplicate_action', 0x20f1059),
 ('action_call_envelope', 0x2b81827), ('content_map_name', 0x1fcd14a),
 ('content_sequence_name', 0x1fcd363), ('content_borrowed_name_match', 0x21dfcc7),
 ('content_owned_name_match', 0x21dfd1e), ('action_to_primary_payload', 0x2b81af3),
 ('content_duplicate_type_error', 0x1fcd5ef), ('content_missing_type_error', 0x1fcd658),
 ('action_box_alloc', 0x2b842fa), ('action_box_copy', 0x2b84318),
 ('primary_payload_id', 0x20af2da), ('primary_payload_choice', 0x20af384),
 ('primary_duplicate_choice', 0x20afb84), ('primary_missing_signature', 0x20af672),
 ('validation_vote_body', 0x36c22b5), ('validation_generic_fallback', 0x36c208b),
 ('validation_first_helper', 0x44f5697), ('validation_second_helper', 0x44f56c8),
 ('validation_error_helper', 0x44f5778),
 ('digest_input', 0x46e4cf6), ('digest_error_allocate', 0x46e4dea),
 ('digest_error_copy', 0x46e4e02), ('digest_error_cleanup', 0x46e4e29),
 ('signature_first_backend', 0x1536ba4), ('signature_second_backend', 0x1536cba),
 ('signature_third_backend', 0x1536db4), ('signature_hash_init', 0x1536e9a),
 ('signature_hash_input', 0x1536eb3), ('signature_hash_finish', 0x1536ec6),
 ('signature_error_builder', 0x1536f14),
 ('context_wrapper_to_core', 0x2457aac),
 ('payload_signature', 0x20eac72), ('payload_id', 0x20eae02),
 ('payload_choice', 0x20eae88), ('payload_chain', 0x20eaef7),
 ('payload_missing_signature', 0x20eb154), ('payload_missing_chain', 0x20eb218),
 ('payload_missing_choice', 0x20eb289), ('payload_missing_nonce', 0x20eb2f3),
 ('payload_missing_id', 0x20eb466),
 ('proposal_compact_find', 0x3c34025), ('vote_compact_find', 0x3c341b7),
 ('lookup_amount', 0x3c341ef), ('update_cursor_history', 0x3c3423d),
 ('lookup_lock_compact', 0x3c34343), ('convert_vote_storage', 0x3c344a4),
 ('convert_vote_iter', 0x3c34526), ('find_compact_insert', 0x3c3456c),
 ('convert_compact_storage', 0x3c345c4), ('insert_compact_record', 0x3c34651),
 ('insert_tree_record', 0x3c347dd), ('bounds_failure', 0x3c3485e),
 ('unwind_1', 0x3c3488d), ('unwind_2', 0x3c348a9),
 ('aggregate_amount', 0x4221c7c), ('amount_compact_lookup', 0x4221b71),
 ('cursor_compact_lookup', 0x4221d91), ('cursor_iter_start', 0x4221ea7),
 ('cursor_iter_next', 0x4221edf), ('tree_nonempty_insert', 0x370a6c4),
 ('tree_alloc', 0x370a6e7), ('tree_allocation_failure', 0x370a78b),
 ('tree_shift_keys', 0x3513e20), ('tree_shift_values', 0x3513e55),
 ('tree_allocate_split', 0x3513ed6), ('compact_grow', 0x454c9b9),
 ('compact_shift_tail', 0x454ca01), ('compact_shift_head', 0x454ca32),
 ('compact_failure', 0x454ca8f),
)

# location, opcode prefix, immediate byte width; values are extracted, not
# substituted from the reference source.
IMMEDIATES = (
 ('validation_tag_bias', 0x36c2062, '482d', 4),
 ('validation_chain_word', 0x44f5653, '66bf', 2),
 ('validation_flag_word', 0x44f565c, '66bf', 2),
 ('validation_nonce_word', 0x44f566a, '66bf', 2),
 ('validation_control_word', 0x44f5674, '66bf', 2),
 ('validation_helper_error_word', 0x44f56e1, '66bf', 2),
 ('validation_success_word', 0x44f5740, '66bf', 2),
 ('signature_table_upper', 0x1536b31, '4883f8', 1),
 ('signature_invalid_upper', 0x1536b50, '3c', 1),
 ('signature_backend_error', 0x1536f0f, 'bf', 4),
 ('signature_selector_error', 0x1536f22, 'bf', 4),
 ('decoded_tag', 0x2b81b44, '41be', 4),
 ('context_type_key_length', 0x2b817f3, '48c7842418010000', 4),
 ('context_action_box_size', 0x2b842f5, 'bf', 4),
 ('name_ordinal', 0x2ba151e, 'c64001', 1),
 ('payload_kind_sequence', 0x20ea767, '83f8', 1),
 ('payload_kind_map', 0x20ea779, '83f8', 1),
 ('payload_signature_length_limit_exclusive', 0x20eac8b, '4883fa', 1),
 ('payload_error_marker', 0x2b81af8, '807c2469', 1),
 ('proposal_missing', 0x3c3402a, '66be', 2),
 ('proposal_expired', 0x3c340b5, '66be', 2),
 ('duplicate_vote', 0x3c3431e, '66be', 2),
 ('no_amount', 0x3c34327, '66be', 2),
 ('core_success', 0x3c3476e, '66be', 2),
 ('bonus_high_bits_shift', 0x3c343d3, '48c1e8', 1),
 ('bonus_amount_shift', 0x3c343d9, '48c1e1', 1),
 ('tree_to_compact_threshold', 0x3c343fa, '4883f8', 1),
 ('compact_to_tree_threshold', 0x3c3457b, '4883fe', 1),
 ('new_tree_alloc_bytes', 0x370a6e2, 'bf', 4),
 ('tree_node_max_slots', 0x370a71e, '4883f9', 1),
 ('nonempty_node_max_slots', 0x3513d75, '4983fc', 1),
 ('sum_item_stride', 0x434f491, '488d72', 1),
)

# duplicate-branch site, error-literal LEA, missing-literal LEA, missing guard.
PRIMARY_FIELD_ROUTES = (
 (0x20af0e3, 0x20af0ec, 0x20afc59, 0x20af636, 0x20af5df),
 (0x20af3a5, 0x20af3ad, 0x20afba3, 0x20af5f3, 0x20af5ed),
 (0x20af28b, 0x20af293, 0x20afbfe, 0x20af798, 0x20af6e2),
 (0x20af335, 0x20af33d, 0x20afb48, 0x20af6f9, 0x20af6f3),
 (0x20af1f2, 0x20af1fb, 0x20afcb4, 0x20af925, 0x20af87c),
)

FIELD_ROUTES = (
 (0x20eabe8, 0x20eb9ee, 0x20eb10c, 0x20eb106),
 (0x20eaeb0, 0x20eb93c, 0x20eb1d3, 0x20eb1d1),
 (0x20eadb2, 0x20eb995, 0x20eb423, 0x20eb237),
 (0x20eae41, 0x20eb8e3, 0x20eb244, 0x20eb240),
 (0x20ead14, 0x20eba47, 0x20eb2ae, 0x20eb2aa),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data, expected=DIGEST):
    require(hashlib.sha256(data).hexdigest() == expected, 'artifact SHA-256 mismatch')


def validate_body(name, raw, expected_hash):
    require(hashlib.sha256(raw).hexdigest() == expected_hash, 'selected body digest mismatch for ' + name)


def file_offset(secs, va, size, executable=False):
    require(type(va) is int and type(size) is int and 0 <= va < 1 << 64 and 0 < size <= (1 << 64) - va,
            'invalid virtual address range')
    hits = [s for s in secs if s['type'] != 8 and s['address'] <= va
            and va + size <= s['address'] + s['size'] and (not executable or s['flags'] & 4)]
    require(len(hits) == 1, 'address range is not uniquely file-backed in a suitable section')
    return hits[0]['offset'] + va - hits[0]['address']


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        rela = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
        require(len(rela) == 1 and rela[0]['size'] % 24 == 0, 'invalid relocation section')
        self.relocs = {}
        for off in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            require(slot not in self.relocs, 'duplicate relocation slot')
            self.relocs[slot] = (info, addend, off)

    def offset(self, va, size, executable=False):
        off = file_offset(self.sections, va, size, executable)
        require(off + size <= len(self.data), 'file range exceeds input')
        return off

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return self.data[off:off + size]

    def expect(self, va, pattern, executable=True):
        raw = self.read(va, len(pattern), executable)
        require(raw == pattern, 'instruction or data anchor mismatch at ' + hex(va))
        return raw

    def symbol(self, index):
        dynsym = [s for s in self.sections if s['name'] == '.dynsym' and s['type'] == 11]
        dynstr = [s for s in self.sections if s['name'] == '.dynstr' and s['type'] == 3]
        require(len(dynsym) == 1 and len(dynstr) == 1, 'missing dynamic symbol tables')
        syms, strings = dynsym[0], dynstr[0]
        require(type(index) is int and index >= 0 and index * 24 + 24 <= syms['size'], 'dynamic symbol index out of bounds')
        record_off = syms['offset'] + index * 24
        name_off = struct.unpack_from('<I', self.data, record_off)[0]
        require(name_off < strings['size'], 'dynamic string offset out of bounds')
        start = strings['offset'] + name_off
        end = self.data.find(b'\x00', start, strings['offset'] + strings['size'])
        require(end >= 0, 'unterminated dynamic symbol name')
        return bytes(self.data[start:end]).decode('ascii')

    def relative(self, slot):
        require(slot in self.relocs, 'missing relocation')
        info, addend, off = self.relocs[slot]
        require(info == 8 and addend >= 0, 'relocation is not symbol-free x86-64 RELATIVE')
        return addend, off


def rip_target(image, va, prefix):
    require(len(prefix) == 3, 'unsupported RIP prefix')
    raw = image.read(va, 7, True)
    require(raw[:3] == prefix, 'RIP instruction mismatch at ' + hex(va))
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def branch(image, va):
    raw = image.read(va, 1, True)
    op = raw[0]
    if op == 0x0f:
        raw = image.read(va, 6, True)
        require(0x80 <= raw[1] <= 0x8f, 'unsupported near branch')
        size, displacement, kind = 6, struct.unpack_from('<i', raw, 2)[0], 'jcc'
    elif 0x70 <= op <= 0x7f:
        raw = image.read(va, 2, True)
        size, displacement, kind = 2, struct.unpack_from('<b', raw, 1)[0], 'jcc'
    elif op in (0xe8, 0xe9):
        raw = image.read(va, 5, True)
        size, displacement, kind = 5, struct.unpack_from('<i', raw, 1)[0], 'call' if op == 0xe8 else 'jmp'
    elif op == 0xeb:
        raw = image.read(va, 2, True)
        size, displacement, kind = 2, struct.unpack_from('<b', raw, 1)[0], 'jmp'
    else:
        raise ValueError('unsupported branch opcode at ' + hex(va))
    target = va + size + displacement
    image.offset(target, 1, True)
    return kind, target, raw


def call(image, va):
    prefix = image.read(va, 2, True)
    if prefix[0] == 0xe8:
        kind, target, raw = branch(image, va)
        return kind, target, None, None, raw
    require(prefix == b'\xff\x15', 'unsupported selected call at ' + hex(va))
    raw = image.read(va, 6, True)
    slot = va + 6 + struct.unpack_from('<i', raw, 2)[0]
    image.offset(slot, 8)
    require(slot in image.relocs, 'selected call slot lacks relocation')
    info, addend, rel_off = image.relocs[slot]
    return 'rip-slot', addend if info == 8 else None, slot, (info, rel_off), raw


def table_entry(image, base, index, count):
    require(type(index) is int and type(count) is int and 0 <= index < count, 'table index out of bounds')
    slot = base + index * 4
    raw = image.read(slot, 4)
    target = base + struct.unpack('<i', raw)[0]
    image.offset(target, 1, True)
    return slot, target, raw


def immediate(image, va, prefix, width):
    p = bytes.fromhex(prefix)
    raw = image.read(va, len(p) + width, True)
    require(raw.startswith(p), 'immediate instruction mismatch at ' + hex(va))
    return int.from_bytes(raw[len(p):], 'little'), raw


def hexbytes(data):
    return data.hex()


def tsv(rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()


def to_signed32(x):
    require(type(x) is int and 0 <= x < (1 << 32), 'cursor component is not u32')
    return x - (1 << 32) if x >= 1 << 31 else x


def cursor_cmp(a, b):
    require(len(a) == 3 and len(b) == 3, 'cursor must have three components')
    aa = (to_signed32(a[0]), a[1], a[2])
    bb = (to_signed32(b[0]), b[1], b[2])
    for value in aa[1:] + bb[1:]:
        require(type(value) is int and 0 <= value < 1 << 32, 'cursor component is not u32')
    return (aa > bb) - (aa < bb)


def updated_cursor(previous, candidate):
    return candidate if cursor_cmp(previous, candidate) < 0 else previous


def checked_sum(values):
    total = 0
    for n in values:
        require(type(n) is int and 0 <= n < 1 << 64, 'amount is not u64')
        total += n
        if total >= 1 << 64:
            return None
    return total


def effective_amount(amount, now, locked_until):
    require(type(amount) is int and 0 <= amount < 1 << 64, 'amount is not u64')
    if locked_until is None or locked_until[0] == 0 or cursor_cmp(now, locked_until) >= 0:
        return amount, 'clear_or_absent'
    if amount >> 62:
        return amount, 'high_bits_preserve'
    return amount << 2, 'multiply'


def signature_selector(value):
    """Model the selected byte's normalization; None is the observed error path."""
    require(type(value) is int and 0 <= value <= 255, 'signature selector is not a byte')
    if value in (0, 27):
        return 0
    if value in (1, 28):
        return 1
    if value <= 34:
        return None
    return (~value) & 1


def validation_prefix(chain_equal, control_bit, nonce_equal, control_word_zero):
    """Model only the four ordered comparisons, not cryptographic verification."""
    if not chain_equal:
        return 0x93
    if control_bit:
        return 0x15
    if not nonce_equal:
        return 0x60
    if not control_word_zero:
        return 0x90
    return None


def vote_decision(proposal, now, deadline, duplicate, amounts, locked_until=None):
    """Synthetic model of selected ordered normal-return checks, not execution."""
    if not proposal:
        return 0x114, None
    if cursor_cmp(now, deadline) > 0:
        return 0x117, None
    if duplicate:
        return 0x115, None
    amount = checked_sum(amounts)
    if not amount:
        return 0x116, None
    value, _ = effective_amount(amount, now, locked_until)
    return 0x1a2, value


def build(data):
    verify_digest(data)
    image = Image(data)
    _, headers = unwind_index(data)
    _, all_fdes = eh_frame_records(data, image.sections)
    by_start = {}
    for item in all_fdes:
        by_start.setdefault(item['start'], []).append(item)
    by_header = {row['start']: row for row in headers}
    funcs = [['name', 'start_va', 'end_va_exclusive', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'byte_length', 'sha256']]
    bodies = [['name', 'start_va', 'end_va_exclusive', 'raw_hex']]
    for name, start, end, expected_hash in FUNCTIONS:
        matches = by_start.get(start, [])
        require(len(matches) == 1 and matches[0]['end'] == end, 'FDE range mismatch for ' + name)
        fde = matches[0]
        require(start in by_header and by_header[start]['fde'] == fde['fde'], 'FDE header mismatch for ' + name)
        raw = image.read(start, end - start, True)
        digest = hashlib.sha256(raw).hexdigest()
        validate_body(name, raw, expected_hash)
        funcs.append([name, hex(start), hex(end), hex(image.offset(start, len(raw), True)), hex(fde['fde']),
                      hex(fde['cie']), '' if fde['lsda'] is None else hex(fde['lsda']), len(raw), digest])
        bodies.append([name, hex(start), hex(end), raw.hex()])

    immrows = [['name', 'instruction_va', 'file_offset', 'raw_hex', 'value_decimal', 'value_hex']]
    imm = {}
    for name, va, prefix, width in IMMEDIATES:
        value, raw = immediate(image, va, prefix, width)
        imm[name] = value
        immrows.append([name, hex(va), hex(image.offset(va, len(raw), True)), raw.hex(), value, hex(value)])
    require(imm['core_success'] == 0x1a2, 'success word mismatch')
    require(tuple(imm[n] for n in ('proposal_missing', 'duplicate_vote', 'no_amount', 'proposal_expired'))
            == (0x114, 0x115, 0x116, 0x117), 'selected result word mismatch')
    require(imm['validation_tag_bias'] == 0x86 and imm['decoded_tag'] == 0xb8, 'action tag mismatch')
    require(tuple(imm[n] for n in ('validation_chain_word', 'validation_flag_word',
            'validation_nonce_word', 'validation_control_word', 'validation_helper_error_word',
            'validation_success_word')) == (0x93, 0x15, 0x60, 0x90, 0x7e, 0x1a2), 'validation word mismatch')
    require(tuple(imm[n] for n in ('signature_table_upper', 'signature_invalid_upper',
            'signature_backend_error', 'signature_selector_error')) == (28, 34, 3, 6), 'signature selector operands mismatch')
    image.expect(0x1536b58, bytes.fromhex('f7d083e00189c1'))
    require(imm['context_type_key_length'] == 4 and imm['context_action_box_size'] == 0xf0, 'context size mismatch')
    require(imm['bonus_high_bits_shift'] == 62 and imm['bonus_amount_shift'] == 2, 'bonus operation mismatch')

    # Contextual name matcher: length 7 selects this arm, then two four-byte
    # immediate comparisons overlap at one byte. Recover all seven bytes.
    name_dispatch = rip_target(image, 0x2ba0a86, bytes.fromhex('488d3d'))
    name_slot, name_arm, name_entry = table_entry(image, name_dispatch, 7 - 4, 0x25)
    require(name_arm == 0x2ba14f0, 'name length table mismatch')
    p1 = image.read(0x2ba1507, 5, True)
    p2 = image.read(0x2ba150e, 5, True)
    require(p1[:1] == b'\xb9' and p2[:1] == b'\xbf' and p1[4] == p2[1], 'name comparisons mismatch')
    action_name = p1[1:5] + p2[2:5]
    require(action_name == b'govVote', 'name match result mismatch')
    ordinal = imm['name_ordinal']
    require(ordinal == imm['decoded_tag'] - imm['validation_tag_bias'], 'ordinal does not match action tag')
    image.expect(0x2ba0a78, bytes.fromhex('488d4afc4883f924'))
    image.expect(0x2ba150c, bytes.fromhex('330e'))
    image.expect(0x2ba1513, bytes.fromhex('337e0309cf'))
    image.expect(0x2b81878, bytes.fromhex('486304814801c8ffe0'))
    require(image.read(rip_target(image, 0x2b817e4, bytes.fromhex('488d05')), imm['context_type_key_length']) == b'type', 'type key literal mismatch')
    image.expect(0x1fcd15a, bytes.fromhex('440fb66c2451'))
    image.expect(0x1fcd191, bytes.fromhex('45882c2441c644240815'))
    image.expect(0x2b8182c, bytes.fromhex('0fb6442428'))
    image.expect(0x2b8186e, bytes.fromhex('0fb6c3'))
    image.expect(0x2b81aed, bytes.fromhex('41b905000000'))
    require(image.read(rip_target(image, 0x2b81ad2, bytes.fromhex('488d15')), 13) == b'GovVoteAction', 'payload type literal mismatch')

    table_rows = [['name', 'index', 'table_va', 'slot_va', 'file_offset', 'slot_raw_hex', 'target_va']]
    def add_table(name, base, index, count, expected):
        slot, target, raw = table_entry(image, base, index, count)
        require(target == expected, 'unexpected selected table entry for ' + name)
        table_rows.append([name, index, hex(base), hex(slot), hex(image.offset(slot, 4)), raw.hex(), hex(target)])
        return target
    table_rows.append(['context_name_length7', 3, hex(name_dispatch), hex(name_slot),
                       hex(image.offset(name_slot, 4)), name_entry.hex(), hex(name_arm)])
    action_table = rip_target(image, 0x2b81871, bytes.fromhex('488d0d'))
    validation_table = rip_target(image, 0x36c2075, bytes.fromhex('488d05'))
    envelope_input_table = rip_target(image, 0x1fccd97, bytes.fromhex('488d0d'))
    content_name_table = rip_target(image, 0x21dfca9, bytes.fromhex('488d0d'))
    add_table('content_map_kind', envelope_input_table, 21, 22, 0x1fccdd3)
    add_table('content_name_borrowed_kind', content_name_table, 12, 15, 0x21dfcbf)
    add_table('content_name_owned_kind', content_name_table, 11, 15, 0x21dfd0f)
    add_table('action_payload', action_table, ordinal, ordinal + 1, 0x2b81ad2)
    add_table('validation_action', validation_table, ordinal, ordinal + 1, 0x36c22a0)
    primary_field_table = rip_target(image, 0x20af0d3, bytes.fromhex('488d0d'))
    for i, (arm, _, _, _, _) in enumerate(PRIMARY_FIELD_ROUTES):
        add_table('primary_payload_field', primary_field_table, i, len(PRIMARY_FIELD_ROUTES), arm)
    signature_table = rip_target(image, 0x1536b39, bytes.fromhex('488d15'))
    for i in range(imm['signature_table_upper'] + 1):
        expected = 0x1536b5f if i in (0, 27) else 0x1536b49 if i in (1, 28) else 0x1536b50
        add_table('signature_byte', signature_table, i, imm['signature_table_upper'] + 1, expected)
    field_table = rip_target(image, 0x20eabcf, bytes.fromhex('488d0d'))
    field_arms = (0x20eabdf, 0x20eaea8, 0x20eadaa, 0x20eae3c, 0x20ead0b)
    for i, arm in enumerate(field_arms):
        add_table('payload_field', field_table, i, len(field_arms), arm)

    descriptor = rip_target(image, 0x2b81ad9, bytes.fromhex('4c8d05'))
    fields = [['index', 'name', 'descriptor_va', 'descriptor_file_offset', 'relocation_file_offset',
               'literal_va', 'literal_length', 'literal_hex', 'field_arm_va', 'duplicate_branch_va',
               'duplicate_target_va', 'duplicate_name_va', 'missing_guard_va', 'missing_name_va',
               'primary_arm_va', 'primary_duplicate_branch_va', 'primary_duplicate_target_va',
               'primary_duplicate_name_va', 'primary_missing_guard_va', 'primary_missing_name_va']]
    expected_names = ('signatureChainId', 'hyperliquidChain', 'id', 'choice', 'nonce')
    for i, (dup, dup_lea, missing_lea, missing_guard) in enumerate(FIELD_ROUTES):
        slot = descriptor + i * 16
        string_va, reloc_off = image.relative(slot)
        length = struct.unpack('<Q', image.read(slot + 8, 8))[0]
        require(0 < length <= 32, 'field name length is outside profile')
        name_raw = image.read(string_va, length)
        name = name_raw.decode('ascii')
        require(name == expected_names[i], 'unexpected field descriptor')
        dup_target = branch(image, dup)[1]
        dup_name = rip_target(image, dup_lea, bytes.fromhex('488d05'))
        missing_name = rip_target(image, missing_lea, bytes.fromhex('488d05'))
        require(image.read(dup_name, length) == name_raw == image.read(missing_name, length), 'field diagnostics disagree')
        require(dup_target <= dup_lea < dup_target + 32, 'duplicate path does not reach its selected literal')
        primary_arm, primary_dup, primary_dup_lea, primary_missing_lea, primary_missing_guard = PRIMARY_FIELD_ROUTES[i]
        primary_target = branch(image, primary_dup)[1]
        primary_dup_name = rip_target(image, primary_dup_lea, bytes.fromhex('488d05'))
        primary_missing_name = rip_target(image, primary_missing_lea, bytes.fromhex('488d05'))
        require(image.read(primary_dup_name, length) == name_raw == image.read(primary_missing_name, length),
                'primary field diagnostics disagree')
        require(primary_target <= primary_dup_lea < primary_target + 32, 'primary duplicate route mismatch')
        fields.append([i, name, hex(slot), hex(image.offset(slot, 16)), hex(reloc_off), hex(string_va),
                       length, name_raw.hex(), hex(field_arms[i]), hex(dup), hex(dup_target), hex(dup_name),
                       hex(missing_guard), hex(missing_name), hex(primary_arm), hex(primary_dup),
                       hex(primary_target), hex(primary_dup_name), hex(primary_missing_guard), hex(primary_missing_name)])

    branches = [['name', 'site_va', 'file_offset', 'kind', 'raw_hex', 'target_va']]
    for name, site in BRANCH_SITES:
        kind, target, raw = branch(image, site)
        require(kind == 'jcc', 'selected branch is not conditional')
        branches.append([name, hex(site), hex(image.offset(site, len(raw), True)), kind, raw.hex(), hex(target)])

    calls = [['name', 'site_va', 'file_offset', 'kind', 'raw_hex', 'slot_va', 'relocation_info',
              'relocation_file_offset', 'resolved_target_va', 'dynamic_symbol']]
    for name, site in CALL_SITES:
        kind, target, slot, reloc, raw = call(image, site)
        info, rel_off = reloc if reloc is not None else (None, None)
        symbol = image.symbol(info >> 32) if info is not None and info & 0xffffffff in (6, 7) else ''
        calls.append([name, hex(site), hex(image.offset(site, len(raw), True)), kind, raw.hex(),
                      '' if slot is None else hex(slot), '' if info is None else hex(info),
                      '' if rel_off is None else hex(rel_off), '' if target is None else hex(target), symbol])
    for va, target in ((0x20f06d3, 0x2b817d0), (0x20f0a29, 0x2b817d0),
                       (0x2b81827, 0x1fccd80), (0x1fcd14a, 0x21dfc90),
                       (0x21dfcc7, 0x2ba0a70), (0x2b81af3, 0x20aedb0),
                       (0x36c22b5, 0x44f5650), (0x36c208b, 0x36aadf0),
                       (0x44f5697, 0x46e4ce0), (0x44f56c8, 0x1536a90),
                       (0x2457aac, 0x3c33f10),
                       (0x3c341ef, 0x4221a90), (0x3c3423d, 0x4221ca0),
                       (0x4221c7c, 0x434f410), (0x3c347dd, 0x370a660),
                       (0x370a6c4, 0x3513d50), (0x3c34651, 0x454c990)):
        require(call(image, va)[1] == target, 'selected call target mismatch at ' + hex(va))

    literals = [['name', 'instruction_va', 'literal_va', 'file_offset', 'length', 'raw_hex']]
    for label, site, prefix, expected in (
        ('digest_json_error', 0x46e4d68, '4c8d3d', b'Failed to serialize serde JSON object'),
        ('digest_hex_error', 0x46e4dce, '4c8d3d', b'Failed to decode hex value'),
        ('digest_struct_hash_error', 0x46e4db0, '4c8d3d', b'Failed to make struct hash from values'),
        ('digest_slice_error', 0x46e4dbf, '4c8d3d', b'Failed to convert slice into byte array'),
        ('digest_nested_error', 0x46e4da1, '4c8d3d', b'Nested Eip712 struct not implemented. Failed to parse.'),
        ('outer_action_field', 0x20f1003, '488d05', b'action'),
        ('outer_duplicate_format', 0x20f103d, '488d3d', b'\x11duplicate field `'),
        ('type_key', 0x2b817e4, '488d05', b'type'),
        ('action_type', 0x2b81ad2, '488d15', b'GovVoteAction'),
        ('payload_missing_format', 0x20eb140, '488d35', b'\x0fmissing field `'),
        ('payload_duplicate_format', 0x20eb90e, '488d35', b'\x11duplicate field `'),
        ('content_missing_format', 0x1fcd64e, '488d3d', b'\x0fmissing field `'),
        ('content_duplicate_format', 0x1fcd5e5, '488d3d', b'\x11duplicate field `'),
    ):
        at = rip_target(image, site, bytes.fromhex(prefix))
        raw = image.read(at, len(expected))
        require(raw == expected, 'selected literal mismatch')
        literals.append([label, hex(site), hex(at), hex(image.offset(at, len(raw))), len(raw), raw.hex()])

    wins = [['name', 'start_va', 'end_va_exclusive', 'file_offset', 'byte_length', 'sha256', 'raw_hex']]
    for name, start, end in WINDOWS:
        raw = image.read(start, end - start, True)
        wins.append([name, hex(start), hex(end), hex(image.offset(start, len(raw), True)),
                     len(raw), hashlib.sha256(raw).hexdigest(), raw.hex()])

    # The condition column names the branch's observed direction; result words
    # come from actual little-endian instruction operands in this image.
    flow = [['stage', 'branch_va', 'branch_target_va', 'site_bytes', 'result_word', 'notes']]
    for label, site, word, notes in (
        ('proposal_compact_missing', 0x3c34030, 'proposal_missing', 'taken after low-bit test'),
        ('proposal_compact_bounds', 0x3c34046, 'proposal_missing', 'taken after unsigned bound'),
        ('proposal_tree_empty', 0x3c33f4e, 'proposal_missing', 'taken loads same word'),
        ('deadline_last_not_later', 0x3c340bc, 'proposal_expired', 'fallthrough stores word; taken continues'),
        ('deadline_earlier_fields_later', 0x3c340c9, 'proposal_expired', 'taken stores word'),
        ('vote_tree_duplicate', 0x3c34174, 'duplicate_vote', 'taken loads word'),
        ('vote_compact_duplicate', 0x3c341bf, 'duplicate_vote', 'taken loads word'),
        ('voter_amount_zero', 0x3c341f8, 'no_amount', 'taken loads word'),
        ('tree_existing_vote_write', 0x3c34731, 'core_success', 'taken writes two value lanes then loads word'),
        ('tree_insert_result', 0x3c347f4, 'core_success', 'word loaded after insertion call'),
    ):
        _, target, raw = branch(image, site)
        flow.append([label, hex(site), hex(target), raw.hex(), hex(imm[word]), notes])

    summary = {
        'target_release': 'node 115', 'binary_sha256': DIGEST, 'coordinate_system': 'linked ELF virtual address',
        'action_name_from_compare_bytes': action_name.decode('ascii'), 'ordinal': ordinal,
        'stored_tag': hex(imm['decoded_tag']), 'tag_bias': hex(imm['validation_tag_bias']),
        'selected_fde_count': len(FUNCTIONS), 'selected_byte_windows': len(WINDOWS),
        'selected_branch_sites': len(BRANCH_SITES), 'selected_call_sites': len(CALL_SITES),
        'field_descriptors': len(FIELD_ROUTES), 'selected_switch_entries': len(table_rows)-1,
        'selected_literals': len(literals)-1,
        'decision_rows': len(flow)-1,
        'limitations': 'Static selected windows and inferred models, not a complete CFG, runtime trace, implementation, or equivalence.',
    }
    return {
        'identity.json': json_bytes(summary), 'functions.tsv': tsv(funcs), 'bodies.tsv': tsv(bodies),
        'windows.tsv': tsv(wins), 'branches.tsv': tsv(branches), 'calls.tsv': tsv(calls),
        'switches.tsv': tsv(table_rows), 'fields.tsv': tsv(fields),
        'immediates.tsv': tsv(immrows), 'decision-path.tsv': tsv(flow), 'literals.tsv': tsv(literals),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    records = build(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(records):
        (args.out / name).write_bytes(records[name])
    print('Generated ' + str(len(records)) + ' deterministic evidence files for node 115.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error, UnicodeError) as exc:
        print('re010_gov_vote_115: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
