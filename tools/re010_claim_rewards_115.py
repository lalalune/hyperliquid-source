#!/usr/bin/env python3
"""Reproduce selected node-115 claim-reward path evidence from ELF bytes.

This is a static extractor, not a disassembler, emulator, or node execution.
The finite instruction sites and ranges were selected during manual analysis.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import fde_extents


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Role, FDE start, FDE end, SHA-256 of every byte in that FDE. These are
# selected windows, not a function census or a source-boundary assertion.
FUNCTIONS = (
    ('top_dispatcher', 0x54a2f90, 0x54a39f8, '01c85a8ccd8782ff8b0164a8f2454db4aef04b2e1c2a51b2f5583ac32d4e1570'),
    ('top_claim_wrapper', 0x550ac60, 0x550b422, 'e99803429cb093df48c6c2534667280aae4b970fb5f2a813cc8f306c18974d92'),
    ('parent', 0x551cb40, 0x551d429, '7995b2622e91c180eca8588b16416eeaa54f86d83be8bb22c0cd6726bb7a7df6'),
    ('selector', 0x4e0fd10, 0x4e10079, 'b0e0dbad2837f6f0c52ca6317f6b556b72e164a829dee3eb3bebe28fa042eab6'),
    ('dispatcher', 0x55faa80, 0x55fbb49, '575684a433c011570dda73947c31d7088d586948f8386c0e6fe1f3eb4bc8124c'),
    ('name_formatter', 0x4d81e00, 0x4d843f2, 'e5ac26af9a87f327599934a856b8b97b3caacf00b529d6161f7865aaa5ae4f69'),
    ('name_matcher', 0x4d67530, 0x4d6861e, '3a526a993918dd06ab92231898f8d0c41e26b5121480925efa2cf7d0ff41fb5a'),
    ('content_name_adapter', 0x57aebd0, 0x57aecda, '2d6fb2baab42692c249badaa8a7facbb063462078c4d0c428a9fa8e4023bcfb0'),
    ('content_envelope', 0x56900d0, 0x56916b1, 'cc3b14e8ca63c914126f5053a06afaafe884133b8936cebc1e3c296898b1f4ca'),
    ('action_decoder', 0x4d3f940, 0x4d42472, '9381b49f78adfc83571db63b66f9f2d748179f11f037221ab66a95a4168a66aa'),
    ('outer_action_content_decoder', 0x56f81d0, 0x56f9abf, '5460758c7bc1c3bc4e9a357b2f7373f8a894e95a25546aacb6ce75c1809b65d8'),
    ('action_container_decoder', 0x5707dd0, 0x5708fbd, '29e9a6efdc7834686f0f646511eb6e39e092818e5501f91bb66fd9baa1bfd4af'),
    ('claim_payload_decoder', 0x573dd90, 0x573e1b0, '7619bf5b2dcdf2473654b3c441bcb50a207d03d11e437dc6fc59d5e6229ed00e'),
    ('ordinal_formatter', 0x3714e60, 0x3715c43, '06b7cc64bf4ff252f8b2d325d541e6c3dafdb60fafdb1d1cb922bebf815c9032'),
    ('claim_handler', 0x54e3030, 0x54e3736, 'b5e09b216fff91e08d1d0db7a79ab824c53393ef4521a529f879c240e3dad40f'),
    ('reward_writer', 0x3c17fc0, 0x3c18252, '6528d9fb3971ddc349726ba95a7c2c8d430a11bfc1ee401b8e6cd6cca64dc157'),
    ('user_lookup', 0x4717930, 0x4717a03, '679f2e0acbdeec6bbba80d644bdde9db6ebb300c73ab17717cd897c2e1965f21'),
    ('reward_iterator', 0x4506370, 0x45065c0, '858357acc6cb0d4fb15b775c282881cdf458a0246d36b44752ae7d8d06eed9da'),
    ('unit_scale', 0x3c49360, 0x3c49433, '3cba201a579f7c81dc4e376af95ddfc2715beba4f1daa86d7865540d56eaefea'),
    ('threshold_conversion', 0x4217e60, 0x4217f8b, 'fac2fd655fcc96694793222711d0fce86e6f5a46a74f0960a4cd03b8eeb59575'),
    ('balance_update', 0x3bfa910, 0x3bfac09, '437a0a20c3b8dd3dccd561a6dc462b3b5b37a90772a00777becfce160a5b6800'),
    ('value_conversion', 0x434f790, 0x434f901, '0929c3bc21a049c48aef024cf8ceb3c6bc43f66d93558ca6950b0e9b96299300'),
    ('mark_lookup', 0x3bf61d0, 0x3bf6514, '72eb5ea7c3cc4f1ddbdf0c6db002082425992840f569ba86183bea7132b287d2'),
    ('account_entry', 0x582c250, 0x582c2f4, 'dd4aad2df1121cfdca76b49bd8f746884d84ea60c4e7cd72517e8955cde4e4b8'),
    ('event_collector', 0x51fb310, 0x51fb49a, '55890cf46e89434539c10139e059d23d2d21ecf651853a49b956de1f0e80baf7'),
    ('event_name', 0x421b2e0, 0x421b42b, 'c80e27f407762689d66de24f4964818a4014e2869a903a1b7edd8d1d0124dc41'),
    ('vector_growth', 0x43bbbf0, 0x43bbc54, '270ccf1145f535574c3c2fa933d3570a0f3c7f41f565a439eceef113d3c92f0e'),
    ('balance_side_map', 0x3c003c0, 0x3c007fd, '880b54782e391852eab0a622b9fc44a4e26cb3c1d9a329e9ec51269b0858f91a'),
    ('side_map_compact_lookup', 0x45537a0, 0x455399d, 'e21f50b3ef60563bbcd7bb344b129b74c29e11803c20caf8c2c3a77980d8d9b9'),
    ('side_map_user_entry', 0x3f17ca0, 0x3f17de7, '0c1df445a9f184f61cf65787df347ca8c9120d8ece12abf41a88c676f42509c3'),
    ('side_map_asset_insert', 0x370e120, 0x370e20c, '350e32a062d95ce4da102c70b538a6a08fd42f0957b89ba097cb2f844dae30c1'),
    ('event_sink', 0x51ca4e0, 0x51ca7c4, '32131d55029f8d58f5321565cec80dc2c52262712585aad632485c0e1b7b8878'),
    ('wide_unsigned_quotient', 0x63efec0, 0x63eff7e, '989c6ef7689fca20c83d7a615696bb50b66e6d650095192c333970f100a4668e'),
)

# These boundaries are instruction-aligned in the manual GNU objdump review.
# Every output byte is read directly from the ELF. Half-open linked VAs.
WINDOWS = (
    ('top_dispatcher_input', 0x54a2f9a, 0x54a2fb0),
    ('top_dispatcher_switch', 0x54a2ffa, 0x54a301c),
    ('top_dispatcher_claim_arm', 0x54a3584, 0x54a3597),
    ('top_dispatcher_outer_arm', 0x54a384d, 0x54a3867),
    ('top_wrapper_input', 0x550ac6a, 0x550aca4),
    ('top_wrapper_identity_failure', 0x550b1bf, 0x550b1d2),
    ('top_wrapper_first_gate', 0x550b1d2, 0x550b211),
    ('top_wrapper_second_gate', 0x550b211, 0x550b24f),
    ('top_wrapper_handler_and_status', 0x550b24f, 0x550b271),
    ('top_wrapper_result_kind', 0x550b2c3, 0x550b2d1),
    ('parent_input', 0x551cb51, 0x551cb7d),
    ('parent_child_and_classifier', 0x551cf82, 0x551cfa3),
    ('parent_first_identity_search', 0x551d010, 0x551d04c),
    ('parent_second_identity_search', 0x551d090, 0x551d0cc),
    ('parent_selector_and_result', 0x551d0fc, 0x551d127),
    ('parent_first_gate', 0x551d147, 0x551d174),
    ('parent_second_gate', 0x551d18e, 0x551d1bb),
    ('parent_dispatch_arguments', 0x551d1bb, 0x551d1ee),
    ('parent_preflight_status', 0x551d26b, 0x551d27b),
    ('selector_switch', 0x4e0fd15, 0x4e0fd3d),
    ('selector_empty', 0x4e0fd5d, 0x4e0fd7b),
    ('dispatcher_switch', 0x55faad8, 0x55faafb),
    ('dispatcher_selected_arm', 0x55fb3de, 0x55fb3f1),
    ('dispatcher_result', 0x55fb8c8, 0x55fb932),
    ('formatter_switch', 0x4d81e00, 0x4d81e2c),
    ('formatter_selected_name', 0x4d8344c, 0x4d834b8),
    ('matcher_length_switch', 0x4d67539, 0x4d6755a),
    ('matcher_selected_comparison', 0x4d6817c, 0x4d681bc),
    ('matcher_selected_result', 0x4d684f2, 0x4d684fc),
    ('matcher_miss_result', 0x4d6838b, 0x4d683c4),
    ('content_adapter_switch', 0x57aebd8, 0x57aebf9),
    ('content_adapter_borrowed_name', 0x57aebff, 0x57aec0e),
    ('content_envelope_output_pointer', 0x56900da, 0x56900f7),
    ('content_envelope_name_result', 0x5690379, 0x56903a4),
    ('content_envelope_ordinal_store', 0x5690c46, 0x5690c7d),
    ('action_decoder_envelope_and_switch', 0x4d3f98a, 0x4d3fa15),
    ('action_decoder_claim_arm', 0x4d410a3, 0x4d410d4),
    ('action_decoder_claim_join_a', 0x4d41b44, 0x4d41b49),
    ('action_decoder_claim_join_b', 0x4d41e6e, 0x4d41e73),
    ('action_decoder_claim_join_c', 0x4d41a96, 0x4d41a9e),
    ('action_decoder_tag_gate', 0x4d422da, 0x4d4232a),
    ('action_decoder_allocation_and_copy', 0x4d42390, 0x4d423f4),
    ('action_decoder_outer_action', 0x4d41bd0, 0x4d41c57),
    ('action_decoder_outer_pointer_stage', 0x4d422c3, 0x4d42366),
    ('outer_container_action_call', 0x56f936f, 0x56f9397),
    ('outer_container_child_store', 0x56f93d0, 0x56f9427),
    ('outer_container_three_fields', 0x56f9494, 0x56f9505),
    ('container_decoder_input_kind', 0x5707dd0, 0x5707e01),
    ('container_decoder_sequence_start', 0x5708456, 0x57084a1),
    ('container_decoder_first_field', 0x57084ea, 0x570851f),
    ('container_decoder_first_field_count', 0x5708543, 0x570855b),
    ('container_decoder_second_field', 0x5708586, 0x57085a2),
    ('container_decoder_action', 0x57085bb, 0x570861a),
    ('container_decoder_pointer_store', 0x570861a, 0x5708653),
    ('container_decoder_exact_three', 0x5708653, 0x5708667),
    ('container_decoder_return', 0x5708b59, 0x5708b6e),
    ('payload_decoder_shape_checks', 0x573dd9c, 0x573ddc1),
    ('payload_decoder_empty_success', 0x573dedd, 0x573deed),
    ('ordinal_store', 0x371567e, 0x371569b),
    ('handler_writer_arguments', 0x54e3047, 0x54e308f),
    ('handler_vector_loop', 0x54e3094, 0x54e30f5),
    ('handler_price_lookup', 0x54e31c0, 0x54e322b),
    ('handler_balance_arguments', 0x54e322b, 0x54e3263),
    ('handler_mark_and_value', 0x54e3263, 0x54e32c0),
    ('handler_token_zero', 0x54e32c0, 0x54e32e4),
    ('handler_cap_and_name', 0x54e32e4, 0x54e3330),
    ('handler_account_add', 0x54e33f1, 0x54e342c),
    ('handler_account_overflow', 0x54e35c1, 0x54e35e9),
    ('handler_event_payload', 0x54e34cd, 0x54e35bc),
    ('handler_writer_error', 0x54e35e9, 0x54e365a),
    ('handler_success', 0x54e365a, 0x54e3694),
    ('handler_failure_cleanup', 0x54e3694, 0x54e3736),
    ('writer_lookup', 0x3c17fce, 0x3c17fea),
    ('writer_absent', 0x3c18046, 0x3c18050),
    ('writer_layout_selection', 0x3c17ffc, 0x3c180af),
    ('writer_iterator_and_test', 0x3c180e0, 0x3c1811e),
    ('writer_threshold_and_branch', 0x3c1811e, 0x3c18147),
    ('writer_mutation_and_append', 0x3c18147, 0x3c1819b),
    ('writer_saturation', 0x3c1819b, 0x3c181ce),
    ('writer_result', 0x3c181ce, 0x3c1822a),
    ('writer_unwind', 0x3c1822a, 0x3c18252),
    ('lookup_one_key', 0x471793b, 0x471798b),
    ('iterator_compact', 0x4506370, 0x45063b5),
    ('iterator_tree', 0x450646f, 0x4506506),
    ('iterator_tree_yield_and_failures', 0x4506561, 0x45065c0),
    ('unit_scale_input', 0x3c49360, 0x3c49399),
    ('unit_scale_ladder', 0x3c49399, 0x3c49433),
    ('threshold_input', 0x4217e60, 0x4217e97),
    ('threshold_quotient', 0x4217e97, 0x4217ef4),
    ('threshold_powers', 0x4217ef4, 0x4217f8b),
    ('wide_quotient_entry', 0x63efec0, 0x63efec8),
    ('wide_quotient_single_divisor', 0x63eff39, 0x63eff7e),
    ('balance_direction_and_amount', 0x3bfa9f4, 0x3bfaa82),
    ('balance_saturation', 0x3bfabe7, 0x3bfac09),
    ('side_map_representation', 0x3c003dd, 0x3c00403),
    ('side_map_compact_limit', 0x3c00499, 0x3c004c5),
    ('side_map_key_insert', 0x3c006b3, 0x3c0075e),
    ('side_map_unwind', 0x3c0079f, 0x3c007fd),
    ('side_map_compact_lookup_result', 0x4553952, 0x455399d),
    ('side_map_user_entry_choice', 0x3f17ca3, 0x3f17cc5),
    ('side_map_user_entry_bounds', 0x3f17d8c, 0x3f17db8),
    ('side_map_asset_insert_existing_root', 0x370e129, 0x370e179),
    ('side_map_asset_insert_empty_root', 0x370e179, 0x370e1d6),
    ('value_conversion', 0x434f790, 0x434f854),
    ('value_power_failure', 0x434f8bc, 0x434f901),
    ('account_entry_selection', 0x582c250, 0x582c2f4),
    ('event_collector_gate', 0x51fb340, 0x51fb3b4),
    ('event_collector_sink', 0x51fb438, 0x51fb485),
    ('event_sink_mode', 0x51ca4f4, 0x51ca51f),
    ('event_sink_append', 0x51ca51f, 0x51ca572),
    ('event_sink_other_modes', 0x51ca572, 0x51ca58d),
)

# Direct edges only. The opcodes and signed displacements are decoded below.
# The list is a manually selected set of instruction starts, not an exhaustive
# scan for opcode bytes, so it makes no whole-function caller-census claim.
DIRECT_EDGES = (
    ('top_dispatch_claim_wrapper', 0x54a358d), ('top_dispatch_join', 0x54a3592),
    ('top_dispatch_outer_parent', 0x54a385d), ('top_dispatch_outer_join', 0x54a3862),
    ('top_wrapper_identity_failure_join', 0x550b1cd),
    ('top_wrapper_first_gate_failure', 0x550b20b),
    ('top_wrapper_second_gate_failure', 0x550b249),
    ('top_wrapper_handler', 0x550b25c), ('top_wrapper_handler_success', 0x550b26f),
    ('top_wrapper_result_join', 0x550b2cc),
    ('parent_classifier_skip', 0x551cf9d), ('parent_empty_collection', 0x551cfb2),
    ('parent_first_identity_found', 0x551d046), ('parent_second_identity_found', 0x551d0c6),
    ('parent_selector', 0x551d10f), ('selector_failure', 0x551d121),
    ('first_gate_failure', 0x551d16e), ('second_gate_failure', 0x551d1b5),
    ('parent_dispatch', 0x551d1e4), ('parent_early_return', 0x551d276),
    ('dispatch_call', 0x55fb3e7), ('dispatch_join', 0x55fb3ec),
    ('dispatch_result_success', 0x55fb8d0),
    ('matcher_length_failure', 0x4d67544), ('matcher_prior_name', 0x4d68196),
    ('matcher_claim_name', 0x4d681b6), ('matcher_return', 0x4d684f7),
    ('content_adapter_name_matcher', 0x57aec07), ('content_adapter_cleanup_join', 0x57aec0c),
    ('content_envelope_name_adapter', 0x5690383), ('content_envelope_name_failure', 0x5690395),
    ('content_envelope_missing_ordinal', 0x5690c4e),
    ('action_decoder_envelope', 0x4d3f995), ('action_decoder_envelope_success', 0x4d3f9a4),
    ('action_decoder_payload', 0x4d410ba), ('action_decoder_payload_failure', 0x4d410c3),
    ('action_decoder_claim_join_a', 0x4d410cf), ('action_decoder_claim_join_b', 0x4d41b44),
    ('action_decoder_claim_join_c', 0x4d41e6e), ('action_decoder_claim_join_d', 0x4d41a99),
    ('action_decoder_tag_success', 0x4d422f0), ('action_decoder_allocation_failure', 0x4d423b9),
    ('outer_action_content', 0x4d41bf4), ('outer_action_content_failure', 0x4d41c08),
    ('outer_action_tag_join', 0x4d41c52), ('outer_container_action', 0x56f937c),
    ('outer_container_action_failure', 0x56f9391), ('outer_container_count_failure', 0x56f9498),
    ('outer_container_return', 0x56f9500),
    ('container_sequence_kind', 0x5707df2), ('container_sequence_first_available', 0x570849d),
    ('container_first_field_failure', 0x570851f), ('container_second_field_failure', 0x570859c),
    ('container_missing_third_field', 0x57085c4), ('container_action_decode', 0x5708608),
    ('container_action_failure', 0x5708614), ('container_exact_three_return', 0x5708661),
    ('payload_kind_14', 0x573dda5), ('payload_other_kind', 0x573ddae),
    ('payload_empty_success', 0x573ddbb), ('payload_nested_failure', 0x573de08),
    ('payload_nested_success', 0x573de1f),
    ('writer_failure', 0x54e3089), ('empty_vector', 0x54e30b9),
    ('zero_asset_price', 0x54e30ef), ('compact_price_representation', 0x54e310d),
    ('price_lookup', 0x54e31c8), ('unit_fallback_if_miss', 0x54e31cf),
    ('unit_fallback_if_bounds', 0x54e31d8), ('balance_update', 0x54e325e),
    ('zero_asset_value', 0x54e3266), ('missing_mark', 0x54e3282),
    ('other_asset_cap_check', 0x54e32b0), ('value_sign_guard', 0x54e32b5),
    ('metadata_bounds', 0x54e32eb), ('name_length', 0x54e3305),
    ('hype_cap_bypass', 0x54e3316), ('account_entry', 0x54e33f9),
    ('account_add_overflow', 0x54e3422), ('event_allocation_failure', 0x54e343a),
    ('event_block_choice', 0x54e3493), ('event_metadata_bounds', 0x54e34d4),
    ('handler_loop', 0x54e35b6), ('handler_after_loop', 0x54e35bc),
    ('writer_user_lookup', 0x3c17fe0), ('writer_user_missing', 0x3c17fe8),
    ('writer_layout', 0x3c18017), ('writer_iterator', 0x3c180f3),
    ('writer_iterator_end', 0x3c180fb), ('writer_zero_amount', 0x3c1810b),
    ('writer_threshold_call', 0x3c18130), ('writer_below_threshold', 0x3c18145),
    ('writer_add_overflow', 0x3c1815b), ('writer_vector_has_room', 0x3c1816c),
    ('writer_loop', 0x3c18196), ('writer_empty_result', 0x3c181d4),
    ('threshold_metadata_bounds', 0x4217e6b), ('threshold_subtraction_failure', 0x4217e8a),
    ('threshold_power_overflow', 0x4217f63), ('threshold_return_after_16', 0x4217f6b),
    ('wide_quotient_low_divisor', 0x63efec6), ('wide_quotient_high_word', 0x63eff3c),
    ('wide_quotient_small_high_word', 0x63eff54),
    ('unit_metadata_empty', 0x3c49368), ('unit_metadata_bounds', 0x3c49371),
    ('unit_subtraction_failure', 0x3c4938a),
    ('balance_side_map', 0x3bfaa4a), ('balance_add_overflow', 0x3bfaa58),
    ('side_map_representation', 0x3c003f9), ('side_map_tree', 0x3c004a6),
    ('side_map_lookup', 0x3c004b4), ('side_map_found', 0x3c004bc),
    ('side_map_compact_limit', 0x3c004c3), ('side_map_existing_key', 0x3c00715),
    ('side_map_user_entry', 0x3c006c1), ('side_map_insert', 0x3c00759),
    ('side_map_new_root', 0x370e134), ('side_map_root_allocation_failure', 0x370e18a),
    ('side_map_root_bound', 0x370e1ac), ('side_map_user_index_bounds', 0x3f17d90),
    ('balance_nonzero_price', 0x3bfaa69), ('value_metadata_bounds', 0x434f79d),
    ('value_subtraction_failure', 0x434f7b9), ('value_power_overflow', 0x434f8d3),
    ('event_enabled_unless_sentinel', 0x51fb370), ('event_sink', 0x51fb46e),
    ('event_sink_mode_zero', 0x51ca517), ('event_sink_other_mode', 0x51ca51d),
    ('event_sink_vector_has_room', 0x51ca529),
)

# These RIP-relative calls all resolve through a single ELF RELATIVE record.
INDIRECT_CALLS = (
    ('writer', 0x54e3076), ('unit_scale', 0x3c18118),
    ('vector_growth', 0x3c18173), ('writer_overflow_recorder', 0x3c181a4),
    ('threshold_division', 0x4217eab), ('price_fallback', 0x54e321a),
    ('mark_lookup', 0x54e3279), ('value_conversion', 0x54e3298),
    ('event_name', 0x54e3511), ('event_collector', 0x54e359d),
    ('account_overflow_recorder', 0x54e35ca),
)

IMPORT_CALLS = (
    ('key_compare', 0x4553936, 'memcmp'),
    ('event_vector_copy', 0x51ca55d, 'memcpy'),
    ('decoder_box_copy', 0x4d423d2, 'memcpy'),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data):
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'node #115 SHA-256 mismatch')


def file_offset(secs, data_length, va, length=1, *, executable=False):
    """Resolve exactly one complete file-backed section; reject NOBITS."""
    require(isinstance(va, int) and isinstance(length, int) and va >= 0 and length > 0,
            'invalid virtual-address range')
    matches = []
    for sec in secs:
        if sec['type'] == 8 or (executable and not sec['flags'] & 4):
            continue
        delta = va - sec['address']
        if 0 <= delta and delta + length <= sec['size']:
            off = sec['offset'] + delta
            if 0 <= off and off + length <= data_length:
                matches.append(off)
    require(len(matches) == 1, 'address is not uniquely file-backed')
    return matches[0]


def expect(actual, expected, label):
    require(actual == expected, 'unexpected bytes: ' + label)


def decode_direct(raw, va):
    """Decode only the fixed rel8/rel32 call, jmp and jcc instruction forms."""
    require(len(raw) >= 2, 'truncated direct edge')
    op = raw[0]
    if op in (0xe8, 0xe9):
        require(len(raw) >= 5, 'truncated rel32')
        size, disp = 5, struct.unpack_from('<i', raw, 1)[0]
        kind = 'call' if op == 0xe8 else 'jmp'
    elif op == 0xeb or 0x70 <= op <= 0x7f:
        size, disp = 2, struct.unpack_from('<b', raw, 1)[0]
        kind = 'jmp' if op == 0xeb else 'jcc-' + format(op & 15, 'x')
    elif op == 0x0f and 0x80 <= raw[1] <= 0x8f:
        require(len(raw) >= 6, 'truncated rel32 condition')
        size, disp = 6, struct.unpack_from('<i', raw, 2)[0]
        kind = 'jcc-' + format(raw[1] & 15, 'x')
    else:
        raise ValueError('unsupported direct-edge opcode')
    return kind, size, va + size + disp


def decode_rip(raw, va, prefix):
    """Decode a selected fixed-prefix RIP-relative disp32 operand."""
    require(raw.startswith(prefix) and len(raw) == len(prefix) + 4,
            'unexpected RIP-relative form')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def unique_record(records, slot):
    rows = [r for r in records if r[0] == slot]
    require(len(rows) == 1, 'missing or duplicate relocation')
    return rows[0]


def unique_relocation(records, slot):
    row = unique_record(records, slot)
    require(row[1] == 8, 'relocation is not R_X86_64_RELATIVE')
    return row


def imported_symbol(row, symbols, names):
    """Resolve the selected ELF64 dynamic symbol using the standard entry form."""
    info = row[1]
    require(info & 0xffffffff == 6, 'relocation is not R_X86_64_GLOB_DAT')
    index = info >> 32
    require(index > 0 and len(symbols) % 24 == 0 and (index + 1) * 24 <= len(symbols),
            'invalid dynamic symbol index')
    name_offset = struct.unpack_from('<I', symbols, index * 24)[0]
    require(name_offset < len(names), 'dynamic symbol name outside string table')
    end = names.find(b'\0', name_offset)
    require(end >= 0, 'unterminated dynamic symbol')
    try:
        name = names[name_offset:end].decode('ascii')
    except UnicodeDecodeError as exc:
        raise ValueError('non-ASCII dynamic symbol') from exc
    require(name != '', 'empty dynamic symbol')
    return index, name


class Image:
    def __init__(self, data):
        verify_digest(data)
        self.data = data
        self.secs = sections(data)
        summary, extents, _ = fde_extents(data)
        require(summary['unwind_start_differs_from_fde_start'] == 0,
                'unwind index and FDE starts disagree')
        by_start = {row['start']: row for row in extents}
        self.functions = {}
        for role, start, end, expected_hash in FUNCTIONS:
            row = by_start.get(start)
            require(row is not None and 'index' in row and row['end'] == end,
                    'selected FDE is missing, unindexed, or has changed bounds: ' + role)
            body = self.read(start, end - start, executable=True)
            digest = hashlib.sha256(body).hexdigest()
            if expected_hash is not None:
                require(digest == expected_hash, 'selected body hash changed: ' + role)
            self.functions[role] = (row, digest)
        self.relocations = self._relocations()

    def read(self, va, length, *, executable=False):
        off = file_offset(self.secs, len(self.data), va, length, executable=executable)
        return self.data[off:off + length]

    def offset(self, va, length=1, *, executable=False):
        return file_offset(self.secs, len(self.data), va, length, executable=executable)

    def owner(self, start, end):
        rows = [(role, row) for role, (row, _) in self.functions.items()
                if row['start'] <= start < end <= row['end']]
        require(len(rows) == 1, 'window is outside a unique selected FDE')
        return rows[0]

    def _relocations(self):
        matches = [s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4]
        require(len(matches) == 1, 'expected one file-backed .rela.dyn')
        sec = matches[0]
        require(sec['size'] % 24 == 0, 'truncated RELA section')
        rows = []
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, off)
            rows.append((slot, info, addend, off))
        return rows

    def direct(self, va):
        # Reading six bytes is safe for every manually selected site.
        raw = self.read(va, 6, executable=True)
        kind, size, target = decode_direct(raw, va)
        self.owner(va, va + size)
        self.read(target, 1, executable=True)
        return kind, raw[:size], target

    def indirect(self, va):
        raw = self.read(va, 6, executable=True)
        self.owner(va, va + 6)
        slot = decode_rip(raw, va, b'\xff\x15')
        self.read(slot, 8)
        row = unique_relocation(self.relocations, slot)
        self.read(row[2], 1, executable=True)
        return raw, row

    def imported(self, va):
        raw = self.read(va, 6, executable=True)
        self.owner(va, va + 6)
        slot = decode_rip(raw, va, b'\xff\x15')
        self.read(slot, 8)
        row = unique_record(self.relocations, slot)
        dynsym = [s for s in self.secs if s['name'] == '.dynsym' and s['type'] == 11]
        dynstr = [s for s in self.secs if s['name'] == '.dynstr' and s['type'] == 3]
        require(len(dynsym) == len(dynstr) == 1, 'missing or duplicate dynamic table')
        syms = self.data[dynsym[0]['offset']:dynsym[0]['offset'] + dynsym[0]['size']]
        names = self.data[dynstr[0]['offset']:dynstr[0]['offset'] + dynstr[0]['size']]
        index, name = imported_symbol(row, syms, names)
        return raw, row, index, name


def immediate(image, address, prefix, size):
    raw = image.read(address, len(prefix) + size, executable=True)
    require(raw.startswith(prefix), 'unexpected immediate instruction')
    return int.from_bytes(raw[len(prefix):], 'little')


def constants(image):
    out = {
        'tag_base': immediate(image, 0x55faadc, b'\x48\x2d', 4),
        'default_index': immediate(image, 0x55faae2, b'\xb9', 4),
        'ordinal': immediate(image, 0x371567e, b'\x48\xc7\x04\x24', 4),
        'not_found': immediate(image, 0x3c18046, b'\x66\xc7\x03', 2),
        'nonzero_but_unclaimed': immediate(image, 0x3c1813d, b'\x66\x41\xbd', 2),
        'success': immediate(image, 0x3c181ed, b'\x66\xc7\x03', 2),
        'threshold_numerator': immediate(image, 0x3c1811e, b'\xbf', 4),
        'value_cap': immediate(image, 0x54e3318, b'\x48\xb8', 8),
        'value_conversion_limit': immediate(image, 0x434f832, b'\x48\xba', 8),
        'account_divisor_magic': immediate(image, 0x54e3404, b'\x48\xb9', 8),
        'zero_asset_divisor_magic': immediate(image, 0x54e32c9, b'\x48\xb9', 8),
        'layout_sentinel': immediate(image, 0x54e3100, b'\x48\xb8', 8),
        'side_tree_to_compact_below': immediate(image, 0x3c003ed, b'\x48\x83\xf8', 1),
        'side_compact_to_tree_above': immediate(image, 0x3c004be, b'\x49\x83\x7f\x18', 1),
    }
    expect(image.read(0x4e0fd1c, 7, executable=True),
           bytes.fromhex('4981e886000000'), 'selector tag bias')
    expect(image.read(0x4d81e07, 6, executable=True),
           bytes.fromhex('482d86000000'), 'name formatter tag bias')
    expect(image.read(0x54a2ffd, 6, executable=True),
           bytes.fromhex('482d86000000'), 'top dispatcher tag bias')
    expect(image.read(0x3715686, 9, executable=True),
           bytes.fromhex('48c744240805000000'), 'second ordinal store')
    require(out['ordinal'] == 5 and out['tag_base'] == 0x86, 'unexpected action ordinal')
    return out


def selected_tables(image, c):
    specs = (
        ('top_dispatcher', 0x54a300c, b'\x48\x8d\x05', 0x54a3584),
        ('ordinal_formatter', 0x3714e76, b'\x48\x8d\x05', 0x371567e),
        ('name_formatter', 0x4d81e16, b'\x48\x8d\x05', 0x4d8344c),
        ('selector', 0x4e0fd2c, b'\x48\x8d\x0d', 0x4e0fd5d),
        ('dispatcher', 0x55faaeb, b'\x48\x8d\x05', 0x55fb3de),
    )
    rows = []
    for role, site, prefix, expected in specs:
        lea = image.read(site, len(prefix) + 4, executable=True)
        base = decode_rip(lea, site, prefix)
        entry = base + 4 * c['ordinal']
        raw = image.read(entry, 4)
        target = base + struct.unpack('<i', raw)[0]
        expect(target, expected, role + ' selected target')
        row = image.functions[role][0]
        require(row['start'] <= target < row['end'], 'switch arm outside its FDE')
        rows.append((role, site, base, entry, raw, target))
    return rows


def literal_at_lea(image, site, prefix, length, expected):
    raw = image.read(site, len(prefix) + 4, executable=True)
    address = decode_rip(raw, site, prefix)
    value = image.read(address, length)
    expect(value, expected, 'target literal')
    return address, value


def selected_name_match(image, c):
    """Read the length table, embedded name immediates and result word."""
    length = immediate(image, 0x4d83496, b'\x48\xc7\x44\x24\x38', 4)
    raw_bias = image.read(0x4d6753c, 4, executable=True)
    expect(raw_bias[:3], b'\x48\x8d\x4a', 'matcher length adjustment')
    bias = -struct.unpack('<b', raw_bias[3:])[0]
    max_index = immediate(image, 0x4d67540, b'\x48\x83\xf9', 1)
    require(bias <= length and length - bias <= max_index, 'selected name outside length switch')
    lea = image.read(0x4d6754a, 7, executable=True)
    table = decode_rip(lea, 0x4d6754a, b'\x48\x8d\x3d')
    entry = table + 4 * (length - bias)
    raw_entry = image.read(entry, 4)
    arm = table + struct.unpack('<i', raw_entry)[0]
    expect(arm, 0x4d6817c, 'matcher length arm')
    first = image.read(0x4d6819c, 10, executable=True)
    last = image.read(0x4d681ac, 7, executable=True)
    expect(first[:2], b'\x48\xb9', 'matcher first name immediate')
    expect(last[:3], b'\x48\x81\xf7', 'matcher second name immediate')
    expect(image.read(0x4d681a6, 6, executable=True), bytes.fromhex('48330e8b7e08'),
           'matcher two input loads')
    expect(image.read(0x4d681b3, 3, executable=True), bytes.fromhex('4809cf'),
           'matcher combined equality')
    name = first[2:] + last[3:]
    expect(name, b'claimRewards', 'matcher name')
    kind, _, target = image.direct(0x4d681b6)
    expect((kind, target), ('jcc-4', 0x4d684f2), 'matcher equal branch')
    packed = immediate(image, target, b'\x66\xc7\x00', 2)
    expect(packed, 0x0509, 'matcher packed result')
    require(packed >> 8 == c['ordinal'], 'matcher and ordinal emitter disagree')
    return length, bias, max_index, table, entry, raw_entry, arm, name, target, packed


def selected_decode_route(image, c):
    """Pin one content-name path through ordinal dispatch to a boxed tag."""
    n = immediate(image, 0x57aebe0, b'\x83\xf8', 1) + 1
    adapter_table = decode_rip(image.read(0x57aebe9, 7, executable=True),
                               0x57aebe9, b'\x48\x8d\x0d')
    hits = []
    for i in range(n):
        entry = adapter_table + 4 * i
        raw = image.read(entry, 4)
        target = adapter_table + struct.unpack('<i', raw)[0]
        if target == 0x57aebff:
            hits.append((i + 1, entry, raw, target))
    require(len(hits) == 1, 'selected content arm is missing or ambiguous')
    adapter_tag, adapter_entry, adapter_raw, adapter_arm = hits[0]
    decoder_table = decode_rip(image.read(0x4d3fa05, 7, executable=True),
                               0x4d3fa05, b'\x48\x8d\x0d')
    decoder_entry = decoder_table + 4 * c['ordinal']
    decoder_raw = image.read(decoder_entry, 4)
    decoder_arm = decoder_table + struct.unpack('<i', decoder_raw)[0]
    expect(decoder_arm, 0x4d410a3, 'decoder ordinal arm')
    for site, expected in ((0x4d3f995, 0x56900d0), (0x5690383, 0x57aebd0),
                           (0x57aec07, 0x4d67530), (0x4d410ba, 0x573dd90),
                           (0x5708608, 0x4d3f940)):
        kind, _, target = image.direct(site)
        expect((kind, target), ('call', expected), 'decoder call chain')
    type_length = immediate(image, 0x4d410b5, b'\xb9', 4)
    type_addr, _ = literal_at_lea(image, 0x4d410a3, b'\x48\x8d\x15', type_length,
                                  b'ClaimRewardsAction')
    tag = immediate(image, 0x4d410c9, b'\x41\xbc', 4)
    expect(tag, c['tag_base'] + c['ordinal'], 'decoded internal tag')
    expect(image.read(0x5690c74, 4, executable=True), bytes.fromhex('41884d08'),
           'envelope ordinal store')
    expect(image.read(0x5690ca2, 8, executable=True), bytes.fromhex('49c7450000000000'),
           'envelope success store')
    expect(image.read(0x4d42322, 8, executable=True), bytes.fromhex('4c89a424d8010000'),
           'decoder boxed tag staging')
    expect(image.read(0x570861a, 5, executable=True), bytes.fromhex('488b5c2478'),
           'container decoded pointer load')
    expect(image.read(0x570864f, 4, executable=True), bytes.fromhex('49895d00'),
           'container decoded pointer store')
    expect(image.read(0x570865d, 4, executable=True), bytes.fromhex('4983fe03'),
           'container exact sequence length')
    kind, _, target = image.direct(0x5708661)
    expect((kind, target), ('jcc-4', 0x5708b59), 'container exact sequence return')
    return (adapter_tag, adapter_table, adapter_entry, adapter_raw, adapter_arm,
            decoder_table, decoder_entry, decoder_raw, decoder_arm, type_addr, tag)


def selected_nested_handoff(image, c):
    """Pin the selected outer variant and its nested child-pointer layout."""
    outer_tag = immediate(image, 0x4d41c4c, b'\x41\xbc', 4)
    ordinal = outer_tag - c['tag_base']
    expect((outer_tag, ordinal), (0xba, 52), 'outer tag and ordinal')
    tables = []
    for site, prefix, expected in ((0x4d3fa05, b'\x48\x8d\x0d', 0x4d41bd0),
                                   (0x54a300c, b'\x48\x8d\x05', 0x54a384d)):
        base = decode_rip(image.read(site, len(prefix) + 4, executable=True), site, prefix)
        entry = base + 4 * ordinal
        raw = image.read(entry, 4)
        target = base + struct.unpack('<i', raw)[0]
        expect(target, expected, 'outer selected table target')
        tables.append((base, entry, raw, target))
    for site, target in ((0x4d41bf4, 0x56f81d0), (0x56f937c, 0x5707dd0),
                         (0x54a385d, 0x551cb40)):
        kind, _, actual = image.direct(site)
        expect((kind, actual), ('call', target), 'outer child call chain')
    for site, raw, label in (
        (0x56f9414, '48894718', 'outer child pointer store'),
        (0x4d41c13, 'f30f6f4c2410', 'outer child register load'),
        (0x4d422df, '660f70c1ee66490f7ec0', 'outer child register extraction'),
        (0x4d4235e, '4c898424f8010000', 'outer child staging'),
        (0x4d423c2, '488db424d8010000baf0000000', 'outer boxed copy'),
        (0x54a384d, '4983c708', 'outer payload argument'),
        (0x551cf8a, '4c8b7b18', 'parent child pointer load'),
        (0x56f9494, '4983fe03', 'outer sequence count'),
    ):
        expect(image.read(site, len(bytes.fromhex(raw)), executable=True), bytes.fromhex(raw), label)
    expect(image.direct(0x4d41c52)[2], 0x4d422c3, 'outer decoder staging join')
    expect(image.direct(0x56f9500)[2], 0x56f91de, 'outer content return')
    child_in_content = image.read(0x56f9414, 4, executable=True)[3]
    child_stage = struct.unpack('<I', image.read(0x4d4235e, 8, executable=True)[4:])[0]
    copy_start = struct.unpack('<I', image.read(0x4d423c2, 8, executable=True)[4:])[0]
    parent_offset = image.read(0x551cf8a, 4, executable=True)[3]
    payload_offset = image.read(0x54a384d, 4, executable=True)[3]
    expect(child_stage - copy_start, payload_offset + parent_offset, 'outer boxed child offset')
    return outer_tag, ordinal, tables, child_in_content, child_stage - copy_start, payload_offset, parent_offset


def threshold(w0, size_decimals, token_decimals, numerator):
    """Static interpretation of the selected floor-conversion path."""
    for n in (w0, size_decimals, token_decimals):
        require(type(n) is int and 0 <= n <= 255, 'invalid metadata byte')
    require(type(numerator) is int and 0 <= numerator < 1 << 64, 'invalid numerator')
    unit_exp, scale_exp = w0 - size_decimals, token_decimals - size_decimals
    require(0 <= unit_exp <= 19 and 0 <= scale_exp <= 19,
            'selected metadata subtraction or power path fails')
    result = numerator * 10 ** scale_exp // 10 ** unit_exp
    return result if result <= (1 << 64) - 1 else None


def model_rows(present, rows, c):
    """Normal-return interpretation; no node instructions are executed.

    Each synthetic row is (asset, current, prior, threshold-or-None). None
    means the conversion's high quotient did not fit in its returned word.
    """
    maximum = (1 << 64) - 1
    require(isinstance(present, bool), 'invalid presence flag')
    values, paid, seen = [], [], False
    for asset, current, prior, minimum in rows:
        require(all(type(v) is int and 0 <= v <= maximum for v in (asset, current, prior)),
                'row outside u64')
        require(minimum is None or (type(minimum) is int and 0 <= minimum <= maximum),
                'threshold outside u64')
        if not present:
            values.append((asset, current, prior))
            continue
        if current:
            seen = True
            if minimum is not None and current >= minimum:
                paid.append((asset, current))
                values.append((asset, 0, min(maximum, prior + current)))
                continue
        values.append((asset, current, prior))
    status = (c['not_found'] if not present else c['success'] if paid else
              c['nonzero_but_unclaimed'] if seen else c['not_found'])
    return status, values, paid


def model_value(asset, amount, mark, exponent, name, c):
    """Interpret only the handler's normal, selected per-row value arithmetic."""
    maximum = (1 << 64) - 1
    require(all(type(v) is int and 0 <= v <= maximum for v in (asset, amount, mark)),
            'value input outside u64')
    require(type(exponent) is int and 0 <= exponent <= 19, 'invalid exponent')
    require(isinstance(name, bytes), 'name must be bytes')
    if asset == 0:
        return amount // 100
    if mark == 0:
        return 0
    value = (amount * mark) // (100 * 10 ** exponent)
    if value >= c['value_conversion_limit']:
        return 0
    if asset != 1 and name != b'HYPE':
        value = min(value, c['value_cap'])
    return value


def model_account_add(old, value):
    """Interpret the nonnegative value increment and signed saturation."""
    require(type(old) is int and -(1 << 63) <= old < 1 << 63, 'invalid signed account')
    require(type(value) is int and 0 <= value < 1 << 64, 'invalid value')
    return min((1 << 63) - 1, old + value // 10000)


def model_event_enabled(word, sentinel):
    """Interpret the collector's 0-minus-word overflow branch."""
    require(type(word) is int and 0 <= word < 1 << 64, 'invalid collector word')
    return word != sentinel


def model_side_map_representation(is_tree, count, found, c):
    """Interpret the selected normal-path compact/tree conversion guards."""
    require(type(is_tree) is bool and type(found) is bool, 'invalid representation flags')
    require(type(count) is int and 0 <= count < 1 << 64, 'invalid map count')
    if is_tree and count < c['side_tree_to_compact_below']:
        is_tree = False
    if not is_tree and not found and count > c['side_compact_to_tree_above']:
        is_tree = True
    return is_tree


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.writer(out, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(image, out):
    c = constants(image)
    tables = selected_tables(image, c)
    matcher = selected_name_match(image, c)
    decoded = selected_decode_route(image, c)
    outer = selected_nested_handoff(image, c)
    out.mkdir(parents=True, exist_ok=True)
    functions = []
    for role, start, end, _ in FUNCTIONS:
        row, digest = image.functions[role]
        body = image.read(start, end - start, executable=True)
        functions.append((role, hex(start), hex(end), hex(image.offset(start, len(body))),
                          hex(row['fde']), hex(row['cie']),
                          '' if row['lsda'] is None else hex(row['lsda']),
                          row['index'], len(body), digest, body.hex()))
    write_tsv(out / 'functions.tsv',
              ('role', 'start_va', 'end_va_exclusive', 'file_offset', 'fde_va', 'cie_va',
               'lsda_va', 'unwind_index', 'length', 'sha256', 'raw_hex'), functions)

    slices = []
    for label, start, end in WINDOWS:
        role, _ = image.owner(start, end)
        raw = image.read(start, end - start, executable=True)
        slices.append((label, role, hex(start), hex(end), hex(image.offset(start, len(raw))), raw.hex()))
    write_tsv(out / 'windows.tsv', ('label', 'function', 'start_va', 'end_va_exclusive',
                                   'file_offset', 'raw_hex'), slices)

    edges = []
    for label, site in DIRECT_EDGES:
        kind, raw, target = image.direct(site)
        role, _ = image.owner(site, site + len(raw))
        edges.append((label, role, hex(site), hex(image.offset(site, len(raw))),
                      raw.hex(), kind, hex(target)))
    write_tsv(out / 'direct-edges.tsv', ('label', 'function', 'site_va', 'file_offset',
                                        'raw_hex', 'kind', 'target_va'), edges)

    relocs = []
    for label, site in INDIRECT_CALLS:
        raw, (slot, info, addend, record_off) = image.indirect(site)
        role, _ = image.owner(site, site + len(raw))
        relocs.append((label, role, hex(site), hex(image.offset(site, len(raw))), raw.hex(),
                       hex(slot), hex(image.offset(slot, 8)), hex(record_off),
                       image.data[record_off:record_off + 24].hex(), hex(info), hex(addend)))
    write_tsv(out / 'indirect-relocations.tsv',
              ('label', 'function', 'site_va', 'site_file_offset', 'raw_hex', 'slot_va',
               'slot_file_offset', 'rela_file_offset', 'rela_raw_hex', 'r_info', 'addend_va'), relocs)

    imports = []
    for label, site, expected in IMPORT_CALLS:
        raw, (slot, info, addend, record_off), index, name = image.imported(site)
        expect(name, expected, 'imported symbol')
        role, _ = image.owner(site, site + len(raw))
        imports.append((label, role, hex(site), hex(image.offset(site, len(raw))), raw.hex(),
                        hex(slot), hex(image.offset(slot, 8)), hex(record_off),
                        image.data[record_off:record_off + 24].hex(), hex(info), index, name, addend))
    write_tsv(out / 'import-relocations.tsv',
              ('label', 'function', 'site_va', 'site_file_offset', 'raw_hex', 'slot_va',
               'slot_file_offset', 'rela_file_offset', 'rela_raw_hex', 'r_info',
               'symbol_index', 'symbol_name', 'addend'), imports)

    write_tsv(out / 'selected-switches.tsv',
              ('function', 'lea_va', 'table_va', 'entry_va', 'entry_file_offset',
               'entry_raw_hex', 'ordinal', 'tag', 'target_va'),
              ((role, hex(site), hex(base), hex(entry), hex(image.offset(entry, 4)), raw.hex(),
                c['ordinal'], hex(c['tag_base'] + c['ordinal']), hex(target))
               for role, site, base, entry, raw, target in tables))

    literal_specs = (
        ('wire_name', 0x4d8348a, b'\x48\x8d\x05',
         immediate(image, 0x4d83496, b'\x48\xc7\x44\x24\x38', 4), b'claimRewards'),
        ('variant_name', 0x4d83460, b'\x48\x8d\x05',
         immediate(image, 0x4d8346c, b'\x48\xc7\x44\x24\x18', 4), b'ClaimRewards'),
        ('type_name', 0x4d834a4, b'\x48\x8d\x35',
         immediate(image, 0x4d834ae, b'\xba', 4), b'ClaimRewardsAction'),
        ('cap_exception', 0x54e3310, b'\x3b\x05',
         immediate(image, 0x54e32ff, b'\x48\x83\x7c\x08\x40', 1), b'HYPE'),
    )
    literals = []
    for label, site, prefix, length, expected in literal_specs:
        address, value = literal_at_lea(image, site, prefix, length, expected)
        literals.append((label, hex(site), hex(address), hex(image.offset(address, length)), length,
                         value.hex(), value.decode('ascii')))
    write_tsv(out / 'literals.tsv', ('label', 'reference_va', 'literal_va', 'file_offset',
                                     'length', 'raw_hex', 'ascii'), literals)

    length, bias, max_index, table, entry, raw, arm, name, target, packed = matcher
    write_tsv(out / 'selected-name-match.tsv',
              ('length', 'length_bias', 'maximum_index', 'table_va', 'entry_va',
               'entry_file_offset', 'entry_raw_hex', 'length_arm_va', 'name_raw_hex',
               'name_ascii', 'equal_branch_va', 'equal_target_va', 'packed_result_word'),
              [(length, bias, max_index, hex(table), hex(entry), hex(image.offset(entry, 4)),
                raw.hex(), hex(arm), name.hex(), name.decode('ascii'), hex(0x4d681b6),
                hex(target), hex(packed))])

    adapter_tag, adapter_table, adapter_entry, adapter_raw, adapter_arm, decoder_table, decoder_entry, decoder_raw, decoder_arm, type_addr, tag = decoded
    write_tsv(out / 'selected-decode-route.tsv',
              ('content_tag', 'adapter_table_va', 'adapter_entry_va', 'adapter_entry_file_offset',
               'adapter_raw_hex', 'adapter_arm_va', 'ordinal', 'decoder_table_va',
               'decoder_entry_va', 'decoder_entry_file_offset', 'decoder_raw_hex',
               'decoder_arm_va', 'type_literal_va', 'decoded_tag'),
              [(adapter_tag, hex(adapter_table), hex(adapter_entry), hex(image.offset(adapter_entry, 4)),
                adapter_raw.hex(), hex(adapter_arm), c['ordinal'], hex(decoder_table),
                hex(decoder_entry), hex(image.offset(decoder_entry, 4)), decoder_raw.hex(),
                hex(decoder_arm), hex(type_addr), hex(tag))])

    outer_tag, outer_ordinal, outer_tables, content_child, boxed_child, payload, parent_child = outer
    decoder, dispatch = outer_tables
    write_tsv(out / 'nested-handoff.tsv',
              ('outer_tag', 'outer_ordinal', 'decoder_table_va', 'decoder_entry_va',
               'decoder_entry_file_offset', 'decoder_entry_raw_hex', 'decoder_target_va',
               'dispatch_table_va', 'dispatch_entry_va', 'dispatch_entry_file_offset',
               'dispatch_entry_raw_hex', 'dispatch_target_va', 'content_child_offset',
               'boxed_child_offset', 'payload_offset', 'parent_child_offset'),
              [(hex(outer_tag), outer_ordinal, hex(decoder[0]), hex(decoder[1]),
                hex(image.offset(decoder[1], 4)), decoder[2].hex(), hex(decoder[3]),
                hex(dispatch[0]), hex(dispatch[1]), hex(image.offset(dispatch[1], 4)),
                dispatch[2].hex(), hex(dispatch[3]), hex(content_child), hex(boxed_child),
                hex(payload), hex(parent_child))])

    power_base = decode_rip(image.read(0x54e34ed, 7, executable=True), 0x54e34ed, b'\x48\x8d\x0d')
    powers = []
    for i in range(20):
        va = power_base + 8 * i
        raw = image.read(va, 8)
        powers.append((i, hex(va), hex(image.offset(va, 8)), raw.hex(), struct.unpack('<d', raw)[0].hex()))
    write_tsv(out / 'sampled-f64-powers.tsv', ('index', 'va', 'file_offset', 'raw_hex', 'binary64_hex'), powers)

    metadata = {
        'artifact': 'artifacts/node/115/hl-node', 'sha256': DIGEST,
        'coordinate_system': 'linked ELF virtual addresses; file offsets are zero-based',
        'scope': 'selected static path; no target execution or exhaustive function census',
        'function_count': len(functions), 'window_count': len(slices),
        'direct_edge_count': len(edges), 'indirect_call_count': len(relocs),
        'import_call_count': len(imports),
        'selected_switch_count': len(tables),
        'selected_name_match_count': 1,
        'selected_decode_route_count': 1,
        'selected_nested_handoff_count': 1,
        'constants': {key: hex(value) for key, value in sorted(c.items())},
        'sampling': '20 consecutive binary64 entries; table bounds are not established',
    }
    (out / 'summary.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    image = Image(ARTIFACT.read_bytes())
    generate(image, args.out)


if __name__ == '__main__':
    main()
