#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Extract selected node 115 CValidator subtype and state-removal evidence.

This is a fixed-site byte reader, not a disassembler or an executor. Addresses
are linked ELF virtual addresses and extents are half-open. The selected branch
and call sites were located by static inspection; no unselected instructions are
inferred to be unreachable. Synthetic models below are not target executions.
"""
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

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
MASK64 = (1 << 64) - 1

# The starts are manually selected investigation sites, not a function census.
# An indexed FDE start, its decoded end, the header entry and file backing must
# all agree. An FDE alone cannot establish complete source-level boundaries.
FUNCTIONS = (
    ('outer_clone', 0x565a210),
    ('outer_serializer', 0x53b2db0),
    ('nested_field_adapter', 0x526e9f0),
    ('nested_field_serializer', 0x5382f60),
    ('variant_visitor', 0x574d0f0),
    ('nested_clone', 0x5659f70),
    ('nested_serializer', 0x5382a50),
    ('state_dispatch', 0x3c3d480),
    ('stake_compact_lookup', 0x4554e80),
    ('profile_compact_lookup', 0x4554cb0),
    ('index_compact_lookup', 0x4555050),
    ('first_map_remove', 0x3ce5780),
    ('profile_compact_remove', 0x4562050),
    ('index_compact_remove', 0x4562190),
    ('index_tree_remove', 0x3903310),
    ('profile_shift', 0x4577ce0),
    ('index_shift', 0x4575f60),
    ('state_followup', 0x3c36ba0),
    ('followup_tree_entry', 0x370bed0),
    ('followup_compact_lookup', 0x455a9e0),
    ('followup_compact_insert', 0x4548f00),
    ('followup_tree_insert', 0x370d5e0),
)

# Selected, instruction-aligned byte ranges supporting dataflow and constants.
# Fixed starts/ends are not used as a body-size denominator.
WINDOWS = (
    ('outer_switch', 'outer_clone', 0x565a21f, 0x565a242),
    ('outer_selected_payload', 'outer_clone', 0x565a61c, 0x565a62e),
    ('outer_copy_and_tag', 'outer_clone', 0x565a62e, 0x565a68e),
    ('outer_serializer_switch', 'outer_serializer', 0x53b2db0, 0x53b2de1),
    ('outer_serializer_selected_arm', 'outer_serializer', 0x53b455b, 0x53b45cd),
    ('outer_serializer_second_field', 'outer_serializer', 0x53b45cd, 0x53b460a),
    ('nested_field_adapter', 'nested_field_adapter', 0x526e9f0, 0x526ea47),
    ('nested_field_tag_gate', 'nested_field_serializer', 0x5382f74, 0x5382f9c),
    ('nested_field_unregister', 'nested_field_serializer', 0x538307c, 0x53830aa),
    ('visitor_entry_and_content_choice', 'variant_visitor', 0x574d0f0, 0x574d121),
    ('visitor_missing_field_descriptor', 'variant_visitor', 0x574d5d7, 0x574d61e),
    ('visitor_first_success_tag', 'variant_visitor', 0x574da6c, 0x574dac2),
    ('visitor_second_success_tag', 'variant_visitor', 0x574dd4c, 0x574ddbd),
    ('clone_tag_gate', 'nested_clone', 0x5659f84, 0x5659fab),
    ('clone_other_canonicalizes', 'nested_clone', 0x565a097, 0x565a09f),
    ('clone_other_store_return', 'nested_clone', 0x565a180, 0x565a19b),
    ('name_tag_gate', 'nested_serializer', 0x5382a66, 0x5382a8e),
    ('name_change_profile', 'nested_serializer', 0x5382a8e, 0x5382ab9),
    ('name_register', 'nested_serializer', 0x5382af5, 0x5382b1d),
    ('name_unregister', 'nested_serializer', 0x5382b69, 0x5382b96),
    ('core_tag_gate', 'state_dispatch', 0x3c3d4a4, 0x3c3d4ed),
    ('core_first_map_choice', 'state_dispatch', 0x3c3d61d, 0x3c3d64f),
    ('core_tree_key_compare', 'state_dispatch', 0x3c3d660, 0x3c3d716),
    ('core_first_compact_lookup', 'state_dispatch', 0x3c3da7f, 0x3c3dacd),
    ('core_first_nonzero_rejection', 'state_dispatch', 0x3c3dacd, 0x3c3dae8),
    ('core_profile_map_choice', 'state_dispatch', 0x3c3dae8, 0x3c3db19),
    ('core_profile_tree_compare', 'state_dispatch', 0x3c3db2c, 0x3c3dbc3),
    ('core_profile_compact_lookup', 'state_dispatch', 0x3c3dbc3, 0x3c3dc0d),
    ('core_profile_missing_status', 'state_dispatch', 0x3c3dd17, 0x3c3dd2a),
    ('core_found_profile_and_first_remove', 'state_dispatch', 0x3c3dee2, 0x3c3df5c),
    ('core_profile_second_lookup', 'state_dispatch', 0x3c3e026, 0x3c3e047),
    ('core_tree_profile_remove', 'state_dispatch', 0x3c3e250, 0x3c3e2ae),
    ('core_compact_profile_remove', 'state_dispatch', 0x3c3e2ae, 0x3c3e2de),
    ('core_profile_repr_threshold', 'state_dispatch', 0x3c3e451, 0x3c3e498),
    ('core_profile_repr_replace', 'state_dispatch', 0x3c3e4f8, 0x3c3e542),
    ('core_index_remove_route', 'state_dispatch', 0x3c3e587, 0x3c3e5dc),
    ('core_index_repr_threshold', 'state_dispatch', 0x3c3e5dc, 0x3c3e628),
    ('core_index_repr_replace', 'state_dispatch', 0x3c3e746, 0x3c3e780),
    ('core_success', 'state_dispatch', 0x3c3e780, 0x3c3e794),
    ('compact_stake_stride', 'stake_compact_lookup', 0x4554f0f, 0x4554f28),
    ('compact_profile_stride', 'profile_compact_lookup', 0x4554d40, 0x4554d59),
    ('compact_index_stride', 'index_compact_lookup', 0x45550e2, 0x4555106),
    ('compact_lookup_match_result', 'profile_compact_lookup', 0x4554e37, 0x4554e77),
    ('first_remove_representation', 'first_map_remove', 0x3ce5791, 0x3ce57da),
    ('first_remove_compact_lookup', 'first_map_remove', 0x3ce583d, 0x3ce5866),
    ('first_remove_compact_shift_count', 'first_map_remove', 0x3ce598f, 0x3ce59bb),
    ('profile_remove_bounds', 'profile_compact_remove', 0x4562059, 0x4562069),
    ('profile_remove_stride', 'profile_compact_remove', 0x4562086, 0x45620af),
    ('profile_remove_split', 'profile_compact_remove', 0x45620d9, 0x456210f),
    ('profile_remove_start_count', 'profile_compact_remove', 0x456210f, 0x456213a),
    ('index_remove_bounds', 'index_compact_remove', 0x4562199, 0x45621a5),
    ('index_remove_stride', 'index_compact_remove', 0x45621c2, 0x45621ed),
    ('index_remove_split', 'index_compact_remove', 0x45621ed, 0x4562219),
    ('index_remove_start_count', 'index_compact_remove', 0x4562219, 0x4562244),
    ('tree_remove_key_width', 'index_tree_remove', 0x390338a, 0x39033b7),
    ('tree_remove_count', 'index_tree_remove', 0x390341b, 0x390346c),
    ('profile_shift_selected_memmove', 'profile_shift', 0x4577d33, 0x4577d55),
    ('index_shift_selected_memmove', 'index_shift', 0x4575fb7, 0x4575feb),
    ('followup_entry', 'state_followup', 0x3c36ba0, 0x3c36be8),
    ('followup_last_value', 'state_followup', 0x3c36cae, 0x3c36d01),
    ('followup_secondary_insert', 'state_followup', 0x3c36d68, 0x3c36dd3),
    ('followup_secondary_compare', 'state_followup', 0x3c36eea, 0x3c36f26),
    ('followup_map_conversion_stores', 'state_followup', 0x3c36dd3, 0x3c36e30),
    ('followup_map_replace', 'state_followup', 0x3c37006, 0x3c37033),
    ('followup_map_lookup_threshold', 'state_followup', 0x3c37033, 0x3c37078),
    ('followup_map_conversion', 'state_followup', 0x3c37078, 0x3c370d5),
    ('followup_compact_insert', 'state_followup', 0x3c37140, 0x3c371e6),
    ('followup_compact_found', 'state_followup', 0x3c37216, 0x3c37252),
    ('followup_tree_compare', 'state_followup', 0x3c3731c, 0x3c37351),
    ('followup_replace_value', 'state_followup', 0x3c3738a, 0x3c373c6),
    ('followup_tree_insert', 'state_followup', 0x3c373c6, 0x3c3744b),
    ('followup_bounds_failure', 'state_followup', 0x3c3745b, 0x3c3748d),
    ('tree_entry_root_choice', 'followup_tree_entry', 0x370bed0, 0x370bee6),
    ('tree_entry_existing_root', 'followup_tree_entry', 0x370bee6, 0x370bf3c),
    ('tree_entry_empty_root', 'followup_tree_entry', 0x370bf3c, 0x370bf6a),
    ('tree_entry_insert_key', 'followup_tree_entry', 0x370bf6a, 0x370bf99),
    ('tree_entry_count_and_return', 'followup_tree_entry', 0x370bf99, 0x370bfbc),
    ('tree_entry_failure_calls', 'followup_tree_entry', 0x370bfbc, 0x370bfe5),
    ('followup_lookup_empty', 'followup_compact_lookup', 0x455a9eb, 0x455aa15),
    ('followup_lookup_missing', 'followup_compact_lookup', 0x455aa70, 0x455aa89),
    ('followup_lookup_equal', 'followup_compact_lookup', 0x455aae0, 0x455ab0f),
    ('followup_lookup_result', 'followup_compact_lookup', 0x455ab67, 0x455aba7),
    ('followup_insert_check', 'followup_compact_insert', 0x4548f08, 0x4548f36),
    ('followup_insert_split', 'followup_compact_insert', 0x4548f36, 0x4548f42),
    ('followup_insert_shift_tail', 'followup_compact_insert', 0x4548f42, 0x4548f89),
    ('followup_insert_shift_head', 'followup_compact_insert', 0x4548f89, 0x4548fba),
    ('followup_insert_copy', 'followup_compact_insert', 0x4548fba, 0x4548fe4),
    ('followup_insert_bad_index', 'followup_compact_insert', 0x4548ff0, 0x4549009),
    ('followup_tree_insert_choice', 'followup_tree_insert', 0x370d5e0, 0x370d5fb),
    ('followup_tree_insert_existing', 'followup_tree_insert', 0x370d5fb, 0x370d657),
    ('followup_tree_insert_empty', 'followup_tree_insert', 0x370d657, 0x370d68f),
    ('followup_tree_insert_key_value', 'followup_tree_insert', 0x370d68f, 0x370d6db),
    ('followup_tree_insert_count', 'followup_tree_insert', 0x370d6db, 0x370d701),
    ('followup_tree_insert_failures', 'followup_tree_insert', 0x370d701, 0x370d72a),
)

# These are selected transfer sites, not a whole-CFG branch census. Every
# rel8/rel32 destination is decoded and checked against its expected target.
BRANCHES = (
    ('serializer_struct_start_error', 0x53b459e, 'jne', 0x53b5222),
    ('serializer_nested_field_error', 0x53b45d2, 'jne', 0x53b518b),
    ('serializer_second_field_success', 0x53b45ff, 'je', 0x53b521d),
    ('adapter_no_prefix', 0x526ea03, 'je', 0x526ea19),
    ('adapter_prefix_error', 0x526ea17, 'jne', 0x526ea29),
    ('field_serializer_zero', 0x5382f90, 'je', 0x538300c),
    ('field_serializer_other', 0x5382f96, 'jne', 0x538307c),
    ('visitor_sequence', 0x574d112, 'je', 0x574d5a3),
    ('visitor_unsupported_content', 0x574d11b, 'jne', 0x574de98),
    ('visitor_empty_sequence', 0x574d5da, 'je', 0x574d5f2),
    ('visitor_present_first_element', 0x574d5ec, 'jne', 0x574d728),
    ('nested_name_zero', 0x5382a82, 'je', 0x5382af5),
    ('nested_name_not_one', 0x5382a88, 'jne', 0x5382b69),
    ('clone_zero', 0x5659f9f, 'je', 0x5659fc7),
    ('clone_not_one', 0x5659fa5, 'jne', 0x565a097),
    ('core_global_hook', 0x3c3d4b6, 'jne', 0x3c3f108),
    ('core_zero', 0x3c3d4dd, 'je', 0x3c3d5ce),
    ('core_not_one', 0x3c3d4e7, 'jne', 0x3c3d61d),
    ('first_compact', 0x3c3d639, 'jne', 0x3c3da7f),
    ('first_tree_empty', 0x3c3d649, 'je', 0x3c3dae8),
    ('first_tree_match', 0x3c3d6e3, 'je', 0x3c3dacd),
    ('first_tree_exhausted', 0x3c3d703, 'jb', 0x3c3dae8),
    ('first_compact_not_found', 0x3c3da92, 'jne', 0x3c3dae8),
    ('first_compact_index_outside', 0x3c3daa0, 'jae', 0x3c3dae8),
    ('first_value_zero', 0x3c3dad2, 'je', 0x3c3dae8),
    ('profile_compact', 0x3c3db03, 'jne', 0x3c3dbc3),
    ('profile_tree_empty', 0x3c3db13, 'je', 0x3c3dc0d),
    ('profile_tree_match', 0x3c3db9c, 'jmp', 0x3c3dee2),
    ('profile_tree_exhausted', 0x3c3dbaf, 'jb', 0x3c3dc0d),
    ('profile_compact_not_found', 0x3c3dbd7, 'jne', 0x3c3dc0d),
    ('profile_compact_index_outside', 0x3c3dbe0, 'jae', 0x3c3dc0d),
    ('profile_compact_found', 0x3c3dc08, 'jmp', 0x3c3deec),
    ('profile_again_compact', 0x3c3df56, 'jne', 0x3c3e026),
    ('profile_again_tree_empty', 0x3c3df6b, 'je', 0x3c3e29c),
    ('profile_again_tree_match', 0x3c3dffb, 'jmp', 0x3c3e250),
    ('profile_again_tree_exhausted', 0x3c3e013, 'jb', 0x3c3e29c),
    ('profile_again_compact_found', 0x3c3e037, 'jne', 0x3c3e2ae),
    ('profile_again_compact_absent', 0x3c3e042, 'jmp', 0x3c3e587),
    ('profile_compact_result_present', 0x3c3e2cb, 'jne', 0x3c3e400),
    ('profile_no_tree_conversion', 0x3c3e46e, 'jne', 0x3c3e542),
    ('index_compact', 0x3c3e58e, 'jne', 0x3c3e5ab),
    ('index_compact_absent', 0x3c3e5c6, 'jne', 0x3c3e76e),
    ('index_no_tree_conversion', 0x3c3e5fe, 'jne', 0x3c3e76e),
    ('index_drain_loop', 0x3c3e744, 'jne', 0x3c3e730),
    ('success_return', 0x3c3e78f, 'jmp', 0x3c3f0e6),
    ('first_remove_compact_found', 0x3ce584c, 'jne', 0x3ce585a),
    ('first_remove_bad_index', 0x3ce5864, 'jbe', 0x3ce58bb),
    ('first_remove_prefix_choice', 0x3ce5897, 'jae', 0x3ce598f),
    ('profile_remove_bad_index', 0x4562063, 'jbe', 0x45620ff),
    ('profile_remove_prefix_choice', 0x45620e5, 'jae', 0x456210f),
    ('index_remove_bad_index', 0x45621a3, 'jbe', 0x4562213),
    ('index_remove_prefix_choice', 0x45621f9, 'jae', 0x4562219),
    ('followup_last_compact', 0x3c36bc8, 'jno', 0x3c36ccb),
    ('followup_last_tree_empty', 0x3c36bd5, 'je', 0x3c36e72),
    ('followup_first_tree_matched', 0x3c36f21, 'jmp', 0x3c36db9),
    ('followup_first_tree_exhausted', 0x3c36f41, 'jb', 0x3c36d6b),
    ('followup_no_small_tree_conversion', 0x3c36dfd, 'jne', 0x3c37033),
    ('followup_second_map_tree', 0x3c37040, 'je', 0x3c372b6),
    ('followup_no_large_compact_conversion', 0x3c37072, 'je', 0x3c37129),
    ('followup_compact_found', 0x3c37142, 'je', 0x3c37216),
    ('followup_compact_bad_index', 0x3c37219, 'jae', 0x3c37474),
    ('followup_tree_found', 0x3c3734f, 'jmp', 0x3c3738a),
    ('followup_tree_exhausted', 0x3c37376, 'jb', 0x3c373c9),
    ('followup_tree_insert_success', 0x3c37449, 'jne', 0x3c37462),
    ('followup_result_bad_index', 0x3c37460, 'jae', 0x3c37474),
    ('tree_entry_empty_root', 0x370bee4, 'je', 0x370bf3c),
    ('tree_entry_existing_root_continues', 0x370bf3a, 'jmp', 0x370bf99),
    ('tree_entry_allocation_failure', 0x370bf4d, 'je', 0x370bfbc),
    ('tree_entry_node_full', 0x370bf75, 'jae', 0x370bfcc),
    ('followup_lookup_empty', 0x455a9f5, 'je', 0x455aa63),
    ('followup_lookup_empty_result', 0x455aa83, 'je', 0x455ab95),
    ('followup_lookup_equal', 0x455aaf0, 'je', 0x455ab05),
    ('followup_lookup_missing_return', 0x455ab00, 'jmp', 0x455ab95),
    ('followup_lookup_found_return', 0x455ab0a, 'jmp', 0x455ab95),
    ('followup_insert_bad_index', 0x4548f0f, 'ja', 0x4548ff0),
    ('followup_insert_no_growth', 0x4548f24, 'jne', 0x4548f36),
    ('followup_insert_head_choice', 0x4548f40, 'jae', 0x4548f89),
    ('followup_tree_empty', 0x370d5f9, 'je', 0x370d657),
    ('followup_tree_existing_continues', 0x370d652, 'jmp', 0x370d6db),
    ('followup_tree_allocation_failure', 0x370d668, 'je', 0x370d701),
    ('followup_tree_node_full', 0x370d69a, 'jae', 0x370d711),
)

# Only direct rel32 calls are listed here. Shared targets are call boundaries,
# not analyzed functions. Further indirect calls and unwind edges are outside
# this selected list.
CALLS = (
    ('outer_clones_nested', 0x565a629, 0x5659f70),
    ('serializer_nested_field', 0x53b45c8, 0x526e9f0),
    ('serializer_second_field', 0x53b45f5, 0x526efb0),
    ('adapter_serializes_nested', 0x526ea22, 0x5382f60),
    ('serialize_unregister_name', 0x538308b, 0x57cf860),
    ('visitor_missing_field_error', 0x574d606, 0x47d2d20),
    ('first_compact_search', 0x3c3da8b, 0x4554e80),
    ('profile_compact_search', 0x3c3dbcb, 0x4554cb0),
    ('cleanup_shared_result', 0x3c3def8, 0x3d08df0),
    ('remove_first_map', 0x3c3df4e, 0x3ce5780),
    ('profile_search_again', 0x3c3e02e, 0x4554cb0),
    ('profile_tree_remove', 0x3c3e28c, 0x3712d20),
    ('profile_compact_remove', 0x3c3e2b9, 0x4562050),
    ('index_tree_remove', 0x3c3e5a4, 0x3903310),
    ('index_compact_search', 0x3c3e5ba, 0x4555050),
    ('index_compact_remove', 0x3c3e5d7, 0x4562190),
    ('followup', 0x3c3e77b, 0x3c36ba0),
    ('first_compact_search', 0x3ce5843, 0x4557ad0),
    ('first_compact_shift', 0x3ce59af, 0x4574800),
    ('profile_shift', 0x456212e, 0x4577ce0),
    ('index_shift', 0x4562238, 0x4575f60),
    ('tree_remove_inner', 0x390341b, 0x35bc320),
    ('followup_map_entry', 0x3c36db4, 0x370bed0),
    ('followup_drain_old_tree', 0x3c37006, 0x3904f30),
    ('followup_compact_search', 0x3c37055, 0x455a9e0),
    ('followup_compact_conversion', 0x3c370bf, 0x3883600),
    ('followup_compact_insert', 0x3c371d9, 0x4548f00),
    ('followup_tree_insert', 0x3c3743b, 0x370d5e0),
    ('tree_entry_existing_root', 0x370bf23, 0x3506430),
    ('followup_insert_shift_tail', 0x4548f71, 0x4577220),
    ('followup_insert_shift_head', 0x4548fa2, 0x4577220),
    ('followup_tree_existing', 0x370d63b, 0x35120e0),
)

RELOCATION_SLOTS = (
    ('core_entry_slot', 0x64e7f10, 8, 0x3c3d480, ''),
    ('comparison_slot', 0x64dfb50, 6, 0, 'memcmp'),
    ('shift_slot', 0x64df568, 6, 0, 'memmove'),
    ('visitor_description', 0x64aff08, 8, 0x9345ad, ''),
    ('tree_entry_allocate_slot', 0x64df480, 8, 0x6355830, ''),
    ('tree_entry_alloc_failure_slot', 0x64df490, 8, 0x141e251, ''),
    ('tree_entry_bound_failure_slot', 0x64df730, 8, 0x1680e60, ''),
    ('compact_insert_growth_slot', 0x64eacc0, 8, 0x4561690, ''),
    ('compact_insert_failure_slot', 0x64df6b8, 8, 0x1680e80, ''),
)


def verify_digest(data, expected=DIGEST):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('target SHA-256 mismatch')


def expect(raw, prefix, label):
    if not raw.startswith(bytes.fromhex(prefix)):
        raise ValueError('unexpected bytes: ' + label)


def va_offset(secs, va, size):
    """Resolve a complete range through exactly one file-backed ELF section."""
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid byte range')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('range is not uniquely file backed')
    return matches[0]['offset'] + va - matches[0]['address']


def get_bytes(data, secs, va, size):
    off = va_offset(secs, va, size)
    out = data[off:off + size]
    if len(out) != size:
        raise ValueError('truncated byte range')
    return out


REL8 = {0x70: 'jo', 0x71: 'jno', 0x72: 'jb', 0x73: 'jae',
        0x74: 'je', 0x75: 'jne', 0x76: 'jbe', 0x77: 'ja', 0xeb: 'jmp'}
REL32 = {0x80: 'jo', 0x81: 'jno', 0x82: 'jb', 0x83: 'jae',
         0x84: 'je', 0x85: 'jne', 0x86: 'jbe', 0x87: 'ja'}


def decode_transfer(raw, va):
    if len(raw) >= 2 and raw[0] in REL8:
        return REL8[raw[0]], va + 2 + struct.unpack_from('<b', raw, 1)[0], raw[:2]
    if len(raw) >= 6 and raw[0] == 0x0f and raw[1] in REL32:
        return REL32[raw[1]], va + 6 + struct.unpack_from('<i', raw, 2)[0], raw[:6]
    if len(raw) >= 5 and raw[0] in (0xe8, 0xe9):
        return ('call' if raw[0] == 0xe8 else 'jmp',
                va + 5 + struct.unpack_from('<i', raw, 1)[0], raw[:5])
    raise ValueError('unsupported or truncated transfer')


def checked_transfer(raw, va, kind, target):
    actual_kind, actual_target, used = decode_transfer(raw, va)
    if (actual_kind, actual_target) != (kind, target):
        raise ValueError('transfer mismatch')
    return used


def rip_lea(raw, va, prefix):
    if len(raw) < 7 or raw[:3] != bytes.fromhex(prefix):
        raise ValueError('unexpected RIP-relative lea')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def fixed_immediate(data, secs, va, prefix, fmt):
    """Decode only a specified fixed instruction prefix and its next field."""
    opcode = bytes.fromhex(prefix)
    raw = get_bytes(data, secs, va, len(opcode) + struct.calcsize(fmt))
    if not raw.startswith(opcode):
        raise ValueError('fixed immediate prefix mismatch')
    return struct.unpack_from(fmt, raw, len(opcode))[0], raw


def classify_word(word):
    """Model the observed wrapping arithmetic; this is not an input validator."""
    if type(word) is not int or not 0 <= word <= MASK64:
        raise ValueError('word outside u64')
    return ((word + (1 << 63) + 1) & MASK64) if word >> 63 else 0


def clone_other_word(word):
    if classify_word(word) < 2:
        raise ValueError('word does not take the other branch')
    return (1 << 63) + 1


def compact_removal_model(capacity, start, length, index):
    """Selected unsigned ring-index choices, assuming valid container invariants."""
    if any(type(v) is not int for v in (capacity, start, length, index)):
        raise ValueError('non-integer model input')
    if not (0 < capacity <= MASK64 and 0 <= start < capacity and
            0 <= length <= capacity and 0 <= index <= MASK64):
        raise ValueError('invalid compact-container model')
    if index >= length:
        return ('out_of_range', start, length, 0)
    tail = length - index - 1
    if tail >= index:
        return ('prefix', (start + 1) % capacity, length - 1, index)
    return ('suffix', start, length - 1, tail)


def removal_outcome(first_found, first_nonzero, profile_found):
    """Normal-return path model; assumes checked calls return normally."""
    if any(type(x) is not bool for x in (first_found, first_nonzero, profile_found)):
        raise ValueError('outcome inputs must be booleans')
    if first_found and first_nonzero:
        return 'first_nonzero', 0x144
    if not profile_found:
        return 'profile_missing', 0x95
    return 'remove_path', 0x1a2


def small_tree_conversion(representation, count):
    """Model the selected sentinel-and-size predicate, not container validity."""
    if any(type(v) is not int or not 0 <= v <= MASK64 for v in (representation, count)):
        raise ValueError('representation inputs must be u64 values')
    return representation == (1 << 63) and count < 0x20


def followup_representation_route(representation, count, lookup_missing):
    """Model the selected follow-up routing after a normal compact lookup."""
    if any(type(v) is not int or not 0 <= v <= MASK64 for v in (representation, count)):
        raise ValueError('representation inputs must be u64 values')
    if type(lookup_missing) is not bool:
        raise ValueError('lookup_missing must be boolean')
    if representation == (1 << 63):
        return 'tree_route'
    if lookup_missing and count >= 0x40:
        return 'compact_conversion'
    return 'compact_route'


def rows_tsv(columns, rows):
    output = io.StringIO(newline='')
    writer = csv.writer(output, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    writer.writerows(rows)
    return output.getvalue().encode('utf-8')


def hx(value):
    return '' if value is None else hex(value)


def find_relocations(data, secs):
    wanted = {x[1] for x in RELOCATION_SLOTS}
    result = {}
    rela_sections = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(rela_sections) != 1:
        raise ValueError('missing or ambiguous relocation section')
    sec = rela_sections[0]
    if sec['size'] % 24:
        raise ValueError('misaligned RELA section')
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        va, info, addend = struct.unpack_from('<QQq', data, off)
        if va in wanted:
            if va in result:
                raise ValueError('duplicate selected relocation')
            result[va] = (off, info & 0xffffffff, info >> 32, addend)
    if set(result) != wanted:
        raise ValueError('selected relocation absent')
    return result


def dynamic_symbol(data, secs, index):
    tables = [s for s in secs if s['name'] == '.dynsym' and s['type'] != 8]
    strings = [s for s in secs if s['name'] == '.dynstr' and s['type'] != 8]
    if len(tables) != 1 or len(strings) != 1:
        raise ValueError('missing dynamic symbol table')
    sym, st = tables[0], strings[0]
    if index < 0 or 24 * (index + 1) > sym['size']:
        raise ValueError('symbol outside dynsym')
    name_off = struct.unpack_from('<I', data, sym['offset'] + index * 24)[0]
    if name_off >= st['size']:
        raise ValueError('symbol name outside dynstr')
    start = st['offset'] + name_off
    end = data.find(b'\0', start, st['offset'] + st['size'])
    if end < 0:
        raise ValueError('unterminated dynamic symbol')
    return data[start:end].decode('ascii')


def load_image(data):
    verify_digest(data)
    secs, header = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    wanted = {start for _, start in FUNCTIONS}
    headers = {}
    for row in header:
        if row['start'] in wanted:
            if row['start'] in headers:
                raise ValueError('duplicate selected unwind header entry')
            headers[row['start']] = row
    selected = {}
    for row in fdes:
        if row['start'] in wanted:
            if row['start'] in selected:
                raise ValueError('duplicate selected FDE')
            selected[row['start']] = row
    if set(headers) != wanted or set(selected) != wanted:
        raise ValueError('selected FDE or indexed start missing')
    for start in wanted:
        fde, entry = selected[start], headers[start]
        if fde['fde'] != entry['fde'] or fde['end'] <= start:
            raise ValueError('FDE header mismatch')
        if fde['end'] > entry['next_index_upper_bound']:
            raise ValueError('selected FDE crosses indexed bound')
        off = va_offset(secs, start, fde['end'] - start)
        executable = [s for s in secs if s['type'] != 8 and s['flags'] & 4 and
                      s['address'] <= start and fde['end'] <= s['address'] + s['size']]
        if len(executable) != 1 or off + fde['end'] - start > len(data):
            raise ValueError('selected FDE is not executable file data')
    return secs, headers, selected


def owner_of(va, by_name):
    owners = [(name, fde) for name, fde in by_name.items()
              if fde['start'] <= va < fde['end']]
    if len(owners) != 1:
        raise ValueError('selected site has no unique selected FDE')
    return owners[0][0]


def generate(data):
    secs, headers, selected = load_image(data)
    named = {name: selected[start] for name, start in FUNCTIONS}
    out = {}
    function_rows, body_rows = [], []
    for name, start in FUNCTIONS:
        f = selected[start]
        body = get_bytes(data, secs, start, f['end'] - start)
        off = va_offset(secs, start, len(body))
        function_rows.append((name, hx(start), hx(f['end']), hx(off), hx(f['fde']),
                              hx(f['cie']), hx(f['lsda']), headers[start]['index'],
                              len(body), hashlib.sha256(body).hexdigest()))
        body_rows.append((name, hx(start), len(body), body.hex()))
    out['functions.tsv'] = rows_tsv(('role', 'start_va', 'end_va_exclusive',
        'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'size',
        'sha256'), function_rows)
    out['bodies.tsv'] = rows_tsv(('role', 'start_va', 'length', 'body_hex'), body_rows)

    window_rows = []
    for label, role, start, end in WINDOWS:
        f = named[role]
        if not f['start'] <= start < end <= f['end']:
            raise ValueError('window crosses selected FDE')
        window_rows.append((label, role, hx(start), hx(end),
                            hx(va_offset(secs, start, end - start)),
                            get_bytes(data, secs, start, end - start).hex()))
    out['windows.tsv'] = rows_tsv(('label', 'owner', 'start_va', 'end_va_exclusive',
                                   'file_offset', 'raw_hex'), window_rows)

    branch_rows = []
    for label, va, kind, target in BRANCHES:
        raw = checked_transfer(get_bytes(data, secs, va, 6), va, kind, target)
        branch_rows.append((label, owner_of(va, named), hx(va),
                            hx(va_offset(secs, va, len(raw))), raw.hex(), kind, hx(target)))
    out['branches.tsv'] = rows_tsv(('label', 'owner', 'site_va', 'file_offset',
                                   'raw_hex', 'condition', 'target_va'), branch_rows)
    call_rows = []
    for label, va, target in CALLS:
        raw = checked_transfer(get_bytes(data, secs, va, 5), va, 'call', target)
        call_rows.append((label, owner_of(va, named), hx(va),
                          hx(va_offset(secs, va, len(raw))), raw.hex(), hx(target),
                          'selected' if target in selected else 'external_boundary'))
    out['calls.tsv'] = rows_tsv(('label', 'owner', 'site_va', 'file_offset',
                                 'raw_hex', 'target_va', 'target_scope'), call_rows)

    relocs = find_relocations(data, secs)
    reloc_rows = []
    for name, slot, expected_type, expected_addend, expected_symbol in RELOCATION_SLOTS:
        off, typ, symbol_index, addend = relocs[slot]
        symbol = dynamic_symbol(data, secs, symbol_index) if symbol_index else ''
        if (typ, addend, symbol) != (expected_type, expected_addend, expected_symbol):
            raise ValueError('relocation mismatch: ' + name)
        reloc_rows.append((name, hx(slot), hx(off), typ, symbol_index, symbol,
                           hx(addend), data[off:off + 24].hex()))
    out['relocations.tsv'] = rows_tsv(('role', 'slot_va', 'rela_file_offset', 'type',
        'symbol_index', 'symbol', 'addend', 'raw_hex'), reloc_rows)

    # Each operand is decoded at a hand-selected instruction with a fixed byte
    # prefix. These are not an instruction census or a general disassembler.
    immediate_specs = (
        ('outer_internal_tag', 0x565a682, '48c703', '<I', 0x3b),
        ('outer_serializer_ordinal', 0x53b4583, '41b8', '<I', 0x27),
        ('outer_serializer_field_count', 0x53b4589, '6a', '<B', 2),
        ('outer_first_payload_offset', 0x53b45a4, '4d8d46', '<B', 8),
        ('outer_second_payload_offset', 0x53b45d8, '4983c6', '<B', 0x70),
        ('outer_first_name_length', 0x53b45c3, 'b9', '<I', 1),
        ('outer_second_name_length', 0x53b45ed, 'b9', '<I', 1),
        ('state_representation_sentinel', 0x3c3d4a4, '49bd', '<Q', 1 << 63),
        ('first_lookup_state_offset', 0x3c3d62a, '488b98', '<I', 0x110),
        ('key_comparison_bytes', 0x3c3d6a9, 'ba', '<I', 0x14),
        ('first_lookup_value_offset', 0x3c3dacd, '48837b', '<B', 0x20),
        ('second_lookup_state_offset', 0x3c3daed, '4c8db0', '<I', 0xd0),
        ('first_remove_state_offset', 0x3c3df3d, '488d70', '<B', 0x10),
        ('copied_profile_field_offset', 0x3c3df02, '410f104424', '<B', 0x3c),
        ('copied_profile_field_tail_offset', 0x3c3df10, '418b4424', '<B', 0x4c),
        ('third_remove_state_offset', 0x3c3e587, '4c39ab', '<I', 0x288),
        ('first_nonzero_result', 0x3c3dadc, '6641c70424', '<H', 0x144),
        ('second_missing_result', 0x3c3dd1e, '6641c70424', '<H', 0x95),
        ('normal_remove_result', 0x3c3e788, '6641c70424', '<H', 0x1a2),
        ('first_lookup_stride_shift', 0x4554f12, '49c1e7', '<B', 6),
        ('second_lookup_stride', 0x4554d40, '486bcd', '<B', 0x70),
        ('third_lookup_stride_shift', 0x45550ed, '48c1e5', '<B', 4),
        ('second_small_tree_threshold', 0x3c3e462, '4883f8', '<B', 0x20),
        ('third_small_tree_threshold', 0x3c3e5f2, '4883f8', '<B', 0x20),
        ('followup_first_state_offset', 0x3c36d50, '4d8ba6', '<I', 0x180),
        ('followup_second_state_offset', 0x3c36dd3, '498b9e', '<I', 0x1e8),
        ('followup_last_collection_offset', 0x3c36bbe, '488b47', '<B', 0x48),
        ('followup_compact_record_stride', 0x3c37241, '486bd6', '<B', 0x38),
        ('tree_entry_empty_node_size', 0x370bf3f, 'bf', '<I', 0xe8),
        ('tree_entry_node_slot_limit', 0x370bf71, '4883f9', '<B', 0xb),
        ('tree_entry_initial_node_count', 0x370bf56, '66c780e6000000', '<H', 0),
        ('tree_entry_key_tail_offset', 0x370bf85, '418b76', '<B', 0x30),
        ('tree_entry_key_first_offset', 0x370bf8d, '410f1046', '<B', 0x20),
        ('tree_insert_empty_node_size', 0x370d65a, 'bf', '<I', 0x248),
        ('tree_insert_node_slot_limit', 0x370d696, '4883f9', '<B', 0xb),
        ('tree_insert_initial_node_count', 0x370d679, '66c78046020000', '<H', 0),
        ('compact_insert_record_stride', 0x4548fba, '496bc7', '<B', 0x38),
        ('followup_small_tree_threshold', 0x3c36df1, '4883f8', '<B', 0x20),
        ('followup_large_compact_threshold', 0x3c37067, '4883fe', '<B', 0x40),
        ('visitor_sequence_content_tag', 0x574d107, '83fd', '<B', 0x14),
        ('visitor_missing_marker', 0x574d60b, '49c706', '<I', 0x86),
        ('nested_unregister_name_length', 0x5383083, 'ba', '<I', 10),
        ('nested_enum_type_length', 0x5382b7b, 'b9', '<I', 16),
    )
    operand_rows = []
    operands = {}
    for label, site, prefix, fmt, expected in immediate_specs:
        value, raw = fixed_immediate(data, secs, site, prefix, fmt)
        if value != expected:
            raise ValueError('immediate mismatch: ' + label)
        operands[label] = value
        operand_rows.append((label, owner_of(site, named), hx(site),
                             hx(va_offset(secs, site, len(raw))), raw.hex(), hx(value)))
    # The LEA and ADD form three times the index before the selected shift.
    expect(get_bytes(data, secs, 0x45550e2, 11),
           '4a8d2c6d000000004c01ed', 'index triple')
    derived_rows = (
        ('first_lookup_record_stride', '1 << first_lookup_stride_shift',
         1 << operands['first_lookup_stride_shift']),
        ('third_lookup_record_stride', '3 << third_lookup_stride_shift',
         3 << operands['third_lookup_stride_shift']),
    )
    out['operands.tsv'] = rows_tsv(('label', 'owner', 'site_va', 'file_offset',
                                    'prefix_and_operand_hex', 'value'), operand_rows)
    out['derived-operands.tsv'] = rows_tsv(('label', 'formula', 'value'),
                                           [(a, b, hx(c)) for a, b, c in derived_rows])

    # The formatter names, ordinal arguments and lengths are extracted from code
    # and checked against the file-backed literal bytes.
    name_specs = (
        ('register', 0x5382afc, '4c8d0d', 0x5382b11, 'zero', 0x5382b16),
        ('changeProfile', 0x5382a95, '4c8d0d', 0x5382aaa, 'one', 0x5382ab2),
        ('unregister', 0x5382b74, '4c8d0d', 0x5382b89, 'two', 0x5382b8f),
    )
    name_rows = []
    for expected, site, prefix, arg_site, arg_form, len_site in name_specs:
        raw = get_bytes(data, secs, site, 7)
        target = rip_lea(raw, site, prefix)
        len_raw = get_bytes(data, secs, len_site, 2)
        expect(len_raw, '6a', 'name length')
        length = len_raw[1]
        literal = get_bytes(data, secs, target, length)
        if literal != expected.encode('ascii'):
            raise ValueError('variant name mismatch')
        if arg_form == 'zero':
            arg = get_bytes(data, secs, arg_site, 3)
            expect(arg, '4531c0', 'ordinal zero')
            ordinal = 0
        else:
            arg = get_bytes(data, secs, arg_site, 6)
            expect(arg, '41b8', 'ordinal immediate')
            ordinal = struct.unpack_from('<I', arg, 2)[0]
        expected_ord = {'one': 1, 'two': 2, 'zero': 0}[arg_form]
        if ordinal != expected_ord:
            raise ValueError('unexpected name ordinal')
        name_rows.append((ordinal, literal.decode('ascii'), hx(site), raw.hex(),
                          hx(target), hx(va_offset(secs, target, length)), length,
                          hx(arg_site), arg.hex(), hx(len_site), len_raw.hex()))
    out['names.tsv'] = rows_tsv(('ordinal', 'name', 'lea_va', 'lea_raw', 'literal_va',
        'literal_file_offset', 'length', 'ordinal_site_va', 'ordinal_raw',
        'length_site_va', 'length_raw'), name_rows)

    # Independent observations of the same niche expression. These pattern
    # checks make the vector model dependent on the actual instructions.
    fmt = get_bytes(data, secs, 0x5382a66, 42)
    expect(fmt, '49bc0400000000000080488b064a8d0c204883c1fd48c1f83f4821c8', 'formatter niche')
    clone = get_bytes(data, secs, 0x5659f84, 35)
    expect(clone, '49bf0000000000000080488b064a8d0c3848ffc148c1f83f4821c8', 'clone niche')
    core = get_bytes(data, secs, 0x3c3d4bc, 41)
    expect(core, '498b064a8d0c2848ffc1488984247001000048c1f83f48898c24c80100004821c8', 'state niche')
    expect(get_bytes(data, secs, 0x565a097, 3), '49ffc7', 'clone canonical increment')
    expect(get_bytes(data, secs, 0x565a189, 3), '4c893b', 'clone canonical store')
    for site, expected in ((0x3c3dadc, '6641c704244401'),
                           (0x3c3dd1e, '6641c704249500'),
                           (0x3c3e788, '6641c70424a201')):
        expect(get_bytes(data, secs, site, 7), expected, 'return word')
    vector_rows = []
    for word in (0, 1, (1 << 63) - 1, 1 << 63, (1 << 63) + 1,
                 (1 << 63) + 2, MASK64):
        index = classify_word(word)
        arm = 'register' if index == 0 else 'changeProfile' if index == 1 else 'other'
        normalized = hx(clone_other_word(word)) if index >= 2 else 'not_modeled'
        vector_rows.append((hx(word), index, arm, normalized))
    out['niche-vectors.tsv'] = rows_tsv(('synthetic_input_u64', 'decoded_index',
                                         'formatter_branch', 'clone_word_if_other'), vector_rows)

    # Selected entries in two independent outer switches. Do not infer either
    # table's complete length or bounds checking from these three entries.
    outer = get_bytes(data, secs, 0x565a21f, 35)
    expect(outer, '488b064883e814b94d000000480f43c84889fb488d05', 'outer table dispatch')
    bias = outer[6]
    lea_va = 0x565a232
    table = rip_lea(get_bytes(data, secs, lea_va, 7), lea_va, '488d05')
    if bias != 0x14 or table != 0x928928:
        raise ValueError('outer switch shape mismatch')
    expect(get_bytes(data, secs, 0x53b2dbe, 19),
           '488b064883e814b94d000000480f43c84889fb', 'outer serializer dispatch')
    ser_lea = 0x53b2dd1
    ser_table = rip_lea(get_bytes(data, secs, ser_lea, 7), ser_lea, '488d05')
    if ser_table != 0x922cb4:
        raise ValueError('outer serializer table mismatch')
    switch_rows = []
    for role, table_va, selected_target in (('outer_clone', table, 0x565a61c),
                                             ('outer_serializer', ser_table, 0x53b455b)):
        for index in (38, 39, 40):
            entry = table_va + 4 * index
            raw = get_bytes(data, secs, entry, 4)
            destination = table_va + struct.unpack('<i', raw)[0]
            if not named[role]['start'] <= destination < named[role]['end']:
                raise ValueError('selected table entry leaves FDE')
            if index == 39 and destination != selected_target:
                raise ValueError('selected outer table target mismatch')
            switch_rows.append((role, index + bias, index, hx(table_va), hx(entry),
                                hx(va_offset(secs, entry, 4)), raw.hex(), hx(destination)))
    expect(get_bytes(data, secs, 0x565a682, 7), '48c7033b000000', 'outer tag store')
    out['outer-switch.tsv'] = rows_tsv(('owner', 'tag', 'index', 'table_va', 'entry_va',
        'entry_file_offset', 'raw_hex', 'target_va'), switch_rows)

    # The variant visitor names its missing-field diagnostic through a RELATIVE
    # data relocation, and each selected successful path stores the same tag.
    descriptor_slot = rip_lea(get_bytes(data, secs, 0x574d5f6, 7),
                              0x574d5f6, '488d15')
    if descriptor_slot != 0x64aff08:
        raise ValueError('visitor descriptor reference mismatch')
    _, _, _, descriptor = relocs[descriptor_slot]
    length = struct.unpack('<Q', get_bytes(data, secs, descriptor_slot + 8, 8))[0]
    description = get_bytes(data, secs, descriptor, length)
    if description != b'struct variant VoteGlobalAction::CValidator with 2 elements':
        raise ValueError('variant description mismatch')
    for site in (0x574daa0, 0x574ddb6):
        expect(get_bytes(data, secs, site, 7), '49c7063b000000', 'visitor tag store')
    literal_specs = (
        ('enum_type', 0x53b4565, '488d05', b'VoteGlobalAction'),
        ('nested_enum_type', 0x5382b6d, '488d05', b'CValidatorAction'),
        ('outer_variant_wire_name', 0x53b456c, '4c8d0d', b'O'),
        ('nested_field_wire_name', 0x53b45b2, '488d15', b'a'),
        ('second_field_wire_name', 0x53b45dc, '488d15', b'c'),
        ('nested_unregister_wire_name', 0x538307c, '488d35', b'unregister'),
    )
    identity_rows = []
    for role, site, prefix, expected in literal_specs:
        raw = get_bytes(data, secs, site, 7)
        target = rip_lea(raw, site, prefix)
        actual = get_bytes(data, secs, target, len(expected))
        if actual != expected:
            raise ValueError('literal mismatch: ' + role)
        identity_rows.append((role, hx(site), raw.hex(), hx(target),
                              hx(va_offset(secs, target, len(actual))),
                              len(actual), actual.decode('ascii')))
    expect(get_bytes(data, secs, 0x53b4583, 6), '41b827000000', 'outer ordinal')
    expect(get_bytes(data, secs, 0x53b45a4, 4), '4d8d4608', 'nested payload pointer')
    expect(get_bytes(data, secs, 0x5383083, 5), 'ba0a000000', 'unregister name length')
    identity_rows.append(('visitor_diagnostic', hx(0x574d5f6),
                          get_bytes(data, secs, 0x574d5f6, 7).hex(), hx(descriptor),
                          hx(va_offset(secs, descriptor, length)), length,
                          description.decode('ascii')))
    out['identity.tsv'] = rows_tsv(('role', 'reference_va', 'reference_raw',
        'literal_va', 'literal_file_offset', 'length', 'literal'), identity_rows)

    decision_rows = []
    for found in (False, True):
        for nonzero in (False, True):
            for profile in (False, True):
                case, result = removal_outcome(found, nonzero, profile)
                decision_rows.append((int(found), int(nonzero), int(profile), case, hx(result)))
    out['decision-vectors.tsv'] = rows_tsv(('first_found', 'first_value_nonzero',
        'profile_found', 'synthetic_result_path', 'normal_result_word'), decision_rows)
    compact_rows = []
    for capacity, start, length in ((1, 0, 0), (1, 0, 1), (7, 0, 1),
                                    (7, 6, 2), (7, 6, 5), (7, 1, 6)):
        for index in range(length + 2):
            route, new_start, new_length, moved = compact_removal_model(capacity, start, length, index)
            compact_rows.append((capacity, start, length, index, route, new_start, new_length, moved))
    out['compact-vectors.tsv'] = rows_tsv(('capacity', 'start', 'length', 'index',
        'synthetic_route', 'new_start', 'new_length', 'records_to_shift'), compact_rows)
    expect(get_bytes(data, secs, 0x3c3e458, 22),
           '4c39abd00000000f94c14883f8200f92c220ca80fa01', 'small-tree predicate')
    expect(get_bytes(data, secs, 0x3c3705a, 24),
           '4885c00f95c1498bb6000200004883fe40400f93c74084f9', 'compact conversion predicate')
    transition_rows = []
    small = operands['second_small_tree_threshold']
    large = operands['followup_large_compact_threshold']
    for representation in (0, operands['state_representation_sentinel']):
        for count in (small - 1, small, small + 1):
            transition_rows.append(('small_tree', hx(representation), count, 'not_used',
                                    str(int(small_tree_conversion(representation, count)))))
        for count in (large - 1, large, large + 1):
            for missing in (False, True):
                transition_rows.append(('followup_route', hx(representation), count, int(missing),
                                        followup_representation_route(representation, count, missing)))
    out['transition-vectors.tsv'] = rows_tsv(('synthetic_predicate', 'representation_word',
        'count', 'lookup_missing', 'modeled_result'), transition_rows)
    summary = {'schema': 1, 'target_sha256': DIGEST, 'coordinate_system': 'linked ELF VA',
        'selected_fdes': len(function_rows), 'selected_windows': len(window_rows),
        'selected_branches': len(branch_rows), 'selected_direct_calls': len(call_rows),
        'selected_relocations': len(reloc_rows), 'selected_immediates': len(operand_rows),
        'derived_operands': len(derived_rows), 'name_variants': len(name_rows),
        'outer_entries': len(switch_rows), 'identity_records': len(identity_rows),
        'niche_vectors': len(vector_rows),
        'decision_vectors': len(decision_rows), 'compact_vectors': len(compact_rows),
        'transition_vectors': len(transition_rows),
        'limitations': 'Selected static slices and synthetic models only; no target execution, whole CFG, wire handoff or implementation equivalence.'}
    out['summary.json'] = (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode()
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    output = generate(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(output.items()):
        (args.out / name).write_bytes(content)
    print('generated %d deterministic evidence files' % len(output))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as exc:
        print('evidence generation failed: %s' % exc, file=sys.stderr)
        raise SystemExit(1)
