#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Extract bounded node #115 link-staking dispatch and state-path evidence.

This reader is deliberately not an x86 disassembler. It recognizes only the
pinned branch, instruction and relocation forms listed here. All addresses are
linked ELF virtual addresses; end addresses are exclusive. No target is run.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Each body hash covers the complete unwind-described range, without masks.
FUNCTIONS = (
    ('action_formatter', 0x2bcbbf0, 0x2bce565, 'fa2c1fb689b1e61663b483354b1319e6e5354188c8739cf046bb0cef288e7b94'),
    ('tree_insert', 0x370caf0, 0x370cc37, 'd0b05006c7a062d8e23ad511a5d54bc904e05fbde237bd549dc09bd64033dfd7'),
    ('relationship_upsert', 0x3ce1080, 0x3ce15ad, 'eff6d70abc69f54c6e4c1d3b4bc95f91749f824b9940ccabe502df76d3d785aa'),
    ('compact_insert', 0x4546140, 0x4546245, '29fcd1512976d6b50c32eab057d63e5d039c266b339851131b11a1be5b2182ff'),
    ('stake_compact_lookup', 0x4556850, 0x4556a4d, '487dd1ca75340cfe63b7fc47453afebe7b643f31c428793d1baf6fdbb76f0e5b'),
    ('relationship_compact_lookup', 0x4559130, 0x455936b, '25d8c0dbc8102d0e5f80cbea5a99eafbb87cf41f4b50c53586dc8c535846bfae'),
    ('request_core', 0x469fa60, 0x469fe8d, 'b44b7ef825e426ba77e2334ef0e34f83a1277a9d5b436b5dfd8c3fb83b1f8b45'),
    ('finalize_core', 0x469fe90, 0x46a02ea, 'fd6c354fc7e8040b27770445695166edee221900c401da14ab503c9b0acfcbec'),
    ('action_selector', 0x4e10080, 0x4e103e9, 'a7c8212e3a22d67f56a8816f85bb7ab20854d7811987c11c51cdc7ff909dfe29'),
    ('gate_iterator', 0x51e4c80, 0x51e502a, 'd2e18ed2767525cee710b2e43420d5e877e6ad6809a2b48f74b6c7f9c95fb720'),
    ('parent_caller', 0x5536770, 0x5537059, 'e192387dca7bbaecb6241251f3e0ce5b30b5d88a6c70fa844de7ca47bdf14da7'),
    ('first_gate', 0x5551140, 0x555153b, '7fd80e0f7934d58a3606828dfe8f8405009fd84b1aba1959f364a20d41dcd246'),
    ('second_gate', 0x5551540, 0x5551914, '70bc11144ab588c0a05464c9975b972d33f07c48378f3a07b287021a01f91b2d'),
    ('action_dispatch', 0x55f99b0, 0x55faa79, 'bd6aabef676273f6fd227a1bc1f0dcd8954be9b0014d5df123ed4eeaa89e4a66'),
    ('request_prerequisite', 0x5611bd0, 0x5611d79, '7e15bc87c0cfb383ab18cec8ab03e018b27f52c4ff4d13cd30b20b8855a01478'),
    ('action_wrapper', 0x58c07d0, 0x58c08b8, '564f93d52fc4ea48466f44ad38a39b02e8a2f24ad69fbf5bf8b1e888e6cbe280'),
)

# Instruction-aligned slices isolate the dataflow behind the decision table.
# Their bytes come from the fully hashed owner ranges, not a disassembler.
SLICES = (
    ('parent_save_key_and_pointer', 'parent_caller', 0x5536791, 0x55367ad),
    ('parent_default_gate_key', 'parent_caller', 0x5536957, 0x5536982),
    ('parent_single_alternate_compare', 'parent_caller', 0x55369a5, 0x55369e8),
    ('parent_alternate_key_load', 'parent_caller', 0x5536b08, 0x5536b29),
    ('parent_secondary_key_choice', 'parent_caller', 0x5536b77, 0x5536bb2),
    ('parent_child_and_classifier', 'parent_caller', 0x5536bba, 0x5536bd3),
    ('parent_dispatch_arguments', 'parent_caller', 0x5536deb, 0x5536e19),
    ('selector_empty_fields', 'action_selector', 0x4e100cd, 0x4e100eb),
    ('first_gate_empty_condition', 'first_gate', 0x5551159, 0x555117e),
    ('second_gate_empty_iterator_setup', 'second_gate', 0x555155a, 0x55515c7),
    ('second_gate_success', 'second_gate', 0x5551770, 0x55517dd),
    ('iterator_empty_return', 'gate_iterator', 0x51e4d29, 0x51e4d45),
    ('dispatch_normalize', 'action_dispatch', 0x55f9a08, 0x55f9a2b),
    ('dispatch_wrapper_arguments', 'action_dispatch', 0x55f9efe, 0x55f9f1a),
    ('wrapper_nonzero_pair', 'action_wrapper', 0x58c07db, 0x58c081b),
    ('wrapper_zero_pair', 'action_wrapper', 0x58c0871, 0x58c089f),
    ('wrapper_error_result', 'action_wrapper', 0x58c0828, 0x58c0871),
    ('wrapper_request_result', 'action_wrapper', 0x58c089f, 0x58c08b8),
    ('stake_key_and_container', 'request_prerequisite', 0x5611bde, 0x5611bff),
    ('stake_missing_error', 'request_prerequisite', 0x5611ce3, 0x5611d23),
    ('stake_found_handoff', 'request_prerequisite', 0x5611d23, 0x5611d42),
    ('request_self_compare', 'request_core', 0x469fa71, 0x469faaf),
    ('request_trading_tag', 'request_core', 0x469fc41, 0x469fc85),
    ('request_staking_tag', 'request_core', 0x469fdad, 0x469fe07),
    ('request_write_arguments', 'request_core', 0x469fe07, 0x469fe53),
    ('finalize_pending_checks', 'finalize_core', 0x469ffb3, 0x46a004c),
    ('finalize_staking_tag', 'finalize_core', 0x46a01a9, 0x46a0241),
    ('finalize_write_arguments', 'finalize_core', 0x46a0241, 0x46a02c5),
    ('upsert_compact_choice', 'relationship_upsert', 0x3ce12c2, 0x3ce137b),
    ('upsert_replace_value', 'relationship_upsert', 0x3ce14a0, 0x3ce14cc),
    ('compact_record_insert', 'compact_insert', 0x45461fa, 0x4546220),
)

# Explicit instruction starts, kinds, and expected destinations. Conditions are
# the machine conditions; labels describe the path, not source-level symbols.
EDGES = (
    ('parent_primary_compact_choice', 0x55367bf, 'jno', 0x55368c1),
    ('parent_primary_tree_empty', 0x55367d5, 'je', 0x5536957),
    ('parent_primary_tree_found', 0x553687b, 'je', 0x55369e8),
    ('parent_primary_tree_exhausted', 0x55368a2, 'jb', 0x5536957),
    ('parent_primary_compact_lookup', 0x55368d4, 'call', 0x57f8ff0),
    ('parent_primary_compact_absent', 0x55368db, 'jne', 0x5536957),
    ('parent_primary_compact_outside', 0x55368e5, 'jae', 0x5536957),
    ('parent_alternate_empty', 0x5536995, 'je', 0x5536bba),
    ('parent_alternate_multiple', 0x553699f, 'jne', 0x5536aba),
    ('parent_alternate_single_mismatch', 0x55369db, 'jne', 0x5536bba),
    ('parent_alternate_single_match', 0x55369e3, 'jmp', 0x5536b08),
    ('parent_secondary_tree_found', 0x5536a7d, 'je', 0x5536b77),
    ('parent_secondary_tree_exhausted', 0x5536aa2, 'jb', 0x5536b74),
    ('parent_alternate_lookup', 0x5536aea, 'call', 0x3ed25b0),
    ('parent_alternate_absent', 0x5536af1, 'je', 0x5536bba),
    ('parent_alternate_index_outside', 0x5536afa, 'jae', 0x5537025),
    ('parent_secondary_compact_lookup', 0x5536b31, 'call', 0x57f8ff0),
    ('parent_secondary_compact_absent', 0x5536b3b, 'jne', 0x5536b77),
    ('parent_secondary_compact_outside', 0x5536b45, 'jae', 0x5536b77),
    ('parent_classifier_nonzero', 0x5536bcd, 'jne', 0x5536d2c),
    ('parent_empty_first_key_tree', 0x5536be2, 'je', 0x5536d2c),
    ('parent_first_key_match', 0x5536c76, 'je', 0x5536e9b),
    ('parent_second_key_match', 0x5536cf6, 'je', 0x5536e9b),
    ('parent_selector_call', 0x5536d3f, 'call', 0x4e10080),
    ('parent_selector_failure', 0x5536d51, 'jne', 0x5536e1e),
    ('parent_first_gate_call', 0x5536d8f, 'call', 0x5551140),
    ('parent_first_gate_failure', 0x5536d9e, 'jne', 0x5536eab),
    ('parent_second_gate_call', 0x5536dd6, 'call', 0x5551540),
    ('parent_second_gate_failure', 0x5536de5, 'jne', 0x5536f6d),
    ('parent_dispatch_call', 0x5536e14, 'call', 0x55f99b0),
    ('parent_dispatch_return', 0x5536e19, 'jmp', 0x5537013),
    ('gate_one_empty', 0x5551178, 'jne', 0x5551505),
    ('gate_two_iterator', 0x555164f, 'call', 0x51e4c80),
    ('gate_two_empty', 0x555165c, 'je', 0x5551770),
    ('gate_two_drain', 0x555177d, 'call', 0x51e4c80),
    ('gate_two_drain_again', 0x5551788, 'jne', 0x5551770),
    ('gate_two_empty_success', 0x555178e, 'je', 0x55517d4),
    ('iterator_empty', 0x51e4c95, 'je', 0x51e4d29),
    ('iterator_empty_kind', 0x51e4d43, 'jne', 0x51e4db2),
    ('dispatch_to_wrapper', 0x55f9f10, 'call', 0x58c07d0),
    ('dispatch_to_result_tail', 0x55f9f15, 'jmp', 0x55fa862),
    ('wrapper_zero_mode', 0x58c07df, 'je', 0x58c0871),
    ('wrapper_final_success', 0x58c0822, 'je', 0x58c08a8),
    ('wrapper_to_prerequisite', 0x58c089a, 'call', 0x5611bd0),
    ('wrapper_request_failure', 0x58c08a6, 'jne', 0x58c0828),
    ('stake_compact_choice', 0x5611bf9, 'jno', 0x5611cc1),
    ('stake_no_tree_root', 0x5611c18, 'je', 0x5611d54),
    ('stake_tree_match', 0x5611c94, 'je', 0x5611d23),
    ('stake_tree_exhausted', 0x5611cae, 'jb', 0x5611d54),
    ('stake_compact_lookup', 0x5611cd3, 'call', 0x4556850),
    ('stake_compact_found', 0x5611ce1, 'je', 0x5611d32),
    ('stake_error_allocation_failure', 0x5611cf1, 'je', 0x5611d69),
    ('stake_error_allocation_success', 0x5611d67, 'jne', 0x5611cf3),
    ('request_same_key', 0x469faa9, 'je', 0x469fbb2),
    ('request_first_compact', 0x469fae2, 'jno', 0x469fc06),
    ('request_first_no_root', 0x469faef, 'je', 0x469fc85),
    ('request_first_tree_found', 0x469fb7c, 'je', 0x469fc41),
    ('request_first_tree_exhausted', 0x469fb9b, 'jb', 0x469fc85),
    ('request_first_lookup', 0x469fc0e, 'call', 0x4559130),
    ('request_first_absent', 0x469fc15, 'jne', 0x469fc85),
    ('request_first_index_outside', 0x469fc1b, 'jae', 0x469fc85),
    ('request_first_zero_tag', 0x469fc45, 'je', 0x469fc85),
    ('request_second_compact', 0x469fcaa, 'jne', 0x469fd6e),
    ('request_second_no_root', 0x469fcb7, 'je', 0x469fe07),
    ('request_second_tree_found', 0x469fd3c, 'je', 0x469fdad),
    ('request_second_tree_exhausted', 0x469fd57, 'jb', 0x469fe07),
    ('request_second_lookup', 0x469fd76, 'call', 0x4559130),
    ('request_second_absent', 0x469fd7d, 'jne', 0x469fe07),
    ('request_second_index_outside', 0x469fd87, 'jae', 0x469fe07),
    ('request_second_zero_tag', 0x469fdb1, 'je', 0x469fe07),
    ('request_write', 0x469fe49, 'call', 0x3ce1080),
    ('request_self_alloc_failure', 0x469fbc3, 'je', 0x469fe6d),
    ('request_first_alloc_failure', 0x469fc55, 'je', 0x469fe7d),
    ('request_second_alloc_failure', 0x469fdc6, 'je', 0x469fe7d),
    ('final_first_compact', 0x469fec7, 'jno', 0x469ffab),
    ('final_first_no_root', 0x469fed9, 'je', 0x46a004c),
    ('final_first_tree_found', 0x469ff77, 'je', 0x46a0003),
    ('final_first_tree_exhausted', 0x469ff8e, 'jb', 0x46a004c),
    ('final_first_lookup', 0x469ffb3, 'call', 0x4559130),
    ('final_first_absent', 0x469ffba, 'jne', 0x46a004c),
    ('final_first_index_outside', 0x469ffc4, 'jae', 0x46a004c),
    ('final_first_nonzero_compact', 0x469ffff, 'jne', 0x46a004c),
    ('final_first_nonzero_tree', 0x46a000c, 'jne', 0x46a004c),
    ('final_pending_peer_equal', 0x46a004a, 'je', 0x46a00b3),
    ('final_second_compact', 0x46a00e8, 'jne', 0x46a01a1),
    ('final_second_tree_found', 0x46a016f, 'je', 0x46a01e4),
    ('final_second_tree_exhausted', 0x46a0184, 'jb', 0x46a0241),
    ('final_second_lookup', 0x46a01a9, 'call', 0x4559130),
    ('final_second_absent', 0x46a01b0, 'jne', 0x46a0241),
    ('final_second_index_outside', 0x46a01ba, 'jae', 0x46a0241),
    ('final_second_zero_tag', 0x46a01e8, 'je', 0x46a0241),
    ('final_first_write', 0x46a0288, 'call', 0x3ce1080),
    ('final_second_write', 0x46a02b6, 'call', 0x3ce1080),
    ('final_pending_error_alloc_failure', 0x46a005a, 'je', 0x46a02ca),
    ('final_second_error_alloc_failure', 0x46a01f8, 'je', 0x46a02da),
    ('upsert_tree_to_compact_guard', 0x3ce10bf, 'jne', 0x3ce11ed),
    ('upsert_lookup', 0x3ce1208, 'call', 0x4559130),
    ('upsert_skip_compact_to_tree', 0x3ce1223, 'je', 0x3ce12c2),
    ('upsert_found_compact', 0x3ce12d1, 'je', 0x3ce1344),
    ('upsert_insert_compact', 0x3ce1317, 'call', 0x4546140),
    ('upsert_bad_index_a', 0x3ce1347, 'jae', 0x3ce1552),
    ('upsert_insert_tree', 0x3ce1517, 'call', 0x370caf0),
    ('upsert_bad_index_b', 0x3ce153b, 'jae', 0x3ce1552),
    ('compact_insert_bad_index', 0x454614f, 'ja', 0x454622c),
    ('tree_insert_empty_root', 0x370cb09, 'je', 0x370cb67),
    ('tree_insert_alloc_failure', 0x370cb78, 'je', 0x370cc0e),
    ('tree_insert_node_bound', 0x370cba6, 'jae', 0x370cc1e),
)

# A few selected indirect slots; imported dynamic symbols are not resolved to a
# loaded address. The non-PLT relative slots identify in-file FDE entries.
SLOTS = {
    0x64e7a80: (8, 0, 0x469fe90, ''),
    0x64e7f20: (8, 0, 0x469fa60, ''),
    0x64dfb50: (6, 12, 0, 'memcmp'),
}
INDIRECT = (
    ('wrapper_finalize', 0x58c0815, 0x64e7a80),
    ('prerequisite_request', 0x5611d3c, 0x64e7f20),
    ('stake_lookup_compare', 0x4556892, 0x64dfb50),
    ('relationship_lookup_compare', 0x4559172, 0x64dfb50),
    ('relationship_lookup_final_compare', 0x4559266, 0x64dfb50),
)

# Each data literal is reached by the indicated RIP-relative instruction.
LITERALS = (
    ('formatter_name', 0x2bcca46, bytes.fromhex('488d05'), 15, b'linkStakingUser'),
    ('variant_label', 0x2bcca1c, bytes.fromhex('488d05'), 15, b'LinkStakingUser'),
    ('stake_missing', 0x5611cfe, bytes.fromhex('0f1005'), 31, b'Staking user has no staked HYPE'),
    ('self_link', 0x469fbd4, bytes.fromhex('0f1005'), 36, b'Cannot link a staking user to itself'),
    ('trading_linked', 0x469fc71, bytes.fromhex('0f1005'), 43, b'Trading user already has a link established'),
    ('staking_linked_request', 0x469fde2, bytes.fromhex('0f1005'), 43, b'Staking user already has a link established'),
    ('pending_required', 0x46a0076, bytes.fromhex('0f1005'), 45, b'Trading user must request before staking user'),
    ('staking_linked_finalize', 0x46a0214, bytes.fromhex('0f1005'), 43, b'Staking user already has a link established'),
)

# Exact prefixes bind each immediate to the particular inspected instruction.
CONSTANTS = (
    ('parent_primary_container_offset', 0x55367ad, '488b9e', 4),
    ('parent_alternate_count_offset', 0x5536982, '4d8bac24', 4),
    ('parent_alternate_value_offset', 0x5536b18, 'f30f6f4408', 1),
    ('parent_secondary_value_offset', 0x5536b8d, '498d87', 4),
    ('parent_child_pointer_offset', 0x5536bba, '4c8b7b', 1),
    ('selector_child_pointer_offset', 0x4e10085, '488b76', 1),
    ('selector_empty_first', 0x4e100cd, '48c74708', 4),
    ('selector_empty_second', 0x4e100d5, '48c74718', 4),
    ('parent_failure_tag', 0x5536fcc, 'c600', 1),
    ('relationship_key_bytes', 0x469fb49, 'ba', 4),
    ('relationship_value_tail_offset', 0x3ce14aa, '498b4d', 1),
    ('compact_last_copy_offset', 0x4546211, '0f1053', 1),
    ('selector_bias', 0x4e1008c, '4981e8', 4),
    ('selector_underflow_index', 0x4e10093, 'b8', 4),
    ('parent_prior_reject_word', 0x5536ea0, '66c74010', 2),
    ('selector_success_word', 0x4e100dd, '66c707', 2),
    ('gate_one_success_word', 0x5551170, '66bd', 2),
    ('gate_two_success_word', 0x55517d8, '66c700', 2),
    ('dispatcher_bias', 0x55f9a0c, '482d', 4),
    ('formatter_bias', 0x2bcbbf8, '482d', 4),
    ('dispatcher_underflow_index', 0x55f9a12, 'b9', 4),
    ('formatter_underflow_index', 0x2bcbbfe, 'b9', 4),
    ('formatter_name_length', 0x2bcca52, '48c7442440', 4),
    ('variant_label_length', 0x2bcca28, '48c7442420', 4),
    ('dispatch_payload_offset', 0x55f9efe, '4983c4', 1),
    ('wrapper_mode_payload_offset', 0x58c07db, '807e', 1),
    ('wrapper_zero_mode_value', 0x58c07db, '807e3d', 1),
    ('wrapper_payload_key_offset', 0x58c07f3, '0f1046', 1),
    ('wrapper_relationship_container_offset', 0x58c07e5, '4881c1', 4),
    ('inner_success_word', 0x58c081b, '66817c2430', 2),
    ('outer_failure_tag', 0x58c086d, 'b0', 1),
    ('outer_success_tag', 0x58c08a8, 'b0', 1),
    ('missing_stake_error_word', 0x5611d08, '66c703', 2),
    ('stake_container_offset', 0x5611bf2, '483b86', 4),
    ('request_relationship_container_offset', 0x5611d32, '4881c6', 4),
    ('relationship_error_word', 0x469fbe8, '66c703', 2),
    ('request_linked_error_word', 0x469fdec, '66c701', 2),
    ('final_pending_error_word', 0x46a0085, '66c701', 2),
    ('final_staking_error_word', 0x46a0223, '66c701', 2),
    ('request_success_word', 0x469fe53, '66c701', 2),
    ('final_success_word', 0x46a02c0, '66c701', 2),
    ('request_value_tag', 0x469fe1b, 'c6442410', 1),
    ('final_first_value_tag', 0x46a0259, 'c6442410', 1),
    ('final_second_value_tag', 0x46a029c, 'c6442410', 1),
    ('tree_representation_sentinel', 0x3ce11ed, '49be', 8),
    ('empty_tree_allocation_bytes', 0x370cb6a, 'bf', 4),
    ('tree_to_compact_below', 0x3ce10b3, '4883f8', 1),
    ('compact_to_tree_at_least', 0x3ce1218, '4883fe', 1),
    ('tree_node_local_bound', 0x370cba2, '4883f9', 1),
)


def check_digest(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != DIGEST:
        raise ValueError('node #115 SHA-256 mismatch')
    return digest


def unique_section(secs, name):
    matches = [s for s in secs if s['name'] == name and s['type'] != 8]
    if len(matches) != 1:
        raise ValueError('missing or ambiguous file-backed section: ' + name)
    return matches[0]


def file_offset(secs, va, size=1):
    if va < 0 or size <= 0:
        raise ValueError('invalid address or size')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address is not uniquely file-backed')
    sec = matches[0]
    return sec['offset'] + va - sec['address']


def raw_at(data, secs, va, size):
    off = file_offset(secs, va, size)
    value = data[off:off + size]
    if len(value) != size:
        raise ValueError('truncated bytes')
    return value


def checked_immediate(data, secs, va, prefix, width):
    prefix = bytes.fromhex(prefix)
    raw = raw_at(data, secs, va, len(prefix) + width)
    if not raw.startswith(prefix):
        raise ValueError('unexpected immediate instruction')
    return int.from_bytes(raw[len(prefix):], 'little')


def rip_target(data, secs, va, prefix):
    raw = raw_at(data, secs, va, len(prefix) + 4)
    if not raw.startswith(prefix):
        raise ValueError('unexpected RIP-relative instruction')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0], raw


def decode_edge(raw, va, kind):
    """Decode a specified direct branch; reject all unlisted forms."""
    short = {'jmp': 0xeb, 'je': 0x74, 'jne': 0x75, 'jb': 0x72,
             'jae': 0x73, 'ja': 0x77, 'jbe': 0x76, 'jno': 0x71}
    near = {'call': 0xe8, 'jmp': 0xe9}
    near_jcc = {'je': 0x84, 'jne': 0x85, 'jb': 0x82, 'jae': 0x83,
                'ja': 0x87, 'jbe': 0x86, 'jno': 0x81}
    if kind in near and len(raw) >= 5 and raw[0] == near[kind]:
        length, delta = 5, struct.unpack_from('<i', raw, 1)[0]
    elif kind in short and len(raw) >= 2 and raw[0] == short[kind]:
        length, delta = 2, struct.unpack_from('<b', raw, 1)[0]
    elif kind in near_jcc and len(raw) >= 6 and raw[:2] == bytes((0x0f, near_jcc[kind])):
        length, delta = 6, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported or corrupted branch')
    return va + length + delta, raw[:length]


def checked_edge(raw, va, kind, expected):
    target, instruction = decode_edge(raw, va, kind)
    if target != expected:
        raise ValueError('branch destination mismatch')
    return target, instruction


def resolve_slot_records(records, wanted):
    selected = {}
    for slot, info, addend, record_offset, record in records:
        if slot in wanted:
            if slot in selected:
                raise ValueError('duplicate relocation slot')
            selected[slot] = (info, addend, record_offset, record)
    if set(selected) != set(wanted):
        raise ValueError('missing relocation slot')
    return selected


def relocation_records(data, secs):
    sec = unique_section(secs, '.rela.dyn')
    if sec['type'] != 4 or sec['size'] % 24:
        raise ValueError('unsupported RELA section')
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        yield slot, info, addend, off, data[off:off + 24]


def dynamic_symbol(data, secs, index):
    sym = unique_section(secs, '.dynsym')
    strings = unique_section(secs, '.dynstr')
    off = sym['offset'] + index * 24
    if off + 24 > sym['offset'] + sym['size']:
        raise ValueError('dynamic symbol index outside table')
    name = struct.unpack_from('<I', data, off)[0]
    if name >= strings['size']:
        raise ValueError('dynamic symbol name outside string table')
    begin = strings['offset'] + name
    end = data.find(b'\0', begin, strings['offset'] + strings['size'])
    if end < 0:
        raise ValueError('unterminated dynamic symbol')
    return data[begin:end].decode('ascii')


def make_relocations(data, secs):
    found = resolve_slot_records(relocation_records(data, secs), SLOTS)
    result = []
    for slot, (typ, sym, addend, name) in sorted(SLOTS.items()):
        info, actual, off, record = found[slot]
        if (info & 0xffffffff, info >> 32, actual) != (typ, sym, addend):
            raise ValueError('unexpected relocation')
        symbol = dynamic_symbol(data, secs, sym) if sym else ''
        if symbol != name:
            raise ValueError('unexpected dynamic symbol')
        result.append((slot, file_offset(secs, slot, 8), typ, sym, actual,
                       symbol, off, record.hex()))
    return result


def switch_targets(data, secs, table, count, owner):
    result = []
    if not 1 <= count <= 256:
        raise ValueError('invalid table count')
    for i in range(count):
        entry = table + 4 * i
        raw = raw_at(data, secs, entry, 4)
        dest = table + struct.unpack('<i', raw)[0]
        if not owner['start'] <= dest < owner['end']:
            raise ValueError('table target outside selected FDE')
        result.append((i, entry, file_offset(secs, entry, 4), raw.hex(), dest))
    return result


def check_window(raw, expected):
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('pinned function window mismatch')


def read_slices(data, secs, slices=None):
    if slices is None:
        slices = SLICES
    owners = {role: (start, end) for role, start, end, _ in FUNCTIONS}
    rows = []
    seen = set()
    for label, owner, start, end in slices:
        if label in seen or owner not in owners or not owners[owner][0] <= start < end <= owners[owner][1]:
            raise ValueError('slice is duplicate or outside selected FDE')
        seen.add(label)
        raw = raw_at(data, secs, start, end - start)
        rows.append((label, owner, start, end, file_offset(secs, start, len(raw)),
                     len(raw), hashlib.sha256(raw).hexdigest(), raw.hex()))
    return rows


def validate_constants(constants):
    if (constants['dispatcher_bias'] != constants['formatter_bias']
            or constants['selector_bias'] != constants['dispatcher_bias']
            or constants['dispatcher_bias'] != 0x86):
        raise ValueError('unexpected enum bias')
    if (constants['dispatcher_underflow_index'] != constants['formatter_underflow_index']
            or constants['selector_underflow_index'] != constants['dispatcher_underflow_index']):
        raise ValueError('underflow route differs')
    successes = ('inner_success_word', 'selector_success_word', 'gate_one_success_word',
                 'gate_two_success_word', 'request_success_word', 'final_success_word')
    errors = ('relationship_error_word', 'missing_stake_error_word',
              'request_linked_error_word', 'final_pending_error_word', 'final_staking_error_word')
    if any(constants[name] != 0x1a2 for name in successes) or any(constants[name] != 0x16f for name in errors):
        raise ValueError('unexpected status words')
    if (constants['wrapper_relationship_container_offset'] != constants['request_relationship_container_offset']
            or constants['wrapper_relationship_container_offset'] != 0x40a0
            or constants['wrapper_zero_mode_value'] != 0):
        raise ValueError('unexpected wrapper input layout')


def collect(data):
    check_digest(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    indexed = {entry['start']: entry for entry in index}
    by_start = {fde['start']: fde for fde in fdes}
    if len(indexed) != len(index) or len(by_start) != len(fdes):
        raise ValueError('duplicate FDE start')
    functions = []
    bodies = []
    selected = {}
    for role, start, expected_end, expected_hash in FUNCTIONS:
        fde, idx = by_start.get(start), indexed.get(start)
        if fde is None or idx is None or fde['fde'] != idx['fde'] or fde['end'] != expected_end:
            raise ValueError('selected FDE/index mismatch')
        body = raw_at(data, secs, start, fde['end'] - start)
        check_window(body, expected_hash)
        selected[start] = fde
        functions.append((role, start, fde['end'], file_offset(secs, start, len(body)),
                          fde['fde'], fde['cie'], fde['lsda'], len(body), hashlib.sha256(body).hexdigest()))
        bodies.append((role, start, fde['end'], len(body), body.hex()))

    constants = {}
    for label, va, prefix, width in CONSTANTS:
        constants[label] = checked_immediate(data, secs, va, prefix, width)
    validate_constants(constants)

    literal_rows = []
    for label, site, prefix, size, expected in LITERALS:
        address, insn = rip_target(data, secs, site, prefix)
        actual = raw_at(data, secs, address, size)
        if actual != expected:
            raise ValueError('literal differs')
        literal_rows.append((label, site, insn.hex(), address, file_offset(secs, address, size),
                             size, actual.decode('ascii')))
    if constants['formatter_name_length'] != len(b'linkStakingUser') or constants['variant_label_length'] != len(b'LinkStakingUser'):
        raise ValueError('formatter literal lengths differ')

    # The 92-entry bound is extracted from a target literal, not inferred by
    # walking until an address happens to leave the FDE.
    sentinel = raw_at(data, secs, 0x60c968, len(b'variant index 0 <= i < 92'))
    match = re.fullmatch(rb'variant index 0 <= i < ([0-9]+)', sentinel)
    if not match:
        raise ValueError('enum bound sentinel mismatch')
    count = int(match.group(1))
    selector_table, selector_lea = rip_target(data, secs, 0x4e1009c, bytes.fromhex('488d0d'))
    fmt_table, fmt_lea = rip_target(data, secs, 0x2bcbc0a, bytes.fromhex('488d05'))
    dispatch_table, dispatch_lea = rip_target(data, secs, 0x55f9a1b, bytes.fromhex('488d05'))
    selector = switch_targets(data, secs, selector_table, count, selected[0x4e10080])
    fmt = switch_targets(data, secs, fmt_table, count, selected[0x2bcbbf0])
    dispatch = switch_targets(data, secs, dispatch_table, count, selected[0x55f99b0])
    # The formatter arm reaches the independently pinned name above.
    selected_index = next((i for i, _, _, _, target in fmt if target == 0x2bcca03), None)
    if (selected_index != 11 or dispatch[selected_index][4] != 0x55f9efe
            or selector[selected_index][4] != 0x4e100cd):
        raise ValueError('selected switch arms differ')
    switches = []
    for fr, sr, dr in zip(fmt, selector, dispatch):
        i, fe, fo, fb, ft = fr
        _, se, so, sb, st = sr
        _, de, do, db, dt = dr
        switches.append((i, constants['dispatcher_bias'] + i, fe, fo, fb, ft,
                         se, so, sb, st, de, do, db, dt))

    edges = []
    for label, va, kind, expected in EDGES:
        owners = [(role, start, end) for role, start, end, _ in FUNCTIONS if start <= va < end]
        if len(owners) != 1:
            raise ValueError('branch outside selected functions')
        target, raw = checked_edge(raw_at(data, secs, va, 6), va, kind, expected)
        edges.append((label, owners[0][0], va, file_offset(secs, va, len(raw)), kind, raw.hex(), target))
    relocations = make_relocations(data, secs)
    indirect = []
    for label, va, expected_slot in INDIRECT:
        slot, raw = rip_target(data, secs, va, bytes.fromhex('ff15'))
        if slot != expected_slot:
            raise ValueError('indirect slot mismatch')
        indirect.append((label, va, file_offset(secs, va, len(raw)), raw.hex(), slot))

    constant_rows = []
    for label, va, prefix, width in CONSTANTS:
        raw = raw_at(data, secs, va, len(bytes.fromhex(prefix)) + width)
        constant_rows.append((label, va, file_offset(secs, va, len(raw)), raw.hex(), constants[label]))
    summary = {
        'target_sha256': DIGEST,
        'selected_fdes': len(functions),
        'selected_direct_edges': len(edges),
        'selected_dataflow_slices': len(SLICES),
        'selected_indirect_sites': len(indirect),
        'selected_relocations': len(relocations),
        'literal_records': len(literal_rows),
        'switch_entries_per_table': count,
        'switch_bound_source_va': hex(0x60c968),
        'switch_bound_literal': sentinel.decode('ascii'),
        'selector_table_lea': selector_lea.hex(),
        'selector_table_va': hex(selector_table),
        'formatter_table_lea': fmt_lea.hex(),
        'dispatch_table_lea': dispatch_lea.hex(),
        'selected_index': selected_index,
        'selected_internal_tag': hex(constants['dispatcher_bias'] + selected_index),
        'formatter_table_va': hex(fmt_table),
        'dispatch_table_va': hex(dispatch_table),
        'limitations': 'Selected static paths only. FDEs are unwind ranges, not complete source boundaries. No target execution, full helper closure, wire decoding, binary equivalence, or component gate is claimed.',
    }
    return functions, bodies, switches, edges, relocations, indirect, literal_rows, constant_rows, summary


def format_cell(value):
    if value is None:
        return ''
    if isinstance(value, int):
        return hex(value)
    return value


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        for row in rows:
            writer.writerow([format_cell(x) for x in row])


def generate(data, out):
    functions, bodies, switches, edges, relocs, indirect, literals, constants, summary = collect(data)
    slices = read_slices(data, sections(data))
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out / 'functions.tsv', ('role', 'start_va', 'end_va_exclusive', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'length', 'sha256'), functions)
    write_tsv(out / 'windows.tsv', ('role', 'start_va', 'end_va_exclusive', 'length', 'raw_hex'), bodies)
    write_tsv(out / 'dataflow.tsv', ('label', 'owner', 'start_va', 'end_va_exclusive', 'file_offset', 'length', 'sha256', 'raw_hex'), slices)
    write_tsv(out / 'switches.tsv', ('index', 'tag', 'formatter_entry_va', 'formatter_entry_file_offset', 'formatter_raw', 'formatter_target_va', 'selector_entry_va', 'selector_entry_file_offset', 'selector_raw', 'selector_target_va', 'dispatch_entry_va', 'dispatch_entry_file_offset', 'dispatch_raw', 'dispatch_target_va'), switches)
    write_tsv(out / 'edges.tsv', ('label', 'owner', 'site_va', 'site_file_offset', 'kind', 'raw_hex', 'target_va'), edges)
    write_tsv(out / 'relocations.tsv', ('slot_va', 'slot_file_offset', 'type', 'symbol_index', 'addend', 'symbol', 'record_file_offset', 'record_hex'), relocs)
    write_tsv(out / 'indirect.tsv', ('label', 'site_va', 'site_file_offset', 'raw_hex', 'slot_va'), indirect)
    write_tsv(out / 'literals.tsv', ('label', 'site_va', 'instruction_hex', 'literal_va', 'literal_file_offset', 'length', 'ascii'), literals)
    write_tsv(out / 'constants.tsv', ('label', 'site_va', 'site_file_offset', 'instruction_hex', 'value'), constants)
    (out / 'summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    return summary



def normalized_index(tag, bias, fallback):
    """Model the pinned unsigned subtraction for an input tag."""
    if type(tag) is not int or not 0 <= tag < (1 << 64):
        raise ValueError('tag is not an unsigned 64-bit value')
    return fallback if tag < bias else tag - bias


def model_transition(constants, mode, actor, payload_key, stake_present, records):
    """Synthetic normal-return model, not execution of the captured binary.

    records maps 20-byte keys to (one-byte relationship tag, 20-byte peer).
    Allocation, malformed container and unwind behavior are deliberately absent.
    """
    if type(mode) is not int or not 0 <= mode <= 255 or type(stake_present) is not bool:
        raise ValueError('invalid mode or stake indicator')
    if not isinstance(actor, bytes) or not isinstance(payload_key, bytes) or len(actor) != 20 or len(payload_key) != 20:
        raise ValueError('keys must each contain 20 bytes')
    for key, value in records.items():
        if not isinstance(key, bytes) or len(key) != 20 or not isinstance(value, tuple) or len(value) != 2:
            raise ValueError('invalid relationship record')
        tag, peer = value
        if type(tag) is not int or not 0 <= tag <= 255 or not isinstance(peer, bytes) or len(peer) != 20:
            raise ValueError('invalid relationship value')
    pending = constants['request_value_tag']
    first = constants['final_first_value_tag']
    second = constants['final_second_value_tag']
    if (pending, first, second) != (0, 1, 2):
        raise ValueError('unexpected relationship tag constants')
    out = records.copy()
    if mode == 0:
        staking, trading = payload_key, actor
        if not stake_present:
            return 'stake_missing', out
        if staking == trading:
            return 'self_link', out
        if trading in out and out[trading][0] != pending:
            return 'trading_linked', out
        if staking in out and out[staking][0] != pending:
            return 'staking_linked', out
        out[trading] = (pending, staking)
        return 'success', out
    staking, trading = actor, payload_key
    if trading not in out or out[trading] != (pending, staking):
        return 'pending_required', out
    if staking in out and out[staking][0] != pending:
        return 'staking_linked', out
    out[trading] = (first, staking)
    out[staking] = (second, trading)
    return 'success', out

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = generate(TARGET.read_bytes(), args.out)
    print('checked', result['selected_fdes'], 'FDEs and', result['selected_direct_edges'], 'direct edges')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('link-staking evidence:', exc, file=sys.stderr)
        raise SystemExit(1)
