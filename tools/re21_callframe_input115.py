#!/usr/bin/env python3
"""Regenerate selected node 115 CALL input and frame handoff evidence from ELF bytes."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
LEGACY_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MAX_U64 = (1 << 64) - 1

# Fixed, manually selected instruction windows. These are local checks, not a
# disassembler or a claim that the intervening bytes form a complete CFG.
PINS = [
    ('driver_table_copy', 0x29a1535, '488d35c409aa03488dbc24100b0000ba00080000ff15b9dfb303'),
    ('driver_cost_literal_copy', 0x29a1601, '0f1005a404c6fd410f118764080000'),
    ('driver_dispatch', 0x29a3390, '488b85180100000fb60848ffc048898518010000488b04cb0fb78c4b0008000048298d88010000720e4889ef4c89feffd084c074cbeb02b020'),
    ('driver_action_read', 0x29a33c9, '0fb68d1001000080f9380f8471030000c6854901000001c68510010000384c8ba5b80000004c8bb5c0000000'),
    ('driver_action_test', 0x29a3451, '84c90f84cc000000'),
    ('driver_child_jump', 0x29a355d, '488b5c24084889dd31f6e9a4040000'),
    ('driver_child_args', 0x29a3a62, '4889b424a80100004889bc24b001000048898c24b801000048899424c00100004c89a424c80100004c89b424d001000048898424d801000044'),
    ('driver_child_call', 0x29a3ac7, '498b453048898424000b0000f3410f6f4500f3410f6f4d10f3410f6f5520660f7f9424f00a0000660f7f8c24e00a0000660f7f8424d00a0000488dbc24300200004c89fe488d9424d00a0000e898a7fcff'),
    ('router_lookup_key', 0x2a6bc5a, '488b3e488db190000000'),
    ('router_borrow', 0x2a6bc78, '4d8b6e50498b56604d85ed7412498b76584531e4eb5cc6'),
    ('router_slice', 0x2a6bcaf, '498b76584c8d49104c8d47014c8941104989d04929f04c890c247212483b5128770c480371204531e44c89c2eb0d498939be0100000041b40131'),
    ('copy_stack_guard', 0x29977eb, '488b473040b52c4883f8030f82a4010000'),
    ('copy_pop_width', 0x2997833, '4883c0fd4989c249c1e2054e8b34124e8b5c12104e0b5c12084e0b5c12184889473040b5240f8542010000'),
    ('copy_charge', 0x299785e, '4c89f048c1e8054489f283e21f4883fa014883d8ff488b965002000048f762280f802d010000488b97880100004829c20f823401000048899788010000'),
    ('copy_zero', 0x299789b, '4d85f60f84b50000004c09c14c09c90f85f0000000'),
    ('copy_grow', 0x29978b0, '4889d84c01f048c7c2ffffffff480f42c24889c148c1e90583e01f4883f8014883d9ff483b8f700100000f87ed000000'),
    ('copy_select', 0x29978e0, '4d09fd4d09e5480f44142448837f38004c8b4f487467488b77404c8b6f10488b471849c74510ffffffff4d8b7d204901c7'),
    ('copy_prefix', 0x2997911, '4c39ca735b4989d44d01f40f82ef0000004d39e14d0f42e14929d44c89e54801dd0f82eb0000004801d6498d3c1f4c89e2ff15c07bb4034c01f30f82db0000004d29e64889ebeb30'),
    ('copy_zerofill', 0x2997971, '4889d94c01f10f829d000000498b55284829c24839d177794901df31ed4c89ff31f64c89f2ff15b47db40349ff4510'),
    ('copy_fail', 0x29979b1, '48c7c0ffffffff488b97880100004829c20f83ccfeffff40b520ebd3'),
    ('range_guard', 0x29998fe, '4c8b6e304983fd04730bc647012cb001e9cc010000'),
    ('range_pop', 0x299995f, '4983c5fc4c89e848c1e0054f0b7413c8498b2c024f0b7413d84d8b5c02084d8b7402104d8b5402184c896e30b0240f85260100004d85e40f8488000000'),
    ('range_input', 0x299999c, '4c09c14c09c90f85110100004c89f84c01e049c7c0ffffffff4c0f43c04c89c148c1e9054183e01f4983f8014883d9ff483b8e700100007656'),
    ('range_zero', 0x2999a24, '49c7c7ffffffff4d01fc0f'),
    ('range_adjust', 0x2999a2b, '4d01fc0f82bc0000004d39e77319488b46184901c748c7c1ffffffff4c0f42f94901c44c0f42e1'),
    ('range_output', 0x2999a52, '4d09deb0244d09d6755d4885ed7460480b5c2428480b5c24204c8b74243075474c89f04801e849c7c0ffffffff4c0f43c04c89c148c1e9054183e01f4983f8014883d9ff483b8e700100007629488d86700100004889'),
    ('range_return', 0x2999ac1, '49c7c6ffffffff4c01f572234c897f084c8967104c89771848896f2031c08807'),
    ('call_stack', 0x299b06d, '488b4f30b02c4883f9020f86b1020000'),
    ('call_target_load', 0x299b08b, '4c8b4407f04883c1fd4989c949c1e105420f1004084c0b4407e8420f104c08104c0b4407f848c7c3ffffffff7505488b5c07e04c8b7407c04c8b7c07c84c8b6c07d00f294c24200f2944241048894e30'),
    ('call_static', 0x299b0db, '660f6f442410660feb44242066480f7ec0660f70c0ee66480f7ec131ed4809c1410f95c4b0274484a6a80100000f8520020000'),
    ('call_range', 0x299b115, '488d7c2430e8d1e7ffff807c243001750a0fb6442431e9fe010000'),
    ('call_target_swap', 0x299b130, '490fcd490fcf490fce49c1ed200f104424380f29842410010000f30f6f442448660f7f84240001000044896c24304c897c24344c8974243c'),
    ('call_host', 0x299b16b, '488dbc24200100004889e6488d54243089e941b8010000004989d9ff1574bcb4030fb68424500100003c02750d0fb6842420010000e989010000'),
    ('call_frame_slice', 0x299b22d, '48c7842480000000000000000f288424100100000f11842488000000660f6f842400010000f30f7f8424a000000048899424b00000004889bc24b8000000'),
    ('call_frame_target', 0x299b26b, '4489ac24c00000004c89bc24c40000004c89b424cc00000048894c247848c744243000'),
    ('call_frame_alloc', 0x299b2a8, 'bfd0000000ff15cd41b4034885c00f84cd0000004889c3488d742430bad00000004889c7ff153642b403'),
    ('call_publish', 0x299b30f, '49c78424b80000000100000049899c24c000000041c684241001000000b004'),
    ('call_unwind_publish', 0x299b3b3, '49c78424b80000000100000049899c24c000000041c6842410010000004c89f7e87856a503'),
    ('memory_cost', 0x45244c8, '4c8b0a4889c849f761500f80f90000004989c04889c848f7e10f80fd0000004d8b49584d85c90f84040100004889c24c09ca48c1ea20740731d249f7f1eb0531d241f7f14901c048c7c0ffffffff490f43c048890f4989c04c2b47'),
    ('memory_charge', 0x452451a, '48890f4989c04c2b470848894708488b5718b0214c29c20f828e00000048895718'),
    ('memory_borrow', 0x4524548, '48c1e1054c8b7e1049c74710ffffffff48034e180f82e1000000498b5f284989ce4929de76'),
    ('memory_zero', 0x4524581, '4d8b6720498d3c1c4983fe027218498d56ff31f6ff15b5b1fb014c01f348ffcb4901dc4c89e7c6070048ffc3498b471048ffc04889d9eb0231c049894f2849894710'),
    ('memory_overflow', 0x45245d1, '49c7c0ffffffff4889c848f7e10f8103ffffff48c7c0ffffffff4d8b49584d85c90f85fcfeffff'),
    ('memory_reserve', 0x4524605, 'b90100000041b8010000004889de4c89f2e825476c01'),
    ('grow_min_cap', 0x5be8d47, '4d89c14d85c0750831ffff1541678f004801f272f34989c8488b37488d04364839c2480f47c231c94981f9010400000f92c14983f901488d4c4901bb08000000480f45d94839d8480f47d849'),
    ('indirect_copy_bound', 0x5be8e1b, '4c8b7f10488b7f1849c74710ffffffff498b47284829f80f82c1000000498b5f204d89ca4d29c276184939f90f87c70000004901d84885c9751531c0e98a00000041b8010000004531d24885c974eb'),
    ('indirect_copy_prefix', 0x5be8e72, '4989ce4901d60f82b40000004d39f24d0f42f24929d64d89f44901f40f82b00000004989cd4901d0488d3c334889f54c89c64c89f2ff155b668f004c01ed0f82970000004c89e94c29f14c89e6eb0d'),
    ('indirect_copy_fill', 0x5be8ec1, '4889ca4801f272724839c277554801f34889df31f64889caff1571688f00498b471048ffc049894710'),
    ('host_value_cost', 0x4335d1a, '7423488b87500200004c8bba880100004c2b78780f824007000089cd4c89ba88010000eb09'),
    ('host_loader', 0x4335d79, '4939cf0f92c120c1488db770020000440fb6af9603000048897c2408488d9798030000440fb6c1488dbc2498000000488974243048895424284c89d1ff1515491b02440fb6a424d00000004180fc02750845'),
    ('host_code_check', 0x433c707, '48837f700074084883c4685b415ec34889fbf30f6f4748f30f6f4f58660f7f4c2450660f7f442440660f740de95811fc660f7405b17011fc660fdbc1660fd7c03dffff00007475488d'),
    ('host_code_publish', 0x433c7c3, '4c8b35aea41a02418b460885c0752f4d8b36f049ff067e3b4883c370488b034885c0740ff048ff0875094889dfff15b2871a024c89334883c4685b415e'),
    ('host_fee_charge', 0x4336296, '410fb6c549c1e7084909c74c89b424980000004c8b4c2440498b89880100004c29f94c8b4424480f828a01000049898988010000'),
    ('host_cap', 0x433636c, '488b442408488b8050020000488b70704885f60f843c0100004889c84809f048c1e82074354889c831d248f7f6eb3131db4d85f60f85d4feffff4c8b74241041f6c501b836000000b9200000000f45c841880e41c6463002eb7289c831d2f7f64889ca4829c24939d04c0f43c24c29c1726f498989880100'),
    ('host_return', 0x4336408, '4885db0f28842480010000660f6f8c2490010000488b442410f30f7f48200f1140104c89304989c64c8940080f954030'),
    ('schedule_copy_multiplier', 0x5be26ba, '48c7402803000000'),
    ('schedule_memory_linear', 0x5be26e2, '48c7405003000000'),
    ('schedule_memory_divisor', 0x5be26ea, '48c7405800020000'),
    ('schedule_call_divisor', 0x5be2703, '48c7407040000000'),
    ('schedule_value_fee', 0x5be270b, '48c7407828230000'),
    ('router_callback_boundary', 0x2a6bcea, '498b8e800000004d8b8688000000488d7c2470ff5018'),
    ('adapter_input_gate_boundary', 0x5c1665d, '4881fad500000075158b1e0fcb4839d9733548'),
    ('adapter_final_gate_boundary', 0x5c166a4, '0fb6aed40000004080fd02'),
    ('schedule_stipend', 0x5be2748, '48c780c0000000fc080000'),
    ('driver_table_heap_copy', 0x29a15da, '488db424100b0000ba620800004889c74c8b2d17dfb303'),
    ('driver_table_context_store', 0x29a17f5, '4c89bc24f00e0000'),
    ('driver_table_reload', 0x29a336c, '488b9c24f00e0000'),
    ('frame_variant_check', 0x296e366, '498b5424204d8b7c24284d8b6c2430410f100424410f104c24100f298c24700400000f298424600400004883fa017464'),
    ('frame_transfer_gate', 0x296e540, '41833f010f8480000000'),
    ('frame_slice_mode', 0x296e621, '498b47504885c00f84d2020000'),
    ('frame_router_handoff', 0x296e9ba, '4c89f24c89f9e87bd20f00'),
]

# Only these eight indexed FDE starts are newly investigated. Older drivers and
# the precompile router appear solely as handoff boundaries in the windows.
FUNCTIONS = [
    ('calldata_copy', 0x29977e0),
    ('call_ranges', 0x29998f0),
    ('call_instruction', 0x299b050),
    ('host_call_gas', 0x4335cf0),
    ('host_code_prepare', 0x433c700),
    ('memory_expand', 0x45244c0),
    ('memory_reserve', 0x5be8d40),
    ('indirect_calldata_copy', 0x5be8e10),
]

# Every target is independently checked against its relative displacement.
# Labels indicate manually interpreted branch predicates and are not inferred
# merely from executable-section membership.
EDGES = [
 ('copy_stack_underflow', 0x29977f6, 0x29979a0),
 ('copy_size_high', 0x2997858, 0x29979a0),
 ('copy_word_cost_overflow', 0x299787e, 0x29979b1),
 ('copy_word_cost_borrow', 0x299788e, 0x29979c8),
 ('copy_zero_size', 0x299789e, 0x2997959),
 ('copy_destination_high', 0x29978aa, 0x29979a0),
 ('copy_expand', 0x29978da, 0x29979cd),
 ('copy_indirect_input', 0x29978f4, 0x299795d),
 ('copy_outside_source', 0x2997914, 0x2997971),
 ('copy_source_end_overflow', 0x299791c, 0x2997a11),
 ('copy_destination_end_overflow', 0x2997932, 0x2997a23),
 ('copy_padding_end_overflow', 0x299794b, 0x2997a2c),
 ('copy_post_expand_error', 0x29979fb, 0x29979a0),
 ('copy_post_expand_resume', 0x29979fd, 0x29978e0),
 ('ranges_four_words', 0x2999906, 0x2999913),
 ('ranges_size_high', 0x299998d, 0x2999ab9),
 ('ranges_input_empty', 0x2999996, 0x2999a24),
 ('ranges_input_offset_high', 0x29999a2, 0x2999ab9),
 ('ranges_input_existing_memory', 0x29999d3, 0x2999a2b),
 ('ranges_input_growth_failed', 0x2999a1c, 0x2999ab9),
 ('ranges_input_end_carry', 0x2999a2e, 0x2999af0),
 ('ranges_output_size_high', 0x2999a5a, 0x2999ab9),
 ('ranges_output_empty', 0x2999a5f, 0x2999ac1),
 ('ranges_output_offset_high', 0x2999a70, 0x2999ab9),
 ('ranges_output_existing_memory', 0x2999a9d, 0x2999ac8),
 ('ranges_output_growth_ok', 0x2999ab7, 0x2999ac8),
 ('ranges_output_end_carry', 0x2999acb, 0x2999af0),
 ('call_three_word_underflow', 0x299b077, 0x299b32e),
 ('call_value_in_static_context', 0x299b108, 0x299b32e),
 ('call_range_helper', 0x299b11a, 0x29998f0),
 ('call_range_success', 0x299b124, 0x299b130),
 ('call_host_success', 0x299b196, 0x299b1a5),
 ('call_frame_allocation_failure', 0x299b2b6, 0x299b389),
 ('call_action_replacement', 0x299b2e6, 0x299b30f),
 ('host_zero_value', 0x4335d1a, 0x4335d3f),
 ('host_value_fee_borrow', 0x4335d2e, 0x4336474),
 ('host_account_result', 0x4335dc8, 0x4335dd2),
 ('host_prepare_code', 0x4335dea, 0x433c700),
 ('host_dynamic_fee_borrow', 0x43362bd, 0x433644d),
 ('host_divisor_zero', 0x433637f, 0x43364c1),
 ('host_forwarded_gas_borrow', 0x43363dc, 0x433644d),
 ('memory_linear_multiply_overflow', 0x45244d2, 0x45245d1),
 ('memory_square_overflow', 0x45244e1, 0x45245e4),
 ('memory_divisor_zero', 0x45244ee, 0x45245f8),
 ('memory_gas_borrow', 0x4524531, 0x45245c5),
 ('memory_needs_reserve', 0x452457b, 0x4524605),
 ('memory_reserve_helper', 0x4524616, 0x5be8d40),
 ('indirect_input_bad_backing', 0x5be8e32, 0x5be8ef9),
 ('indirect_input_empty_range', 0x5be8e42, 0x5be8e5c),
 ('indirect_input_range_outside', 0x5be8e47, 0x5be8f14),
 ('indirect_input_source_past_end', 0x5be8e70, 0x5be8ec1),
 ('indirect_input_source_end_carry', 0x5be8e78, 0x5be8f32),
 ('indirect_input_dest_end_carry', 0x5be8e8e, 0x5be8f44),
 ('indirect_input_zero_end_carry', 0x5be8ec7, 0x5be8f3b),
 ('indirect_input_dest_bounds', 0x5be8ecc, 0x5be8f23),
 ('frame_variant_call', 0x296e394, 0x296e3fa),
 ('frame_depth_ok', 0x296e452, 0x296e4ed),
 ('frame_bypass_transfer', 0x296e544, 0x296e5ca),
 ('frame_transfer_failure', 0x296e5c4, 0x296eb73),
 ('frame_direct_slice', 0x296e628, 0x296e900),
 ('frame_router', 0x296e9c0, 0x2a6bc40),
 ('router_registry_lookup', 0x2a6bc64, 0x2a6c360),
 ('router_lookup_miss', 0x2a6bc6c, 0x2a6bc8e),
 ('router_borrowed_slice', 0x2a6bc83, 0x2a6bc97),
 ('router_invalid_slice_start', 0x2a6bcc9, 0x2a6bcdd),
 ('router_invalid_slice_end', 0x2a6bccf, 0x2a6bcdd),
 ('driver_base_charge_borrow', 0x29a33b7, 0x29a33c7),
 ('driver_next_instruction', 0x29a33c3, 0x29a3390),
 ('driver_child_action', 0x29a3453, 0x29a3525),
 ('driver_child_prepare', 0x29a3567, 0x29a3a10),
 ('driver_frame_handoff', 0x29a3b13, 0x296e2b0),
]

# Each instruction is exactly ff 15 disp32 (indirect call via a RIP slot).
CALL_SLOTS = [
 ('copy_direct_memcpy', 0x2997942, 0x64df508),
 ('copy_indirect_helper', 0x2997967, 0x64e6df8),
 ('copy_direct_memset', 0x2997996, 0x64df750),
 ('copy_memory_expand', 0x29979e7, 0x64e6de0),
 ('ranges_input_expand', 0x29999fe, 0x64e6de0),
 ('ranges_output_expand', 0x2999aac, 0x64e6de0),
 ('call_host_gas', 0x299b186, 0x64e6e00),
 ('call_frame_copy', 0x299b2cc, 0x64df508),
 ('host_account_load', 0x4335db5, 0x64ea6d0),
 ('indirect_copy_memcpy', 0x5be8ea7, 0x64df508),
 ('indirect_copy_memset', 0x5be8ed9, 0x64df750),
 ('callback_adapter_boundary', 0x5c165c2, 0x64eaee8),
]

# Opcode entries and the two historical handoff slots are relocations, not
# function pointers read out of an unrelocated in-memory image.
RELATIVE_SLOTS = [
 ('opcode_37', 0x64420b8, 0x29977e0),
 ('opcode_f1', 0x6442688, 0x299b050),
 ('address_09_callback', 0x64c0748, 0x5c165b0),
 ('memory_expansion', 0x64e6de0, 0x45244c0),
 ('input_copy_helper', 0x64e6df8, 0x5be8e10),
 ('host_gas_helper', 0x64e6e00, 0x4335cf0),
 ('account_loader', 0x64ea6d0, 0x4323870),
 ('precompile_adapter', 0x64eaee8, 0x5c16650),
]
SYMBOL_SLOTS = [('memcpy', 0x64df508), ('memset', 0x64df750)]

# The descriptors are reached by selected overflow, bounds or divisor error
# branches in the eight new FDEs. Only a safe source suffix is exported.
SOURCE_REFERENCES = [
 ('copy_destination_bound', 0x2997a02, '488d3d', 0x64bfda0),
 ('copy_source_carry', 0x2997a11, '488d3d', 0x64bfd40),
 ('copy_empty_fill_carry', 0x2997a1a, '488d3d', 0x64bfd88),
 ('copy_prefix_carry', 0x2997a23, '488d3d', 0x64bfd58),
 ('copy_fill_carry', 0x2997a2c, '488d3d', 0x64bfd70),
 ('range_end_carry', 0x2999af0, '488d3d', 0x6443880),
 ('memory_zero_divisor', 0x45245f8, '488d3d', 0x648f230),
 ('memory_word_limit', 0x4524636, '488d3d', 0x648f1d0),
 ('memory_base_carry', 0x4524643, '488d3d', 0x64bfcf8),
 ('input_backing_underflow', 0x5be8f00, '488d15', 0x64bfc98),
 ('input_bound', 0x5be8f14, '488d3d', 0x64bfcb0),
 ('host_cost_carry', 0x43364b8, '488d3d', 0x6486b40),
 ('host_zero_divisor', 0x43364c1, '488d3d', 0x6486af8),
 ('host_secondary_carry', 0x43364d0, '488d3d', 0x6486b10),
 ('host_combined_carry', 0x43364d9, '488d3d', 0x6486b28),
]

# Each row fixes the complete opcode/register prefix and extracts the
# displacement bytes directly. The equations in lineage() then connect the
# helper result, spilled values, constructed frame and router field.
LINEAGE_FIELDS = [
 ('range_result_rsp', 0x299b115, '488d7c24', 1),
 ('input_start_result', 0x2999acd, '4c897f', 1),
 ('input_end_result', 0x2999ad1, '4c8967', 1),
 ('output_start_result', 0x2999ad5, '4c8977', 1),
 ('output_end_result', 0x2999ad9, '48896f', 1),
 ('input_load_rsp', 0x299b13d, '0f104424', 1),
 ('input_spill_rsp', 0x299b142, '0f298424', 4),
 ('output_load_rsp', 0x299b14a, 'f30f6f4424', 1),
 ('output_spill_rsp', 0x299b150, '660f7f8424', 4),
 ('representation_store_rsp', 0x299b22d, '48c78424', 4),
 ('input_reload_rsp', 0x299b239, '0f288424', 4),
 ('input_store_rsp', 0x299b241, '0f118424', 4),
 ('output_reload_rsp', 0x299b249, '660f6f8424', 4),
 ('output_store_rsp', 0x299b252, 'f30f7f8424', 4),
 ('key_store_0_rsp', 0x299b26b, '4489ac24', 4),
 ('key_store_1_rsp', 0x299b273, '4c89bc24', 4),
 ('key_store_2_rsp', 0x299b27b, '4c89b424', 4),
 ('second_key_store_0_rsp', 0x299b1cf, '4489ac24', 4),
 ('second_key_store_1_rsp', 0x299b1d7, '4c89bc24', 4),
 ('second_key_store_2_rsp', 0x299b1df, '4c89b424', 4),
 ('frame_copy_rsp', 0x299b2bf, '488d7424', 1),
 ('router_key_field', 0x2a6bc5d, '488db1', 4),
 ('router_representation_field', 0x2a6bc78, '4d8b6e', 1),
 ('router_input_end_field', 0x2a6bc7c, '498b56', 1),
 ('router_input_start_field', 0x2a6bcaf, '498b76', 1),
]


def verified_bytes(path, digest):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('artifact SHA-256 mismatch')
    return data


def section_named(sec, name):
    found = [s for s in sec if s['name'] == name and s['type'] != 8]
    if len(found) != 1:
        raise ValueError('missing, ambiguous, or unbacked section: ' + name)
    return found[0]


def file_offset(sec, va, size, executable=False):
    if size <= 0 or va < 0:
        raise ValueError('invalid file mapping request')
    found = [s for s in sec if s['type'] != 8 and
             (not executable or s['flags'] & 4) and
             s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('address has no unique file-backed section')
    return found[0], found[0]['offset'] + va - found[0]['address']


def read_va(data, sec, va, size, executable=False):
    _, pos = file_offset(sec, va, size, executable)
    chunk = data[pos:pos + size]
    if len(chunk) != size:
        raise ValueError('mapped bytes are truncated')
    return chunk


def check_pin(data, sec, va, expected):
    expected = bytes.fromhex(expected)
    got = read_va(data, sec, va, len(expected), True)
    if got != expected:
        raise ValueError('instruction window mismatch at ' + hex(va))
    return got


def relative_branch(data, sec, va):
    first = read_va(data, sec, va, 2, True)
    if first[0] in (0xe8, 0xe9):
        size, disp_off, fmt = 5, 1, '<i'
    elif first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
        size, disp_off, fmt = 6, 2, '<i'
    elif 0x70 <= first[0] <= 0x7f or first[0] == 0xeb:
        size, disp_off, fmt = 2, 1, '<b'
    else:
        raise ValueError('unsupported relative branch at ' + hex(va))
    raw = read_va(data, sec, va, size, True)
    return raw, va + size + struct.unpack_from(fmt, raw, disp_off)[0]


def indirect_slot(data, sec, va):
    raw = read_va(data, sec, va, 6, True)
    if raw[:2] != b'\xff\x15':
        raise ValueError('not a RIP-relative indirect call')
    return raw, va + 6 + struct.unpack_from('<i', raw, 2)[0]


def rip_target(data, sec, va, prefix):
    raw = read_va(data, sec, va, 7, True)
    if raw[:3] != prefix:
        raise ValueError('unexpected RIP-relative instruction')
    return raw, va + 7 + struct.unpack_from('<i', raw, 3)[0]


def relocation_rows(data, sec, requests):
    section = section_named(sec, '.rela.dyn')
    if section['size'] % 24:
        raise ValueError('unsupported RELA size')
    wanted = {va for _, va, _, _ in requests}
    if len(wanted) != len(requests):
        raise ValueError('duplicate relocation request')
    hits = {}
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        va, info, addend = struct.unpack_from('<QQq', data, off)
        if va in wanted:
            if va in hits:
                raise ValueError('ambiguous relocation')
            hits[va] = (off, info, addend)
    dynsym = section_named(sec, '.dynsym')
    dynstr = section_named(sec, '.dynstr')
    out = []
    for label, va, expected_type, expected in requests:
        if va not in hits:
            raise ValueError('missing relocation ' + label)
        off, info, addend = hits[va]
        typ, symidx = info & 0xffffffff, info >> 32
        if typ != expected_type:
            raise ValueError('relocation type mismatch')
        symbol = ''
        if typ == 8:
            if symidx != 0 or (expected is not None and addend != expected):
                raise ValueError('relative relocation target mismatch')
        elif typ == 6:
            symoff = dynsym['offset'] + symidx * 24
            if symoff + 24 > dynsym['offset'] + dynsym['size']:
                raise ValueError('dynamic symbol outside section')
            name = struct.unpack_from('<I', data, symoff)[0]
            if name >= dynstr['size']:
                raise ValueError('dynamic symbol name outside section')
            nameoff = dynstr['offset'] + name
            end = data.find(b'\0', nameoff, dynstr['offset'] + dynstr['size'])
            if end < 0:
                raise ValueError('unterminated dynamic symbol')
            symbol = data[nameoff:end].decode('ascii')
            if symbol != expected:
                raise ValueError('dynamic symbol mismatch')
        else:
            raise ValueError('unsupported relocation')
        out.append([label, hex(va), hex(off), hex(info), str(addend),
                    symbol, data[off:off + 24].hex()])
    return out


def sanitize_source_path(raw):
    marker = b'z_vendor/'
    pos = raw.find(marker)
    if pos < 0 or raw.find(marker, pos + 1) >= 0 or b'\0' in raw:
        raise ValueError('unexpected source location path')
    suffix = raw[pos:].decode('ascii')
    if any(part in ('', '.', '..') for part in suffix.split('/')):
        raise ValueError('invalid source path suffix')
    return suffix


def source_locations(data, sec):
    requests = [(name, descriptor, 8, None) for name, _, _, descriptor in SOURCE_REFERENCES]
    relocations = relocation_rows(data, sec, requests)
    rows = []
    for (name, ref_va, prefix, desc_va), relocation in zip(SOURCE_REFERENCES, relocations):
        ref, target = rip_target(data, sec, ref_va, bytes.fromhex(prefix))
        if target != desc_va:
            raise ValueError('source descriptor reference mismatch')
        desc = read_va(data, sec, desc_va, 24)
        pointer, length, line, column = struct.unpack('<QQII', desc)
        if pointer != 0 or not 0 < length <= 512:
            raise ValueError('unsupported source descriptor')
        path_va = int(relocation[4])
        suffix = sanitize_source_path(read_va(data, sec, path_va, length))
        rows.append([name, hex(ref_va), hex(file_offset(sec, ref_va, len(ref), True)[1]),
                     ref.hex(), hex(desc_va), hex(file_offset(sec, desc_va, 24)[1]),
                     desc.hex(), relocation[2], relocation[6], hex(path_va), suffix, str(line), str(column)])
    return rows


def select_fdes(data, sec):
    _, index = unwind_index(data)
    _, fdes = eh_frame_records(data, sec)
    selected = {va for _, va in FUNCTIONS}
    found = {}
    for fde in fdes:
        if fde['start'] in selected:
            if fde['start'] in found:
                raise ValueError('duplicate selected FDE start')
            found[fde['start']] = fde
    index_map = {row['start']: row for row in index if row['start'] in selected}
    rows, bodies, exceptions = [], [], []
    for label, start in FUNCTIONS:
        fde, idx = found.get(start), index_map.get(start)
        if fde is None or idx is None or fde['fde'] != idx['fde']:
            raise ValueError('FDE and unwind index disagree: ' + label)
        if fde['end'] <= start:
            raise ValueError('empty FDE')
        _, off = file_offset(sec, start, fde['end'] - start, True)
        body = data[off:off + fde['end'] - start]
        rows.append([label, hex(start), hex(fde['end']), hex(fde['fde']),
                     hex(fde['cie']), '' if fde['lsda'] is None else hex(fde['lsda']),
                     hex(off), str(len(body)), hashlib.sha256(body).hexdigest()])
        bodies.append({'label': label, 'start_va': hex(start), 'end_va': hex(fde['end']),
                       'file_offset': hex(off), 'hex': body.hex()})
        if fde['lsda'] is not None:
            exceptions.extend(lsda_sites(data, sec, label, fde))
    return rows, bodies, exceptions


def lsda_sites(data, sec, label, fde):
    """Read only the observed LSDA call-site encoding; leave action chains opaque."""
    table = section_named(sec, '.gcc_except_table')
    va = fde['lsda']
    if not table['address'] <= va < table['address'] + table['size']:
        raise ValueError('LSDA outside exception section')
    pos = table['offset'] + va - table['address']
    limit = table['offset'] + table['size']
    if pos + 2 > limit or data[pos] != 0xff:
        raise ValueError('unsupported LSDA landing base')
    type_encoding = data[pos + 1]
    pos += 2
    type_base = None
    if type_encoding != 0xff:
        if type_encoding != 0x9b:
            raise ValueError('unsupported LSDA type table encoding')
        type_offset, pos = uleb(data, pos, limit)
        type_base = pos + type_offset
        if type_base > limit:
            raise ValueError('LSDA type table outside section')
    if pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call site encoding')
    length, pos = uleb(data, pos + 1, limit)
    end = pos + length
    if end > limit:
        raise ValueError('call site table outside section')
    if type_base is not None and end > type_base:
        raise ValueError('call sites overlap type table base')
    rows = []
    while pos < end:
        begin = pos
        site, pos = uleb(data, pos, end)
        size, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        if site + size > fde['end'] - fde['start']:
            raise ValueError('call site outside FDE')
        if landing and landing >= fde['end'] - fde['start']:
            raise ValueError('landing outside FDE')
        rows.append([label, hex(va), hex(begin), hex(fde['start'] + site),
                     hex(fde['start'] + site + size),
                     '' if landing == 0 else hex(fde['start'] + landing),
                     str(action), data[begin:pos].hex()])
    return rows


def lineage(data, sec):
    fields = {}
    rows = []
    for label, va, prefix_hex, width in LINEAGE_FIELDS:
        prefix = bytes.fromhex(prefix_hex)
        raw = read_va(data, sec, va, len(prefix) + width, True)
        if not raw.startswith(prefix) or width not in (1, 4):
            raise ValueError('unexpected lineage instruction: ' + label)
        value = int.from_bytes(raw[len(prefix):], 'little')
        _, off = file_offset(sec, va, len(raw), True)
        fields[label] = value
        rows.append({'label': label, 'va': hex(va), 'file_offset': hex(off),
                     'hex': raw.hex(), 'displacement': value})
    f = fields
    base = f['frame_copy_rsp']
    if not (f['range_result_rsp'] == base and
            [f['input_start_result'], f['input_end_result'],
             f['output_start_result'], f['output_end_result']] == [8, 16, 24, 32] and
            f['input_load_rsp'] == base + f['input_start_result'] and
            f['output_load_rsp'] == base + f['output_start_result'] and
            f['input_spill_rsp'] == f['input_reload_rsp'] and
            f['output_spill_rsp'] == f['output_reload_rsp'] and
            f['input_store_rsp'] - base == f['router_input_start_field'] and
            f['input_store_rsp'] - base + 8 == f['router_input_end_field'] and
            f['representation_store_rsp'] - base == f['router_representation_field'] and
            f['key_store_0_rsp'] - base == f['router_key_field'] and
            [f['key_store_1_rsp'], f['key_store_2_rsp']] ==
            [f['key_store_0_rsp'] + 4, f['key_store_0_rsp'] + 12] and
            [f['second_key_store_1_rsp'], f['second_key_store_2_rsp']] ==
            [f['second_key_store_0_rsp'] + 4, f['second_key_store_0_rsp'] + 12]):
        raise ValueError('lineage displacement relationship mismatch')
    representation_immediate = read_va(data, sec, 0x299b235, 4, True)
    if representation_immediate != bytes(4):
        raise ValueError('input representation is not zero')
    return {'instructions': rows,
            'frame_base_rsp_displacement': base,
            'frame_input_representation_field': f['router_representation_field'],
            'frame_input_start_field': f['router_input_start_field'],
            'frame_input_end_field': f['router_input_end_field'],
            'frame_output_start_field': f['output_store_rsp'] - base,
            'frame_output_end_field': f['output_store_rsp'] - base + 8,
            'frame_key_field': f['router_key_field'],
            'frame_second_key_field': f['second_key_store_0_rsp'] - base,
            'representation_immediate_hex': representation_immediate.hex()}


def project_address(value):
    if not 0 <= value < 1 << 256:
        raise ValueError('word outside 256 bits')
    return (value & ((1 << 160) - 1)).to_bytes(20, 'big')


def copy_result(source, offset, length):
    if not 0 <= offset <= MAX_U64 or not 0 <= length <= MAX_U64:
        raise ValueError('copy argument outside 64 bits')
    # This models the success-only prefix and zero fill, not allocations or gas.
    if length > 65536:
        raise ValueError('synthetic example too large')
    available = source[offset:offset + length] if offset < len(source) else b''
    return available + bytes(length - len(available))


def words_for_bytes(length):
    if not 0 <= length <= MAX_U64:
        raise ValueError('length outside 64 bits')
    return (length >> 5) + bool(length & 31)


def base_charge(gas, cost):
    """Model the dispatcher's in-place u64 subtraction and subsequent branch."""
    if not all(0 <= value <= MAX_U64 for value in (gas, cost)):
        raise ValueError('invalid charge')
    return (0x20 if gas < cost else 0, (gas - cost) & MAX_U64)


def copy_charge(gas, length, per_word):
    """Model the copy handler's saturating word charge and guarded write."""
    if not all(0 <= value <= MAX_U64 for value in (gas, length, per_word)):
        raise ValueError('invalid copy charge')
    charge = min(words_for_bytes(length) * per_word, MAX_U64)
    return (0x20, gas) if gas < charge else (0, gas - charge)


def memory_cost(words, linear, divisor):
    if not all(0 <= value <= MAX_U64 for value in (words, linear)) or not 0 < divisor <= MAX_U64:
        raise ValueError('invalid memory cost arguments')
    product = min(words * linear, MAX_U64)
    square = min(words * words, MAX_U64)
    return min(product + square // divisor, MAX_U64)


def expand_metadata(words, old_cost, gas, linear, divisor):
    """Model metadata and gas on the monotonic, materializable expansion path."""
    if not all(0 <= value <= MAX_U64 for value in (old_cost, gas)):
        raise ValueError('invalid expansion state')
    total = memory_cost(words, linear, divisor)
    if total < old_cost:
        raise ValueError('nonmonotonic expansion state')
    delta = total - old_cost
    return (0x21 if gas < delta else 0, words, total, gas if gas < delta else gas - delta)


def call_stack_gate(count, value, static_byte):
    if not 0 <= count <= MAX_U64 or not 0 <= value < (1 << 256) or not 0 <= static_byte <= 255:
        raise ValueError('invalid synthetic stack state')
    if count < 3:
        return (0x2c, count, 'first_pop')
    count -= 3
    if value and static_byte & 1:
        return (0x27, count, 'static_value')
    if count < 4:
        return (0x2c, count, 'ranges_pop')
    return (0, count - 4, 'ranges_ready')


def range_check(offset, length):
    """Classify a range after assuming any necessary expansion returned normally."""
    if not 0 <= offset < (1 << 256) or not 0 <= length < (1 << 256):
        raise ValueError('range word outside 256 bits')
    if length > MAX_U64:
        return 'size_high'
    if length == 0:
        return 'empty'
    if offset > MAX_U64:
        return 'offset_high'
    if offset + length > MAX_U64:
        return 'end_carry'
    return 'accepted'


def forwarded_gas(remaining, requested, divisor, stipend=0):
    """Model the reached capped branch, assuming its earlier charges succeeded."""
    if not all(0 <= value <= MAX_U64 for value in (remaining, requested, stipend)):
        raise ValueError('invalid gas quantity')
    if not 0 < divisor <= MAX_U64:
        raise ValueError('invalid cap divisor')
    cap = remaining - remaining // divisor
    charged = min(requested, cap)
    return remaining - charged, min(charged + stipend, MAX_U64)


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.writer(out, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(data, out):
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('artifact SHA-256 mismatch')
    sec = sections(data)
    if RELATIVE_SLOTS[0][1] != 0x6441f00 + 8 * 0x37 or RELATIVE_SLOTS[1][1] != 0x6441f00 + 8 * 0xf1:
        raise ValueError('opcode table indices do not match selected slots')
    windows = []
    for name, va, expected in PINS:
        raw = check_pin(data, sec, va, expected)
        section, offset = file_offset(sec, va, len(raw), True)
        windows.append([name, hex(va), hex(offset), section['name'], str(len(raw)), raw.hex()])
    edges = []
    for name, va, expected in EDGES:
        raw, target = relative_branch(data, sec, va)
        if target != expected:
            raise ValueError('branch target mismatch: ' + name)
        _, off = file_offset(sec, va, len(raw), True)
        edges.append([name, hex(va), hex(off), raw.hex(), hex(target)])
    for name, va, expected in CALL_SLOTS:
        raw, target = indirect_slot(data, sec, va)
        if target != expected:
            raise ValueError('indirect slot mismatch: ' + name)
        _, off = file_offset(sec, va, len(raw), True)
        edges.append([name, hex(va), hex(off), raw.hex(), hex(target)])
    for name, va, prefix, expected in [
        ('table_source', 0x29a1535, b'\x48\x8d\x35', 0x6441f00),
        ('copy_cost_source', 0x29a1601, b'\x0f\x10\x05', 0x601aac),
    ]:
        raw, target = rip_target(data, sec, va, prefix)
        if target != expected:
            raise ValueError('data reference mismatch')
        _, off = file_offset(sec, va, len(raw), True)
        edges.append([name, hex(va), hex(off), raw.hex(), hex(target)])
    requests = [(name, va, 8, target) for name, va, target in RELATIVE_SLOTS]
    requests += [(name, va, 6, name) for name, va in SYMBOL_SLOTS]
    relocs = relocation_rows(data, sec, requests)
    sources = source_locations(data, sec)
    fdes, bodies, exceptions = select_fdes(data, sec)
    lineage_data = lineage(data, sec)
    address = read_va(data, sec, 0x64c0750, 20)
    literal = read_va(data, sec, 0x601aac, 16)
    if address != bytes(19) + b'\x09' or literal != bytes.fromhex('02000200020003000200030002000300'):
        raise ValueError('data literal mismatch')
    literal_rows = []
    for label, va, chunk in [('address_09_key', 0x64c0750, address),
                              ('base_cost_vector', 0x601aac, literal)]:
        _, off = file_offset(sec, va, len(chunk))
        literal_rows.append([label, hex(va), hex(off), chunk.hex(), ''])
    literal_rows.append(['opcode_37_base_cost', hex(0x601aac + 10),
                         hex(file_offset(sec, 0x601aac + 10, 2)[1]),
                         literal[10:12].hex(), str(struct.unpack_from('<H', literal, 10)[0])])
    size_bytes = read_va(data, sec, 0x5c16660, 4, True)
    literal_rows.append(['adapter_input_size_boundary', hex(0x5c16660),
                         hex(file_offset(sec, 0x5c16660, 4, True)[1]),
                         size_bytes.hex(), str(struct.unpack('<I', size_bytes)[0])])
    for label, va, expected in PINS:
        if label.startswith('schedule_'):
            raw = bytes.fromhex(expected)
            imm_offset = 7 if label == 'schedule_stipend' else 4
            immediate = struct.unpack_from('<i', raw, imm_offset)[0]
            _, off = file_offset(sec, va + imm_offset, 4, True)
            literal_rows.append([label, hex(va + imm_offset), hex(off),
                                 raw[imm_offset:imm_offset + 4].hex(), str(immediate)])
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out / 'windows.tsv', ['label', 'va', 'file_offset', 'section', 'size', 'hex'], windows)
    write_tsv(out / 'edges.tsv', ['label', 'instruction_va', 'file_offset', 'hex', 'branch_target_or_slot_va'], edges)
    write_tsv(out / 'relocations.tsv', ['label', 'slot_va', 'rela_file_offset', 'r_info', 'addend_decimal', 'dynamic_symbol', 'rela_hex'], relocs)
    write_tsv(out / 'functions.tsv', ['label', 'fde_start_va', 'fde_end_va', 'fde_va', 'cie_va', 'lsda_va', 'body_file_offset', 'body_size', 'body_sha256'], fdes)
    write_tsv(out / 'exceptions.tsv', ['label', 'lsda_va', 'record_file_offset', 'site_start_va', 'site_end_va', 'landing_va', 'action', 'record_hex'], exceptions)
    write_tsv(out / 'literals.tsv', ['label', 'va', 'file_offset', 'hex', 'value_decimal'], literal_rows)
    write_tsv(out / 'sources.tsv', ['label', 'reference_va', 'reference_file_offset', 'reference_hex',
                                   'descriptor_va', 'descriptor_file_offset', 'descriptor_hex',
                                   'rela_file_offset', 'rela_hex', 'path_va', 'sanitized_path_suffix', 'line', 'column'], sources)
    (out / 'bodies.json').write_text(json.dumps(bodies, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (out / 'lineage.json').write_text(json.dumps(lineage_data, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    summary = {'target_release': '115', 'target_sha256': TARGET_SHA256,
               'address_coordinate': 'ELF virtual address before load bias',
               'file_coordinate': 'byte offset from start of artifact',
               'selected_function_fdes': len(fdes),
               'selected_fde_body_bytes': sum(int(row[7]) for row in fdes),
               'selected_fdes_with_lsda': sum(bool(row[5]) for row in fdes),
               'selected_windows': len(windows),
               'selected_relative_branches': len(EDGES), 'selected_indirect_calls': len(CALL_SLOTS),
               'selected_rip_data_references': 2, 'selected_relocations': len(relocs),
               'selected_literal_rows': len(literal_rows), 'selected_exception_sites': len(exceptions),
               'selected_lineage_instructions': len(lineage_data['instructions']),
               'selected_source_descriptors': len(sources),
               'selected_source_suffixes': len({row[10] for row in sources}),
               'warning': 'FDE ranges and selected windows are not a complete CFG or evidence of runtime execution.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def check_legacy(path, target):
    data = verified_bytes(path, LEGACY_SHA256)
    sec = sections(data)
    legacy_address = read_va(data, sec, 0x574f0c0, 20)
    target_sec = sections(target)
    target_address = read_va(target, target_sec, 0x64c0750, 20)
    if legacy_address != target_address or target_address != project_address(9):
        raise ValueError('legacy and target address keys differ')
    rows = relocation_rows(data, sec, [('legacy_callback', 0x574f0b0, 8, 0x4e9d2a0),
                                       ('legacy_compressor', 0x5776f28, 8, 0x4e9a8a0)])
    old_call, old_slot = indirect_slot(data, sec, 0x4e9d3bd)
    if old_slot != 0x5776f28:
        raise ValueError('historical compression call slot mismatch')
    old_gate = read_va(data, sec, 0x4e9d2aa, 8, True)
    new_gate = read_va(target, target_sec, 0x5c1665d, 7, True)
    if old_gate[:4] != bytes.fromhex('48817e10') or new_gate[:3] != bytes.fromhex('4881fa'):
        raise ValueError('input size instruction mismatch')
    old_length = struct.unpack_from('<I', old_gate, 4)[0]
    new_length = struct.unpack_from('<I', new_gate, 3)[0]
    if old_length != new_length:
        raise ValueError('cross-release input sizes differ')
    return {'legacy_release': '94', 'legacy_sha256': LEGACY_SHA256,
            'legacy_key_va': hex(0x574f0c0), 'target_key_va': hex(0x64c0750),
            'legacy_key_file_offset': hex(file_offset(sec, 0x574f0c0, 20)[1]),
            'target_key_file_offset': hex(file_offset(target_sec, 0x64c0750, 20)[1]),
            'key_hex': legacy_address.hex(), 'legacy_relocations': rows,
            'legacy_compression_call_va': hex(0x4e9d3bd), 'legacy_call_hex': old_call.hex(),
            'legacy_compression_call_file_offset': hex(file_offset(sec, 0x4e9d3bd, len(old_call), True)[1]),
            'legacy_size_va': hex(0x4e9d2aa), 'target_size_va': hex(0x5c1665d),
            'legacy_size_file_offset': hex(file_offset(sec, 0x4e9d2aa, len(old_gate), True)[1]),
            'target_size_file_offset': hex(file_offset(target_sec, 0x5c1665d, len(new_gate), True)[1]),
            'legacy_size_instruction': old_gate.hex(), 'target_size_instruction': new_gate.hex(),
            'matching_length': new_length}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--legacy', type=Path, help='optional digest-checked node 94 for historical key cross-check')
    args = parser.parse_args()
    data = verified_bytes(ROOT / TARGET, TARGET_SHA256)
    legacy_result = check_legacy(args.legacy, data) if args.legacy else None
    summary = generate(data, args.out)
    if legacy_result is not None:
        summary['legacy_cross_check'] = legacy_result
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('re21_callframe_input115: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
