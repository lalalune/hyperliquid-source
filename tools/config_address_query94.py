#!/usr/bin/env python3
"""Retain byte-checked, digest-pinned static evidence for one #94 callback path."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

ARTIFACT = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280

# Each window was selected by inspecting the authenticated target. Exact patterns
# avoid a dependency on any disassembler's formatting or instruction discovery.
WINDOWS = [
    ('prior_route_binding', 0x27abbab, '488d15da4bc4fd4889e7488d742420b912000000e8fc1b7cff'),
    ('prior_constructor_binding', 0x1f6d81b, '0f104424080f11004889442410488d0531417203488944241848c7442408000000004c8d4424084889df4c89e64c89fa4c89f1ff15fc308003'),
    ('wrapper_forward_refcount', 0x1f9a993, '488d742408488d4c24104889c2e88b4efdfff049ff0e750b488d7c2408ff158a897d03'),
    ('wrapper_unwind_refcount', 0x1f9a9c1, '4889c3f049ff0e750b488d7c2408ff156b897d034889dfe833576c03'),
    ('input_split', 0x1f6f865, '48b901000000000000804939cd0f94c24885c0400f94c64008d674154939cd0f85a300000031c0b901000000e9b1000000807d007b0f858d000000'),
    ('object_wrapper_call', 0x1f6f8bc, '488dbc2490000000488d742440e8a2cfbbff80bc2490000000010f85db010000'),
    ('positional_empty_array', 0x1f6f92d, '4883f80275110fb74d00663b0d68304bfe0f8490010000'),
    ('positional_call_and_tag', 0x1f6f957, '4889e7488db424d0000000e8598cefff4c8b24244983fc030f856b010000'),
    ('lookup_key_transfer', 0x1f6f975, '8b442418894424500f104424080f294424404883c310488d7424404889dfe808b3840041bc03000000'),
    ('object_success_transfer', 0x1f6fab7, '8b8424a1000000894424180f108424910000000f11442408e9a1feffff'),
    ('callback_result_byte', 0x1f6f9c6, '48c78424e0000000000000004c89a424f0000000889c24f8000000888424f9000000'),
    ('callback_result_builder', 0x1f6fa29, '488d7c24404889e6488d9424e0000000488b8c24c8000000e89ab05500488b442460498947200f10442450410f114710488b442468498947280fb6442478418847380f10442440410f1107488b84248800000049894730'),
    ('callback_positional_error', 0x1f6fb07, '488d3d274f45fe488d15274f45fe4c8d442440be07000000b9070000004531c9ff153b0e8003'),
    ('callback_unwind', 0x1f6fbd0, '488bbc2488000000e8f38c04004584ff740c498b3e498b7608e8428704004889dfe81a056f03ff152ce57f03'),
    ('object_wrapper_call_and_depth', 0x1b2c8ad, 'c644245080488d742408e814721700803b007559'),
    ('object_wrapper_trailing_mask', 0x1b2c8d8, '48ffc148be002600000100000066662e0f1f8400000000000fb67c0aff4883ff20773f480fa3fe7339'),
    ('object_wrapper_trailing_error', 0x1b2c93a, '48c744245816000000488d7c2408488d742458e82e12000048894308b001ebbe'),
    ('object_token_depth', 0x1ca3b49, '83ff5b0f84a502000083ff7b0f857e050000410fb6564884d20f84f4050000feca418856480f8428050000'),
    ('object_key_match', 0x1ca3c83, '48837c241007751d418b0424330575bc74fe418b4c2403330d6dbc74fe09c10f8488000000'),
    ('object_unknown_field', 0x1ca3cf0, '4883fe3a0f85d20300004885c00f844c040000498946284c89f7e851a0e8ff4885c00f8562030000'),
    ('object_duplicate_branch', 0x1ca3d30, 'f6442458010f85de030000'),
    ('object_value_decode', 0x1ca3d83, '4883fe3a0f853f0300004885c00f84b9030000498946284889e74c89f6e80b33b600803c24010f84e3020000'),
    ('object_mark_seen', 0x1ca3deb, 'b0014889442458e921ffffff'),
    ('object_missing_branch', 0x1ca3e52, 'f6442458010f84df010000'),
    ('object_missing_template', 0x1ca403c, '488d05473a71fe488944244848c744245007000000488d44244848890424488d052f3351004889442408488d3d86b853fe4889e6e86b6e2100'),
    ('object_error_codes', 0x1ca409c, '48c7042418000000e990faffff400fb6c783f87d750d48c7042415000000e900ffffff48c7042411000000e9f3feffff48c7042406000000e9e6feffff'),
    ('object_comma_error', 0x1ca40f2, '48c7042408000000e9c0feffff'),
    ('object_duplicate_template', 0x1ca4119, '488d056a3971fe488944244848c744245007000000488d44244848890424488d05523251004889442408488d3d8bce53fee91effffff'),
    ('array_initial_token', 0x1e685eb, '4d85ff0f844d0200004989f6410fb6042483f82c742283f85b741d83f85d0f85c300000049c7060100000049c7460800000000e91e020000'),
    ('array_depth_and_call', 0x1e68678, 'c68424900000008048c784249800000000000000c68424a000000000488dbc24a8000000488d742448e81a22ccff0fb68424a80000003c027568'),
    ('array_success_tag', 0x1e68805, '48c744241003000000'),
    ('array_no_more_params', 0x1e68841, 'bf0e000000ff158c5790034885c00f848a00000048b96520706172616d734889480648b94e6f206d6f726520488908'),
    ('array_error_call', 0x1e68887, '488d15997155fe4c8d442448b90e0000004889dfbea680ffffe8fb4da600'),
    ('value_whitespace_and_empty', 0x1b2a8e1, '49b800260000010000000f1f440000440fb60c024983f92277274d0fa3c8731b48ffc0488946284839c175e34889c848894650c60702e9ee000000'),
    ('value_token_and_decoder', 0x1b2a91c, '4983f922740c4183f95b74064183f97b75084989ff40b501eb054989ff31ed48894650488d7c24184989f4e864c7cd00807c2418017524'),
    ('lookup_lock', 0x27bacd0, '4c8db378050000488b837805000089c183e108c1e9034883f8f00f93c208ca74124c89f731f6b900ca9a3bff15e748fb02eb0b488d4810f0490fb10e75e3'),
    ('lookup_tree_root', 0x27bad94, '488b83d04900004885c0448b6424080f84d40000004c89742438488b8bd849000048894c24484c8b35c736fb02'),
    ('lookup_tree_keys', 0x27badc1, '488db0680100000fb7884602000048894424704c8d68e048894c24688d048d00000000488d1c80'),
    ('lookup_compare_key', 0x27badf0, '4885db743b4c8d6614ba140000004c89ff41ffd648984885c00f98c10f9fc028c84983c52048ffc54883c3ec4c89e63c0174cd0fb6c085c07436eb09'),
    ('lookup_child', 0x27bae30, '488b6c2468448b642408488b4424484883e8010f82830100004889442448488b442470488b84e848020000e961ffffff'),
    ('lookup_found_or_default', 0x27bae60, '4c8b742438448b642408488b1def8afb028b432085c0741ae9690100004531ed488b1dd98afb028b432085c00f85540100004d85ed75034989dd450fb67d1c'),
    ('lookup_release', 0x27bae9f, '48c7c0f0fffffff0490fc1064883e0f24883f8120f8463010000'),
    ('lookup_slow_gate', 0x27baf04, 'f20f10442440f20f58c2660f2e05a2fba4fd776de99d000000'),
    ('lookup_slow_gate_after_wait', 0x27baf71, 'f20f10442440f20f58c2660f2e0535fba4fd7635'),
    ('lookup_name_mask_and_return', 0x27baf85, '4c8b359c39fb02418b465085c00f8592000000410fb6464883f81f7718b900603c800fa3c1730e8b05e6fbfb0285c00f85af0000004489f84883c4785b415c415d415e415f5d'),
    ('lookup_default_once', 0x27bafcc, '4531ed4c8b742438488b1d8589fb028b432085c00f84acfeffff48895c2410488d4424104889442420488d7b20488d0df82ff0024c8d05d92ff002488d542420be01000000ff15a138fb02e976feffff'),
    ('lookup_name_once', 0x27bb02a, '4c8974241048895c2420498d7e50488d0dd101ec024c8d05f201ec02488d542420be01000000ff156238fb02410fb6464883f81f0f863effffffe951ffffff'),
    ('lookup_secondary_once', 0x27bb069, '488d0510fbfb02488944241048895c2420488d3d17fbfb02488d0de0eeea024c8d05c1eeea02488d542420be01000000ff151938fb02e916ffffff'),
    ('lookup_unwind_unlock', 0x27bb0a4, '48c7c1f0ffffff4c89f7f0490fc10e4989c64883e1f24883f912752aff153245fb02eb22'),
    ('builder_allocation_and_tag', 0x24cab05, 'bf80000000ff15c8342a034885c00f84d707000048895c247048c744245880000000488944246048c744246800000000837d10037565'),
    ('builder_success_payload_pointer', 0x24cab3b, 'c744244800000000488d5d1048be0000000000000080'),
    ('builder_success_payload_copy', 0x24cabdb, 'c6842450010000010f10030f104b100f1053200f298424000100000f298c24100100000f29942420010000488b433048898424300100004889ac24380100004c89b424e80000004c89b424400100004c89ac2448010000'),
    ('builder_serializer_and_result', 0x24cac3c, '488dbc2400010000488d742478e872bd4a004989c54885c00f84f6000000'),
    ('builder_success_output', 0x24cad50, '488b442468498947200f10442458410f114710488b4424400f10008b442448418947288b4424084189472c41c6473800410f110749c7473000000000e9c4030000'),
    ('builder_cleanup', 0x24cb134, '488d7c2450e8c2c20300488b7424584885f6740d488b7c246031d2ff15bb2e2a03'),
    ('builder_return', 0x24cb22f, '4c89f84881c4780100005b415c415d415e415f5dc3'),
    ('builder_allocation_failure', 0x24cb2f0, 'bf01000000be80000000ff15b82c2a03e9be000000'),
    ('serializer_header', 0x29769cd, '488d354ef6a7fdba010000004889dfe81f63c3ff4885c00f85d0010000c64424080048895c241041807e50017574488d156704a8fdb9070000004889dfe8e1e4f4ff4885c00f85a2010000'),
    ('serializer_version', 0x2976a35, '488d150fbda4fdb9030000004889dfe8a7e4f4ff4885c00f8568010000'),
    ('serializer_id', 0x2976a6f, 'c644240902488d15d9f7a7fdb9020000004889dfe868e4f4ff4885c00f8529010000488d359af5a7fdba010000004889dfe85b62c3ff4885c00f850c010000'),
    ('serializer_result_field', 0x2976ac7, '41833e037564488d354ff5a7fdba010000004889dfe81f62c3ff4885c00f85d0000000488d157f03a8fdb9060000004889dfe8f2e3f4ff4885c00f85b3000000488d3524f5a7fdba010000004889dfe8e561c3ff4885c00f859600000041807e0800753b4d8b7610eb39'),
    ('serializer_boolean', 0x2976b66, '4983c609410fb6064889c24883f205488d0d843389fd488d3599f4a7fd4885c0480f45f14889dfe86e61c3ff4885c07523488d357cf4a7fdba010000004889dfe85561c3ff4885c0750a'),
    ('registration_helper_and_branch', 0x2a484dd, '4d89c64989cf4989d44889fb4889f7ff15aeb0d2024889e74889c64c89e24c89f9e8cd050000488b0c244885c90f84d9000000488b542408488b442410488b7c2418'),
    ('registration_vtable_copy', 0x2a4851f, '498b76104889742410410f10060f290424488b304c8b40084d89c14921f9'),
    ('registration_probe_branches', 0x2a4853d, 'f3420f6f040e66440fd7d04585d20f846e010000f3450fbcd24d01ca4d21c2460fb60c164584c90f897b010000'),
    ('registration_entry_write', 0x2a48575, '42883c1642887c1e1049f7da4b8d3c924180e10148894cfed8488954fee0488d0cfe4883c1e80f2804240f1144fee8488b542410488954fef8f30f6f4010410fb6d1660f6eca660fc60dbcae7bfd02660ffbc1f30f7f401048894b0848c70303000000'),
    ('registration_zero_entry_copy', 0x2a485e9, '4d85ff790d31ff4c89feff15bf59d2020f0b74174c89ffff15d259d2024885c00f84ee0000004989c5eb0641bd010000004c89ef4c89e64c89faff15b759d20248c703000000004c897b084c896b104c897b18'),
    ('registration_zero_entry_cleanup_jump', 0x2a4863c, '498b064983c608488d0deea09dfd486304814801c8ffe0'),
    ('registration_unwind', 0x2a48707, '4889c34c89f7e8be0100004889dfe8f679c102ff15085ad202'),
    ('writer_size_check', 0x25acd0b, '4885d20f84840100004889d3488934244c8b37498b7610488d0416493946180f8345010000'),
    ('writer_copy_or_grow', 0x25ace75, '498b064829f04839c37729490376084889f7488b34244889daff154c111c0349015e1031c0'),
    ('writer_growth', 0x25acea9, 'b90100000041b8010000004c89f74889dae8e1954900498b7610ebbb'),
    ('writer_unwind', 0x25acef2, 'be180000004c89ef31d2ff150e111c034889dfe806320b03'),
]

# These are unwind ranges, not a claim that source function boundaries or the
# complete instruction control-flow graph have been recovered.
SELECTED = [
    ('wrapper', 0x1f9a950, 0x1f9a9e3),
    ('callback', 0x1f6f830, 0x1f6fbfc),
    ('object_wrapper', 0x1b2c870, 0x1b2c97e),
    ('object_parser', 0x1ca3ad0, 0x1ca41f4),
    ('positional_adapter', 0x1e685c0, 0x1e68930),
    ('value_adapter', 0x1b2a8c0, 0x1b2aa7b),
    ('keyed_lookup', 0x27baca0, 0x27bb100),
    ('response_builder', 0x24caae0, 0x24cb5cd),
    ('response_serializer', 0x29769c0, 0x2976bca),
    ('registration_entry', 0x2a484d0, 0x2a48720),
    ('response_writer', 0x25acd00, 0x25acf0a),
]

# Relative control transfers are decoded directly and checked against the
# reviewed destination. A conditional entry has two successors: the recorded
# target and the following instruction. Calls have a normal fall-through too.
TRANSFERS = [
    ('prior_route_to_constructor', 0x27abbbf, 0x1f6d7c0),
    ('wrapper_to_callback', 0x1f9a9a0, 0x1f6f830),
    ('object_input', 0x1f6f87f, 0x1f6f896),
    ('not_object', 0x1f6f89a, 0x1f6f92d),
    ('object_to_wrapper', 0x1f6f8c9, 0x1b2c870),
    ('object_non_error', 0x1f6f8d6, 0x1f6fab7),
    ('empty_brackets', 0x1f6f93e, 0x1f6fad4),
    ('callback_to_positional', 0x1f6f962, 0x1e685c0),
    ('positional_non_success', 0x1f6f96f, 0x1f6fae0),
    ('callback_to_lookup', 0x1f6f993, 0x27baca0),
    ('callback_to_result_builder', 0x1f6fa41, 0x24caae0),
    ('object_to_lookup_path', 0x1f6facf, 0x1f6f975),
    ('object_wrapper_to_parser', 0x1b2c8b7, 0x1ca3ad0),
    ('trailing_non_space', 0x1b2c8f9, 0x1b2c93a),
    ('trailing_not_masked', 0x1b2c8ff, 0x1b2c93a),
    ('array_shape', 0x1ca3b4c, 0x1ca3df7),
    ('depth_depleted', 0x1ca3b6e, 0x1ca409c),
    ('matched_address_key', 0x1ca3ca2, 0x1ca3d30),
    ('unknown_key_to_helper', 0x1ca3d0a, 0x1b2dd60),
    ('duplicate_key', 0x1ca3d35, 0x1ca4119),
    ('colon_missing', 0x1ca3d87, 0x1ca40cc),
    ('object_value_to_decoder', 0x1ca3da0, 0x28070b0),
    ('value_decoder_error', 0x1ca3da9, 0x1ca4092),
    ('required_address_missing', 0x1ca3e57, 0x1ca403c),
    ('empty_positional', 0x1e685ee, 0x1e68841),
    ('invalid_positional_prefix', 0x1e68609, 0x1e686d2),
    ('positional_to_value', 0x1e686a1, 0x1b2a8c0),
    ('positional_value_present', 0x1e686b0, 0x1e6871a),
    ('positional_error_result', 0x1e688a0, 0x28cd6a0),
    ('value_to_decoder', 0x1b2a947, 0x28070b0),
    ('empty_tree', 0x27bada3, 0x27bae7d),
    ('key_equal', 0x27bae28, 0x27bae60),
    ('tree_height_exhausted', 0x27bae43, 0x27bafcc),
    ('default_needs_once', 0x27bae8c, 0x27bafe6),
    ('found_row', 0x27bae95, 0x27bae9a),
    ('slow_timing_gate', 0x27baf16, 0x27baf85),
    ('slow_timing_gate_after_wait', 0x27baf83, 0x27bafba),
    ('name_needs_once', 0x27baf92, 0x27bb02a),
    ('name_above_mask_range', 0x27bafa0, 0x27bafba),
    ('name_mask_clear', 0x27bafaa, 0x27bafba),
    ('secondary_needs_once', 0x27bafb4, 0x27bb069),
    ('unlock_unwind', 0x27bb0be, 0x27bb0ea),
    ('builder_allocation_failure', 0x24cab13, 0x24cb2f0),
    ('builder_non_success_tag', 0x24cab39, 0x24caba0),
    ('builder_to_serializer', 0x24cac49, 0x29769c0),
    ('builder_serialized_ok', 0x24cac54, 0x24cad50),
    ('serializer_non_success_tag', 0x2976acb, 0x2976b31),
    ('serializer_inline_boolean', 0x2976b29, 0x2976b66),
    ('serializer_boolean_to_writer', 0x2976b8d, 0x25acd00),
    ('serializer_writer_error', 0x2976b95, 0x2976bba),
    ('registration_to_entry_helper', 0x2a484fe, 0x2a48ad0),
    ('registration_zero_entry_result', 0x2a4850a, 0x2a485e9),
    ('registration_probe_again', 0x2a4854b, 0x2a486bf),
    ('registration_slot_control', 0x2a48564, 0x2a486e5),
    ('registration_allocation_failure', 0x2a48609, 0x2a486fd),
    ('registration_unwind_cleanup', 0x2a4870d, 0x2a488d0),
    ('writer_nonempty_capacity', 0x25acd2a, 0x25ace75),
    ('writer_needs_growth', 0x25ace7e, 0x25acea9),
    ('writer_grow', 0x25aceba, 0x2a464a0),
]

# RIP displacements are read from the exact selected instruction patterns.
RIPS = [
    ('method_literal', 0x27abbab, '488d15', 0x3f078c),
    ('constructor_vtable', 0x1f6d828, '488d05', 0x5691960),
    ('constructor_registry_slot', 0x1f6d84e, 'ff15', 0x5770950),
    ('empty_brackets_literal', 0x1f6f937, '663b0d', 0x4229a6),
    ('address_head_literal', 0x1ca3c8f, '3305', 0x3ef90a),
    ('address_tail_literal', 0x1ca3c9a, '330d', 0x3ef90d),
    ('missing_field_name', 0x1ca403c, '488d05', 0x3b7a8a),
    ('missing_field_format', 0x1ca4066, '488d3d', 0x1df8f3),
    ('duplicate_field_name', 0x1ca4119, '488d05', 0x3b7a8a),
    ('duplicate_field_format', 0x1ca4143, '488d3d', 0x1e0fd5),
    ('key_compare_slot', 0x27badba, '4c8b35', 0x576e488),
    ('default_cell_slot_found', 0x27bae6a, '488b1d', 0x5773960),
    ('default_cell_slot_empty', 0x27bae80, '488b1d', 0x5773960),
    ('slow_threshold', 0x27baf0e, '660f2e05', 0x20aab8),
    ('slow_threshold_after_wait', 0x27baf7b, '660f2e05', 0x20aab8),
    ('name_cell_slot', 0x27baf85, '4c8b35', 0x576e928),
    ('secondary_once_state', 0x27bafac, '8b05', 0x577ab98),
    ('serializer_jsonrpc_field', 0x29769fb, '488d15', 0x3f6e69),
    ('serializer_version', 0x2976a35, '488d15', 0x3c274b),
    ('serializer_id_field', 0x2976a74, '488d15', 0x3f6254),
    ('serializer_result_field', 0x2976aea, '488d15', 0x3f6e70),
    ('serializer_true', 0x2976b75, '488d0d', 0x209f00),
    ('serializer_false', 0x2976b7c, '488d35', 0x3f601c),
    ('writer_copy_slot', 0x25ace8e, 'ff15', 0x576dfe0),
]

RELOC_EXPECTED = {
    0x5691960: (8, 0, 0x1f9b760),
    0x5691978: (8, 0, 0x1f9a950),
    0x5691980: (8, 0, 0x1f6f830),
    0x5691988: (8, 0, 0x1f6f830),
    0x576e488: (6, 12, 0),
    0x576dfe0: (6, 6, 0),
    0x576e8b8: (8, 0, 0x4ee3b20),
    0x576e928: (8, 0, 0x577b288),
    0x576f5e8: (8, 0, 0x4e0b770),
    0x576f5f8: (8, 0, 0x4e0be20),
    0x5770950: (8, 0, 0x2a484d0),
    0x5770960: (8, 0, 0x2a48e20),
    0x5770968: (8, 0, 0x2a48c80),
    0x5773340: (8, 0, 0x4762980),
    0x5773960: (8, 0, 0x5786388),
}
DESCRIPTOR_BASE = 0x5668288


def checked_digest(data):
    if len(data) != SIZE:
        raise ValueError('node #94 size or SHA-256 mismatch')
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise ValueError('node #94 size or SHA-256 mismatch')
    return digest


def va_offset(secs, address, size):
    if address < 0 or size <= 0:
        raise ValueError('invalid address or size')
    found = [s for s in secs if s['type'] != 8 and s['flags'] & 2
             and s['address'] <= address and address + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('address range is not in one file-backed allocated section')
    section = found[0]
    return section['offset'] + address - section['address'], section['name']


def at(data, secs, address, size):
    offset, _ = va_offset(secs, address, size)
    return data[offset:offset + size]


def read_u64(data, secs, address):
    return struct.unpack('<Q', at(data, secs, address, 8))[0]


def rel_target(data, secs, address):
    first = at(data, secs, address, 1)[0]
    if first in (0xe8, 0xe9):
        raw = at(data, secs, address, 5)
        length, displacement, kind = 5, struct.unpack('<i', raw[1:])[0], ('call' if first == 0xe8 else 'jump')
    elif 0x70 <= first <= 0x7f:
        raw = at(data, secs, address, 2)
        length, displacement, kind = 2, struct.unpack('<b', raw[1:])[0], 'conditional'
    elif first == 0x0f and 0x80 <= at(data, secs, address + 1, 1)[0] <= 0x8f:
        raw = at(data, secs, address, 6)
        length, displacement, kind = 6, struct.unpack('<i', raw[2:])[0], 'conditional'
    else:
        raise ValueError(f'unsupported transfer opcode at {address:#x}')
    return raw, kind, address + length + displacement


def rip_target(data, secs, address, opcode):
    prefix = bytes.fromhex(opcode)
    raw = at(data, secs, address, len(prefix) + 4)
    if not raw.startswith(prefix):
        raise ValueError(f'RIP opcode mismatch at {address:#x}')
    return raw, address + len(raw) + struct.unpack('<i', raw[-4:])[0]


def relocation_map(data, secs, requested):
    tables = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(tables) != 1 or tables[0]['size'] % 24:
        raise ValueError('invalid relocation section')
    section = tables[0]
    result = {}
    for pos in range(section['offset'], section['offset'] + section['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', data, pos)
        if target in requested:
            if target in result:
                raise ValueError('duplicate relocation for selected slot')
            result[target] = (info & 0xffffffff, info >> 32, addend)
    if set(result) != set(requested):
        raise ValueError('selected relocation absent')
    return result


def dynsym_name(data, secs, index):
    by_name = {s['name']: s for s in secs}
    symbols, strings = by_name['.dynsym'], by_name['.dynstr']
    if symbols['type'] == 8 or strings['type'] == 8 or symbols['size'] % 24 or index >= symbols['size'] // 24:
        raise ValueError('invalid symbol table index')
    name_offset = struct.unpack_from('<I', data, symbols['offset'] + 24 * index)[0]
    if name_offset >= strings['size']:
        raise ValueError('symbol name outside string table')
    start = strings['offset'] + name_offset
    end = data.find(b'\0', start, strings['offset'] + strings['size'])
    if end < 0:
        raise ValueError('unterminated symbol')
    return data[start:end].decode('ascii')


def name_selected(value, mask):
    if not 0 <= value <= 255:
        raise ValueError('expected an unsigned byte')
    return value <= 31 and bool(mask & (1 << value))


def key_matches(candidate, expected):
    """Model the two overlapping four-byte XOR comparisons at the checked site."""
    if len(expected) != 7:
        raise ValueError('expected key literal must be seven bytes')
    if len(candidate) != 7:
        return False
    first = int.from_bytes(candidate[:4], 'little') ^ int.from_bytes(expected[:4], 'little')
    last = int.from_bytes(candidate[3:], 'little') ^ int.from_bytes(expected[3:], 'little')
    return first | last == 0


def boolean_selection(value):
    """Model the checked zero-test, conditional pointer and XOR length."""
    if not 0 <= value <= 255:
        raise ValueError('expected an unsigned byte')
    return ('true' if value else 'false', value ^ 5)


def exceeds_threshold(value, threshold):
    """Model the ordered greater-than test at the two checked branch sites."""
    return value > threshold


def collect(data):
    """Build outputs from already-authenticated bytes; also used for corruption controls."""
    secs = sections(data)
    win = []
    for label, va, expected in WINDOWS:
        raw = at(data, secs, va, len(bytes.fromhex(expected)))
        if raw.hex() != expected:
            raise ValueError(f'window mismatch: {label}')
        offset, section = va_offset(secs, va, len(raw))
        win.append((label, hex(va), hex(offset), section, len(raw), raw.hex()))

    edges = []
    for label, va, expected in TRANSFERS:
        raw, kind, target = rel_target(data, secs, va)
        if target != expected:
            raise ValueError(f'transfer destination mismatch: {label}')
        if not any(start <= va and va + len(raw) <= start + len(bytes.fromhex(pattern))
                   for _, start, pattern in WINDOWS):
            raise ValueError(f'transfer lacks a byte-checked window: {label}')
        continuation = '' if kind == 'jump' else hex(va + len(raw))
        edges.append((label, hex(va), kind, raw.hex(), hex(target), continuation))

    rip_rows = []
    for label, va, opcode, expected in RIPS:
        raw, target = rip_target(data, secs, va, opcode)
        if target != expected:
            raise ValueError(f'RIP target mismatch: {label}')
        if not any(start <= va and va + len(raw) <= start + len(bytes.fromhex(pattern))
                   for _, start, pattern in WINDOWS):
            raise ValueError(f'RIP instruction lacks byte-checked window: {label}')
        rip_rows.append({'label': label, 'instruction_va': hex(va), 'bytes': raw.hex(), 'target_va': hex(target)})

    _, fdes = eh_frame_records(data, secs)
    selected = []
    for label, start, end in SELECTED:
        matches = [f for f in fdes if f['start'] == start]
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError(f'FDE mismatch: {label}')
        fde = matches[0]
        raw = at(data, secs, start, end - start)
        offset, section = va_offset(secs, start, len(raw))
        selected.append({'label': label, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                         'fde_va': hex(fde['fde']), 'lsda_va': hex(fde['lsda']) if fde['lsda'] else None,
                         'file_offset': hex(offset), 'section': section, 'size': len(raw),
                         'body_sha256': hashlib.sha256(raw).hexdigest(), 'body_bytes_hex': raw.hex()})

    mask = struct.unpack('<I', at(data, secs, 0x27bafa3, 4))[0]
    values = [i for i in range(32) if name_selected(i, mask)] + [32]
    slots = {DESCRIPTOR_BASE + 16 * i for i in values}
    relocs = relocation_map(data, secs, set(RELOC_EXPECTED) | slots)
    for address, expected in RELOC_EXPECTED.items():
        if relocs[address] != expected:
            raise ValueError(f'relocation mismatch at {address:#x}')
    names = []
    for i in values:
        slot = DESCRIPTOR_BASE + 16 * i
        typ, symbol, target = relocs[slot]
        if typ != 8 or symbol != 0:
            raise ValueError('unexpected descriptor relocation')
        length = read_u64(data, secs, slot + 8)
        if length > 128:
            raise ValueError('invalid descriptor length')
        name = at(data, secs, target, length).decode('ascii')
        names.append({'discriminant': i, 'descriptor_va': hex(slot), 'literal_va': hex(target),
                      'length': length, 'name': name, 'mask_selected': name_selected(i, mask)})
    compare_name = dynsym_name(data, secs, relocs[0x576e488][1])
    if compare_name != 'memcmp':
        raise ValueError('unexpected comparison symbol')
    copy_name = dynsym_name(data, secs, relocs[0x576dfe0][1])
    if copy_name != 'memcpy':
        raise ValueError('unexpected copy symbol')
    literals = {
        'method': at(data, secs, 0x3f078c, 18).decode('ascii'),
        'field': at(data, secs, 0x3ef90a, 7).decode('ascii'),
        'diagnostic_field': at(data, secs, 0x3b7a8a, 7).decode('ascii'),
        'empty_array': at(data, secs, 0x4229a6, 2).decode('ascii'),
        'threshold_f64': struct.unpack('<d', at(data, secs, 0x20aab8, 8))[0],
        'whitespace_mask_u64': hex(struct.unpack('<Q', at(data, secs, 0x1b2c8dd, 8))[0]),
        'no_more_params': (at(data, secs, 0x1e68865, 8) + at(data, secs, 0x1e68857, 8)[2:]).decode('ascii'),
        'invalid_params_text': at(data, secs, 0x3bfa27, 14).decode('ascii'),
        'positional_error_code': struct.unpack('<i', at(data, secs, 0x1e6889c, 4))[0],
        'jsonrpc_field': at(data, secs, 0x3f6e69, 7).decode('ascii'),
        'jsonrpc_version': at(data, secs, 0x3c274b, 3).decode('ascii'),
        'id_field': at(data, secs, 0x3f6254, 2).decode('ascii'),
        'result_field': at(data, secs, 0x3f6e70, 6).decode('ascii'),
        'bool_false': at(data, secs, 0x3f601c, 5).decode('ascii'),
        'bool_true': at(data, secs, 0x209f00, 4).decode('ascii'),
    }
    if literals != {'method': 'eth_usingBigBlocks', 'field': 'address', 'diagnostic_field': 'address', 'empty_array': '[]',
                    'threshold_f64': 3.0, 'whitespace_mask_u64': '0x100002600',
                    'no_more_params': 'No more params', 'invalid_params_text': 'Invalid params',
                    'positional_error_code': -32602, 'jsonrpc_field': 'jsonrpc',
                    'jsonrpc_version': '2.0', 'id_field': 'id', 'result_field': 'result',
                    'bool_false': 'false', 'bool_true': 'true'}:
        raise ValueError('literal or constant mismatch')
    field = literals['field'].encode('ascii')
    mutations = [field] + [field[:i] + bytes([field[i] ^ 1]) + field[i + 1:] for i in range(len(field))]
    metadata = {
        'artifact': 'artifacts/node/94/hl-node', 'sha256': SHA256,
        'coordinate_system': 'ELF linked virtual address; file offsets are separate; FDE end exclusive',
        'scope': 'Selected exact windows and unwind extents only; neither complete CFG nor runtime behavior.',
        'fdes': selected, 'rip_targets': rip_rows,
        'relocations': [{'slot_va': hex(a), 'type': relocs[a][0], 'symbol_index': relocs[a][1],
                         'addend': hex(relocs[a][2])} for a in sorted(RELOC_EXPECTED)],
        'vtable_size': read_u64(data, secs, 0x5691968),
        'vtable_alignment': read_u64(data, secs, 0x5691970),
        'comparison_dynamic_symbol': compare_name, 'copy_dynamic_symbol': copy_name,
        'literals_and_constants': literals, 'name_mask_u32': hex(mask), 'name_descriptors': names,
        'key_comparison_controls': [{'candidate_hex': item.hex(), 'matches': key_matches(item, field)}
                                    for item in mutations],
        'boolean_selection_controls': [{'byte': i, 'selected_literal': boolean_selection(i)[0],
                                        'requested_length': boolean_selection(i)[1]} for i in (0, 1)],
        'timing_controls': [{'candidate': label, 'enters_name_check': exceeds_threshold(value, literals['threshold_f64'])}
                            for label, value in [('below', 2.0), ('equal', 3.0), ('above', 4.0),
                                                 ('unordered_nan', float('nan'))]],
        'window_count': len(win), 'direct_transfer_count': len(edges), 'selected_fde_count': len(selected),
    }
    if metadata['vtable_size'] != 8 or metadata['vtable_alignment'] != 8:
        raise ValueError('unexpected vtable layout')
    return metadata, win, edges


def tsv(headers, rows):
    output = io.StringIO(newline='')
    writer = csv.writer(output, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue().encode('utf-8')


def generate(data, out):
    checked_digest(data)
    metadata, windows, edges = collect(data)
    files = {
        'path.json': (json.dumps(metadata, indent=2, ensure_ascii=True) + '\n').encode(),
        'windows.tsv': tsv(['label', 'start_va', 'file_offset', 'section', 'size', 'bytes_hex'], windows),
        'transfers.tsv': tsv(['label', 'instruction_va', 'kind', 'bytes_hex', 'target_va', 'fallthrough_va'], edges),
    }
    out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (out / name).write_bytes(files[name])
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(ARTIFACT.read_bytes(), args.out)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        print(f'config_address_query94: {exc}', file=sys.stderr)
        raise SystemExit(1)
