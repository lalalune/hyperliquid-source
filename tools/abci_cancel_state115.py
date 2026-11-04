#!/usr/bin/env python3
"""Extract selected node-115 scheduled-cancel state evidence, without execution."""

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
TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OLD_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
PATH_SUFFIX = b'l1/src/abci/state.rs'

# FDE ends are exclusive. An FDE range is not asserted to be a source boundary.
FUNCTIONS = [
    ('json_container', 0x3c741e0, 0x3c748a2),
    ('json_pairs', 0x37b12c0, 0x37b1490),
    ('json_pair', 0x3f6c790, 0x3f6cb70),
    ('json_object', 0x374f340, 0x374f5a2),
    ('json_key', 0x421a240, 0x421a320),
    ('json_value_adapter', 0x3f4b160, 0x3f4b217),
    ('json_value', 0x40758a0, 0x4075fb6),
    ('json_optional', 0x45173d0, 0x4517519),
    ('binary_container', 0x336ff60, 0x3370779),
    ('binary_map', 0x373e700, 0x373eb18),
    ('binary_pairs', 0x3769fe0, 0x376a29e),
    ('binary_pair', 0x31ec530, 0x31ed0e3),
    ('binary_value', 0x31c9130, 0x31ca57e),
    ('map_finish', 0x3cbc860, 0x3cbca25),
    ('small_sort', 0x4371920, 0x4371a50),
    ('large_sort_adapter', 0x36feb50, 0x36fec4e),
    ('compact_map_clone', 0x5844190, 0x584452b),
    ('tree_map_clone', 0x522ea30, 0x522eea9),
    ('snapshot_map', 0x5673cd0, 0x5673dfa),
    ('snapshot_entries', 0x52d03a0, 0x52d0cb0),
    ('snapshot_value_binary', 0x4d933e0, 0x4d935e6),
    ('snapshot_value_named', 0x4d935f0, 0x4d9374f),
    ('root_value_visitor', 0x3d38b00, 0x3d38b65),
    ('root_value_constructor', 0x3d38ab0, 0x3d38afd),
    ('root_option_visitor', 0x4513370, 0x45133e2),
]

# Selected, unmasked bytes; ctx_ and root_map_ are connecting context in
# earlier selected ranges, not new ownership of those functions.
WINDOWS = [
    ('ctx_json_return_pointer', 0x3efb0ac, '4889bc2490000000'),
    ('ctx_json_init_head', 0x3efb0b4, '49bd0000000000000080'),
    ('ctx_json_init_field', 0x3efb112, '498d450148898424b007000048c7842480310000020000004c89ac245807000048898424880100004889842438010000'),
    ('ctx_json_duplicate', 0x3efc235, '488b8424b000000048398424380100000f85fbad0000'),
    ('ctx_json_value', 0x3efdb35, '4883fe3a0f8597a900004885c00f84f2cc000048894528488dbc24f81400004889eee88466d7ff'),
    ('ctx_json_result', 0x3efdb5c, '4c8bac24f81400004c8ba42400150000488bac24b00000004939ed0f84e4520000'),
    ('ctx_json_commit', 0x3efe792, '4c89ac24380100004c89a424400100000f288424e0340000488d8424400100000f11400849bd0000000000000080e96ecbffff'),
    ('ctx_json_missing', 0x3f0a297, '488b8424b000000048398424380100000f85ac020000488d053ea28bfc488984244009000048c784244809000018000000'),
    ('ctx_json_missing_error', 0x3f0a36f, 'e84c8f7e00488b8c24900000004889410848c70102000000'),
    ('ctx_json_continue', 0x3f0a559, '0f108424380100000f108c24480100000f298c24f00600000f298424e0060000'),
    ('ctx_json_result_base', 0x3f0bf23, '4c8bac2490000000'),
    ('ctx_json_output_field', 0x3f0c115, '0f288424e00600000f288c24f0060000410f118588240000410f118d98240000'),
    ('ctx_nested_payload_output', 0x40909d0, '488dbc2488340000'),
    ('ctx_nested_payload_source', 0x4090b4d, '488db42498340000'),
    ('ctx_nested_output_payload', 0x4090d89, '488d7b10'),
    ('ctx_nested_copy_length', 0x4090d95, 'ba98270000'),
    ('ctx_outer_copy_length', 0x404c51a, 'baa8270000'),
    ('ctx_binary_return_pointer', 0x2fd72cb, '4889fb'),
    ('ctx_binary_parent', 0x32cb09c, '400fb6ee0fb743226685c00f84c923000066ffc8668943220f84430700004989fe48899c24a0bf000089ac24a8bf0000488dbc2460400000488db424a0bf0000e87fc1d0ff4c8bbc24604000000f108424684000000f298424a08000000f108424784000000f298424b08000004983ff020f850e010000'),
    ('ctx_binary_parent_copy1', 0x32cb221, '488db42488400000488dbc2420980000ba80270000'),
    ('ctx_binary_parent_remaining', 0x32cb268, '8b8424a8bf000085c00f842005000029c50f8235220000'),
    ('ctx_binary_parent_copy2', 0x32cb797, '488dbc2498100000488db424f8970000baa8270000'),
    ('ctx_binary_parent_finish', 0x32cb7c6, '488db42498100000e995000000'),
    ('ctx_binary_parent_copy3', 0x32cb868, 'baa82700004c89f7'),
    ('ctx_binary_init_head', 0x2fd72ce, '48b80000000000000080'),
    ('ctx_binary_init_field', 0x2fd731c, '488d480148898c24601e000048c78424704600000200000048898424601c000048898c24a001000048898c24c0010000'),
    ('ctx_binary_duplicate_and_call', 0x2fd8b4d, '488b8424b000000048398424c00100000f85e6620000410fb65524488dbc24380b00004c89eee8e8733900'),
    ('ctx_binary_result', 0x2fd8b78, '8b8424380b0000488d8c24400b00000f10010f1049100f298424800600000f298c249006000083f8010f84f2320000'),
    ('ctx_binary_commit', 0x2fd9d2d, '0f288424800600000f288c24900600000f298c24d00100000f298424c0010000e98edaffff'),
    ('ctx_binary_missing', 0x2fe2629, '488b8424b000000048398424c00100000f8557010000488d05a3357bfd488984240803000048c784241003000018000000'),
    ('ctx_binary_missing_error', 0x2fe26ff, 'e83c400600488d8424400b00000f10000f1048100f114b180f11430848c70302000000'),
    ('ctx_binary_continue', 0x2fe2796, '0f288424c00100000f288c24d00100000f298c24d00a00000f298424c00a0000'),
    ('ctx_binary_output_field', 0x2fe480a, '0f288424c00a00000f288c24d00a00000f1183882400000f118b98240000'),
    ('ctx_materialize_registers', 0x3c2e8a7, '4989f64889fb'),
    ('ctx_materialize_field', 0x3c2ed5e, '498d86882400000f1038440f104010498d86a8240000440f1008440f105010440f1058200f1183283d00000f11a3183d00000f119b083d00000f1193f83c00000f118be83c00000f11b3983f00000f11ab883f00000f11bba83f0000440f1183b83f0000'),
    ('ctx_clone_registers', 0x55ea09b, '4989d64989f74989fd'),
    ('ctx_clone_marker', 0x55ea0b8, '48bb0000000000000080'),
    ('ctx_clone_output_saved', 0x55ea0f8, '4c89ac24b8050000'),
    ('ctx_clone_output_base_a', 0x55eeac1, '4c8bb424b8050000'),
    ('ctx_clone_output_base_b', 0x55eeb0f, '4c8bb424b8050000'),
    ('ctx_clone_marker_live', 0x55f0151, '48bb0000000000000080'),
    ('ctx_clone_switch', 0x55f0460, '49399fa83f000075304983bfc03f0000007464498bb7b03f00004885f60f8421290000498b97b83f0000488dbc24c0050000e899e5c3ffeb56498db7a83f0000488dbc24c0050000e8e33c2500'),
    ('ctx_clone_empty', 0x55f04d7, '48c78424c00500000000000048c78424d005000000000000'),
    ('ctx_clone_stage', 0x55f04ad, '488b8424c00500000f108424c80500000f298424100a0000488b8c24d805000048898c24200a0000eb4b'),
    ('ctx_clone_pack', 0x55f04ef, '488b8424d005000048898424200a0000488b8424c005000048898424100a0000488b8424c805000048898424180a00004889d8498db7c83f000048898424301200000f288424100a00000f11842438120000488b8424200a00004889842448120000'),
    ('ctx_clone_output', 0x55f224d, '0f108424301200000f108c2440120000410f118eb83f0000410f1186a83f0000'),
    ('ctx_expand_input_base', 0x548ce9b, '4989f64889fb'),
    ('ctx_expand_field', 0x548d233, '0f1083a83f00000f108bb83f00000f118424386200000f118c2448620000'),
    ('ctx_expand_out_base', 0x548d83f, '488db42420170000ba384e00004889c74989c6'),
    ('ctx_snapshot_field', 0x548209c, '498d97184b00004889e74c89f6e8221c1f00'),
    ('ctx_hash_capture', 0x4e3455b, '498d87184b00004889842448020000'),
    ('ctx_hash_descriptor', 0x54425f7, '48898c2460010000488d0d025e060148898c2468010000'),
    ('json_dispatch', 0x3c74274, '448d47a54183f8200f87dd000000488d3577fcb3fc4e6304864901f041ffe0'),
    ('json_array_depth', 0x3c74293, '41807e48007519410fb64e4984c90f845e050000fec941884e490f84290500004883f8010f843b05000048ffc849894628488d7c24604c89f6ba01000000e8eacfb3ff'),
    ('json_object_depth', 0x3c743e8, '41807e48007519410fb64e4984c90f8416040000fec941884e490f84d40300004883f8010f84e603000048ffc849894628488d7c24604c89f6ba01000000e815afadff'),
    ('json_pairs_loop', 0x37b1357, '4c89f74c89fee82eb47b00488b442458488b5c24604883f8027437'),
    ('json_pairs_finish', 0x37b13df, '48bb0100000000000080488b44241048898424a00000000f1004240f29842490000000488d7c2458488db42490000000e84cb4500048395c2458'),
    ('json_pairs_duplicate', 0x37b1448, '488d3d99c8fefcbe0d000000e8e71df400'),
    ('json_pair_key_width', 0x3f6c8c7, '488d442450488944241048c744241814000000488d742408e8ac5506004883f801'),
    ('json_pair_value', 0x3f6c9c9, '488d7c2408488d742470e85801feff807c2408010f84b4feffff807c2409010f85d6000000488b742470488d7c2408e8a38e10004c8b7c2410837c2408010f84e4feffff'),
    ('json_object_loop', 0x374f3ec, '4c89f7488d742450e8f7857f00807c2430010f84b8000000807c2431010f85e9000000488b7424504c89f7e824aeac00807c2430010f8495000000488b5c2431418b450189442408410fb74505668944240c8b6c243f440fb76424434c89f7488d742450e80bbd7f00837c2430017460'),
    ('json_object_collect', 0x374f390, '49c1e4204909ec488b4424184b8d0c7f48c1e10448891c088b1424895408080fb7542404668954080c4c89e248c1ea206689540812448964080e0f288424800000000f114408140f1084248c0000000f1144082049ffc74c897c2420'),
    ('json_object_finish', 0x374f4f8, '48bb0100000000000080488b44242048894424700f104424100f29442460488d7c2430488d742460e83bd3560048395c2430742d'),
    ('json_object_duplicate', 0x374f559, '488d3d88e704fdbe0d000000e8d63cfa004c8b7424284989460849891e'),
    ('json_key_width', 0x421a2de, '48894c242848c744243014000000488d7c24204889d64889c2e8841fdaff4883f801'),
    ('json_value_colon', 0x3f4b1df, '4983f83a751a4885c07420488946284889dfe8aaa612004889d84883c4205b'),
    ('json_value_init', 0x4075a4d, '48c74424400000000048c744243800000000'),
    ('json_t_seen', 0x4075a70, '8b44241c8944244c488b4424204889442460b8010000004889442440'),
    ('json_key_t', 0x4075af6, '48837c2410010f85ee000000410fb6073c747566837c2440010f84ac030000'),
    ('json_key_n', 0x4075b70, '3c6e757c48837c2438010f844a030000'),
    ('json_t_parse', 0x4075c70, '4883fe3a0f85170200004885c00f84850200004989442428488d7c24184c89e6e83b174a00837c2418010f85d0fdffffe97e010000'),
    ('json_n_parse', 0x4075ca5, '4883fe3a75324885c00f845402000049894424284c89e7e84fd4e7ff4889542430a8010f8570010000b8010000004889442438'),
    ('json_value_result', 0x4075d3e, '4c897b08896b104c896b1431c0488903'),
    ('json_value_defaults', 0x4075d89, '4531e4f6442440018b6c244c410f44ecf6442438014c8b7c24304d0f44fc'),
    ('json_duplicate_error', 0x4075ec1, '488d0531c074fceb07488d0596bc74fc488944241848c744242001000000488d44241848890424488d05017966004889442408488d3d1fd63bfc4889e6e8bdd36700'),
    ('json_null_compare', 0x451743c, '4183f96e75664883f8010f84c0000000488d78ff48897e284839cf0f83890000000fb67c02ff488946284080ff750f85910000004839c87371488d7801440fb6040248897e284180f86c75794839cf73590fb64c02014883c0024889462880f96c7562c7430400000000eb31'),
    ('json_null_error', 0x45174e6, '48c744240805000000488d4424084889f74889c6e851bf9dffebbd48c744240809000000ebe3'),
    ('rmp_marker_dispatch', 0x336ff79, '3c017563488b4e184885c9741f4c8b461048ffc9410fb60049ffc04c89461048894e1884c0780e4531c9eb56c6470800e92703000041b1e03cdf77463c90730a240f4189c0e99b0000003ca0730a240f4189c0e93b010000'),
    ('rmp_fixed_map', 0x337005e, '410fb6d80fb746226685c00f845b06000066ffc8668946220f84a80400004989ff4989f64889742450895c2458488d7c2428488d742450e866e63c00'),
    ('rmp_map_remainder', 0x33700d5, '8b44245885c00f84d303000029c30f820a060000c644240804895c240c48c7042401000000488dbc2480000000e87956c9ffe9ca030000'),
    ('rmp_fixed_array', 0x337010c, '410fb6d80fb746226685c00f84ba05000066ffc8668946220f84fa0300004989ff4989f64889742450895c2458488d7c2428488d742450e8989e3f00'),
    ('rmp_map_children', 0x373e80d, 'b904000000488d7c2410488bb42488000000488d15c6b8d1fce8757882ff0fb64424100fb65c2419f20f104424110f298424c0000000440fb664241a440fb66c241b440fb674241c3c090f855d0100004c8b7c241d488d7c2410488bb4248800000031d2e8baa8a8ff0fb64424103c090f856c010000'),
    ('rmp_map_finish', 0x373e96f, '488d7c2410488db42490000000e8dfde57004c8b742478498d7e0848b8010000000000008048394424100f84260100000f104424100f104c24200f114f100f110731c0'),
    ('rmp_map_duplicate', 0x373eac5, '488d351cf205fdba0d000000e8ea7b90ffb801000000e9d2feffff'),
    ('rmp_pairs_child', 0x376a0b3, '488dbc24880000004c89fe31d2e86b24a8ff80bc2488000000000f8599000000'),
    ('rmp_pairs_finish', 0x376a1f0, '488dbc2488000000488db424f0000000e85b265500498d7e0848b8010000000000008048398424880000007431'),
    ('rmp_pairs_duplicate', 0x376a24e, '488d35933a03fdba0d000000e861c48dffb801000000ebd0'),
    ('rmp_pair_value', 0x31ec9e7, '4488542406488d7c24484c89c631d2e835c7fdff0fb64424484883f8090f8515030000'),
    ('rmp_field_seen_init', 0x31c9266, 'c784249c0000000000000048c78424f800000000000000eb17c784249c00000001000000'),
    ('rmp_n_duplicate', 0x31c9343, '84c00f84a90300000fb6c083f8010f85ee0300004883bc24f8000000010f84b0100000'),
    ('rmp_n_seen', 0x31c9926, '8b7424083c090f85b10800004889b42420010000b80100000048898424f8000000'),
    ('rmp_key_select', 0x31c964e, '410fb604243c6e0f94c1b20228ca3c740fb6c2b9000000000f44c1'),
    ('rmp_t_duplicate', 0x31c96e4, '0fb6003c6e0f94c13c740f859001000083bc249c000000010f84080d0000'),
    ('rmp_t_null', 0x31c9898, '48c78424c80000000000000089c23cc00f84d1f9ffff885620884e21b9040000004c89ff4989f7488d15b20629fde86561daff0fb604243c090f853f0800008b44240448898424c8000000488b44240848898424180100004c89fe4989e7'),
    ('rmp_value_defaults', 0x31c9fbd, '31c0f68424f800000001488b942420010000480f44d0f684249c00000001488b8c24c80000000f44c8488b842418010000e951fbffff4c8b7e104b8d04374889461048894e18488d7c24504c89fe4c89f2ff15945c3103837c24500175454889e74c89'),
    ('sort_dispatch_small', 0x3cbc883, '4983fc020f8328010000'),
    ('sort_adjacent_keys', 0x3cbc8a0, '48ffc84883f8027263f30f6f01f30f6f4930660f74c8660f6e4110660f6e51404883c130660f74d0660fdbd1660fd7d281faffff000075c848b8000000000000008048ffc0488903'),
    ('sort_duplicate_release', 0x3cbc8e8, '498b074885c00f84b200000048c1e004488d34404c89f731d2ff15992b8202'),
    ('map_storage_limit', 0x3cbc90c, '498b074983fc40763f4b8d0c6448c1e104'),
    ('map_storage_compact', 0x3cbc954, '48c7442420000000004c8964242848894424104c89742418488d7c241031f6e828cc8a00'),
    ('sort_dispatch_large', 0x3cbc9b5, '4983fc15731a488d4c2410ba010000004c89f74c89e6e8504f6b00e9b8feffff488d5424104c89f74c89e6ff1512b98202e9a2feffff'),
    ('snapshot_field_name', 0x5673ce8, '807e0b007429488d05215a2bfbba180000004989ff4889f74989f44889c6e855bb15004c89e64c89ff4883f8027560'),
    ('snapshot_layout', 0x5673d17, '488b034c39f07525488b430831d24989c14885c0410f95c074044c8b4b18488b4b104488c24531c04989d2eb72'),
    ('snapshot_map_child', 0x5673de1, '4c894c24404889e2e8b2c5c5ff'),
    ('snapshot_sequence_a', 0x52d0685, 'e8f6f70400488b442418483904240f85d7020000488b5c24604c8b6c247848b800000000000000804839c30f848b0000008b942480000000488d7c24204c89eee8d6e44f00488b4424204883f8020f85cf020000'),
    ('snapshot_value_call_named', 0x52d0741, '4889e74c89e64c89eae8a12eacff48bb0000000000000080'),
    ('snapshot_value_call_binary', 0x52d08da, '4889e74c89e64c89eae8f82aacff48bb0000000000000080488b44241848390424'),
    ('binary_writer_count', 0x4d93401, '8b6e084c8b3e31d24d85ff0f95c283fd0183daff41807e1b00'),
    ('binary_writer_t', 0x4d9344f, '85ed74674983c40841807e1b017533498b06498b76104839f00f84e0000000498b4e08c60431a148ffc6498976104839f00f84ec000000c604317448ffc649897610'),
    ('binary_writer_n', 0x4d934ba, '4d85ff745241807e1b017533498b06498b76104839f00f84c4000000498b4e08c60431a148ffc6498976104839f00f84d0000000c604316e48ffc649897610'),
    ('binary_writer_error', 0x4d9351a, '488b4c24084c892b4889430848894b10eb10488b442410488943100f1004240f1103'),
    ('named_writer_count', 0x4d93611, '8b6e084c8b3e31d24d85ff0f95c283fd0183daff41807e0b00'),
    ('named_writer_t', 0x4d9366b, '85ed744e41807e0b01751a488d359b31b8fbba010000004c89f7e8d6c1a3004883f8027574'),
    ('named_writer_n', 0x4d936bd, '4d85ff743941807e0b01751a488d35122ab8fbba010000004c89f7e883c1a3004883f802754f'),
    ('root_map_capacity', 0x4d9df91, '488b571849bff8ffffffffffff7f4989d649c1e6044889d048c1e83c0f95c04d39fe0f97c108c1740b31ff4c89f6ff15d314740148895424384889b42488000000488b1f4983c7084d85f6'),
    ('root_map_descriptors', 0x4d9e12e, '4c8d355bc66f014c8d3d7ce66f01'),
    ('root_map_value_pointer', 0x4d9e199, '498d45304889442448498d6d184d85ed751a'),
    ('root_map_value_append', 0x4d9e1c5, '4c8b6424184c3b6424087507488d7c2408ffd3488b4424104c89e148c1e1044c892c084c8974080849ffc44c89642418'),
    ('root_map_submit', 0x4d9e21d, '0f104424100f104c2428488b4424384889842490000000488d8424900000004889842498000000488d05a5c46f0148898424a00000000f114424400f114c2450488d842498000000488944246048c744246801000000488d742440488bbc2488000000e81bdc0700'),
    ('root_map_allocation_error', 0x4d9e2d1, 'bf080000004c89f6ff15b9117401bf080000004c89f6ff15ab1174010f0b'),
    ('root_value_visitor', 0x3d38b00, '4883ec484889f0488d4f0848894c2408488d0de1fc730248894c241048897c2418488d0dd0b4730248894c2420488d4c240848894c242848c744243001000000488d4c241848894c243848c744244001000000488d7424284889c7e8205747004883c448c3'),
    ('root_value_constructor', 0x3d38ab0, '534889fbbf30000000ff15c1697a024885c0742948b901000000000000804889084889481848c703020000004889430848c74310020000004889d85bc3bf08000000be30000000ff159b697a02'),
    ('root_option_visitor', 0x4513370, '4883ec384889f0833f00742d48897c2428488d0d28b4f70148894c2430488d4c242848894c240848c744241001000000488d0d31b2f701eb1948c74424080800000048c744241000000000488d0d26b2f70148894c241848c744242001000000488d7424084889c7e8a3aec9ff4883c438c3'),
    ('sort_small_bounds', 0x4371920, '488d42ff4839f00f83210100004839f20f8417010000'),
    ('sort_small_setup', 0x4371944, '4889fb4c8d2c7649c1e5044901fd48c1e2044c8d24524e8d3427488b2debe116024c8d7c24104c896c2408'),
    ('sort_small_compare', 0x43719b7, '498d76d0ba140000004c89f7ffd585c079dd'),
    ('sort_small_save', 0x43719c9, '410f1006410f104e10410f1056200f295424300f294c24200f29442410'),
    ('sort_small_shift', 0x43719f0, '420f10442bd0420f104c2be0420f10542bf0420f11542b20420f114c2b10420f11042b4983fd300f8463ffffff4a8d342b4883c6a0ba140000004c89ffffd54983c5d085c078b94901dde944ffffff'),
    ('sort_large_capacity', 0x36feb60, '4889d34889f148d1e94889f04829c84881fe0a8b020041bc0a8b02004c0f42e64939c44c0f46e04983fc567225'),
    ('sort_large_overflow', 0x36feb8d, '4c89e148c1e1044c8d3c4948b9aaaaaaaaaaaaaa024839c8761531ff4c89feff15e608de02'),
    ('sort_large_stack_or_heap', 0x36febb2, '4989e6b955000000eb204989fe4c89ff4989f5ff15b508de024c89f74c89ee4989c64c89e14885c07440'),
    ('sort_large_delegate', 0x36febdc, '4531c04883fe41410f92c04c89f24989d9e8de4c7b004983fc55761349c1e4044b8d34644c89f731d2ff159508de02'),
    ('sort_large_oom', 0x36fec1c, 'bf080000004c89feff156e08de02'),
    ('compact_clone_guard', 0x58441a1, '4c8b66184c89e048c1e0044c8d344048b8aaaaaaaaaaaaaa024939c4760b31ff4c89f6ff15ceb2c900'),
    ('compact_clone_allocate', 0x58441cd, '4d85f6741d4989f54c89f7ff15a2b2c9004885c00f84fa0200004d89e74c89eeeb08b8080000004531ff'),
    ('compact_clone_cursors', 0x58441f7, '0f57c00f114424104c893c2448894424084d85e4742b488b16488b4e1031c04839d1480f43c24829c14889d74829cf4c89e04829f877104901cc31c04c89e2eb0631c931d231c0488b760848c1e104488d0c49488d3c0e48c1e204488d14524c8d04164c8d0c4049c1e1044901f1'),
    ('compact_clone_reserve', 0x584429d, '4d39fe0f86a90000004889e7b90800000041b83000000031f64c89f2e852f71100'),
    ('compact_clone_output', 0x58444ae, '488b442420488b4c2428480148180f1004240f104c24100f114b100f1103'),
    ('compact_clone_oom', 0x58444e1, 'bf080000004c89f6ff15a9afc900'),
    ('tree_clone_entry', 0x522ea41, '4989ff4885d248897424200f843a0200004989d6488bb6f001000049ffce488d7c24084c89f2e8c4ffffff'),
    ('tree_clone_parent_alloc', 0x522ea7a, '4c8b6c2410bf50020000ff15f6092b014885c00f84960300004989c448c7000000000066c780ee0100000000'),
    ('tree_clone_leaf_alloc', 0x522ec8c, 'bff0010000ff15e9072b014885c00f84aa01000048c7000000000066c780ee010000000048894424080f57c00f11442410488b7424206683beee010000000f84c1000000'),
    ('tree_clone_leaf_copy', 0x522ecf0, '448b411044898424800000000f10010f29442470448b470844894424384c8b074c89442430440fb780ee0100004983f80b0f83c1000000'),
    ('tree_clone_leaf_store', 0x522ed27, '4c8b4ff849ffc6458d500166448990ee0100004f8d1480448b9c248000000046895c92100f28442470420f1104924f8d04404e890cc64c8b4c24304e894cc608448b4c243846894cc6104c8b442420450fb780ee0100004883c1144883c7184d39c60f8261ffffff'),
    ('tree_clone_internal_guard', 0x522ebc7, '410fb78c24ee0100004883f90b0f83f3010000'),
    ('tree_clone_error', 0x522edcd, 'be20000000488d3de79722fb488d1500b72601ff154a092b01eb60488d3dd19722fb488d15bab62601be20000000ff152f092b01eb45bf08000000bef0010000488b6c2428ff1578062b01eb2e488d3d7f502701ff15090a2b01eb1fbf08000000be50020000ff1557062b01eb0d488d3db6b62601ff15e8092b010f0b'),
    ('tree_clone_leaf_result', 0x522ed91, '4531f64c897424184d8977100f10442408410f1107'),
]

# Each selected transfer or RIP-relative LEA is instruction-aligned by human
# inspection; this is not an instruction census or a general x86 decoder.
EDGES = [
    ('ctx_json_value', 0x3efdb57, 'e88466d7ff', 0x3c741e0),
    ('ctx_binary_value', 0x2fd8b73, 'e8e8733900', 0x336ff60),
    ('ctx_binary_parent', 0x32cb0dc, 'e87fc1d0ff', 0x2fd7260),
    ('ctx_binary_copy1', 0x32cb236, 'ff15cc422103', 0x64df508),
    ('ctx_binary_copy2', 0x32cb7ac, 'ff15563d2103', 0x64df508),
    ('ctx_binary_copy3', 0x32cb870, 'ff15923c2103', 0x64df508),
    ('ctx_json_missing_literal', 0x3f0a2ad, '488d053ea28bfc', 0x7c44f2),
    ('ctx_binary_missing_literal', 0x2fe263f, '488d05a3357bfd', 0x795be9),
    ('ctx_json_missing_error', 0x3f0a36f, 'e84c8f7e00', 0x46f32c0),
    ('ctx_binary_missing_error', 0x2fe26ff, 'e83c400600', 0x3046740),
    ('ctx_clone_tree', 0x55f0492, 'e899e5c3ff', 0x522ea30),
    ('ctx_clone_compact', 0x55f04a8, 'e8e33c2500', 0x5844190),
    ('ctx_snapshot_map', 0x54820a9, 'e8221c1f00', 0x5673cd0),
    ('json_array_entries', 0x3c742d1, 'e8eacfb3ff', 0x37b12c0),
    ('json_object_entries', 0x3c74426, 'e815afadff', 0x374f340),
    ('json_pair_iteration', 0x37b135d, 'e82eb47b00', 0x3f6c790),
    ('json_pair_finish', 0x37b140f, 'e84cb45000', 0x3cbc860),
    ('json_pair_duplicate', 0x37b1454, 'e8e71df400', 0x46f3240),
    ('json_pair_value', 0x3f6c9f8, 'e8a38e1000', 0x40758a0),
    ('json_object_key', 0x374f417, 'e824aeac00', 0x421a240),
    ('json_object_value_adapter', 0x374f450, 'e80bbd7f00', 0x3f4b160),
    ('json_object_finish', 0x374f520, 'e83bd35600', 0x3cbc860),
    ('json_object_duplicate', 0x374f565, 'e8d63cfa00', 0x46f3240),
    ('json_value_adapter', 0x3f4b1f1, 'e8aaa61200', 0x40758a0),
    ('json_t_optional', 0x4075c90, 'e83b174a00', 0x45173d0),
    ('json_n_scalar', 0x4075cbc, 'e84fd4e7ff', 0x3ef3110),
    ('json_non_null_helper', 0x45174ad, 'e84eacabff', 0x3fd2100),
    ('rmp_map_entries', 0x3370095, 'e866e63c00', 0x373e700),
    ('rmp_pair_entries', 0x3370143, 'e8989e3f00', 0x3769fe0),
    ('rmp_map_key', 0x373e826, 'e8757882ff', 0x2f660a0),
    ('rmp_map_value', 0x373e871, 'e8baa8a8ff', 0x31c9130),
    ('rmp_map_finish', 0x373e97c, 'e8dfde5700', 0x3cbc860),
    ('rmp_map_duplicate', 0x373ead1, 'e8ea7b90ff', 0x30466c0),
    ('rmp_pairs_child', 0x376a0c0, 'e86b24a8ff', 0x31ec530),
    ('rmp_pairs_finish', 0x376a200, 'e85b265500', 0x3cbc860),
    ('rmp_pairs_duplicate', 0x376a25a, 'e861c48dff', 0x30466c0),
    ('rmp_pair_value', 0x31ec9f6, 'e835c7fdff', 0x31c9130),
    ('sort_small', 0x3cbc9cb, 'e8504f6b00', 0x4371920),
    ('sort_comparator_slot', 0x437195e, '488b2debe11602', 0x64dfb50),
    ('sort_large_delegate', 0x36febed, 'e8de4c7b00', 0x3eb38d0),
    ('compact_clone_reserve', 0x58442b9, 'e852f71100', 0x5963a10),
    ('tree_clone_recurse', 0x522ea67, 'e8c4ffffff', 0x522ea30),
    ('sort_large_slot', 0x3cbc9e0, 'ff1512b98202', 0x64e82f8),
    ('map_large', 0x3cbc93e, 'e89d6cbdff', 0x38935e0),
    ('map_compact', 0x3cbc973, 'e828cc8a00', 0x45695a0),
    ('map_duplicate_release', 0x3cbc901, 'ff15992b8202', 0x64df4a0),
    ('snapshot_name', 0x5673d06, 'e855bb1500', 0x57cf860),
    ('snapshot_entries', 0x5673de9, 'e8b2c5c5ff', 0x52d03a0),
    ('snapshot_named_value', 0x52d074a, 'e8a12eacff', 0x4d935f0),
    ('snapshot_binary_value', 0x52d08e3, 'e8f82aacff', 0x4d933e0),
    ('binary_time_value', 0x4d934ab, 'e8c03c5700', 0x5307170),
    ('binary_count_value', 0x4d93502, 'e819c8a300', 0x57cfd20),
    ('named_header', 0x4d93632, 'e8c9aaa300', 0x57ce100),
    ('named_t_key', 0x4d93685, 'e8d6c1a300', 0x57cf860),
    ('named_time_value', 0x4d936ae, 'e85d3e5700', 0x5307510),
    ('named_n_key', 0x4d936d8, 'e883c1a300', 0x57cf860),
    ('named_count_value', 0x4d936ec, 'e8bfc9a300', 0x57d00b0),
    ('root_iterator', 0x4d9e1b5, 'e8d65b3900', 0x5133d90),
    ('root_submit', 0x4d9e280, 'e81bdc0700', 0x4e1bea0),
    ('root_pair', 0x3d38b5b, 'e820574700', 0x41ae280),
    ('root_option', 0x45133d8, 'e8a3aec9ff', 0x41ae280),
    ('root_key_desc', 0x4d9e12e, '4c8d355bc66f01', 0x649a790),
    ('root_value_desc', 0x4d9e135, '4c8d3d7ce66f01', 0x649c7b8),
    ('value_option_desc', 0x3d38b10, '488d0de1fc7302', 0x64787f8),
    ('value_count_desc', 0x3d38b21, '488d0dd0b47302', 0x6473ff8),
    ('option_some_desc', 0x45133a0, '488d0d31b2f701', 0x648e5d8),
    ('option_none_desc', 0x45133bb, '488d0d26b2f701', 0x648e5e8),
]
BRANCHES = [
    ('ctx_json_duplicate', 0x3efc245, '0f85fbad0000', 0x3f07046),
    ('ctx_json_colon_error', 0x3efdb39, '0f8597a90000', 0x3f084d6),
    ('ctx_json_child_error', 0x3efdb77, '0f84e4520000', 0x3f02e61),
    ('ctx_json_field_present', 0x3f0a2a7, '0f85ac020000', 0x3f0a559),
    ('ctx_binary_duplicate', 0x2fd8b5d, '0f85e6620000', 0x2fdee49),
    ('ctx_binary_child_error', 0x2fd8ba1, '0f84f2320000', 0x2fdbe99),
    ('ctx_binary_field_present', 0x2fe2639, '0f8557010000', 0x2fe2796),
    ('ctx_binary_parent_depth_zero', 0x32cb0a7, '0f84c9230000', 0x32cd476),
    ('ctx_binary_parent_depth_exhausted', 0x32cb0b4, '0f8443070000', 0x32cb7fd),
    ('ctx_binary_parent_child_ok', 0x32cb10d, '0f850e010000', 0x32cb221),
    ('ctx_binary_parent_remaining_zero', 0x32cb271, '0f8420050000', 0x32cb797),
    ('ctx_binary_parent_length_underflow', 0x32cb279, '0f8235220000', 0x32cd4b4),
    ('ctx_clone_compact', 0x55f0467, '7530', 0x55f0499),
    ('ctx_clone_tree_empty', 0x55f0471, '7464', 0x55f04d7),
    ('ctx_clone_tree_null', 0x55f047d, '0f8421290000', 0x55f2da4),
    ('json_depth_zero', 0x3c742a1, '0f845e050000', 0x3c74805),
    ('json_depth_exhausted', 0x3c742ad, '0f8429050000', 0x3c747dc),
    ('json_value_t_duplicate', 0x4075b0f, '0f84ac030000', 0x4075ec1),
    ('json_value_n_duplicate', 0x4075b7a, '0f844a030000', 0x4075eca),
    ('json_value_n_error', 0x4075cc8, '0f8570010000', 0x4075e3e),
    ('json_null_lead', 0x4517440, '7566', 0x45174a8),
    ('json_null_bad_u', 0x451746a, '0f8591000000', 0x4517501),
    ('rmp_marker_above_df', 0x336ffb3, '7746', 0x336fffb),
    ('rmp_marker_array_min', 0x336ffb7, '730a', 0x336ffc3),
    ('rmp_marker_array_max', 0x336ffc5, '730a', 0x336ffd1),
    ('rmp_depth_zero', 0x3370069, '0f845b060000', 0x33706ca),
    ('rmp_depth_exhausted', 0x3370076, '0f84a8040000', 0x3370524),
    ('rmp_length_underflow', 0x33700e3, '0f820a060000', 0x33706f3),
    ('rmp_child_error', 0x373e87d, '0f856c010000', 0x373e9ef),
    ('rmp_map_duplicate', 0x373e999, '0f8426010000', 0x373eac5),
    ('rmp_pair_duplicate', 0x376a21b, '7431', 0x376a24e),
    ('rmp_value_t_duplicate', 0x31c96fc, '0f84080d0000', 0x31ca40a),
    ('rmp_value_n_duplicate', 0x31c9360, '0f84b0100000', 0x31ca416),
    ('rmp_nil', 0x31c98a8, '0f84d1f9ffff', 0x31c927f),
    ('sort_short', 0x3cbc887, '0f8328010000', 0x3cbc9b5),
    ('small_sort_in_order', 0x43719c7, '79dd', 0x43719a6),
    ('small_sort_shift', 0x4371a35, '78b9', 0x43719f0),
    ('large_sort_stack', 0x36feb8b, '7225', 0x36febb2),
    ('large_sort_oom', 0x36febda, '7440', 0x36fec1c),
    ('compact_clone_size_ok', 0x58441bd, '760b', 0x58441ca),
    ('compact_clone_zero_size', 0x58441d0, '741d', 0x58441ef),
    ('compact_clone_allocation_null', 0x58441e1, '0f84fa020000', 0x58444e1),
    ('tree_clone_leaf', 0x522ea4c, '0f843a020000', 0x522ec8c),
    ('tree_clone_parent_allocation_null', 0x522ea8d, '0f8496030000', 0x522ee29),
    ('tree_clone_leaf_allocation_null', 0x522ec9a, '0f84aa010000', 0x522ee4a),
    ('tree_clone_node_full', 0x522ed21, '0f83c1000000', 0x522ede8),
    ('tree_clone_internal_full', 0x522ebd4, '0f83f3010000', 0x522edcd),
    ('adjacent_unequal', 0x3cbc8d6, '75c8', 0x3cbc8a0),
    ('compact_limit', 0x3cbc913, '763f', 0x3cbc954),
    ('sort_threshold', 0x3cbc9b9, '731a', 0x3cbc9d5),
    ('snapshot_omit_name', 0x5673cec, '7429', 0x5673d17),
    ('snapshot_name_failure', 0x5673d15, '7560', 0x5673d77),
    ('binary_omit_t', 0x4d93451, '7467', 0x4d934ba),
    ('binary_t_name_mode', 0x4d9345c, '7533', 0x4d93491),
    ('binary_t_child_error', 0x4d934b8, '7572', 0x4d9352c),
    ('binary_omit_n', 0x4d934bd, '7452', 0x4d93511),
    ('binary_n_name_mode', 0x4d934c4, '7533', 0x4d934f9),
    ('named_omit_t', 0x4d9366d, '744e', 0x4d936bd),
    ('named_t_name_error', 0x4d9368e, '7574', 0x4d93704),
    ('named_omit_n', 0x4d936c0, '7439', 0x4d936fb),
    ('root_capacity_ok', 0x4d9dfb8, '740b', 0x4d9dfc5),
    ('root_alloc_fail', 0x4d9dff1, '0f84da020000', 0x4d9e2d1),
    ('root_empty_mode', 0x4d9e03d, '7469', 0x4d9e0a8),
    ('root_subtract_carry', 0x4d9e060, '7767', 0x4d9e0c9),
    ('root_iterator_end', 0x4d9e1c3, '7458', 0x4d9e21d),
    ('root_option_absent', 0x451337a, '742d', 0x45133a9),
]

# Relative relocation slots in root descriptor records. Their contents are
# independently decoded, not taken from the dynamic loader or inferred names.
RELOCATIONS = [
    ('root_field_visit', 0x64a8420, 0x4d9df80),
    ('root_field_create', 0x64a8428, 0x4d9db00),
    ('key_visit', 0x649a7a8, 0x41f8050),
    ('key_create', 0x649a7b0, 0x43025f0),
    ('value_visit', 0x649c7d0, 0x3d38b00),
    ('value_create', 0x649c7d8, 0x3d38ab0),
    ('option_visit', 0x6478810, 0x4513370),
    ('option_create', 0x6478818, 0x4512b40),
    ('count_visit', 0x6474010, 0x14199b0),
    ('count_create', 0x6474018, 0x14196d0),
]


def digest_checked(data, expected):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('input SHA-256 mismatch')
    return actual


def mapped_offset(data, secs, va, size):
    """Find exactly one file-backed section covering the complete range."""
    if (type(va) is not int or type(size) is not int or va < 0 or size <= 0
            or va >= 1 << 64 or size > (1 << 64) - va):
        raise ValueError('invalid virtual address range')
    matches = []
    for sec in secs:
        start, extent = sec['address'], sec['size']
        if sec['type'] != 8 and start <= va and va + size <= start + extent:
            off = sec['offset'] + va - start
            if off < 0 or off + size > len(data):
                raise ValueError('mapped bytes outside file')
            matches.append((off, sec['name']))
    if len(matches) != 1:
        raise ValueError('address is not uniquely file-backed')
    return matches[0]


def read_va(data, secs, va, size):
    off, _ = mapped_offset(data, secs, va, size)
    return data[off:off + size]


def unique_section(secs, name):
    found = [s for s in secs if s['name'] == name and s['type'] != 8]
    if len(found) != 1:
        raise ValueError('missing or duplicate section: ' + name)
    return found[0]


def relative_relocations(data, secs):
    sec = unique_section(secs, '.rela.dyn')
    start, size = sec['offset'], sec['size']
    if size % 24 or start + size > len(data):
        raise ValueError('invalid relocation table extent')
    result = {}
    for off in range(start, start + size, 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        result.setdefault(slot, []).append((info & 0xffffffff, info >> 32, addend, off))
    return result


def selected_relocation(relocs, slot, target=None):
    rows = relocs.get(slot, [])
    if len(rows) != 1:
        raise ValueError('missing or duplicate relocation')
    kind, sym, addend, off = rows[0]
    if kind != 8 or sym != 0 or (target is not None and addend != target):
        raise ValueError('unexpected relative relocation')
    return kind, sym, addend, off


def imported_symbol(data, secs, relocs, slot, expected_name):
    rows = relocs.get(slot, [])
    if len(rows) != 1:
        raise ValueError('missing or duplicate import relocation')
    kind, sym, addend, off = rows[0]
    symbols = unique_section(secs, '.dynsym')
    strings = unique_section(secs, '.dynstr')
    if (kind != 6 or sym == 0 or addend != 0 or symbols['type'] != 11
            or strings['type'] != 3 or symbols['size'] % 24
            or sym >= symbols['size'] // 24):
        raise ValueError('invalid import relocation or symbol table')
    symbol_off = symbols['offset'] + sym * 24
    name_off, info, other, section_index, value, size = struct.unpack_from('<IBBHQQ', data, symbol_off)
    if section_index != 0 or name_off >= strings['size']:
        raise ValueError('import is not a valid undefined symbol')
    name_at = strings['offset'] + name_off
    end = data.find(b'\0', name_at, strings['offset'] + strings['size'])
    if end < 0:
        raise ValueError('unterminated imported symbol')
    name = data[name_at:end]
    if name != expected_name:
        raise ValueError('unexpected imported symbol')
    return [hex(slot), hex(off), kind, sym, hex(symbol_off), section_index,
            name.decode('ascii'), data[off:off + 24].hex(), data[symbol_off:symbol_off + 24].hex()]


def read_location(data, secs, relocs, va):
    _, _, path_va, reloff = selected_relocation(relocs, va)
    raw = read_va(data, secs, va, 24)
    length, line, col = struct.unpack_from('<QII', raw, 8)
    if length == 0 or length > 4096:
        raise ValueError('invalid source location length')
    name = read_va(data, secs, path_va, length)
    if not name.endswith(PATH_SUFFIX):
        raise ValueError('unexpected source location suffix')
    return {'location_va': hex(va), 'file_offset': hex(mapped_offset(data, secs, va, 24)[0]),
            'relocation_file_offset': hex(reloff), 'source_va': hex(path_va),
            'source_length': length, 'source_suffix': PATH_SUFFIX.decode('ascii'),
            'line': line, 'column': col}


def exact_window(actual, expected):
    if actual != expected:
        raise ValueError('selected byte window mismatch')


def decode_transfer(va, raw):
    """Decode only selected, complete relative transfer and LEA/MOV forms."""
    if len(raw) == 2 and (0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb):
        return va + 2 + struct.unpack_from('<b', raw, 1)[0]
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        return va + 5 + struct.unpack_from('<i', raw, 1)[0]
    if len(raw) == 6 and (raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f
                          or raw[:2] in (b'\xff\x15', b'\xff\x25')):
        return va + 6 + struct.unpack_from('<i', raw, 2)[0]
    if (len(raw) == 7 and raw[0] in (0x48, 0x4c) and raw[1] in (0x8d, 0x8b)
            and raw[2] & 0xc7 == 5):
        return va + 7 + struct.unpack_from('<i', raw, 3)[0]
    raise ValueError('unsupported selected instruction')


def validate_transfer(va, actual, expected, target):
    exact_window(actual, expected)
    if decode_transfer(va, actual) != target:
        raise ValueError('selected transfer target mismatch')


def selected_functions(data, secs, table, fdes):
    by_start = {}
    for f in fdes:
        by_start.setdefault(f['start'], []).append(f)
    indexes = {}
    for row in table:
        indexes.setdefault(row['start'], []).append(row)
    rows = []
    for label, start, end in FUNCTIONS:
        matches = by_start.get(start, [])
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError('selected FDE extent mismatch')
        f = matches[0]
        entries = indexes.get(start, [])
        if len(entries) != 1 or entries[0]['fde'] != f['fde']:
            raise ValueError('selected FDE not uniquely indexed')
        idx = entries[0]
        offset, sec = mapped_offset(data, secs, start, end - start)
        if sec != '.text':
            raise ValueError('selected FDE outside text')
        raw = read_va(data, secs, start, end - start)
        rows.append([label, hex(start), hex(end), hex(offset), len(raw),
                     hex(f['fde']), hex(f['cie']), hex(f['lsda']) if f['lsda'] is not None else '',
                     idx['index'], hashlib.sha256(raw).hexdigest()])
    return rows


def evidence_scope(va, length):
    """Separate new FDEs from byte witnesses in prior analysis boundaries."""
    if any(start <= va and va + length <= end for _, start, end in FUNCTIONS):
        return 'new'
    return 'prior-boundary'


def marker_kind(marker, map_min, array_min, other_min, mask):
    if type(marker) is not int or not 0 <= marker <= 255:
        raise ValueError('marker must be a byte')
    if map_min <= marker < array_min:
        return 'fixed-map', marker & mask
    if array_min <= marker < other_min:
        return 'fixed-array', marker & mask
    return 'other', None


def writer_choice(count, tag):
    """Model only the two checked omission tests, not child encoders."""
    if type(count) is not int or not 0 <= count < (1 << 64):
        raise ValueError('count is not a u64')
    if type(tag) is not int or not 0 <= tag < (1 << 32):
        raise ValueError('tag is not a u32')
    keys = ('t' if tag else '') + ('n' if count else '')
    return len(keys), keys


def adjacent_equal(a, b):
    if not isinstance(a, bytes) or not isinstance(b, bytes) or len(a) != 20 or len(b) != 20:
        raise ValueError('keys must be 20 bytes')
    return a[:16] == b[:16] and a[16:20] == b[16:20]


def map_plan(count, duplicate, small_limit, compact_limit):
    if type(count) is not int or not 0 <= count < (1 << 64) or type(duplicate) is not bool:
        raise ValueError('invalid map model input')
    if count < 2:
        if duplicate:
            raise ValueError('a single entry has no adjacent pair')
        ordering = 'none'
    elif count < small_limit:
        ordering = 'direct-helper'
    else:
        ordering = 'indirect-helper'
    storage = 'duplicate-error' if duplicate else ('compact' if count <= compact_limit else 'large-helper')
    return ordering, storage


def clone_count_case(count, limit, stride):
    """Model the selected count guard, leaving allocation results unknown."""
    if type(count) is not int or not 0 <= count < (1 << 64):
        raise ValueError('count is not a u64')
    if count > limit:
        return 'size-error', None
    if count == 0:
        return 'zero-size', 0
    return 'allocate', count * stride


def clone_representation(word, length, pointer, marker):
    if any(type(v) is not int or not 0 <= v < (1 << 64) for v in (word, length, pointer, marker)):
        raise ValueError('clone header word is not a u64')
    if word != marker:
        return 'compact'
    if length == 0:
        return 'empty-tree'
    return 'tree' if pointer != 0 else 'missing-tree-pointer'


def node_insert_case(count, limit):
    if type(count) is not int or not 0 <= count < (1 << 16):
        raise ValueError('node length is not a u16')
    return 'full-error' if count >= limit else 'write'


def project_range(source, destination, length, offset, width):
    values = (source, destination, length, offset, width)
    if any(type(v) is not int or v < 0 or v >= 1 << 64 for v in values) or width == 0:
        raise ValueError('invalid projected range')
    if (source + length > 1 << 64 or destination + length > 1 << 64
            or offset < source or offset + width > source + length):
        raise ValueError('field outside projected copy range')
    return destination + offset - source


def field_events(events):
    """Model successfully decoded t/n values and the earlier duplicate guards."""
    seen = set()
    values = {'t': 0, 'n': 0}
    for key, value in events:
        if key not in values:
            raise ValueError('unknown key is delegated')
        if key in seen:
            return 'duplicate-' + key, values['n'], values['t']
        if type(value) is not int or value < 0 or value >= (1 << (32 if key == 't' else 64)):
            raise ValueError('value outside selected width')
        seen.add(key)
        values[key] = value
    return 'ok', values['n'], values['t']


def decode_dispatch(raw, base, first_byte, expected_hash):
    if len(raw) != 33 * 4 or hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError('selected JSON table bytes differ')
    rows = []
    for i in range(len(raw) // 4):
        rel = struct.unpack_from('<i', raw, 4 * i)[0]
        target = base + rel
        if not 0x3c741e0 <= target < 0x3c748a2:
            raise ValueError('selected JSON table target outside FDE')
        rows.append([i, hex(i + first_byte), hex(base + 4 * i),
                     raw[4 * i:4 * i + 4].hex(), hex(target)])
    return rows


def tsv(header, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue()


def json_text(value):
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n'


def collect(data):
    digest = digest_checked(data, TARGET_SHA256)
    secs, unwind = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    funcs = selected_functions(data, secs, unwind, fdes)
    relocs = relative_relocations(data, secs)
    loc = read_location(data, secs, relocs, 0x64767a8)
    if (loc['line'], loc['column'], loc['source_length']) != (123, 37, 20):
        raise ValueError('node-115 Location mismatch')

    window_rows = []
    for label, va, hx in WINDOWS:
        want = bytes.fromhex(hx)
        raw = read_va(data, secs, va, len(want))
        exact_window(raw, want)
        scope = evidence_scope(va, len(raw))
        window_rows.append([label, scope, hex(va), hex(mapped_offset(data, secs, va, len(raw))[0]),
                            len(raw), raw.hex()])

    def transfers(spec):
        rows = []
        for label, va, hx, target in spec:
            want = bytes.fromhex(hx)
            raw = read_va(data, secs, va, len(want))
            validate_transfer(va, raw, want, target)
            scope = evidence_scope(va, len(raw))
            rows.append([label, scope, hex(va), hex(mapped_offset(data, secs, va, len(raw))[0]),
                         raw.hex(), hex(decode_transfer(va, raw))])
        return rows

    edge_rows, branch_rows = transfers(EDGES), transfers(BRANCHES)
    relspec = RELOCATIONS + [
        ('sort_slot', 0x64e82f8, 0x36feb50),
        ('growth_slot', 0x64e64f0, 0x43bc3d0),
        ('allocation_slot', 0x64df480, 0x6355830),
        ('allocation_error_slot', 0x64df498, 0x141e264),
        ('release_slot', 0x64df4a0, 0x635de30),
    ]
    relocation_rows = []
    for label, slot, target in relspec:
        typ, sym, addend, off = selected_relocation(relocs, slot, target)
        scope = ('prior-boundary' if label in ('root_field_visit', 'root_field_create', 'growth_slot',
                                               'allocation_slot', 'allocation_error_slot', 'release_slot')
                 else 'new-link')
        relocation_rows.append([label, scope, hex(slot), hex(off), typ, sym, hex(addend),
                                data[off:off + 24].hex()])
    imports = [
        ['prior-boundary'] + imported_symbol(data, secs, relocs, 0x64dfb50, b'memcmp'),
        ['prior-boundary'] + imported_symbol(data, secs, relocs, 0x64df508, b'memcpy'),
    ]

    literal_spec = [
        ('json_field', 0x7c44f2, b'user_to_scheduled_cancel'),
        ('binary_field', 0x795be9, b'user_to_scheduled_cancel'),
        ('snapshot_field', 0x929716, b'user_to_scheduled_cancel'),
        ('duplicate_key', 0x79dce8, b'duplicate key'),
        ('named_t', 0x916818, b't'), ('named_n', 0x9160e2, b'n'),
        ('duplicate_t', 0x7c1ef9, b't'), ('duplicate_n', 0x7c1b67, b'n'),
        ('key_type', 0x45a0ec, b'User'), ('time_type', 0x459f78, b'Time'),
    ]
    literals = []
    for label, va, expected in literal_spec:
        raw = read_va(data, secs, va, len(expected))
        exact_window(raw, expected)
        literals.append([label, hex(va), hex(mapped_offset(data, secs, va, len(raw))[0]),
                         len(raw), raw.hex(), raw.decode('ascii')])

    # This table is 33 signed PC-independent offsets from one base, entered
    # only after the preceding range check. It is not an instruction census.
    table_va = 0x7b3f00
    first_byte = -struct.unpack('<b', read_va(data, secs, 0x3c74277, 1))[0]
    table_count = read_va(data, secs, 0x3c7427b, 1)[0] + 1
    if (first_byte, table_count) != (0x5b, 33):
        raise ValueError('selected JSON table guard differs')
    table_raw = read_va(data, secs, table_va, table_count * 4)
    dispatch_rows = decode_dispatch(table_raw, table_va, first_byte,
                                    '7b6a74f73c154eb302177bc5ddcc03f2be868af62f996f094984e1762ef8779b')
    if (int(dispatch_rows[0][-1], 16), int(dispatch_rows[32][-1], 16)) != (0x3c74293, 0x3c743e8):
        raise ValueError('selected JSON table cases differ')

    # Immediates and structural sizes below are read from checked instructions
    # and descriptor records. Synthetic cases exercise only these branches.
    small_limit = read_va(data, secs, 0x3cbc9b5, 4)[3]
    compact_limit = read_va(data, secs, 0x3cbc90f, 4)[3]
    short_limit = read_va(data, secs, 0x3cbc883, 4)[3]
    array_min = read_va(data, secs, 0x336ffb5, 2)[1]
    marker_mask = read_va(data, secs, 0x336ffb9, 2)[1]
    other_min = read_va(data, secs, 0x336ffc3, 2)[1]
    map_min = array_min - marker_mask - 1
    if (short_limit, small_limit, compact_limit, map_min, array_min, other_min, marker_mask) != (
            2, 21, 64, 0x80, 0x90, 0xa0, 15):
        raise ValueError('selected immediate mismatch')
    map_offset = struct.unpack_from('<I', read_va(data, secs, 0x548209c, 7), 3)[0]
    capture_offset = struct.unpack_from('<I', read_va(data, secs, 0x4e3455b, 7), 3)[0]
    root_stride = read_va(data, secs, 0x4d9e199, 4)[3]
    root_value_offset = read_va(data, secs, 0x4d9e1a2, 4)[3]
    option_offset = read_va(data, secs, 0x3d38b07, 4)[3]
    json_result_offset = struct.unpack('<I', read_va(data, secs, 0x3f0c129, 4))[0]
    binary_result_offset = struct.unpack('<I', read_va(data, secs, 0x2fe481d, 4))[0]
    nested_result = struct.unpack('<I', read_va(data, secs, 0x40909d4, 4))[0]
    nested_payload = struct.unpack('<I', read_va(data, secs, 0x4090b51, 4))[0]
    json_header = nested_payload - nested_result
    binary_child_base = struct.unpack('<I', read_va(data, secs, 0x32cb0d0, 4))[0]
    binary_copy1_source = struct.unpack('<I', read_va(data, secs, 0x32cb225, 4))[0]
    binary_copy1_dest = struct.unpack('<I', read_va(data, secs, 0x32cb22d, 4))[0]
    binary_copy1_length = struct.unpack('<I', read_va(data, secs, 0x32cb232, 4))[0]
    binary_copy2_dest = struct.unpack('<I', read_va(data, secs, 0x32cb79b, 4))[0]
    binary_copy2_source = struct.unpack('<I', read_va(data, secs, 0x32cb7a3, 4))[0]
    binary_copy2_length = struct.unpack('<I', read_va(data, secs, 0x32cb7a8, 4))[0]
    binary_copy3_length = struct.unpack('<I', read_va(data, secs, 0x32cb869, 4))[0]
    nested_output_payload = read_va(data, secs, 0x4090d8c, 1)[0]
    nested_copy_length = struct.unpack('<I', read_va(data, secs, 0x4090d96, 4))[0]
    outer_copy_length = struct.unpack('<I', read_va(data, secs, 0x404c51b, 4))[0]
    materialize_input_offset = struct.unpack('<I', read_va(data, secs, 0x3c2ed61, 4))[0]
    materialize_output_offset = struct.unpack('<I', read_va(data, secs, 0x3c2edb6, 4))[0]
    clone_input_offset = struct.unpack('<I', read_va(data, secs, 0x55f0463, 4))[0]
    clone_output_offset = struct.unpack('<I', read_va(data, secs, 0x55f2269, 4))[0]
    expand_input_offset = struct.unpack('<I', read_va(data, secs, 0x548d236, 4))[0]
    expand_field_stack = struct.unpack('<I', read_va(data, secs, 0x548d245, 4))[0]
    expand_output_stack = struct.unpack('<I', read_va(data, secs, 0x548d843, 4))[0]
    expand_output_size = struct.unpack('<I', read_va(data, secs, 0x548d848, 4))[0]
    clone_limit = struct.unpack('<Q', read_va(data, secs, 0x58441b2, 8))[0]
    clone_stride = struct.unpack('<I', read_va(data, secs, 0x58442b0, 4))[0]
    clone_marker = struct.unpack('<Q', read_va(data, secs, 0x55f0153, 8))[0]
    tree_limit = read_va(data, secs, 0x522ed20, 1)[0]
    key_size, key_align = struct.unpack('<QQ', read_va(data, secs, 0x649a798, 16))
    value_size, value_align = struct.unpack('<QQ', read_va(data, secs, 0x649c7c0, 16))
    option_size, option_align = struct.unpack('<QQ', read_va(data, secs, 0x6478800, 16))
    field_size, field_align = struct.unpack('<QQ', read_va(data, secs, 0x64a8410, 16))
    if (map_offset, capture_offset, root_stride, root_value_offset, option_offset,
            key_size, key_align, value_size, value_align, option_size, option_align,
            field_size, field_align, json_result_offset, binary_result_offset, json_header,
            nested_output_payload, nested_copy_length, outer_copy_length,
            materialize_input_offset, materialize_output_offset,
            clone_input_offset, clone_output_offset, expand_input_offset, expand_field_stack,
            expand_output_stack, expand_output_size, clone_limit, clone_stride, clone_marker, tree_limit,
            binary_child_base, binary_copy1_source, binary_copy1_dest, binary_copy1_length,
            binary_copy2_dest, binary_copy2_source, binary_copy2_length, binary_copy3_length) != (
            0x4b18, 0x4b18, 48, 24, 8, 20, 1, 24, 8, 12, 4, 32, 8, 0x2488, 0x2488, 16,
            16, 0x2798, 0x27a8, 0x2488, 0x3fa8,
            0x3fa8, 0x3fa8, 0x3fa8, 0x6238, 0x1720, 0x4e38,
            0x2aaaaaaaaaaaaaa, 48, 0x8000000000000000, 11, 0x4060, 0x4088, 0x9820, 0x2780,
            0x1098, 0x97f8, 0x27a8, 0x27a8):
        raise ValueError('field or descriptor layout mismatch')
    if expand_field_stack - expand_output_stack != map_offset or map_offset + field_size > expand_output_size:
        raise ValueError('expanded field offset or extent mismatch')
    nested_offset = project_range(json_header, nested_output_payload, nested_copy_length,
                                  json_result_offset, field_size)
    json_outer_offset = project_range(0, 0, outer_copy_length, nested_offset, field_size)
    binary_stage1_field = project_range(binary_copy1_source, binary_copy1_dest, binary_copy1_length,
                                        binary_child_base + binary_result_offset, field_size)
    binary_stage2_field = project_range(binary_copy2_source, binary_copy2_dest, binary_copy2_length,
                                        binary_stage1_field, field_size)
    binary_outer_offset = project_range(binary_copy2_dest, 0, binary_copy3_length,
                                        binary_stage2_field, field_size)
    if json_outer_offset != materialize_input_offset or materialize_output_offset != clone_input_offset:
        raise ValueError('selected field handoff offset mismatch')
    if binary_outer_offset != materialize_input_offset:
        raise ValueError('selected binary field handoff offset mismatch')
    layout = {'state_snapshot_offset': hex(map_offset), 'state_root_capture_offset': hex(capture_offset),
              'json_visitor_result_field_offset': hex(json_result_offset),
              'binary_visitor_result_field_offset': hex(binary_result_offset),
              'binary_first_staging_field_offset': hex(binary_stage1_field),
              'binary_second_staging_field_offset': hex(binary_stage2_field),
              'binary_parent_result_field_offset': hex(binary_outer_offset),
              'json_outer_payload_header_bytes': json_header,
              'json_nested_output_payload_offset': nested_output_payload,
              'json_nested_copy_bytes': nested_copy_length,
              'json_outer_copy_bytes': outer_copy_length,
              'json_exchange_payload_field_offset': hex(json_outer_offset),
              'materialize_input_field_offset': hex(materialize_input_offset),
              'materialize_output_field_offset': hex(materialize_output_offset),
              'clone_input_field_offset': hex(clone_input_offset),
              'clone_output_field_offset': hex(clone_output_offset),
              'expanded_staging_field_offset': hex(expand_field_stack),
              'expanded_staging_base': hex(expand_output_stack),
              'expanded_output_size': expand_output_size,
              'clone_element_stride': clone_stride, 'clone_count_max': clone_limit,
              'clone_tree_marker': hex(clone_marker),
              'tree_node_insert_limit': tree_limit,
              'pair_stride_bytes': root_stride, 'pair_key_offset': 0, 'pair_value_offset': root_value_offset,
              'value_count_offset': 0, 'value_option_offset': option_offset,
              'key_descriptor': {'size': key_size, 'alignment': key_align},
              'value_descriptor': {'size': value_size, 'alignment': value_align},
              'option_descriptor': {'size': option_size, 'alignment': option_align},
              'field_descriptor': {'size': field_size, 'alignment': field_align},
              'small_sort_exclusive_limit': small_limit, 'compact_max_count': compact_limit,
              'note': 'Offsets describe selected code paths; identity across separate state objects is unproved.'}

    marker_rows = []
    for marker in range(256):
        kind, count = marker_kind(marker, map_min, array_min, other_min, marker_mask)
        marker_rows.append([hex(marker), kind, '' if count is None else count])
    model_rows = []
    for n in (0, 1, 2, 20, 21, 64, 65):
        for duplicate in ((False, True) if n >= 2 else (False,)):
            sort, storage = map_plan(n, duplicate, small_limit, compact_limit)
            model_rows.append([n, int(duplicate), sort, storage])
    writer_rows = []
    for count in (0, 1, (1 << 64) - 1):
        for tag in (0, 1, (1 << 32) - 1):
            n, keys = writer_choice(count, tag)
            writer_rows.append([count, tag, n, keys])
    event_inputs = [[], [('t', 0)], [('n', 0)], [('t', 1), ('n', 7)],
                    [('t', 0), ('t', 1)], [('n', 0), ('n', 7)], [('n', 7), ('t', 1)]]
    event_rows = []
    for events in event_inputs:
        status, count, tag = field_events(events)
        event_rows.append([','.join(f'{key}={value}' for key, value in events), status, count, tag])
    clone_rows = []
    for n in (0, 1, clone_limit - 1, clone_limit, clone_limit + 1, (1 << 64) - 1):
        outcome, size = clone_count_case(n, clone_limit, clone_stride)
        clone_rows.append([n, outcome, '' if size is None else size])
    mode_rows = []
    for word, length, pointer in ((0, 0, 0), (0, 1, 0), (clone_marker, 0, 0),
                                  (clone_marker, 0, 8), (clone_marker, 1, 0),
                                  (clone_marker, 1, 8), (clone_marker + 1, 1, 0)):
        mode_rows.append([hex(word), length, pointer, clone_representation(word, length, pointer, clone_marker)])
    node_rows = [[n, node_insert_case(n, tree_limit)] for n in (0, tree_limit - 1, tree_limit, (1 << 16) - 1)]

    summary = {'target_release': 'node 115', 'binary_sha256': digest,
               'coordinate_system': 'unrelocated ELF virtual addresses and file offsets',
               'source_location': loc, 'selected_fde_count': len(funcs),
               'selected_window_count': len(window_rows), 'selected_transfer_count': len(edge_rows),
               'selected_branch_count': len(branch_rows), 'selected_relocation_count': len(relocation_rows),
               'selected_import_count': len(imports),
               'selected_literal_count': len(literals), 'json_table_entries': len(dispatch_rows),
               'marker_models': len(marker_rows), 'map_models': len(model_rows),
               'writer_models': len(writer_rows), 'event_models': len(event_rows),
               'clone_models': len(clone_rows), 'clone_mode_models': len(mode_rows),
               'node_models': len(node_rows),
               'limitations': 'Selected static paths only; no execution, complete CFG, final digest, or component coverage.'}
    files = {
        'functions.tsv': tsv(['role', 'start_va', 'end_va_exclusive', 'file_offset', 'length',
                              'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'sha256'], funcs),
        'windows.tsv': tsv(['label', 'scope', 'va', 'file_offset', 'length', 'bytes_hex'], window_rows),
        'transfers.tsv': tsv(['label', 'scope', 'va', 'file_offset', 'bytes_hex', 'target_va'], edge_rows),
        'branches.tsv': tsv(['label', 'scope', 'va', 'file_offset', 'bytes_hex', 'target_va'], branch_rows),
        'relocations.tsv': tsv(['label', 'scope', 'slot_va', 'record_file_offset', 'type', 'symbol', 'addend', 'bytes_hex'], relocation_rows),
        'imports.tsv': tsv(['scope', 'slot_va', 'relocation_file_offset', 'type', 'symbol_index', 'symbol_file_offset',
                            'section_index', 'symbol_name', 'relocation_hex', 'symbol_hex'], imports),
        'literals.tsv': tsv(['label', 'va', 'file_offset', 'length', 'bytes_hex', 'ascii'], literals),
        'json-dispatch.tsv': tsv(['index', 'input_byte', 'entry_va', 'bytes_hex', 'target_va'], dispatch_rows),
        'marker-cases.tsv': tsv(['input_byte', 'selected_class', 'count'], marker_rows),
        'map-cases.tsv': tsv(['count', 'adjacent_duplicate', 'sort', 'result'], model_rows),
        'writer-cases.tsv': tsv(['count_word', 'option_dword', 'fields', 'keys_in_order'], writer_rows),
        'field-events.tsv': tsv(['already_decoded_events', 'result', 'count_word', 'option_dword'], event_rows),
        'clone-cases.tsv': tsv(['input_count', 'guard_outcome', 'allocation_size'], clone_rows),
        'clone-mode-cases.tsv': tsv(['first_word', 'tree_length', 'tree_pointer', 'selected_branch'], mode_rows),
        'node-cases.tsv': tsv(['node_length', 'insert_branch'], node_rows),
        'layout.json': json_text(layout), 'summary.json': json_text(summary),
    }
    return files


def compare_historical(old, current):
    """Optional authenticated cross-release comparison of two bounded windows."""
    digest_checked(old, OLD_SHA256)
    old_secs, old_unwind = unwind_index(old)
    _, old_fdes = eh_frame_records(old, old_secs)
    old_map = [f for f in old_fdes if f['start'] == 0x4c64890]
    old_index = [u for u in old_unwind if u['start'] == 0x4c64890]
    if len(old_map) != 1 or len(old_index) != 1 or old_map[0]['end'] != 0x4c64a96 or old_map[0]['fde'] != old_index[0]['fde']:
        raise ValueError('historical FDE mismatch')
    old_location = read_location(old, old_secs, relative_relocations(old, old_secs), 0x56dfbf8)
    if (old_location['line'], old_location['column'], old_location['source_length']) != (107, 37, 49):
        raise ValueError('historical Location mismatch')
    current_secs = sections(current)
    old_bytes = read_va(old, old_secs, 0x4c648b1, 20)
    new_bytes = read_va(current, current_secs, 0x4d93401, 20)
    if old_bytes != new_bytes or old_bytes.hex() != '8b6e084c8b3e31d24d85ff0f95c283fd0183daff':
        raise ValueError('historical writer window mismatch')
    old_insert = read_va(old, old_secs, 0x363f1e9, 5)
    if old_insert.hex() != 'e882f1d5ff' or decode_transfer(0x363f1e9, old_insert) != 0x339e370:
        raise ValueError('historical JSON insertion witness mismatch')
    old_result = read_va(old, old_secs, 0x363f1ee, 11)
    if old_result.hex() != '48833c24000f8427ffffff' or decode_transfer(0x363f1f3, old_result[5:]) != 0x363f120:
        raise ValueError('historical insertion-result witness mismatch')
    old_location_ref = read_va(old, old_secs, 0x3273856, 7)
    if old_location_ref.hex() != '488d0d9bc34602' or decode_transfer(0x3273856, old_location_ref) != 0x56dfbf8:
        raise ValueError('historical Location reference mismatch')
    return {'historical_release': 'node 94', 'historical_sha256': OLD_SHA256,
            'historical_location': old_location, 'historical_writer_va': '0x4c648b1',
            'current_writer_va': '0x4d93401', 'window_length': len(old_bytes),
            'raw_window_hex': old_bytes.hex(), 'raw_equal': True,
            'historical_json_insert_site': '0x363f1e9',
            'historical_json_insert_target': hex(decode_transfer(0x363f1e9, old_insert)),
            'historical_insert_result_bytes': old_result.hex(),
            'historical_zero_result_target': hex(decode_transfer(0x363f1f3, old_result[5:])),
            'historical_location_reference': '0x3273856',
            'limits': 'Selected windows only; no whole-function or cross-release behavioral equivalence.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='directory for deterministic evidence')
    parser.add_argument('--historical', type=Path, help='optional separately authenticated node-94 ELF')
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    files = collect(data)
    old_result = compare_historical(args.historical.read_bytes(), data) if args.historical else None
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (args.out / name).write_text(files[name], encoding='utf-8', newline='\n')
    if old_result is not None:
        print(json_text(old_result), end='')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print('abci_cancel_state115: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
