#!/usr/bin/env python3
"""Extract selected node 115 EVM checkpoint/hash evidence without executing it."""
import argparse
import bisect
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Names are research labels. The intervals are independently decoded FDEs.
FUNCTIONS = [
    ('outer_checkpoint', 0x518d140, 0x518d271),
    ('checkpoint_select', 0x3915d30, 0x391601f),
    ('save_current', 0x38c2e00, 0x38c3231),
    ('choose_directory', 0x1692ff0, 0x1693220),
    ('persist_three', 0x38c2580, 0x38c268f),
    ('json_outer_fields', 0x38c2230, 0x38c257b),
    ('json_inner_fields', 0x36c5cf0, 0x36c5f1b),
    ('json_hash_field', 0x46545c0, 0x4654657),
    ('json_byte_array', 0x4670ae0, 0x4670e8f),
    ('parse_file', 0x422e730, 0x422eab5),
    ('parse_json_tail', 0x3ef1790, 0x3ef18a5),
    ('parse_outer_hashes', 0x411f770, 0x412031d),
    ('parse_inner_hash', 0x40833f0, 0x4083f8c),
    ('parse_hash_sequence', 0x3fd2880, 0x3fd2cc1),
    ('end_hash_sequence', 0x3ef3560, 0x3ef3660),
    ('parse_hash_byte', 0x3f86140, 0x3f862be),
    ('decode_string_boundary', 0x5c56f10, 0x5c571ca),
    ('write_file', 0x422f030, 0x422f314),
    ('load_selected', 0x38c2690, 0x38c2a3e),
    ('prefix_a', 0x3d4cbe0, 0x3d4d000),
    ('prefix_c', 0x3d4c7c0, 0x3d4cbe0),
    ('prefix_s', 0x3d4d000, 0x3d4d420),
    ('construct_a', 0x3c27f30, 0x3c28210),
    ('construct_c', 0x3c284f0, 0x3c287d0),
    ('construct_s', 0x3c28210, 0x3c284f0),
    ('scan_a', 0x3d4acf0, 0x3d4b40c),
    ('scan_s', 0x3d4a640, 0x3d4ace4),
    ('scan_c', 0x3d4b410, 0x3d4bb8e),
    ('fold_a_batch', 0x3d4be10, 0x3d4c08f),
    ('fold_c_batch', 0x3d4bb90, 0x3d4be0f),
    ('fold_s_batch', 0x3d4c090, 0x3d4c30f),
]
WINDOWS = [
    ('outer_entry', 0x518d159, '4989f64889fb488d7c2438ff1536c43501'),
    ('outer_trailing_branches', 0x518d16a, '31c0493b86201b0000712e4983be381b0000007450498b86281b00004885c00f84b8000000498b96301b00004889e74889c6e8dfbd0900eb3d4981c6201b00004889e74c89f6e87b4e6a00'),
    ('outer_trailing_sentinel', 0x518d1cf, '48c704240000000048c74424100000000049be0000000000000080488b4424104889442430488b04244889442420488b4424084889442428'),
    ('outer_null_failure', 0x518d247, '488d3d6a6c3101ff15dc2535010f0b'),
    ('outer_copy', 0x518d207, '488d742438ba201b00004889dfff15ee2235014c89b3201b00000f284424200f1183281b0000488b442430488983381b0000'),
    ('checkpoint_entry_save', 0x3915d41, '4989cc4889d54989f74889fb488dbc248000000031c9ff157304bd02'),
    ('list_read_error', 0x3915d5d, '498bb7181b00004883c610488d7c2410e8be30b500488b4c24104889c848f7d80f80be010000'),
    ('list_count', 0x3915d97, '4889c348c1e3054a8d142b4c896c241048894c247048894c24204c896c241848895424284885c00f84b8010000'),
    ('row_match', 0x3915de0, '4d39f775304983c4204c39e30f84800100004f8b7c25004b396c251874e24d85ff74e24b8b7c25084c89fe31d2ff158d96bc02ebd0'),
    ('selected_row', 0x3915e15, '4b8b4425184889442460430f104425080f114424504c897c2448'),
    ('open_selected', 0x3915e88, '488b4424080f10000f1048100f1050200f295424300f294c24200f29442410488dbc2498000000488d742410e877d9f9ff488b5c2478488dbc24c8000000488d742448488d94249800000031c9e80623b500488dbc24c800000031f6e8e7dbf9ff488d5424484889df4889c6ff152e36bd02'),
    ('unwrap_and_missing', 0x3915f41, '488b4424184889442448488d3dc6b6e8fc488d0d9f8bb5024c8d05088db502488d542448be2b000000ff153097bc02eb17488b4424684889442418488d3dfd8cb502ff15a798bc02'),
    ('save_three_state_inputs', 0x38c2e4f, '498db7f8000000488dac24f80700004c8b35a3c6c102ba100800004889ef41ffd6498db7000a0000488dbc2408100000ba1008000041ffd6498db708130000488dbc2418180000ba1008000041ffd6'),
    ('save_first_digest_input', 0x38c2f4f, 'ba000800004c89e74889ee41ffd5488b2db4c5c102488d7c24204c89e6ffd5'),
    ('save_second_digest_input', 0x38c3011, 'ba000800004c89e7488db4240810000041ffd5488d7c24204c89e6ffd5'),
    ('save_third_digest_input', 0x38c30d1, 'ba000800004c89e7488db4241818000041ffd5488d7c24204c89e6ffd5'),
    ('save_select_path', 0x38c30ee, '498bb7181b00004883c6104c8b7424184d85f674234889f74c89f64889dab902000000e88afbdcfd4885db793831ff4889deff1572c3c102488dbc24f8070000488b542408ff1547efc102'),
    ('save_persist_output', 0x38c3189, '4c89ff4c89ee4c89e2e8e9f3ffff488b4424104889184c8968084c896010'),
    ('path_create_branch', 0x1692ff0, '55415741564154534881ecb00000004989d74989f64889fb4889e7e8a0faffff488b542408488b4c2410488d7c2418be02000000e8673b00004c8b642420488b7424284c89e7ff1514d9e40489c5488b7424184885f6740b4c89e731d2ff154dc4e4044084ed0f850c0100008b0576d1e50485c00f8529010000'),
    ('path_create_call', 0x1693129, '488d7c24184c89f64c89fae877f9ffff4c8b7c2420488b5424284c89f74c89feb902000000e84dfbffff488b7424184885f6740b4c89ff31d2ff1538c3e4044080f501488b442410488943100f1004240f110340886b18'),
    ('persist_input_copies', 0x38c25d5, '488db3f80000004c8d7424304c8b3d20cfc102ba100800004c89f741ffd7488db3000a0000488dbc2440080000ba1008000041ffd74881c308130000488dbc2450100000ba100800004889de41ffd7'),
    ('persist_call_and_drop_error', 0x38c2624, '488b5c2410488b542418488d0dcbc1ba024c89f74889dee8f0c996004885c07408488b084889c7ff11488b7424084885f6740b4889df31d2ff153ecec102'),
    ('persist_unwind', 0x38c266f, '4989c6488b7424084885f6740b4889df31d2ff1519cec1024c89f7e8c1e3b202'),
    ('load_file_call', 0x38c2709, '488d050075ddfd4889842438090000488d35aaccb8fc4889e7488d942430090000ff15b8cfc102488b742408488b542410488d0dd7c0ba02488dbc2430090000e8e2bf960083bc2430090000017557'),
    ('load_error_tags', 0x38c2758, '4c8bac243809000048c784245024000000000000488dbc2470350000488dac24502400004c8b3585cdc102ba180800004889ee41ffd6488dbc24883d0000ba180800004889ee41ffd6498b45004c89efff10e987000000'),
    ('load_cached_tags', 0x38c27cd, '488db42438090000488dbc24783500004c8b3524cdc102ba1008000041ffd648c784247035000001000000488dbc24903d0000ba100800004889ee41ffd648c78424883d000001000000488dbc2458240000ba100800004c89ee41ffd648c784245024000001000000'),
    ('load_prefix_a', 0x38c2836, '4c8d6b10488dbc2430090000be1a0000004c89eae891a34800488dbc24a0450000488db42430090000488d942470350000e8c4563600'),
    ('load_prefix_c', 0x38c286c, '488dbc2430090000be1b0000004c89eae83f9f4800488dbc24682c0000488db42430090000488d9424883d0000e8525c3600'),
    ('load_prefix_s', 0x38c289e, '488dbc2430090000be1c0000004c89eae84da74800488d7c2428488db42430090000488d942450240000e843593600'),
    ('load_join_three', 0x38c28cd, '4c8dac2430090000488db424a04500004c8b3524ccc102ba080900004c89ef41ffd6488dbc2438120000488db424682c0000ba0809000041ffd6488dbc24401b0000488d742428ba0809000041ffd648899c24482400004c89ef4c89fe4c89e2e84efcffff488db42430090000ba201b0000488b5c24184889dfff15bbcbc102'),
    ('read_error_tag', 0x422e908, '488d7c24084c89f6e85b0200004889430848c70301000000'),
    ('read_parse_error', 0x422e97a, 'e8112eccff4c8ba4248800000083bc2480000000010f85a6000000488d7c24084c89e6e84e0200004889430848c70301000000'),
    ('read_success_tag', 0x422ea3b, '488db42490000000488d7b10ba28180000ff15b60a2b024c89630848c70300000000'),
    ('prefix_lookup_a', 0x3d4ccb9, '488d0530d172024e8b24f8bf02000000ff15b12779024885c00f84b80200004989c7410fb7042466418907'),
    ('prefix_lookup_c', 0x3d4c899, '488d0550d572024e8b24f8bf02000000ff15d12b79024885c00f84b80200004989c7410fb7042466418907'),
    ('prefix_lookup_s', 0x3d4d0d9, '488d0510cd72024e8b24f8bf02000000ff15912379024885c00f84b80200004989c7410fb7042466418907'),
    ('reuse_a', 0x3c27f56, '8b057c828c02833a01753b85c00f85ba0100004883c2084c8b2594758b024989d7baf80000004889df4c89f641ffd4488dbbf8000000ba100800004c89fe41ffd4e97201000085c00f85cb010000'),
    ('rebuild_a', 0x3c27fa4, 'bf01000000e832c305024989c789d54d8d66204c8d6c2470ba100800004c89ef31f6ff1584778b02488dbc2488080000ba40420f004c89e64c89e9e80c2d1200'),
    ('reuse_s', 0x3c28236, '8b059c7f8c02833a01753b85c00f85ba0100004883c2084c8b25b4728b024989d7baf80000004889df4c89f641ffd4488dbbf8000000ba100800004c89fe41ffd4e97201000085c00f85cb010000'),
    ('rebuild_s', 0x3c28284, 'bf01000000e852c005024989c789d54d8d66204c8d6c2470ba100800004c89ef31f6ff15a4748b02488dbc2488080000ba40420f004c89e64c89e9e87c231200'),
    ('reuse_c', 0x3c28516, '8b05bc7c8c02833a01753b85c00f85ba0100004883c2084c8b25d46f8b024989d7baf80000004889df4c89f641ffd4488dbbf8000000ba100800004c89fe41ffd4e97201000085c00f85cb010000'),
    ('rebuild_c', 0x3c28564, 'bf01000000e872bd05024989c789d54d8d66204c8d6c2470ba100800004c89ef31f6ff15c4718b02488dbc2488080000ba40420f004c89e64c89e9e86c2e1200'),
    ('scan_buffer', 0x3d4ad38, 'ba100800004889ceff15c24779024c89f048c1e005488d344048b855555555555555014939c6760831ffff15304779024885f64c897c2438741f4889f34889f7ff15024779024885c07516bf080000004889deff1507477902'),
    ('scan_prefix_test', 0x3d4ae87, '4c89ff41ffd684c00f848503000048c78424d0080000000000004c89ff488db424d0080000ff15fe7179024885c00f845f030000488bac24d00800004939ed0f874e0300004889c34889c74c89e64c89eaff151a4b790285c00f8534030000'),
    ('scan_key_width_20', 0x3d4aee6, '498d45144839c5488dac24c00000000f8575ffffff428b442b1089442450f3420f6f042b660f7f442440'),
    ('scan_parse_branch', 0x3d4af44, '488b9424d00800004889ef4889c6e8d9d3ffff83bc24c0000000017542488b8424c80000004883f8020f82fdfeffff488bb424d00000000f84e7feffff488bbc24d80000004883f8034885f60f84dafeffff31d2ff1502457902e9cdfeffff'),
    ('scan_push_flush', 0x3d4b068, '488b5c2420483b5c2410750b488d7c2410ff1521e67902488b542418488d045b48c1e0050f288424100100000f114402500f288424000100000f11440240660f6f8424c0000000660f6f8c24d0000000660f6f9424e00000000f289c24f00000000f115c0230f30f7f540220f30f7f4c0210f30f7f040248ffc348895c2420483b5c24280f827efdffff4889ef488d7424604889d9e80e0d0000'),
    ('scan_counter_saturation', 0x3d4b132, '488b8424d010000048038424e01800004889c148c7c2ffffffff480f42ca480f43c8488b8424d810000048898c24d010000048038424e81800004889c1480f42ca480f43c848898c24d8100000'),
    ('scan_lanes', 0x3d4b190, 'f30f6f8444d0080000660f6fc8660f71d108660f71f008660febc1f30f6f8c44e0100000660f6fd1660f71d208660f71f108660febca660ffdc8660f6fc1660f71d008660f71f108660febc8f30f7f8c44d00800004883c008483d00040000759f'),
    ('scan_tail', 0x3d4b21a, '488b4c24204885c94c8b7424380f841f010000488b542418488dbc24c0000000488d742460e8cc0b0000'),
    ('scan_null_iterator', 0x3d4b3aa, '488d3df7847402ff15794479020f0b'),
    ('fold_counter_saturation', 0x3d4bf54, '488b84241808000048038424281000004889c1490f42cc480f43c8488b84242008000048898c241808000048038424301000004889c1490f42cc480f43c848898c2420080000'),
    ('fold_lanes', 0x3d4bfa0, 'f30f6f444418660f6fc8660f71d108660f71f008660febc1f30f6f8c4448180000660f6fd1660f71d208660f71f108660febca660ffdc8660f6fc1660f71d008660f71f108660febc8f30f7f4c44184883c008483d0004000075a5'),
    ('writer_route', 0x422f118, '488d15c66823fcb903000000e8770b37fd84c0747148c704240000000048c74424080100000048c7442410000000004c89ac2488000000c784249000000000040001c684249400000000488d7c2438488d9424880000004c89e6e8392f69ff4c8b64243848b800000000000000804883c8044939c4'),
    ('writer_return', 0x422f241, '4d85ed74144c89e74c89ee31d24889c3ff1549022b024889d84881c4980000005b415c415d415e415f5d'),
]

WINDOWS += [
    ('scan_s_key_predicate', 0x3d4a801, '4c8bb424d00000004d39f50f87e80200004889c34889c7488b7424484c89eaff15d251790285c00f85cc020000498d45344939c60f8575ffffff'),
    ('scan_s_key_fields', 0x3d4a82e, '498d45344939c60f8575ffffff428b442b1089442460f3420f6f042b660f7f4424504a8b442b1448894424404e8b642b1c4e8b742b244a8b6c2b2c'),
    ('scan_s_value_parse', 0x3d4a8a0, '488b9424d0000000488dbc24d00000004889c6e8c8d8ffff83bc24d0000000017542488b8424d80000004883f8020f82dcfeffff488bb424e00000000f84befeffff488bbc24e80000004883f8034885f60f84b9feffff31d2ff15a14b7902e9acfeffff'),
    ('scan_s_row_transform', 0x3d4a954, '480fcd490fce490fcc488b4c2440480fc9488b542418486bc35848892c024c897402084c8964021048894c02188b8c24e0000000894c02300f288424d00000000f11440220660f6f8424f0100000660f6f8c2400110000f30f7f440238f30f7f4c0248'),
    ('scan_s_push_flush', 0x3d4a9b7, '48ffc348895c2420483b5c24280f82e6fdffff4c8db424f01000004c89f7488d7424704889d9e8ae160000'),
    ('scan_s_counters', 0x3d4aa12, '488b8424d008000048038424e01000004889c148c7c2ffffffff480f42ca480f43c8488b8424d808000048898c24d008000048038424e81000004889c1480f42ca480f43c848898c24d8080000'),
    ('scan_s_lanes', 0x3d4aa70, 'f30f6f8444d0000000660f6fc8660f71d108660f71f008660febc1f30f6f8c44e0080000660f6fd1660f71d208660f71f108660febca660ffdc8660f6fc1660f71d008660f71f108660febc8f30f7f8c44d00000004883c008483d00040000759f'),
    ('scan_c_key_predicate', 0x3d4b5db, '488bac24a00000004939ed0f87d60200004889c34889c74c89e64c89eaff15fa43790285c00f85bc020000498d45204839c57581'),
    ('scan_c_key_fields', 0x3d4b606, '498d45204839c57581f3420f6f042bf3420f6f4c2b10660f7f8c24d0100000660f7f8424c0100000'),
    ('scan_c_value_parse', 0x3d4b662, '488b9424a0000000488dbc24a00000004889c6e876ceffff488b8424a00000004883f8050f85fb010000'),
    ('scan_c_push_flush', 0x3d4b6bc, '488b5c2420483b5c2410750b488d7c2410ff15d5df7902488b542418488d049b488b8c24c000000048894cc220660f6f8424a0000000660f6f8c24b0000000f30f7f4cc210f30f7f04c248ffc348895c2420483b5c24280f8277feffff488dac24c01000004889ef488d7424404889d9e85f040000'),
    ('scan_c_counters', 0x3d4b761, '488b8424a008000048038424b01000004889c148c7c2ffffffff480f42ca480f43c8488b8424a808000048898c24a008000048038424b81000004889c1480f42ca480f43c848898c24a8080000'),
    ('scan_c_lanes', 0x3d4b7b0, 'f30f6f8444a0000000660f6fc8660f71d108660f71f008660febc1f30f6f8c44b0080000660f6fd1660f71d208660f71f108660febca660ffdc8660f6fc1660f71d008660f71f108660febc8f30f7f8c44a00000004883c008483d00040000759f'),
    ('writer_emit_boundary', 0x422f200, '4885c075674c8b2c244c8b6424084c89e848f7d8706c488b6c24104c89ff4c89f6ff15010e2b024885c075154c89e74889ee4c89fa4c89f14989d8ff15a7172b02'),
    ('writer_error_paths', 0x422f26c, '488b34244885f6740d488b7c240831d2ff151e022b02488d7c24784c89e6e8e1030000ebc9488b5c24404c8b742448488b34244885f6740d488b7c240831d2ff15ef012b024c8964243848895c24404c89742448488d7c2478488d742438e871040000eb89'),
]

WINDOWS += [
    ('fold_a_record_producer', 0x3d4be99, '488dbc2438100000488d742418e815060500488b8424381000004889442408488b84244010000048890424488b9c2448100000488dbc2458200000ba100800004c89f6ff15263679024885db'),
    ('fold_c_record_producer', 0x3d4bc19, '488dbc2438100000488d742418e855180500488b8424381000004889442408488b84244010000048890424488b9c2448100000488dbc2458200000ba100800004c89f6ff15a63879024885db'),
    ('fold_s_record_producer', 0x3d4c119, '488dbc2438100000488d742418e865190500488b8424381000004889442408488b84244010000048890424488b9c2448100000488dbc2458200000ba100800004c89f6ff15a63379024885db'),
    ('fold_a_next_record', 0x3d4c009, '4981c6100800004939de0f8507ffffff'),
    ('fold_c_next_record', 0x3d4bd89, '4981c6100800004939de0f8507ffffff'),
    ('fold_s_next_record', 0x3d4c289, '4981c6100800004939de0f8507ffffff'),
    ('fold_c_counters', 0x3d4bcd4, '488b84241808000048038424281000004889c1490f42cc480f43c8488b84242008000048898c241808000048038424301000004889c1490f42cc480f43c848898c2420080000'),
    ('fold_c_lanes', 0x3d4bd20, 'f30f6f444418660f6fc8660f71d108660f71f008660febc1f30f6f8c4448180000660f6fd1660f71d208660f71f108660febca660ffdc8660f6fc1660f71d008660f71f108660febc8f30f7f4c44184883c008483d0004000075a5'),
    ('fold_s_counters', 0x3d4c1d4, '488b84241808000048038424281000004889c1490f42cc480f43c8488b84242008000048898c241808000048038424301000004889c1490f42cc480f43c848898c2420080000'),
    ('fold_s_lanes', 0x3d4c220, 'f30f6f444418660f6fc8660f71d108660f71f008660febc1f30f6f8c4448180000660f6fd1660f71d208660f71f108660febca660ffdc8660f6fc1660f71d008660f71f108660febc8f30f7f4c44184883c008483d0004000075a5'),
]

WINDOWS += [
    ('outer_field_accounts', 0x38c2285, '488d3596f1edfc488d7c2408ba0d000000e80519e500807c2408010f84ee0100004c8b7424104d8b3e498b07498b77104829f04883f8010f8615020000498b470866c704303a204883c602498977104889df4c89f6e8113ae0ff'),
    ('outer_field_contracts', 0x38c22ed, '488d353bf1edfc488d7c2408ba0e000000e89d18e500807c2408010f8486010000488dbb100800004c8b7424104d8b3e498b07498b77104829f04883f8010f86c7010000498b470866c704303a204883c602498977104c89f6e8a539e0ff'),
    ('outer_field_storage', 0x38c2359, '488d35ddf0edfc488d7c2408ba0c000000e83118e500807c2408010f841a0100004881c3201000004c8b7424104d8b3e498b07498b77104829f04883f8010f8682010000498b470866c704303a204883c602498977104889df4c89f6e83639e0ff'),
    ('inner_hash_fields', 0x36c5d44, '488d8b00080000488d35427d0dfd4889e7ba0a000000e8c12ef8004885c00f8542010000803c24000f8504010000488d8b08080000488d351e7d0dfd4889e7ba07000000e8932ef8004885c00f8514010000803c24000f85d6000000488d350d41d9fc4889e7ba040000004889d9e809e8f800'),
    ('hash_2048_argument', 0x46545ff, '498d7e08b9000800004c89f64889dae8cdc40100'),
    ('writer_json_dispatch', 0x422f1c8, '4c896c2438488d05ca8e59fc488944244048c74424480200000048c744245000000000c644245800488d7424384c89e7e8333069ff4989c44885c0'),
    ('scan_c_value_failure', 0x3d4b887, '83f8020f8200fdffff488bb424a800000083f8020f84e2fcffff488bbc24b000000083f8034885f60f84dbfcffff31d2ff15e33b7902e9cefcffff'),
]

WINDOWS += [
    ('array_open', 0x4670aee, '488914244c8b7f104983ffff0f8482030000488b1e498d4701488944241048894710c64718004c8b73104c39330f840d030000488b430842c604305b49ffc64c8973104885c90f84a0020000'),
    ('array_byte_decimal', 0x4670c20, '488b04240fb6004883f86376330fb6c88d14898d0cd1c1e90c6bd16428d00fb6c0488d15469116fc0fb7044266894424314531ed89c8eb120f1f84000000000041bd020000003c0a73160c304288442c30eb23666666662e0f1f840000000000488d0d079116fc0fb70441668944243141bd01000000'),
    ('array_loop', 0x4670cb7, '488b7b084c01f74889ea4c8b2d40e8e60141ffd54901ee4c897310488b542420c642180131c0488b4c24284c893c244939cf4c8b7c24180f857cfeffffeb67'),
    ('array_close', 0x4670dda, '4c897f104c3933742a488b430842c604305d49ffc64c89731031c0'),
]

WINDOWS += [
    ('parse_inner_entry', 0x3ef1798, '0f10060f104e100f1056200f115424400f114c24300f1144242048c74424080000000048c74424100100000048c74424180000000066c74424500080488d742408e892df2200803b00755b'),
    ('parse_trailing_whitespace', 0x3ef17e3, '488b4c2428488b5424304839ca7347488b74242048f7d948ffc248bf002600000100000031c00f1f8000000000440fb64416ff4983f82077424c0fa3c7733c48895424304c8d041149ffc048ffc24983f80175d9eb0231c0488903'),
    ('parse_trailing_error', 0x3ef185e, '48c744245816000000488d7c2408488d742458e81a02000048894308b801000000ebba'),
]

WINDOWS += [
    ('outer_parse_dispatch', 0x411f7d2, '488b4e20488b46284839c87339498b561848ffc048f7d948bd00260000010000000fb67402ff4883fe207735480fa3f5732f49894628488d340148ffc648ffc04883fe0175db48c744245005000000488d7424504c89f7e86222ddffe90708000083fe5b0f84b600000083fe7b0f8589090000'),
    ('outer_duplicate_accounts', 0x411fb1c, '4883f80d0f852b010000498b450048b96163636f756e74734831c8498b4d0548334c24384809c10f850801000048837c2428010f84bd060000'),
    ('outer_duplicate_contracts', 0x411fbb0, '498b450048b9636f6e74726163744831c8498b4d0648ba6374735f686173684831d14809c1757a48837c2420010f844c060000'),
    ('outer_duplicate_storage', 0x411fc30, '498b450048b973746f726167655f4831c8418b4d084881f1686173684809c1747c'),
    ('outer_duplicate_storage_flag', 0x411fccd, '48837c2418010f841c050000'),
    ('outer_required_order', 0x411fe85, 'f6442428010f8449020000f6442420010f8481020000f6442418010f8493020000'),
    ('outer_missing_accounts', 0x41200d9, '488d05b11e6afc488984246808000048c78424700800000d000000eb5e'),
    ('outer_missing_contracts_storage', 0x412011c, '488d057b1e6afc488984246808000048c78424700800000e000000eb1b488d056c1e6afc488984246808000048c78424700800000c000000'),
    ('outer_duplicate_names', 0x41201f5, '488d05b01d6afc488984246808000048c78424700800000c000000eb38488d05781d6afc488984246808000048c78424700800000d000000eb1b488d05681d6afc488984246808000048c78424700800000e000000488d8424680800004889442450488d0592d55b004889442458488d3db03231fce905ffffff'),
    ('inner_duplicate_elements', 0x40837cc, '4883f90a0f8546010000488b0848ba6e5f656c656d656e4831d10fb740084835747300004809c80f852301000048837c2428010f8476060000'),
    ('inner_duplicate_bytes', 0x4083880, '8b08ba6e5f627931d18b4003ba7974657331d009c80f858100000048837c2420010f84b7050000'),
    ('inner_duplicate_hash', 0x408399e, 'f6442418010f85ef040000'),
    ('inner_required_order', 0x4083be4, 'f6442428010f847e010000f6442420010f84a8010000f6442418010f84ba010000'),
    ('inner_missing_names', 0x4083d6d, '488d05cae873fc488984246008000048c78424680800000a000000eb50488d35af783f02488d15b0753f02bf01000000e924ffffff488d059fe873fc488984246008000048c784246808000007000000eb1b488d05ee603dfc488984246008000048c784246808000004000000'),
    ('inner_duplicate_names', 0x4083e5e, '488d05e3e773fc488984246008000048c784246808000007000000eb38488d05bce773fc488984246008000048c78424680800000a000000eb1b488d0515603dfc488984246008000048c784246808000004000000488d8424600800004889442458488d05299965004889442460488d3d47f63afce922ffffff'),
]

WINDOWS += [
    ('inner_hash_parse_call', 0x40839f5, '4883fe3a0f85270400004885c00f84d004000049894424284889ef4c89e6e868eef4ff807c2458010f84d5faffff'),
    ('hash_input_kind', 0x3fd28bb, '48bf0026000001000000440fb604024983f822777d4c0fa3c7732e48ffc0498946284839c175e348c744243805000000488d7424384c89f7e898f1f1ff48894308c60301e9500200004983f82275434883f8ff0f843b03000048ffc04989462849c7461000000000488d7c24384c89f2ff15377d5102837c243802488b7424400f85ac01000048897308c60301e9070200004183f85b0f85ab020000'),
    ('hash_input_array_count', 0x3fd29d4, '498946284c89742428c644243001488d7c24384531ffba0008000031f6ff1559cd50024c8d6424184c8d6c24286666666666662e0f1f8400000000004c89e74c89eee815a1f7ff807c241801746d807c2419010f856b010000488b7424284c89e7e80637fbff807c241801744e0fb64424194288443c3849ffc74981ff0008000075b9'),
    ('hash_input_close', 0x3fd2ab1, '4c89f7e8a70af2ff4084ed0f85a70000004885c00f8516010000'),
    ('hash_input_string_count', 0x3fd2aed, '488b7c24484881ff000800000f852f010000'),
    ('hash_input_short_error', 0x3fd2b98, '488d15e1834a02488d7424074c89ffe8d4635d004989c740b50141807e48000f84e1feffff'),
    ('end_sequence_branches', 0x3ef3560, '4883ec18488b7720488b47284839f0733d488b4f1848ffc04989f049f7d848ba0026000001000000440fb64c01ff4983f92c777a4c0fa3ca7329488947284d8d0c0049ffc148ffc04983f90175da48c70424020000004889e6e8d2e4ffff4883c418c34983f92c75454885c00f848100000048894728'),
    ('end_sequence_brackets', 0x3ef360e, '4183f95d752a4885c0743a4889472831c04883c418c383fe5d751548c70424150000004889e6e857e4ffff4883c418c348c70424160000004889e6e842e4ffff4883c418c3'),
    ('u8_number_tags_range', 0x3f861e3, 'e858c2f6ff488b4c24284883f903753b488b44243048894308c603014883c4385b415ec3488d15c2504f02488d74240f4c89f7e895c8f6ff4889c74c89f6e81ab06e0048894308b001eb30488b44243083f901741983f902752b483d0001000072144889442418c644241002eb51483d00010000733f88430131c088034883c4385b415ec3'),
]

WINDOWS += [
    ('string_scan_delimiters', 0x5c56f64, '498b6e084d8b6e104d89ec4939ed0f84880000000f832c020000498b0e420fb604294d89ec83f82274724d89ec83f85c746a'),
    ('string_backslash', 0x5c57000, '4939ec0f84180100000f8388010000498b36420fb6042683f85c756b4c89e54c29ed498b07498b7f104829f84839c5771e'),
    ('string_borrowed_owned', 0x5c57087, '83f8220f859c000000498b7f104c89e54c29ed4885ff7462498b074829f84839c50f87b50000004d39ec74144c01ee49037f084889eaff1545848800498b7f104801ef49897f1049ffc44d896610498b4708488b5c240848c703010000004889430848897b10eb62488b5c24084889430848c70302000000eb5049ffc44c01ee4d896610488b5c240848c703000000004889730848896b10eb30'),
    ('string_error_cases', 0x5c57121, '48c744241004000000eb1049ffc44d89661048c744241010000000488d542410488b5c24084889df4c89f6e8aff4ffff'),
]

EDGES = [
    ('outer_to_selector', 0x518d164, 'ff1536c43501', 'slot', 0x64e95a0),
    ('outer_other_variant', 0x518d173, '712e', 'jcc', 0x518d1a3),
    ('outer_sentinel_empty', 0x518d17d, '7450', 'jcc', 0x518d1cf),
    ('outer_sentinel_null', 0x518d189, '0f84b8000000', 'jcc', 0x518d247),
    ('selector_to_save', 0x3915d57, 'ff157304bd02', 'slot', 0x64e61d0),
    ('list_error', 0x3915d7d, '0f80be010000', 'jcc', 0x3915f41),
    ('empty_list', 0x3915dbe, '0f84b8010000', 'jcc', 0x3915f7c),
    ('row_equal', 0x3915dfc, '74e2', 'jcc', 0x3915de0),
    ('row_present', 0x3915de3, '7530', 'jcc', 0x3915e15),
    ('list_exhausted', 0x3915dec, '0f8480010000', 'jcc', 0x3915f72),
    ('path_setup_a', 0x3915eb4, 'e877d9f9ff', 'call', 0x38b3830),
    ('path_setup_c', 0x3915ee4, 'e8e7dbf9ff', 'call', 0x38b3ad0),
    ('selector_to_load', 0x3915ef4, 'ff152e36bd02', 'slot', 0x64e9528),
    ('save_choose_path', 0x38c3133, 'ff1547efc102', 'slot', 0x64e2080),
    ('save_to_persist', 0x38c3192, 'e8e9f3ffff', 'call', 0x38c2580),
    ('write_call', 0x38c263b, 'e8f0c99600', 'call', 0x422f030),
    ('write_result_zero', 0x38c2643, '7408', 'jcc', 0x38c264d),
    ('file_read', 0x38c2749, 'e8e2bf9600', 'call', 0x422e730),
    ('read_success', 0x38c2756, '7557', 'jcc', 0x38c27af),
    ('choose_prefix_a', 0x38c284a, 'e891a34800', 'call', 0x3d4cbe0),
    ('construct_a', 0x38c2867, 'e8c4563600', 'call', 0x3c27f30),
    ('choose_prefix_c', 0x38c287c, 'e83f9f4800', 'call', 0x3d4c7c0),
    ('construct_c', 0x38c2899, 'e8525c3600', 'call', 0x3c284f0),
    ('choose_prefix_s', 0x38c28ae, 'e84da74800', 'call', 0x3d4d000),
    ('construct_s', 0x38c28c8, 'e843593600', 'call', 0x3c28210),
    ('load_to_persist', 0x38c292d, 'e84efcffff', 'call', 0x38c2580),
    ('parsed_variant', 0x422e98f, '0f85a6000000', 'jcc', 0x422ea3b),
    ('fallback_parse_variant', 0x422ea04, '752d', 'jcc', 0x422ea33),
    ('reuse_a_branch', 0x3c27f5f, '753b', 'jcc', 0x3c27f9c),
    ('scan_a_call', 0x3c27fdf, 'e80c2d1200', 'call', 0x3d4acf0),
    ('reuse_s_branch', 0x3c2823f, '753b', 'jcc', 0x3c2827c),
    ('scan_s_call', 0x3c282bf, 'e87c231200', 'call', 0x3d4a640),
    ('reuse_c_branch', 0x3c2851f, '753b', 'jcc', 0x3c2855c),
    ('scan_c_call', 0x3c2859f, 'e86c2e1200', 'call', 0x3d4b410),
    ('alloc_bound', 0x3d4ad5e, '7608', 'jcc', 0x3d4ad68),
    ('alloc_ok', 0x3d4ad81, '7516', 'jcc', 0x3d4ad99),
    ('null_iter', 0x3d4adeb, '0f84b9050000', 'jcc', 0x3d4b3aa),
    ('end_iter', 0x3d4ae59, '0f84bb030000', 'jcc', 0x3d4b21a),
    ('prefix_mismatch', 0x3d4aee0, '0f8534030000', 'jcc', 0x3d4b21a),
    ('key_width_mismatch', 0x3d4aef5, '0f8575ffffff', 'jcc', 0x3d4ae70),
    ('parse_success', 0x3d4af5f, '7542', 'jcc', 0x3d4afa3),
    ('threshold_continue', 0x3d4b0ec, '0f827efdffff', 'jcc', 0x3d4ae70),
    ('batch_fold', 0x3d4b0fd, 'e80e0d0000', 'call', 0x3d4be10),
    ('lane_loop', 0x3d4b1ef, '759f', 'jcc', 0x3d4b190),
    ('tail_fold', 0x3d4b23f, 'e8cc0b0000', 'call', 0x3d4be10),
    ('lane_fold_loop', 0x3d4bff9, '75a5', 'jcc', 0x3d4bfa0),
    ('fold_a_next', 0x3d4c013, '0f8507ffffff', 'jcc', 0x3d4bf20),
    ('fold_c_next', 0x3d4bd93, '0f8507ffffff', 'jcc', 0x3d4bca0),
    ('fold_s_next', 0x3d4c293, '0f8507ffffff', 'jcc', 0x3d4c1a0),
]

EDGES += [
    ('s_short_key', 0x3d4a80c, '0f87e8020000', 'jcc', 0x3d4aafa),
    ('s_prefix_mismatch', 0x3d4a828, '0f85cc020000', 'jcc', 0x3d4aafa),
    ('s_wrong_width', 0x3d4a835, '0f8575ffffff', 'jcc', 0x3d4a7b0),
    ('s_value_ok', 0x3d4a8c0, '7542', 'jcc', 0x3d4a904),
    ('s_threshold_continue', 0x3d4a9c4, '0f82e6fdffff', 'jcc', 0x3d4a7b0),
    ('s_batch_fold', 0x3d4a9dd, 'e8ae160000', 'call', 0x3d4c090),
    ('s_lane_loop', 0x3d4aacf, '759f', 'jcc', 0x3d4aa70),
    ('s_tail_fold', 0x3d4ab1f, 'e86c150000', 'call', 0x3d4c090),
    ('c_short_key', 0x3d4b5e6, '0f87d6020000', 'jcc', 0x3d4b8c2),
    ('c_prefix_mismatch', 0x3d4b600, '0f85bc020000', 'jcc', 0x3d4b8c2),
    ('c_wrong_width', 0x3d4b60d, '7581', 'jcc', 0x3d4b590),
    ('c_value_error', 0x3d4b686, '0f85fb010000', 'jcc', 0x3d4b887),
    ('c_threshold_continue', 0x3d4b713, '0f8277feffff', 'jcc', 0x3d4b590),
    ('c_batch_fold', 0x3d4b72c, 'e85f040000', 'call', 0x3d4bb90),
    ('c_lane_loop', 0x3d4b80f, '759f', 'jcc', 0x3d4b7b0),
    ('c_tail_fold', 0x3d4b8e7, 'e8a4020000', 'call', 0x3d4bb90),
]

EDGES += [
    ('writer_extension_false', 0x422f12b, '7471', 'jcc', 0x422f19e),
    ('json_dispatch', 0x422f1f8, 'e8333069ff', 'call', 0x38c2230),
    ('json_writer_error', 0x422f203, '7567', 'jcc', 0x422f26c),
    ('outer_accounts_label', 0x38c2296, 'e80519e500', 'call', 0x4713ba0),
    ('outer_accounts_value', 0x38c22da, 'e8113ae0ff', 'call', 0x36c5cf0),
    ('outer_contracts_label', 0x38c22fe, 'e89d18e500', 'call', 0x4713ba0),
    ('outer_contracts_value', 0x38c2346, 'e8a539e0ff', 'call', 0x36c5cf0),
    ('outer_storage_label', 0x38c236a, 'e83118e500', 'call', 0x4713ba0),
    ('outer_storage_value', 0x38c23b5, 'e83639e0ff', 'call', 0x36c5cf0),
    ('field_elements', 0x36c5d5a, 'e8c12ef800', 'call', 0x4648c20),
    ('field_bytes', 0x36c5d88, 'e8932ef800', 'call', 0x4648c20),
    ('field_hash', 0x36c5db2, 'e809e8f800', 'call', 0x46545c0),
    ('hash_payload', 0x465460e, 'e8cdc40100', 'call', 0x4670ae0),
    ('c_error_small_tag', 0x3d4b88a, '0f8200fdffff', 'jcc', 0x3d4b590),
    ('c_error_dynamic_drop', 0x3d4b89b, '0f84e2fcffff', 'jcc', 0x3d4b583),
    ('c_error_empty_buffer', 0x3d4b8af, '0f84dbfcffff', 'jcc', 0x3d4b590),
]

EDGES += [
    ('array_empty', 0x4670b34, '0f84a0020000', 'jcc', 0x4670dda),
    ('byte_lt_100', 0x4670c2b, '7633', 'jcc', 0x4670c60),
    ('byte_ge_10', 0x4670c68, '7316', 'jcc', 0x4670c80),
    ('array_next', 0x4670cee, '0f857cfeffff', 'jcc', 0x4670b70),
    ('array_grow_close', 0x4670de1, '742a', 'jcc', 0x4670e0d),
]

EDGES += [
    ('parse_json', 0x422e97a, 'e8112eccff', 'call', 0x3ef1790),
    ('parse_value', 0x3ef17d9, 'e892df2200', 'call', 0x411f770),
    ('parse_error', 0x3ef17e1, '755b', 'jcc', 0x3ef183e),
    ('pass_without_tail', 0x3ef17f0, '7347', 'jcc', 0x3ef1839),
    ('reject_above_32', 0x3ef181a, '7742', 'jcc', 0x3ef185e),
    ('reject_not_whitespace', 0x3ef1820, '733c', 'jcc', 0x3ef185e),
    ('parse_next_tail', 0x3ef1835, '75d9', 'jcc', 0x3ef1810),
]

EDGES += [
    ('outer_sequence_start', 0x411f836, '0f84b6000000', 'jcc', 0x411f8f2),
    ('outer_bad_start', 0x411f83f, '0f8589090000', 'jcc', 0x41201ce),
    ('outer_inner_sequence', 0x411f95b, 'e8903af6ff', 'call', 0x40833f0),
    ('outer_inner_accounts', 0x411fd41, 'e8aa36f6ff', 'call', 0x40833f0),
    ('outer_inner_contracts', 0x411fda1, 'e84a36f6ff', 'call', 0x40833f0),
    ('outer_inner_storage', 0x411fe01, 'e8ea35f6ff', 'call', 0x40833f0),
    ('outer_dup_accounts', 0x411fb4f, '0f84bd060000', 'jcc', 0x4120212),
    ('outer_dup_contracts', 0x411fbdd, '0f844c060000', 'jcc', 0x412022f),
    ('outer_dup_storage', 0x411fcd3, '0f841c050000', 'jcc', 0x41201f5),
    ('outer_missing_accounts', 0x411fe8a, '0f8449020000', 'jcc', 0x41200d9),
    ('outer_missing_contracts', 0x411fe95, '0f8481020000', 'jcc', 0x412011c),
    ('outer_missing_storage', 0x411fea0, '0f8493020000', 'jcc', 0x4120139),
    ('inner_dup_elements', 0x40837ff, '0f8476060000', 'jcc', 0x4083e7b),
    ('inner_dup_bytes', 0x40838a1, '0f84b7050000', 'jcc', 0x4083e5e),
    ('inner_dup_hash', 0x40839a3, '0f85ef040000', 'jcc', 0x4083e98),
    ('inner_missing_elements', 0x4083be9, '0f847e010000', 'jcc', 0x4083d6d),
    ('inner_missing_bytes', 0x4083bf4, '0f84a8010000', 'jcc', 0x4083da2),
    ('inner_missing_hash', 0x4083bff, '0f84ba010000', 'jcc', 0x4083dbf),
]

EDGES += [
    ('inner_to_hash_input', 0x4083a13, 'e868eef4ff', 'call', 0x3fd2880),
    ('string_decoder_slot', 0x3fd292b, 'ff15377d5102', 'slot', 0x64ea668),
    ('string_decoder_success', 0x3fd293b, '0f85ac010000', 'jcc', 0x3fd2aed),
    ('not_sequence', 0x3fd2951, '0f85ab020000', 'jcc', 0x3fd2c02),
    ('sequence_next', 0x3fd2a16, 'e815a1f7ff', 'call', 0x3f4cb30),
    ('sequence_next_error', 0x3fd2a20, '746d', 'jcc', 0x3fd2a8f),
    ('sequence_short', 0x3fd2a27, '0f856b010000', 'jcc', 0x3fd2b98),
    ('sequence_byte_parse', 0x3fd2a35, 'e80637fbff', 'call', 0x3f86140),
    ('sequence_byte_error', 0x3fd2a3f, '744e', 'jcc', 0x3fd2a8f),
    ('sequence_loop', 0x3fd2a55, '75b9', 'jcc', 0x3fd2a10),
    ('sequence_end', 0x3fd2ab4, 'e8a70af2ff', 'call', 0x3ef3560),
    ('string_length_error', 0x3fd2af9, '0f852f010000', 'jcc', 0x3fd2c2e),
    ('end_nonwhitespace', 0x3ef3598, '7329', 'jcc', 0x3ef35c3),
    ('end_not_comma', 0x3ef35c7, '7545', 'jcc', 0x3ef360e),
    ('end_not_close', 0x3ef3612, '752a', 'jcc', 0x3ef363e),
    ('end_after_comma_error', 0x3ef3627, '7515', 'jcc', 0x3ef363e),
    ('byte_not_parse_error', 0x3f861f1, '753b', 'jcc', 0x3f8622e),
    ('byte_tag_one', 0x3f86236, '7419', 'jcc', 0x3f86251),
    ('byte_tag_not_two', 0x3f8623b, '752b', 'jcc', 0x3f86268),
    ('byte_tag_two_ok', 0x3f86243, '7214', 'jcc', 0x3f86259),
    ('byte_tag_one_error', 0x3f86257, '733f', 'jcc', 0x3f86298),
]

EDGES += [
    ('string_escape_helper', 0x5c56f56, 'e8f5efffff', 'call', 0x5c55f50),
    ('string_escape_error', 0x5c56f5e, '0f858b010000', 'jcc', 0x5c570ef),
    ('string_scan_end', 0x5c56f72, '0f8488000000', 'jcc', 0x5c57000),
    ('string_scan_outside', 0x5c56f78, '0f832c020000', 'jcc', 0x5c571aa),
    ('string_quote', 0x5c56f8c, '7472', 'jcc', 0x5c57000),
    ('string_backslash', 0x5c56f94, '746a', 'jcc', 0x5c57000),
    ('string_unterminated', 0x5c57003, '0f8418010000', 'jcc', 0x5c57121),
    ('string_outside', 0x5c57009, '0f8388010000', 'jcc', 0x5c57197),
    ('string_not_backslash', 0x5c5701a, '756b', 'jcc', 0x5c57087),
    ('string_not_quote', 0x5c5708a, '0f859c000000', 'jcc', 0x5c5712c),
    ('string_borrowed', 0x5c5709d, '7462', 'jcc', 0x5c57101),
    ('string_error_builder', 0x5c5714c, 'e8aff4ffff', 'call', 0x5c56600),
]

RELATIVE = 8
EDGE_SLOTS = {
    0x64e95a0: 0x3915d30,
    0x64e61d0: 0x38c2e00,
    0x64e9528: 0x38c2690,
    0x64e2080: 0x1692ff0,
    0x64ea668: 0x5c56f10,
}
LOCATION_SLOTS = {
    0x646e800: ('l1/src/evm/hash.rs', 68, 27),
    0x646e818: ('l1/src/evm/evm_db.rs', 189, 67),
    0x646ec68: ('l1/src/evm/evm_db.rs', 91, 14),
    0x646ec80: ('l1/src/evm/evm_db.rs', 94, 14),
}
FORK_MARKERS = (
    'z_forks/reth-chainspec/',
    'z_forks/reth-ethereum-forks/',
    'z_forks/reth-rpc-eth-types/',
    'z_forks/reth-rpc-server-types/',
    'z_forks/revm-precompile/',
    'z_vendor/revm-context/',
    'z_vendor/revm-interpreter/',
)


def check_digest(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('node 115 SHA-256 mismatch')


def check_window(actual, expected):
    if actual != bytes.fromhex(expected):
        raise ValueError('selected instruction window differs')


def frame_record(image, va):
    """Retain a shared-parser-identified frame record, including its length word."""
    section = image.named['.eh_frame']
    if not section['address'] <= va <= section['address'] + section['size'] - 4:
        raise ValueError('frame address outside section')
    length = struct.unpack('<I', image.read(va, 4))[0]
    if length < 4 or length == 0xffffffff or va + 4 + length > section['address'] + section['size']:
        raise ValueError('invalid frame record length')
    return image.read(va, length + 4)


def decode_transfer(site, raw):
    """Decode only the five explicit relative-transfer encodings used here."""
    if len(raw) >= 5 and raw[0] in (0xe8, 0xe9):
        size, kind = 5, 'call' if raw[0] == 0xe8 else 'jmp'
        displacement = struct.unpack_from('<i', raw, 1)[0]
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        size, kind = 6, 'jcc'
        displacement = struct.unpack_from('<i', raw, 2)[0]
    elif len(raw) >= 2 and 0x70 <= raw[0] <= 0x7f:
        size, kind = 2, 'jcc'
        displacement = struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) >= 6 and raw[:2] in (b'\xff\x15', b'\xff\x25'):
        size, kind = 6, 'slot'
        displacement = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported transfer encoding')
    if len(raw) != size:
        raise ValueError('wrong transfer length')
    return kind, site + size + displacement


def chunk_plan(count, capacity):
    if type(count) is not int or type(capacity) is not int or count < 0 or capacity <= 0:
        raise ValueError('invalid chunk model input')
    return divmod(count, capacity)


def trailing_region_case(tag_word, first_word, flag_word, sentinel):
    """Model the selected wrapper's four trailing-region outcomes only."""
    if any(type(v) is not int or not 0 <= v < (1 << 64)
           for v in (tag_word, first_word, flag_word, sentinel)):
        raise ValueError('invalid trailing-region word')
    if tag_word != sentinel:
        return 'other_variant'
    if flag_word == 0:
        return 'sentinel_empty'
    if first_word == 0:
        return 'sentinel_null_failure'
    return 'sentinel_nonempty'


def classify_key(key, prefix, tail_size):
    """Model selected scan's prefix-stop, key-size skip and decode branches."""
    if not isinstance(key, bytes) or not isinstance(prefix, bytes) or type(tail_size) is not int or tail_size < 0:
        raise ValueError('invalid key model input')
    if len(key) < len(prefix) or key[:len(prefix)] != prefix:
        return 'stop'
    if len(key) != len(prefix) + tail_size:
        return 'skip'
    return 'decode'


def split_es_key(key, prefix, first_size, second_size):
    if classify_key(key, prefix, first_size + second_size) != 'decode':
        raise ValueError('invalid selected composite key')
    body = key[len(prefix):]
    return body[:first_size], body[first_size:][::-1]


def first_missing(mask, ordered_names):
    """Model the checked post-map presence tests, not earlier parser errors."""
    if type(mask) is not int or mask < 0 or mask >= (1 << len(ordered_names)):
        raise ValueError('invalid field-presence mask')
    return next((name for index, name in enumerate(ordered_names) if not (mask >> index) & 1), None)


def sequence_count_case(count, expected):
    """Classify length only, assuming valid token syntax and numeric values."""
    if type(count) is not int or type(expected) is not int or count < 0 or expected <= 0:
        raise ValueError('invalid sequence-count model input')
    return 'short' if count < expected else 'long' if count > expected else 'exact'


def decoded_string_gate(tag, length, expected):
    """Model length after the selected decoder returns tag 0, 1, or 2."""
    if type(tag) is not int or tag not in (0, 1, 2) or type(length) is not int or length < 0 or type(expected) is not int or expected <= 0:
        raise ValueError('invalid decoded-string model input')
    return tag != 2 and length == expected


def numeric_byte_variant(tag, word):
    """Model only the selected post-number-parser tag and unsigned range checks."""
    if type(tag) is not int or type(word) is not int or not 0 <= word < (1 << 64):
        raise ValueError('invalid parsed number input')
    return tag in (1, 2) and word < 256


def valid_json_tail(data, maximum, mask):
    """Model the selected post-value tail check, not the complete JSON parser."""
    if not isinstance(data, bytes) or type(maximum) is not int or type(mask) is not int or maximum < 0 or mask < 0:
        raise ValueError('invalid trailing-byte model input')
    return all(value <= maximum and (mask >> value) & 1 for value in data)


def decimal_byte(value, table):
    """Model the selected byte-to-decimal branches with the target's digit table."""
    if type(value) is not int or not 0 <= value <= 255 or len(table) != 200:
        raise ValueError('invalid decimal-byte input')
    if value > 99:
        hundreds = (value * 41) >> 12
        remainder = value - 100 * hundreds
        return bytes((0x30 | hundreds,)) + table[2 * remainder:2 * remainder + 2]
    if value < 10:
        return bytes((0x30 | value,))
    return table[2 * value:2 * value + 2]


def merge_records(left, right, payload_size):
    """Model the selected big-endian u16 lanes and two saturating u64 fields."""
    if type(payload_size) is not int or payload_size <= 0 or payload_size % 2:
        raise ValueError('invalid payload width')
    if len(left) != payload_size + 16 or len(right) != payload_size + 16:
        raise ValueError('invalid record width')
    result = bytearray(payload_size + 16)
    for i in range(0, payload_size, 2):
        v = (int.from_bytes(left[i:i + 2], 'big') +
             int.from_bytes(right[i:i + 2], 'big')) & 0xffff
        result[i:i + 2] = v.to_bytes(2, 'big')
    for i in (payload_size, payload_size + 8):
        v = min((1 << 64) - 1, int.from_bytes(left[i:i + 8], 'little') +
                int.from_bytes(right[i:i + 8], 'little'))
        result[i:i + 8] = v.to_bytes(8, 'little')
    return bytes(result)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        names = [s['name'] for s in self.secs]
        for name in ('.text', '.rodata', '.rela.dyn', '.eh_frame', '.eh_frame_hdr'):
            if names.count(name) != 1:
                raise ValueError('missing or duplicate required section')
        self.named = {s['name']: s for s in self.secs}
        self.file_backed = [s for s in self.secs
                            if s['type'] != 8 and s['flags'] & 2 and s['size']]
        for s in self.file_backed:
            if s['offset'] + s['size'] > len(data):
                raise ValueError('file-backed section outside file')
        _, self.index = unwind_index(data)
        _, fdes = eh_frame_records(data, self.secs)
        self.fde_by_start = {}
        for fde in fdes:
            if fde['start'] in self.fde_by_start:
                raise ValueError('duplicate FDE start')
            self.fde_by_start[fde['start']] = fde
        self.index_by_start = {row['start']: row for row in self.index}
        if len(self.index_by_start) != len(self.index):
            raise ValueError('duplicate index start')
        self.relocations = self._relative_relocations()

    def offset(self, va, size=1):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
            raise ValueError('invalid byte range')
        matches = [s for s in self.file_backed
                   if s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('range is not uniquely file-backed')
        s = matches[0]
        return s['offset'] + va - s['address']

    def read(self, va, size):
        o = self.offset(va, size)
        return self.data[o:o + size]

    def _relative_relocations(self):
        s = self.named['.rela.dyn']
        if s['type'] == 8 or s['size'] % 24:
            raise ValueError('invalid relocation section')
        rows = {}
        for p in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, p)
            if (info & 0xffffffff) == RELATIVE:
                if info >> 32 or slot in rows:
                    raise ValueError('ambiguous relative relocation')
                rows[slot] = (addend, p, info)
        return rows

    def relative(self, slot):
        if slot not in self.relocations:
            raise ValueError('missing relative relocation')
        self.offset(slot, 8)
        return self.relocations[slot][0]

    def fde(self, start, end):
        fde = self.fde_by_start.get(start)
        idx = self.index_by_start.get(start)
        if not fde or not idx or fde['end'] != end or idx['fde'] != fde['fde']:
            raise ValueError('selected FDE/index mismatch')
        sec = self.named['.text']
        if not (sec['address'] <= start < end <= sec['address'] + sec['size']):
            raise ValueError('selected FDE outside text')
        self.offset(start, end - start)
        return fde

    def containing_selected(self, va, size=1):
        found = [(name, start, end) for name, start, end in FUNCTIONS
                 if start <= va and va + size <= end]
        if len(found) != 1:
            raise ValueError('window outside selected FDEs')
        return found[0]


def mov_edx_imm(image, addr):
    raw = image.read(addr, 5)
    if raw[0] != 0xba:
        raise ValueError('expected mov edx immediate')
    return struct.unpack_from('<I', raw, 1)[0]


def mov_esi_imm(image, addr):
    raw = image.read(addr, 5)
    if raw[0] != 0xbe:
        raise ValueError('expected mov esi immediate')
    return struct.unpack_from('<I', raw, 1)[0]


def relative_lea(image, addr):
    raw = image.read(addr, 7)
    if raw[:3] != b'\x48\x8d\x05':
        raise ValueError('expected RIP-relative lea')
    return addr + 7 + struct.unpack_from('<i', raw, 3)[0]


def string_reference(image, lea_site, length_site, expected):
    raw = image.read(lea_site, 7)
    if raw[:3] != bytes.fromhex('488d35'):
        raise ValueError('invalid schema string reference')
    pointer = lea_site + 7 + struct.unpack_from('<i', raw, 3)[0]
    length = mov_edx_imm(image, length_site)
    if image.read(pointer, length) != expected.encode('ascii'):
        raise ValueError('schema string mismatch')
    return pointer, length


def record_offset(image, site, opcode):
    raw = image.read(site, 7)
    if raw[:3] != bytes.fromhex(opcode):
        raise ValueError('record offset instruction mismatch')
    return struct.unpack_from('<I', raw, 3)[0]


def error_field_reference(image, site, expected):
    pointer = relative_lea(image, site)
    raw = image.read(site + 15, 12)
    if raw[:4] != bytes.fromhex('48c78424'):
        raise ValueError('invalid error field length instruction')
    length = struct.unpack_from('<I', raw, 8)[0]
    if image.read(pointer, length) != expected.encode('ascii'):
        raise ValueError('error field name mismatch')
    return pointer, length


def location_record(image, slot, expected):
    ptr = image.relative(slot)
    size, line, col = struct.unpack('<QII', image.read(slot + 8, 16))
    if size < 1 or size > 128:
        raise ValueError('invalid location length')
    try:
        path = image.read(ptr, size).decode('ascii')
    except UnicodeDecodeError as error:
        raise ValueError('non-ASCII location') from error
    if (path, line, col) != expected:
        raise ValueError('location mismatch')
    return path, line, col, ptr


def marker_offsets(image, marker):
    s = image.named['.rodata']
    needle = marker.encode('ascii')
    found, pos = [], s['offset']
    limit = s['offset'] + s['size']
    while True:
        pos = image.data.find(needle, pos, limit)
        if pos < 0:
            break
        found.append((s['address'] + pos - s['offset'], pos))
        pos += 1
    if not found:
        raise ValueError('missing fork marker')
    return found


def hexva(value):
    return '' if value is None else hex(value)


def tsv(header, rows):
    from io import StringIO
    stream = StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def build(image):
    # All output is assembled and validated before the output directory is made.
    function_rows = []
    frames = set()
    for name, start, end in sorted(FUNCTIONS, key=lambda x: x[1]):
        fde = image.fde(start, end)
        frames.add(('fde', fde['fde']))
        frames.add(('cie', fde['cie']))
        raw = image.read(start, end - start)
        function_rows.append((name, hex(start), hex(end), hex(image.offset(start, end-start)),
                              len(raw), hex(fde['fde']), hex(fde['cie']),
                              hexva(fde['lsda']), hashlib.sha256(raw).hexdigest()))

    frame_rows = []
    for kind, va in sorted(frames, key=lambda row: (row[1], row[0])):
        raw = frame_record(image, va)
        frame_rows.append((kind, hex(va), hex(image.offset(va, len(raw))), len(raw), raw.hex()))

    window_rows = []
    for name, va, expected in WINDOWS:
        raw = image.read(va, len(bytes.fromhex(expected)))
        image.containing_selected(va, len(raw))
        check_window(raw, expected)
        window_rows.append((name, hex(va), hex(image.offset(va, len(raw))), len(raw), raw.hex()))

    edge_rows = []
    for name, va, expected, kind, target in EDGES:
        raw = image.read(va, len(bytes.fromhex(expected)))
        _, start, end = image.containing_selected(va, len(raw))
        check_window(raw, expected)
        decoded_kind, decoded_target = decode_transfer(va, raw)
        if (decoded_kind, decoded_target) != (kind, target):
            raise ValueError('relative transfer mismatch')
        if kind == 'jcc' and not start <= target < end:
            raise ValueError('branch target outside selected FDE')
        resolved = image.relative(target) if kind == 'slot' else None
        if kind == 'slot' and EDGE_SLOTS.get(target) != resolved:
            raise ValueError('indirect call relocation mismatch')
        edge_rows.append((name, hex(va), raw.hex(), kind, hex(target), hexva(resolved)))

    location_rows = []
    for slot, expected in sorted(LOCATION_SLOTS.items()):
        path, line, col, ptr = location_record(image, slot, expected)
        location_rows.append((hex(slot), hex(image.offset(slot,24)), hex(ptr), path, line, col))

    table = relative_lea(image, 0x3d4ccb9)
    if table != relative_lea(image, 0x3d4c899) or table != relative_lea(image, 0x3d4d0d9):
        raise ValueError('prefix table references differ')
    prefixes = []
    for label, mov_site, want, builder, constructor, scanner, key_site, key_size in (
        ('a', 0x38c2842, b'Ea', 0x3d4cbe0, 0x3c27f30, 0x3d4acf0, 0x3d4aee6, 20),
        ('c', 0x38c2874, b'Ec', 0x3d4c7c0, 0x3c284f0, 0x3d4b410, 0x3d4b606, 32),
        ('s', 0x38c28a6, b'Es', 0x3d4d000, 0x3c28210, 0x3d4a640, 0x3d4a82e, 52),
    ):
        selector = mov_esi_imm(image, mov_site)
        slot = table + selector * 8
        ptr = image.relative(slot)
        prefix = image.read(ptr, 2)
        if prefix != want:
            raise ValueError('prefix table bytes mismatch')
        key_add = image.read(key_site, 4)
        if key_add[:3] != bytes.fromhex('498d45') or key_add[3] != key_size:
            raise ValueError('selected key-width instruction mismatch')
        prefixes.append((label, selector, hex(mov_site), hex(slot), hex(ptr),
                         hex(image.offset(ptr,2)), prefix.decode('ascii'),
                         hex(builder), hex(constructor), hex(scanner), key_add[3], hex(key_site)))

    if image.read(0x38c22d4, 3) != bytes.fromhex('4889df') or image.read(0x36c5daf, 3) != bytes.fromhex('4889d9'):
        raise ValueError('zero-offset record forwarding mismatch')
    offsets = [0, record_offset(image, 0x38c230e, '488dbb'),
               record_offset(image, 0x38c237a, '4881c3'),
               record_offset(image, 0x36c5d44, '488d8b'),
               record_offset(image, 0x36c5d72, '488d8b'), 0]
    if offsets != [0, 0x810, 0x1020, 0x800, 0x808, 0]:
        raise ValueError('schema field offsets differ')
    mask_insn = image.read(0x3ef17fd, 10)
    cmp_insn = image.read(0x3ef1816, 4)
    if mask_insn[:2] != bytes.fromhex('48bf') or cmp_insn[:3] != bytes.fromhex('4983f8'):
        raise ValueError('trailing-byte predicate mismatch')
    tail_mask = struct.unpack_from('<Q', mask_insn, 2)[0]
    tail_max = cmp_insn[3]
    if tail_mask != 0x100002600 or tail_max != 32:
        raise ValueError('trailing-byte predicate constants differ')
    tail_rows = [(value, int(valid_json_tail(bytes((value,)), tail_max, tail_mask))) for value in range(256)]

    first_ref = image.read(0x4670c41, 7)
    second_ref = image.read(0x4670c80, 7)
    if first_ref[:3] != bytes.fromhex('488d15') or second_ref[:3] != bytes.fromhex('488d0d'):
        raise ValueError('decimal table instruction mismatch')
    decimal_va = 0x4670c48 + struct.unpack_from('<i', first_ref, 3)[0]
    if decimal_va != 0x4670c87 + struct.unpack_from('<i', second_ref, 3)[0]:
        raise ValueError('decimal table references differ')
    digit_table = image.read(decimal_va, 200)
    expected_digits = b''.join(('%02d' % i).encode('ascii') for i in range(100))
    if digit_table != expected_digits:
        raise ValueError('decimal table contents differ')
    decimal_rows = [(value, decimal_byte(value, digit_table).decode('ascii')) for value in range(256)]

    schema = []
    for (scope, label, lea, length_site, related), offset in zip((
        ('outer', 'accounts_hash', 0x38c2285, 0x38c2291, 'Ea'),
        ('outer', 'contracts_hash', 0x38c22ed, 0x38c22f9, 'Ec'),
        ('outer', 'storage_hash', 0x38c2359, 0x38c2365, 'Es'),
        ('inner', 'n_elements', 0x36c5d4b, 0x36c5d55, ''),
        ('inner', 'n_bytes', 0x36c5d79, 0x36c5d83, ''),
        ('inner', 'hash', 0x36c5da0, 0x36c5daa, ''),
    ), offsets):
        pointer, length = string_reference(image, lea, length_site, label)
        schema.append((scope, label, hex(lea), hex(pointer), hex(image.offset(pointer,length)),
                       length, offset, related))

    if image.read(0x4325c4, 16) != bytes([15]) + b'missing field `' or image.read(0x43351a, 18) != bytes([17]) + b'duplicate field `':
        raise ValueError('parser error templates differ')
    parser_errors = []
    for scope, field, missing_branch, missing_site, duplicate_branch, duplicate_site in (
        ('outer', 'accounts_hash', 0x411fe8a, 0x41200d9, 0x411fb4f, 0x4120212),
        ('outer', 'contracts_hash', 0x411fe95, 0x412011c, 0x411fbdd, 0x412022f),
        ('outer', 'storage_hash', 0x411fea0, 0x4120139, 0x411fcd3, 0x41201f5),
        ('inner', 'n_elements', 0x4083be9, 0x4083d6d, 0x40837ff, 0x4083e7b),
        ('inner', 'n_bytes', 0x4083bf4, 0x4083da2, 0x40838a1, 0x4083e5e),
        ('inner', 'hash', 0x4083bff, 0x4083dbf, 0x40839a3, 0x4083e98),
    ):
        missing_ptr, missing_len = error_field_reference(image, missing_site, field)
        duplicate_ptr, duplicate_len = error_field_reference(image, duplicate_site, field)
        if (missing_ptr, missing_len) != (duplicate_ptr, duplicate_len):
            raise ValueError('field error references differ')
        parser_errors.append((scope, field, hex(missing_branch), hex(missing_site),
                              hex(duplicate_branch), hex(duplicate_site), hex(missing_ptr), missing_len))
    missing_vectors = []
    for scope in ('outer', 'inner'):
        ordered = tuple(row[1] for row in parser_errors if row[0] == scope)
        for mask in range(1 << len(ordered)):
            missing_vectors.append((scope, mask, first_missing(mask, ordered) or ''))

    blob = image.read(0x44f3c9, 17)
    if blob != bytes.fromhex('c00f2f6c745f6861736865732e6a736f6e'):
        raise ValueError('checkpoint path format literal mismatch')
    fork_rows = []
    for marker in FORK_MARKERS:
        hits = marker_offsets(image, marker)
        for va, off in hits:
            fork_rows.append((marker, len(hits), hex(va), hex(off)))

    slots = sorted(set(EDGE_SLOTS) | set(LOCATION_SLOTS) |
                   {table + int(row[1])*8 for row in prefixes})
    relocation_rows = []
    for slot in slots:
        addend, off, info = image.relocations[slot]
        relocation_rows.append((hex(slot), hex(off), hex(info), hex(addend),
                                image.data[off:off+24].hex()))

    record_size = mov_edx_imm(image, 0x38c25e8)
    payload_size = mov_edx_imm(image, 0x38c2f4f)
    descriptor_size = mov_edx_imm(image, 0x3c27f77)
    batch_size = mov_edx_imm(image, 0x3c27fd4)
    if (record_size, payload_size, descriptor_size, batch_size) != (0x810, 0x800, 0xf8, 1000000):
        raise ValueError('selected operand mismatch')
    if batch_size != mov_edx_imm(image, 0x3c282b4) or batch_size != mov_edx_imm(image, 0x3c28594):
        raise ValueError('batch arguments differ')

    sentinel_insn = image.read(0x518d1e0, 10)
    if sentinel_insn[:2] != bytes.fromhex('49be'):
        raise ValueError('trailing-region sentinel instruction mismatch')
    sentinel = struct.unpack_from('<Q', sentinel_insn, 2)[0]
    if sentinel != 1 << 63:
        raise ValueError('trailing-region sentinel differs')

    key_tail_size = prefixes[0][10]
    if prefixes[2][10] != prefixes[0][10] + prefixes[1][10]:
        raise ValueError('composite suffix widths differ')
    selected_prefix = prefixes[0][6].encode('ascii')
    sample_keys = [b'E', selected_prefix, selected_prefix + bytes(key_tail_size - 1),
                   selected_prefix + bytes(key_tail_size),
                   selected_prefix + bytes(key_tail_size + 1), b'Eb' + bytes(key_tail_size)]

    es_prefix = prefixes[2][6].encode('ascii')
    es_input = es_prefix + bytes(range(prefixes[0][10])) + bytes(range(prefixes[1][10]))
    es_first, es_second = split_es_key(es_input, es_prefix, prefixes[0][10], prefixes[1][10])

    sequence_cmp = image.read(0x3fd2a4e, 7)
    string_cmp = image.read(0x3fd2af2, 7)
    tag1_cmp = image.read(0x3f86251, 6)
    tag2_cmp = image.read(0x3f8623d, 6)
    if sequence_cmp[:3] != bytes.fromhex('4981ff') or string_cmp[:3] != bytes.fromhex('4881ff'):
        raise ValueError('hash length predicate mismatch')
    sequence_size = struct.unpack_from('<I', sequence_cmp, 3)[0]
    if sequence_size != payload_size or struct.unpack_from('<I', string_cmp, 3)[0] != sequence_size:
        raise ValueError('hash input and output widths differ')
    if tag1_cmp[:2] != bytes.fromhex('483d') or tag2_cmp != tag1_cmp:
        raise ValueError('byte range instructions differ')
    if struct.unpack_from('<I', tag1_cmp, 2)[0] != 256:
        raise ValueError('byte range differs')
    sequence_vectors = [(n, sequence_count_case(n, sequence_size)) for n in
                        (0, sequence_size - 1, sequence_size, sequence_size + 1)]
    string_vectors = [(tag, n, int(decoded_string_gate(tag, n, sequence_size)))
                      for tag in (0, 1, 2) for n in (sequence_size - 1, sequence_size, sequence_size + 1)]
    numeric_vectors = [(tag, word, int(numeric_byte_variant(tag, word))) for tag in (0, 1, 2, 3)
                       for word in (0, 255, 256, (1 << 64) - 1)]

    left, right = bytearray(record_size), bytearray(record_size)
    left[:8], right[:8] = bytes.fromhex('00ffffff1234ffff'), bytes.fromhex('0001000100010001')
    struct.pack_into('<QQ', left, payload_size, (1 << 64)-1, (1 << 64)-2)
    struct.pack_into('<QQ', right, payload_size, 1, 1)
    merged = merge_records(left, right, payload_size)
    vectors = {
        'target_sha256': SHA256,
        'input_scope': 'synthetic vectors for the selected static arithmetic, not target execution',
        'descriptor_bytes': descriptor_size,
        'record_bytes': record_size,
        'payload_bytes': payload_size,
        'u16_lanes': payload_size // 2,
        'batch_capacity': batch_size,
        'outer_trailing_sentinel': hex(sentinel),
        'outer_trailing_cases': [
            {'tag': hex(tag), 'word_1b28': first, 'word_1b38': flag,
             'outcome': trailing_region_case(tag, first, flag, sentinel)}
            for tag, first, flag in ((0, 0, 0), (sentinel, 0, 0),
                                     (sentinel, 0, 1), (sentinel, 1, 1))],
        'decimal_table_va': hex(decimal_va),
        'decimal_table_file_offset': hex(image.offset(decimal_va, len(digit_table))),
        'decimal_table_hex': digit_table.hex(),
        'decimal_vectors': len(decimal_rows),
        'trailing_byte_mask': hex(tail_mask),
        'trailing_byte_max': tail_max,
        'trailing_accepted_bytes': [v for v, accepted in tail_rows if accepted],
        'selected_key_suffix_bytes': key_tail_size,
        'all_key_suffix_bytes': {row[6]: row[10] for row in prefixes},
        'es_composite_vector': {'key_hex': es_input.hex(),
                                'first_field_hex': es_first.hex(),
                                'second_field_reversed_hex': es_second.hex()},
        'selected_key_vectors': [{'key_hex': key.hex(),
                                  'decision': classify_key(key, selected_prefix, key_tail_size)}
                                 for key in sample_keys],
        'lane_vector': {
            'left_first_eight_hex': bytes(left[:8]).hex(),
            'right_first_eight_hex': bytes(right[:8]).hex(),
            'sum_first_eight_hex': merged[:8].hex(),
            'left_tail_counters': list(struct.unpack_from('<QQ', left, payload_size)),
            'right_tail_counters': list(struct.unpack_from('<QQ', right, payload_size)),
            'sum_tail_counters': list(struct.unpack_from('<QQ', merged, payload_size)),
        },
        'accepted_rows_to_full_batches_and_tail': [
            {'rows': n, 'full_batches': chunk_plan(n, batch_size)[0],
             'tail_rows': chunk_plan(n, batch_size)[1]}
            for n in (0, 1, batch_size - 1, batch_size, batch_size + 1, 2 * batch_size)],
        'counts': {'selected_fdes': len(function_rows),
                   'selected_fde_bytes': sum(row[4] for row in function_rows),
                   'windows': len(window_rows),
                   'transfers': len(edge_rows), 'prefixes': len(prefixes),
                   'locations': len(location_rows), 'schema_fields': len(schema),
                   'parser_error_fields': len(parser_errors),
                   'relative_relocations': len(relocation_rows),
                   'fork_path_occurrences': len(fork_rows)},
    }
    data_rows = []
    for label, va, size in (('file_name_format', 0x44f3c9, 17),
                            ('writer_extension_rmp', 0x4659e5, 3),
                            ('missing_field_format', 0x4325c4, 16),
                            ('duplicate_field_format', 0x43351a, 18),
                            ('decimal_digits', decimal_va, len(digit_table))):
        raw = image.read(va, size)
        if label == 'writer_extension_rmp' and raw != b'rmp':
            raise ValueError('writer extension bytes differ')
        data_rows.append((label, hex(va), hex(image.offset(va, size)), size, raw.hex()))
    return {
        'data.tsv': tsv(('label','va','file_offset','length','bytes_hex'), data_rows),
        'functions.tsv': tsv(('label','start_va','end_va_exclusive','file_offset','length','fde_va','cie_va','lsda_va','sha256'), function_rows),
        'frames.tsv': tsv(('kind','va','file_offset','length','bytes_hex'), frame_rows),
        'windows.tsv': tsv(('label','va','file_offset','length','bytes_hex'), window_rows),
        'transfers.tsv': tsv(('label','site_va','bytes_hex','kind','branch_or_slot_va','relative_addend_va'), edge_rows),
        'locations.tsv': tsv(('slot_va','slot_file_offset','path_va','path','line','column'), location_rows),
        'prefixes.tsv': tsv(('label','selector','selector_site_va','slot_va','prefix_va','prefix_file_offset','prefix_ascii','builder_fde','constructor_fde','fallback_fde','key_suffix_bytes','key_width_site_va'), prefixes),
        'schema.tsv': tsv(('scope','field','lea_site_va','name_va','name_file_offset','name_length','record_offset','related_prefix'), schema),
        'parse-errors.tsv': tsv(('scope','field','missing_branch_va','missing_target_va','duplicate_branch_va','duplicate_target_va','name_va','name_length'), parser_errors),
        'presence-vectors.tsv': tsv(('scope','present_mask','first_missing_field'), missing_vectors),
        'decimal-vectors.tsv': tsv(('input_byte','decimal_ascii'), decimal_rows),
        'trailing-bytes.tsv': tsv(('input_byte','accepted_after_value'), tail_rows),
        'sequence-vectors.tsv': tsv(('element_count','length_case'), sequence_vectors),
        'numeric-byte-vectors.tsv': tsv(('parsed_tag','u64_word','accepted_by_range_gate'), numeric_vectors),
        'string-length-vectors.tsv': tsv(('decoder_tag','decoded_length','accepted_by_gate'), string_vectors),
        'relocations.tsv': tsv(('slot_va','rela_file_offset','r_info','addend_va','raw_record_hex'), relocation_rows),
        'fork-markers.tsv': tsv(('path_fragment','fragment_occurrences','va','file_offset'), fork_rows),
        'vectors.json': (json.dumps(vectors, indent=2, sort_keys=True) + '\n').encode('ascii'),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    data = BINARY.read_bytes()
    check_digest(data)
    outputs = build(Image(data))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in outputs.items():
        (args.out / name).write_bytes(content)
    print('wrote', len(outputs), 'deterministic evidence files')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print('error:', type(error).__name__, str(error), file=sys.stderr)
        raise SystemExit(1)
