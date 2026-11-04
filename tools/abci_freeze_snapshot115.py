#!/usr/bin/env python3
"""Reproduce bounded node #115 freeze-state and snapshot evidence without execution."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

import elf_index
import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK64 = (1 << 64) - 1

# Names are descriptive only; the FDEs do not prove original Rust function names.
FUNCTIONS = [
    ('task_constructor', 0x2b3aba0), ('upper_dispatch', 0x2b1df60),
    ('context_constructor', 0x2d275d0),
    ('entry_adapter', 0x2774590), ('engine', 0x2d23610),
    ('end_selection', 0x2d25620), ('link_builder', 0x22ed1f0),
    ('link_adapter', 0x26a23d0), ('snapshot_parent', 0x269ab70),
    ('snapshot_binary', 0x26a2810), ('snapshot_outer', 0x22ebdc0),
    ('snapshot_fields', 0x2c6bee0), ('freeze_field', 0x2ceabe0),
    ('unsigned_writer', 0x25e9c70), ('unsigned_16', 0x25ea4b0),
    ('unsigned_32', 0x25ea780),
    ('map_writer', 0x25e7670), ('marker_packer', 0x25eab50),
    ('path_prepare', 0x1505a50),
    ('root_adapter', 0x2bb37c0), ('root_capture_wrapper', 0x26a21b0),
    ('root_captures', 0x269a1b0), ('root_descriptors', 0x2b7f5b0),
    ('root_split', 0x29f9300), ('root_serial_worker', 0x26e1660),
    ('root_freeze_visitor', 0x22a0fa0), ('root_freeze_constructor', 0x22a0b60),
    ('collection_wrapper', 0x22ed710), ('collection_reserve', 0x2ccdbf0),
    ('item_join', 0x26a1e90), ('item_join_output', 0x231b370),
]

# Each window was chosen by bounded instruction inspection; these hashes bind all
# bytes, including operands and padding inside a window, with no normalization.
WINDOWS = [
    ('task_entry', 0x2b3abb8, 18, 'e725e08306a0a53681468a7d88591540ef47e3efa32f531a0222ed5592d2a840'),
    ('task_first_copy', 0x2b3abef, 80, '284b592869b6332ff3ded50db9528dc066366b5120f48158750768eeee3dd7a0'),
    ('task_vtable_and_copy', 0x2b3ac3f, 118, 'a8f4af69e015cdb8afe5b2d8ce71ddfb711861fde2e635a04e78f133c92fd50f'),
    ('task_allocate_and_handoff', 0x2b3accc, 117, 'c54171899919b17358d6fc8e93e64dcf4c171c1c17f1605f2ec9195d80e86370'),
    ('task_allocation_failure', 0x2b3ad95, 21, '9c1e5c34e99914940b5be24a5fa6b815099e56b967b9d4e122b5e1a78f993f8a'),
    ('upper_input_copy', 0x2b1e0ff, 58, '68535e4befd7b3f8354524dd48d9759d61f912604c047cca1357cad414cd388e'),
    ('upper_seed_constructor', 0x2b1e171, 140, '58763e51589fd9b10b92189c8fa5f929f280ef130221a8bba21278c47a2b7f91'),
    ('upper_loop_setup', 0x2b1e1fd, 33, '5e1eafae0e52e486de8ccb392f3310b2a8e29b6270c6841a571374798ddee366'),
    ('upper_dispatch', 0x2b1e357, 156, 'aaffba76a28c0e09db46667d858b1c49833449271b747f684399e48dc8a33bbb'),
    ('upper_result_cleanup_a', 0x2b1e3f3, 92, '163eae453630d790c64cd4d9e633162464d39f7a0a9fff2d9e6c0514979a591e'),
    ('upper_result_cleanup_b', 0x2b1e44f, 173, 'a70f07dbb4355559001cbf64a4ee40190fca09fa4f2ddcacc4170800a2fdaee1'),
    ('upper_end_result_cleanup', 0x2b1e4fc, 114, '5fd487d4b3a35f4de7f1386c2566614d4e2e0e0478f9784a1fe695f2eb92aa28'),
    ('upper_initial_state_fetch', 0x2b1e29f, 28, '11c47df9e11de3b7b11c66a507fd9114bcb2d9aa3946b98b660e77494b300fe5'),
    ('upper_allocation_failure', 0x2b1eddd, 21, 'a52437cef09dcf7c68ccff1c4c6b378603266c3fba62aba84dc1c944d69a1c13'),
    ('context_initialization', 0x2d275d0, 164, '5c0c3fcde51b0848a69da7cbe57457b9e0875140a10fe4a72adc7b6138a5502f'),
    ('context_output_cleanup', 0x2d27674, 101, '16cb92109f9dcb6c999089b00b588f44db33d054e259b7d83db7c3458a37d7d1'),
    ('context_unwind', 0x2d276d9, 57, '7817cc7d69a8b749a781db2e152a04aa9dab5b558e5d91c6e5979f891791e919'),
    ('entry_adapter', 0x27745c3, 50, 'e3b91cdfbe7b5328ed4d65382b7580ff3f1feb8911c3ec8d774efab3c2cabf9c'),
    ('engine_save_input', 0x2d23621, 14, 'b77611706a0a59112ae74d901d47f692a00e83c7fab9d721b654fc6dbac8f8cf'),
    ('engine_tag_guard', 0x2d2368b, 68, '9feed0837b12c99dc4f532c550479b694780f39d109699b8315fe0949a2b5fa3'),
    ('engine_begin_boundary', 0x2d23781, 44, '74833abe391b19e9b97fbf9e8a3689be4cc6e59aedd58a598b190a672ea97729'),
    ('engine_spill', 0x2d23941, 17, '68d3d817c9f066a6f7473d2381e6938cc1c3305da3730575619fc3f9e39f98b5'),
    ('engine_collection_handoff', 0x2d23ab1, 191, 'b3499c1b34d1c6d2fcc3746af61a98585a4840b3293aa5d35b781dbdf2485a26'),
    ('engine_restore', 0x2d24bc5, 46, '10e89117c6e25dc74f6dfcd7a19c97c2d2c878f3e5cf6826809547f7a8c35eb6'),
    ('engine_end_and_change', 0x2d24ed1, 67, '1582242979d2bcd6a10cc260f3a39a57314d71d466bd301bcbd8cc13d37822a5'),
    ('engine_result', 0x2d24fbd, 51, '83fd3df469bb5552db02d5bc2b04e65094eb33566c8e6a1ea1a40ef0129ae6b6'),
    ('engine_result_full', 0x2d24f11, 223, 'bef927aa18725d4065c50bea30da0646b00e9404696f4411c1b84380ba2e6338'),
    ('engine_equal_failure', 0x2d25177, 21, 'abc3652756752c4198eb6a2499c7dd8bfa07332f39767657a21855a0b15e1783'),
    ('engine_past_failure', 0x2d2523c, 30, 'b87e95a7374bdbfee4a56c7b2380cb487c52b6147fe3a02aaf02d981a01f3366'),
    ('end_ordered_guards', 0x2d25631, 206, 'cd79dda3cbe8868c1ae555b6bf5b46db7fa51c3acf85e904c9227c1de3e3419b'),
    ('end_interval_division', 0x2d257bc, 62, '5338af349857261f7cdbdcf4d5afff12448805ac1553c1a199a798a9b4c99a48'),
    ('end_queue_clear', 0x2d25724, 84, '51851421537c8d7d91de760b6bb386f688fa4a8d6c900f0635dee968f1d60e04'),
    ('end_flag_spill_small', 0x2d25826, 22, '1689fc4164121b3ff5111e0c53cdb1832dcfc83f76fdf4170addf80c22ed54f7'),
    ('end_flag_restore_small', 0x2d258c3, 47, '6822459eb0a40e7318d7ba9d3f09caab390acd1de9b7a6c6f881cb9c4bc27075'),
    ('end_state_replacement', 0x2d258f2, 143, '407e095fc181479797cdb62248bf8fe17312cf13e154c34ba41c2d8128b6b9b4'),
    ('end_flag_spill_large', 0x2d25989, 26, '79b43bdd6fde1af9c0c58c854c4670029a1a5987a16928522b82beebe6d3437b'),
    ('end_flag_temp_spill', 0x2d25a5c, 35, '9df7032804406b9de3eadc25ac5a0cced453a34d78bb19d4592c4e6ecd2f3ffa'),
    ('end_flag_restore_large', 0x2d25b2d, 27, 'b6c8ad197bfb16abf27002e288596aea70188bf655ff9d45b81bc2add84a83cf'),
    ('end_past_failures', 0x2d26226, 50, '245ee936419a7ea8a9d87df99582fee9e75a21767826927f7a4f83ba24cf315c'),
    ('end_named_snapshot', 0x2d262ac, 128, 'cdd6cf48d3158e1060be11270df2b3ab2afae74d993523e05f2314c180489a65'),
    ('end_result_saves', 0x2d2632c, 106, '872d3b6d5e7540f2d1c093e6c083ae50b34caeac2e09b6377e5eb2b7079b0716'),
    ('end_result_restore', 0x2d2706a, 168, 'a19517fb38025bf99884e898647ca4b74c8d112c2740f07999f077380c15529f'),
    ('end_result_copy', 0x2d271ae, 125, '46b1fadfa7def9b903480e4b491270518032443d042de7880723718e1a4d2dd5'),
    ('link_entry_and_height', 0x22ed1f0, 65, '05122633d9ffec9b350632b8a9c40c06b00abdede658ccb3843652bb78cfe7f2'),
    ('link_build_context', 0x22ed275, 75, '17845755719df72a0f076fea0b470b881c9b87bbdb7ca384e204a8cc05c6a353'),
    ('link_location_and_prepare', 0x22ed2c0, 140, '2d4119321ab79e9661714da10f35d4eeefc35b69b152b39d59f252cfb7f55b40'),
    ('link_output', 0x22ed506, 146, '22a72f0c411012aea15d042573027d7c224ab7302a250d6b82ffe44a08de23e4'),
    ('link_failure', 0x22ed599, 44, '121e341b98a9e000def4981ad654175b305efb2c41a5320999bcc4d91aedd80c'),
    ('adapter_branch', 0x26a23d0, 66, '684d82cc57ca58f0b5bc9ae50d5b4cde540be00b200db605f8705925a59df9d7'),
    ('adapter_direct', 0x26a245e, 32, '1488774a80054d25434ea8973a25440fac1f2e5e9290d5a1adf8dfdf544943a7'),
    ('adapter_tls_guard', 0x26a24e9, 53, 'f88807266a3b1991870b9f3e7fda1f23e35b5db614daf74f9b2243f8a14a96f4'),
    ('output_parent_entry', 0x269ab70, 76, '1c320881c8f0d9b0b06453a2a393813e2073330b1a52d04ee9ff83e519e17750'),
    ('output_parent_direct', 0x269abed, 136, 'a2b2fed073898b0ed0814a8b4e2985b828fc5f043f57ce5994d83f5af6929420'),
    ('output_serializer_setup', 0x26a2810, 180, '36fcdabbf920d095fb4c30485347e30d3fac607a9219071d129667c20e8016f1'),
    ('output_binary_handoff', 0x26a28c4, 67, '51d2a5ba284b786eb93aa01dfcfee74924a05e5394c04f066aaf925b17a57093'),
    ('output_return', 0x26a2af4, 42, '4123b477829784a5fa0e0dcfc60f582cbccb9f1e6b16e685a299521795bb1f3f'),
    ('output_handoff_failure', 0x26a2b1e, 42, '100a7d0d4e291dfa24066881e8153ccf2e9545f7f6ea30f40c8e7a1f25c9691d'),
    ('output_serialize_failure', 0x26a2b88, 90, 'f5d9ff0e6f1214bf351cd62ea3f3bc150154bac648192f629c87f7123e69369a'),
    ('top_writer', 0x22ebdc0, 228, '37f691286e7cceb4b80c4745243f84d1e5afda475b909a84c518ce3077ca4f07'),
    ('inner_map_header', 0x2c6bee0, 150, 'c27fff54315222e496f6d1dc7dea04121d58751da58a6b795bd0eb45c939eb69'),
    ('inner_freeze_field', 0x2c6c1a6, 45, '6db487c65fc16ce378d59ffbb6a9d78164d5e99b1cdadd0785b35e7233a31520'),
    ('inner_error', 0x2c6c7b4, 76, '57576ebc123ebc2f84728d78c85025daa9d6a0b0bfb6495906305fd1beb9d998'),
    ('freeze_field', 0x2ceabe0, 191, '67e36ae106d3c2094c900e861d230db44f86a6d77f516639377851a2015ca663'),
    ('freeze_growth', 0x2ceac9f, 142, 'ced953ccb971a5759a29f6a640bbecd73a5e44069a0615471399ce72bd3d9b75'),
    ('number_selection', 0x25e9c70, 230, 'f50f2d74deaebcbe9078076499a297a3412b811d53e055750e0d672955f93425'),
    ('number_small_markers', 0x25e9d9d, 85, '0f5fc2bab5364507897f08de261943cb27bc096631587e20422437dbdd343348'),
    ('number_small_second_byte', 0x25e9e5a, 31, '0cfacfe0068a9b78e4362cae7cc96a15cd9e879602f6548f7da4fd7fe75a18c9'),
    ('u16_marker_and_growth', 0x25ea4b0, 85, 'ae85077ee727bcda4e531b9ac56b08c305cd82009ae7dcdd7a015290e0012b9e'),
    ('u16_big_endian', 0x25ea564, 42, 'eeb21db82884f9fc13ff847b5b0a1937a73ae49ae6190fe4e1af84c368e716f9'),
    ('u32_marker', 0x25ea780, 85, 'b28928761586f7201c728a1b0f646404ffb44d1463d5417d37065549436ee8b1'),
    ('u32_big_endian', 0x25ea834, 40, '6c334ae67013b2e01ff700c82a9ff83b29d7bcccd1ebd91ec7407f96774e0f74'),
    ('map_marker_selection', 0x25e767e, 99, '3c0c0acde5e5433b30aa953e353127f32d4ebfe8aae732d49c110c6cbc37da33'),
    ('map_count_big_endian', 0x25e76e1, 32, '0a158f0115925e9778b7ae44d6dcc6c2f92457892a33847e3417a1bd88d876d4'),
    ('map_u16_store', 0x25e777a, 25, '42fa0608d80308760745a66bbe725c79aa38de09b67839de533cd92a29e10a5c'),
    ('map_pack', 0x25eab50, 78, '97a69885f4ce8f473e5c0139e173b3c35bbee945b4519ffa9ad5d7e5bdbe1aaa'),
    ('path_prepare', 0x1505a50, 42, '6ffa9a80378fda5c13a1d4f525b6e85cad263e1f420fd5431d5289ab68bcaf67'),
    ('path_prepare_finish', 0x1505aea, 100, '6f38210cfca5277685e73549db065abb34c7e4b3ae64aed20d1194743a8b1523'),
    ('end_root_call', 0x2d256ff, 24, '363e2ff35d772bc380a5376a7f38bb3152dac2ca8acefccf2868e237f485ca8e'),
    ('root_adapter', 0x2bb37c0, 80, 'b9b4d0f1ea33f6c048b0c0803e46ab3f614f10dd6ad9f370fa4a5616876b112d'),
    ('root_adapter_output', 0x2bb38b7, 55, '625189bdb61e39dfce5162137404f80c01b9b8923f5ab1f34c1f16b9115af9b8'),
    ('root_capture_wrapper', 0x26a21b0, 174, 'b32065e1619923cd93735d70a3a8269bb9c060f98c706416a13256825ed06de3'),
    ('root_capture_setup', 0x269a1c1, 1124, 'cd1eb93fe2f91ee4629dc655c52027ca5354c6b34e3fa49fb648939ae32e7d0c'),
    ('root_capture_allocation', 0x269a625, 468, '2012f5ce499c30ccfdff9f3ce0a14d56b2b08a8db77e9349896b59266df855fa'),
    ('root_capture_result', 0x269a7f9, 135, '190ce186eee5a32728dffe00ed2c3e506d90d71c059740a8632865a56d800753'),
    ('root_capture_return', 0x269aa88, 50, '33bd8ae4f5f20d967825fc619185678fe9ece5e9ea66b3b0a8722b1367051733'),
    ('root_capture_alloc_failure', 0x269ab07, 16, 'f09091dfad74fbe58010588db103b849a8442b77dd2a20e8f15a6e66d8515922'),
    ('root_descriptor_freeze', 0x2b7f6e4, 60, '68a4d30d05c0d0bd73432ba10465b656d30fed8ceb04b0cb439fced6783698ad'),
    ('root_builder_entry', 0x2b7f5b0, 48, '72709bd99bd0f9706f7acdbc023ed6104c4716ea3f73456b929c494145abc871'),
    ('root_descriptor_group', 0x2b7fc0b, 120, '1e691148fed72bf83df83c6aeceb4561bbdbb84710620a0440a67a873ed8f2c4'),
    ('root_descriptor_count', 0x2b7fc0b, 63, '3c63a6b08d4e111993d8ee0f337684dc12129e54b23eff7d2082c442512dbda5'),
    ('root_descriptor_dispatch', 0x2b80771, 115, '51bc123135ed51ea4d8e86044041fb96abee2d9ce11aac11274eeccdd02d0702'),
    ('root_split_serial', 0x29f9300, 214, '970b8ef7a68bac4d9135a060aaaa06c295bd3ccb46c8dc679e4693a3c6b71b15'),
    ('root_serial_worker', 0x26e166e, 212, '665c106a9632d04da12c2466fc08b2d2290ba1611e5691b8057fa1586f4286ac'),
    ('root_freeze_visitor', 0x22a0fa0, 274, '5cac0b763bf1e8e3e697e105fdfa21cdd48a2280e72d64a2a1adfc0a744d0737'),
    ('root_freeze_constructor', 0x22a0b60, 77, 'a8287cbc83d30d78e7f4e9ada9e6af07731bec12049cfef9a2873f43209b9749'),
    ('collection_wrapper_input', 0x22ed710, 101, '4887ecb215ea70c03308f49253736c11c6899ba1ec79c7275f92b545622d23b5'),
    ('collection_wrapper_output', 0x22ed775, 297, 'db57f05f95a02a306ea6bcaf21f51bdd5e8a25977d672667fab29380e1bcbc2e'),
    ('collection_reserve', 0x2ccdbf0, 217, '2cb7a9373246e301194b3c370bba3f05a20575f41f882602d1c078bd84541f34'),
    ('collection_failure', 0x2ccdccc, 116, 'a87280d57ef6ea6aa124e8a5d980ac842ecfd44eeeafd58a989f889994786e70'),
    ('join_length_and_spans', 0x26a1e90, 144, '4c77c265f8b6e168dd7a294815b1961473308e033f4a551faa81144016f91cb1'),
    ('join_mismatch', 0x26a1f20, 27, 'bd32b18f19c56c5f298414e56b6231f492413681a989019ee40c19427b3644f6'),
    ('join_output_allocation', 0x231b370, 209, '26b3cb9fd0113c01a2e1060320960b8d2fa6abc49ea0bc626b4c7cf99c5bcc7b'),
    ('join_output_loop', 0x231b490, 104, 'd68447e05a8b50eb55384c787aa8879e9dc91c79dd97da1e78f0c1f43126213b'),
]

# These are manually selected instruction starts, not an x86 instruction census.
# Targets are re-derived from signed bytes, then checked against the expected edge.
EDGES = [
    ('task_allocation_failure', 0x2b3acef, 0x2b3ad95),
    ('task_final_copy_slot', 0x2b3ad25, 0x64df508),
    ('task_schedule_slot', 0x2b3ad3b, 0x64e7718),
    ('upper_copy_one_slot', 0x2b1e133, 0x64df508),
    ('upper_copy_two_slot', 0x2b1e186, 0x64df508),
    ('upper_allocation_failure', 0x2b1e1a6, 0x2b1eddd),
    ('upper_to_constructor', 0x2b1e1f8, 0x2d275d0),
    ('upper_to_adapter', 0x2b1e3ee, 0x2774590),
    ('upper_result_empty', 0x2b1e406, 0x2b1e430),
    ('upper_result_item_loop', 0x2b1e42e, 0x2b1e410),
    ('upper_end_result_sentinel', 0x2b1e526, 0x2b1e55a),
    ('upper_end_result_empty', 0x2b1e52b, 0x2b1e53d),
    ('constructor_copy_slot', 0x2d2763f, 0x64df508),
    ('constructor_to_end', 0x2d2766f, 0x2d25620),
    ('constructor_sentinel', 0x2d27682, 0x2d276b3),
    ('constructor_return_copy_slot', 0x2d276c0, 0x64df508),
    ('entry_to_engine', 0x27745e0, 0x2d23610),
    ('engine_equal_tag_bypass', 0x2d236b5, 0x2d236cf),
    ('engine_past_error', 0x2d236c3, 0x2d2523c),
    ('engine_equal_error', 0x2d236c9, 0x2d25177),
    ('engine_clock_boundary', 0x2d237a8, 0x2bdf270),
    ('engine_to_collection', 0x2d23b15, 0x22ed710),
    ('collection_to_reserve', 0x22ed770, 0x2ccdbf0),
    ('reserve_grow', 0x2ccdc1c, 0x2ccdcb0),
    ('reserve_underflow', 0x2ccdc25, 0x2ccdcd9),
    ('reserve_insufficient', 0x2ccdc2e, 0x2ccdce8),
    ('reserve_count_mismatch', 0x2ccdc98, 0x2ccdd03),
    ('engine_to_join', 0x2d23b6b, 0x26a1e90),
    ('join_count_mismatch', 0x26a1eb3, 0x26a1f20),
    ('join_to_output', 0x26a1f0e, 0x231b370),
    ('join_allocation_valid', 0x231b3f2, 0x231b3fe),
    ('join_allocation_success', 0x231b427, 0x231b441),
    ('engine_to_end', 0x2d24ed9, 0x2d25620),
    ('end_to_root', 0x2d25712, 0x2bb37c0),
    ('root_to_adapter', 0x2bb37ff, 0x26a21b0),
    ('root_adapter_to_capture', 0x26a2249, 0x269a1b0),
    ('capture_to_builder', 0x269a7f4, 0x2b7f5b0),
    ('capture_result_fallback', 0x269a7fb, 0x269a85f),
    ('builder_to_split', 0x2b807df, 0x29f9300),
    ('split_to_serial', 0x29f93c9, 0x26e1660),
    ('end_periodic', 0x2d25661, 0x2d25685),
    ('end_tag_not_one', 0x2d2566a, 0x2d256a0),
    ('end_past_early', 0x2d25673, 0x2d26226),
    ('end_mode_equal_a', 0x2d25681, 0x2d2568e),
    ('end_mode_not_equal_b', 0x2d2568c, 0x2d256a9),
    ('end_mode_equal_c', 0x2d256a7, 0x2d2568e),
    ('end_tag_not_one_later', 0x2d256b0, 0x2d256cb),
    ('end_past_late', 0x2d256b9, 0x2d2623f),
    ('end_interval', 0x2d256f9, 0x2d257bc),
    ('end_interval_64_width', 0x2d257cd, 0x2d257e5),
    ('end_interval_64_nonzero', 0x2d257da, 0x2d27112),
    ('end_interval_32_nonzero', 0x2d257ef, 0x2d27112),
    ('end_clear_branch_other', 0x2d2574e, 0x2d258f2),
    ('end_sentinel_after_root', 0x2d25910, 0x2d25b48),
    ('end_replace_guard', 0x2d25943, 0x2d25a0b),
    ('end_snapshot_bypass', 0x2d262ae, 0x2d27112),
    ('end_to_link', 0x2d262ea, 0x22ed1f0),
    ('link_to_adapter', 0x22ed2bb, 0x26a23d0),
    ('link_prepare_slot', 0x22ed310, 0x64e09e0),
    ('link_prepare_failure', 0x22ed319, 0x22ed599),
    ('link_secondary_slot', 0x22ed339, 0x64e4f38),
    ('link_adapter_direct', 0x26a2469, 0x269ab70),
    ('parent_to_binary', 0x269ac4d, 0x26a2810),
    ('binary_to_outer', 0x26a28a0, 0x22ebdc0),
    ('binary_serialize_failure', 0x26a28be, 0x26a2b88),
    ('binary_delivery_slot', 0x26a28f3, 0x64e09e8),
    ('binary_delivery_failure', 0x26a2901, 0x26a2b1e),
    ('outer_map_header', 0x22ebdef, 0x25e7670),
    ('outer_field_name', 0x22ebe46, 0x25e8750),
    ('outer_to_fields', 0x22ebe5a, 0x2c6bee0),
    ('fields_map_header', 0x2c6bf0f, 0x25e7670),
    ('fields_to_freeze', 0x2c6c1c4, 0x2ceabe0),
    ('fields_freeze_failure', 0x2c6c1cd, 0x2c6c7ee),
    ('freeze_name_writer', 0x2ceac1b, 0x25e8750),
    ('freeze_name_failure', 0x2ceac27, 0x2ceac86),
    ('freeze_non_one', 0x2ceac2d, 0x2ceac59),
    ('freeze_to_unsigned', 0x2ceac37, 0x25e9c70),
    ('freeze_unsigned_ok', 0x2ceac45, 0x2ceac7d),
    ('unsigned_16_select', 0x25e9c87, 0x25e9ccf),
    ('unsigned_32_select', 0x25e9cd6, 0x25e9cfc),
    ('unsigned_64_select', 0x25e9d03, 0x25e9d29),
    ('unsigned_to_16', 0x25e9cdd, 0x25ea4b0),
    ('unsigned_to_32', 0x25e9d0a, 0x25ea780),
    ('map_to_marker', 0x25e76bd, 0x25eab50),
    ('prepare_output_slot', 0x1505b37, 0x64e09e8),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data, expected=SHA115):
    require(digest(data) == expected, 'target SHA-256 mismatch')


def section_by_name(secs, name):
    found = [s for s in secs if s['name'] == name]
    require(len(found) == 1 and found[0]['type'] != 8, 'missing, duplicate or NOBITS section: ' + name)
    return found[0]


def mapping(secs, va, size, *, executable=False):
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
            'invalid address or size')
    found = [s for s in secs if s['type'] != 8 and s['flags'] & 2
             and (not executable or s['flags'] & 4)
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(found) == 1, 'address does not have one file-backed allocated mapping')
    s = found[0]
    return s['offset'] + va - s['address']


def read_va(data, secs, va, size, *, executable=False):
    offset = mapping(secs, va, size, executable=executable)
    result = data[offset:offset + size]
    require(len(result) == size, 'truncated byte range')
    return result


def require_bytes(actual, expected, what):
    require(actual == expected, 'unexpected instruction bytes: ' + what)


def verify_window(data, secs, spec):
    name, va, size, expected = spec
    raw = read_va(data, secs, va, size, executable=True)
    require(digest(raw) == expected, 'window changed: ' + name)
    return raw


def frames_for(data, secs, table, selected):
    _, raw = fde_extents.eh_frame_records(data, secs)
    by_start = {}
    for fde in raw:
        by_start.setdefault(fde['start'], []).append(fde)
    indexed = {row['start']: row for row in table}
    ordered = []
    for label, start in selected:
        matches = by_start.get(start, [])
        require(len(matches) == 1 and start in indexed, 'selected FDE is missing or ambiguous')
        fde = matches[0]
        require(indexed[start]['fde'] == fde['fde'] and fde['end'] > start,
                'unwind header and FDE disagree')
        offset = mapping(secs, start, fde['end'] - start, executable=True)
        raw_body = data[offset:offset + fde['end'] - start]
        require(len(raw_body) == fde['end'] - start, 'truncated FDE body')
        row = dict(label=label, start=start, end=fde['end'], fde=fde['fde'],
                   cie=fde['cie'], lsda=fde['lsda'], offset=offset, sha256=digest(raw_body))
        ordered.append(row)
    ranges = sorted(ordered, key=lambda r: r['start'])
    require(all(a['end'] <= b['start'] for a, b in zip(ranges, ranges[1:])),
            'selected FDE extents overlap')
    return ordered


def containing_frame(frames, va, size):
    matches = [f for f in frames if f['start'] <= va and va + size <= f['end']]
    require(len(matches) == 1, 'selected site outside one selected FDE')
    return matches[0]


def verify_windows(data, secs, frames):
    rows = []
    for spec in WINDOWS:
        name, va, size, _ = spec
        raw = verify_window(data, secs, spec)
        owner = containing_frame(frames, va, size)
        rows.append(dict(label=name, va=va, offset=mapping(secs, va, size, executable=True),
                         owner=owner['start'], raw=raw.hex(), sha256=digest(raw)))
    return rows


def decode_transfer(raw, site, expected=None):
    require(len(raw) >= 2, 'short transfer')
    if raw[0] in (0xe8, 0xe9):
        size, disp, kind = 5, 1, 'call' if raw[0] == 0xe8 else 'jump'
    elif raw[:2] in (b'\xff\x15', b'\xff\x25'):
        size, disp, kind = 6, 2, 'indirect_slot_call' if raw[1] == 0x15 else 'indirect_slot_jump'
    elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        size, disp, kind = 6, 2, 'conditional_near'
    elif 0x70 <= raw[0] <= 0x7f:
        size, disp, kind = 2, 1, 'conditional_short'
    else:
        raise ValueError('unsupported transfer opcode')
    require(len(raw) >= size, 'truncated transfer')
    delta = struct.unpack_from('<b' if size == 2 else '<i', raw, disp)[0]
    target = site + size + delta
    require(expected is None or target == expected, 'transfer destination changed')
    return kind, size, target


def read_edges(data, secs, frames, windows):
    rows = []
    for name, va, expected in EDGES:
        raw = read_va(data, secs, va, 6, executable=True)
        kind, size, target = decode_transfer(raw, va, expected)
        frame = containing_frame(frames, va, size)
        require(any(w['owner'] == frame['start'] and w['va'] <= va
                    and va + size <= w['va'] + len(bytes.fromhex(w['raw'])) for w in windows),
                'selected transfer lacks a checked window')
        rows.append(dict(label=name, va=va, offset=mapping(secs, va, size, executable=True),
                         owner=frame['start'], kind=kind, target=target, raw=raw[:size].hex()))
    return rows


def relative_relocations(data, secs):
    s = section_by_name(secs, '.rela.dyn')
    require(s['size'] % 24 == 0, 'malformed relocation section')
    out = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', data, off)
        out.setdefault(address, []).append((info & 0xffffffff, info >> 32, addend, off))
    return out


def one_relative(relocs, slot):
    rows = relocs.get(slot, [])
    require(len(rows) == 1 and rows[0][0] == 8 and rows[0][1] == 0,
            'missing, duplicate or non-relative relocation')
    return rows[0]


def location(data, secs, relocs, va):
    kind, sym, path_va, reloc_off = one_relative(relocs, va)
    raw = read_va(data, secs, va, 24)
    word, length, line, column = struct.unpack('<QQII', raw)
    require(word == 0 and 0 < length <= 256 and line > 0 and column > 0,
            'malformed Location record')
    path = read_va(data, secs, path_va, length)
    require(path.endswith(b'l1/src/abci/state.rs'), 'unexpected Location file')
    # A historical path can include build-machine prefixes; keep only its digest.
    return dict(va=va, offset=mapping(secs, va, 24), path_va=path_va,
                path_length=length, path_sha256=digest(path), line=line, column=column,
                reloc_offset=reloc_off, relocation_type=kind, symbol=sym)


def rel_lea(data, secs, va, prefix):
    raw = read_va(data, secs, va, len(prefix) + 4, executable=True)
    require_bytes(raw[:len(prefix)], prefix, 'RIP-relative LEA')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def literal(data, secs, va, length):
    raw = read_va(data, secs, va, length)
    return dict(va=va, offset=mapping(secs, va, length), length=length,
                hex=raw.hex(), ascii=raw.decode('ascii'), sha256=digest(raw))


def extract_constants(data, secs):
    def at(va, expected):
        raw = read_va(data, secs, va, len(expected), executable=True)
        require_bytes(raw, expected, hex(va))
        return raw
    engine = at(0x2d23693, bytes.fromhex('488bbbe8100000'))
    end = at(0x2d25663, bytes.fromhex('83bee810000001'))
    payload = at(0x2c6c1b7, bytes.fromhex('498b8ef0100000'))
    field_load = at(0x2c6c1b0, bytes.fromhex('498b96e8100000'))
    at(0x2d236b1, bytes.fromhex('4883ff01'))
    at(0x2d236b7, bytes.fromhex('488b7b28'))
    at(0x2d2563e, bytes.fromhex('4c8b7e28'))
    at(0x2d2567c, bytes.fromhex('41837d0002'))
    at(0x2d25687, bytes.fromhex('41837d0002'))
    at(0x2d256a2, bytes.fromhex('41837d0002'))
    at(0x2d257bc, bytes.fromhex('488b8ec8390000'))
    at(0x2d257d4, bytes.fromhex('48f7f1'))
    at(0x2d257ea, bytes.fromhex('f7f1'))
    at(0x2ceac29, bytes.fromhex('4983ff01'))
    at(0x22a0fb3, bytes.fromhex('833f01'))
    at(0x22a0fd8, bytes.fromhex('4883c708'))
    at(0x2d24ee9, bytes.fromhex('8b91e8100000'))
    at(0x2d24ef7, bytes.fromhex('85c2'))
    at(0x2d24f03, bytes.fromhex('483b81f0100000'))
    at(0x2d24f0a, bytes.fromhex('0f95c2'))
    at(0x2d24f0f, bytes.fromhex('09c2'))
    flag_spill = at(0x2d25826, bytes.fromhex('899c2488000000'))
    at(0x2d258eb, bytes.fromhex('8b9c2488000000'))
    at(0x2d2598e, bytes.fromhex('899c2488000000'))
    at(0x2d25b41, bytes.fromhex('8b9c2488000000'))
    at(0x2d25a66, bytes.fromhex('89dd'))
    at(0x2d25a76, bytes.fromhex('89eb'))
    at(0x2d25650, bytes.fromhex('48c1c804'))
    magic_insn = read_va(data, secs, 0x2d25642, 10, executable=True)
    limit_insn = read_va(data, secs, 0x2d25654, 10, executable=True)
    require_bytes(magic_insn[:2], b'\x48\xb8', 'periodic multiplier')
    require_bytes(limit_insn[:2], b'\x48\xb9', 'periodic limit')
    magic = struct.unpack_from('<Q', magic_insn, 2)[0]
    limit = struct.unpack_from('<Q', limit_insn, 2)[0]
    inv = pow(magic, -1, 1 << 64)
    period = inv << 4
    require(period < (1 << 64) and limit == MASK64 // period + 1,
            'unproved periodic parameter relationship')
    # Fixed opcode witnesses for each normal-capacity integer byte order.
    at(0x25e9ca0, bytes.fromhex('84d2'))
    at(0x25e9dc8, bytes.fromhex('c60430cc'))
    at(0x25ea4d7, bytes.fromhex('c60401cd'))
    at(0x25ea569, bytes.fromhex('66c1c608'))
    at(0x25ea7a7, bytes.fromhex('c60401ce'))
    at(0x25ea839, bytes.fromhex('0fce'))
    nil = at(0x2ceac75, bytes.fromhex('c60430c0'))[-1]
    cmp8 = at(0x25e9c80, bytes.fromhex('4881fa00010000'))
    cmp16 = at(0x25e9ccf, bytes.fromhex('4881fa00000100'))
    shift = at(0x25e9cff, bytes.fromhex('48c1e820'))[-1]
    field_va = rel_lea(data, secs, 0x2ceac06, b'\x48\x8d\x05')
    field_len = struct.unpack_from('<I', at(0x2ceac0d, bytes.fromhex('ba17000000')), 1)[0]
    field = literal(data, secs, field_va, field_len)
    require(field['ascii'] == 'scheduled_freeze_height', 'field literal changed')
    freeze_va = rel_lea(data, secs, 0x2d262ca, b'\x48\x8d\x05')
    periodic_va = rel_lea(data, secs, 0x2d262d1, b'\x48\x8d\x15')
    freeze_name = literal(data, secs, freeze_va, 6)
    periodic_name = literal(data, secs, periodic_va, 8)
    require((freeze_name['ascii'], periodic_name['ascii']) == ('freeze', 'periodic'),
            'snapshot labels changed')
    past_va = rel_lea(data, secs, 0x2d2523c, b'\x48\x8d\x3d')
    past_len = struct.unpack_from('<I', at(0x2d2524a, bytes.fromhex('be3e000000')), 1)[0]
    equal_va = rel_lea(data, secs, 0x2d25183, b'\x48\x8d\x3d')
    equal_len = struct.unpack_from('<I', at(0x2d2517e, bytes.fromhex('be29000000')), 1)[0]
    past_msg = literal(data, secs, past_va, past_len)
    equal_msg = literal(data, secs, equal_va, equal_len)
    require(past_msg['ascii'] == 'assertion failed: freeze_height >= self.locus.context.height()'
            and equal_msg['ascii'] == 'assertion failed: !self.state.is_frozen()',
            'failure literal changed')
    require(struct.unpack_from('<I', engine, 3)[0] == struct.unpack_from('<I', end, 2)[0]
            == struct.unpack_from('<I', field_load, 3)[0], 'freeze tag offsets differ')
    return dict(tag_offset=struct.unpack_from('<I', engine, 3)[0],
                payload_offset=struct.unpack_from('<I', payload, 3)[0],
                engine_compare_bits=64, end_compare_bits=32, root_compare_bits=32,
                writer_compare_bits=64,
                tag_some=end[-1], snapshot_flag_spill_offset=struct.unpack_from('<I', flag_spill, 3)[0],
                magic=magic, rotated_bits=4, threshold_exclusive=limit,
                inverse=inv, period=period, nil=nil,
                u8_limit=struct.unpack_from('<I', cmp8, 3)[0],
                u16_limit=struct.unpack_from('<I', cmp16, 3)[0],
                u32_limit=1 << shift, marker_u8=0xcc, marker_u16=0xcd,
                marker_u32=0xce, field=field,
                labels=dict(freeze=freeze_name, periodic=periodic_name),
                failures=dict(past=past_msg, equal=equal_msg))


def check_word(n):
    require(type(n) is int and 0 <= n <= MASK64, 'expected a u64')


def is_periodic(n, c):
    check_word(n)
    x = (n * c['magic']) & MASK64
    k = c['rotated_bits']
    rotated = ((x >> k) | ((x << (64 - k)) & MASK64)) & MASK64
    return rotated < c['threshold_exclusive']


def entry_decision(tag, target, height):
    for n in (tag, target, height):
        check_word(n)
    if tag != 1:
        return 'continue'
    if target < height:
        return 'past_failure'
    if target == height:
        return 'equal_failure'
    return 'continue'


def end_decision(tag, target, height, mode, interval, c):
    for n in (tag, target, height, mode, interval):
        check_word(n)
    special = is_periodic(height, c)
    low_tag = tag & 0xffffffff
    if not special and low_tag == c['tag_some']:
        if target < height:
            return 'first_past_failure'
        special = target == height
    if mode & 0xffffffff == 2:
        return 'mode_sentinel'
    if low_tag == c['tag_some'] and target < height:
        return 'second_past_failure'
    freeze = low_tag == c['tag_some'] and target == height
    if special:
        return 'write_freeze' if freeze else 'write_periodic'
    if interval == 0:
        return 'division_by_zero'
    if height % interval:
        return 'skip_snapshot'
    return 'interval_path_no_snapshot'


def field_bytes(tag, value, c):
    check_word(tag)
    check_word(value)
    if tag != c['tag_some']:
        return bytes([c['nil']])
    if value < c['u8_limit'] // 2:
        return bytes([value])
    if value < c['u8_limit']:
        return bytes([c['marker_u8'], value])
    if value < c['u16_limit']:
        return bytes([c['marker_u16']]) + value.to_bytes(2, 'big')
    if value < c['u32_limit']:
        return bytes([c['marker_u32']]) + value.to_bytes(4, 'big')
    # The selected caller delegates the wider range to an unowned boundary.
    return None


def field_hex(tag, value, c):
    raw = field_bytes(tag, value, c)
    return 'unresolved' if raw is None else raw.hex()


def root_choice(tag, c):
    """Selected visitor branch, before its container and child-status checks."""
    check_word(tag)
    return 'payload_then_one' if tag & 0xffffffff == c['tag_some'] else 'zero_only'


def change_byte(old_tag, old_value, new_tag, new_value):
    """Model the final byte from the selected post-end comparison instructions."""
    for n in (old_tag, old_value, new_tag, new_value):
        check_word(n)
    if old_tag & new_tag & 0xffffffff:
        return int(old_value != new_value)
    return (old_tag | new_tag) & 0xff


def change_cases():
    inputs = [(0, 0, 0, 42), (0, 0, 1, 42), (1, 9, 0, 9),
              (1, 9, 1, 9), (1, 9, 1, 10), (2, 9, 0, 10),
              (2, 9, 2, 9), (2, 9, 2, 10), (0x100, 9, 0, 10),
              (0x100000001, 9, 1, 10), (0xffffffff, 9, 0, 10),
              (0x100000000, 9, 0x100000000, 10)]
    return [dict(old_tag=a, old_value=b, new_tag=c, new_value=d,
                 result=change_byte(a, b, c, d)) for a, b, c, d in inputs]


def reserve_decision(capacity, length, requested, produced=None, *,
                     grown_capacity=None, grown_length=None):
    """Model only the selected reserve checks, with an explicit growth boundary."""
    for n in (capacity, length, requested):
        check_word(n)
    remaining_wrapped = (capacity - length) & MASK64
    if requested > remaining_wrapped:
        if grown_capacity is None and grown_length is None:
            return 'grow_required'
        check_word(grown_capacity)
        check_word(grown_length)
        capacity, length = grown_capacity, grown_length
    if capacity < length:
        return 'capacity_underflow'
    if capacity - length < requested:
        return 'insufficient_capacity'
    if produced is None:
        return 'producer_required'
    check_word(produced)
    if produced != requested:
        return 'produced_count_mismatch'
    return 'advance_length'


def join_decision(left, right, c):
    """Under valid non-wrapping spans, model the join's checked allocation bound."""
    check_word(left)
    check_word(right)
    if left != right:
        return 'length_mismatch'
    if left > c['max_output_items']:
        return 'allocation_size_failure'
    return 'empty_output' if left == 0 else 'allocation_required'


def collection_cases(c):
    vectors = [(10, 3, 7, 7, None, None), (10, 3, 8, None, None, None),
               (10, 3, 8, 8, 20, 3), (10, 3, 8, 8, 10, 3),
               (3, 10, 0, 0, None, None), (10, 3, 7, 6, None, None),
               (MASK64, MASK64 - 1, 1, 1, None, None)]
    reserve = [dict(capacity=a, length=b, requested=d, produced=e, grown_capacity=f,
                    grown_length=g, decision=reserve_decision(a, b, d, e,
                                      grown_capacity=f, grown_length=g))
               for a, b, d, e, f, g in vectors]
    bound = c['max_output_items']
    join = [dict(left=a, right=b, decision=join_decision(a, b, c))
            for a, b in ((0, 0), (1, 0), (1, 1), (bound, bound),
                         (bound + 1, bound + 1), (MASK64, MASK64))]
    return dict(reserve=reserve, join=join)


def mutation_choice(header, count, lookup_result, c):
    """Identify only the two pinned store sites, not the final context state."""
    for n in (header, count, lookup_result):
        check_word(n)
    if header == c['sentinel'] and count < c['small_limit_exclusive']:
        return 'small_sentinel_stores'
    if header != c['sentinel'] and lookup_result != 0 and count >= c['replacement_limit_inclusive']:
        return 'replacement_stores'
    return 'other_or_unresolved'


def mutation_cases(c):
    sentinel = c['sentinel']
    values = [(sentinel, 0, 0), (sentinel, 31, 1), (sentinel, 32, 1),
              (sentinel, 64, 1), (0, 63, 1), (0, 64, 0), (0, 64, 1),
              (MASK64, MASK64, 1)]
    return [dict(header=h, count=n, lookup=r, decision=mutation_choice(h, n, r, c))
            for h, n, r in values]


def model_cases(c):
    rows = []
    # The models are synthetic boundary inputs; they are not target executions.
    for value in (0, c['u8_limit']//2-1, c['u8_limit']//2, c['u8_limit']-1,
                  c['u8_limit'], c['u16_limit']-1, c['u16_limit'],
                  c['u32_limit']-1, c['u32_limit'], MASK64):
        rows.append(dict(kind='wire', tag=1, target=value, height=0, mode=0,
                         interval=1, entry='not_applicable', end='not_applicable',
                         root='not_applicable',
                         bytes=field_hex(1, value, c)))
    cases = [
        (0, 10000, 10000, 0, 10), (1, 9999, 10000, 0, 10),
        (1, 9999, 10000, 2, 10), (1, 9998, 9999, 2, 10),
        (1, 10000, 10000, 0, 10), (1, 10001, 10000, 0, 10),
        (1, 10000, 9999, 0, 10), (0, 0, 9999, 0, 3),
        (0, 0, 9999, 0, 10), (0, 0, 9999, 0, 0),
        (0x100000001, 9998, 9999, 0, 10),
        (0x100000001, 9999, 9999, 0, 10),
        (0x100000001, 10000, 9999, 0, 10),
        (0xffffffff, 9999, 9999, 0, 10),
        (1, MASK64, MASK64, 0, 1),
    ]
    for tag, target, height, mode, interval in cases:
        rows.append(dict(kind='decision', tag=tag, target=target, height=height,
                         mode=mode, interval=interval,
                         entry=entry_decision(tag, target, height),
                         end=end_decision(tag, target, height, mode, interval, c),
                         root=root_choice(tag, c),
                         bytes=field_hex(tag, target, c)))
    return rows


def extract_map(data, secs):
    def fixed(va, expected):
        actual = read_va(data, secs, va, len(expected), executable=True)
        require_bytes(actual, expected, hex(va))
        return actual
    outer_insn = fixed(0x22ebdea, bytes.fromhex('ba01000000'))
    inner_insn = fixed(0x2c6bf0a, bytes.fromhex('ba3b000000'))
    small = fixed(0x25e7689, bytes.fromhex('83fa10'))[-1]
    base = struct.unpack_from('<I', fixed(0x25e768f, bytes.fromhex('bd80000000')), 1)[0]
    xor = fixed(0x25e7687, bytes.fromhex('34df'))[-1]
    fixed(0x25eab88, bytes.fromhex('4080e60f'))
    fixed(0x25eab8c, bytes.fromhex('4080ce80'))
    fixed(0x25e7780, bytes.fromhex('66c1c008'))
    fixed(0x25e7788, bytes.fromhex('66890431'))
    outer = struct.unpack_from('<I', outer_insn, 1)[0]
    inner = struct.unpack_from('<I', inner_insn, 1)[0]
    require(outer < small <= inner < (1 << 16), 'unexpected selected map sizes')
    key_va = rel_lea(data, secs, 0x22ebe37, b'\x48\x8d\x35')
    key_len = struct.unpack_from('<I', fixed(0x22ebe3e, bytes.fromhex('ba08000000')), 1)[0]
    key = literal(data, secs, key_va, key_len)
    require(key['ascii'] == 'exchange', 'outer key changed')
    return dict(outer_count=outer, inner_count=inner, key=key,
                normal_outer_header=bytes([base | outer]).hex(),
                normal_inner_header=(bytes([xor ^ 1]) + inner.to_bytes(2, 'big')).hex())


def decode_capture_pairs(raw, start_va, stack_start):
    """Decode only the repeated LEA/store pattern selected in the capture FDE."""
    require(len(raw) % 15 == 0, 'truncated capture pair sequence')
    rows = []
    for off in range(0, len(raw), 15):
        one = raw[off:off + 15]
        require(one[:3] == b'\x49\x8d\x87' and one[7:11] == b'\x48\x89\x84\x24',
                'capture opcode changed')
        state_offset = struct.unpack_from('<I', one, 3)[0]
        stack_offset = struct.unpack_from('<I', one, 11)[0]
        require(stack_offset == stack_start + 8 * len(rows), 'capture slots not consecutive')
        rows.append(dict(site=start_va + off, store_site=start_va + off + 7,
                         state_offset=state_offset, stack_offset=stack_offset,
                         raw=one.hex()))
    return rows


def decode_slot_stores(raw):
    """Decode selected R12 sentinel stores; require the entire input to match."""
    offsets = []
    cursor = 0
    while cursor < len(raw):
        rest = raw[cursor:]
        if rest.startswith(b'\x4c\x89\x20'):
            size, offset = 3, 0
        elif rest.startswith(b'\x4c\x89\x60'):
            require(len(rest) >= 4, 'truncated short sentinel store')
            size, offset = 4, struct.unpack_from('<b', rest, 3)[0]
        elif rest.startswith(b'\x4c\x89\xa0'):
            require(len(rest) >= 7, 'truncated sentinel store')
            size, offset = 7, struct.unpack_from('<i', rest, 3)[0]
        else:
            raise ValueError('unrecognized sentinel store')
        require(offset == 24 * len(offsets), 'sentinel slots not consecutive')
        offsets.append(offset)
        cursor += size
    return offsets


def root_capture_evidence(data, secs, relocs, constants):
    def at(va, expected):
        actual = read_va(data, secs, va, len(expected), executable=True)
        require_bytes(actual, expected, hex(va))
        return actual

    at(0x269a1c1, bytes.fromhex('4989f7'))
    first = at(0x269a1dd, bytes.fromhex('4c89bc2428010000'))
    initial = struct.unpack_from('<I', first, 4)[0]
    next_lea = at(0x269a1d6, bytes.fromhex('498d87c0070000'))
    second = at(0x269a1e5, bytes.fromhex('4889842430010000'))
    second_stack = struct.unpack_from('<I', second, 4)[0]
    require(second_stack == initial + 8, 'second capture slot changed')
    captures = [dict(site=0x269a1dd, store_site=0x269a1dd,
                     state_offset=0, stack_offset=initial, raw=first.hex()),
                dict(site=0x269a1d6, store_site=0x269a1e5,
                     state_offset=struct.unpack_from('<I', next_lea, 3)[0],
                     stack_offset=second_stack, raw=(next_lea + second).hex())]
    captures += decode_capture_pairs(read_va(data, secs, 0x269a1ed, 0x269a625-0x269a1ed,
                                             executable=True), 0x269a1ed, initial + 16)
    for index, row in enumerate(captures):
        row['index'] = index
    matching = [r for r in captures if r['state_offset'] == constants['tag_offset']]
    require(len(matching) == 1, 'freeze capture missing or ambiguous')
    capture = matching[0]
    at(0x269a7e7, bytes.fromhex('488dbc2428010000'))

    allocation = struct.unpack_from('<I', at(0x269a625, bytes.fromhex('bf88050000')), 1)[0]
    sentinel = struct.unpack_from('<Q', at(0x269a639,
                              bytes.fromhex('49bc0100000000000080')), 2)[0]
    slot_bytes = read_va(data, secs, 0x269a643, 0x269a7cd - 0x269a643, executable=True)
    slot_offsets = decode_slot_stores(slot_bytes)
    count = struct.unpack_from('<I', at(0x269a7cd,
                                 bytes.fromhex('48c74424183b000000')), 5)[0]
    require(count == len(slot_offsets) and allocation == count * 24,
            'sentinel allocation and length disagree')
    at(0x2b7f5b7, bytes.fromhex('48897c2408'))
    first_separate = struct.unpack_from('<I', at(0x2b7f5c8,
                                      bytes.fromhex('488b8780000000')), 3)[0] // 8
    load = at(0x2b7f702, bytes.fromhex('488b8fe0000000'))
    pointer = struct.unpack_from('<I', load, 3)[0]
    store = at(0x2b7f709, bytes.fromhex('48898c24d8000000'))
    descriptor_stack = struct.unpack_from('<I', store, 4)[0]
    table_va = rel_lea(data, secs, 0x2b7f711, b'\x48\x8d\x0d')
    at(0x2b7f718, bytes.fromhex('48898c24e0000000'))
    at(0x2b7fc1a, bytes.fromhex('48837e103b'))
    at(0x2b7fc3d, bytes.fromhex('488d4c2408'))
    at(0x2b7fc4a, bytes.fromhex('48c78424c007000001000000'))
    at(0x2b7fc5e, bytes.fromhex('488d4c2418'))
    at(0x2b807d3, bytes.fromhex('bf3b000000'))
    require(pointer == capture['stack_offset'] - initial, 'builder does not select capture')
    descriptor_index = (descriptor_stack - 8) // 16
    require(descriptor_stack >= 8 and (descriptor_stack - 8) % 16 == 0
            and capture['index'] - first_separate + 1 == descriptor_index,
            'capture and descriptor grouping disagree')

    table_raw = read_va(data, secs, table_va, 40)
    words = struct.unpack('<QQQQQ', table_raw)
    require(words == (0, 16, 8, 0, 0), 'field descriptor table changed')
    bindings = []
    for relative, expected, role in ((24, 0x22a0fa0, 'visitor'),
                                     (32, 0x22a0b60, 'constructor')):
        kind, sym, addend, off = one_relative(relocs, table_va + relative)
        require(addend == expected, 'field descriptor relocation changed')
        bindings.append(dict(slot=table_va + relative, type=kind, symbol=sym,
                             addend=addend, offset=off, role=role))
    at(0x26e16fa, bytes.fromhex('41ff5618'))
    at(0x26e1720, bytes.fromhex('41ff5620'))
    ctor_size = struct.unpack_from('<I', at(0x22a0b64, bytes.fromhex('bf30000000')), 1)[0]
    at(0x22a0b74, bytes.fromhex('48b90100000000000080'))
    at(0x22a0b7e, bytes.fromhex('48890848894818'))
    at(0x22a0b85, bytes.fromhex('48c70302000000'))
    at(0x22a0b90, bytes.fromhex('48c7431002000000'))
    require(ctor_size == 2 * 24, 'visitor constructor size changed')
    one_va = rel_lea(data, secs, 0x22a104a, b'\x48\x8d\x3d')
    zero_va = rel_lea(data, secs, 0x22a1098, b'\x48\x8d\x3d')
    one = read_va(data, secs, one_va, 8)
    zero = read_va(data, secs, zero_va, 8)
    require(struct.unpack('<Q', one)[0] == 1 and struct.unpack('<Q', zero)[0] == 0,
            'visitor constants changed')
    root = dict(capture_count=len(captures), capture_stack_base=initial,
                selected_capture_index=capture['index'], selected_capture=capture,
                first_separate_capture_index=first_separate,
                descriptor_index=descriptor_index, descriptor_input_offset=pointer,
                descriptor_pair_stack_offset=descriptor_stack, descriptor_count=count,
                table=dict(va=table_va, file_offset=mapping(secs, table_va, len(table_raw)),
                           words=list(words), raw=table_raw.hex(), sha256=digest(table_raw),
                           relocations=bindings),
                allocation_bytes=allocation, slot_size=24, sentinel=sentinel,
                slot_offsets=slot_offsets,
                visitor_constructor_bytes=ctor_size, visitor_constructor_slots=2,
                visitor_one=dict(va=one_va, file_offset=mapping(secs, one_va, 8), hex=one.hex()),
                visitor_zero=dict(va=zero_va, file_offset=mapping(secs, zero_va, 8), hex=zero.hex()))
    return captures, root


def context_mutations(data, secs):
    def fixed(va, expected):
        actual = read_va(data, secs, va, len(expected), executable=True)
        require_bytes(actual, expected, hex(va))
        return actual
    def store(va, code):
        raw = fixed(va, bytes.fromhex(code))
        return dict(site=va, context_offset=struct.unpack_from('<I', raw, 3)[0],
                    value=struct.unpack_from('<I', raw, 7)[0], size=8)
    # These are separate guarded paths, not an unconditional write sequence.
    small = [store(0x2d25762, '49c7850804000000000000'),
             store(0x2d2576d, '49c7851804000000000000')]
    replacement = [store(0x2d25960, '49c7850004000000000000'),
                   store(0x2d2596b, '49c7850804000008000000')]
    fixed(0x2d25976, bytes.fromhex('0f57c0'))
    zero = fixed(0x2d25979, bytes.fromhex('410f118510040000'))
    replacement.append(dict(site=0x2d25979, context_offset=struct.unpack_from('<I', zero, 4)[0],
                            value=0, size=16))
    sentinel = struct.unpack_from('<Q', fixed(0x2d25732,
                                    bytes.fromhex('48b90000000000000080')), 2)[0]
    fixed(0x2d2573c, bytes.fromhex('4939ce'))
    small_limit = fixed(0x2d25742, bytes.fromhex('4883f820'))[-1]
    replacement_limit = fixed(0x2d25938, bytes.fromhex('4883f940'))[-1]
    fixed(0x2d2592a, bytes.fromhex('4885c0'))
    return dict(small_sentinel_path=small, replacement_path=replacement,
                small_limit_exclusive=small_limit, replacement_limit_inclusive=replacement_limit,
                sentinel=sentinel)


def collection_evidence(data, secs):
    def at(va, expected):
        raw = read_va(data, secs, va, len(expected), executable=True)
        require_bytes(raw, expected, hex(va))
        return raw
    # Specific LEA encodings below form 5*x*8 and 3*x*8, respectively.
    at(0x2ccdc0c, bytes.fromhex('488b07'))
    at(0x2ccdc0f, bytes.fromhex('4c8b6710'))
    at(0x2ccdc16, bytes.fromhex('4c29e1'))
    at(0x2ccdc19, bytes.fromhex('4839ce'))
    shift = at(0x2ccdc37, bytes.fromhex('48c1e005'))[-1]
    element = struct.unpack_from('<I', at(0x2ccdcb5,
                                  bytes.fromhex('41b820000000')), 2)[0]
    require(element == 1 << shift, 'reserve element size changed')
    at(0x2ccdc95, bytes.fromhex('4c39f8'))
    at(0x2ccdc9a, bytes.fromhex('4d01fc'))
    at(0x2ccdc9d, bytes.fromhex('4d896610'))
    at(0x26a1e9f, bytes.fromhex('488b4610'))
    at(0x26a1ea7, bytes.fromhex('488b4a10'))
    at(0x26a1eb0, bytes.fromhex('4839c8'))
    left = at(0x26a1ebf, bytes.fromhex('488d3480488d34f2'))
    right = at(0x26a1ece, bytes.fromhex('488d0440498d04c0'))
    require(left[-1] == 0xf2 and right[-1] == 0xc0, 'span encodings changed')
    output_shift = at(0x231b3d8, bytes.fromhex('48c1e606'))[-1]
    sentinel = struct.unpack_from('<Q', at(0x231b384,
                                  bytes.fromhex('48b90000000000000080')), 2)[0]
    adjust = struct.unpack('<b', at(0x231b3e6, bytes.fromhex('4883c1f8'))[-1:])[0]
    at(0x231b3df, bytes.fromhex('48c1e83a'))
    at(0x231b3f0, bytes.fromhex('08c1'))
    at(0x231b3fc, bytes.fromhex('0f0b'))
    at(0x26a1f39, bytes.fromhex('0f0b'))
    output_stride = 1 << output_shift
    byte_limit = (sentinel + adjust) & MASK64
    return dict(reserve_element_bytes=element, left_span_stride=5 * 8,
                right_span_stride=3 * 8, output_stride=output_stride,
                output_byte_limit=byte_limit, max_output_items=byte_limit // output_stride,
                length_field_offset=16, failure_instruction='ud2')


def upper_join_evidence(data, secs, relocs):
    """Join the selected incoming pointer, constructor, block call, and return slots."""
    def fixed(va, expected):
        actual = read_va(data, secs, va, len(expected), executable=True)
        require_bytes(actual, expected, hex(va))
        return actual
    def dword(va, raw, index):
        return struct.unpack_from('<I', fixed(va, bytes.fromhex(raw)), index)[0]

    input_base = fixed(0x2b1e11a, bytes.fromhex('488d7148'))[-1]
    first_dst = dword(0x2b1e126, '488dbc2490110000', 4)
    first_size = dword(0x2b1e12e, 'ba48030000', 1)
    second_dst = dword(0x2b1e171, '488dbc2470060000', 4)
    second_src = dword(0x2b1e179, '488db42488110000', 4)
    second_size = dword(0x2b1e181, 'ba50030000', 1)
    pointer_stack = dword(0x2b1e18c, '488b9c2490090000', 4)
    require(second_dst <= pointer_stack and pointer_stack + 8 <= second_dst + second_size,
            'state pointer outside second copy')
    first_pointer = second_src + pointer_stack - second_dst
    require(first_dst <= first_pointer and first_pointer + 8 <= first_dst + first_size,
            'state pointer outside first copy')
    input_pointer = input_base + first_pointer - first_dst
    seed_store = dword(0x2b1e1bf, '48899c2420060000', 4)
    context_stack = dword(0x2b1e1e5, '488dbc24180d0000', 4)
    seed_stack = dword(0x2b1e1ed, '4c8da42400020000', 4)
    context_input = dword(0x2d275e2, '4c8bb620040000', 3)
    require(seed_store - seed_stack == context_input, 'constructor input pointer join changed')
    local_pointer = dword(0x2d27612, '4c89b42460040000', 4)
    local_base = fixed(0x2d2762a, bytes.fromhex('4c8d742410'))[-1]
    fixed(0x2d2762f, bytes.fromhex('488db42480040000'))
    context_bytes = dword(0x2d27637, 'ba50040000', 1)
    fixed(0x2d2763c, bytes.fromhex('4c89f7'))
    fixed(0x2d276b3, bytes.fromhex('488d742410'))
    output_bytes = dword(0x2d276b8, 'ba70040000', 1)
    fixed(0x2d276bd, bytes.fromhex('4889df'))
    state_in_context = local_pointer - local_base
    require(state_in_context == context_bytes and output_bytes >= state_in_context + 8,
            'constructor output does not include state pointer')
    later_context = dword(0x2b1e3c8, '488d8424180d0000', 4)
    wrapper_context_slot = dword(0x2b1e3d0, '48898424a0000000', 4)
    wrapper_stack = dword(0x2b1e216, '488d9c2480000000', 4)
    fixed(0x2b1e3e8, bytes.fromhex('4c89e74889de'))
    wrapper_context_offset = fixed(0x27745d4, bytes.fromhex('488b7620'))[-1]
    fixed(0x2d2368b, bytes.fromhex('498b9c2450040000'))
    context_read = dword(0x2b1e29f, '488b842468110000', 4)
    require(context_stack == later_context
            and context_stack + state_in_context == context_read
            and wrapper_context_slot == wrapper_stack + wrapper_context_offset,
            'upper context handoff changed')
    end_result_offset = fixed(0x2d24fe6, bytes.fromhex('0f114078'))[-1]
    change_byte_offset = dword(0x2d24fea, '8890f8000000', 2)
    end_result_stack = dword(0x2b1e511, '488bb42478020000', 4)
    require(end_result_stack - seed_stack == end_result_offset, 'upper result slot join changed')
    fixed(0x2b1e519, bytes.fromhex('48b80000000000000080'))

    memcpy_slot = 0x64df508
    rows = relocs.get(memcpy_slot, [])
    require(len(rows) == 1 and rows[0][0] == 6 and rows[0][1] != 0 and rows[0][2] == 0,
            'external copy relocation changed')
    typ, sym_index, addend, reloc_offset = rows[0]
    symbols, strings = section_by_name(secs, '.dynsym'), section_by_name(secs, '.dynstr')
    require(symbols['type'] == 11 and strings['type'] == 3, 'dynamic symbol sections changed')
    sym_offset = sym_index * 24
    require(sym_offset + 24 <= symbols['size'], 'dynamic symbol index outside section')
    sym_file = symbols['offset'] + sym_offset
    name_offset, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, sym_file)
    require(name_offset < strings['size'], 'dynamic string outside section')
    string_file = strings['offset'] + name_offset
    string_limit = strings['offset'] + strings['size']
    end = data.find(b'\x00', string_file, string_limit)
    require(end >= 0 and data[string_file:end] == b'memcpy', 'dynamic copy name changed')
    dynamic = dict(slot=memcpy_slot, relocation_type=typ, symbol_index=sym_index,
                   addend=addend, relocation_file_offset=reloc_offset,
                   symbol_file_offset=sym_file, string_file_offset=string_file,
                   symbol_name='memcpy', symbol_info=info, symbol_other=other,
                   symbol_section_index=shndx, symbol_value=value, symbol_size=size,
                   role='external copy boundary; runtime binding not observed')
    return dict(input_state_pointer_offset=input_pointer,
                first_copy=dict(input_offset=input_base, stack_dst=first_dst, size=first_size),
                second_copy=dict(stack_src=second_src, stack_dst=second_dst, size=second_size),
                pointer_stack=pointer_stack, seed_stack=seed_stack, seed_pointer_stack=seed_store,
                constructor_input_pointer_offset=context_input, context_stack=context_stack,
                context_state_offset=state_in_context, context_state_stack=context_read,
                constructor_context_copy_size=context_bytes, constructor_return_copy_size=output_bytes,
                wrapper_context_slot=wrapper_context_slot,
                result_stack=seed_stack, end_result_offset=end_result_offset,
                end_result_stack=end_result_stack, change_byte_offset=change_byte_offset,
                external_copy=dynamic)


def task_evidence(data, secs, relocs, upper):
    """Join one task-construction copy with the relocated upper-dispatch slot."""
    def fixed(va, expected):
        actual = read_va(data, secs, va, len(expected), executable=True)
        require_bytes(actual, expected, hex(va))
        return actual
    def dword(va, code, index):
        return struct.unpack_from('<I', fixed(va, bytes.fromhex(code)), index)[0]

    fixed(0x2b3abbb, bytes.fromhex('4989fe'))
    fixed(0x2b3abef, bytes.fromhex('4c89f6'))
    first_dst = dword(0x2b3ac28, '488dbc24f4040000', 4)
    copy_slot = rel_lea(data, secs, 0x2b3ac30, b'\x4c\x8b\x35')
    require(copy_slot == upper['external_copy']['slot'], 'task copy slot changed')
    first_size = dword(0x2b3ac37, 'ba50030000', 1)
    fixed(0x2b3ac3c, bytes.fromhex('41ffd6'))
    vtable_slot = rel_lea(data, secs, 0x2b3ac57, b'\x48\x8d\x05')
    vtable_stack = dword(0x2b3ac5e, '4889842490000000', 4)
    second_dst = dword(0x2b3ac9a, '488dbc24bc000000', 4)
    second_src = dword(0x2b3aca2, '488d9c24f0040000', 4)
    second_size = dword(0x2b3acaa, 'ba54030000', 1)
    fixed(0x2b3acaf, bytes.fromhex('4889de41ffd6'))
    allocation_size = dword(0x2b3acdc, 'bf00040000', 1)
    task_stack = dword(0x2b3ad15, '488db42480000000', 4)
    final_size = dword(0x2b3ad1d, 'ba00040000', 1)
    fixed(0x2b3ad22, bytes.fromhex('4c89ff'))
    require(final_size == allocation_size, 'task allocation/copy sizes differ')
    task_pointer = upper['input_state_pointer_offset']
    stack_pointer = task_stack + task_pointer
    require(second_dst <= stack_pointer and stack_pointer + 8 <= second_dst + second_size,
            'task state pointer outside second copy')
    first_pointer = second_src + stack_pointer - second_dst
    require(first_dst <= first_pointer and first_pointer + 8 <= first_dst + first_size,
            'task state pointer outside first copy')
    input_pointer = first_pointer - first_dst
    kind, sym, addend, reloc_file = one_relative(relocs, vtable_slot)
    require(addend == 0x2b1df60 and vtable_stack - task_stack == 16,
            'task dispatch slot does not point to upper function')
    return dict(input_state_pointer_offset=input_pointer,
                first_copy=dict(stack_dst=first_dst, size=first_size),
                second_copy=dict(stack_src=second_src, stack_dst=second_dst, size=second_size),
                final_copy=dict(stack_src=task_stack, size=final_size),
                task_state_pointer_offset=task_pointer, vtable_pointer_offset=vtable_stack-task_stack,
                dispatch_slot=dict(va=vtable_slot, type=kind, symbol=sym,
                                   addend=addend, relocation_file_offset=reloc_file),
                limitation='Conditional copy and slot assignment; scheduler execution not observed.')


def read_relocation_witnesses(relocs):
    targets = [(0x64e09e0, 0x1505a50), (0x64e09e8, 0x15024a0),
               (0x64e4f38, 0x38d7f20)]
    rows = []
    for va, expected in targets:
        kind, sym, addend, offset = one_relative(relocs, va)
        require(addend == expected, 'relocation target changed')
        rows.append(dict(slot=va, type=kind, symbol=sym, addend=addend, offset=offset,
                         role='contextual call target, not ownership'))
    return rows


def build_evidence(data):
    authenticate(data)
    secs, table = elf_index.unwind_index(data)
    frames = frames_for(data, secs, table, FUNCTIONS)
    windows = verify_windows(data, secs, frames)
    edges = read_edges(data, secs, frames, windows)
    relocs = relative_relocations(data, secs)
    locations = [location(data, secs, relocs, va)
                 for va in (0x642d338, 0x642d350, 0x6437490, 0x64374a8, 0x64374c0)]
    constants = extract_constants(data, secs)
    map_info = extract_map(data, secs)
    cases = model_cases(constants)
    changes = change_cases()
    captures, root_info = root_capture_evidence(data, secs, relocs, constants)
    mutations = context_mutations(data, secs)
    mutation_models = mutation_cases(mutations)
    collection = collection_evidence(data, secs)
    collection_models = collection_cases(collection)
    upper = upper_join_evidence(data, secs, relocs)
    task = task_evidence(data, secs, relocs, upper)
    bindings = read_relocation_witnesses(relocs)
    return dict(frames=frames, windows=windows, edges=edges, locations=locations,
                constants=constants, map_info=map_info, cases=cases, relocations=bindings,
                captures=captures, root_info=root_info, mutations=mutations, upper=upper,
                changes=changes, collection=collection, collection_models=collection_models,
                task=task, mutation_models=mutation_models)


def old_crosscheck(new_data, old_data):
    """Check old/new navigation anchors; this does not claim equivalence."""
    authenticate(new_data)
    authenticate(old_data, SHA94)
    old_secs, old_index = elf_index.unwind_index(old_data)
    old_frames = frames_for(old_data, old_secs, old_index,
                            [('old_outer', 0x32725d0), ('old_location', 0x3273810)])
    old_relocs = relative_relocations(old_data, old_secs)
    old_loc_va = rel_lea(old_data, old_secs, 0x3273856, b'\x48\x8d\x0d')
    require(old_loc_va == 0x56dfbf8, 'old Location reference changed')
    old_loc = location(old_data, old_secs, old_relocs, old_loc_va)
    old_kind, old_size, old_target = decode_transfer(
        read_va(old_data, old_secs, 0x3273862, 6, executable=True), 0x3273862, 0x3c155a0)
    _, _, old_slot = decode_transfer(
        read_va(old_data, old_secs, 0x3272785, 6, executable=True), 0x3272785, 0x57755a8)
    require(one_relative(old_relocs, old_slot)[2] == 0x3273810, 'old loader slot changed')
    new_secs = elf_index.sections(new_data)
    new_relocs = relative_relocations(new_data, new_secs)
    new_loc_va = rel_lea(new_data, new_secs, 0x3c1352f, b'\x48\x8d\x15')
    require(new_loc_va == 0x64767a8, 'new Location reference changed')
    new_loc = location(new_data, new_secs, new_relocs, new_loc_va)
    require((old_loc['line'], old_loc['column']) == (107, 37), 'old source anchor changed')
    require((new_loc['line'], new_loc['column']) == (123, 37), 'new source anchor changed')
    return dict(old_release='94', old_sha256=SHA94, old_outer=hex(old_frames[0]['start']),
                old_wrapper=hex(old_frames[1]['start']), old_location=old_loc,
                old_call=dict(va=hex(0x3273862), kind=old_kind, size=old_size,
                              target=hex(old_target)),
                new_release='115', new_sha256=SHA115, new_location=new_loc,
                new_location_lea=hex(0x3c1352f),
                limitation='Contextual anchors only; no release equivalence inferred.')


def hex_or_dash(value):
    return '-' if value is None else hex(value)


def tsv(headers, rows):
    text = io.StringIO(newline='')
    writer = csv.writer(text, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return text.getvalue()


def json_text(data):
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + '\n'


def write_evidence(out, e):
    out.mkdir(parents=True, exist_ok=True)
    frames = e['frames']
    (out / 'functions.tsv').write_text(tsv(
        ['label', 'start_va', 'end_va_exclusive', 'fde_va', 'cie_va', 'lsda_va',
         'file_offset', 'length', 'sha256'],
        [(r['label'], hex(r['start']), hex(r['end']), hex(r['fde']), hex(r['cie']),
          hex_or_dash(r['lsda']), hex(r['offset']), r['end']-r['start'], r['sha256'])
         for r in frames]), encoding='utf-8')
    (out / 'windows.tsv').write_text(tsv(
        ['label', 'start_va', 'file_offset', 'owner_fde_start', 'raw_hex', 'sha256'],
        [(r['label'], hex(r['va']), hex(r['offset']), hex(r['owner']), r['raw'], r['sha256'])
         for r in e['windows']]), encoding='utf-8')
    (out / 'transfers.tsv').write_text(tsv(
        ['label', 'site_va', 'file_offset', 'owner_fde_start', 'kind', 'target_va_or_slot', 'raw_hex'],
        [(r['label'], hex(r['va']), hex(r['offset']), hex(r['owner']), r['kind'],
          hex(r['target']), r['raw']) for r in e['edges']]), encoding='utf-8')
    (out / 'locations.json').write_text(json_text(e['locations']), encoding='utf-8')
    (out / 'constants.json').write_text(json_text(dict(freeze=e['constants'], maps=e['map_info'],
                                                       context_mutations=e['mutations'])),
                                        encoding='utf-8')
    (out / 'relocations.json').write_text(json_text(e['relocations']), encoding='utf-8')
    (out / 'root.json').write_text(json_text(e['root_info']), encoding='utf-8')
    (out / 'upper.json').write_text(json_text(e['upper']), encoding='utf-8')
    (out / 'task.json').write_text(json_text(e['task']), encoding='utf-8')
    (out / 'collection.json').write_text(json_text(e['collection']), encoding='utf-8')
    (out / 'collection-cases.json').write_text(json_text(e['collection_models']), encoding='utf-8')
    (out / 'captures.tsv').write_text(tsv(
        ['index', 'instruction_va', 'store_va', 'state_offset', 'stack_offset', 'raw_hex'],
        [(r['index'], hex(r['site']), hex(r['store_site']), hex(r['state_offset']),
          hex(r['stack_offset']), r['raw']) for r in e['captures']]), encoding='utf-8')
    (out / 'synthetic-cases.tsv').write_text(tsv(
        ['kind', 'tag_u64', 'payload_u64', 'height_u64', 'mode_u64', 'interval_u64',
         'entry_decision', 'end_decision', 'root_visitor_choice', 'field_bytes_hex_or_unresolved'],
        [(r['kind'], hex(r['tag']), hex(r['target']), hex(r['height']), hex(r['mode']),
          hex(r['interval']), r['entry'], r['end'], r['root'], r['bytes'])
         for r in e['cases']]), encoding='utf-8')
    (out / 'change-cases.tsv').write_text(tsv(
        ['old_tag_u64', 'old_payload_u64', 'new_tag_u64', 'new_payload_u64', 'result_byte_hex'],
        [(hex(r['old_tag']), hex(r['old_value']), hex(r['new_tag']), hex(r['new_value']),
          f"{r['result']:02x}") for r in e['changes']]), encoding='utf-8')
    (out / 'mutation-cases.tsv').write_text(tsv(
        ['context_header_u64', 'count_u64', 'lookup_result_u64', 'selected_stores'],
        [(hex(r['header']), hex(r['count']), hex(r['lookup']), r['decision'])
         for r in e['mutation_models']]), encoding='utf-8')
    summary = dict(target_release='115', target_sha256=SHA115,
                   fdes=len(frames), windows=len(e['windows']), transfers=len(e['edges']),
                   locations=len(e['locations']), relocation_witnesses=len(e['relocations']),
                   root_captures=len(e['captures']), root_slots=len(e['root_info']['slot_offsets']),
                   synthetic_cases=len(e['cases']), change_cases=len(e['changes']),
                   collection_cases=sum(len(x) for x in e['collection_models'].values()),
                   mutation_cases=len(e['mutation_models']),
                   scope='Selected static observations only; no execution or equivalence claim.')
    (out / 'summary.json').write_text(json_text(summary), encoding='utf-8')
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--old-elf', type=Path, help='optionally authenticate and check the historical #94 anchor')
    args = p.parse_args()
    data = TARGET.read_bytes()
    evidence = build_evidence(data)
    if args.old_elf:
        print(json_text(old_crosscheck(data, args.old_elf.read_bytes())), end='')
    print(json_text(write_evidence(args.out, evidence)), end='')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as exc:
        print('abci_freeze_snapshot115: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
