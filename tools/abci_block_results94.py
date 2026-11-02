#!/usr/bin/env python3
"""Reproduce selected node #94 block-result byte evidence; never execute target code."""
import argparse
import bisect
from collections import Counter
import csv
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import unwind_index
from fde_extents import eh_frame_records, uleb

BINARY = ROOT / 'artifacts/node/94/hl-node'
EXPECTED_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Addresses were selected by inspecting the downstream lane, not by a byte scan.
# Ends are checks against the shared FDE reader, not inferred from the next index row.
# Hashes bind each complete selected unwind-described extent, not function coverage.
OWNED = (
    ('delayed_output', 0x47f60d0, 0x47f61ed, '1a0d6c0d1d13c8b405eeb4061533cd75f950008fee786475f1119ef0945795dc'),
    ('action_orchestrator', 0x446d810, 0x446d909, '47ed2d20610a97019ac403b7ebc1be4af763ec99c17008d96024d772c59a33a5'),
    ('descriptor_thunk', 0x47f9220, 0x47f922c, '60893a101cf78d55139d5e8653dfae63954ac7fe0e2f77fb1a87aeaaf5552a6c'),
    ('descriptor_reserve', 0x4a13850, 0x4a13a13, 'ad29097be9b7f1f11d5e44f5530863b29f788fceaf08bf76b1b460a5e14f6c8d'),
    ('descriptor_partition', 0x476a320, 0x476a5d3, '06b9a754a7ceddf380895e103caff12bfbed76ceaefc2ea15ea29aa1835e42eb'),
    ('serial_descriptors', 0x4552020, 0x455219e, '3481224adb68ceba8b87d4ec3e65aac98c2320844e0e716d931085070d2c2c96'),
    ('nested_descriptor_thunk', 0x47f9770, 0x47f977c, 'f49a9e3e62ca08a3d2c494ccf24526ee6b71fdfb03eeafc038d36ff0fa755826'),
    ('nested_descriptor_reserve', 0x4a12960, 0x4a12b23, '07dd62e50eb3a42fa07f7b670ef8e650b1a05029167937f5c5dda10f08d0cf80'),
    ('descriptor_unwind_drop', 0x4a0e3e0, 0x4a0e48c, '03d0ed583a0e3db0be2c565a7afe6917f9276412c9c7a658bfcc1f3066bbc408'),
    ('descriptor_item_drop', 0x47e2440, 0x47e2532, '2ecdcc6be020ebc362f68390305155dd9f7fcbe651146dc92716af87d935f111'),
    ('serial_item_drop', 0x4a0df60, 0x4a0e052, '042009c41744626ac174bb529e472ea3cc3acca7e53353b71fdfab1012170cd2'),
    ('status_drop_dispatch', 0x47e3940, 0x47e3e2f, 'a266c50f039a4c6b39122a7649498072dd4b75cf7f71eafa1d318548b710fe6e'),
    ('result_headers', 0x454da60, 0x454db7d, '9ce2e4d230c82447fc6b9bc4a2d23a8b6692aa307c5e3f20601c3ddc741292ac'),
    ('temporary_map_insert', 0x49367c0, 0x4936a31, 'bf96c1793398ca607aad049488eb7af815199994e4b517067b3157397d1c9018'),
    ('temporary_map_nonempty_insert', 0x420b7f0, 0x420c7b9, 'a91ea4d58d980896f265fe3ae9c6b8aca622be6028d176c7acff15f57dd63b33'),
    ('zip_tail_drop', 0x44c71f0, 0x44c7376, 'ffa7e550b6594545df3e653f3ba172f52ccf69e50a8f2e5aa178dc020392cafe'),
    ('materialize_map', 0x4870700, 0x48709ff, 'ac0a3876370c368ae2ac47e1bbbb11d22d8b49ee9e1276d42825502db9c141d6'),
    ('map_iterator', 0x4951230, 0x49515dd, '083ddcce87cd82a123fc1b2d3cfe49406d49ec6099074f2431a7a6c884e9fb8c'),
    ('end_rows_to_state_map', 0x47bd580, 0x47bd9b9, 'a4bfc60b9ad22813132cc68914e7a4671822f036ec2c70ee84bfcb8a401d37e3'),
    ('state_map_insert', 0x4929e10, 0x492a04f, '6f80046c133a8280810bc1c6366259231307eda730262f80c51a6c215cce81f8'),
    ('state_map_nonempty_insert', 0x425ac80, 0x425bc10, 'ff459422685f2f53d0ec891475f0cee7f80903be4eac91e9852d072e45b172f6'),
)

# Small windows in already-owned callers are context only; all others are
# selected readable byte slices within the newly studied FDEs.
WINDOWS = (
    ('parent_delay_range', 0x42e5e7e, 0x42e5ebf, 'ab8f2c41e75ca1dd793e94902cd83cdc60c907b4818a2b12d9d225f17c6c854d'),
    ('parent_input_count', 0x42e5f8d, 0x42e5fb7, 'e176be5ae1a5ef35b6defa7876dbb7e69272a5383d49b5b347834991b994a906'),
    ('parent_pointer_append', 0x42e5fc0, 0x42e5feb, '208036c986aa1a8ead8e1b139c4c009c17762da78bd1e3d6222a7e3386137849'),
    ('parent_metadata_append', 0x42e5feb, 0x42e606c, '863e163e76de4fe6329c64e4e80a7c991ed2bee45dba7037a82054087b5fa34e'),
    ('parent_gate_arguments', 0x42e6091, 0x42e60a8, 'e5cc2309a7e15388e40ccabd50c034f5fd8e1360e178710083495feaedbc1ef0'),
    ('parent_gate_cleanup', 0x42e60b9, 0x42e6113, '3a1ea34871be697b40a1e344c093ac9e874cc10effe0918a8601de9f6ffd9f42'),
    ('parent_status', 0x42e60ad, 0x42e60b9, '84ec54c787ea80d3d1b79a213c533025783e2f56f6bfdc1a144873520478a7c8'),
    ('parent_collect_zip', 0x42e6143, 0x42e61be, 'edfa2e5bc1ee6896a7dee1547bb76b7fcc3c33878d51b29ec29d0c524decc0d4'),
    ('parent_zip_shape', 0x42e61be, 0x42e6220, '7b2875b7507295d5946a8037301a3dbc83e3b18cd1b953253877811c30c01394'),
    ('parent_map_insert', 0x42e6230, 0x42e6292, 'a345ba16d344326a801f8f7bed0445b732e02f5c9e3a0c3214ae73b6bdc222b9'),
    ('parent_old_drop', 0x42e6292, 0x42e631d, 'e300a2536c800dc39547a84445e62aaee022c901d3735e2160ef5a2ad7599701'),
    ('parent_map_iter', 0x42e631d, 0x42e63c8, '8a239f1311c6474af98748f8a4fcafc7a4325855c1f4b0bef9b9ea17f99682bd'),
    ('parent_end_mode', 0x42e63c8, 0x42e6453, 'aef4dbadba272ac10b1455fe4bd226442be467d2ef0e1485c3bbc91f8222fcc8'),
    ('parent_end_map', 0x42e6639, 0x42e665a, '1c86c1e131cb6b43702c6dfbbfcba8ff54dae644bbd4c68d1440b703885c4ba2'),
    ('parent_return', 0x42e6dac, 0x42e6e22, '0664a0f5134b09d35e7a69c74fd5084af5c2ac250d6efebeadef327edf236f73'),
    ('worker_return_copy', 0x4678b6d, 0x4678b9c, 'abcd2de36b79991ba4bef2b6063bea9291c91e7bf2db09aa9d7ee976b1043067'),
    ('worker_first_drop', 0x4678b9c, 0x4678bfa, 'fc45112b06935eea80ece1db274adb022c81aaaf3f8dcab74021028f7db2f001'),
    ('worker_second_drop', 0x4678c07, 0x4678c28, 'c96e2bf4a86dbae187f2be3c032a7f35470960c194f024f34083b853ab2464bf'),
    ('delay_alloc', 0x47f60de, 0x47f6146, '647350fef3652695405c136cea992fa55fc812e4d1b0921ef909b08f9b4c616c'),
    ('descriptor_bounds', 0x4a13869, 0x4a1389c, '5ba8b8455c607d03c7a453ee7c136ad94b879d3f9d8e643507ee13eb3e4992e5'),
    ('descriptor_count', 0x4a1391a, 0x4a13957, '6f37ad026e0ffc0062682b4e591fbd49963634227b8da10fd0a769ac38423f62'),
    ('descriptor_failure', 0x4a13966, 0x4a139f8, '2d0e9552b953e93b09b221f13ad25fcb2f9134f591b7a7a6de1ea9f6f64e54ce'),
    ('temp_map_search', 0x49367e4, 0x493689b, '3c7f20e9b6a3644f8f39168e4bdd332b50254e2ea52020184a552e4cd7fbec29'),
    ('state_map_search', 0x4929e31, 0x4929ef1, '866370c360065c8ebac59f96dd2efdddc95958fbca08e59263d1f979077fe1e9'),
    ('temp_split_head', 0x420b7f0, 0x420b847, 'f4d2b3b76fc4d79ecf0e16abbd7612b469498e7ef014934714b9a1c620405b6c'),
    ('state_split_head', 0x425ac80, 0x425acd5, '429741281ecc50d91c37a2e976996073e137e7f2df37734b0e25b397b14502d7'),
    ('output_alloc', 0x4870714, 0x4870762, 'b5eeada23f6007587868291b5c3d9b57164276036dc4240cbf4f9d0422b7bede'),
    ('output_iter', 0x4870830, 0x48708ae, '1f5cb4d7683bef43c483d89b903c3e960c75c08612728d61ca0775f0b0e2bc22'),
    ('state_update', 0x47bd60e, 0x47bd6ec, '9f6dc4f4d484e598cac89abdf6aaf45107f5e2edcfa6fe6b7b451aa58f403f55'),
    ('serial_descriptor_loop', 0x4552038, 0x4552108, '43caa0d6d8361c9e5d42b39352fec5155dc3515180c764a19ae9f9fcf4c45682'),
    ('nested_reserve_bounds', 0x4a1297c, 0x4a129ac, 'e8e70af10859785fd2849d4cd3b66523e19601a87e271e1cecb2678952ccb5e7'),
    ('nested_result_count', 0x4a12a43, 0x4a12a61, '303b580ee89353608a9f11ece2429f657504d6f15b5609ab4a7f84eeb18b8c85'),
    ('descriptor_drop_normal', 0x4a0e3eb, 0x4a0e44b, '2e523f49f0d5a4aaa6415bfe09cdabb9eaa132c18e65cf71004c5fd8e112d2a9'),
    ('descriptor_drop_unwind', 0x4a0e44b, 0x4a0e486, 'adc69d5033a5d289ae350ec6f942e1963a2f80aeb4b600944515e3eac1a6ba10'),
    ('descriptor_item_drop', 0x47e244e, 0x47e24b6, '6f18d8d9ebd4d1d5e3a4b5c130b1a1c909068f9d3b154b76c6b734befa7397c2'),
    ('serial_item_drop', 0x4a0df6e, 0x4a0dfd6, '6751d5ac6966ea11070f72dc3915b325acf75348a96de626767be3dffa91b539'),
    ('status_dispatch_head', 0x47e3945, 0x47e3963, 'a6852b0ab616521e8126878081cfbb2a4cbaaebdddcac8ad54c69658c08a8097'),
    ('status_dispatch_second', 0x47e3981, 0x47e399f, '28d1282ac2122e378043525872bb16756962e3e33ec7a7f0e16b54144159d140'),
    ('status_dispatch_return', 0x47e3b10, 0x47e3b16, '208e1268728ac1c1ff348862cb1fe94ae30ac65e6363456e37a8e6bf7a5b0ac1'),
    ('status_one_region', 0x47e3963, 0x47e3981, '5a753598ece0ab443f88d35f6c13b5b27a238f7dd8ea4db4a9a52235ff5fbea4'),
    ('status_optional_and_indirect', 0x47e3a15, 0x47e3a3b, '1cf814fbca35dc01e5d38508ada718cf6e9646aadb665381d3b95243c5937d11'),
    ('status_two_regions', 0x47e3a3b, 0x47e3a73, '076c23c275c3bdb90115a2cafb1f16113e84febc8494ce3c3b06c762756d22bd'),
    ('status_nested_object', 0x47e3a73, 0x47e3aab, 'c728b817b417fe59692f3d21450c924843ed8a6233664aa2ce254b04b3cdcc32'),
    ('status_region_at_10', 0x47e3ad3, 0x47e3ae5, '22f3de5c645241abca3eaea2b8ea8d23c1d7d8de91b8340d8a801518b5e12154'),
)

# (label, instruction VA, expected condition, destination VA).
# This is a deliberately selected decision list, not an instruction sweep.
BRANCHES = (
    ('delayed_size_ok',0x47f60f3,'be',0x47f6102),
    ('delayed_empty',0x47f611a,'e',0x47f613e),
    ('delayed_alloc_null',0x47f6128,'e',0x47f61bb),
    ('reserve_needs_growth',0x4a13879,'a',0x4a13966),
    ('reserve_sub_underflow',0x4a13882,'b',0x4a13995),
    ('reserve_insufficient',0x4a1388b,'b',0x4a139a2),
    ('reserve_result_mismatch',0x4a13930,'ne',0x4a139bb),
    ('reserve_recheck_ok',0x4a1398f,'ae',0x4a13888),
    ('partition_split_threshold',0x476a353,'ae',0x476a3c3),
    ('partition_flag_zero',0x476a3c5,'e',0x476a3e7),
    ('partition_budget_zero',0x476a3ea,'e',0x476a355),
    ('partition_input_underflow',0x476a425,'b',0x476a571),
    ('partition_output_underflow',0x476a432,'b',0x476a58a),
    ('partition_tls_null',0x476a4ef,'e',0x476a5a3),
    ('partition_tls_different',0x476a4fc,'ne',0x476a5bb),
    ('serial_no_input',0x4552042,'e',0x4552108),
    ('serial_nested_sentinel',0x45520c7,'o',0x4552108),
    ('serial_output_capacity',0x45520d9,'ae',0x455212f),
    ('serial_next_input',0x4552102,'ne',0x4552070),
    ('nested_reserve_grow',0x4a1298c,'a',0x4a12a73),
    ('nested_reserve_sub_underflow',0x4a12995,'b',0x4a12aa2),
    ('nested_reserve_insufficient',0x4a1299e,'b',0x4a12aaf),
    ('nested_count_mismatch',0x4a12a58,'ne',0x4a12ac8),
    ('nested_recheck_ok',0x4a12a9c,'ae',0x4a1299b),
    ('descriptor_drop_exhausted',0x4a0e404,'e',0x4a0e417),
    ('descriptor_drop_no_allocation',0x4a0e41d,'e',0x4a0e43c),
    ('descriptor_unwind_drop_exhausted',0x4a0e453,'e',0x4a0e467),
    ('descriptor_items_empty',0x47e2459,'e',0x47e24a5),
    ('descriptor_item_tag',0x47e2498,'e',0x47e2480),
    ('descriptor_item_no_allocation',0x47e24ab,'e',0x47e24ca),
    ('descriptor_item_unwind_more',0x47e24df,'ne',0x47e2500),
    ('descriptor_unwind_item_tag',0x47e2520,'e',0x47e2510),
    ('serial_items_empty',0x4a0df79,'e',0x4a0dfc5),
    ('serial_item_tag',0x4a0dfb8,'e',0x4a0dfa0),
    ('serial_item_no_allocation',0x4a0dfcb,'e',0x4a0dfea),
    ('serial_item_unwind_more',0x4a0dfff,'ne',0x4a0e020),
    ('serial_unwind_item_tag',0x4a0e040,'e',0x4a0e030),
    ('status_primary_outside',0x47e3951,'a',0x47e3981),
    ('status_secondary_outside',0x47e3989,'a',0x47e3b10),
    ('status_nested32_outside',0x47e39a7,'a',0x47e3b9c),
    ('status_nested14_outside',0x47e39c5,'a',0x47e3cd9),
    ('status_nested7_outside',0x47e3ab3,'a',0x47e3b10),
    ('status_nested5a_outside',0x47e3bec,'a',0x47e3c69),
    ('status_nested5b_outside',0x47e3c30,'a',0x47e3b10),
    ('status_one_region_empty',0x47e396a,'e',0x47e3b10),
    ('status_signed_region_negative',0x47e3a1c,'s',0x47e3b10),
    ('status_signed_region_nonzero',0x47e3a22,'ne',0x47e3970),
    ('status_first_region_empty',0x47e3a42,'e',0x47e3a59),
    ('status_second_region_empty',0x47e3a60,'e',0x47e3b10),
    ('status_nested_tag_one',0x47e3a7e,'e',0x47e3b2d),
    ('status_nested_tag_nonzero',0x47e3a87,'ne',0x47e3b36),
    ('status_nested_region_empty',0x47e3a94,'e',0x47e3b36),
    ('status_region_at_10_empty',0x47e3ada,'e',0x47e3b10),
    ('headers_resize_unneeded',0x454dafa,'e',0x454db2b),
    ('headers_zero_old_size',0x454daff,'e',0x454db25),
    ('headers_resize_succeeded',0x454db13,'ne',0x454db2b),
    ('temp_map_empty',0x49367da,'e',0x493689b),
    ('temp_map_keys_exhausted',0x4936803,'e',0x4936830),
    ('temp_map_next_key',0x493681d,'e',0x4936800),
    ('temp_map_equal',0x4936826,'e',0x4936847),
    ('temp_map_leaf',0x4936837,'b',0x493697a),
    ('temp_map_alloc_null',0x49368b7,'e',0x49369d6),
    ('temp_map_first_node_full',0x493690e,'ae',0x49369e8),
    ('temp_insert_nonfull',0x420b819,'b',0x420b847),
    ('temp_tail_empty',0x44c720d,'e',0x44c72af),
    ('output_size_ok',0x4870729,'be',0x4870738),
    ('output_empty',0x487073e,'e',0x487075b),
    ('output_alloc_ok',0x487074f,'ne',0x4870762),
    ('output_count_exceeds_capacity',0x48707d1,'a',0x487096f),
    ('output_iterator_end',0x4870843,'e',0x48708ae),
    ('output_sentinel',0x4870869,'o',0x48708ae),
    ('iterator_empty',0x4951245,'e',0x4951379),
    ('iterator_bad_tag',0x4951255,'ne',0x49515ce),
    ('iterator_current_node',0x4951260,'ne',0x49512ff),
    ('iterator_node_exhausted',0x4951315,'ae',0x49513ea),
    ('iterator_cleanup_tag',0x495138f,'e',0x495158f),
    ('state_rows_empty',0x47bd594,'e',0x47bd97a),
    ('state_nested_empty',0x47bd627,'e',0x47bd660),
    ('state_nested_zero_capacity',0x47bd634,'e',0x47bd99b),
    ('state_insert_no_old',0x47bd6e6,'e',0x47bd600),
    ('state_old_nested_empty',0x47bd6f7,'e',0x47bd740),
    ('state_map_empty',0x4929e27,'e',0x4929ef1),
    ('state_map_keys_exhausted',0x4929e53,'e',0x4929e80),
    ('state_map_equal',0x4929e76,'e',0x4929e97),
    ('state_map_leaf',0x4929e87,'b',0x4929f99),
    ('state_map_alloc_null',0x4929f0e,'e',0x4929ff2),
    ('state_map_first_node_full',0x4929f3c,'ae',0x492a004),
    ('state_insert_nonfull',0x425aca7,'b',0x425acd5),
    ('state_insert_split_position',0x425acbe,'ae',0x425ad29),
    ('parent_status_tag',0x42e60b7,'e',0x42e6113),
    ('parent_no_rows',0x42e6203,'e',0x42e6310),
    ('parent_row_sentinel',0x42e6247,'e',0x42e6308),
    ('parent_no_old',0x42e6290,'e',0x42e6230),
    ('parent_state_update_mode',0x42e6409,'ne',0x42e6453),
    ('parent_counter_equal',0x42e642a,'e',0x42e6d6e),
)

# Each selected guard is a fixed byte range ending at the named branch.
GUARDS = (
    ('delayed_size_ok', 0x47f60f0, '4939c4'),
    ('delayed_empty', 0x47f6117, '4d85ff'),
    ('delayed_alloc_null', 0x47f6125, '4885c0'),
    ('reserve_needs_growth', 0x4a13873, '4c29f94839ce'),
    ('reserve_result_mismatch', 0x4a1392d, '4c39f0'),
    ('partition_split_threshold', 0x476a34d, '48d1ee4c39c6'),
    ('partition_flag_zero', 0x476a3c3, '84d2'),
    ('partition_budget_zero', 0x476a3e7, '4885c9'),
    ('partition_input_underflow', 0x476a422, '4929f6'),
    ('partition_output_underflow', 0x476a42f, '4829f0'),
    ('serial_no_input', 0x455203f, '4939ed'),
    ('serial_nested_sentinel', 0x45520c1, '4889c148f7d9'),
    ('serial_output_capacity', 0x45520d6, '4d39fc'),
    ('nested_reserve_grow', 0x4a12986, '4c29f94839ce'),
    ('nested_count_mismatch', 0x4a12a55, '4c39f0'),
    ('descriptor_drop_exhausted', 0x4a0e400, '4983fd01'),
    ('descriptor_item_tag', 0x47e2491, '6642813c3b8601'),
    ('serial_item_tag', 0x4a0dfb1, '6642813c3b8601'),
    ('status_primary_outside', 0x47e394b, '81f9c0000000'),
    ('status_secondary_outside', 0x47e3986, '83f827'),
    ('status_nested32_outside', 0x47e39a3, '4883f81f'),
    ('status_nested14_outside', 0x47e39c1, '4883f80d'),
    ('status_nested7_outside', 0x47e3aaf, '4883f806'),
    ('status_nested5a_outside', 0x47e3be8, '4883f904'),
    ('status_nested5b_outside', 0x47e3c2c, '4883f804'),
    ('status_one_region_empty', 0x47e3967, '4885f6'),
    ('status_signed_region_negative', 0x47e3a19, '4885f6'),
    ('status_first_region_empty', 0x47e3a3f, '4885f6'),
    ('status_second_region_empty', 0x47e3a5d, '4885f6'),
    ('status_nested_tag_one', 0x47e3a7a, '4883f801'),
    ('status_nested_tag_nonzero', 0x47e3a84, '4885c0'),
    ('status_nested_region_empty', 0x47e3a91, '4885f6'),
    ('status_region_at_10_empty', 0x47e3ad7, '4885f6'),
    ('temp_map_empty', 0x49367d4, '488b064885c0'),
    ('temp_map_next_key', 0x4936805, '483b54f810410f97c34180db004983c03848ffc74180fb01'),
    ('temp_map_equal', 0x493681f, '450fb6cb4585c9'),
    ('temp_map_leaf', 0x4936833, '4883e901'),
    ('temp_insert_nonfull', 0x420b815, '4883fb0b'),
    ('output_size_ok', 0x4870718, '486bf33848b849922449922449024839c3'),
    ('output_empty', 0x487073b, '4885f6'),
    ('output_sentinel', 0x4870863, '4889ce48f7de'),
    ('state_rows_empty', 0x47bd591, '4839f7'),
    ('state_nested_empty', 0x47bd621, '4b837c273800'),
    ('state_nested_zero_capacity', 0x47bd62d, '488b70284885f6'),
    ('state_insert_no_old', 0x47bd6dd, '4883bc240801000000'),
    ('state_map_equal', 0x4929e6f, '450fb6cb4585c9'),
    ('state_insert_nonfull', 0x425ac9e, '4883fb0b48894c2408'),
    ('parent_status_tag', 0x42e60ad, '6681bc24100100008601'),
    ('parent_no_rows', 0x42e6200, '4885c9'),
    ('parent_row_sentinel', 0x42e6240, '488b48284c39f1'),
    ('parent_no_old', 0x42e6285, '4c8ba424300100004d39f4'),
    ('parent_state_update_mode', 0x42e6401, '4183bfe83a000002'),
    ('parent_counter_equal', 0x42e6417, '498b87883b0000488b401048894424104939c5'),
)

# LEA, unsigned bound operand and raw table hashes for the status-drop
# dispatch. Each entry is a signed 32-bit offset relative to its table base.
TABLES = (
    ('primary',0x47e3953,'488d05',0x6fc4c0,0x47e394b,'81f9',4,0xc0,'d570d1f1324009b46bfbcc6a08a857abcc1722e0a6a68219523ec1b4789a6001'),
    ('secondary',0x47e398f,'488d0d',0x6fc7c4,0x47e3986,'83f8',1,0x27,'3cef284064fadaa52f19da637e2e88837faa4f162e2733b81d303441019cd7a2'),
    ('nested32',0x47e39ad,'488d0d',0x6fc864,0x47e39a3,'4883f8',1,0x1f,'9cc4bf10e8f8b72a3d3dfe431b794db23878c3c5ee285d85587f93c96e2c1440'),
    ('nested14',0x47e39cb,'488d0d',0x6fc90c,0x47e39c1,'4883f8',1,0x0d,'416ee2e53d0a47042b57ed927250079b59bb5962d724d71ae6e0c2ab6b84af50'),
    ('nested7',0x47e3ab5,'488d0d',0x6fc944,0x47e3aaf,'4883f8',1,0x06,'beab60854411e49497ff0861e72ed0edf0aa5252fa9c2bef2af779bb835a10b7'),
    ('nested5a',0x47e3bf2,'488d15',0x6fc8e4,0x47e3be8,'4883f9',1,0x04,'6846ceae24e4eb034a71c3857f1ab23842d4ac9ea5fef9b459d210e1a67d8377'),
    ('nested5b',0x47e3c36,'488d0d',0x6fc8f8,0x47e3c2c,'4883f8',1,0x04,'f0a1cbfc7eb0c3af38f91d274938c61ca02d8c19fb50743cd8082569afc0cb3c'),
)

# Direct rel32 transfers only. Targets that are prior work are boundaries.
TRANSFERS = (
    ('parent_delayed',0x42e5eba,'call',0x47f60d0),
    ('parent_action_collect',0x42e6163,'call',0x446d810),
    ('parent_gate_cleanup_boundary',0x42e610e,'call',0x4344430),
    ('orchestrator_descriptors',0x446d868,'call',0x47f9220),
    ('thunk_descriptors',0x47f9227,'jmp',0x4a13850),
    ('descriptors_partition',0x4a1391a,'call',0x476a320),
    ('descriptors_grow_boundary',0x4a1397d,'call',0x454f5d0),
    ('partition_serial',0x476a3a8,'call',0x4552020),
    ('serial_nested',0x45520aa,'call',0x47f9770),
    ('nested_thunk',0x47f9777,'jmp',0x4a12960),
    ('nested_scheduler_boundary',0x4a12a43,'call',0x4764ef0),
    ('nested_grow_boundary',0x4a12a8a,'call',0x454f5d0),
    ('orchestrator_unwind_drop',0x446d8f6,'call',0x4a0e3e0),
    ('descriptor_drop_item',0x4a0e40d,'call',0x47e2440),
    ('descriptor_unwind_item',0x4a0e45d,'call',0x47e2440),
    ('serial_unwind_drop',0x455215c,'call',0x4a0df60),
    ('descriptor_status_drop',0x47e249e,'call',0x47e3940),
    ('descriptor_unwind_status',0x47e2525,'call',0x47e3940),
    ('serial_status_drop',0x4a0dfbe,'call',0x47e3940),
    ('serial_unwind_status',0x4a0e045,'call',0x47e3940),
    ('status_nested_cleanup_boundary',0x47e3b31,'call',0x47e48a0),
    ('partition_tls_boundary',0x476a50e,'call',0x46980f0),
    ('partition_join_boundary',0x476a55a,'call',0x452b090),
    ('delayed_fill_boundary',0x47f6195,'call',0x4448ad0),
    ('orchestrator_result_headers',0x446d8bb,'call',0x454da60),
    ('result_header_boundary',0x454daa8,'call',0x444d5c0),
    ('parent_zip_boundary',0x42e61b9,'call',0x471e100),
    ('parent_temp_insert',0x42e6280,'call',0x49367c0),
    ('temp_nonempty_insert',0x49369ca,'call',0x420b7f0),
    ('parent_zip_tail_drop',0x42e6318,'call',0x44c71f0),
    ('parent_materialize',0x42e63c3,'call',0x4870700),
    ('materialize_iterator',0x4870836,'call',0x4951230),
    ('parent_end_boundary',0x42e63e0,'call',0x446f130),
    ('parent_state_update',0x42e6655,'call',0x47bd580),
    ('state_nested_boundary',0x47bd646,'call',0x4984140),
    ('state_row_insert',0x47bd6d8,'call',0x4929e10),
    ('state_nonempty_insert',0x4929fe6,'call',0x425ac80),
)

# Selected RIP-indirect calls and their slot VAs.  Shared runtime slots are
# external boundaries; these rows neither identify nor claim their functions.
INDIRECT = (
    ('delayed_size_failure',0x47f60fa,0x576dfb8),
    ('delayed_allocation',0x47f611f,0x576dfd8),
    ('reserve_sub_underflow',0x4a1399c,0x576e150),
    ('reserve_insufficient',0x4a139b5,0x576e108),
    ('reserve_count_mismatch',0x4a139f0,0x576e098),
    ('partition_input_underflow',0x476a584,0x576e098),
    ('partition_output_underflow',0x476a59d,0x576e108),
    ('serial_capacity_failure',0x455214c,0x576e098),
    ('nested_reserve_sub_underflow',0x4a12aa9,0x576e150),
    ('nested_reserve_insufficient',0x4a12ac2,0x576e108),
    ('nested_count_mismatch',0x4a12b00,0x576e098),
    ('descriptor_drop_unwind_release',0x4a0e478,0x576e010),
    ('descriptor_item_unwind_release',0x47e24f2,0x576e010),
    ('serial_item_unwind_release',0x4a0e012,0x576e010),
    ('headers_resize',0x454db07,0x576e030),
    ('headers_resize_failure',0x454db1d,0x576e020),
    ('output_size_failure',0x487072d,0x576dfb8),
    ('output_allocation',0x4870746,0x576dfd8),
    ('state_node_allocation',0x4929f05,0x576dfd8),
    ('state_node_alloc_failure',0x4929ffc,0x576e020),
    ('state_nested_invalid',0x47bd9a2,0x576e470),
    ('state_old_iter_invalid',0x47bd9af,0x576e470),
    ('parent_counter_failure',0x42e6448,0x5770688),
    ('status_first_region_release',0x47e3a50,0x576e010),
    ('status_nested_region_release',0x47e3aa0,0x576e010),
)

INDIRECT_TAILS = (
    ('status_one_region_tail',0x47e397b,0x576e010),
    ('descriptor_item_release_tail',0x47e24c4,0x576e010),
    ('serial_item_release_tail',0x4a0dfe4,0x576e010),
    ('descriptor_array_release_tail',0x4a0e436,0x576e010),
)

# Byte strings are bounded by the constant sizes loaded at their inspected
# reference sites; the references are not source-code identities.
LITERALS = (
    ('partition_output_bound',0x6f5ea2, b'assertion failed: index <= len',0x476a58a,0x476a598),
    ('reserve_capacity_bound',0x6f6099, b'assertion failed: vec.capacity() - start >= len',0x4a139a2,0x4a139b0),
    ('map_node_bound',0x20ca60, b'assertion failed: idx < CAPACITY',0x492a004,0x492a012),
)

# Selected LSDA addresses and hashes of the encoded header plus call-site
# table, as reached from the CIE/FDE reader. None means no LSDA in that FDE.
LSDAS = {
    'delayed_output': (0xb7ec68, '7ab5b35d69c44efa06bc10682a24ab2922a91ef1ec54d4cc870f295569c167fb'),
    'action_orchestrator': (0xb404f0, 'b011e78a6e6f6fe67aea3b53d050a121db7a6b050312c0e608e3136fea444f0d'),
    'descriptor_thunk': None,
    'descriptor_reserve': (0xb915bc, 'c9d9b8fc29581ae33ecc6fcc76ca7212d9568ad9a7071425a1a3a3bb24858432'),
    'descriptor_partition': None,
    'serial_descriptors': (0xb4ea80, '723d4a30469c75154e7e760e3376e04d521fb6311c7ecd850a9b7c8d50007ad0'),
    'nested_descriptor_thunk': None,
    'nested_descriptor_reserve': (0xb91598, 'ecc1fe0fd13ac91c2f6195c5004f0d0df60023628308b02c2c160fdf5f7bae9e'),
    'descriptor_unwind_drop': (0xb90f18, '0bf3717e1b1b0cca26d05afbb1651da6fb577fdbe1c55489fef8e2ad60f5286f'),
    'descriptor_item_drop': (0xb7d800, 'f5a85df142e482230d71027d1a3c0455c46d7302d5cb18de749c6574358059fc'),
    'serial_item_drop': (0xb90e98, 'f5a85df142e482230d71027d1a3c0455c46d7302d5cb18de749c6574358059fc'),
    'status_drop_dispatch': (0xb7d924, '4768aed44fe3b3c40a28e66c79259c0cf7a09ee4257676159073174ea68d50b9'),
    'result_headers': (0xb4e8e4, '9febf53becefb155bb090e1204221910b4ffaac7b909bd4f21694ad4e63d7f1a'),
    'temporary_map_insert': (0xb86ef4, '3b7dc7e8f668bdf940de083fb3aaada86ac29781edfca0b94ef3770e257cd0e1'),
    'temporary_map_nonempty_insert': (0xb22d58, 'bdf4c4fef529cbbe8910e607e88ddce69998f86c526ab12e6e7186ed69790643'),
    'zip_tail_drop': (0xb43998, '212437d683bb398366235398d322b050a6e462665dad5534341a40aa59b122d4'),
    'materialize_map': (0xb826cc, 'ce2debfdcde0c055fbd7ed89333aebf39fbd1e229f870f7665c623eef11a9926'),
    'map_iterator': (0xb87988, 'e9ef6f8952b20f969f166a3cf6e1fd50363a9408168b609c2122861f2e6f7bd0'),
    'end_rows_to_state_map': (0xb7b828, '1356706101977e2061405113dc941f26fdb9d0057f916bef386c62f4fc057350'),
    'state_map_insert': (0xb86820, 'e9b40cb3e05e741e631de11ba28d96e8aad1dc8137a466c9e223f7a7b14f0df4'),
    'state_map_nonempty_insert': (0xb24e6c, 'a3863a20b95cc7d597ac140daae770c16c937c9eb03de33641b2d45295f4d748'),
}

# Immediate operands at inspected instruction starts: prefix, width, expected.
# Values are read back from the ELF, and exact instruction prefixes are checked.
OPERANDS = (
    ('delayed_input_stride',0x42e5e88,'4869542420',4,0x148),
    ('parent_input_record_stride',0x42e5fdb,'4883c5',1,0x28),
    ('delayed_range_byte_limit',0x47f60e6,'48b8',8,0x749f49f49f49f498),
    ('delayed_allocation_factor',0x47f6109,'49bf',8,0xf3831f3831f38328),
    ('delayed_count_factor',0x47f612e,'48b9',8,0x8f9c18f9c18f9c19),
    ('action_status_tag',0x42e60ad,'6681bc2410010000',2,0x186),
    ('zip_sentinel',0x42e6209,'49be',8,0x8000000000000000),
    ('zip_record_stride',0x42e623c,'4983c7',1,0x40),
    ('temporary_key_value_stride',0x49367ec,'4d6bd1',1,0x38),
    ('state_key_value_stride',0x4929e39,'4d6bd1',1,0x38),
    ('result_value_stride',0x4870718,'486bf3',1,0x38),
    ('result_count_limit',0x487071c,'48b8',8,0x249249249249249),
    ('state_map_offset',0x42e6639,'4d8da7',4,0x3b10),
    ('temporary_node_capacity',0x420b815,'4883fb',1,0xb),
    ('state_node_capacity',0x425ac9e,'4883fb',1,0xb),
    ('serial_input_pointer_stride',0x45520df,'4983c5',1,0x8),
    ('serial_output_record_stride',0x45520fb,'4883c3',1,0x20),
    ('nested_result_record_stride',0x4a129a4,'4d6bef',1,0x70),
    ('descriptor_item_status_tag',0x47e2491,'6642813c3b',2,0x186),
    ('serial_item_status_tag',0x4a0dfb1,'6642813c3b',2,0x186),
    ('descriptor_item_stride',0x47e2487,'4983c7',1,0x70),
    ('descriptor_range_shift',0x446d88e,'48c1e2',1,5),
    ('result_header_count_shift',0x454dab3,'49c1ed',1,3),
    ('result_header_inverse_three',0x454dab7,'48b8',8,0xaaaaaaaaaaaaaaab),
    ('zip_output_range_shift',0x42e61d9,'49c1e5',1,6),
    ('state_input_range_shift',0x47bd5a6,'48c1e8',1,6),
)

CONDITIONS = ('o','no','b','ae','e','ne','be','a','s','ns','p','np','l','ge','le','g')


def verify_sha(data):
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
        raise ValueError('node #94 SHA-256 mismatch')


def file_offset(secs, va, size, executable=True):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid address or size')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address range is not uniquely file-backed')
    s = matches[0]
    return s['offset'] + va - s['address'], s['name']


def pinned_bytes(data, secs, start, end, expected_hash):
    off, name = file_offset(secs, start, end-start)
    raw = bytes(data[off:off+end-start])
    if len(raw) != end-start or hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError('byte window mismatch at ' + hex(start))
    return off, name, raw


def branch(data, secs, va, expected_condition, expected_target):
    off, name = file_offset(secs, va, 2)
    first = data[off]
    if 0x70 <= first <= 0x7f:
        size, cond = 2, first & 15
        file_offset(secs, va, size)
        delta = struct.unpack_from('<b', data, off+1)[0]
    elif first == 0x0f and 0x80 <= data[off+1] <= 0x8f:
        size, cond = 6, data[off+1] & 15
        file_offset(secs, va, size)
        delta = struct.unpack_from('<i', data, off+2)[0]
    else:
        raise ValueError('unsupported branch encoding at ' + hex(va))
    target = va + size + delta
    if CONDITIONS[cond] != expected_condition or target != expected_target:
        raise ValueError('conditional branch changed at ' + hex(va))
    file_offset(secs, target, 1)
    return off, name, size, CONDITIONS[cond], target, bytes(data[off:off+size])


def guard(data, secs, va, expected_hex, branch_va):
    expected = bytes.fromhex(expected_hex)
    if not expected or va + len(expected) != branch_va:
        raise ValueError('guard is not adjacent to its branch')
    off, sec = file_offset(secs, va, len(expected))
    raw = bytes(data[off:off+len(expected)])
    if raw != expected:
        raise ValueError('selected branch guard changed at ' + hex(va))
    return off, sec, raw


def transfer(data, secs, va, expected_kind, expected_target):
    off, name = file_offset(secs, va, 5)
    opcode = {'call': 0xe8, 'jmp': 0xe9}.get(expected_kind)
    if opcode is None or data[off] != opcode:
        raise ValueError('unsupported transfer at ' + hex(va))
    target = va + 5 + struct.unpack_from('<i', data, off+1)[0]
    if target != expected_target:
        raise ValueError('transfer destination changed at ' + hex(va))
    file_offset(secs, target, 1)
    return off, name, target, bytes(data[off:off+5])


def indirect(data, secs, va, expected_slot):
    off, name = file_offset(secs, va, 6)
    if bytes(data[off:off+2]) != b'\xff\x15':
        raise ValueError('unsupported indirect transfer at ' + hex(va))
    slot = va + 6 + struct.unpack_from('<i', data, off+2)[0]
    if slot != expected_slot:
        raise ValueError('indirect slot changed at ' + hex(va))
    file_offset(secs, slot, 8, executable=False)
    return off, name, slot, bytes(data[off:off+6])


def indirect_tail(data, secs, va, expected_slot):
    off, name = file_offset(secs, va, 6)
    if bytes(data[off:off+2]) != b'\xff\x25':
        raise ValueError('unsupported indirect tail transfer at ' + hex(va))
    slot = va + 6 + struct.unpack_from('<i', data, off+2)[0]
    if slot != expected_slot:
        raise ValueError('indirect tail slot changed at ' + hex(va))
    file_offset(secs, slot, 8, executable=False)
    return off, name, slot, bytes(data[off:off+6])


def operand(data, secs, va, prefix_hex, width, expected):
    prefix = bytes.fromhex(prefix_hex)
    if width not in (1,2,4,8):
        raise ValueError('unsupported immediate width')
    off, name = file_offset(secs, va, len(prefix)+width)
    raw = bytes(data[off:off+len(prefix)+width])
    if raw[:len(prefix)] != prefix:
        raise ValueError('operand instruction changed at ' + hex(va))
    value = int.from_bytes(raw[len(prefix):], 'little')
    if value != expected:
        raise ValueError('operand value changed at ' + hex(va))
    return off, name, value, raw


def literal(data, secs, va, expected, reference_va, length_va):
    ref_off, _ = file_offset(secs, reference_va, 7)
    reference = bytes(data[ref_off:ref_off+7])
    if reference[:3] != b'\x48\x8d\x3d' or reference_va + 7 + struct.unpack_from('<i', reference, 3)[0] != va:
        raise ValueError('literal reference changed at ' + hex(reference_va))
    _, _, size, size_raw = operand(data, secs, length_va, 'be', 4, len(expected))
    off, sec = file_offset(secs, va, len(expected), executable=False)
    raw = bytes(data[off:off+len(expected)])
    if raw != expected:
        raise ValueError('literal changed at ' + hex(va))
    return off, sec, raw, reference, size, size_raw


def jump_table(data, secs, spec):
    """Decode one fixed relative-offset table and its bound from ELF bytes."""
    name, lea_va, prefix_hex, expected_base, bound_va, bound_prefix, width, expected_bound, digest = spec
    lea_off, _ = file_offset(secs, lea_va, 7)
    lea = bytes(data[lea_off:lea_off+7])
    if lea[:3] != bytes.fromhex(prefix_hex):
        raise ValueError('jump-table reference opcode changed')
    base = lea_va + 7 + struct.unpack_from('<i', lea, 3)[0]
    if base != expected_base:
        raise ValueError('jump-table reference destination changed')
    _, _, bound, bound_raw = operand(data, secs, bound_va, bound_prefix, width, expected_bound)
    if name == 'primary':
        _, _, encoded_start, start_raw = operand(data, secs, 0x47e3948, '8d48', 1, 0xc6)
        first = -struct.unpack('<b', bytes([encoded_start]))[0]
    elif name == 'secondary':
        _, _, encoded_start, start_raw = operand(data, secs, 0x47e3981, '05', 4, 0xfffffeb5)
        first = -struct.unpack('<i', encoded_start.to_bytes(4, 'little'))[0]
    else:
        first, start_raw = 0, b''
    count = bound + 1
    off, sec = file_offset(secs, base, count*4, executable=False)
    raw = bytes(data[off:off+count*4])
    if len(raw) != count*4 or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('jump-table bytes changed')
    rows = []
    for index in range(count):
        displacement = struct.unpack_from('<i', raw, index*4)[0]
        target = base + displacement
        if not 0x47e3940 <= target < 0x47e3e2f:
            raise ValueError('jump-table destination outside selected FDE')
        file_offset(secs, target, 1)
        rows.append((name, index, first+index, base+index*4, off+index*4,
                     displacement, target, raw[index*4:index*4+4]))
    header = (name, lea_va, lea_off, lea, base, off, sec, bound_va, bound_raw,
              first, start_raw, count, digest)
    return header, rows


def selected_fdes(data, secs, table, all_records=False):
    _, fdes = eh_frame_records(data, secs)
    by_start = {}
    for entry in fdes:
        by_start.setdefault(entry['start'], []).append(entry)
    indexes = {entry['start']: entry for entry in table}
    result = []
    for label, start, expected_end, expected_hash in OWNED:
        matches = by_start.get(start, [])
        if len(matches) != 1 or start not in indexes:
            raise ValueError('missing or ambiguous selected FDE at ' + hex(start))
        item = matches[0]
        index = indexes[start]
        if item['end'] != expected_end or item['fde'] != index['fde']:
            raise ValueError('selected FDE/index mismatch at ' + hex(start))
        expected_lsda = LSDAS[label]
        if item['lsda'] != (expected_lsda[0] if expected_lsda else None):
            raise ValueError('selected FDE/LSDA mismatch at ' + hex(start))
        off, sec, raw = pinned_bytes(data, secs, start, item['end'], expected_hash)
        result.append((label, start, item['end'], item['fde'], index['index'], sec, off, expected_hash, raw))
    return (result, fdes) if all_records else result


def lsda_table(data, secs, fde, upper_va, expected_va, expected_hash):
    """Decode only the selected omitted-LPStart, uleb call-site format."""
    sections = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(sections) != 1:
        raise ValueError('missing or ambiguous exception table')
    section = sections[0]
    lo, hi = section['address'], section['address'] + section['size']
    if fde['lsda'] != expected_va or not lo <= expected_va < upper_va <= hi:
        raise ValueError('selected LSDA address or upper bound changed')
    off, sec = file_offset(secs, expected_va, 1, executable=False)
    limit = section['offset'] + upper_va - lo
    if off + 3 > limit or data[off] != 0xff or data[off+1] not in (0xff, 0x9b):
        raise ValueError('unsupported LSDA header')
    type_encoding = data[off+1]
    pos = off + 2
    type_base = None
    if type_encoding == 0x9b:
        type_offset, pos = uleb(data, pos, limit)
        type_base = pos + type_offset
        if type_base > limit:
            raise ValueError('LSDA type base outside selected upper bound')
    if pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, limit)
    table_start, table_end = pos, pos + size
    if table_end > limit or (type_base is not None and table_end > type_base):
        raise ValueError('LSDA call-site table outside bounds')
    rows = []
    previous_end = fde['start']
    while pos < table_end:
        record_start = pos
        fields = []
        for _ in range(4):
            number, pos = uleb(data, pos, table_end)
            fields.append(number)
        relative_start, length, landing, action = fields
        start, end = fde['start'] + relative_start, fde['start'] + relative_start + length
        pad = fde['start'] + landing if landing else None
        if (not fde['start'] <= start <= end <= fde['end'] or start < previous_end or
                (pad is not None and not fde['start'] <= pad < fde['end'])):
            raise ValueError('LSDA call-site range or landing outside selected FDE')
        previous_end = end
        rows.append((start, end, pad, action, record_start, bytes(data[record_start:pos])))
    raw = bytes(data[off:table_end])
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError('selected LSDA table changed')
    header = (expected_va, off, sec, upper_va, type_encoding,
              None if type_base is None else lo + type_base - section['offset'],
              table_start-off, size, expected_hash, raw)
    return header, rows


def selected_lsdas(data, secs, funcs, all_fdes):
    exceptions = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(exceptions) != 1:
        raise ValueError('missing or ambiguous exception table')
    section = exceptions[0]
    lo, hi = section['address'], section['address'] + section['size']
    pointers = sorted({f['lsda'] for f in all_fdes if f['lsda'] is not None and lo <= f['lsda'] < hi})
    by_start = {f['start']: f for f in all_fdes}
    headers, records = [], []
    for name, start, *_ in funcs:
        expected = LSDAS[name]
        if expected is None:
            continue
        va, digest = expected
        at = bisect.bisect_right(pointers, va)
        upper = pointers[at] if at < len(pointers) else hi
        fde = by_start[start]
        header, rows = lsda_table(data, secs, fde, upper, va, digest)
        headers.append((name, start, *header, len(rows)))
        records.extend((name, *row) for row in rows)
    return headers, records


def collect(data):
    # Check before even parsing sections, including for malformed or absent files.
    verify_sha(data)
    secs, table = unwind_index(data)
    funcs, all_fdes = selected_fdes(data, secs, table, all_records=True)
    lsda_headers, lsda_rows = selected_lsdas(data, secs, funcs, all_fdes)
    windows = []
    for label, start, end, expected_hash in WINDOWS:
        off, sec, raw = pinned_bytes(data, secs, start, end, expected_hash)
        windows.append((label, start, end, off, sec, expected_hash, raw))
    branches = []
    for label, va, cond, target in BRANCHES:
        off, sec, size, actual_cond, actual_target, raw = branch(data, secs, va, cond, target)
        branches.append((label, va, off, sec, actual_cond, va+size, actual_target, raw))
    by_label = {row[0]: row for row in branches}
    if len(by_label) != len(branches):
        raise ValueError('duplicate branch label')
    decisions = []
    for label, guard_va, raw_hex in GUARDS:
        if label not in by_label:
            raise ValueError('guard has no selected branch')
        _, site, _, _, condition, fallthrough, target, branch_raw = by_label[label]
        guard_off, guard_sec, guard_raw = guard(data, secs, guard_va, raw_hex, site)
        decisions.append((label, guard_va, guard_off, guard_sec, guard_raw, site,
                          condition, fallthrough, target, branch_raw))
    transfers = []
    for label, va, kind, target in TRANSFERS:
        off, sec, actual_target, raw = transfer(data, secs, va, kind, target)
        transfers.append((label, va, off, sec, kind, actual_target, raw))
    indirects = []
    for label, va, slot in INDIRECT:
        off, sec, actual_slot, raw = indirect(data, secs, va, slot)
        indirects.append((label, va, off, sec, actual_slot, raw))
    operands = []
    for label, va, prefix, width, expected in OPERANDS:
        off, sec, value, raw = operand(data, secs, va, prefix, width, expected)
        operands.append((label, va, off, sec, value, raw))
    literals = []
    for label, va, expected, reference_va, length_va in LITERALS:
        off, sec, raw, reference, size, size_raw = literal(data, secs, va, expected, reference_va, length_va)
        literals.append((label, va, off, sec, raw, reference_va, reference, length_va, size, size_raw))
    table_headers, table_rows = [], []
    for spec in TABLES:
        header, rows = jump_table(data, secs, spec)
        table_headers.append(header)
        table_rows.extend(rows)
    tails = []
    for label, va, slot in INDIRECT_TAILS:
        off, sec, actual_slot, raw = indirect_tail(data, secs, va, slot)
        tails.append((label, va, off, sec, actual_slot, raw))
    associations = []
    selected_calls = [(n, va, 5) for n, va, off, sec, kind, target, raw in transfers if kind == 'call']
    selected_calls += [(n, va, 6) for n, va, off, sec, slot, raw in indirects]
    for label, va, size in selected_calls:
        owners = [row for row in funcs if row[1] <= va and va + size <= row[2]]
        if not owners:  # Selected context in an earlier-owned FDE.
            continue
        if len(owners) != 1:
            raise ValueError('ambiguous selected call owner')
        owner = owners[0][0]
        matches = [row for row in lsda_rows if row[0] == owner and row[1] <= va and va+size <= row[2]]
        if len(matches) > 1:
            raise ValueError('overlapping LSDA call-site records')
        if LSDAS[owner] is None:
            status, pad, action = 'no_lsda', None, None
        elif matches:
            status, pad, action = 'covered', matches[0][3], matches[0][4]
        else:
            status, pad, action = 'no_covering_record', None, None
        associations.append((label, va, owner, status, pad, action))
    return funcs, windows, branches, transfers, indirects, operands, literals, lsda_headers, lsda_rows, associations, decisions, table_headers, table_rows, tails


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(out):
    with BINARY.open('rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            funcs, wins, branches, calls, indirects, operands, literals, lsda_headers, lsda_rows, associations, decisions, table_headers, table_rows, tails = collect(data)
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out/'functions.tsv', ('label','start_va','end_va_exclusive','fde_va','unwind_index','section','file_offset','sha256','body_hex'),
              ((n,hex(a),hex(b),hex(f),i,s,hex(o),h,raw.hex()) for n,a,b,f,i,s,o,h,raw in funcs))
    write_tsv(out/'windows.tsv', ('label','start_va','end_va_exclusive','file_offset','section','sha256','bytes_hex'),
              ((n,hex(a),hex(b),hex(o),s,h,raw.hex()) for n,a,b,o,s,h,raw in wins))
    write_tsv(out/'branches.tsv', ('label','site_va','file_offset','section','condition','fallthrough_va','taken_va','bytes_hex'),
              ((n,hex(a),hex(o),s,c,hex(f),hex(t),raw.hex()) for n,a,o,s,c,f,t,raw in branches))
    write_tsv(out/'decisions.tsv', ('label','guard_va','guard_file_offset','section','guard_bytes','branch_va','condition','fallthrough_va','taken_va','branch_bytes'),
              ((n,hex(va),hex(off),sec,raw.hex(),hex(site),cond,hex(fall),hex(target),braw.hex())
               for n,va,off,sec,raw,site,cond,fall,target,braw in decisions))
    write_tsv(out/'transfers.tsv', ('label','site_va','file_offset','section','kind','target_va','bytes_hex'),
              ((n,hex(a),hex(o),s,k,hex(t),raw.hex()) for n,a,o,s,k,t,raw in calls))
    write_tsv(out/'indirect.tsv', ('label','site_va','file_offset','section','slot_va','bytes_hex'),
              ((n,hex(a),hex(o),s,hex(t),raw.hex()) for n,a,o,s,t,raw in indirects))
    write_tsv(out/'indirect-tails.tsv', ('label','site_va','file_offset','section','slot_va','bytes_hex'),
              ((n,hex(a),hex(o),s,hex(t),raw.hex()) for n,a,o,s,t,raw in tails))
    write_tsv(out/'operands.tsv', ('label','site_va','file_offset','section','immediate_unsigned','bytes_hex'),
              ((n,hex(a),hex(o),s,hex(v),raw.hex()) for n,a,o,s,v,raw in operands))
    write_tsv(out/'literals.tsv', ('label','data_va','file_offset','section','size','bytes_hex','ascii','reference_va','reference_bytes','length_va','length_bytes'),
              ((n,hex(a),hex(o),s,size,raw.hex(),raw.decode('ascii'),hex(rva),ref.hex(),hex(lva),lraw.hex())
               for n,a,o,s,raw,rva,ref,lva,size,lraw in literals))
    write_tsv(out/'lsda-headers.tsv', ('function','function_va','lsda_va','file_offset','section','next_lsda_upper_va','type_encoding','type_base_va','header_size','call_site_bytes','sha256','header_and_table_hex','row_count'),
              ((n,hex(start),hex(va),hex(off),sec,hex(upper),hex(encoding),'-' if base is None else hex(base),hsize,size,sha,raw.hex(),count)
               for n,start,va,off,sec,upper,encoding,base,hsize,size,sha,raw,count in lsda_headers))
    write_tsv(out/'lsda-rows.tsv', ('function','start_va','end_va_exclusive','landing_va','action_index','file_offset','bytes_hex'),
              ((n,hex(a),hex(b),'-' if pad is None else hex(pad),action,hex(off),raw.hex())
               for n,a,b,pad,action,off,raw in lsda_rows))
    write_tsv(out/'lsda-calls.tsv', ('call_label','site_va','function','status','landing_va','action_index'),
              ((n,hex(va),owner,status,'-' if pad is None else hex(pad),'-' if action is None else action)
               for n,va,owner,status,pad,action in associations))
    write_tsv(out/'dispatch-tables.tsv', ('table','lea_va','lea_file_offset','lea_bytes','table_va','table_file_offset','section','bound_va','bound_bytes','first_selector','selector_adjust_bytes','entry_count','table_sha256'),
              ((n,hex(lva),hex(lo),lea.hex(),hex(base),hex(off),sec,hex(bva),braw.hex(),hex(first),sraw.hex(),count,sha)
               for n,lva,lo,lea,base,off,sec,bva,braw,first,sraw,count,sha in table_headers))
    write_tsv(out/'dispatch-entries.tsv', ('table','index','selector','entry_va','file_offset','signed_displacement','target_va','entry_bytes'),
              ((n,index,hex(selector),hex(va),hex(off),delta,hex(target),raw.hex())
               for n,index,selector,va,off,delta,target,raw in table_rows))
    counts = Counter((row[0], row[6]) for row in table_rows)
    write_tsv(out/'dispatch-targets.tsv', ('table','target_va','entries'),
              ((name,hex(target),counts[(name,target)])
               for name, *_ in TABLES for target in sorted(t for n,t in counts if n == name)))
    summary = {'target':'node-94', 'sha256':EXPECTED_SHA,
               'owned_selected_fdes':len(funcs), 'selected_windows':len(wins),
               'selected_conditional_branches':len(branches), 'selected_direct_transfers':len(calls),
               'selected_adjacent_guards':len(decisions),
               'selected_indirect_call_sites':len(indirects),
               'selected_indirect_tail_sites':len(tails),
               'selected_immediate_operands':len(operands),
               'selected_literals':len(literals),
               'selected_lsda_tables':len(lsda_headers), 'selected_lsda_call_site_rows':len(lsda_rows),
               'selected_call_lsda_associations':len(associations),
               'selected_jump_tables':len(table_headers), 'selected_jump_table_entries':len(table_rows),
               'coordinate_system':'ELF link-time VA and file offset; end exclusive',
               'completeness':'selected sites only; FDE extents are not a function census',
               'boundary':'prior parent and worker windows are context, not newly owned functions'}
    (out/'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True)+'\n', encoding='utf-8')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    generate(args.out)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('abci_block_results94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
