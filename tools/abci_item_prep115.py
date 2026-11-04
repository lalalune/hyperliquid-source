#!/usr/bin/env python3
"""Reproduce selected node 115 ABCI item-preparation evidence from ELF bytes.

This is a static, digest-bound extractor, not a disassembler or an execution
harness. The selected transfer sites are instruction-aligned manual pins.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Each hash covers the complete unwind-described extent, without masks. FDEs
# bound unwind ranges, not necessarily source functions or all executable code.
FUNCTIONS = (
    ('outer_collect', 0x5b3a2d0, 0x5b3a77a, 'f95cf78fa4c50de81cfac5d4d438eafafa1bcf1476a409f6f46b966d62dd111f'),
    ('location_mapper', 0x5618990, 0x5618a86, '136eee420a911aa529cbeac57db650201637801a27343362e51200d8791b22f6'),
    ('nested_append', 0x564b740, 0x564b8fe, 'eb7f756f6e975b421c82600a5bee1a778c9c1e2790ab3c7f39f439a61a231d34'),
    ('nested_drive', 0x5b5c2d0, 0x5b5c37b, 'bf3c8049efd2bfe986d8c2d86f5acef150fd2bbca897b1e8fa9112a9a8068ffe'),
    ('nested_dispatch', 0x57c3a60, 0x57c3b2b, '3e8b03dc5e3c26146e86edb5066fd80296e0945a9205ce4be9e8383cf4b2156b'),
    ('zip_worker', 0x5b35f80, 0x5b36978, '0ac06f6df9958f3c62846e3363cfeffe5a7345f7caf862ee6248b978d494347f'),
    ('row_precheck', 0x5921480, 0x5921e12, '4d6028e22abe5c2270b1a6b5631c431df8b35d988a2965ed12c15d2282dc9626'),
    ('common_precheck', 0x4d909b0, 0x4d90b93, '05ab86ebda42720c9b3f6c6d0f1a4bc7a4560de85c708a2725100f303e144317'),
    ('special_precheck', 0x4d915c0, 0x4d91c97, '89daf40d2283f4ab5910fb03713c4201ff94937ced4d80c0343dfe95e76d8fa4'),
    ('value_dispatch', 0x4d90d40, 0x4d90ed7, '734032ac6d3026d5585a2fe2d88f35077cd9988cf9385011d5cb9b78ed503b9a'),
    ('key_search', 0x4554610, 0x45547d7, 'bf9dcfe3295b64c02d95443d188a2b91fba0e65a7657c2d481311c346b226af4'),
    ('key_member', 0x4716b00, 0x4716bd5, 'cb3b710fa97021fd268d57608398ce84de44efd8222c1fa7f2d23efe7d3ed262'),
    ('key_scan', 0x55ffa50, 0x55ffc85, '289c7335a208468b1b0e32d5162856e3e12fd691226d87f565c7725d2263e5ea'),
    ('bucket_merge', 0x5b6ee00, 0x5b6f7e1, '99f7ac0ebc8e8c691a257b4d3516294d6d8f6f0d994361f6ccf6344286007e95'),
)

# (name, instruction VA, exact bytes, immediate offset, width, signed)
FIELDS = (
    ('parent_stride', 0x5b35fec, '4969f368010000', 3, 4, False),
    ('action_stride', 0x5b35ff6, '486bfa70', 3, 1, False),
    ('row_stride', 0x5b363eb, '4981c490000000', 3, 4, False),
    ('outer_stride', 0x5b3a46b, '4983c720', 3, 1, False),
    ('high_bit_sentinel', 0x5b3a3b0, '49bd0000000000000080', 2, 8, False),
    ('row_data_bias', 0x5b360f9, '4d8d6022', 3, 1, False),
    ('row_parent_displacement', 0x5b3638b, '49895c24de', 4, 1, True),
    ('row_index_displacement', 0x5b36390, '49894424ee', 4, 1, True),
    ('row_tag_displacement', 0x5b36395, '6645897c24fe', 5, 1, True),
    ('stop_tag', 0x5b3614e, '4181ffa3010000', 3, 4, False),
    ('prepare_tag', 0x5b361be, '3da2010000', 1, 4, False),
    ('special_tag', 0x59214a1, '817e10ba000000', 3, 4, False),
    ('common_return_comparison', 0x59215a4, '3da2010000', 1, 4, False),
    ('special_return_comparison', 0x5921532, '3da2010000', 1, 4, False),
    ('output_tag', 0x5921947, '66c703a201', 3, 2, False),
    ('output_key_first', 0x592191b, '0f2804240f114303', 7, 1, False),
    ('output_key_last', 0x5921914, '8b442410894313', 6, 1, False),
    ('consumer_key_first', 0x5865f28, '420f10446d23', 5, 1, False),
    ('consumer_key_last', 0x5865f1c, '428b446d33', 4, 1, False),
    ('bucket_tag', 0x548ca8e, '817d1086000000', 3, 4, False),
    ('merge_limit', 0x5b6f0b2, '48b8e3388ee3388ee300', 2, 8, False),
    ('merge_copy_width', 0x5b6f4ea, 'ba90000000', 1, 4, False),
    ('switch_base', 0x4d90d44, '4981e886000000', 3, 4, False),
    ('switch_default', 0x4d90d4b, 'b814000000', 1, 4, False),
    ('value_threshold', 0x4d90deb, '48817e1811270000', 4, 4, False),
    ('nested_special', 0x4d915f0, '41813eba000000', 3, 4, False),
    ('special_reject_nested', 0x4d915f9, '66c7032101', 3, 2, False),
    ('special_reject_key', 0x4d91636, '66c7032b01', 3, 2, False),
    ('special_reject_lookup', 0x4d917db, '66c7032301', 3, 2, False),
    ('precheck_reject_lookup', 0x5921822, '66c7032401', 3, 2, False),
    ('precheck_reject_scan', 0x5921860, '66c7038100', 3, 2, False),
    ('precheck_reject_variant', 0x592190d, '66c7031500', 3, 2, False),
    ('precheck_reject_missing', 0x5921d27, '66c7030700', 3, 2, False),
    ('precheck_reject_pair', 0x5921c30, '66c703eb00', 3, 2, False),
    ('precheck_reject_predicate', 0x5921d8f, '66c703ea00', 3, 2, False),
    ('consumer_tag', 0x5865f0c, '6681bc2470010000a201', 8, 2, False),
    ('returned_stop_tag', 0x5b36234, '4181ffa3010000', 3, 4, False),
    ('bucket_a_length_stack', 0x548caad, '4c8b7c2418', 4, 1, False),
    ('bucket_c_length_stack', 0x548caf7, '4c8b7c2448', 4, 1, False),
    ('bucket_b_length_stack', 0x548cb63, '4c8b7c2430', 4, 1, False),
    ('bucket_d_length_stack', 0x548cba8, '4c8b7c2460', 4, 1, False),
    ('merge_initial_mode', 0x548cc6e, '48c784249800000001000000', 8, 4, False),
    ('merge_ordered_mode', 0x5b6f43f, '4183fd01', 3, 1, False),
    ('merge_a_input_offset', 0x5b6f44e, '410f104608', 4, 1, False),
    ('merge_b_input_offset', 0x5b6f532, '410f104628', 4, 1, False),
    ('merge_c_input_offset', 0x5b6f5c2, '498d4648', 3, 1, False),
    ('merge_d_input_offset', 0x5b6ee1a, '4c8b4668', 3, 1, False),
    ('bucket_a_pointer_stack', 0x548cc0b, '488b4c2410', 4, 1, False),
    ('bucket_b_pointer_stack', 0x548cc25, '488b7c2428', 4, 1, False),
    ('bucket_c_pointer_stack', 0x548cc3f, '4c8b542440', 4, 1, False),
    ('bucket_d_pointer_stack', 0x548cc59, '4c8b742458', 4, 1, False),
    ('bucket_a_pack_stack', 0x548cc7a, '48898c24a0000000', 4, 4, False),
    ('bucket_b_pack_stack', 0x548cc9a, '4889bc24c0000000', 4, 4, False),
    ('bucket_c_pack_stack', 0x548ccba, '4c899424e0000000', 4, 4, False),
    ('bucket_d_pack_stack', 0x548ccda, '4c89b42400010000', 4, 4, False),
    ('bucket_pack_argument_stack', 0x548ccfa, '488db42498000000', 4, 4, False),
    ('engine_state_cell', 0x5a06727, '498d8750040000', 3, 4, False),
    ('engine_save_stack', 0x5a0672e, '4889442418', 4, 1, False),
    ('engine_reload_stack', 0x5a06ac1, '4c8b742418', 4, 1, False),
    ('collect_cell_store', 0x54864f5, '4c89742458', 4, 1, False),
    ('collect_descriptor_base', 0x54864ff, '4c8d7c2440', 4, 1, False),
    ('wrapper_cell_address', 0x5b5bacb, '488d4618', 3, 1, False),
    ('wrapper_address_store', 0x5b5badf, '4889442448', 4, 1, False),
    ('wrapper_address_load', 0x5b5bb55, '488d442448', 4, 1, False),
    ('outer_frame', 0x5b3a2da, '4881ec68010000', 3, 4, False),
    ('outer_stack_argument', 0x5b3a2ea, '4c8bb424a8010000', 4, 4, False),
    ('outer_cell_save', 0x5b3a34b, '4889442428', 4, 1, False),
    ('outer_mapper_argument', 0x5b3a3f7, '488d742428', 4, 1, False),
    ('mapper_descriptor_base', 0x56189d4, '0f29442430', 4, 1, False),
    ('mapper_cell_store', 0x56189e3, '4889442458', 4, 1, False),
    ('append_cell_chunk_source', 0x564b796, '0f105320', 3, 1, False),
    ('append_cell_chunk_stack', 0x564b79a, '0f29542460', 4, 1, False),
    ('append_cell_address_stack', 0x564b7bf, '488d7c2468', 4, 1, False),
    ('append_cell_save_stack', 0x564b7d8, '48897c2420', 4, 1, False),
    ('append_argument_base', 0x564b803, '488d542410', 4, 1, False),
    ('dispatcher_argument_offset', 0x57c3aab, '4983c710', 3, 1, False),
    ('worker_frame', 0x5b35f8a, '4881ec18030000', 3, 4, False),
    ('worker_stack_argument', 0x5b35f9a, '4c8ba42450030000', 4, 4, False),
    ('common_input_key_tail', 0x4d909c6, '8b4210', 2, 1, False),
    ('common_output_key_first', 0x4d90a86, '0f114302', 3, 1, False),
    ('common_output_key_last', 0x4d90a7e, '894312', 2, 1, False),
    ('common_selector_threshold', 0x4d909e7, '80f902', 2, 1, False),
    ('loader_result_comparison', 0x3c1353b, '4883f801', 3, 1, False),
    ('output_key_second_first', 0x5921927, '0f114317', 3, 1, False),
    ('output_key_second_last', 0x592192f, '894327', 2, 1, False),
    ('output_key_third_first', 0x592193b, 'f30f7f432b', 4, 1, False),
    ('output_key_third_last', 0x5921944, '89433b', 2, 1, False),
    ('output_flag_offset', 0x5921932, 'c6430200', 2, 1, False),
    ('output_flag_value', 0x5921932, 'c6430200', 3, 1, False),
    ('map_representation_offset', 0x59215db, '493b8424884b0000', 4, 4, False),
    ('map_count_offset', 0x59217e0, '483b90a04b0000', 3, 4, False),
    ('map_search_count_offset', 0x455461b, '488b4718', 3, 1, False),
    ('empty_search_tag', 0x45546ab, 'b801000000', 1, 4, False),
    ('scan_representation_offset', 0x55ffa5c, '488b8798030000', 3, 4, False),
    ('scan_count_offset', 0x55ffa96, '488bb7b0030000', 3, 4, False),
    ('mode_offset', 0x592186a, '4180bc240a17000003', 4, 4, False),
    ('mode_skip_value', 0x592186a, '4180bc240a17000003', 8, 1, False),
    ('parent_option_offset', 0x59218dc, '4180bd5001000000', 3, 4, False),
    ('engine_mode_offset', 0x5a0671a, '80b90a17000003', 2, 4, False),
    ('engine_mode_value', 0x5a0671a, '80b90a17000003', 6, 1, False),
    ('context_first_counter_load', 0x548543d, '498b86b0160000', 3, 4, False),
    ('context_first_counter_store', 0x5485452, '498986b0160000', 3, 4, False),
    ('context_second_counter_load', 0x54854bd, '498b86b8160000', 3, 4, False),
    ('context_second_counter_store', 0x54854cf, '498986b8160000', 3, 4, False),
    ('context_admission_count', 0x5485221, '488b98e8140000', 3, 4, False),
    ('context_admission_singleton', 0x5485231, '4883fb01', 3, 1, False),
    ('context_admission_pointer', 0x5485240, '488b80e0140000', 3, 4, False),
    ('context_admission_key_first', 0x5485247, 'f30f6f4048', 4, 1, False),
    ('context_admission_key_tail', 0x5485255, '660f6e5058', 4, 1, False),
    ('context_handler_input_tag', 0x54851bc, '3da2010000', 1, 4, False),
    ('context_handler_result_tag', 0x54854ab, '3da2010000', 1, 4, False),
)

# Register moves and dereferences which connect the offset joins. These fixed
# patterns are not a general x86 decoder.
PATTERNS = (
    ('collector_save_state_cell', 0x54864af, '4989f6'),
    ('reserve_read_descriptor', 0x564baf4, '0f1003'),
    ('reserve_copy_tail', 0x564bafb, '0f294c2410'),
    ('reserve_copy_head', 0x564bb00, '0f290424'),
    ('reserve_forward_descriptor', 0x564bb09, '4889e6'),
    ('wrapper_push_address', 0x5b5bb6b, '50'),
    ('outer_prologue', 0x5b3a2d0, '55415741564155415453'),
    ('outer_load_wrapper_pointer', 0x5b3a326, '498b06'),
    ('mapper_double_dereference', 0x561899f, '488b06488b00'),
    ('mapper_copy_input', 0x56189d0, '410f1006'),
    ('drive_forwards_descriptor', 0x5b5c30a, '4889d6'),
    ('dispatcher_stack_argument', 0x57c3ae7, '4c893c24'),
    ('worker_prologue', 0x5b35f80, '55415741564155415453'),
    ('worker_load_cell_holder', 0x5b35fd9, '4d8b1424'),
    ('worker_load_state_pointer', 0x5b361cc, '498b02488b10'),
    ('worker_precheck_arguments', 0x5b361d2, '4889f9'),
    ('worker_parent_argument', 0x5b361dd, '4889de'),
    ('precheck_saves_state_pointer', 0x5921494, '4989d4'),
    ('common_input_key', 0x4d909cd, '0f1002'),
    ('common_selector_index', 0x4d909e1, '488d51ff'),
    ('common_selector_conditional', 0x4d909ea, '480f43f2'),
    ('common_result_key_to_output', 0x59215af, '660f6f442460'),
    ('precheck_key_saved', 0x5921834, '8b842470010000'),
    ('precheck_key_first_to_stack', 0x5921848, '660f7f0424'),
    ('empty_scan_returns_zero', 0x55ffc75, '31c0eb02'),
    ('context_first_counter_saturation', 0x5485444, '48ffc048c7c3ffffffff480f44c3'),
    ('context_second_counter_saturation', 0x54854c4, '48ffc0480f44c3'),
    ('context_handler_dereference_cell', 0x5485219, '488b06'),
)

# (role, start VA, exclusive end VA). Contexts belong to previous proposals.
WINDOWS = (
    ('context_loader', 0x3c13520, 0x3c13556),
    ('context_engine_cell', 0x5a0671a, 0x5a06733),
    ('context_engine_collector', 0x5a06ac1, 0x5a06af9),
    ('context_collector_descriptor', 0x54864ac, 0x548650c),
    ('context_reserve_descriptor', 0x564baf4, 0x564bb14),
    ('context_outer_cell_capture', 0x5b5bac0, 0x5b5bb2e),
    ('context_outer_entry', 0x5b5bb2e, 0x5b5bb77),
    ('context_return_to_block', 0x548650c, 0x54865a8),
    ('context_guard_row', 0x5868080, 0x58680dd),
    ('context_classify_setup', 0x548c960, 0x548c9c3),
    ('context_classify_a', 0x548ca07, 0x548cacd),
    ('context_classify_c', 0x548cad0, 0x548cb36),
    ('context_classify_b_d', 0x548cb40, 0x548cbe7),
    ('context_merge_call', 0x548cc06, 0x548cd0a),
    ('context_consume_setup', 0x58681f2, 0x5868264),
    ('context_item_result', 0x5b324b0, 0x5b32561),
    ('context_item_fields', 0x5865e5b, 0x5865f40),
    ('context_handler_handoff', 0x5866008, 0x5866047),
    ('context_handler_admission', 0x54851b9, 0x548527f),
    ('context_handler_counters', 0x548542b, 0x54854d6),
    ('outer_first_and_empty', 0x5b3a319, 0x5b3a3c4),
    ('outer_map_and_write', 0x5b3a3d0, 0x5b3a482),
    ('outer_return', 0x5b3a5ef, 0x5b3a659),
    ('outer_capacity_error', 0x5b3a65a, 0x5b3a6ab),
    ('location_map_body', 0x5618990, 0x5618a86),
    ('append_guards', 0x564b740, 0x564b783),
    ('append_copy', 0x564b783, 0x564b835),
    ('append_failure', 0x564b835, 0x564b8c6),
    ('inner_driver', 0x5b5c2d0, 0x5b5c34d),
    ('inner_dispatch', 0x57c3a60, 0x57c3b10),
    ('zip_input_lengths', 0x5b35fba, 0x5b360b9),
    ('zip_tags_and_call', 0x5b36120, 0x5b361e5),
    ('zip_success_copy', 0x5b36315, 0x5b36406),
    ('zip_branch_exit', 0x5b366e5, 0x5b3671d),
    ('zip_return', 0x5b36770, 0x5b3679b),
    ('zip_failures', 0x5b3679b, 0x5b36819),
    ('check_dispatch', 0x592149d, 0x59215af),
    ('check_key_gates', 0x59217bf, 0x5921888),
    ('check_simple_success', 0x59218dc, 0x5921961),
    ('check_variant_gate', 0x5921961, 0x5921a25),
    ('check_missing_or_pair', 0x5921b27, 0x5921c3a),
    ('check_singleton', 0x5921cda, 0x5921d31),
    ('check_other_returns', 0x5921d82, 0x5921df4),
    ('common_dispatch', 0x4d909b0, 0x4d90a9e),
    ('special_guards', 0x4d915c0, 0x4d9168c),
    ('special_lookup', 0x4d9178b, 0x4d91871),
    ('value_dispatch_entry', 0x4d90d40, 0x4d90db5),
    ('value_threshold', 0x4d90de7, 0x4d90e2f),
    ('key_search_body', 0x4554610, 0x45547d7),
    ('key_member_body', 0x4716b00, 0x4716bd5),
    ('key_scan_body', 0x55ffa50, 0x55ffc85),
    ('merge_count_and_allocation', 0x5b6f0a7, 0x5b6f110),
    ('merge_first_group', 0x5b6f43f, 0x5b6f523),
    ('merge_second_group', 0x5b6f523, 0x5b6f5b7),
    ('merge_third_group', 0x5b6f5b7, 0x5b6f647),
    ('merge_fourth_group', 0x5b6f647, 0x5b6f6ca),
    ('merge_result', 0x5b6f6ca, 0x5b6f6f6),
    ('merge_grow', 0x5b6f703, 0x5b6f733),
)

# Selected sites, targets and linked-image VAs. Prior sites are context only.
EDGES = (
    ('loader_location_context', 0x3c1352f, 0x64767a8),
    ('engine_collector_context', 0x5a06af4, 0x54864a0),
    ('outer_call_context', 0x5b5bb6e, 0x5b3a2d0),
    ('parent_reserve_context', 0x5486507, 0x564bab0),
    ('reserve_driver_context', 0x564bb0f, 0x5b5bac0),
    ('collector_continuation_context', 0x54865a3, 0x59618e0),
    ('context_handler_wrong_tag_context', 0x54851c1, 0x548527f),
    ('context_singleton_admission_context', 0x548527a, 0x548542b),
    ('context_handler_other_result_context', 0x54854b0, 0x5485654),
    ('classify_call_context', 0x58681ff, 0x548c8e0),
    ('merge_call_context', 0x548cd05, 0x5b6ee00),
    ('item_projection_context', 0x586825f, 0x5b324b0),
    ('item_loop_context', 0x5b3255c, 0x5865d80),
    ('handler_context', 0x5866042, 0x54851a0),
    ('outer_split', 0x5b3a31f, 0x5b3a376),
    ('outer_empty', 0x5b3a353, 0x5b3a3a8),
    ('outer_sentinel', 0x5b3a368, 0x5b3a3b0),
    ('outer_map', 0x5b3a401, 0x5618990),
    ('outer_result_sentinel', 0x5b3a40b, 0x5b3a5ef),
    ('outer_capacity', 0x5b3a430, 0x5b3a65a),
    ('outer_loop', 0x5b3a475, 0x5b3a3d0),
    ('outer_parallel', 0x5b3a590, 0x59ef1d0),
    ('outer_join', 0x5b3a5e8, 0x5adf8c0),
    ('outer_cleanup', 0x5b3a620, 0x5b0c670),
    ('outer_capacity_failure', 0x5b3a66d, 0x64df6b8),
    ('mapping_length_mismatch', 0x56189be, 0x5618a3b),
    ('mapping_location_reference', 0x5618a3b, 0x64aa260),
    ('mapping_append', 0x5618a14, 0x564b740),
    ('mapping_failure', 0x5618a50, 0x64dfa18),
    ('append_grow', 0x564b76b, 0x564b835),
    ('append_underflow', 0x564b774, 0x564b85e),
    ('append_bound', 0x564b77d, 0x564b86d),
    ('append_driver', 0x564b808, 0x5b5c2d0),
    ('append_count_mismatch', 0x564b81d, 0x564b888),
    ('append_grow_call', 0x564b849, 0x5963a10),
    ('append_underflow_call', 0x564b865, 0x64df848),
    ('append_bound_call', 0x564b880, 0x64df730),
    ('append_mismatch_call', 0x564b8be, 0x64df6b8),
    ('drive_bounds', 0x5b5c301, 0x5b5c332),
    ('drive_dispatch', 0x5b5c310, 0x57c3a60),
    ('drive_bounds_call', 0x5b5c345, 0x64df730),
    ('dispatch_worker', 0x57c3afe, 0x5b35f80),
    ('zip_split', 0x5b35fc0, 0x5b36406),
    ('zip_index_overflow', 0x5b36035, 0x5b367fb),
    ('zip_empty', 0x5b360b3, 0x5b36424),
    ('zip_parent_end', 0x5b3612b, 0x5b366e5),
    ('zip_action_end', 0x5b3613b, 0x5b366ed),
    ('zip_input_stop', 0x5b36155, 0x5b3644a),
    ('zip_tag_dispatch', 0x5b361c3, 0x5b36280),
    ('zip_prepare', 0x5b361e0, 0x5921480),
    ('zip_return_tag', 0x5b3626a, 0x5b36315),
    ('zip_capacity', 0x5b36385, 0x5b3679b),
    ('zip_loop', 0x5b363fb, 0x5b36120),
    ('zip_direct_fallback', 0x5b3643f, 0x5b35fc6),
    ('zip_cleanup_skip', 0x5b36764, 0x5b36750),
    ('zip_cleanup_call', 0x5b36769, 0x5b1b250),
    ('zip_capacity_call', 0x5b367d8, 0x64df6b8),
    ('zip_bounds_call', 0x5b367f3, 0x64df730),
    ('zip_overflow_call', 0x5b36802, 0x64df520),
    ('precheck_special_test', 0x59214a8, 0x592155b),
    ('precheck_special_call', 0x5921503, 0x4d915c0),
    ('precheck_special_result', 0x5921537, 0x59216f8),
    ('precheck_common_call', 0x592157f, 0x4d909b0),
    ('precheck_common_result', 0x59215a9, 0x5921759),
    ('precheck_representation', 0x59215eb, 0x59217bf),
    ('precheck_tree_null', 0x59215fc, 0x592182c),
    ('precheck_key_search', 0x59217cf, 0x4554610),
    ('precheck_search_miss', 0x59217d6, 0x592182c),
    ('precheck_search_bounds', 0x59217e7, 0x592182c),
    ('precheck_member', 0x5921818, 0x4716b00),
    ('precheck_member_found', 0x5921820, 0x5921834),
    ('precheck_scan', 0x5921857, 0x55ffa50),
    ('precheck_scan_result', 0x592185e, 0x592186a),
    ('precheck_mode', 0x5921873, 0x59218dc),
    ('precheck_value_dispatch', 0x5921883, 0x4d90d40),
    ('precheck_value_result', 0x5921892, 0x59218c6),
    ('precheck_optional', 0x59218e4, 0x5921914),
    ('precheck_optional_result', 0x592190b, 0x5921961),
    ('precheck_optional_reject_return', 0x5921912, 0x592194c),
    ('special_nested_test', 0x4d915f7, 0x4d91600),
    ('special_key_test', 0x4d91634, 0x4d91650),
    ('special_type_bits', 0x4d91686, 0x4d915f9),
    ('special_key_search', 0x4d91797, 0x4554610),
    ('special_key_miss', 0x4d917a8, 0x4d917db),
    ('special_index_bound', 0x4d917b1, 0x4d917db),
    ('special_common_call', 0x4d9186c, 0x4d909b0),
    ('special_common_result', 0x4d91896, 0x4d91949),
    ('common_dispatch_call', 0x4d909d8, 0x64e7860),
    ('common_predicate', 0x4d90a0a, 0x64e4e38),
    ('common_predicate_result', 0x4d90a12, 0x4d90a7a),
    ('common_secondary', 0x4d90a47, 0x55feb90),
    ('common_secondary_result', 0x4d90a67, 0x4d90a9e),
    ('value_bound_a', 0x4d90df3, 0x4d90e7d),
    ('value_bound_b', 0x4d90e15, 0x4d90e7d),
    ('value_bound_c', 0x4d90e3b, 0x4d90e7d),
    ('value_bound_d', 0x4d90e7b, 0x4d90ec7),
    ('search_compare_first', 0x4554652, 0x64dfb50),
    ('search_empty', 0x4554625, 0x4554693),
    ('search_empty_return', 0x45546b3, 0x45547c5),
    ('search_compare_middle', 0x45546ee, 0x64dfb50),
    ('search_compare_last', 0x4554718, 0x64dfb50),
    ('member_empty', 0x4716b12, 0x4716bb4),
    ('member_singleton', 0x4716b1c, 0x4716b55),
    ('member_singleton_miss', 0x4716b51, 0x4716bb6),
    ('member_hash', 0x4716b6c, 0x4717440),
    ('member_probe', 0x4716b90, 0x3ee6fb0),
    ('member_index_bound', 0x4716ba1, 0x4716bc2),
    ('scan_representation', 0x55ffa69, 0x55ffa96),
    ('scan_empty_count', 0x55ffaa0, 0x55ffacd),
    ('scan_representation_loop', 0x55ffb37, 0x55ffb85),
    ('scan_match', 0x55ffb7f, 0x55ffc79),
    ('scan_first_end', 0x55ffb88, 0x55ffba0),
    ('scan_null', 0x55ffb8d, 0x55ffc75),
    ('scan_empty_return', 0x55ffbc0, 0x55ffc75),
    ('classify_stop_context', 0x548ca13, 0x548cbef),
    ('classify_first_context', 0x548ca95, 0x548cad0),
    ('classify_predicate_a_context', 0x548cad7, 0x64e4f58),
    ('classify_predicate_a_result_context', 0x548cadf, 0x548cb40),
    ('classify_predicate_b_context', 0x548cb43, 0x64e4f60),
    ('classify_predicate_b_result_context', 0x548cb5b, 0x548cba2),
    ('merge_limit_branch', 0x5b6f0bf, 0x5b6f0cb),
    ('merge_limit_failure', 0x5b6f0c3, 0x64df498),
    ('merge_alloc_failure', 0x5b6f0e9, 0x5b6f733),
    ('merge_first_mode', 0x5b6f448, 0x5b6f5b7),
    ('merge_first_empty', 0x5b6f48b, 0x5b6f523),
    ('merge_first_loop', 0x5b6f502, 0x5b6f4e0),
    ('merge_second_empty', 0x5b6f52c, 0x5b6f5b7),
    ('merge_second_loop', 0x5b6f592, 0x5b6f570),
    ('merge_third_empty', 0x5b6f5bc, 0x5b6f647),
    ('merge_third_loop', 0x5b6f622, 0x5b6f600),
    ('merge_fourth_empty', 0x5b6f64d, 0x5b6f6ca),
    ('merge_fourth_loop', 0x5b6f6b2, 0x5b6f690),
    ('merge_need_grow', 0x5b6f42c, 0x5b6f703),
    ('merge_grow_call', 0x5b6f715, 0x5963a10),
)

# Selected existing slots are recorded as boundary context, not owned functions.
SLOTS = {
    0x64df508: (6, 0, 'memcpy'),
    0x64df568: (6, 0, 'memmove'),
    0x64dfb50: (6, 0, 'memcmp'),
    0x64e4f58: (8, 0x36c5b00, ''),
    0x64e4f60: (8, 0x36c5680, ''),
    0x64e7860: (8, 0x36c2030, ''),
    0x64e4e38: (8, 0x36c8430, ''),
}


def verify_digest(data, expected=SHA256):
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise ValueError('target SHA-256 mismatch')
    return got


def file_offset(data, sec_rows, va, size, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid file-backed range')
    found = []
    for sec in sec_rows:
        if sec['type'] == 8 or not sec['size'] or (executable and not sec['flags'] & 4):
            continue
        if sec['address'] <= va and va + size <= sec['address'] + sec['size']:
            off = sec['offset'] + va - sec['address']
            if off + size > len(data):
                raise ValueError('section mapping exceeds file')
            found.append(off)
    if len(found) != 1:
        raise ValueError('range has no unique file-backed section')
    return found[0]


def get_bytes(data, secs, va, size, executable=False):
    off = file_offset(data, secs, va, size, executable)
    return bytes(data[off:off + size])


def section_named(secs, name):
    found = [s for s in secs if s['name'] == name and s['type'] != 8]
    if len(found) != 1:
        raise ValueError('required section is absent or ambiguous: ' + name)
    return found[0]


def check_body(raw, expected_hash):
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError('selected FDE body changed')


def read_field(raw, expected, offset, width, signed=False):
    if raw != bytes.fromhex(expected) or width < 1 or offset < 0 or offset + width > len(raw):
        raise ValueError('selected operand instruction changed')
    return int.from_bytes(raw[offset:offset + width], 'little', signed=signed)


def check_pattern(raw, expected):
    if raw != bytes.fromhex(expected):
        raise ValueError('selected register/data-flow pattern changed')


def decode_transfer(raw, site):
    if len(raw) < 2:
        raise ValueError('truncated selected transfer')
    if raw[0] in (0xe8, 0xe9):
        length = 5
        kind = 'call' if raw[0] == 0xe8 else 'jump'
    elif raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f:
        length = 2
        kind = 'jump' if raw[0] == 0xeb else 'branch'
    elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        length = 6
        kind = 'branch'
    elif raw[:2] in (b'\xff\x15', b'\xff\x25'):
        length = 6
        kind = 'indirect_call_slot' if raw[1] == 0x15 else 'indirect_jump_slot'
    elif raw[:3] in (b'\x48\x8d\x15', b'\x4c\x8d\x0d'):
        length = 7
        kind = 'rip_reference'
    else:
        raise ValueError('unsupported selected transfer opcode')
    if len(raw) < length:
        raise ValueError('truncated selected transfer')
    displacement = int.from_bytes(raw[length - (1 if length == 2 else 4):length], 'little', signed=True)
    return kind, raw[:length], site + length + displacement


def ensure_target(decoded, expected):
    if decoded != expected:
        raise ValueError('selected transfer target changed')


def read_relocations(data, secs, wanted):
    rel = section_named(secs, '.rela.dyn')
    if rel['size'] % 24:
        raise ValueError('partial relocation entry')
    found = {slot: [] for slot in wanted}
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in found:
            found[slot].append((off, info & 0xffffffff, info >> 32, addend))
    if any(len(rows) != 1 for rows in found.values()):
        raise ValueError('missing or duplicate selected relocation')
    return {slot: rows[0] for slot, rows in found.items()}


def dynamic_symbol(data, secs, index):
    sym = section_named(secs, '.dynsym')
    strings = section_named(secs, '.dynstr')
    if index < 1 or (index + 1) * 24 > sym['size']:
        raise ValueError('invalid dynamic symbol index')
    nameoff = struct.unpack_from('<I', data, sym['offset'] + 24 * index)[0]
    if nameoff >= strings['size']:
        raise ValueError('dynamic symbol string outside table')
    start = strings['offset'] + nameoff
    end = data.find(b'\0', start, strings['offset'] + strings['size'])
    if end < 0:
        raise ValueError('unterminated dynamic symbol')
    return bytes(data[start:end]).decode('ascii')


def selected_fdes(data, secs):
    # Both readers are shared repository parsers; the header is reconciled with
    # the actual .eh_frame record rather than treated as an extent by itself.
    _, header = unwind_index(data)
    _, frames = eh_frame_records(data, secs)
    header_by_start = {}
    for row in header:
        header_by_start.setdefault(row['start'], []).append(row)
    frame_by_start = {}
    for row in frames:
        frame_by_start.setdefault(row['start'], []).append(row)
    out = []
    for role, start, end, digest in FUNCTIONS:
        h, f = header_by_start.get(start, []), frame_by_start.get(start, [])
        if len(h) != 1 or len(f) != 1 or h[0]['fde'] != f[0]['fde'] or f[0]['end'] != end:
            raise ValueError('selected FDE/header extent mismatch')
        for other in frames:
            if other['fde'] != f[0]['fde'] and other['start'] < end and start < other['end']:
                raise ValueError('selected FDE overlaps another FDE')
        raw = get_bytes(data, secs, start, end - start, executable=True)
        check_body(raw, digest)
        out.append(dict(role=role, start=start, end=end, fde=f[0]['fde'], cie=f[0]['cie'],
                        lsda=f[0]['lsda'], index=h[0]['index'], digest=digest, raw=raw))
    return out


def lsda_rows(data, secs, fde):
    if fde['lsda'] is None:
        return []
    sec = section_named(secs, '.gcc_except_table')
    va = fde['lsda']
    if not sec['address'] <= va < sec['address'] + sec['size']:
        raise ValueError('LSDA outside exception section')
    pos = file_offset(data, secs, va, 1)
    limit = sec['offset'] + sec['size']
    if pos + 2 > limit or data[pos] != 0xff or data[pos + 1] not in (0x9b, 0xff):
        raise ValueError('unsupported LSDA header')
    typ = data[pos + 1]
    pos += 2
    if typ == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
    else:
        type_base = limit
    if type_base > limit or pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    length, pos = uleb(data, pos + 1, limit)
    end = pos + length
    if end > limit or end > type_base:
        raise ValueError('truncated LSDA call-site table')
    result = []
    while pos < end:
        entry = pos
        start, pos = uleb(data, pos, end)
        length, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        if start + length > fde['end'] - fde['start']:
            raise ValueError('LSDA range exceeds FDE')
        if landing and landing >= fde['end'] - fde['start']:
            raise ValueError('LSDA landing exceeds FDE')
        result.append(dict(role=fde['role'], lsda=va, file_offset=entry,
                           start=fde['start'] + start, end=fde['start'] + start + length,
                           landing=None if not landing else fde['start'] + landing,
                           action=action, raw=bytes(data[entry:pos]).hex()))
    if pos != end:
        raise ValueError('misaligned LSDA table')
    return result


def make_joins(v):
    # Byte offsets come from independently pinned instructions above. These
    # equalities describe a selected route, conditional on normal helper calls.
    parent = v['row_data_bias'] + v['row_parent_displacement']
    index = v['row_data_bias'] + v['row_index_displacement']
    tag = v['row_data_bias'] + v['row_tag_displacement']
    first = tag + v['output_key_first']
    last = tag + v['output_key_last']
    if (v['high_bit_sentinel'] != 1 << 63 or v['stop_tag'] != v['prepare_tag'] + 1 or
        v['bucket_tag'] != v['switch_base'] or v['prepare_tag'] != v['output_tag'] or
        v['prepare_tag'] != v['consumer_tag'] or
        v['prepare_tag'] != v['context_handler_input_tag'] or
        v['prepare_tag'] != v['context_handler_result_tag'] or
        v['stop_tag'] != v['returned_stop_tag'] or
        v['prepare_tag'] != v['common_return_comparison'] or
        v['prepare_tag'] != v['special_return_comparison'] or
        v['special_tag'] != v['nested_special'] or v['special_tag'] == v['bucket_tag'] or
        v['row_stride'] != v['merge_copy_width'] or
        first != v['consumer_key_first'] or last != v['consumer_key_last'] or
        last - first != 16 or v['merge_limit'] != ((1 << 63) - 1) // v['row_stride']):
        raise ValueError('selected offsets, tags, or allocation bound do not join')
    if (v['merge_initial_mode'] != v['merge_ordered_mode'] or
        [v['merge_a_input_offset'], v['merge_b_input_offset'],
         v['merge_c_input_offset'], v['merge_d_input_offset']] != [8, 40, 72, 104] or
        [v['bucket_a_length_stack'], v['bucket_b_length_stack'],
         v['bucket_c_length_stack'], v['bucket_d_length_stack']] != [24, 48, 72, 96]):
        raise ValueError('selected classification and merge layout changed')
    for bucket in 'abcd':
        if (v[f'bucket_{bucket}_length_stack'] != v[f'bucket_{bucket}_pointer_stack'] + 8 or
            v[f'bucket_{bucket}_pack_stack'] - v['bucket_pack_argument_stack'] !=
                v[f'merge_{bucket}_input_offset']):
            raise ValueError('bucket pointer does not reach its selected merge input')
    if (v['engine_save_stack'] != v['engine_reload_stack'] or
        v['collect_cell_store'] - v['collect_descriptor_base'] != v['wrapper_cell_address'] or
        v['wrapper_address_store'] != v['wrapper_address_load'] or
        v['outer_stack_argument'] != v['outer_frame'] + 6 * 8 + 8 + 8 or
        v['outer_cell_save'] != v['outer_mapper_argument'] or
        v['mapper_cell_store'] - v['mapper_descriptor_base'] != 40 or
        v['append_cell_chunk_stack'] + (v['mapper_cell_store'] - v['mapper_descriptor_base']
                                        - v['append_cell_chunk_source']) != v['append_cell_address_stack'] or
        v['append_cell_save_stack'] - v['append_argument_base'] != v['dispatcher_argument_offset'] or
        v['worker_stack_argument'] != v['worker_frame'] + 6 * 8 + 8):
        raise ValueError('state-cell pointer handoff does not join')
    if (v['common_input_key_tail'] != 16 or
        v['common_output_key_last'] - v['common_output_key_first'] != 16 or
        v['output_key_second_last'] - v['output_key_second_first'] != 16 or
        v['output_key_third_last'] - v['output_key_third_first'] != 16 or
        v['output_key_second_first'] - v['output_key_first'] != 20 or
        v['output_key_third_first'] - v['output_key_second_first'] != 20 or
        v['output_flag_offset'] != 2 or v['output_flag_value'] != 0 or
        v['map_representation_offset'] + v['map_search_count_offset'] != v['map_count_offset'] or
        v['mode_offset'] != v['engine_mode_offset'] or v['mode_skip_value'] != v['engine_mode_value']):
        raise ValueError('precheck key copies or map offsets do not join')
    if (v['context_first_counter_load'] != v['context_first_counter_store'] or
        v['context_second_counter_load'] != v['context_second_counter_store'] or
        v['context_second_counter_load'] - v['context_first_counter_load'] != 8 or
        v['context_admission_count'] - v['context_admission_pointer'] != 8 or
        v['context_admission_key_tail'] - v['context_admission_key_first'] != 16 or
        v['context_admission_singleton'] != 1):
        raise ValueError('context counter load and store offsets do not join')
    if (parent, index, tag) != (0, 16, 32):
        raise ValueError('selected row layout changed')
    return {
        'source_parent_stride': v['parent_stride'],
        'engine_state_cell_offset': v['engine_state_cell'],
        'loader_result_comparison': v['loader_result_comparison'],
        'collector_cell_descriptor_offset': v['wrapper_cell_address'],
        'mapper_cell_descriptor_offset': v['mapper_cell_store'] - v['mapper_descriptor_base'],
        'dispatcher_cell_descriptor_offset': v['dispatcher_argument_offset'],
        'source_action_stride': v['action_stride'],
        'outer_row_stride': v['outer_stride'],
        'prepared_row_stride': v['row_stride'],
        'prepared_parent_offset': parent,
        'prepared_index_offset': index,
        'prepared_tag_offset': tag,
        'precheck_key_first_offset': v['output_key_first'],
        'precheck_key_last_word_offset': v['output_key_last'],
        'prepared_key_first_offset': first,
        'prepared_key_last_word_offset': last,
        'simple_precheck_key_offsets': [v['output_key_first'], v['output_key_second_first'],
                                        v['output_key_third_first']],
        'simple_precheck_flag_offset': v['output_flag_offset'],
        'simple_precheck_flag_value': v['output_flag_value'],
        'map_representation_offset': v['map_representation_offset'],
        'map_count_offset': v['map_count_offset'],
        'scan_representation_offset': v['scan_representation_offset'],
        'scan_count_offset': v['scan_count_offset'],
        'mode_offset': v['mode_offset'],
        'mode_skip_value': v['mode_skip_value'],
        'parent_option_offset': v['parent_option_offset'],
        'context_first_saturating_counter_offset': v['context_first_counter_load'],
        'context_second_saturating_counter_offset': v['context_second_counter_load'],
        'context_admission_pointer_offset': v['context_admission_pointer'],
        'context_admission_count_offset': v['context_admission_count'],
        'context_admission_key_offsets': [v['context_admission_key_first'], v['context_admission_key_tail']],
        'common_selector_threshold': v['common_selector_threshold'],
        'consumer_key_first_offset': v['consumer_key_first'],
        'consumer_key_last_word_offset': v['consumer_key_last'],
        'prepared_tag': v['prepare_tag'],
        'stop_tag': v['stop_tag'],
        'high_bit_sentinel': v['high_bit_sentinel'],
        'special_parent_tag': v['special_tag'],
        'first_bucket_parent_tag': v['bucket_tag'],
        'merge_mode': v['merge_initial_mode'],
        'bucket_input_offsets_in_merge_order': [v['merge_a_input_offset'], v['merge_b_input_offset'],
                                                v['merge_c_input_offset'], v['merge_d_input_offset']],
        'bucket_lengths_in_merge_order': [v['bucket_a_length_stack'], v['bucket_b_length_stack'],
                                          v['bucket_c_length_stack'], v['bucket_d_length_stack']],
        'merge_allocation_max_count': v['merge_limit'],
        'conditions': 'Selected normal returns, valid spans, unchanged indirect bindings, '
                      'preserved object identity and no conflicting alias writes.',
    }


def model_bucket(parent_tag, first_predicate, second_predicate, special_tag):
    """Model the selected classifier with predicate returns supplied by the caller."""
    if parent_tag == special_tag:
        return 0
    if first_predicate:
        return 2
    if second_predicate:
        return 1
    return 3


def model_order(rows, special_tag):
    """Group (identity, parent tag, predicate 1, predicate 2) records stably."""
    buckets = [[], [], [], []]
    for row in rows:
        buckets[model_bucket(row[1], row[2], row[3], special_tag)].append(row[0])
    return [item for bucket in buckets for item in bucket]


def model_equal20(left, right):
    """Model the selected 16-byte plus four-byte equality test, not a node call."""
    if len(left) != 20 or len(right) != 20:
        raise ValueError('expected two 20-byte values')
    mask16 = sum((a == b) << i for i, (a, b) in enumerate(zip(left[:16], right[:16])))
    mask4 = 0xfff0 | sum((a == b) << i for i, (a, b) in enumerate(zip(left[16:], right[16:])))
    return mask16 & mask4 == 0xffff


def model_common_index(category):
    """Model the pinned unsigned-byte selector, without claiming its input domain."""
    if type(category) is not int or not 0 <= category <= 255:
        raise ValueError('expected an unsigned byte')
    return 0 if category < 2 else category - 1


def model_three_key_writes(key, joins):
    """Model only the stores on the documented success branch."""
    if len(key) != 20:
        raise ValueError('expected a 20-byte key')
    writes = {0: joins['prepared_tag'].to_bytes(2, 'little'),
              joins['simple_precheck_flag_offset']: bytes([joins['simple_precheck_flag_value']])}
    for offset in joins['simple_precheck_key_offsets']:
        writes[offset] = bytes(key)
    return writes


def model_simple_case(key, joins, *, parent_tag, action_tag, category, map_marker, map_count,
                      scan_marker, scan_count, mode, parent_option):
    """Model only the explicitly documented empty-map/empty-scan success case."""
    if (parent_tag != joins['first_bucket_parent_tag'] or action_tag != joins['prepared_tag'] or
        category != joins['common_selector_threshold'] or
        map_marker == joins['high_bit_sentinel'] or map_count != 0 or
        scan_marker == joins['high_bit_sentinel'] or scan_count != 0 or
        mode != joins['mode_skip_value'] or parent_option != 0):
        return None
    return model_three_key_writes(key, joins)


def model_allocation_bytes(count, stride, maximum):
    """Evaluate the selected count guard without allocating or executing target code."""
    if type(count) is not int or count < 0 or stride <= 0 or maximum < 0:
        raise ValueError('invalid modeled count')
    return None if count > maximum else count * stride


def model_saturating_increment64(value):
    """Model the prior-context unsigned qword increment after its admission gate."""
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError('expected an unsigned qword')
    return min(value + 1, (1 << 64) - 1)


def rip_reference(data, secs, site, prefix):
    raw = get_bytes(data, secs, site, 7, executable=True)
    if raw[:3] != bytes.fromhex(prefix):
        raise ValueError('unexpected RIP-relative instruction')
    return site + 7 + struct.unpack_from('<i', raw, 3)[0]


def tsv(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def collect(data, expected=SHA256):
    digest = verify_digest(data, expected)
    secs = sections(data)
    fdes = selected_fdes(data, secs)
    fde_by_role = {f['role']: f for f in fdes}
    function_rows = []
    for f in sorted(fdes, key=lambda row: row['start']):
        function_rows.append((f['role'], hex(f['start']), hex(f['end']),
                              hex(file_offset(data, secs, f['start'], len(f['raw']), True)),
                              len(f['raw']), hex(f['fde']), hex(f['cie']),
                              '-' if f['lsda'] is None else hex(f['lsda']), f['index'],
                              f['digest'], f['raw'].hex()))

    field_values, field_rows = {}, []
    for name, va, expected_bytes, off, width, signed in FIELDS:
        raw = get_bytes(data, secs, va, len(bytes.fromhex(expected_bytes)), executable=True)
        val = read_field(raw, expected_bytes, off, width, signed)
        if name in field_values:
            raise ValueError('duplicate selected field')
        field_values[name] = val
        field_rows.append((name, hex(va), hex(file_offset(data, secs, va, len(raw), True)),
                           raw.hex(), off, width, int(signed), val, hex(val)))
    joins = make_joins(field_values)

    pattern_rows = []
    for label, va, expected_hex in PATTERNS:
        expected_raw = bytes.fromhex(expected_hex)
        raw = get_bytes(data, secs, va, len(expected_raw), executable=True)
        check_pattern(raw, expected_hex)
        pattern_rows.append((label, hex(va), hex(file_offset(data, secs, va, len(raw), True)), raw.hex()))

    window_rows = []
    for role, start, end in WINDOWS:
        if end <= start:
            raise ValueError('empty selected window')
        owners = [f for f in fdes if f['start'] <= start and end <= f['end']]
        if not role.startswith('context_') and len(owners) != 1:
            raise ValueError('new window outside one selected FDE')
        if role.startswith('context_') and owners:
            raise ValueError('context window unexpectedly overlaps an owned FDE')
        raw = get_bytes(data, secs, start, end - start, executable=True)
        window_rows.append((role, 'prior_context' if role.startswith('context_') else owners[0]['role'],
                            hex(start), hex(end), hex(file_offset(data, secs, start, end-start, True)),
                            hashlib.sha256(raw).hexdigest(), raw.hex()))

    edge_rows, edge_objects = [], []
    for label, va, expected_target in EDGES:
        raw = get_bytes(data, secs, va, 7, executable=True)
        kind, opcode, target = decode_transfer(raw, va)
        ensure_target(target, expected_target)
        owners = [f for f in fdes if f['start'] <= va and va + len(opcode) <= f['end']]
        context = label.endswith('_context')
        if context and owners:
            raise ValueError('prior context unexpectedly in a selected FDE')
        if not context and len(owners) != 1:
            raise ValueError('selected transfer outside one owned FDE')
        owner = 'prior_context' if context else owners[0]['role']
        edge_rows.append((label, owner, hex(va), hex(file_offset(data, secs, va, len(opcode), True)),
                          kind, opcode.hex(), hex(target)))
        edge_objects.append(dict(label=label, owner=owner, va=va, kind=kind, target=target))

    location_pins = ((0x64767a8, 123, 37), (0x64aa260, 340, 21))
    relocs = read_relocations(data, secs, set(SLOTS) | {x[0] for x in location_pins})
    locations = []
    for va, expect_line, expect_col in location_pins:
        entry, typ, sym, ptr = relocs[va]
        if typ != 8 or sym != 0 or ptr < 0:
            raise ValueError('Location pointer relocation changed')
        length, line, col = struct.unpack('<QII', get_bytes(data, secs, va + 8, 16))
        if length <= 0 or length > 4096:
            raise ValueError('invalid Location string length')
        raw = get_bytes(data, secs, ptr, length)
        tail = b'l1/src/abci/state.rs'
        if not raw.endswith(tail) or line != expect_line or col != expect_col:
            raise ValueError('Location contents changed')
        locations.append((hex(va), hex(file_offset(data, secs, va, 24)), hex(entry),
                          hex(ptr), length, line, col, tail.decode('ascii')))

    slot_rows = []
    for slot, (expected_type, expected_addend, expected_name) in sorted(SLOTS.items()):
        entry, typ, sym, addend = relocs[slot]
        name = dynamic_symbol(data, secs, sym) if sym else ''
        if (typ, addend, name) != (expected_type, expected_addend, expected_name):
            raise ValueError('selected boundary relocation changed')
        if typ == 8 and sym != 0:
            raise ValueError('relative relocation has nonzero symbol')
        slot_rows.append((hex(slot), hex(entry), typ, sym, hex(addend), name))

    # Derive sites from the authenticated instructions rather than duplicating
    # their numeric addresses in this report. The selected control-flow edges
    # identify the predicate tests and the four backwards copy-loop targets.
    edges_by_label = {edge['label']: edge for edge in edge_objects}
    if len(edges_by_label) != len(edge_objects):
        raise ValueError('duplicate selected transfer label')
    field_sites = {name: va for name, va, *_ in FIELDS}
    buckets = (
        ('A', 'parent_tag_equal', field_sites['bucket_tag'],
         edges_by_label['merge_first_loop']['target'], 'a'),
        ('B', 'first_zero_second_nonzero', edges_by_label['classify_predicate_b_context']['va'],
         edges_by_label['merge_second_loop']['target'], 'b'),
        ('C', 'first_nonzero', edges_by_label['classify_predicate_a_context']['va'],
         edges_by_label['merge_third_loop']['target'], 'c'),
        ('D', 'both_zero', edges_by_label['classify_predicate_b_result_context']['va'],
         edges_by_label['merge_fourth_loop']['target'], 'd'),
    )
    evaluation_sites = sorted(x[2] for x in buckets)
    bucket_rows = []
    for rank, (label, condition, test_site, copy_site, key) in enumerate(sorted(buckets, key=lambda x: x[3]), 1):
        bucket_rows.append((label, condition, evaluation_sites.index(test_site) + 1, hex(test_site),
                            field_values[f'bucket_{key}_length_stack'],
                            field_values[f'bucket_{key}_pointer_stack'],
                            field_values[f'merge_{key}_input_offset'], rank, hex(copy_site)))

    table_specs = (
        ('common_selector', rip_reference(data, secs, 0x4d909ee, '488d0d'), 4, 'common_precheck'),
        ('value_selector', rip_reference(data, secs, 0x4d90d54, '488d0d'),
         field_values['switch_default'] + 1, 'value_dispatch'),
    )
    if table_specs[0][1] != 0x914ea8 or table_specs[1][1] != 0x915028:
        raise ValueError('selected branch table base changed')
    table_rows = []
    for label, base, count, owner in table_specs:
        fde = fde_by_role[owner]
        for i in range(count):
            at = base + 4*i
            raw = get_bytes(data, secs, at, 4)
            target = base + struct.unpack('<i', raw)[0]
            if not fde['start'] <= target < fde['end']:
                raise ValueError('selected table target outside expected FDE')
            if label == 'common_selector' and i == model_common_index(field_values['common_selector_threshold']):
                if target != 0x4d90a7a:
                    raise ValueError('selected common-key success arm changed')
            table_rows.append((label, i, hex(at), hex(file_offset(data, secs, at, 4)),
                               raw.hex(), hex(target)))

    unwind = []
    for fde in sorted(fdes, key=lambda row: row['start']):
        unwind.extend(lsda_rows(data, secs, fde))
    unwind_rows = [(r['role'], hex(r['lsda']), hex(r['file_offset']), hex(r['start']),
                    hex(r['end']), '-' if r['landing'] is None else hex(r['landing']),
                    r['action'], r['raw']) for r in unwind]
    call_rows = []
    for edge in edge_objects:
        if edge['owner'] == 'prior_context' or edge['kind'] not in ('call', 'indirect_call_slot'):
            continue
        hits = [r for r in unwind if r['role'] == edge['owner'] and r['start'] <= edge['va'] < r['end']]
        if len(hits) > 1:
            raise ValueError('ambiguous unwind call-site range')
        if hits:
            state = 'covered'
            landing = '-' if hits[0]['landing'] is None else hex(hits[0]['landing'])
            action = str(hits[0]['action'])
        else:
            state = 'no_lsda' if fde_by_role[edge['owner']]['lsda'] is None else 'not_in_table'
            landing = action = '-'
        call_rows.append((edge['label'], edge['owner'], hex(edge['va']), state, landing, action))

    # Evidence counts are selected records, not a whole-component denominator.
    result = {
        'functions.tsv': tsv(('role','start_va','end_va_exclusive','file_offset','size','fde_va',
                              'cie_va','lsda_va','unwind_index','sha256','raw_hex'), function_rows),
        'fields.tsv': tsv(('name','instruction_va','file_offset','raw_hex','byte_offset','byte_width',
                           'signed','value_decimal','value_hex'), field_rows),
        'patterns.tsv': tsv(('name','instruction_va','file_offset','raw_hex'), pattern_rows),
        'windows.tsv': tsv(('role','ownership','start_va','end_va_exclusive','file_offset',
                            'sha256','raw_hex'), window_rows),
        'transfers.tsv': tsv(('label','ownership','site_va','file_offset','kind','raw_hex',
                              'target_va_or_slot'), edge_rows),
        'locations.tsv': tsv(('location_va','file_offset','relocation_file_offset','path_va',
                              'path_length','line','column','path_suffix'), locations),
        'relocations.tsv': tsv(('slot_va','relocation_file_offset','type','symbol_index','addend',
                                'symbol_name'), slot_rows),
        'buckets.tsv': tsv(('bucket','condition','evaluation_order','test_site_va','length_stack_offset',
                            'pointer_stack_offset','merge_input_offset','merge_order','copy_loop_va'), bucket_rows),
        'tables.tsv': tsv(('role','index','entry_va','file_offset','raw_hex','target_va'), table_rows),
        'unwind.tsv': tsv(('role','lsda_va','record_file_offset','start_va','end_va_exclusive',
                           'landing_va_or_dash','action','raw_hex'), unwind_rows),
        'unwind-calls.tsv': tsv(('label','role','site_va','status','landing_va_or_dash','action'), call_rows),
        'joins.json': json_bytes(joins),
    }
    result['summary.json'] = json_bytes({
        'binary_sha256': digest,
        'release': 'node115',
        'selected_fde_count': len(function_rows),
        'selected_instruction_fields': len(field_rows),
        'selected_dataflow_patterns': len(pattern_rows),
        'selected_windows': len(window_rows),
        'context_windows': sum(row[1] == 'prior_context' for row in window_rows),
        'selected_transfers': len(edge_rows),
        'context_transfers': sum(row[1] == 'prior_context' for row in edge_rows),
        'location_records': len(locations),
        'boundary_relocations': len(slot_rows),
        'selected_table_entries': len(table_rows),
        'selected_buckets': len(bucket_rows),
        'selected_lsda_rows': len(unwind_rows),
        'selected_call_unwind_links': len(call_rows),
        'limitations': 'Selected static records only; FDEs are unwind ranges, '
                       'not complete function or component coverage.',
    })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    # Complete authentication and analysis before creating any output files.
    result = collect(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(result.items()):
        (args.out / name).write_bytes(content)


if __name__ == '__main__':
    main()
