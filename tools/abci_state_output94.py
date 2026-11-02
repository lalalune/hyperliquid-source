#!/usr/bin/env python3
"""Qualify a node 94 state-loader output path using fixed, file-backed ELF bytes.

The selected functions are distinct from the previously indexed loader, caller,
and sink extents.  Their limited handoff windows are marked boundary-only.
No target code is executed and no native program is invoked.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from elf_index import unwind_index
from fde_extents import eh_frame_records

ROOT = HERE.parent
TARGET = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Each end and code hash is a pin, not an assumption that unwind extents are
# complete source-function boundaries.  Names describe only the bounded role.
FUNCTIONS = {
    0x2519180: (0x2519329, '86b781b754523489e41a778c0ed00bb89c0386680deb65ef6e924467f8b3ccb2', 'conditional record conversion'),
    0x2862490: (0x2862887, '398e87d59737d22bdb8fe86de80d1d9c63b5950ba771a011f8839331b197a160', 'temporary ordered-map update'),
    0x25dd540: (0x25dd609, '14aa98c81f85f6f02f65f1c6855facf81e624f9ac72e7c5452fa40a11e168d3c', 'map output adapter'),
    0x2566730: (0x2566a30, '5b99de3a9162b7c2a63fa155ce64b836f8f1aeff8aebe32d6f0562ff0671af66', 'map entry pointer collection'),
    0x1e37f00: (0x1e3818b, 'afc43be0a5fbb3d312b34b11112fc52cd74bd3c9a532b10dc2f483203a28896a', 'entry sequence writer'),
    0x1df07d0: (0x1df0a1f, 'e7baf90e968f57ce8cc9a4a5f1db6a74f1fcbb174066789e9b5f41f8b48a6a76', 'key value pair writer'),
    0x28c7b10: (0x28c7c74, '9469c8b555a2aa35e23f660f8a5b4c5f897c4d8d92314fab6c895dea28e87e85', 'book order container writer'),
    0x1e562a0: (0x1e56410, 'cb431a7f908a808b1237d0a3f6e6729a583740867d5a2c4564e804e8fbbb0bb0', 'two-sided list writer'),
    0x1e4a950: (0x1e4aca4, '1f28e46e3dccb964491f3040c4657508ba156052373865f78c5321988f5a7fd0', 'converted record list writer'),
    0x28c7770: (0x28c78d2, 'fbf19d86fe67afe9e59bf02b835d53eacc366a03a881dc94fc6b92ada1ed4b65', 'converted record discriminant writer'),
    0x1e0f590: (0x1e0f6ed, '3107c3349f6a6fec9436004028c90bf3fd604d16f4f2c3370edd722d84caf2df', 'first pair element writer'),
    0x1e0e6b0: (0x1e0e7b3, '6e54e4c666b3baed30645e8fcfe719a752dbd6bc594010d7a444ff98fdfecad5', 'second pair element writer'),
    0x23367a0: (0x2336b49, '8960e55ebddf3879f23ff1f996bc41952e43274f6bd5665c6a8d6c0ddddaeb5b', 'sixteen-field order writer'),
    0x23d4ac0: (0x23d4b20, 'c03262861aa98193ee7c817fd11fc722015a189b46d5265824e33511b09c1dc4', 'children field adapter'),
    0x1e3ba80: (0x1e3bdd4, 'eb74d5ed3f4b36119e76d0b3b80cab1d8fcfd5ce987b26dd374fc8abfc011a9b', 'children list writer'),
    0x25e7da0: (0x25e7e66, 'f2c905b2a4c3adcceab5e0cce31ab5b32ed3633afa355b1a43cd5379c341fded', 'text map output adapter'),
    0x290ea20: (0x290f70e, '02b1118011f18f3a3e6e18c19e9687ac1802d43eeb43cbca2ff3e89b838fefeb', 'text entry and container writer'),
    0x2399b40: (0x2399e84, 'b75d80fee071f97000f6c0244a37391bba57dc36fc11edd2491b4eb355c9d886', 'text two-sided list writer'),
    0x294c110: (0x294c770, '2c4bc40f69fdc26c1c29f24728b4d1ca5931d8faae220f929034eca46f491449', 'text converted record list writer'),
    0x2336310: (0x2336799, 'c2c384adc15c555455476a1629f06b23a2008da6be0d6fda5a9738a4d1c39ecb', 'text sixteen-field order writer'),
    0x23d2050: (0x23d2087, '6b853930783999d0c56023cca6154e116308ceff7b0b0b800ff7d05cf3a0c82c', 'text children field adapter'),
    0x2967f60: (0x2968301, '53d4fd778b77908ec3397e224ddef07aa74277b113eb33049ecd2559f118b5bd', 'text children list writer'),
}

# Boundary windows are *not* claimed functions.  The first ends before the
# previously inventoried call site; the earlier loader GOT is not re-analysed.
BOUNDARY_WINDOWS = [
    ('loaded_value_arguments', 0x22aec15, 0x22aec2e, 'f66fa8543a1f9eaac72f699875613871c1141e7d22613d0cf0bea3656dbe93ed'),
    ('processor_entry', 0x28c66c1, 0x28c66f6, '050fb23508634e3171dd03ae371ce77d38ca834e619c6f294af138017cccd036'),
    ('source_traversal_setup', 0x28c66f6, 0x28c675b, '87a39d18dff786d8b28cc9e86bc6ccd10d6dedc93e52aef882873a97ee44330e'),
    ('source_mul_continue', 0x28c6794, 0x28c67b3, '71e16c6192f72fe87c5c79790a03ca70674ca1117c9d5b6eff9a6963c641cc92'),
    ('source_mul_add', 0x28c6805, 0x28c6822, '7d0454719bf01e216b9286792f044c142a31fb689e186192f9187d5778c6c032'),
    ('source_overflow_failure', 0x28c6d25, 0x28c6d43, '8cc861606889d0f05ba57a4a17ccaca6059500ccebc29e962e869cee4bbad246'),
    ('source_traversal_loop', 0x28c67c0, 0x28c6805, '13e4d5c69e0acebdd0746575eb4bf3da20f6793c9a10cf625909be2fc3538c05'),
    ('map_finished', 0x28c6b98, 0x28c6bb3, '9e329e92608bd5cecdf855b55d12a94d167abb6345bf19ca463723094efb3ada'),
    ('height_mode_zero', 0x28c6bef, 0x28c6c02, '20fcf0b45b83e05ac6519c7374788a2edc4ce3c07a08dec53ee7826d8bf8b7f0'),
    ('result_build', 0x28c690e, 0x28c69d4, '71f914cfb3d8a9a870720005458f63b2596d30c54b1de290b0e70e7b3f2f1b1c'),
    ('map_value_without_conversion', 0x28c69e0, 0x28c6a1d, '9dc43b93797632bcf0cb128d5a92939566e059f508998a00178976a8805ec8ff'),
    ('map_update_handoff', 0x28c6abe, 0x28c6b04, '1ce1fb8aa462d1c0efae3521bade4343f292de692adc267b3c2d5a0e57a624cb'),
    ('map_update_cleanup_choice', 0x28c6b04, 0x28c6b0a, '15b7e822d2b9c8c62b292992259c5fe8cfa3116c03040ef07d8c89e4523ac488'),
    ('result_handoff', 0x28c6bb3, 0x28c6bef, '793ac2fa595e0acaf1b1d5861e2e205e4a66dc6c11ec20fd6c85e864a2503f80'),
    ('sink_entry', 0x28cb9fa, 0x28cba18, 'b67eb8073c64a4aa7206c7027bb2be96fed77d2e2d0a3b093641298db38c6064'),
    ('sink_dispatch', 0x28cbae0, 0x28cbb98, '7e2931662595325553a2abae3abb371364ae29a6ca1ce1a7e9b37fbb55ada9ae'),
    ('sink_text_dispatch', 0x28cbd9b, 0x28cbe25, '3b80b18128ccbdc6a9f145d3728e0f4cfb71b3276a42ee985726d2dcea9bbd0d'),
    ('sink_write_dispatch', 0x28cbe25, 0x28cbe5d, '42135da981fdc126131ba5eaf1d2dbba43b4082181b70511dd38962eab5b39f6'),
    ('sink_null_return', 0x28cbee8, 0x28cbf0a, '668a8c6ce5c14d65210825aa679a9d1d55ffa134714b65a2e0e1bb1b4c7a6baa'),
    ('sink_writer_failure', 0x28cbf0a, 0x28cbf76, '6f977b6fbb4c10c56e16cd6084953544b89d7bcddcfa000cc00767ef2f5177f7'),
]

# Ranges are manually selected instruction-aligned windows, not a linear
# disassembly or an exhaustive reachability claim.  Ends are exclusive.
OWNED_WINDOWS = [
    ('record_allocation', 0x2519194, 0x2519202),
    ('record_conversion_loop', 0x2519240, 0x25192bd),
    ('map_search_and_replace', 0x28624a1, 0x2862646),
    ('map_empty_insert', 0x2862709, 0x2862807),
    ('map_failure_paths', 0x2862819, 0x2862846),
    ('map_adapter', 0x25dd549, 0x25dd5e4),
    ('entry_collection_start', 0x2566738, 0x2566805),
    ('entry_collection_end', 0x25669cb, 0x2566a11),
    ('sequence_header', 0x1e37f19, 0x1e37f7b),
    ('sequence_initial_state', 0x1e37f7b, 0x1e37fa5),
    ('sequence_loop', 0x1e380b3, 0x1e3810a),
    ('pair_selected_path', 0x1df07f3, 0x1df08a4),
    ('container_complete', 0x28c7b26, 0x28c7c64),
    ('sides_selected', 0x1e562c0, 0x1e563be),
    ('record_list_selected', 0x1e4a969, 0x1e4a9e2),
    ('record_list_loop', 0x1e4aa2a, 0x1e4aa68),
    ('record_variant', 0x28c777b, 0x28c785e),
    ('tag_zero_first_element', 0x1e0f664, 0x1e0f6b2),
    ('tag_zero_second_element', 0x1e0e75b, 0x1e0e77d),
    ('order_writer_complete', 0x23367a0, 0x2336b49),
    ('children_adapter_complete', 0x23d4ac0, 0x23d4b20),
    ('children_sequence', 0x1e3ba99, 0x1e3bb98),
    ('children_failure', 0x1e3bd15, 0x1e3bda8),
    ('text_adapter', 0x25e7da7, 0x25e7e40),
    ('text_outer_sequence', 0x290ea2e, 0x290eaa0),
    ('text_entry_key', 0x290eb50, 0x290ecc1),
    ('text_value_variant', 0x290ed60, 0x290ee7e),
    ('text_container_keys', 0x290ee7e, 0x290ef49),
    ('text_sentinel_sides', 0x290eff0, 0x290f0ce),
    ('text_result', 0x290f620, 0x290f631),
    ('text_two_sides', 0x2399b4e, 0x2399ce3),
    ('text_record_start', 0x294c11e, 0x294c191),
    ('text_record_direct', 0x294c1a0, 0x294c1d8),
    ('text_record_discriminant', 0x294c2a0, 0x294c2c9),
    ('text_record_pair', 0x294c370, 0x294c45e),
    ('text_order_complete', 0x2336310, 0x2336799),
    ('text_children_adapter_complete', 0x23d2050, 0x23d2087),
    ('text_children_start', 0x2967f60, 0x2968018),
    ('text_children_loop', 0x29680f0, 0x2968128),
]

# Selected direct transfers; no raw scanning or instruction-boundary inference.
EDGES = [
    ('converted_records_from_boundary', 0x28c697d, 0x2519180),
    ('map_update_from_boundary', 0x28c6adb, 0x2862490),
    ('sink_from_boundary', 0x28c6bd8, 0x28cb9f0),
    ('adapter_from_boundary', 0x28cbb65, 0x25dd540),
    ('collect_entries', 0x25dd5aa, 0x2566730),
    ('write_entries', 0x25dd5b8, 0x1e37f00),
    ('write_entry', 0x1e380ee, 0x1df07d0),
    ('write_entry_value', 0x1df0853, 0x28c7b10),
    ('write_sentinel_side_map', 0x28c7b46, 0x1e562a0),
    ('write_side_map', 0x28c7be8, 0x1e562a0),
    ('write_untriggered', 0x28c7c29, 0x1e4a950),
    ('side_zero_list', 0x1e56361, 0x1e4a950),
    ('side_one_list', 0x1e56381, 0x1e4a950),
    ('write_converted_record', 0x1e4aa49, 0x28c7770),
    ('tag_one_order', 0x28c778a, 0x23367a0),
    ('tag_zero_first', 0x28c780b, 0x1e0f590),
    ('tag_zero_second', 0x28c7829, 0x1e0e6b0),
    ('tag_zero_order', 0x1e0e776, 0x23367a0),
    ('order_children', 0x2336a03, 0x23d4ac0),
    ('children_element', 0x1e3bb79, 0x23367a0),
    ('text_adapter_from_boundary', 0x28cbdfb, 0x25e7da0),
    ('text_collect_entries', 0x25e7e07, 0x2566730),
    ('text_write_entries', 0x25e7e12, 0x290ea20),
    ('text_write_side_map', 0x290eed1, 0x2399b40),
    ('text_write_untriggered', 0x290ef3b, 0x294c110),
    ('text_sentinel_side_zero', 0x290effc, 0x294c110),
    ('text_sentinel_side_one', 0x290f0c0, 0x294c110),
    ('text_side_zero_list', 0x2399c18, 0x294c110),
    ('text_side_one_list', 0x2399cd5, 0x294c110),
    ('text_tag_nonzero_order', 0x294c1a7, 0x2336310),
    ('text_tag_zero_order', 0x294c450, 0x2336310),
    ('text_order_children', 0x233659a, 0x23d2050),
    ('text_children_order', 0x29680ff, 0x2336310),
]

# This tail jump is separate from e8 calls, with its own fixed opcode.
TAIL_EDGES = [('text_children_tail', 0x23d2064, 0x2967f60)]

# label, branch address, required mnemonic, required destination
BRANCHES = [
    ('boundary_no_height', 0x28c66cf, 'je', 0x28c6bef),
    ('boundary_non_two_kind', 0x28c6bfc, 'jne', 0x28c66f6),
    ('boundary_convert_flag_zero', 0x28c691a, 'je', 0x28c69e0),
    ('boundary_cleanup_flag_nonzero', 0x28c6b08, 'jne', 0x28c6b74),
    ('boundary_mul_fits', 0x28c67ac, 'jno', 0x28c6816),
    ('boundary_mul_overflow', 0x28c6810, 'jo', 0x28c6d25),
    ('boundary_add_overflow', 0x28c681c, 'jb', 0x28c6d34),
    ('boundary_source_empty', 0x28c67cd, 'je', 0x28c6845),
    ('boundary_source_end', 0x28c67e8, 'je', 0x28c6b98),
    ('boundary_more_work', 0x28c6bad, 'jb', 0x28c685e),
    ('boundary_sink_no_height', 0x28cba12, 'je', 0x28cbae0),
    ('boundary_null_path', 0x28cbb09, 'je', 0x28cbee8),
    ('boundary_predicate_zero', 0x28cbb20, 'je', 0x28cbd9b),
    ('boundary_writer_failure', 0x28cbb80, 'jne', 0x28cbf0a),
    ('allocation_size_allowed', 0x25191a9, 'jbe', 0x25191b8),
    ('record_zero_capacity', 0x25191cd, 'je', 0x25191fa),
    ('record_allocation_failure', 0x25191de, 'je', 0x25192f7),
    ('record_empty', 0x2519231, 'je', 0x25192bd),
    ('record_loop_finished', 0x2519294, 'je', 0x25192b6),
    ('record_flag_nonzero', 0x251929e, 'jne', 0x2519260),
    ('map_empty', 0x28624af, 'je', 0x28625a3),
    ('map_search_next', 0x2862544, 'je', 0x2862500),
    ('map_existing_key', 0x286254b, 'je', 0x286257b),
    ('map_allocation_failure', 0x286271a, 'je', 0x2862819),
    ('map_node_capacity_failure', 0x2862784, 'jae', 0x286282b),
    ('adapter_empty_root', 0x25dd555, 'je', 0x25dd58c),
    ('collection_size_ok', 0x256675f, 'je', 0x256676c),
    ('collection_empty', 0x256676f, 'je', 0x256679f),
    ('collection_allocation_failure', 0x256678f, 'je', 0x2566a03),
    ('collection_invalid_iterator', 0x2566821, 'je', 0x25669f4),
    ('collection_invalid_node', 0x2566906, 'je', 0x25669e5),
    ('sequence_not_fast_path', 0x1e37f36, 'je', 0x1e37f50),
    ('sequence_header_error', 0x1e37f75, 'jne', 0x1e3802e),
    ('sequence_entry_error', 0x1e380fb, 'jne', 0x1e37fe0),
    ('pair_other_writer_mode', 0x1df07fc, 'jno', 0x1df089d),
    ('pair_header_error', 0x1df0826, 'jne', 0x1df08cb),
    ('pair_key_error', 0x1df0842, 'jne', 0x1df0996),
    ('pair_value_error', 0x1df0861, 'jne', 0x1df09d2),
    ('container_regular_variant', 0x28c7b2b, 'jno', 0x28c7b50),
    ('container_positional', 0x28c7b5f, 'je', 0x28c7b93),
    ('container_header_ok', 0x28c7b7c, 'je', 0x28c7bb0),
    ('container_skip_first_name', 0x28c7bb5, 'jne', 0x28c7bd1),
    ('container_skip_second_name', 0x28c7bfe, 'jne', 0x28c7c1a),
    ('container_first_name_error', 0x28c7bcf, 'jne', 0x28c7c3a),
    ('container_first_value_error', 0x28c7bf7, 'jne', 0x28c7c49),
    ('container_second_name_error', 0x28c7c18, 'jne', 0x28c7c3a),
    ('container_second_value_error', 0x28c7c33, 'jne', 0x28c7c49),
    ('sides_ordinary_name', 0x1e562c4, 'jne', 0x1e562e7),
    ('side_first_error', 0x1e56370, 'jne', 0x1e563c0),
    ('side_second_error', 0x1e5638b, 'jne', 0x1e563c0),
    ('list_count_needs_alternate_path', 0x1e4a9b6, 'jne', 0x1e4aabd),
    ('list_header_error', 0x1e4a9dc, 'jne', 0x1e4aaa3),
    ('list_element_error', 0x1e4aa56, 'jne', 0x1e4ac1f),
    ('record_tag_not_one', 0x28c7781, 'jne', 0x28c7794),
    ('record_first_error', 0x28c7818, 'jne', 0x28c785e),
    ('record_second_error', 0x28c7832, 'jne', 0x28c785e),
    ('second_writer_non_sentinel', 0x1e0e6cd, 'jno', 0x1e0e6d8),
    ('second_writer_header_error', 0x1e0e705, 'jne', 0x1e0e77d),
    ('second_writer_byte_error', 0x1e0e73c, 'jne', 0x1e0e787),
    ('order_positional', 0x23367c3, 'je', 0x23367fb),
    ('order_header_ok', 0x23367e0, 'je', 0x2336818),
    ('order_coin_name_error', 0x2336837, 'jne', 0x2336b2a),
    ('order_coin_value_error', 0x2336851, 'jne', 0x2336b2a),
    ('order_side_name_error', 0x233687e, 'jne', 0x2336b2a),
    ('order_side_b', 0x2336888, 'je', 0x2336893),
    ('order_side_value_error', 0x23368ab, 'jne', 0x2336b2a),
    ('order_limit_error', 0x23368d5, 'jne', 0x2336b12),
    ('order_size_error', 0x23368ff, 'jne', 0x2336b12),
    ('order_id_name_error', 0x2336924, 'jne', 0x2336b2a),
    ('order_id_value_error', 0x2336944, 'jne', 0x2336b25),
    ('order_timestamp_error', 0x233696c, 'jne', 0x2336b12),
    ('order_trigger_condition_error', 0x2336998, 'jne', 0x2336b12),
    ('order_trigger_flag_error', 0x23369c4, 'jne', 0x2336b12),
    ('order_trigger_price_error', 0x23369f1, 'jne', 0x2336b12),
    ('order_children_error', 0x2336a0d, 'jne', 0x2336b12),
    ('order_position_flag_error', 0x2336a39, 'jne', 0x2336b12),
    ('order_reduce_flag_error', 0x2336a65, 'jne', 0x2336b12),
    ('order_type_error', 0x2336a91, 'jne', 0x2336b12),
    ('order_original_size_error', 0x2336aba, 'jne', 0x2336b12),
    ('order_tif_error', 0x2336ae1, 'jne', 0x2336b12),
    ('order_cloid_error', 0x2336b0b, 'jne', 0x2336b12),
    ('children_without_name', 0x23d4ac4, 'je', 0x1e3ba80),
    ('children_name_ok', 0x23d4b04, 'je', 0x1e3ba80),
    ('children_header_error', 0x1e3bb0c, 'jne', 0x1e3bbd3),
    ('children_element_error', 0x1e3bb86, 'jne', 0x1e3bd4f),
    ('children_next', 0x1e3bb96, 'jne', 0x1e3bb70),
    ('children_count_overflow', 0x1e3bcbe, 'je', 0x1e3bd87),
    ('children_allocation_failure', 0x1e3bc01, 'je', 0x1e3bd96),
    ('boundary_text_allocation_failure', 0x28cbda9, 'je', 0x28cc090),
    ('boundary_text_writer_error', 0x28cbe06, 'jne', 0x28cbf4e),
    ('text_adapter_empty_root', 0x25e7db0, 'je', 0x25e7de7),
    ('text_adapter_no_free', 0x25e7e1f, 'je', 0x25e7e38),
    ('text_depth_overflow', 0x290ea36, 'je', 0x290f6e7),
    ('text_outer_empty', 0x290ea72, 'je', 0x290f557),
    ('text_container_regular', 0x290ed6b, 'jno', 0x290ee30),
    ('text_first_key_bad_state', 0x290ee97, 'je', 0x290f631),
    ('text_first_value_error', 0x290eed9, 'jne', 0x290f622),
    ('text_second_key_bad_state', 0x290eefd, 'je', 0x290f631),
    ('text_second_value_error', 0x290ef43, 'jne', 0x290f622),
    ('text_sentinel_first_error', 0x290f004, 'jne', 0x290f622),
    ('text_sentinel_second_error', 0x290f0c8, 'jne', 0x290f622),
    ('text_sides_depth_overflow', 0x2399b56, 'je', 0x2399e6a),
    ('text_first_side_error', 0x2399c20, 'jne', 0x2399d95),
    ('text_second_side_error', 0x2399cdd, 'jne', 0x2399d95),
    ('text_list_depth_overflow', 0x294c126, 'je', 0x294c756),
    ('text_list_empty', 0x294c16b, 'je', 0x294c620),
    ('text_record_nonzero', 0x294c2ac, 'jne', 0x294c1a0),
    ('text_direct_order_error', 0x294c1af, 'jne', 0x294c63f),
    ('text_pair_first_error', 0x294c3a5, 'jne', 0x294c63f),
    ('text_pair_order_error', 0x294c458, 'jne', 0x294c63f),
    ('text_order_depth_overflow', 0x2336323, 'je', 0x233678c),
    ('text_order_coin_error', 0x233637b, 'jne', 0x23366c8),
    ('text_order_side_error', 0x23363e9, 'jne', 0x23366c8),
    ('text_order_limit_error', 0x233644f, 'jne', 0x23366c8),
    ('text_order_size_error', 0x23364b5, 'jne', 0x23366c8),
    ('text_order_oid_error', 0x23364db, 'jne', 0x23366c8),
    ('text_order_timestamp_error', 0x2336506, 'jne', 0x23366c8),
    ('text_order_trigger_condition_error', 0x2336531, 'jne', 0x23366c8),
    ('text_order_is_trigger_error', 0x233655f, 'jne', 0x23366c8),
    ('text_order_trigger_price_error', 0x233658d, 'jne', 0x23366c8),
    ('text_order_children_error', 0x23365a2, 'jne', 0x23366c8),
    ('text_order_position_error', 0x23365d0, 'jne', 0x23366c8),
    ('text_order_reduce_error', 0x23365fe, 'jne', 0x23366c8),
    ('text_order_type_error', 0x2336629, 'jne', 0x23366c8),
    ('text_order_orig_size_error', 0x2336653, 'jne', 0x23366c8),
    ('text_order_tif_error', 0x2336679, 'jne', 0x23366c8),
    ('text_order_cloid_error', 0x23366a2, 'jne', 0x23366c8),
    ('text_children_adapter_bad_state', 0x23d2053, 'jne', 0x23d2069),
    ('text_children_empty', 0x2967ff6, 'je', 0x2968170),
    ('text_children_element_error', 0x2968107, 'jne', 0x2968198),
    ('text_children_next', 0x2968120, 'jne', 0x2968020),
]

# Every entry is (expected binary name, RIP-relative LEA, length-immediate,
# value setup start, value helper call).  children is named in its adapter.
FIELD_SPECS = [
    ('coin', 0x233681f, 0x2336826, 0x233683d, 0x2336848),
    ('side', 0x2336866, 0x233686d, 0x2336857, 0x23368a2),
    ('limitPx', 0x23368b7, 0x23368c3, 0x23368b1, 0x23368cb),
    ('sz', 0x23368e1, 0x23368ed, 0x23368db, 0x23368f5),
    ('oid', 0x233690c, 0x2336913, 0x233692a, 0x2336936),
    ('timestamp', 0x233694e, 0x233695a, 0x233694a, 0x2336962),
    ('triggerCondition', 0x233697a, 0x2336986, 0x2336972, 0x233698e),
    ('isTrigger', 0x23369a6, 0x23369b2, 0x233699e, 0x23369ba),
    ('triggerPx', 0x23369d3, 0x23369df, 0x23369ca, 0x23369e7),
    ('children', 0x23d4acf, 0x23d4ad9, 0x23369f7, 0x2336a03),
    ('isPositionTpsl', 0x2336a1b, 0x2336a27, 0x2336a13, 0x2336a2f),
    ('reduceOnly', 0x2336a47, 0x2336a53, 0x2336a3f, 0x2336a5b),
    ('orderType', 0x2336a73, 0x2336a7f, 0x2336a6b, 0x2336a87),
    ('origSz', 0x2336a9c, 0x2336aa8, 0x2336a93, 0x2336ab0),
    ('tif', 0x2336ac3, 0x2336acf, 0x2336abc, 0x2336ad7),
    ('cloid', 0x2336aea, 0x2336af6, 0x2336ae3, 0x2336b01),
]


# The text writer has a separate implementation; this table binds its key
# references and helper calls to the independently decoded binary names.
TEXT_FIELD_SPECS = [
    (0x2336361, 0x233636b, 0x2336373),
    (0x233638b, 0x2336395, 0x233639a),
    (0x23363f4, 0x23363fe, 0x2336403),
    (0x233645a, 0x2336464, 0x2336469),
    (0x23364c4, 0x23364ce, 0x23364d3),
    (0x23364ef, 0x23364f9, 0x23364fe),
    (0x233651a, 0x2336524, 0x2336529),
    (0x2336548, 0x2336552, 0x2336557),
    (0x2336576, 0x2336580, 0x2336585),
    (0x23d2058, 0x23d205f, 0x233659a),
    (0x23365b9, 0x23365c3, 0x23365c8),
    (0x23365e7, 0x23365f1, 0x23365f6),
    (0x2336612, 0x233661c, 0x2336621),
    (0x233663c, 0x2336646, 0x233664b),
    (0x2336662, 0x233666c, 0x2336671),
    (0x2336688, 0x2336692, 0x233669a),
]


# Prefix, displacement width and expected offset are fixed instruction pins.
# All offsets are recovered from the file bytes, relative to the order pointer.
VALUE_SPECS = [
    ('coin', 0x233683d, '498b76', 1, 0x08, 'load'),
    ('coin', 0x2336841, '498b56', 1, 0x10, 'load'),
    ('side', 0x2336857, '410fb6ae', 4, 0x90, 'load'),
    ('limitPx', 0x23368b1, 'f2410f1046', 1, 0x60, 'load'),
    ('sz', 0x23368db, 'f2410f1046', 1, 0x68, 'load'),
    ('oid', 0x233692a, '498b56', 1, 0x70, 'load'),
    ('timestamp', 0x233694a, '4d8b46', 1, 0x78, 'load'),
    ('triggerCondition', 0x2336972, '4d8b46', 1, 0x20, 'load'),
    ('triggerCondition', 0x2336976, '4d8b4e', 1, 0x28, 'load'),
    ('isTrigger', 0x233699e, '450fb686', 4, 0x91, 'load'),
    ('triggerPx', 0x23369ca, 'f2410f1086', 4, 0x80, 'load'),
    ('children', 0x23369f7, '498d56', 1, 0x30, 'address'),
    ('isPositionTpsl', 0x2336a13, '450fb686', 4, 0x92, 'load'),
    ('reduceOnly', 0x2336a3f, '450fb686', 4, 0x93, 'load'),
    ('orderType', 0x2336a6b, '4d8b46', 1, 0x50, 'load'),
    ('orderType', 0x2336a6f, '4d8b4e', 1, 0x58, 'load'),
    ('origSz', 0x2336a93, 'f2410f1086', 4, 0x88, 'load'),
    ('tif', 0x2336abc, '4d8d86', 4, 0xa5, 'address'),
    ('cloid', 0x2336ae3, '4981c6', 4, 0x94, 'address'),
]


def authenticate(data, expected=SHA256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('target SHA-256 mismatch')
    return actual


def file_mapping(secs, va, size, *, executable=False):
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
        raise ValueError('invalid VA or size')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('unmapped, NOBITS, crossing or ambiguous VA')
    s = matches[0]
    return s, s['offset'] + va - s['address']


def read_va(data, secs, va, size, *, executable=False):
    _, off = file_mapping(secs, va, size, executable=executable)
    value = data[off:off + size]
    if len(value) != size:
        raise ValueError('file-backed read exceeds input')
    return value


def read_exact(data, secs, va, prefix):
    got = read_va(data, secs, va, len(prefix), executable=True)
    if got != prefix:
        raise ValueError(f'wrong instruction bytes at {va:#x}')
    return got


def source_operand(data, secs, va, prefix, width, expected):
    if width not in (1, 4):
        raise ValueError('unsupported source operand width')
    raw = read_va(data, secs, va, len(prefix) + width, executable=True)
    if not raw.startswith(prefix):
        raise ValueError(f'unexpected source operand at {va:#x}')
    offset = int.from_bytes(raw[len(prefix):], 'little')
    if offset != expected:
        raise ValueError(f'wrong source offset at {va:#x}')
    return offset, raw


def relative(data, secs, va, opcode, size):
    b = read_va(data, secs, va, size, executable=True)
    if not b.startswith(opcode) or size != len(opcode) + 4:
        raise ValueError(f'unexpected relative encoding at {va:#x}')
    disp = struct.unpack_from('<i', b, len(opcode))[0]
    return va + size + disp, b


def direct_call(data, secs, va, expected=None):
    target, raw = relative(data, secs, va, b'\xe8', 5)
    if expected is not None and target != expected:
        raise ValueError(f'wrong call target at {va:#x}')
    return target, raw


def direct_jump(data, secs, va, expected=None):
    target, raw = relative(data, secs, va, b'\xe9', 5)
    if expected is not None and target != expected:
        raise ValueError(f'wrong tail target at {va:#x}')
    return target, raw


def branch(data, secs, va, expected_kind=None, expected_target=None):
    first = read_va(data, secs, va, 2, executable=True)
    if first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
        raw = read_va(data, secs, va, 6, executable=True)
        cc, displacement = first[1] - 0x80, struct.unpack_from('<i', raw, 2)[0]
    elif 0x70 <= first[0] <= 0x7f:
        raw = first
        cc, displacement = first[0] - 0x70, struct.unpack_from('<b', raw, 1)[0]
    else:
        raise ValueError(f'unsupported conditional branch at {va:#x}')
    names = ('jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja',
             'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg')
    kind, target = names[cc], va + len(raw) + displacement
    if (expected_kind is not None and kind != expected_kind) or (expected_target is not None and target != expected_target):
        raise ValueError(f'wrong conditional branch at {va:#x}')
    return kind, target, raw


def rip_lea(data, secs, va):
    b = read_va(data, secs, va, 7, executable=True)
    if b[:3] not in (b'\x48\x8d\x05', b'\x48\x8d\x15', b'\x48\x8d\x35'):
        raise ValueError(f'unexpected RIP LEA at {va:#x}')
    return va + 7 + struct.unpack_from('<i', b, 3)[0], b


def imm32(data, secs, va, opcode):
    b = read_va(data, secs, va, 5, executable=True)
    if b[0] != opcode:
        raise ValueError(f'unexpected immediate opcode at {va:#x}')
    return struct.unpack_from('<I', b, 1)[0]


def checked_product_sum(multiplier, operand, addend):
    """Model the selected unsigned 64-bit checks, not target execution."""
    maximum = (1 << 64) - 1
    if any(type(x) is not int or not 0 <= x <= maximum
           for x in (multiplier, operand, addend)):
        raise ValueError('arithmetic input outside unsigned 64-bit range')
    product = multiplier * operand
    if product > maximum:
        return 'multiply_overflow', None
    result = product + addend
    if result > maximum:
        return 'add_overflow', None
    return 'ok', result


def variant_routes(raw_word):
    """Model the two pinned discriminant comparisons, not target execution."""
    if type(raw_word) is not int or not 0 <= raw_word < (1 << 64):
        raise ValueError('tag word outside unsigned 64-bit range')
    return {'binary_direct_order': (raw_word & 0xffffffff) == 1,
            'text_direct_order': (raw_word & 0xff) != 0}


def h(value):
    return hex(value)


def analyze(data, *, check_digest=True):
    if check_digest:
        authenticate(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    indexed = {row['start']: row for row in index}
    functions = []
    for start, (end, expected_hash, role) in sorted(FUNCTIONS.items()):
        rows = by_start.get(start, [])
        if len(rows) != 1:
            raise ValueError('missing or ambiguous selected FDE')
        fde = rows[0]
        if fde['end'] != end or start not in indexed or indexed[start]['fde'] != fde['fde']:
            raise ValueError('FDE extent or header mismatch')
        sec, off = file_mapping(secs, start, end - start, executable=True)
        raw = read_va(data, secs, start, end - start, executable=True)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected_hash:
            raise ValueError(f'selected extent hash mismatch at {start:#x}')
        functions.append({'start': h(start), 'end_exclusive': h(end), 'size': len(raw),
                          'file_offset': h(off), 'section': sec['name'],
                          'fde': h(fde['fde']), 'cie': h(fde['cie']),
                          'lsda': None if fde['lsda'] is None else h(fde['lsda']),
                          'code_sha256': digest, 'code_bytes': raw.hex(), 'role': role})

    def covered(va, size):
        selected = any(start <= va and va + size <= item[0]
                       for start, item in FUNCTIONS.items())
        boundary = any(start <= va and va + size <= end
                       for _, start, end, _ in BOUNDARY_WINDOWS)
        return selected or boundary

    windows = []
    for boundary, rows in ((True, BOUNDARY_WINDOWS), (False, OWNED_WINDOWS)):
        for item in rows:
            name, start, end = item[:3]
            if not boundary and not covered(start, end - start):
                raise ValueError(f'window outside selected extents: {name}')
            sec, off = file_mapping(secs, start, end - start, executable=True)
            raw = read_va(data, secs, start, end - start, executable=True)
            digest = hashlib.sha256(raw).hexdigest()
            if boundary and digest != item[3]:
                raise ValueError(f'boundary window changed: {name}')
            windows.append({'name': name, 'boundary_only': boundary, 'va': h(start),
                            'end_exclusive': h(end), 'file_offset': h(off),
                            'section': sec['name'], 'bytes': raw.hex(), 'sha256': digest})

    edges = []
    for label, va, expect in EDGES:
        target, raw = direct_call(data, secs, va, expect)
        if not covered(va, len(raw)):
            raise ValueError(f'transfer outside selected windows: {label}')
        _, off = file_mapping(secs, va, len(raw), executable=True)
        edges.append({'label': label, 'site': h(va), 'file_offset': h(off),
                      'bytes': raw.hex(), 'target': h(target)})

    for label, va, expect in TAIL_EDGES:
        target, raw = direct_jump(data, secs, va, expect)
        if not covered(va, len(raw)):
            raise ValueError(f'tail outside selected windows: {label}')
        _, off = file_mapping(secs, va, len(raw), executable=True)
        edges.append({'label': label, 'site': h(va), 'file_offset': h(off),
                      'bytes': raw.hex(), 'target': h(target)})

    branches = []
    for label, va, kind, expect in BRANCHES:
        actual, target, raw = branch(data, secs, va, kind, expect)
        if not covered(va, len(raw)):
            raise ValueError(f'branch outside selected windows: {label}')
        _, off = file_mapping(secs, va, len(raw), executable=True)
        branches.append({'label': label, 'site': h(va), 'file_offset': h(off),
                         'bytes': raw.hex(), 'condition': actual, 'taken_target': h(target),
                         'fallthrough': h(va + len(raw))})

    fields = []
    for i, (expected_name, lea, immediate, value, call) in enumerate(FIELD_SPECS, 1):
        name_va, lea_raw = rip_lea(data, secs, lea)
        op = read_va(data, secs, immediate, 1, executable=True)[0]
        if op not in (0xb9, 0xba):
            raise ValueError('field name length is not a supported immediate')
        length = imm32(data, secs, immediate, op)
        if not 0 < length <= 32:
            raise ValueError('field name length out of range')
        raw = read_va(data, secs, name_va, length)
        if raw != expected_name.encode('ascii'):
            raise ValueError(f'field name mismatch: {expected_name}')
        target, call_raw = direct_call(data, secs, call)
        fields.append({'ordinal': i, 'name': raw.decode('ascii'), 'name_va': h(name_va),
                       'name_length': length, 'lea_va': h(lea), 'lea_bytes': lea_raw.hex(),
                       'length_va': h(immediate), 'value_setup_va': h(value),
                       'call_va': h(call), 'call_bytes': call_raw.hex(), 'helper_va': h(target)})

    binary_calls = [int(field['call_va'], 16) for field in fields]
    if any(right <= left for left, right in zip(binary_calls, binary_calls[1:])):
        raise ValueError('binary field calls not in instruction order')

    layout = []
    for name, va, prefix, width, expect, access in VALUE_SPECS:
        offset, raw = source_operand(data, secs, va, bytes.fromhex(prefix), width, expect)
        if name not in {f['name'] for f in fields}:
            raise ValueError('layout field has no named field')
        layout.append({'field': name, 'instruction_va': h(va), 'bytes': raw.hex(),
                       'order_offset': h(offset), 'access': access})

    if len(TEXT_FIELD_SPECS) != len(fields):
        raise ValueError('field tables differ in length')
    text_fields = []
    for field, (lea, immediate, call) in zip(fields, TEXT_FIELD_SPECS):
        name_va, lea_raw = rip_lea(data, secs, lea)
        length = imm32(data, secs, immediate, 0xba)
        if not 0 < length <= 32:
            raise ValueError('text field name length out of range')
        raw = read_va(data, secs, name_va, length)
        if raw != field['name'].encode('ascii'):
            raise ValueError('binary/text field order mismatch')
        target, call_raw = direct_call(data, secs, call)
        text_fields.append({'ordinal': field['ordinal'], 'name': raw.decode('ascii'),
                            'name_va': h(name_va), 'name_length': length,
                            'lea_va': h(lea), 'lea_bytes': lea_raw.hex(),
                            'length_va': h(immediate), 'call_va': h(call),
                            'call_bytes': call_raw.hex(), 'helper_va': h(target)})

    text_calls = [int(field['call_va'], 16) for field in text_fields]
    if any(right <= left for left, right in zip(text_calls, text_calls[1:])):
        raise ValueError('text field calls not in instruction order')

    count = imm32(data, secs, 0x23367cd, 0xba)
    if count != len(fields):
        raise ValueError('order field count differs from header')
    labels = []
    label_specs = (
        ('side_map', 0x28c7bd1, 0x28c7bdd, 0xb9, b'SideMap'),
        ('sentinel_side_map', 0x28c7b31, 0x28c7b38, 0xb9, b'SideMap'),
        ('book_orders', 0x28c7bb7, 0x28c7bbe, 0xba, b'book_orders'),
        ('untriggered_orders', 0x28c7c00, 0x28c7c07, 0xba, b'untriggered_orders'),
        ('text_book_orders', 0x290ee86, 0x290ee7e, 0xba, b'book_orders'),
        ('text_untriggered_orders', 0x290eeec, 0x290eee4, 0xba, b'untriggered_orders'),
        ('side_zero', 0x2336893, 0x233689a, 0xba, b'B'),
        ('side_one', 0x233688a, 0x233689a, 0xba, b'A'),
    )
    for name, lea, imm, opcode, expected in label_specs:
        addr, raw = rip_lea(data, secs, lea)
        length = imm32(data, secs, imm, opcode)
        if length != len(expected):
            raise ValueError('container or side label length mismatch')
        literal = read_va(data, secs, addr, length)
        if literal != expected:
            raise ValueError('container or side label mismatch')
        labels.append({'role': name, 'va': h(addr), 'bytes': literal.hex(),
                       'text': literal.decode('ascii'), 'lea_va': h(lea),
                       'lea_bytes': raw.hex(), 'length_va': h(imm)})

    # Literal store instructions on selected text output routes.  These do not
    # assert the behavior of the separately owned escaping/value helpers.
    syntax = []
    for role, va, encoding, literal_size in (
        ('array_open', 0x290ea64, 'c604305b', 1),
        ('array_close', 0x290f568, 'c604305d', 1),
        ('object_open', 0x290ee67, 'c604307b', 1),
        ('object_close', 0x290f19e, '42c604207d', 1),
        ('quote', 0x290ec88, 'c6040122', 1),
        ('comma_newline', 0x290eb89, '6642c704202c0a', 2),
        ('colon_space', 0x290eebd, '66c704303a20', 2),
    ):
        raw = read_exact(data, secs, va, bytes.fromhex(encoding))
        syntax.append({'role': role, 'va': h(va), 'instruction_bytes': raw.hex(),
                       'stored_bytes': raw[-literal_size:].hex()})

    # Processor source fields and the repeated group stride, reached through
    # the previously indexed loader handoff; exact types remain unresolved.
    source_base = read_exact(data, secs, 0x28c6727, bytes.fromhex('498b8c24c0050000'))
    source_count = read_exact(data, secs, 0x28c672f, bytes.fromhex('49698424c8050000f0020000'))
    source_step = read_exact(data, secs, 0x28c67f2, bytes.fromhex('4881c6f0020000'))
    source_layout = {'base_offset': h(int.from_bytes(source_base[4:], 'little')),
                     'count_offset': h(int.from_bytes(source_count[4:8], 'little')),
                     'group_stride': h(int.from_bytes(source_count[8:], 'little')),
                     'loop_stride': h(int.from_bytes(source_step[3:], 'little'))}
    if source_layout['group_stride'] != source_layout['loop_stride']:
        raise ValueError('source traversal strides differ')

    multiplier = imm32(data, secs, 0x28c67a3, 0xb8)
    if imm32(data, secs, 0x28c6807, 0xb8) != multiplier or multiplier == 0:
        raise ValueError('source traversal multipliers differ')
    mul_a = read_exact(data, secs, 0x28c67a8, bytes.fromhex('49f76530'))
    mul_b = read_exact(data, secs, 0x28c680c, bytes.fromhex('49f76530'))
    if mul_a != mul_b:
        raise ValueError('source traversal multiply operands differ')
    arithmetic = {'multiplier': multiplier, 'operand_offset': h(mul_a[-1]),
                  'operand_bits': 64,
                  'maximum_operand_without_product_overflow': ((1 << 64) - 1) // multiplier}

    # The two list writers compare different widths and constants.  Only 0/1
    # tags are produced by the selected conversion; other tags are controls.
    discriminants = []
    for mode, va, expected, width in (
        ('binary', 0x28c777e, b'\x83\x3e\x01', 4),
        ('text', 0x294c2a9, b'\x80\x38\x00', 1),
    ):
        raw = read_exact(data, secs, va, expected)
        discriminants.append({'mode': mode, 'va': h(va), 'bytes': raw.hex(),
                              'width_bytes': width, 'compare_immediate': raw[-1]})

    # Fixed, instruction-bound operands for the 0xc0 -> 0xc8 conversion.
    read_exact(data, secs, 0x251926d, b'\x31\xc0')
    read_exact(data, secs, 0x251926f, b'\x49\x81\xc4\xc0\x00\x00\x00')
    read_exact(data, secs, 0x2519276, b'\x49\x89\x46\xf8')
    read_exact(data, secs, 0x25192a0, b'\x49\x8d\x74\x24\x18')
    read_exact(data, secs, 0x251928a, b'\x49\x81\xc6\xc8\x00\x00\x00')
    read_exact(data, secs, 0x251929b, b'\x80\x38\x00')
    full_copy = imm32(data, secs, 0x2519260, 0xba)
    output_copy = imm32(data, secs, 0x251927a, 0xba)
    input_stride = struct.unpack('<I', read_va(data, secs, 0x2519272, 4, executable=True))[0]
    small_copy = imm32(data, secs, 0x25192a5, 0xba)
    tag_one = imm32(data, secs, 0x25192af, 0xb8)
    stride = struct.unpack('<I', read_va(data, secs, 0x251928d, 4, executable=True))[0]
    source_offset = read_va(data, secs, 0x25192a4, 1, executable=True)[0]
    if (full_copy, output_copy, input_stride, small_copy, tag_one, stride, source_offset) != (192, 192, 192, 168, 1, 200, 24):
        raise ValueError('record conversion operands differ')
    # Sink initializes the serializer control word and byte on this branch.
    read_exact(data, secs, 0x28cbb4b, b'\xc7\x44\x24\x10\x00\x04\x00\x01')
    read_exact(data, secs, 0x28cbb53, b'\xc6\x44\x24\x14\x00')
    control = read_va(data, secs, 0x28cbb4f, 4, executable=True)
    flag = read_va(data, secs, 0x28cbb57, 1, executable=True)[0]
    if control[3] != 1 or flag != 0:
        raise ValueError('unexpected selected writer controls')
    return {
        'target_sha256': SHA256,
        'coordinate_system': 'ELF link-time virtual address; file offsets refer to the target ELF',
        'functions': functions, 'windows': windows, 'edges': edges, 'branches': branches,
        'fields': fields, 'field_layout': layout, 'text_fields': text_fields, 'binary_labels': labels, 'text_syntax': syntax, 'discriminants': discriminants, 'source_layout': source_layout, 'arithmetic': arithmetic,
        'record_layout': {'input_stride': input_stride, 'output_stride': stride,
                          'zero_flag_tag': tag_one, 'zero_flag_source_offset': source_offset,
                          'zero_flag_defined_copy': small_copy,
                          'zero_flag_other_stored_bytes': output_copy - small_copy,
                          'nonzero_flag_tag': 0, 'nonzero_flag_defined_copy': full_copy,
                          'serializer_control_word_bytes': control.hex(),
                          'serializer_following_byte': flag},
        'counts': {'owned_fde_extents': len(functions), 'boundary_windows': len(BOUNDARY_WINDOWS),
                   'owned_windows': len(OWNED_WINDOWS), 'direct_transfers': len(edges),
                   'conditional_branches': len(branches), 'order_fields': count,
                   'text_order_fields': len(text_fields), 'field_operand_rows': len(layout),
                   'binary_labels': len(labels), 'text_literal_stores': len(syntax)},
    }


def write_tsv(path, rows, columns):
    with path.open('w', encoding='utf-8', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, delimiter='\t', lineterminator='\n', extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def produce(out, data):
    result = analyze(data)
    out.mkdir(parents=True, exist_ok=True)
    for filename, key, columns in (
        ('functions.tsv', 'functions', ('start', 'end_exclusive', 'size', 'file_offset', 'section', 'fde', 'cie', 'lsda', 'code_sha256', 'role')),
        ('extents.tsv', 'functions', ('start', 'end_exclusive', 'code_sha256', 'code_bytes')),
        ('windows.tsv', 'windows', ('name', 'boundary_only', 'va', 'end_exclusive', 'file_offset', 'section', 'bytes', 'sha256')),
        ('edges.tsv', 'edges', ('label', 'site', 'file_offset', 'bytes', 'target')),
        ('branches.tsv', 'branches', ('label', 'site', 'file_offset', 'bytes', 'condition', 'taken_target', 'fallthrough')),
        ('fields.tsv', 'fields', ('ordinal', 'name', 'name_va', 'name_length', 'lea_va', 'lea_bytes', 'length_va', 'value_setup_va', 'call_va', 'call_bytes', 'helper_va')),
        ('field-layout.tsv', 'field_layout', ('field', 'instruction_va', 'bytes', 'order_offset', 'access')),
        ('text-fields.tsv', 'text_fields', ('ordinal', 'name', 'name_va', 'name_length', 'lea_va', 'lea_bytes', 'length_va', 'call_va', 'call_bytes', 'helper_va')),
    ):
        write_tsv(out / filename, result[key], columns)
    summary = {k: result[k] for k in ('target_sha256', 'coordinate_system', 'counts', 'record_layout', 'binary_labels', 'text_syntax', 'discriminants', 'source_layout', 'arithmetic')}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        produce(args.out, TARGET.read_bytes())
    except (OSError, ValueError, struct.error) as error:
        print(f'abci_state_output94: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
