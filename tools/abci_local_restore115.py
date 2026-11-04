#!/usr/bin/env python3
"""Recover one static node-115 local-state restore path; never run the capture."""
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
TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MAX64 = (1 << 64) - 1

WINDOW_SPECS = (
    ('parent_entry_context', 0x2cbbc2c, 0x2cbbcb2, 'cbe1ef090d0143aabcd0e96a8753012435d927bec8946b0cb59648ad309fc6f9', 'context'),
    ('parent_setup_context', 0x2cbbd1d, 0x2cbbdae, 'bfc08ada41033ef1029c68856fc60b6d7dc95eb533c799c178b843d5b7b8d903', 'context'),
    ('parent_child_setup_context', 0x2cbbdae, 0x2cbbdfb, '9aa3a056dadb0b37f3dd9498f90dd528cadac755e6256d3d5813aadbd91b36f1', 'context'),
    ('parent_result_context', 0x2cbc4a2, 0x2cbc535, '57ee5f1af76ad7b077ac279b69d6df1fe1caf911690ae9df4211eb5d0c4c544d', 'context'),
    ('parent_failure_context', 0x2cbee0f, 0x2cbee73, 'a434f64950885e82045608f7dee116240d555a237f68d6cb1ccb83d219e855b7', 'context'),
    ('parent_terminal_context', 0x2cbf001, 0x2cbf003, '54468dbf4fa476a33fda462613e3906e78c91c71147953fd83a2a92b2fcc2e32', 'context'),
    ('future_entry', 0x2cc115f, 0x2cc11c7, '18422fd860d18cbb04ba251486766d15b828a90332f8290c509a7302c85afe55', 'new'),
    ('input_read', 0x2cc11ef, 0x2cc1295, 'ffaa0042d0c56cfab4ce806e34ab9ad4c758211049d13986e4dcc337b0c3b8a4', 'new'),
    ('select_future_value', 0x2cc1295, 0x2cc12b0, '0ec0995e168e05aeb1edc2caddc11d02c8d0e6ef9d7b6f629b4936742a66527a', 'new'),
    ('selection_dispatch_prelude', 0x2cc12b0, 0x2cc1457, 'd7ade4ff6e7f6b7aeacc30af2432191a007c925d14781d118125d61be1197cde', 'new'),
    ('classify_future_value', 0x2cc1457, 0x2cc1489, '291473d863b2068cd74bc1bef6f1ac8dbe47d75144c4f51e0dd9f524d92a5899', 'new'),
    ('fallback_context_choice', 0x2cc1489, 0x2cc14ad, 'b538b7d8654cd45915c53f73160f02ad2c5f04ad3577bcca24ff89ad908c2eea', 'new'),
    ('classify_branch', 0x2cc151a, 0x2cc1530, '0ea81965c8c2ef7285c79df06d4b37d14c217ad78a083c8a37fd25ef83e5906c', 'new'),
    ('reader_intermediate', 0x2cc15ba, 0x2cc1649, 'b566fb310e3886082310ea031ce17174bf9fa6883554efac48e6c989e9ecaf1b', 'new'),
    ('select_saved_state', 0x2cc1649, 0x2cc16c8, '9b86dff6c41e0101f2fb58e6871b7432da3b958790f2ea66508a7460cb018a95', 'new'),
    ('consumer_and_vector', 0x2cc180e, 0x2cc195d, 'a23ef3fa428367e4e8f6ac113d277f22f96a55666293f48c3ae8468417d569c1', 'new'),
    ('materialize_and_guard', 0x2cc195d, 0x2cc1aca, '14e07fc3cb025539c3c898a23175ba225b0b1ac33ede3c758925d8f8afe396bf', 'new'),
    ('hardfork_literal_reference', 0x2cc1b63, 0x2cc1b95, '684f0651c58ab8537fda916bc24e9fadab9097d1aa8c0e7dd5c4b28e68dce0c4', 'new'),
    ('reset_and_next_decision', 0x2cc1c5a, 0x2cc1d1f, 'fb6f71327cbf58911e9624a6bea814d46ce362adbe5a843beb8012051e101b72', 'new'),
    ('time_gate', 0x2cc1d1f, 0x2cc1e4c, '5284bacab67c573eed94558eacbcd2c6207436388821b7e050a2b3925b8c86ff', 'new'),
    ('fallback_build', 0x2cc1f06, 0x2cc2137, '518cf966d44c277719985e382cf524bb8b4e778dbbd9a41675efdc9e0bcc3db7', 'new'),
    ('continuation_setup', 0x2cc22cc, 0x2cc23a1, '55cd7e8e486a04e44a9e08737f979b6edf837111f58c609a21f05efe2bb62012', 'new'),
    ('continuation_mid_a', 0x2cc23a1, 0x2cc255b, '11f9a5be1b4ea02cd8d21bbbce42329d8c647cecbf662e4f48dced987ad0b2c1', 'new'),
    ('continuation_allocation', 0x2cc255b, 0x2cc25dc, '44ecdabe5d75db001cca6f79501aec89b101133d977b1452d8a6903ec69b3e01', 'new'),
    ('continuation_mid_b', 0x2cc25dc, 0x2cc274a, 'a49d4088bb67a2f8c4a6eba9621bfc9fb388e31c8fc9ee5d9dcb1d7b6f13cb81', 'new'),
    ('continuation_tail', 0x2cc274a, 0x2cc2844, '61816646bbc75ae4a52aa4e7115dc199558a409750a1960841a1f00afad8eecc', 'new'),
    ('continuation_mid_c', 0x2cc2844, 0x2cc28c3, 'e51da5feac34ee573cc4ac3b7d14a94a2f7569cab0580717244804d6b16abb37', 'new'),
    ('result_projection', 0x2cc28c3, 0x2cc298f, 'cad942ca25eb7aa01ed5ea612a4b19fb7e7b7e4b659ffdafa6852430e1ee894d', 'new'),
    ('candidate_ordering', 0x2cc298f, 0x2cc29f4, '77ee81237aef01ebc5f5d9a8172a0d570aa064b80d4a0511ed7ef88cb212f8fb', 'new'),
    ('candidate_success_handoff', 0x2cc29f4, 0x2cc2be9, 'f120a13ee4fe26adb32cc9d85b0213c52b4fb3e6bc201af759559132143b836e', 'new'),
    ('allocation_failure', 0x2cc3c6f, 0x2cc3cae, 'c896ed6403c094476297220002f93190c06155c5ebe4e6115942c4b44b63ad0b', 'new'),
    ('fallback_input_failure', 0x2cc3cae, 0x2cc3cc0, 'bd60d4ae92d9bf39d8c5fd75df5b188ae6083eb4ee60831efa2ddc1d1ce495f1', 'new'),
    ('freeze_assertion', 0x2cc3dde, 0x2cc3e01, 'b5f7cc380b51ead894aff1d1308a4a7ae88112b58282c50a9b877583052923f6', 'new'),
    ('fallback_alloc_failure', 0x2cc3f1d, 0x2cc3f5e, '97f04e57bd604f4b66c26d1a4066570dc503a68041b73338d38bfe203d336753', 'new'),
    ('vector_failure', 0x2cc3f5e, 0x2cc3f71, 'f6647b23c18877265b62abafa1baedc39463f3ff7e33439db10ee31f9f94f19b', 'new'),
    ('pending_output', 0x2cc73ac, 0x2cc7407, '0ab29f83ca56e65159d587a3da8f4ce6e86203a89df29ec4ab8abf20e47df2a1', 'new'),
    ('fallback_shuffle', 0x2cc48a0, 0x2cc4a03, '53a247ab8c601f2416466635cbffab57d4ea0884cd9fd658ece6044400b65242', 'new'),
    ('fallback_bounds_failure', 0x2cc6501, 0x2cc652f, '16ef7b6fbd7d5f3e89aed07cf722f1a1d96a164eb509f18ec0381a1caa421803', 'new'),
    ('future_unwind', 0x2cc7eba, 0x2cc7efc, '42f6563f714b6cc46f2e256a4e8eb029f8fb15bd9dfc0d4f06c9021eedb2177a', 'new'),
    ('assert_terminal_ud2', 0x2cc7f3b, 0x2cc7f3d, '54468dbf4fa476a33fda462613e3906e78c91c71147953fd83a2a92b2fcc2e32', 'new'),
    ('future_return', 0x2cc9321, 0x2cc9348, '782f987da11ba1b74f345c782663ecc31f83d8c566df330c6bdad778d789507b', 'new'),
    ('parent_error_adapter', 0x2cbfc40, 0x2cbfd05, '7636055d24544f7ae47ae4052cc56c79604b2db23ac3e595dad54091f7be5494', 'new'),
    ('path_builder', 0x2c7d5f0, 0x2c7d751, '119706eeddefae312267272c259666a0c175d60e6a500d5ebd022e0983c851fa', 'new'),
    ('path_reader', 0x26a3610, 0x26a392c, 'fb10cf60498ed5d81b01168857e48e80c9b58f3f11a4b4d191d8d6670740293e', 'new'),
    ('binary_error_adapter', 0x26a4020, 0x26a40a7, '4d36e6ede6f857187fd383375ee4637918b565940742ea9160b5b5c1cca36307', 'new'),
    ('binary_read_error', 0x26a40c0, 0x26a4133, 'e8c9170800f46bd8de7c8072dd28e5973fe4f09703525a19bc0a0fe434e4448c', 'new'),
    ('text_read_error', 0x26a4140, 0x26a41b3, '67dbe60221694325d82ba36c4509495fd42a54e1f220e7c5ec94181ed69484ba', 'new'),
    ('json_error_adapter', 0x26a41c0, 0x26a4286, 'f5452e6db2e074a22dbcf1d3c73344fb9594de365a479b82781a5923727de6cb', 'new'),
    ('tagged_error_cleanup', 0x26ae520, 0x26ae5ee, '4f1f60d72ef4e8c4b1ef8b82bf1160cad0ed9de9fea9c54adbb6132d992b03d9', 'new'),
    ('json_tail', 0x1d74270, 0x1d743e0, '0b5c1b8ecca7dca8f95a48722a493c6a5611defe0ee43969334ca3f0ec078c73', 'new'),
    ('binary_initial_marker', 0x1b44f30, 0x1b450a9, '6a0fa6bc419ba04622428d826fe8fadae3e8d1f35d278f36b89553ba238cdd20', 'new'),
    ('binary_depth_failure', 0x1b45cc1, 0x1b45ce5, '2f7faf47660676f61b09e4d128b666cefdeb587be0fd37758cacf4a7adb9cdba', 'new'),
    ('path_factory', 0x2bacad0, 0x2bacc12, 'b040fc4b4a384060dcc577a34c4a4098c1ac6e5f2c01897061335ffad6a7224f', 'new'),
    ('intermediate_empty', 0x25d3f20, 0x25d40c7, '0fddeb2a9195298b0b4ae3e2524da9c514da188a59245c38d5bbeb6bc579e5a6', 'new'),
    ('reset_child_a', 0x2754c70, 0x2754e4c, '83f3abbff86549fe0d83529a7875e2f00097d48f92fca16e932bb4bb3d4911de', 'new'),
    ('reset_child_b', 0x2754e50, 0x2755004, '7422aac11e178fdccc8666d63c14e155fe9014bcc53fdd2d5255522343a1c294', 'new'),
)
FDE_SPECS = (
    ('parent_error_adapter', 0x2cbfc40, 0x2cbfd05, '7636055d24544f7ae47ae4052cc56c79604b2db23ac3e595dad54091f7be5494'),
    ('future', 0x2cc1120, 0x2cc971b, '3efcb009eaf0ab2e2a477d73edbf7834894109e9fdcd943460d2bce59b9a0c57'),
    ('path_builder', 0x2c7d5f0, 0x2c7d751, '119706eeddefae312267272c259666a0c175d60e6a500d5ebd022e0983c851fa'),
    ('path_reader', 0x26a3610, 0x26a392c, 'fb10cf60498ed5d81b01168857e48e80c9b58f3f11a4b4d191d8d6670740293e'),
    ('intermediate', 0x25d3f20, 0x25d4cab, 'cd11b83dc9a67867122c303d7fd4350800d82d4585281ce7553aadde1dfa1ba7'),
    ('path_factory', 0x2bacad0, 0x2bacc12, 'b040fc4b4a384060dcc577a34c4a4098c1ac6e5f2c01897061335ffad6a7224f'),
    ('reset_child_a', 0x2754c70, 0x2754e4c, '83f3abbff86549fe0d83529a7875e2f00097d48f92fca16e932bb4bb3d4911de'),
    ('reset_child_b', 0x2754e50, 0x2755004, '7422aac11e178fdccc8666d63c14e155fe9014bcc53fdd2d5255522343a1c294'),
    ('json_tail', 0x1d74270, 0x1d743e0, '0b5c1b8ecca7dca8f95a48722a493c6a5611defe0ee43969334ca3f0ec078c73'),
    ('binary_decoder', 0x1b44f30, 0x1b463a7, '2ebd9c6c7d91b200de21a2c8ff0b656f72e219e7686ff0c979a1ecbdfd9386a8'),
    ('binary_error_adapter', 0x26a4020, 0x26a40c0, '4938d6d7fd3cb198673e470d015c60374df8ba6d31d6ffd39191635e226af780'),
    ('binary_read_error', 0x26a40c0, 0x26a4133, 'e8c9170800f46bd8de7c8072dd28e5973fe4f09703525a19bc0a0fe434e4448c'),
    ('text_read_error', 0x26a4140, 0x26a41b3, '67dbe60221694325d82ba36c4509495fd42a54e1f220e7c5ec94181ed69484ba'),
    ('json_error_adapter', 0x26a41c0, 0x26a4286, 'f5452e6db2e074a22dbcf1d3c73344fb9594de365a479b82781a5923727de6cb'),
    ('tagged_error_cleanup', 0x26ae520, 0x26ae5ee, '4f1f60d72ef4e8c4b1ef8b82bf1160cad0ed9de9fea9c54adbb6132d992b03d9'),
)

# Only these instruction-aligned sites are decoded; no linear-sweep census is implied.
TRANSFER_SPECS = (
    ('parent_unexpected_result_error', 0x2cbee69, 'call', 0x2cbfc40),
    ('parent_unexpected_result_terminal', 0x2cbee6e, 'jmp', 0x2cbf001),
    ('parent_error_format', 0x2cbfc6e, 'slot', 0x64df6b8),
    ('parent_error_unwind_resume', 0x2cbfcaf, 'call', 0x63f0a50),
    ('parent_error_free_unwind_resume', 0x2cbfcc4, 'call', 0x63f0a50),
    ('parent_setup_result', 0x2cbbdb6, 'jcc', 0x2cbee0f),
    ('parent_to_child_setup', 0x2cbbdf6, 'jmp', 0x2cbc4a2),
    ('parent_to_future', 0x2cbc4b4, 'call', 0x2cc1120),
    ('parent_completed', 0x2cbc4c1, 'jcc', 0x2cbc4de),
    ('parent_pending', 0x2cbc4d9, 'jmp', 0x2cbdb10),
    ('parent_copy_result', 0x2cbc517, 'slot', 0x64df508),
    ('make_cache_path', 0x2cc1217, 'call', 0x2c7d5f0),
    ('path_check', 0x2cc1232, 'slot', 0x64e0950),
    ('path_absent', 0x2cc123a, 'jcc', 0x2cc1261),
    ('read_state', 0x2cc1249, 'call', 0x26a3610),
    ('read_accepted', 0x2cc1253, 'jcc', 0x2cc15ba),
    ('construct_auxiliary', 0x2cc15de, 'call', 0x25d3f20),
    ('auxiliary_present', 0x2cc15f8, 'jcc', 0x2cc195d),
    ('prepare_materializer_aux', 0x2cc19af, 'call', 0x2bacad0),
    ('materializer_prior_boundary', 0x2cc19ea, 'slot', 0x64e73a0),
    ('freeze_tag_other', 0x2cc1aad, 'jcc', 0x2cc1cfd),
    ('freeze_height_past', 0x2cc1abe, 'jcc', 0x2cc3dde),
    ('freeze_height_future', 0x2cc1ac4, 'jcc', 0x2cc1cfd),
    ('reset_child_a', 0x2cc1ca7, 'call', 0x2754c70),
    ('reset_child_b', 0x2cc1cc7, 'call', 0x2754e50),
    ('context_absent', 0x2cc1d19, 'jcc', 0x2cc2daf),
    ('time_range_first', 0x2cc1dc5, 'jcc', 0x2cc298f),
    ('time_range_second', 0x2cc1de5, 'jcc', 0x2cc298f),
    ('time_conversion_empty', 0x2cc1e23, 'jcc', 0x2cc298f),
    ('time_conversion_present', 0x2cc1e47, 'jmp', 0x2cc29af),
    ('ordering_first_difference', 0x2cc29d1, 'jcc', 0x2cc2be1),
    ('ordering_second_difference', 0x2cc29e1, 'jcc', 0x2cc2be1),
    ('ordering_third_less', 0x2cc29ee, 'jcc', 0x2cc2be9),
    ('ordering_result_true', 0x2cc2be3, 'jcc', 0x2cc29f4),
    ('use_materialized_state', 0x2cc2bdc, 'jmp', 0x2cc1295),
    ('reset_temporary', 0x2cc12ab, 'call', 0x2c826a0),
    ('prelude_global_branch', 0x2cc1334, 'jcc', 0x2cc3c19),
    ('prelude_empty_a', 0x2cc1440, 'jcc', 0x2cc1457),
    ('prelude_empty_b', 0x2cc1445, 'jcc', 0x2cc1457),
    ('fallback_context_mode', 0x2cc14a7, 'jcc', 0x2cc1f06),
    ('fallback_empty_elements', 0x2cc1f16, 'jcc', 0x2cc1f77),
    ('fallback_alloc_null', 0x2cc1f29, 'jcc', 0x2cc3f1d),
    ('fallback_missing_elements', 0x2cc1f5d, 'jcc', 0x2cc3cae),
    ('fallback_nonempty_subobject', 0x2cc1f8f, 'jcc', 0x2cc1f55),
    ('fallback_construct_span', 0x2cc2103, 'call', 0x2360050),
    ('fallback_to_shuffle', 0x2cc2132, 'jmp', 0x2cc48a0),
    ('fallback_tls_alternative', 0x2cc4916, 'jcc', 0x2cc4dd6),
    ('fallback_tls_overflow', 0x2cc4922, 'jcc', 0x2cc7f3b),
    ('fallback_fewer_than_two', 0x2cc493f, 'jcc', 0x2cc49d4),
    ('fallback_first_bounds', 0x2cc497e, 'jcc', 0x2cc6501),
    ('fallback_second_bounds', 0x2cc4987, 'jcc', 0x2cc6511),
    ('fallback_shuffle_repeat', 0x2cc49ca, 'jcc', 0x2cc4950),
    ('fallback_bounds_error', 0x2cc6524, 'slot', 0x64df730),
    ('fallback_bounds_terminal', 0x2cc652a, 'jmp', 0x2cc7f3b),
    ('fallback_later_failure', 0x2cc49fd, 'jcc', 0x2cc775d),
    ('fallback_alloc_error', 0x2cc3f25, 'slot', 0x64df498),
    ('fallback_alloc_error_terminal', 0x2cc3f2b, 'jmp', 0x2cc7f3b),
    ('fallback_input_error', 0x2cc3cb5, 'slot', 0x64df830),
    ('fallback_input_error_terminal', 0x2cc3cbb, 'jmp', 0x2cc7f3b),
    ('value_dispatch', 0x2cc1483, 'jcc', 0x2cc151a),
    ('value_one', 0x2cc151d, 'jcc', 0x2cc1649),
    ('state_mode_equal', 0x2cc16b9, 'jcc', 0x2cc180e),
    ('vector_sentinel', 0x2cc1910, 'jcc', 0x2cc1955),
    ('vector_empty', 0x2cc191c, 'jcc', 0x2cc1955),
    ('vector_alloc_failure', 0x2cc1935, 'jcc', 0x2cc3f5e),
    ('vector_empty_continue', 0x2cc1958, 'jmp', 0x2cc22cc),
    ('allocation_error_30', 0x2cc3c79, 'slot', 0x64df490),
    ('allocation_error_30_terminal', 0x2cc3c7f, 'jmp', 0x2cc7f3b),
    ('allocation_error_2f0', 0x2cc3c8e, 'slot', 0x64df490),
    ('allocation_error_2f0_terminal', 0x2cc3c94, 'jmp', 0x2cc7f3b),
    ('allocation_error_a8', 0x2cc3ca3, 'slot', 0x64df490),
    ('allocation_error_a8_terminal', 0x2cc3ca9, 'jmp', 0x2cc7f3b),
    ('allocation_30_failure', 0x2cc22e1, 'jcc', 0x2cc3c6f),
    ('allocation_2f0_failure', 0x2cc236a, 'jcc', 0x2cc3c84),
    ('allocation_a8_failure', 0x2cc2570, 'jcc', 0x2cc3c99),
    ('reference_count_failure_first', 0x2cc23dc, 'jcc', 0x2cc7f3b),
    ('reference_count_failure', 0x2cc27f9, 'jcc', 0x2cc7f3b),
    ('future_emit_copy', 0x2cc293a, 'slot', 0x64df508),
    ('future_emit_return', 0x2cc298a, 'jmp', 0x2cc9332),
    ('freeze_assert_call', 0x2cc3df6, 'slot', 0x64df730),
    ('freeze_assert_terminal', 0x2cc3dfc, 'jmp', 0x2cc7f3b),
    ('future_pending_return', 0x2cc7402, 'jmp', 0x2cc9332),
    ('future_unwind_drop', 0x2cc7ed2, 'call', 0x2ca6e30),
    ('cache_key_length', 0x2c7d612, 'jcc', 0x2c7d68a),
    ('reader_path_failure', 0x26a364a, 'jcc', 0x26a3659),
    ('reader_component_tag', 0x26a36fc, 'jcc', 0x26a379f),
    ('reader_double_dot', 0x26a3717, 'jcc', 0x26a379f),
    ('reader_suffix_compare', 0x26a375c, 'call', 0x159fca0),
    ('reader_text_fallback', 0x26a3763, 'jcc', 0x26a379f),
    ('binary_read_failure', 0x26a378a, 'jcc', 0x26a3874),
    ('binary_read_error', 0x26a3798, 'call', 0x26a40c0),
    ('text_read_failure', 0x26a37c4, 'jcc', 0x26a3808),
    ('text_read_error', 0x26a37ce, 'call', 0x26a4140),
    ('text_decode', 0x26a382e, 'call', 0x1d74270),
    ('text_decode_ok', 0x26a383a, 'jcc', 0x26a3859),
    ('text_decode_error', 0x26a3844, 'call', 0x26a41c0),
    ('binary_decode', 0x26a38aa, 'call', 0x1b44f30),
    ('binary_decode_error_branch', 0x26a38b4, 'jcc', 0x26a38c8),
    ('binary_decode_error', 0x26a38e6, 'call', 0x26a4020),
    ('json_decode', 0x1d742ba, 'call', 0x1f3d760),
    ('json_decode_failed', 0x1d742c6, 'jcc', 0x1d74327),
    ('json_tail_empty', 0x1d742d5, 'jcc', 0x1d74325),
    ('json_tail_above_20', 0x1d742fa, 'jcc', 0x1d74351),
    ('json_tail_not_whitespace', 0x1d74300, 'jcc', 0x1d74351),
    ('json_error_cleanup', 0x1d74372, 'call', 0x1d990c0),
    ('binary_marker_source', 0x1b44f92, 'jcc', 0x1b44ff9),
    ('binary_input_empty', 0x1b44f9b, 'jcc', 0x1b44fba),
    ('binary_depth_zero', 0x1b4508d, 'jcc', 0x1b46202),
    ('binary_depth_after_decrement', 0x1b4509b, 'jcc', 0x1b45cdd),
    ('adapter_tag_outside_table', 0x26a4064, 'jcc', 0x26a409f),
    ('adapter_cleanup', 0x26a407d, 'call', 0x26ae520),
    ('tagged_cleanup_entry', 0x26ae538, 'jcc', 0x26ae546),
    ('aux_formatter_failure', 0x2bacb33, 'jcc', 0x2bacba1),
    ('reset_a_missing_item', 0x2754caf, 'jcc', 0x2754e24),
    ('reset_a_second_missing_item', 0x2754d35, 'jcc', 0x2754e15),
    ('reset_a_first_failure_call', 0x2754e2b, 'slot', 0x64df830),
    ('reset_a_second_failure_call', 0x2754e1c, 'slot', 0x64df830),
    ('reset_b_failure_call', 0x2754ffe, 'slot', 0x64df830),
    ('reset_b_missing_item', 0x2754e72, 'jcc', 0x2754ff7),
)

# Displacements are extracted from these exact encodings. Values are checked against
# the interpretation documented in the packet, rather than inferred from an FDE.
OPERAND_SPECS = (
    ('fallback_tag_base', 0x2cc1279, 10, 2, 8, 0x8000000000000000),
    ('fallback_tag_increment', 0x2cc1283, 4, 3, 1, 3),
    ('fallback_context_flag', 0x2cc1491, 4, 3, 1, 0x10),
    ('fallback_context_base', 0x2cc1495, 4, 3, 1, 0x18),
    ('fallback_span_count', 0x2cc1f06, 5, 4, 1, 0x20),
    ('fallback_span_pointer', 0x2cc1f18, 5, 4, 1, 0x18),
    ('fallback_empty_pointer', 0x2cc1f77, 6, 2, 4, 1),
    ('fallback_future_count', 0x2cc2123, 7, 3, 4, 0xd0),
    ('parent_input_variant', 0x2cbbc5e, 3, 2, 1, 2),
    ('parent_child_state_store', 0x2cbbde9, 7, 2, 4, 0xb6),
    ('parent_child_state_zero', 0x2cbbde9, 7, 6, 1, 0),
    ('parent_child_base', 0x2cbc4a2, 4, 3, 1, 0x68),
    ('future_dispatch_byte', 0x2cc115f, 4, 3, 1, 0x4e),
    ('parent_pending_tag', 0x2cbc4b9, 8, 7, 1, 2),
    ('parent_result_temp', 0x2cbc502, 8, 4, 4, 0x2d50),
    ('parent_result_pointer_stack', 0x2cbc525, 8, 4, 4, 0x30d0),
    ('read_status_bit', 0x2cc1251, 2, 1, 1, 1),
    ('parsed_auxiliary_source', 0x2cc15ba, 4, 3, 1, 0x28),
    ('parsed_drop_size', 0x2cc1623, 5, 1, 4, 0x27a8),
    ('reset_source_sequence', 0x2cc1c65, 4, 3, 1, 0x18),
    ('reset_source_height', 0x2cc1c69, 4, 3, 1, 0x28),
    ('reset_source_round', 0x2cc1c71, 4, 3, 1, 0x30),
    ('reset_child_a_address', 0x2cc1c9d, 7, 3, 4, 0xd88),
    ('reset_child_b_address', 0x2cc1cc0, 7, 3, 4, 0xed8),
    ('selected_state_mode', 0x2cc168f, 8, 4, 4, 0xb9a),
    ('selected_context_mode', 0x2cc16a2, 5, 4, 1, 0x10),
    ('selected_context_expected', 0x2cc16b5, 4, 3, 1, 0x5a),
    ('vector_optional_tag', 0x2cc1909, 7, 3, 4, 0x38e0),
    ('vector_length', 0x2cc1912, 7, 3, 4, 0x38f0),
    ('choice_high_bit', 0x2cc2bc4, 10, 2, 8, 0x8000000000000000),
    ('choice_high_bit_increment', 0x2cc2bce, 4, 3, 1, 1),
    ('time_range_add_first', 0x2cc1dab, 10, 2, 8, 0xffdf3b645a1cac08),
    ('time_range_limit_first', 0x2cc1db8, 10, 2, 8, 0xffbe76c8b4395810),
    ('time_range_add_second', 0x2cc1dcb, 10, 2, 8, 0xffff574000000000),
    ('time_range_limit_second', 0x2cc1dd8, 10, 2, 8, 0xfffeae7ffffeae81),
    ('alloc_error_size_30', 0x2cc3c74, 5, 1, 4, 0x30),
    ('alloc_error_size_2f0', 0x2cc3c89, 5, 1, 4, 0x2f0),
    ('alloc_error_size_a8', 0x2cc3c9e, 5, 1, 4, 0xa8),
    ('cache_key_length', 0x2c7d60d, 5, 4, 1, 10),
    ('cache_key_head', 0x2c7d617, 10, 2, 8, 0x6174735f69636261),
    ('cache_key_tail', 0x2c7d628, 7, 3, 4, 0x6574),
    ('future_saved_state', 0x2cc19f4, 7, 3, 4, 0xe0),
    ('future_owns_state', 0x2cc19fb, 8, 3, 4, 0xfd9),
    ('freeze_tag', 0x2cc1aa6, 7, 2, 4, 0x10e8),
    ('freeze_tag_expected', 0x2cc1aa6, 7, 6, 1, 1),
    ('state_height', 0x2cc1ab3, 4, 3, 1, 0x28),
    ('freeze_value', 0x2cc1ab7, 7, 3, 4, 0x10f0),
    ('reset_initial_height', 0x2cc1c6d, 4, 3, 1, 0x10),
    ('reset_incremented_word', 0x2cc1c83, 4, 3, 1, 0x18),
    ('reset_copied_word', 0x2cc1c87, 4, 3, 1, 0x20),
    ('reset_freeze_tag', 0x2cc1c8b, 11, 3, 4, 0x10e8),
    ('reset_freeze_value', 0x2cc1c8b, 11, 7, 4, 0),
    ('reset_first_round_copy', 0x2cc1c96, 7, 3, 4, 0xdf0),
    ('reset_second_round_copy', 0x2cc1cb9, 7, 3, 4, 0xef8),
    ('reset_short_a', 0x2cc1cd9, 10, 4, 4, 0x3e28),
    ('reset_short_b', 0x2cc1ce3, 10, 4, 4, 0x3ee0),
    ('reset_byte', 0x2cc1ced, 8, 3, 4, 0x39b0),
    ('reset_byte_value', 0x2cc1ced, 8, 7, 1, 2),
    ('choice_saved_pointer', 0x2cc2bbd, 7, 3, 4, 0xe0),
    ('choice_future_word', 0x2cc12a0, 4, 3, 1, 0x20),
    ('selection_load', 0x2cc1651, 4, 3, 1, 0x20),
    ('selection_stack_slot', 0x2cc16ae, 5, 4, 1, 0x20),
    ('output_prefix_length', 0x2cc292a, 5, 1, 4, 0x308),
    ('output_state_offset', 0x2cc294e, 8, 4, 4, 0x380),
    ('parent_result_copy_length', 0x2cbc512, 5, 1, 4, 0x3b8),
    ('json_whitespace_mask', 0x1d742e2, 10, 2, 8, 0x100002600),
    ('json_trailing_error', 0x1d74354, 9, 5, 4, 0x16),
    ('binary_depth_field', 0x1b45085, 5, 4, 1, 0x22),
    ('binary_depth_tag', 0x1b45cdd, 3, 2, 1, 8),
)

TABLE_SPECS = (
    ('parent_inner_context', 0x60bc24, (0x2cbbd07, 0x2cbef5c, 0x2cbef4a, 0x2cbc4a2)),
    ('future_entry', 0x60bcf8, (0x2cc1177, 0x2cc3ebe, 0x2cc3eb1, 0x2cc11c7, 0x2cc14dc)),
    ('future_inner', 0x60bd88, (0x2cc11ef, 0x2cc3ef4, 0x2cc3ecb, 0x2cc1530, 0x2cc1544)),
    ('binary_error_cleanup', 0x5f2efc, (0x26a4076, 0x26a4076, 0x26a409f, 0x26a409f, 0x26a409f, 0x26a4084, 0x26a4084)),
)

RELOC_SPECS = (
    ('cache_key_descriptor', 0x644dae0, 0x60eb53),
    ('local_state_location', 0x644de70, 0x44ac48),
    ('exchange_assert_location', 0x642d380, 0x4318d3),
    ('startup_error_location', 0x644e428, 0x438c81),
    ('state_location_prior', 0x64767a8, 0x443168),
    ('materializer_prior_boundary', 0x64e73a0, 0x3c13610),
)


# RIP-relative LEA references are decoded from complete, instruction-aligned bytes.
REFERENCE_SPECS = (
    ('cache_key_descriptor', 0x2cc1205, '488d35', 0x644dae0),
    ('local_state_location', 0x2cc123c, '488d15', 0x644de70),
    ('frozen_log', 0x2cc1b63, '488d05', 0x60edab),
    ('selected_log', 0x2cc2a86, '488d05', 0x60edd7),
    ('freeze_assertion', 0x2cc3de3, '488d3d', 0x5eadd9),
    ('freeze_assert_location', 0x2cc3dea, '488d15', 0x642d380),
    ('cache_rmp_suffix', 0x2c7d634, '488d15', 0x60eb5d),
    ('cache_json_suffix', 0x2c7d63b, '488d0d', 0x459f60),
    ('reader_rmp_suffix', 0x26a3750, '488d15', 0x5f4300),
    ('parent_error_message', 0x2cbfc5b, '488d3d', 0x432c30),
    ('parent_error_location', 0x2cbfc62, '488d15', 0x644e428),
)

LITERAL_SPECS = (
    ('parent_error_message', 0x432c30, b'\x2ferror loading gossip config for non-validator: '),
    ('cache_key', 0x60eb53, b'abci_state'),
    ('selected_suffix', 0x60eb5d, b'rmp'),
    ('reader_suffix', 0x5f4300, b'rmp'),
    ('other_suffix', 0x459f60, b'json'),
    ('frozen_log_prefix', 0x60edab, b'applying hardfork to frozen local abci_state'),
    ('selected_log_prefix', 0x60edd7, b'initializing with local abci_state'),
    ('freeze_assertion', 0x5eadd9, b'assertion failed: freeze_height >= self.locus.context.height()'),
    ('binary_error_prefix', 0x438861, b'\x10rmp_from_slice:'),
    ('read_error_prefix', 0x43dbe3, b'\x06read:'),
    ('text_read_error_prefix', 0x43aa89, b'\x10read_to_string:'),
    ('json_error_prefix', 0x434554, b'\x16serde_json::from_str:'),
)


def checked_digest(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('capture SHA-256 mismatch')


def section_named(secs, name):
    matches = [s for s in secs if s['name'] == name and s['type'] != 8]
    if len(matches) != 1:
        raise ValueError('missing, ambiguous, or non-file-backed section: ' + name)
    return matches[0]


def file_offset(data, secs, va, size, executable=False):
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
        raise ValueError('invalid virtual address or size')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address has no unique file-backed allocated section')
    s = matches[0]
    off = s['offset'] + va - s['address']
    if off < 0 or off + size > len(data):
        raise ValueError('section bytes outside input')
    return off


def bytes_at(data, secs, va, size, executable=False):
    off = file_offset(data, secs, va, size, executable)
    return data[off:off + size]


def check_windows(data, secs):
    rows = []
    for name, start, end, wanted, scope in WINDOW_SPECS:
        raw = bytes_at(data, secs, start, end - start, True)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != wanted:
            raise ValueError('instruction window changed: ' + name)
        rows.append([name, scope, hex(start), hex(end), hex(file_offset(data, secs, start, len(raw), True)),
                     len(raw), digest, raw.hex()])
    return rows


def covered(va, size):
    return any(start <= va and va + size <= end for _, start, end, _, _ in WINDOW_SPECS)


def decode_transfer(data, secs, name, va, form, expected):
    first = bytes_at(data, secs, va, 2, True)
    if form in ('call', 'jmp'):
        opcode = {'call': 0xe8, 'jmp': 0xe9}[form]
        if first[0] != opcode:
            raise ValueError('incorrect transfer opcode: ' + name)
        size, pos, width = 5, 1, 4
    elif form == 'slot':
        if first != b'\xff\x15':
            raise ValueError('incorrect indirect-call opcode: ' + name)
        size, pos, width = 6, 2, 4
    elif form == 'jcc':
        if 0x70 <= first[0] <= 0x7f:
            size, pos, width = 2, 1, 1
        elif first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
            size, pos, width = 6, 2, 4
        else:
            raise ValueError('incorrect conditional-jump opcode: ' + name)
    else:
        raise ValueError('unsupported transfer form')
    raw = bytes_at(data, secs, va, size, True)
    displacement = int.from_bytes(raw[pos:pos + width], 'little', signed=True)
    target = va + size + displacement
    if target != expected or not covered(va, size):
        raise ValueError('unexpected target or uncovered transfer: ' + name)
    return [name, hex(va), hex(file_offset(data, secs, va, size, True)), raw.hex(), form, hex(target)]


def check_transfers(data, secs):
    return [decode_transfer(data, secs, *spec) for spec in TRANSFER_SPECS]


def check_operands(data, secs):
    rows = []
    for name, va, size, pos, width, wanted in OPERAND_SPECS:
        if pos < 0 or width < 1 or pos + width > size or not covered(va, size):
            raise ValueError('invalid or uncovered operand: ' + name)
        raw = bytes_at(data, secs, va, size, True)
        actual = int.from_bytes(raw[pos:pos + width], 'little')
        if actual != wanted:
            raise ValueError('operand changed: ' + name)
        rows.append([name, hex(va), hex(file_offset(data, secs, va, size, True)), raw.hex(),
                     pos, width, hex(actual)])
    return rows


def check_tables(data, secs):
    rows = []
    for name, va, expected in TABLE_SPECS:
        raw = bytes_at(data, secs, va, 4 * len(expected))
        for i, wanted in enumerate(expected):
            cell = raw[4*i:4*i+4]
            dest = va + int.from_bytes(cell, 'little', signed=True)
            if dest != wanted:
                raise ValueError('relative dispatch entry changed: ' + name)
            rows.append([name, hex(va), i, hex(va + i * 4), hex(file_offset(data, secs, va + i * 4, 4)),
                         cell.hex(), hex(dest)])
    return rows


def check_relocations(data, secs, specs=RELOC_SPECS):
    rel = section_named(secs, '.rela.dyn')
    if rel['size'] % 24:
        raise ValueError('invalid RELA size')
    wanted = {va: (name, value) for name, va, value in specs}
    if len(wanted) != len(specs):
        raise ValueError('duplicate requested relocation')
    found = {}
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        dst, info, addend = struct.unpack_from('<QQq', data, off)
        if dst in wanted:
            if dst in found:
                raise ValueError('duplicate matching relocation')
            name, value = wanted[dst]
            if info != 8 or addend != value:
                raise ValueError('unexpected relocation: ' + name)
            if bytes_at(data, secs, dst, 8) != bytes(8):
                raise ValueError('unexpected relocated slot contents: ' + name)
            found[dst] = [name, hex(dst), hex(file_offset(data, secs, dst, 8)), hex(off),
                          hex(info), hex(addend)]
    if len(found) != len(wanted):
        raise ValueError('missing required relocation')
    return [found[va] for _, va, _ in specs]



def decode_reference(data, secs, name, va, prefix, expected):
    raw = bytes_at(data, secs, va, 7, True)
    target = va + len(raw) + int.from_bytes(raw[3:], 'little', signed=True)
    if raw[:3].hex() != prefix or target != expected or not covered(va, len(raw)):
        raise ValueError('reference changed: ' + name)
    return [name, hex(va), hex(file_offset(data, secs, va, len(raw), True)), raw.hex(), hex(target)]


def check_references(data, secs):
    return [decode_reference(data, secs, *spec) for spec in REFERENCE_SPECS]


def check_key_descriptor(data, secs):
    va = 0x644dae0
    raw = bytes_at(data, secs, va, 16)
    ptr, length = struct.unpack('<QQ', raw)
    value = bytes_at(data, secs, 0x60eb53, length)
    if ptr != 0 or length != 10 or value != b'abci_state':
        raise ValueError('cache key descriptor changed')
    return [['local_state_key', hex(va), hex(file_offset(data, secs, va, 16)), raw.hex(),
             hex(0x60eb53), length, value.hex()]]


def check_literals(data, secs):
    rows = []
    for name, va, expected in LITERAL_SPECS:
        raw = bytes_at(data, secs, va, len(expected))
        if raw != expected:
            raise ValueError('literal changed: ' + name)
        rows.append([name, hex(va), hex(file_offset(data, secs, va, len(raw))), len(raw), raw.hex()])
    return rows


def check_locations(data, secs):
    rows = []
    specs = (('local_state', 0x644de70, 0x44ac48, b'node/src/local_abci_state.rs', 32, 30),
             ('exchange_assertion', 0x642d380, 0x4318d3, b'l1/src/exchange/exchange.rs', 607, 17),
             ('parent_error', 0x644e428, 0x438c81, b'node/src/startup.rs', 355, 17),
             ('prior_state_context', 0x64767a8, 0x443168, b'l1/src/abci/state.rs', 123, 37))
    for name, va, target, path, want_line, want_col in specs:
        raw = bytes_at(data, secs, va, 24)
        ptr, length, line, col = struct.unpack('<QQII', raw)
        actual_path = bytes_at(data, secs, target, length)
        if ptr != 0 or actual_path != path or (line, col) != (want_line, want_col):
            raise ValueError('source location changed: ' + name)
        rows.append([name, hex(va), hex(file_offset(data, secs, va, 24)), raw.hex(), hex(target),
                     actual_path.decode('ascii'), length, line, col])
    return rows


def check_fdes(data, secs, table, fdes):
    by_start = {row['start']: row for row in fdes}
    indexed = {row['start']: row for row in table}
    if len(by_start) != len(fdes) or len(indexed) != len(table):
        raise ValueError('duplicate FDE start')
    rows, selected = [], []
    for name, start, end, wanted in FDE_SPECS:
        fde, index = by_start.get(start), indexed.get(start)
        if fde is None or index is None or fde['end'] != end or fde['fde'] != index['fde'] or end > index['next_index_upper_bound']:
            raise ValueError('FDE extent or index mismatch: ' + name)
        raw = bytes_at(data, secs, start, end - start, True)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != wanted:
            raise ValueError('FDE contents changed: ' + name)
        rows.append([name, hex(start), hex(end), hex(file_offset(data, secs, start, end-start, True)),
                     hex(fde['fde']), hex(fde['cie']), '' if fde['lsda'] is None else hex(fde['lsda']),
                     hex(index['next_index_upper_bound']), len(raw), digest])
        selected.append((name, fde))
    ordered = sorted(selected, key=lambda item: item[1]['start'])
    if any(a['end'] > b['start'] for (_, a), (_, b) in zip(ordered, ordered[1:])):
        raise ValueError('selected FDE ranges overlap')
    for name, start, end, _, scope in WINDOW_SPECS:
        if scope == 'new' and not any(fde['start'] <= start < end <= fde['end'] for _, fde in selected):
            raise ValueError('window outside selected FDEs: ' + name)
    return rows, selected


def check_lsdas(data, secs, selected):
    table = section_named(secs, '.gcc_except_table')
    lim = table['offset'] + table['size']
    rows = []
    for name, fde in selected:
        va = fde['lsda']
        if va is None:
            continue
        pos = file_offset(data, secs, va, 1)
        if not table['offset'] <= pos < lim or data[pos] != 0xff:
            raise ValueError('unsupported LSDA base encoding: ' + name)
        pos += 1
        if pos >= lim:
            raise ValueError('truncated LSDA')
        typ = data[pos]
        pos += 1
        if typ == 0x9b:
            _, pos = uleb(data, pos, lim)
        elif typ != 0xff:
            raise ValueError('unsupported LSDA type encoding: ' + name)
        if pos >= lim or data[pos] != 1:
            raise ValueError('unsupported LSDA call-site encoding: ' + name)
        pos += 1
        length, pos = uleb(data, pos, lim)
        end = pos + length
        if end > lim:
            raise ValueError('LSDA call-site table outside section')
        while pos < end:
            begin = pos
            start, pos = uleb(data, pos, end)
            size, pos = uleb(data, pos, end)
            landing, pos = uleb(data, pos, end)
            action, pos = uleb(data, pos, end)
            if start + size > fde['end'] - fde['start'] or (landing and fde['start'] + landing >= fde['end']):
                raise ValueError('LSDA call-site range outside FDE: ' + name)
            rows.append([name, hex(va), hex(begin), data[begin:pos].hex(),
                         hex(fde['start'] + start), hex(fde['start'] + start + size),
                         '' if not landing else hex(fde['start'] + landing), action])
    return rows



def link_unwind(transfers, lsda_rows):
    links = []
    for name, site_text, _, raw, form, target in transfers:
        if form not in ('call', 'slot'):
            continue
        site = int(site_text, 16)
        size = len(raw) // 2
        matches = [row for row in lsda_rows if int(row[4], 16) <= site
                   and site + size <= int(row[5], 16)]
        if len(matches) > 1:
            raise ValueError('ambiguous selected unwind call-site link: ' + name)
        if matches:
            fde_name, lsda_va, _, _, begin, end, landing, action = matches[0]
            links.append([name, site_text, raw, target, fde_name, lsda_va, begin, end, landing, action])
    return links


def checked_word(value, bits):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError('unsigned value outside modeled width')
    return value


def freeze_decision(tag, height, freeze):
    checked_word(tag, 64)
    checked_word(height, 64)
    checked_word(freeze, 64)
    if tag & 0xffffffff != 1:
        return 'skip_tag'
    if freeze < height:
        return 'past_assert'
    if freeze > height:
        return 'future_skip'
    return 'equal_reset'


def saturated_increment(value):
    checked_word(value, 64)
    return min(value + 1, MAX64)


def selected_suffix(key):
    if not isinstance(key, bytes):
        raise ValueError('cache key must be bytes')
    return 'rmp' if key == b'abci_state' else 'json'


def whitespace_byte(value):
    checked_word(value, 8)
    return value <= 0x20 and bool((0x100002600 >> value) & 1)


def selection_class(word):
    checked_word(word, 64)
    high = 1 << 63
    decoded = (word ^ high) if word & high else 2
    return 'context_fallback' if ((decoded - 2) & MAX64) < 2 else 'other'


def time_selection(word):
    checked_word(word, 64)
    if ((word + 0xffdf3b645a1cac08) & MAX64) <= 0xffbe76c8b4395810:
        return 'default_first'
    if ((word + 0xffff574000000000) & MAX64) < 0xfffeae7ffffeae81:
        return 'default_second'
    return 'conversion_call'


def candidate_ge(left, right):
    if len(left) != 3 or len(right) != 3:
        raise ValueError('candidate tuple must have three fields')
    for value in (*left, *right):
        checked_word(value, 32)
    signed = lambda v: v if v < 0x80000000 else v - 0x100000000
    return (signed(left[0]), left[1], left[2]) >= (signed(right[0]), right[1], right[2])


def model_cases():
    rows = [['freeze', 'tag=0;height=0;freeze=0', freeze_decision(0, 0, 0)],
            ['freeze', 'tag=1;height=5;freeze=4', freeze_decision(1, 5, 4)],
            ['freeze', 'tag=1;height=5;freeze=6', freeze_decision(1, 5, 6)],
            ['freeze', 'tag=1;height=5;freeze=5', freeze_decision(1, 5, 5)],
            ['freeze', 'tag=0x100000001;height=0;freeze=0', freeze_decision(0x100000001, 0, 0)],
            ['increment', '0xffffffffffffffff', hex(saturated_increment(MAX64))],
            ['suffix', 'abci_state', selected_suffix(b'abci_state')],
            ['suffix', 'abci_StATe', selected_suffix(b'abci_StATe')],
            ['json_tail', '0x09,0x0a,0x0d,0x20', ','.join(hex(x) for x in range(256) if whitespace_byte(x))],
            ['selection', '0x8000000000000001', selection_class(0x8000000000000001)],
            ['selection', '0x8000000000000003', selection_class(0x8000000000000003)],
            ['selection', '0x8000000000000004', selection_class(0x8000000000000004)],
            ['time_gate', '0x0', time_selection(0)],
            ['time_gate', '0x20c49ba5e353f8', time_selection(0x20c49ba5e353f8)],
            ['time_gate', '0xa8bfffffffff', time_selection(0xa8bfffffffff)],
            ['time_gate', '0xa8c000000000', time_selection(0xa8c000000000)],
            ['time_gate', '0xffff573ffffeae80', time_selection(0xffff573ffffeae80)],
            ['time_gate', '0xffff573ffffeae81', time_selection(0xffff573ffffeae81)],
            ['ordering', '0xffffffff,0,0 >= 0,0,0', str(candidate_ge((0xffffffff, 0, 0), (0, 0, 0))).lower()],
            ['ordering', '1,0xffffffff,0 >= 1,0,0', str(candidate_ge((1, 0xffffffff, 0), (1, 0, 0))).lower()],
            ['ordering', '1,2,3 >= 1,2,3', str(candidate_ge((1, 2, 3), (1, 2, 3))).lower()]]
    return rows


def check_historical(data94, data115, secs115):
    checked_digest(data94, SHA94)
    secs94, table94 = unwind_index(data94)
    _, frames94 = eh_frame_records(data94, secs94)
    indexed94 = {row['start']: row for row in table94}
    selected94 = {row['start']: row for row in frames94 if row['start'] in (0x32725d0, 0x3273810)}
    for start, sites in ((0x32725d0, (0x3272785, 0x327280f)), (0x3273810, (0x3273856, 0x3273871))):
        entry, fde = indexed94.get(start), selected94.get(start)
        if entry is None or fde is None or entry['fde'] != fde['fde'] or any(not start <= site < fde['end'] for site in sites):
            raise ValueError('historical FDE mismatch')
    old_call = bytes_at(data94, secs94, 0x3272785, 6, True)
    if old_call[:2] != bytes.fromhex('ff15'):
        raise ValueError('historical loader call form changed')
    old_slot = 0x3272785 + 6 + int.from_bytes(old_call[2:], 'little', signed=True)
    if old_slot != 0x57755a8:
        raise ValueError('historical loader call slot changed')
    check_relocations(data94, secs94, (('old_location', 0x56dfbf8, 0x1dd8eb),
                                      ('old_loader', old_slot, 0x3273810)))
    lea = bytes_at(data94, secs94, 0x3273856, 7, True)
    if lea[:3] != bytes.fromhex('488d0d') or 0x3273856 + 7 + int.from_bytes(lea[3:], 'little', signed=True) != 0x56dfbf8:
        raise ValueError('historical loader location reference changed')
    old_compare = bytes_at(data94, secs94, 0x3273871, 4, True)
    if old_compare != bytes.fromhex('4983fd02'):
        raise ValueError('historical loader tag comparison changed')
    raw = bytes_at(data94, secs94, 0x56dfbf8, 24)
    ptr, length, line, col = struct.unpack('<QQII', raw)
    if ptr or length != 49 or (line, col) != (107, 37):
        raise ValueError('historical location mismatch')
    if not bytes_at(data94, secs94, 0x1dd8eb, length).endswith(b'l1/src/abci/state.rs'):
        raise ValueError('historical location suffix mismatch')
    if bytes_at(data94, secs94, 0x3272799, 5, True) != bytes.fromhex('488d7c2468'):
        raise ValueError('historical state base mismatch')
    if bytes_at(data94, secs94, 0x327280f, 12, True) != bytes.fromhex('48c78424f80b000000000000'):
        raise ValueError('historical reset mismatch')
    if bytes_at(data115, secs115, 0x2cc1c8b, 11, True) != bytes.fromhex('49c786e810000000000000'):
        raise ValueError('target reset mismatch')
    check_locations(data115, secs115)
    old_base = bytes_at(data94, secs94, 0x3272799, 5, True)[4]
    old_disp = int.from_bytes(bytes_at(data94, secs94, 0x327280f, 12, True)[4:8], 'little')
    new_disp = int.from_bytes(bytes_at(data115, secs115, 0x2cc1c8b, 11, True)[3:7], 'little')
    if old_disp < old_base:
        raise ValueError('historical stack-relative displacement underflow')
    return (
        'release 94 sha256=' + hashlib.sha256(data94).hexdigest(),
        'release 94 location_va=' + hex(0x56dfbf8) + ' location_file_offset=' + hex(file_offset(data94, secs94, 0x56dfbf8, 24))
        + ' path_length=' + str(length) + ' line=' + str(line) + ' column=' + str(col),
        'release 94 caller_va=' + hex(0x32725d0) + ' call_va=' + hex(0x3272785)
        + ' caller_end_va=' + hex(selected94[0x32725d0]['end']) + ' call_slot=' + hex(old_slot) + ' callee_va=' + hex(0x3273810)
        + ' callee_end_va=' + hex(selected94[0x3273810]['end'])
        + ' location_reference_va=' + hex(0x3273856) + ' compare_va=' + hex(0x3273871) + ' compare_value=' + str(old_compare[3]),
        'release 94 base_lea_va=' + hex(0x3272799) + ' base_stack_offset=' + hex(old_base)
        + ' reset_va=' + hex(0x327280f) + ' reset_file_offset=' + hex(file_offset(data94, secs94, 0x327280f, 12, True))
        + ' reset_stack_offset=' + hex(old_disp) + ' reset_relative_offset=' + hex(old_disp - old_base),
        'release 115 sha256=' + hashlib.sha256(data115).hexdigest() + ' reset_va=' + hex(0x2cc1c8b)
        + ' reset_file_offset=' + hex(file_offset(data115, secs115, 0x2cc1c8b, 11, True))
        + ' reset_relative_offset=' + hex(new_disp),
    )


def tsv_bytes(header, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def analyse(data):
    checked_digest(data, SHA115)
    secs, table = unwind_index(data)
    frame = section_named(secs, '.eh_frame')
    header = section_named(secs, '.eh_frame_hdr')
    if header['address'] + 4 + struct.unpack_from('<i', data, header['offset'] + 4)[0] != frame['address']:
        raise ValueError('unwind header points outside the frame section')
    _, fdes = eh_frame_records(data, secs)
    fde_rows, selected = check_fdes(data, secs, table, fdes)
    # Authenticate two previously published relocation boundaries without claiming them.
    check_relocations(data, secs, RELOC_SPECS[4:])
    transfers = check_transfers(data, secs)
    lsda_rows = check_lsdas(data, secs, selected)
    results = {
        'windows.tsv': (['name', 'scope', 'start_va', 'end_va_exclusive', 'file_offset', 'size', 'sha256', 'bytes_hex'], check_windows(data, secs)),
        'fdes.tsv': (['name', 'start_va', 'end_va_exclusive', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'next_index_bound_va', 'size', 'sha256'], fde_rows),
        'transfers.tsv': (['name', 'site_va', 'file_offset', 'bytes_hex', 'form', 'target_va_or_slot'], transfers),
        'operands.tsv': (['name', 'instruction_va', 'file_offset', 'instruction_hex', 'operand_byte_offset', 'operand_size', 'value'], check_operands(data, secs)),
        'dispatch.tsv': (['name', 'table_va', 'index', 'cell_va', 'file_offset', 'cell_hex', 'target_va'], check_tables(data, secs)),
        'relocations.tsv': (['name', 'slot_va', 'slot_file_offset', 'rela_file_offset', 'info', 'addend'], check_relocations(data, secs, RELOC_SPECS[:4])),
        'references.tsv': (['name', 'site_va', 'file_offset', 'bytes_hex', 'target_va'], check_references(data, secs)),
        'key-descriptor.tsv': (['name', 'descriptor_va', 'file_offset', 'descriptor_hex', 'relocated_key_va', 'key_length', 'key_hex'], check_key_descriptor(data, secs)),
        'literals.tsv': (['name', 'va', 'file_offset', 'size', 'bytes_hex'], check_literals(data, secs)),
        'locations.tsv': (['name', 'va', 'file_offset', 'descriptor_hex', 'path_va', 'path', 'length', 'line', 'column'], check_locations(data, secs)),
        'unwind-sites.tsv': (['fde_name', 'lsda_va', 'entry_file_offset', 'entry_hex', 'range_start_va', 'range_end_va_exclusive', 'landing_va', 'action'], lsda_rows),
        'unwind-links.tsv': (['transfer_name', 'site_va', 'bytes_hex', 'target_va_or_slot', 'fde_name', 'lsda_va', 'range_start_va', 'range_end_va_exclusive', 'landing_va', 'action'], link_unwind(transfers, lsda_rows)),
        'model-cases.tsv': (['model', 'inputs', 'result'], model_cases()),
    }
    summary = {'artifact_sha256': SHA115, 'release': 'node-115-linux-x86-64',
               'selected_counts': {name: len(rows) for name, (_, rows) in sorted(results.items())},
               'limits': 'Selected unwind extents and byte windows only; not complete function coverage, runtime behavior, a whole loader, or equivalence.'}
    encoded = {name: tsv_bytes(header, rows) for name, (header, rows) in results.items()}
    encoded['summary.json'] = (json.dumps(summary, sort_keys=True, indent=2) + '\n').encode()
    return encoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--historical', type=Path, help='optionally authenticate and compare the original release-94 capture')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    generated = analyse(data)
    if args.historical is not None:
        for line in check_historical(args.historical.read_bytes(), data, sections(data)):
            print(line)
        print('historical comparison: validated')
    args.out.mkdir(parents=True, exist_ok=True)
    for name, contents in sorted(generated.items()):
        (args.out / name).write_bytes(contents)
    print('validated node 115; wrote ' + str(len(generated)) + ' evidence files')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print('analysis failed: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
