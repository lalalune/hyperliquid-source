#!/usr/bin/env python3
"""RE-017: reproduce the conditional node 94 snapshot and status handoff.

This is static parsing only. The capture is never executed. Selected transfer
sites are byte-pattern checked; no external instruction decoder is invoked.
"""
import argparse
import csv
import hashlib
import io
import json
import mmap
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/94/hl-node'
EXPECTED_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# FDE bounds are checked against both shared readers; hashes bind whole extents.
FUNCTIONS = [
    ('path_factory', 0x37ead90, 0x37eaf66, '490377336dfa44a03d93a3ba7f8554e2a0f298ba32e46663f3d288e8ff153907'),
    ('poll_table_thunk', 0x22a4270, 0x22a4275, '7dfc11430af259efa613f2881948009c8f1aad3fad5b7be445fd181e750193c4'),
    ('read_table_thunk', 0x229f8f0, 0x229f8f5, '330ebdaaf9c5cf11aa9989f047c83923b154e30c983b57b745545207861bbf75'),
    ('scheduler', 0x1d964d0, 0x1d96878, '362592f095693e5019c402e9a542ea6626155ee86c687fde7f1eb77e9a8b1ad1'),
    ('poll_bridge', 0x2016670, 0x201685f, 'e82d57e02b7fd23db451dd648c71c7031339313ef16590f195e57b685f2170e3'),
    ('slot_replace', 0x201ea60, 0x201eb59, '453132b49eac6b6578f2edfc8b04be77d6c26e464a7b31a56354a58a49b251a2'),
    ('slot_drop', 0x1faf4f0, 0x1faf5c1, '5cbb63f4473a92552dd7d1aab389428ce7b8f30e6cf61448ced3869e1f82d2e8'),
    ('result_reader', 0x1d579c0, 0x1d57b30, '7ac363ecc84c52b57284c1ed2ace7b22abff869679a1a12639849bdf4a72699c'),
    ('ready_guard', 0x4f5a350, 0x4f5a5b2, 'ae97f39d44da13b38b76a50d4a08add7bf77bf484dfe2e0db23c5d6b0f881b2f'),
    ('finish', 0x1dabb20, 0x1dabe0b, '47c846eb4948036a8477587c6634ad2a005509787adecd2f43a892f12b667b09'),
    ('task_deallocate', 0x1d3bdd0, 0x1d3bea6, '8d62df9abd438166a913ca548c9413ff429c19cafeda731df5d16dfacff94309'),
    ('output_drop', 0x1d38d70, 0x1d38e40, '2a572b11cd4ae1757039a88988113c27c08efe46592e077bdde2f5a34a5e8930'),
]

# Selected evidence windows. Prior-function windows are boundary context.
WINDOWS = [
    ('host_dispatch', 0x22b47f5, 0x22b480f, 'f6eb28bd79939f3f6714b85cdfc10059b594868947e8c3f6356df17401e12bad'),
    ('host_entry_flags', 0x22b481d, 0x22b4849, '6998d799f1f2b77a697ead633334d4f757254aee781f9fe541f9d0738ad05b96'),
    ('input_height', 0x22b4bb4, 0x22b4bb8, 'c2e1c008e09d22cfda57c0cc848d81c777e06a1e3672f969bb86d91f00ae94ad'),
    ('input_height_store', 0x22b4bc5, 0x22b4bcd, 'aba65d2bdf2054c4e3c4a6e3634d8fa83a04dbcb017d0612143a71ae28578929'),
    ('source_path_format', 0x22b4c3c, 0x22b4cd2, 'c0f6b01dfacf6bb49289fe88a6335245a058d3c79a828191a7453983a9c5ad7f'),
    ('host_select_reload', 0x22b49f1, 0x22b4a24, 'e3f594d2b3e5a10666fc4d7337b0c16fa0d02a03625ba222f0380c2103f7ae41'),
    ('reload_return_gate', 0x22b4c32, 0x22b4c3c, 'f45708cf28c3a59e6e5d569868d89185840050e489c168c6e73139eea89d7756'),
    ('paths_and_replacement', 0x22b4cd2, 0x22b4d55, 'be3e2aafec6e8ed37b16571a59629a3de5d2298bf3d986f2fcac1ddcce44390e'),
    ('status_path_copy', 0x22b4d55, 0x22b4e1e, 'fa0b5fa6361fb420a9154900e873f401185666d1885bee93d0c5cdcd8b50e403'),
    ('status_task_and_await', 0x22b4e1e, 0x22b4ea4, '37ae4e3a2cf1ba6cb08ba168afcbdab63a23780bc8140b85251648fcb5146d55'),
    ('status_result_and_cleanup', 0x22b4ea4, 0x22b4f5b, '14643f9c09d00617d5d942a2306a492dd8dc79e2a20d96f466bc2b36e7e6b8a5'),
    ('reload_result_copy', 0x22b4f5b, 0x22b4f87, '984f3557289f5bb1f9f12c562c1f4c002cb4b015d69cc3569c5f1d222e7217ce'),
    ('host_result_return', 0x22b5ad1, 0x22b5af9, '52589dbb55f6cab184d8a4fcb71349b3fe4f5efb07d980c5a7b3f8bf19db6e38'),
    ('replacement_error', 0x22b5bc9, 0x22b5bf9, 'c7750636d9831f73b71b8428748fc2f72ee088ba03a93e233f20ba296fcf9665'),
    ('status_error', 0x22b5cac, 0x22b5d20, '6454a9cf880a0fb32526559708f0414805e0f343009820eee5de36640187e1f0'),
    ('task_input_and_vtable', 0x2021da5, 0x2021e0d, '713982a3cd17a54d76e4e8cddcd456c284b8bb93c816c5ae966e6297a5ecf29b'),
    ('task_initial_copy', 0x2021e0d, 0x2021e9f, '0735bf6a173c6c15a62dbf7d73baa316482c3e50ace2ce88627ba4634fd08fcc'),
    ('await_vtable_dispatch', 0x204687a, 0x20468a3, '63350b378cd4fa925c7669f931a6ef129e0a42f192cdb2521b394a41fd3fa80e'),
    ('previous_path_format', 0x37eac5b, 0x37ead0d, 'ce033a23af3c3c2b9e2931469f15c0318e206293c540861ee81e5ac62dd225ae'),
    ('date_format_boundary', 0x1454a24, 0x1454a39, 'a89a3a76af732c3ec763195806a1499c11bc2f8b93b4f7fce902789df0e2025e'),
    ('path_time_and_prior_path', 0x37ead9e, 0x37eade8, '3abe56a7960c5b31d8a66cb9f3391037d778c714bafb0605271726d5a553473b'),
    ('status_dir_setup', 0x37eade8, 0x37eae42, '96627521cd30f38c6dfe4c0b44da3828a3faaa0df77ba9f706d2d2dc54a097c9'),
    ('status_path_setup', 0x37eae42, 0x37eae8f, '0fd23b83ff2edc44c24a7ce091898451864262bdfb1b7fc070c58de179f8dc20'),
    ('path_return', 0x37eaea6, 0x37eaedd, '79b69d89558f738d9d265ffc5590393732ec8075a4fc0e6207966cf96c42e3ba'),
    ('path_time_failure', 0x37eaede, 0x37eaef7, '185dbcac7d6095269609f0975ae0031bcc89f437c17476834e3641c7883e274b'),
    ('reader_guard_and_tag', 0x1d579cb, 0x1d57a35, 'daf50d36a7e630558a0dc44da2508c4349626e90dea4d6478edfffe9c2d84937'),
    ('reader_old_output', 0x1d57a41, 0x1d57aa3, 'f3512510db7de2039ae6089880b5eae03bd14c013d1e6107d430396b930721ed'),
    ('reader_bad_tag', 0x1d57aa3, 0x1d57abe, '2cee6489c4b7f06b0ac4b20f003916f70d408ab073b9842be991a13755a2e6bf'),
    ('poll_task_dispatch', 0x1d964d9, 0x1d96589, 'd237cfd1bac408706ca58ce6d9f410d65125fe3dbd6ba8a2edb31ee4a43d42ea'),
    ('poll_completion_record', 0x1d9666c, 0x1d966be, 'd565133596993138ce2440757e2ea8e8db9a5872099509fe3b77fa4643908bf8'),
    ('bridge_state_take', 0x201667e, 0x201672e, 'a20376c7a352ae3b42c82d7d9c75e05294a55276a62aff389c0d76ae2d841c32'),
    ('bridge_result', 0x201672e, 0x201674a, '7c8cf98207ce40fcb7394b50397c0eef964f28e6d04cba44b2381cd9a3d8f0e5'),
    ('bridge_return', 0x201679c, 0x20167f0, '74a5fe36d7de54819290fdde5950f42a000d27dcd63999e1949662af2cea87cd'),
    ('replace_payload', 0x201eac1, 0x201eae3, 'a5491672c67a5e31b853a16db190646ce8ad230f6c59eb3eca9769bc151c91cd'),
    ('drop_state_select', 0x1faf4f5, 0x1faf58c, 'd0e345acd50c0952e87c329a7e06a794f3a8141877422d722588e2a3869e73f9'),
    ('finish_state', 0x1dabb2c, 0x1dabb6a, 'b04876ee337574097d543edcd093db996c4853bd7c8ecd228bc9e8dd9bc803e1'),
    ('finish_release', 0x1dabbfe, 0x1dabc28, '6290f2b907dcf2bcb9610092e96ddc61c67c2d7fcbc85b1b25ec90dea9d70d91'),
    ('guard_fast', 0x4f5a359, 0x4f5a368, 'a41a329eebe8b7c4815297cebf3b961814582c9066d6c447218a8779cf480aca'),
    ('guard_return', 0x4f5a4b6, 0x4f5a4c2, '126a34e107d25fe63f85a2ef443a98c19f4310ec03a8b41ce8e52fd82fcc490f'),
    ('deallocate_and_drop', 0x1d3bdd4, 0x1d3be3c, '3282cd2e19683406a00a8be9533e412bd28947c137e118b2274298aeaf942498'),
    ('drop_slot_by_tag', 0x1d38d75, 0x1d38e0b, '970997c8421eedf7fd563eb89d0e97a55149546dcc1956878f9a367f23cacbfa'),
]

# Fixed instruction sites, bytes and expected destinations.
BRANCHES = [
    (0x22b4843, '0f84a8010000', 0x22b49f1),
    (0x22b4a03, '0f85a6010000', 0x22b4baf),
    (0x22b4a11, '0f8478010000', 0x22b4b8f),
    (0x22b4b9b, '0f82ef120000', 0x22b5e90),
    (0x22b4c36, '0f841f030000', 0x22b4f5b),
    (0x22b4d4f, '0f85740e0000', 0x22b5bc9),
    (0x22b4d89, '0f884ffcffff', 0x22b49de),
    (0x22b4da2, '0f84b1100000', 0x22b5e59),
    (0x22b4e87, '741b', 0x22b4ea4),
    (0x22b4ee8, '0f85be0d0000', 0x22b5cac),
    (0x22b4f01, '0f85e40d0000', 0x22b5ceb),
    (0x22b4f11, '740f', 0x22b4f22),
    (0x22b4f2f, '740f', 0x22b4f40),
    (0x22b4f4a, '740f', 0x22b4f5b),
    (0x37eadd0, '0f8408010000', 0x37eaede),
    (0x37eadf5, '0f85fc000000', 0x37eaef7),
    (0x37eae97, '740d', 0x37eaea6),
    (0x37eaf33, '7412', 0x37eaf47),
    (0x1d9650b, '0f84d6010000', 0x1d966e7),
    (0x1d96513, '74db', 0x1d964f0),
    (0x1d96519, '0f86e1010000', 0x1d96700),
    (0x1d96532, '75d5', 0x1d96509),
    (0x1d96583, '0f840c010000', 0x1d96695),
    (0x1d965a2, '0f8471010000', 0x1d96719),
    (0x1d965aa, '7534', 0x1d965e0),
    (0x1d965b5, '7549', 0x1d96600),
    (0x1d965bb, '0f863f010000', 0x1d96700),
    (0x1d9662f, '0f856bffffff', 0x1d965a0),
    (0x1d96603, '0f8829010000', 0x1d96732),
    (0x1dabb3c, '75f2', 0x1dabb30),
    (0x1dabb40, '0f84ec000000', 0x1dabc32),
    (0x1dabb48, '0f85fd000000', 0x1dabc4b),
    (0x1dabb50, '7518', 0x1dabb6a),
    (0x1dabb6c, '745c', 0x1dabbca),
    (0x1dabba0, '0f841c010000', 0x1dabcc2),
    (0x1dabba8, '0f8429010000', 0x1dabcd7),
    (0x1dabbb0, '7518', 0x1dabbca),
    (0x2016682, '7530', 0x20166b4),
    (0x20166a6, '743a', 0x20166e2),
    (0x20166ab, '7520', 0x20166cd),
    (0x201670b, '7051', 0x201675e),
    (0x2016717, '7505', 0x201671e),
    (0x2016736, '740e', 0x2016746),
    (0x201ea92, '7421', 0x201eab5),
    (0x201ea97, '7505', 0x201ea9e),
    (0x1faf4f9, '7459', 0x1faf554),
    (0x1faf4fe, '0f8582000000', 0x1faf586),
    (0x1faf509, '7468', 0x1faf573),
    (0x1faf512, '7472', 0x1faf586),
    (0x1faf55e, '7026', 0x1faf586),
    (0x1faf560, '7324', 0x1faf586),
    (0x1d579dd, '7456', 0x1d57a35),
    (0x1d57a00, '0f859d000000', 0x1d57aa3),
    (0x1d57a1b, '7424', 0x1d57a41),
    (0x1d57a4a, '7445', 0x1d57a91),
    (0x1d57a4f, '74cc', 0x1d57a1d),
    (0x4f5a362, '0f854e010000', 0x4f5a4b6),
    (0x1d3bdde, '7410', 0x1d3bdf0),
    (0x1d3bde4, '750a', 0x1d3bdf0),
    (0x1d3be00, '7407', 0x1d3be09),
    (0x1d3be10, '7410', 0x1d3be22),
    (0x1d3be16, '750a', 0x1d3be22),
    (0x1d38d79, '7459', 0x1d38dd4),
    (0x1d38d7e, '0f8581000000', 0x1d38e05),
    (0x1d38d8d, '7464', 0x1d38df3),
    (0x1d38d92, '7471', 0x1d38e05),
    (0x1d38d9e, '7405', 0x1d38da5),
    (0x1d38dac, '7457', 0x1d38e05),
    (0x1d38dde, '7025', 0x1d38e05),
    (0x1d38de0, '7323', 0x1d38e05),
    (0x1d38df6, '740d', 0x1d38e05),
]

TRANSFERS = [
    ('host_path_factory', 0x22b4cde, 'ff1504ed4b03', 0x57739e8),
    ('host_replacement_boundary', 0x22b4d3c, 'ff15aeec4b03', 0x57739f0),
    ('host_task_boundary', 0x22b4e59, 'e8b2ced6ff', 0x2021d10),
    ('host_await_boundary', 0x22b4e7a, 'e87119d9ff', 0x20467f0),
    ('path_factory_prior', 0x37eade2, 'ff15e0b0f801', 0x5775ec8),
    ('path_time', 0x37eadb1, 'ff15e93af801', 0x576e8a0),
    ('path_time_convert', 0x37eadc4, 'ff157e3cf801', 0x576ea48),
    ('scheduler_thunk', 0x22a4270, 'e95b22afff', 0x1d964d0),
    ('reader_thunk', 0x229f8f0, 'e9cb80abff', 0x1d579c0),
    ('scheduler_poll', 0x1d9657c, 'e8ef002800', 0x2016670),
    ('scheduler_store', 0x1d966b9, 'e8a2832800', 0x201ea60),
    ('scheduler_finish', 0x1d966c1, 'e85a540100', 0x1dabb20),
    ('finish_drop', 0x1dabb63, 'e8f82e2700', 0x201ea60),
    ('bridge_touch', 0x2016728, 'ff153a8f7503', 0x576f668),
    ('bridge_drop', 0x20167a4, 'e8478df9ff', 0x1faf4f0),
    ('replace_drop', 0x201eacc, 'e81f0af9ff', 0x1faf4f0),
    ('reader_guard', 0x1d579d5, 'ff15356da103', 0x576e710),
    ('scheduler_drop_task', 0x1d9664c, 'e87f57faff', 0x1d3bdd0),
    ('finish_drop_task', 0x1dabc23, 'e8a801f9ff', 0x1d3bdd0),
    ('deallocate_drop_output', 0x1d3bdf4, 'e877cfffff', 0x1d38d70),
    ('deallocate_boundary', 0x1d3be36, 'ff25d421a303', 0x576e010),
    ('drop_owned_boundary', 0x1d38dce, 'ff253c52a303', 0x576e010),
    ('drop_unpolled_boundary', 0x1d38ded, 'ff251d52a303', 0x576e010),
    ('drop_reference_boundary', 0x1d3bdea, 'ff158028a303', 0x576e670),
]

REFERENCES = [
    ('host_dispatch_table', 0x22b47ff, '488d0dea1d12fe', 0x3d65f0),
    ('task_vtable', 0x2021dcf, '488d35da496703', 0x56967b0),
    ('status_descriptor', 0x37eae10, '488d05718df001', 0x56f3b88),
    ('data_template', 0x37eae28, '488d35e6eda0fc', 0x1f9c15),
    ('status_template', 0x37eae78, '488d356656a0fc', 0x1f04e5),
    ('display_owned_string', 0x37eae04, '4c8d3d958b0200', 0x38139a0),
    ('display_slice', 0x37eae1c, '488d050d1e0000', 0x37ecc30),
    ('touch_location', 0x201671e, '488d15d3bf6703', 0x56926f8),
    ('task_label', 0x22b4de0, '488d05de2812fe', 0x3d76c5),
    ('host_error_literal', 0x22b5bd1, '488d3db51c12fe', 0x3d788d),
    ('clock_error_literal', 0x37eaede, '488d3df0eda2fc', 0x219cd5),
    ('reader_error_prefix', 0x1d57aa3, '488d3dc25766fe', 0x3bd26c),
    ('source_path_template', 0x22b4cbd, '488d3545d6f3fd', 0x1f2309),
    ('source_name_descriptor', 0x22b4c8f, '488d05aa8e3e03', 0x569db40),
    ('source_extension', 0x22b4c3f, '488d05be7513fe', 0x3ec204),
    ('host_config_slot', 0x22b4c5a, '4c8b3dc79c4b03', 0x576e928),
    ('factory_config_slot', 0x37eade8, '4c8b3d393bf801', 0x576e928),
    ('factory_date_formatter_slot', 0x37eae56, '488b05033cf801', 0x576ea60),
    ('factory_word_formatter_slot', 0x37eae6c, '488b05bd3bf801', 0x576ea30),
    ('previous_directory_descriptor', 0x37eac8f, '488d05e28ef001', 0x56f3b78),
    ('previous_config_slot', 0x37eac67, '4c8b35ba3cf801', 0x576e928),
    ('previous_path_template', 0x37eacfb, '488d35e0589ffc', 0x1e05e2),
    ('previous_date_formatter_slot', 0x37eacd9, '488b05803df801', 0x576ea60),
    ('previous_word_formatter_slot', 0x37eacef, '488b053a3df801', 0x576ea30),
    ('date_format_literal', 0x1454a24, '488d057754dcfe', 0x219ea2),
    ('finish_not_running_literal', 0x1dabc32, '488d3d874ca2fe', 0x7d08c0),
    ('finish_already_complete_literal', 0x1dabc4b, '488d3d914ca2fe', 0x7d08e3),
    ('bridge_repeat_literal', 0x201675e, '488d3d27d73afe', 0x3c3e8c),
    ('bridge_bad_stage_literal', 0x20166b4, '488d3d17e23afe', 0x3c48d2),
    ('scheduler_not_notified_literal', 0x1d966e7, '488d3daea1a3fe', 0x7d089c),
    ('scheduler_no_refs_literal', 0x1d96700, '488d3dcfa2a3fe', 0x7d09d6),
    ('scheduler_not_running_literal', 0x1d96719, '488d3d59a1a3fe', 0x7d0879),
]

OPERANDS = [
    ('host_dispatch_byte_offset', 0x22b47f8, '0fb683033b0000', 3, 4),
    ('initial_mode_byte', 0x22b4824, '0fb66b01', 3, 1),
    ('enter_mode_mask', 0x22b49ff, '40f6c501', 3, 1),
    ('selected_height_load', 0x22b4bb4, '4d8b7500', 3, 1),
    ('height_in_loader_input', 0x22b4bc5, '4c89b424b8800000', 4, 4),
    ('after_load_mode_mask', 0x22b4c32, '40f6c501', 3, 1),
    ('height_for_paths', 0x22b4cd2, '498b7500', 3, 1),
    ('snapshot_length_slot', 0x22b4cec, '48898328760000', 3, 4),
    ('snapshot_triple_slot', 0x22b4cfb, '0f118318760000', 3, 4),
    ('status_triple_slot', 0x22b4d0a, '0f118330760000', 3, 4),
    ('status_length_slot', 0x22b4d19, '48898340760000', 3, 4),
    ('replace_source_ptr', 0x22b4d20, '488bbb08760000', 3, 4),
    ('replace_source_len', 0x22b4d27, '488bb310760000', 3, 4),
    ('replace_destination_ptr', 0x22b4d2e, '488b9320760000', 3, 4),
    ('replace_destination_len', 0x22b4d35, '488b8b28760000', 3, 4),
    ('status_path_ptr', 0x22b4d55, '4c8ba338760000', 3, 4),
    ('status_path_len', 0x22b4d5c, '4c8bab40760000', 3, 4),
    ('status_owned_len', 0x22b4dc8, '4c89ab58760000', 3, 4),
    ('reload_out_offset', 0x22b4f5b, '488db3183b0000', 3, 4),
    ('reload_out_copy_size', 0x22b4f6a, 'bae83a0000', 1, 4),
    ('task_initial_word', 0x2021db7, '48c7842480000000cc000000', 8, 4),
    ('bridge_tag_offset', 0x201667e, '837f1800', 2, 1),
    ('bridge_capacity_offset', 0x20166f3, '4d8b6720', 3, 1),
    ('bridge_pointer_offset', 0x201670d, '4d8b6f28', 3, 1),
    ('bridge_length_offset', 0x2016711, '498b7730', 3, 1),
    ('bridge_final_tag', 0x20167a9, '41c7042402000000', 4, 4),
    ('reader_guard_offset', 0x1d579d1, '488d7758', 3, 1),
    ('reader_slot_final_tag', 0x1d579f3, '41c7463802000000', 4, 4),
    ('reader_expected_tag', 0x1d579fb, '837c242001', 4, 1),
    ('reader_output_tag', 0x1d57a1d, '48c70300000000', 3, 4),
    ('reader_output_payload', 0x1d57a28, '0f114308', 3, 1),
    ('reader_output_last_word', 0x1d57a31, '48894318', 3, 1),
    ('scheduler_completion_tag', 0x1d966a9, 'c744242001000000', 4, 4),
    ('finish_xor_mask', 0x1dabb33, '4883f103', 3, 1),
    ('date_format_length', 0x1454a30, '48c744244006000000', 5, 4),
    ('drop_output_completed_tag', 0x1d38d7b, '83f801', 2, 1),
    ('drop_task_size', 0x1d3be22, 'be00010000', 1, 4),
    ('guard_fast_value', 0x4f5a35c, 'b101', 1, 1),
    ('guard_ready_mask', 0x4f5a35e, '41f6c502', 3, 1),
    ('finish_not_running_length', 0x1dabc40, 'be23000000', 1, 4),
    ('finish_already_complete_length', 0x1dabc59, 'be25000000', 1, 4),
    ('bridge_repeat_length', 0x201676c, 'be2d000000', 1, 4),
]

# RELATIVE slots used by this route. Prior entries are identified as boundaries.
RELOCATIONS = {
    0x56926f8: ('touch_location_path', 0x1e103e),
    0x569db40: ('source_name', 0x3d73f8),
    0x56967b0: ('task_poll_entry', 0x22a4270),
    0x56967c8: ('task_read_entry', 0x229f8f0),
    0x56f3b78: ('previous_state_directory', 0x59c134),
    0x56f3b88: ('status_directory', 0x59c148),
    0x576e710: ('reader_guard', 0x4f5a350),
    0x576e8a0: ('clock_boundary', 0x151cba0),
    0x576e928: ('config_boundary', 0x577b288),
    0x576ea30: ('integer_display_boundary', 0x1570900),
    0x576ea48: ('date_boundary', 0x151cec0),
    0x576ea60: ('date_display_boundary', 0x1454a00),
    0x576f668: ('touch_boundary', 0x144fd70),
    0x57739e8: ('host_path_factory', 0x37ead90),
    0x57739f0: ('replacement_boundary', 0x37eaa70),
    0x5775ec8: ('prior_state_path_boundary', 0x37eac50),
}
TABLES = [
    ('host_initial_dispatch', 0x3d65f0, (0x22b480f,)),
    ('scheduler_before_poll', 0x3bce8c,
     (0x1d96547, 0x1d96653, 0x1d966c6, 0x1d96649)),
    ('scheduler_after_poll', 0x3bce9c,
     (0x1d966c6, 0x1d9674b, 0x1d96649, 0x1d966d0)),
]
TEMPLATES = [
    ('source_path', 0x1f2309, 'c0122f68797065726c69717569645f646174612fc0012ec000'),
    ('data_directory', 0x1f9c15, 'c0062f646174612fc000'),
    ('status_path', 0x1f04e5, 'c0012fc0012fc000'),
    ('prior_state_path_template', 0x1e05e2, 'c0012fc0012fc0042e726d7000'),
]
LITERALS = [
    ('source_extension', 0x3ec204, b'rmp'),
    ('host_task_label', 0x3d76c5, b'async_touch'),
    ('host_failure', 0x3d788d, b'called `Result::unwrap()` on an `Err` value'),
    ('time_range_failure', 0x219cd5, b'Local time out of range for `NaiveDateTime`'),
    ('reader_failure_prefix', 0x3bd26c, b'JoinHandle polled after completion'),
    ('date_format', 0x219ea2, b'%Y%m%d'),
    ('finish_not_running', 0x7d08c0, b'assertion failed: prev.is_running()'),
    ('finish_already_complete', 0x7d08e3, b'assertion failed: !prev.is_complete()'),
    ('bridge_repeat', 0x3c3e8c, b'[internal exception] blocking task ran twice.'),
    ('bridge_bad_stage_prefix', 0x3c48d2, b'internal error: entered unreachable code: unexpected stage'),
    ('scheduler_not_notified', 0x7d089c, b'assertion failed: next.is_notified()'),
    ('scheduler_no_refs', 0x7d09d6, b'assertion failed: self.ref_count() > 0'),
    ('scheduler_not_running', 0x7d0879, b'assertion failed: curr.is_running()'),
]


def check_digest(data, expected=EXPECTED_SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise ValueError('target SHA-256 mismatch')
    return digest


def section_named(items, name):
    matches = [s for s in items if s['name'] == name]
    if len(matches) != 1 or matches[0]['type'] == 8:
        raise ValueError('missing, duplicate, or fileless section: ' + name)
    return matches[0]


def file_offset(items, address, length, file_size, executable=False):
    if not isinstance(address, int) or not isinstance(length, int) or address < 0 or length <= 0:
        raise ValueError('invalid address or length')
    if address + length > (1 << 64):
        raise ValueError('address overflow')
    candidates = [s for s in items if s['type'] != 8
                  and (not executable or s['flags'] & 4)
                  and s['address'] <= address
                  and address + length <= s['address'] + s['size']]
    if len(candidates) != 1:
        raise ValueError('address has no unique file-backed section')
    section = candidates[0]
    off = section['offset'] + address - section['address']
    if off < 0 or off + length > file_size:
        raise ValueError('mapped range is outside file')
    return off


def va_bytes(data, items, address, length, executable=False):
    off = file_offset(items, address, length, len(data), executable)
    return bytes(data[off:off + length])


def checked_window(data, items, start, end, expected_hash, executable=True):
    if end <= start:
        raise ValueError('empty window')
    raw = va_bytes(data, items, start, end - start, executable)
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError('window or extent bytes changed at ' + hex(start))
    return raw


CONDITIONS = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
              's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')


def branch_condition(raw):
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        opcode = raw[0]
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        opcode = raw[1]
    else:
        raise ValueError('unsupported conditional branch')
    return CONDITIONS[opcode & 0xf]


def decode_branch(raw, site):
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        disp = struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported conditional branch')
    return site + len(raw) + disp


def decode_transfer(raw, site):
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        kind = 'call_rel32' if raw[0] == 0xe8 else 'jump_rel32'
        disp = struct.unpack_from('<i', raw, 1)[0]
    elif len(raw) == 6 and raw[:2] in (b'\xff\x15', b'\xff\x25'):
        kind = 'call_indirect_slot' if raw[1] == 0x15 else 'jump_indirect_slot'
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported transfer')
    return kind, site + len(raw) + disp


def collect_relocations(data, rela, wanted):
    if rela['type'] != 4 or rela['size'] % 24:
        raise ValueError('unsupported relocation section')
    if rela['offset'] < 0 or rela['offset'] + rela['size'] > len(data):
        raise ValueError('relocations outside file')
    found = {}
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', data, pos)
        if target not in wanted:
            continue
        if target in found:
            raise ValueError('duplicate selected relocation')
        name, expected = wanted[target]
        if (info & 0xffffffff) != 8 or info >> 32 != 0 or addend != expected:
            raise ValueError('selected relocation changed: ' + name)
        found[target] = {'name': name, 'slot_va': hex(target),
                         'record_file_offset': hex(pos), 'type': info & 0xffffffff,
                         'symbol': info >> 32, 'addend_va': hex(addend)}
    if set(found) != set(wanted):
        raise ValueError('selected relocation missing')
    return found


def selected_extents(data, items, index, fdes):
    selected_starts = {start for _, start, _, _ in FUNCTIONS}
    idx = {}
    for entry in index:
        if entry['start'] in selected_starts:
            if entry['start'] in idx:
                raise ValueError('duplicate unwind index entry')
            idx[entry['start']] = entry
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    rows = []
    for name, start, end, digest in FUNCTIONS:
        choices = by_start.get(start, [])
        entry = idx.get(start)
        if len(choices) != 1 or entry is None:
            raise ValueError('missing or duplicate FDE for ' + name)
        fde = choices[0]
        if fde['end'] != end or fde['fde'] != entry['fde']:
            raise ValueError('FDE extent/index mismatch for ' + name)
        raw = checked_window(data, items, start, end, digest)
        rows.append({'name': name, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                     'file_offset': hex(file_offset(items, start, len(raw), len(data), True)),
                     'fde_va': hex(fde['fde']), 'cie_va': hex(fde['cie']),
                     'lsda_va': None if fde['lsda'] is None else hex(fde['lsda']),
                     'byte_count': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                     'raw_hex': raw.hex()})
    return rows


def selected_windows(data, items):
    rows = []
    for name, start, end, digest in WINDOWS:
        raw = checked_window(data, items, start, end, digest)
        boundary = not any(lo <= start < end <= hi for _, lo, hi, _ in FUNCTIONS)
        rows.append({'name': name, 'scope': 'prior-boundary' if boundary else 'selected-extent',
                     'start_va': hex(start), 'end_va_exclusive': hex(end),
                     'file_offset': hex(file_offset(items, start, len(raw), len(data), True)),
                     'bytes_hex': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest()})
    return rows


def selected_branches(data, items):
    rows = []
    for site, expected_hex, expected_target in BRANCHES:
        expected = bytes.fromhex(expected_hex)
        raw = va_bytes(data, items, site, len(expected), True)
        if raw != expected or decode_branch(raw, site) != expected_target:
            raise ValueError('branch changed at ' + hex(site))
        rows.append({'site_va': hex(site), 'file_offset': hex(file_offset(items, site, len(raw), len(data), True)),
                     'bytes_hex': raw.hex(), 'condition': branch_condition(raw),
                     'displacement': decode_branch(raw, site) - (site + len(raw)),
                     'fallthrough_va': hex(site + len(raw)),
                     'target_va': hex(decode_branch(raw, site))})
    return rows


def selected_transfers(data, items):
    rows = []
    for name, site, expected_hex, expected_target in TRANSFERS:
        expected = bytes.fromhex(expected_hex)
        raw = va_bytes(data, items, site, len(expected), True)
        kind, target = decode_transfer(raw, site)
        if raw != expected or target != expected_target:
            raise ValueError('transfer changed: ' + name)
        rows.append({'name': name, 'site_va': hex(site),
                     'file_offset': hex(file_offset(items, site, len(raw), len(data), True)),
                     'bytes_hex': raw.hex(), 'kind': kind, 'target_va': hex(target)})
    return rows


def selected_references(data, items):
    rows = []
    for name, site, expected_hex, expected_target in REFERENCES:
        raw = va_bytes(data, items, site, 7, True)
        if raw.hex() != expected_hex or raw[1] not in (0x8b, 0x8d) or raw[2] & 0xc7 != 0x05:
            raise ValueError('RIP reference changed: ' + name)
        target = site + len(raw) + struct.unpack_from('<i', raw, 3)[0]
        if target != expected_target:
            raise ValueError('RIP target changed: ' + name)
        rows.append({'name': name, 'site_va': hex(site),
                     'file_offset': hex(file_offset(items, site, len(raw), len(data), True)),
                     'bytes_hex': raw.hex(), 'target_va': hex(target)})
    return rows


def selected_operands(data, items):
    rows = []
    for name, site, expected_hex, start, width in OPERANDS:
        expected = bytes.fromhex(expected_hex)
        raw = va_bytes(data, items, site, len(expected), True)
        if raw != expected or width not in (1, 4) or start + width > len(raw):
            raise ValueError('operand instruction changed: ' + name)
        value = int.from_bytes(raw[start:start + width], 'little')
        rows.append({'name': name, 'site_va': hex(site),
                     'file_offset': hex(file_offset(items, site, len(raw), len(data), True)),
                     'bytes_hex': raw.hex(), 'operand_offset': start, 'operand_bytes': width,
                     'unsigned_value': value, 'value_hex': hex(value)})
    return rows


def selected_tables(data, items):
    rows = []
    for name, base, expected in TABLES:
        for i, target in enumerate(expected):
            entry = base + i * 4
            raw = va_bytes(data, items, entry, 4)
            displacement = struct.unpack('<i', raw)[0]
            actual = base + displacement
            if actual != target:
                raise ValueError('jump table entry changed')
            rows.append({'table': name, 'index': i, 'table_va': hex(base),
                         'entry_va': hex(entry), 'bytes_hex': raw.hex(),
                         'displacement': displacement, 'target_va': hex(actual)})
    return rows


def selected_data(data, items, relocs):
    records = {'templates': [], 'literals': [], 'descriptors': []}
    for name, va, expected in TEMPLATES:
        raw = va_bytes(data, items, va, len(bytes.fromhex(expected)))
        if raw.hex() != expected:
            raise ValueError('template changed: ' + name)
        records['templates'].append({'name': name, 'va': hex(va), 'bytes_hex': raw.hex()})
    for name, va, expected in LITERALS:
        raw = va_bytes(data, items, va, len(expected))
        if raw != expected:
            raise ValueError('literal changed: ' + name)
        records['literals'].append({'name': name, 'va': hex(va), 'length': len(raw), 'text': raw.decode('ascii')})
    for name, va, expected in [('source_name', 0x569db40, b'abci_state'),
                               ('previous_state_directory', 0x56f3b78, b'periodic_abci_states'),
                               ('status_directory', 0x56f3b88, b'periodic_abci_state_statuses')]:
        raw = va_bytes(data, items, va, 16)
        if raw[:8] != bytes(8):
            raise ValueError('unexpected pre-relocation pointer')
        length = struct.unpack_from('<Q', raw, 8)[0]
        ptr = int(relocs[va]['addend_va'], 16)
        if length != len(expected) or va_bytes(data, items, ptr, length) != expected:
            raise ValueError('descriptor changed: ' + name)
        records['descriptors'].append({'name': name, 'va': hex(va), 'target_va': hex(ptr),
                                       'length': length, 'text': expected.decode('ascii')})
    location = 0x56926f8
    raw = va_bytes(data, items, location, 24)
    zero, length, line, col = struct.unpack('<QQII', raw)
    ptr = int(relocs[location]['addend_va'], 16)
    path = va_bytes(data, items, ptr, length)
    if zero or length != 43 or (line, col) != (250, 32) or not path.endswith(b'base/src/fu.rs'):
        raise ValueError('touch Location changed')
    records['location'] = {'va': hex(location), 'file_va': hex(ptr), 'file_length': length,
                           'source_suffix': 'base/src/fu.rs', 'full_path_sha256': hashlib.sha256(path).hexdigest(),
                           'line': line, 'column': col}
    return records


def select_before_poll(word):
    """One successful compare-exchange; no concurrency or reachability claim."""
    if not isinstance(word, int) or not 0 <= word < (1 << 64):
        raise ValueError('word is not unsigned 64-bit')
    if not word & 4:
        raise ValueError('running precondition fails')
    if not word & 3:
        return ((word & ~7) + 1, (word >> 5) & 1)
    if word <= 63:
        raise ValueError('reference-count precondition fails')
    new = word - 64
    return (new, 2 + int(new < 64))


def selected_finish(word):
    """One successful finish exchange, before the later refcount decrement."""
    if not isinstance(word, int) or not 0 <= word < (1 << 64):
        raise ValueError('word is not unsigned 64-bit')
    if not word & 1 or word & 2:
        raise ValueError('finish precondition fails')
    return (word ^ 3, bool(word & 8))


def analyse(data):
    digest = check_digest(data)
    items, index = unwind_index(data)
    _, fdes = eh_frame_records(data, items)
    relocs = collect_relocations(data, section_named(items, '.rela.dyn'), RELOCATIONS)
    for va in RELOCATIONS:
        if va_bytes(data, items, va, 8) != bytes(8):
            raise ValueError('selected RELATIVE slot is not zero in file')
    functions = selected_extents(data, items, index, fdes)
    windows = selected_windows(data, items)
    branches = selected_branches(data, items)
    transfers = selected_transfers(data, items)
    tables = selected_tables(data, items)
    references = selected_references(data, items)
    operands = selected_operands(data, items)
    data_records = selected_data(data, items, relocs)
    raw_state = va_bytes(data, items, 0x2021db7, 12, True)
    if raw_state[:8] != bytes.fromhex('48c7842480000000'):
        raise ValueError('task initial-state instruction changed')
    initial_word = struct.unpack_from('<I', raw_state, 8)[0]
    copy_size = va_bytes(data, items, 0x22b4f6a, 5, True)
    if copy_size[0] != 0xba:
        raise ValueError('state-copy immediate instruction changed')
    summary = {'binary_sha256': digest, 'selected_fde_count': len(functions),
               'window_count': len(windows), 'conditional_branch_count': len(branches),
               'transfer_count': len(transfers), 'table_entry_count': len(tables),
               'rip_reference_count': len(references), 'operand_count': len(operands),
               'relative_relocation_count': len(relocs),
               'initial_task_word': hex(initial_word),
               'state_copy_bytes': struct.unpack_from('<I', copy_size, 1)[0],
               'limitations': 'Selected sites, not a complete call graph, runtime trace, or function-coverage denominator.'}
    return {'functions.json': functions, 'windows.tsv': windows, 'branches.tsv': branches,
            'transfers.tsv': transfers, 'jump-tables.tsv': tables,
            'references.tsv': references, 'operands.tsv': operands,
            'relocations.tsv': [relocs[k] for k in sorted(relocs)],
            'data.json': data_records, 'summary.json': summary}


def encode_table(rows):
    if not rows:
        raise ValueError('empty table')
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=list(rows[0]), delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def generate(out):
    with TARGET.open('rb') as source:
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
            records = analyse(data)
    out.mkdir(parents=True, exist_ok=True)
    for name in sorted(records):
        obj = records[name]
        encoded = (json.dumps(obj, indent=2, sort_keys=True) + '\n').encode() if name.endswith('.json') else encode_table(obj)
        (out / name).write_bytes(encoded)
    return records['summary.json']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    generate(args.out)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('abci_loader_snapshot94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
