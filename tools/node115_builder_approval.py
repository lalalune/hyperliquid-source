#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce selected node 115 builder-approval observations from ELF bytes.

No captured program is run, and no external program or disassembler is used.
Instruction interpretation is limited to the pinned byte windows and the few
relative-transfer encodings explicitly decoded below.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Selected entries, not a function census. All ranges come from FDE records.
FUNCTIONS = (
    ('name_formatter', 0x2bd0ef0),
    ('action_decoder', 0x2b84370),
    ('decoder_container', 0x20bc850),
    ('execution_caller', 0x55f4d60),
    ('writer', 0x3c1a510),
    ('tree_remove', 0x3901f10),
    ('ring_shift', 0x456fb70),
    ('row_hash_probe', 0x3ee6280),
    ('outer_row_insert', 0x3ec8b70),
    ('percentage_adapter', 0x421e240),
    ('status_formatter', 0x46ef710),
    ('row_entry', 0x4717c50),
    ('compact_insert', 0x4549b40),
    ('tree_insert', 0x3710950),
    ('action_dispatch', 0x54a3a00),
    ('system_handler', 0x5520ca0),
    ('user_handler', 0x5533140),
    ('shared_approval_gate', 0x55f43a0),
)

# Hand-selected complete instruction windows. The hashes fail closed if a
# reviewed window changes, even in tests which deliberately bypass the digest.
WINDOWS = (
    ('container_entry', 0x20bc850, 0x20bc873, 'e871e8e5356ee6ba6e3b5e9e04b9e618ace437bfed61289b7418ea56eb264d17'),
    ('container_first_field', 0x20bcf3c, 0x20bd061, '6af9e8e2a7233a8f0676e30a48b1311ea772b9ba351c3a446906532877fa0a9b'),
    ('container_second_field', 0x20bd061, 0x20bd0e0, 'e3f1a2efac569619291d5fb224dfc9e84e2f572c53a708f95b9d8044f3f04ce8'),
    ('container_action_field', 0x20bd0e0, 0x20bd1f9, '1a4193b2fd3f7cc3ffd42688f9aaee0b1c18c5101ba3bf393c27ad518e11584f'),
    ('container_success', 0x20bd1f9, 0x20bd210, '9ad7eb3ef50650825ac3e04d5213052be80107c975522500a97c0e8a28828e30'),
    ('container_missing_field', 0x20bcfa1, 0x20bcfd8, 'a3712aab2b0eff0b4ee4c3b06aab40885b41e340d1b23f9fc0872bf812d0f6e9'),
    ('container_return', 0x20bd7bc, 0x20bd7d1, '736614d74448b8e013a6b4e1c4c4f0b9c3af2896966503007f3ffe75fb6f1208'),
    ('execution_caller_entry', 0x55f4d60, 0x55f4d8e, '4bcecd50d78d48ecd715b1051bf12d3379d3b15d1c70fb1774114ac2a2380bb4'),
    ('execution_caller_gate', 0x55f4f3f, 0x55f4f80, '14dca1f8dbeda20f5cbcfd0fc072151de8456c9c13958082a11b0b145e2c54c7'),
    ('execution_caller_decision', 0x55f508e, 0x55f50be, 'e21dfafa3e31f091e47c52031619d23e38558941eecd174cc876e3612717e715'),
    ('execution_caller_propagate', 0x55f520e, 0x55f525a, '5bd649d1ba110bbc88065101b9763ffdcd6eb412ac5861ce69217d5b8077f9bb'),
    ('execution_caller_flagged', 0x55f525a, 0x55f5290, '673426ac52e55436948fca6b2c6c6c6266fec73b0126d1a7bf252ef85da8651e'),
    ('execution_caller_error', 0x55f5182, 0x55f51fc, 'c79d6fb7a0e49aefd562307dbf30b00a9b641472bf4018810b75906c1e7ad06d'),
    ('decoder_envelope', 0x2b84381, 0x2b84445, '40e730d4b064a2b9f28465402e31ec30ed737bf6732d9007a7c173ae6eb9876d'),
    ('decoder_user', 0x2b864e7, 0x2b86561, 'b1d6e642cca0660337c3c1ae0ba6a7aa9c73b0a3ea725798139e80599b3c5613'),
    ('decoder_system', 0x2b845db, 0x2b84641, 'c074db55745d93f956d387fa9c426367011189980bf4f37bfdf5735f73d71d96'),
    ('decoder_user_failure', 0x2b86979, 0x2b86995, '783567d16e2ea63893b1b6efe6aaa8fe2584dcc5845f2d7895894d26460f0c0c'),
    ('decoder_system_success', 0x2b86701, 0x2b86709, 'f9163249fba712039288e5546c566c96dd0fc57c00d82a3ef098e64b6493a165'),
    ('decoder_box_return', 0x2b86d0c, 0x2b86e2b, '863490cd7d6d809f2778262b886f20015f96286fe18f1babf8ce89479b76ce48'),
    ('decoder_alloc_failure', 0x2b86e8b, 0x2b86e9d, '48be9d842f60604c275cdfd780e742975e8be656cb1cbb5ed6226818f2103f99'),
    ('dispatch_selector', 0x54a3a1d, 0x54a3a8c, '8580190e63979e3555e842903ab1d5c0f8029a95a14ce11ed99dee1890443b7d'),
    ('dispatch_user_arm', 0x54a4276, 0x54a4290, '564001844baeb2dfb1b278c390ff0fbabb5fb58270737ece80bf7ce2fb771cb9'),
    ('dispatch_system_arm', 0x54a3b07, 0x54a3b21, '80c2ced8a5577093b89516cbfa819eea049057a0ba155d4b8a4f4a8ced4acbb1'),
    ('name_selector', 0x2bd0ef4, 0x2bd0f16, '2cf66b9e15aa4e67eeab870b6d1a26ccc1f58f07bb0a7ba9d698011ca480cc2c'),
    ('name_user_arm', 0x2bd2f84, 0x2bd2fed, 'd5e05b91f23b5e164c7ec27ef237c2a596f5c9d69ccab5d69ac4f3441335a215'),
    ('name_system_arm', 0x2bd112b, 0x2bd1194, '7460e7fff8ab50cb8a9da62bd5b9f0ee5f7df47e604f0c0945c8ad3a36cf9e9e'),
    ('system_preflight_first', 0x55210ba, 0x5521150, 'fd885c7ea68f776d1a206f4e5406af6eb3b1567e5dd3df705a4d106933888e45'),
    ('system_preflight_second', 0x5521168, 0x55211ff, '6a3820555b9f14cc98c5f5bbe098da492e4284efcc181ae03041285f02d8ac44'),
    ('user_preflight_first', 0x553355a, 0x55335ec, '7d50e88446e3ac3e2c1da5d82d179ccba5e6a5dadd1dff48e23212bda66421f4'),
    ('user_preflight_second', 0x5533608, 0x553369f, 'f32f293829624674bedd8f94eca3874a73d22e8a9ef298e1b50ffbdd419333cc'),
    ('system_preflight_rejection', 0x55211ff, 0x5521212, '05c37820e3b39f0bc0f3d087bf6445adbc58dfd30ce3aadd39a1393a5d179c7c'),
    ('system_preflight_and_call', 0x5521212, 0x552130a, 'ea54b1efd448bdc243535b4dcb2bdaf0f209c901cace31b135580b3d8fc03e6a'),
    ('system_number_failure', 0x5521419, 0x552142a, 'ddce238a618472c6a944eaa1b746301e004a2d7f130a4aa4b94e7d0947ae4189'),
    ('user_preflight_rejection', 0x553369f, 0x55336b2, '00d9f9e69f978009b9d05152dcd95fa983f95a9f9c1d710ba394cd07ac87a37e'),
    ('user_preflight_and_length', 0x55336b2, 0x5533777, 'c4d5ea56e09b543a71f410cda2448a6f7c20710cd4f64a31f62d0b2f11403ef2'),
    ('user_parse_and_call', 0x5533896, 0x5533900, '2f2209d6795c596a1ae3826cfd6c9154993d30810f16b47f9596a3efb44f2d0f'),
    ('parser_suffix', 0x421e24e, 0x421e283, '2b03f3fa99384f45080c09c2f00795b318ccb62a8bb5a9d40cf59a942fc9d3bb'),
    ('parser_scale', 0x421e283, 0x421e2cb, '0a36604e630d7639e44d68a68a8322dad430438aef4296f60b59a82cefd67074'),
    ('parser_failure', 0x421e3ab, 0x421e3bd, 'a2638eac8bb55c8d516d062a83ff4ea1151f405f2e22bf70151f8faea194c7db'),
    ('parser_bounds', 0x421e3bd, 0x421e4dd, 'abdee794a67ab87ddba64cebe3bc4ae3912c57f7ff55e0f8b957a9835be9bd0e'),
    ('approval_gate_entry', 0x55f43b1, 0x55f43ce, 'd4b7aa21214ef5d37665b39384fcf4fdf139eb52f0664875662677e34fd5beae'),
    ('approval_builder_lookup', 0x55f43ce, 0x55f443e, '98349c24c5c067c1216ddba94af54f0ed8ecaf780776378d4876739d2e7689db'),
    ('approval_balance_threshold', 0x55f443e, 0x55f4471, '875409ab58fec83e6598a5e44fe8d34a043fc63ec98aeca6609fb615707e1467'),
    ('approval_writer_result', 0x55f4471, 0x55f4496, '9dca96f584ee3497366a0154566880e698a5b6e8bfae0d030b9bf27adee42875'),
    ('approval_missing_root', 0x55f4536, 0x55f4564, '0b68467d891260b47de4dc013d2f0d9e8a3d89cdc58b66df4280dd1f56980471'),
    ('writer_entry', 0x3c1a521, 0x3c1a5ed, '82bae50c2c3964a3420ced8e0b4a485e6e4ee8ed84d5befd53ef0974b5ceb382'),
    ('writer_decision', 0x3c1a5ed, 0x3c1a621, '0c1b0cd605b8ec5d8c5b40a155cd3b3afb81fa35a871df118ba45cc86b8593b2'),
    ('writer_zero_remove', 0x3c1a690, 0x3c1a6dd, '535807cc78910da531a2c7dbae718c5cfaca5039ed35d43bcd7a1f4aae8a4374'),
    ('writer_zero_compact_lookup', 0x3c1a751, 0x3c1a77a, 'd7b143ca48056d6d19ae51399a0df43c157ba63948e86bd444ecb3e887d0645e'),
    ('writer_compact_search', 0x3c1a8e6, 0x3c1a911, '295eb39fc086c8b410e2eab8007a08d7028abaa66146ddfbfb76f60a163256e1'),
    ('writer_insert_or_update', 0x3c1a9c3, 0x3c1aa2a, '81ba857dc7a8c0cdb4ef9e58cbe21c4b5d4cb02bec60ecf498204fd3e2cdda82'),
    ('writer_update', 0x3c1ab44, 0x3c1ab87, '70588ac8658638d16fc5ab2aadf1a8f2a62c5ac482000b547ef1d467d3be6392'),
    ('writer_tree_search', 0x3c1ac2c, 0x3c1ad02, '7731501705047bae9b26f6ddba691a6834538024e85bb080a665264aa6ed68fa'),
    ('writer_tree_insert', 0x3c1ad02, 0x3c1ad90, '06c288df3dd526109db35560b09966920200dc5fc72c05dfbaf6dbf42854b9fd'),
    ('row_entry_decision', 0x4717c50, 0x4717c66, 'ac81640d934ad1f78272ff50351c9dfe2ae595bc116f646156a0efbdabffa0ae'),
    ('row_entry_insert', 0x4717cc5, 0x4717d2c, '52fbe208a4f8eec2ea0878cf9c06a433c9c7537b916d6cd5d69034d3d60f95e0'),
    ('row_probe', 0x3ee62e9, 0x3ee638d, '5dd4c6b6c246e35bbdda7f5d83e25aeebe742001950dcbd23990d8dd4e366b16'),
    ('outer_insert_entry', 0x3ec8b70, 0x3ec8bc0, '6c03b53c760f5cb01de989bf751ab21c29ab4b9c9918e68d4a8e074542c28e24'),
    ('outer_insert_slot', 0x3ec8c93, 0x3ec8cf3, '6b0ab23838d1a7ff5b76bdd1b6345eb297e0bda04799b5780710df6c2e7a6850'),
    ('outer_insert_append', 0x3ec8cf3, 0x3ec8d81, 'cfd9ae3e8501d1fd213bb1bd6279baf939cf99b58c0db7faac8ba56c385eeb20'),
    ('outer_insert_growth', 0x3ec8dfe, 0x3ec8f11, 'df77519e3d65c66948665d11bd0e210baf5d1e9b8e61b8a54bfc386fd62d3789'),
    ('outer_insert_alloc_failure', 0x3ec8f46, 0x3ec8f58, 'bc3c89e5dc8b65691af1e92739963de612cf067918d2ca2464dffb42caddbe2f'),
    ('compact_insert', 0x4549bfa, 0x4549c25, '952f961123b1d0614f64438989356f507aaeed14ff7f55a3dc878e52a5741814'),
    ('tree_insert_empty', 0x37109c4, 0x3710a4e, 'b833acba34a7abb4c25d5698b6d5a83b3b1a149ace05e1d9235b0c19739e1d77'),
    ('tree_insert_failures', 0x3710a4e, 0x3710a77, '873bee7763e8698f3d8213f9416416d3568c7e4f7006fbc8de8f8bb98dc192d9'),
    ('tree_remove_lookup', 0x3901f1e, 0x3901fd6, 'fdff11a8dd61b035e5a43c8d1a0549fa26e569f6cc29f64154fcef121667d214'),
    ('tree_remove_success', 0x3901fd6, 0x3902072, 'b838c71c723a5e61a5c4f30342a7ebf504a3864a79172d44c1f65c496ba1fe01'),
    ('compact_remove_shift', 0x3c1ab87, 0x3c1abbe, '28bd7f375deb6b6d8ff08c9b48fd9eaeca794d976432790c7bfbcde2d745b89c'),
    ('ring_shift_and_memmove', 0x456fb70, 0x456fc3f, '3511b5a843235d8067736e3023c2d9b23f990bec00c4379bda3648f2327593fa'),
    ('status_dispatch', 0x46ef710, 0x46ef727, '35f169e3f16b6965f7680de7f5c46e6862165255cd60d1f1a901d7812b8a7c66'),
)

DIRECT_CALLS = (
    ('container_first_field', 0x20bd026, 0x211f110),
    ('container_second_field', 0x20bd0b4, 0x2125310),
    ('container_action_decoder', 0x20bd142, 0x2b84370),
    ('container_cleanup', 0x20bd201, 0x282a5e0),
    ('caller_direct_dispatch', 0x55f50b4, 0x54a3a00),
    ('caller_flagged_dispatch', 0x55f5281, 0x54a3a00),
    ('decoder_envelope', 0x2b843c5, 0x1fcfbe0),
    ('decoder_user_payload', 0x2b8650b, 0x207f3d0),
    ('decoder_system_payload', 0x2b845ff, 0x2066ab0),
    ('decoder_unwind_cleanup', 0x2b86ea8, 0x2c97a00),
    ('dispatch_user', 0x54a4286, 0x5533140),
    ('dispatch_system', 0x54a3b17, 0x5520ca0),
    ('system_gate_one', 0x552123f, 0x5551140),
    ('system_gate_two', 0x552127b, 0x5551540),
    ('system_shared_approval', 0x55212ec, 0x55f43a0),
    ('user_gate_one', 0x55336df, 0x5551140),
    ('user_gate_two', 0x553371b, 0x5551540),
    ('user_shared_approval', 0x55338e0, 0x55f43a0),
    ('builder_lookup', 0x55f4412, 0x4716be0),
    ('row_hash', 0x3c1a549, 0x4717440),
    ('row_probe', 0x3c1a59b, 0x3ee6280),
    ('row_entry', 0x3c1a5e5, 0x4717c50),
    ('tree_remove', 0x3c1a6ab, 0x3901f10),
    ('compact_lookup_remove', 0x3c1a759, 0x4553fd0),
    ('compact_lookup_upsert', 0x3c1a8ee, 0x4553fd0),
    ('compact_insert', 0x3c1aa1d, 0x4549b40),
    ('tree_insert', 0x3c1ad58, 0x3710950),
    ('row_insert', 0x4717cdb, 0x3ec8b70),
    ('tree_insert_nonempty', 0x37109ab, 0x34cc660),
    ('tree_remove_inner', 0x3902008, 0x35b5a50),
    ('compact_remove_shift', 0x3c1abaf, 0x456fb70),
    ('compact_insert_shift', 0x4549bb1, 0x456fb70),
)
DIRECT_JUMPS = (
    ('decoder_user_to_common', 0x2b8655c, 0x2b86d0c),
    ('decoder_system_to_box', 0x2b86704, 0x2b86d6b),
    ('decoder_system_error', 0x2b8463c, 0x2b86d3b),
    ('decoder_user_error', 0x2b86990, 0x2b86d0f),
    ('dispatch_user_join', 0x54a428b, 0x54a43aa),
    ('dispatch_system_join', 0x54a3b1c, 0x54a43aa),
    ('caller_direct_join', 0x55f50b9, 0x55f51fc),
    ('caller_flagged_join', 0x55f528b, 0x55f51fc),
)
INDIRECT_CALLS = (
    ('caller_preflight', 0x55f4f56, 0x64e7e98, 0x3becda0),
    ('decoder_box_allocate', 0x2b86df9, 0x64df480, 0x6355830),
    ('decoder_allocation_failure', 0x2b86e95, 0x64df490, 0x141e251),
    ('user_parse', 0x55338a2, 0x64e50c8, 0x421e240),
    ('parse_decimal', 0x421e274, 0x64e4e60, 0x43099f0),
    ('scale_decimal', 0x421e2b7, 0x64ea6a0, 0x5c457a0),
    ('normalize_decimal', 0x421e3d4, 0x64ea6a8, 0x5c448a0),
    ('balance_summary', 0x55f4450, 0x64e6d20, 0x3beb980),
    ('approval_writer', 0x55f4480, 0x64e7e90, 0x3c1a510),
    ('missing_root_panic', 0x55f455c, 0x64df6a0, 0x1680c30),
)
BRANCHES = (
    ('container_selected_sequence', 0x20bc86d, 'je'),
    ('container_first_missing', 0x20bcf8b, 'je'),
    ('container_first_present', 0x20bcf9f, 'jne'),
    ('container_first_decode_error', 0x20bd032, 'jne'),
    ('container_second_missing', 0x20bd05b, 'je'),
    ('container_second_absent', 0x20bd074, 'je'),
    ('container_second_decode_error', 0x20bd0c5, 'jne'),
    ('container_third_missing', 0x20bd0e9, 'je'),
    ('container_third_absent', 0x20bd102, 'je'),
    ('container_action_decode_error', 0x20bd14e, 'jne'),
    ('container_three_field_success', 0x20bd20a, 'je'),
    ('caller_special_result', 0x55f4f66, 'jne'),
    ('caller_special_word', 0x55f4f7a, 'jne'),
    ('caller_error_result', 0x55f5090, 'je'),
    ('caller_other_result', 0x55f5098, 'jne'),
    ('caller_flagged_path', 0x55f50a2, 'jne'),
    ('decoder_user_payload_failure', 0x2b8651f, 'jo'),
    ('decoder_system_payload_success', 0x2b84636, 'je'),
    ('decoder_user_success', 0x2b86d39, 'jne'),
    ('decoder_box_allocation_failure', 0x2b86e02, 'je'),
    ('system_first_match_not_equal', 0x5521145, 'jne'),
    ('system_second_match_equal', 0x55211d3, 'je'),
    ('system_search_exhausted', 0x55211ec, 'jb'),
    ('user_first_match_not_equal', 0x55335e5, 'jne'),
    ('user_second_match_equal', 0x5533673, 'je'),
    ('user_search_exhausted', 0x553368c, 'jb'),
    ('system_first_gate_error', 0x552124b, 'jne'),
    ('system_second_gate_error', 0x5521287, 'jne'),
    ('system_number_limit', 0x55212d1, 'jae'),
    ('system_approval_error', 0x55212f8, 'jne'),
    ('user_first_gate_error', 0x55336eb, 'jne'),
    ('user_second_gate_error', 0x5533727, 'jne'),
    ('user_below_length_limit', 0x5533759, 'jb'),
    ('user_parser_error', 0x55338b2, 'jne'),
    ('user_approval_error', 0x55338ec, 'jne'),
    ('parse_empty', 0x421e258, 'je'),
    ('parse_missing_percent', 0x421e263, 'jne'),
    ('parse_decimal_error', 0x421e281, 'jne'),
    ('parse_scale_success', 0x421e2c5, 'je'),
    ('parse_upper_bound', 0x421e4c7, 'jae'),
    ('zero_bypasses_balance', 0x55f43ba, 'je'),
    ('missing_root_panics', 0x55f43c8, 'je'),
    ('signed_balance_above', 0x55f4468, 'jg'),
    ('writer_error_propagates', 0x55f448d, 'jne'),
    ('row_probe_miss', 0x3c1a5a3, 'je'),
    ('row_entry_existing', 0x4717c60, 'je'),
    ('outer_hash_length_overflow', 0x3ec8ccc, 'je'),
    ('outer_vector_growth', 0x3ec8ced, 'je'),
    ('outer_growth_retry', 0x3ec8e4e, 'je'),
    ('outer_growth_failure', 0x3ec8ef2, 'je'),
    ('writer_zero_path', 0x3c1a5fa, 'je'),
    ('writer_count_above_limit', 0x3c1a60f, 'ja'),
    ('writer_non_sentinel', 0x3c1a61b, 'jno'),
    ('remove_non_sentinel', 0x3c1a696, 'jno'),
    ('remove_absent_compact', 0x3c1a764, 'jne'),
    ('compact_no_conversion', 0x3c1a90b, 'je'),
    ('writer_tree_sentinel', 0x3c1a9d4, 'je'),
    ('compact_existing', 0x3c1a9dc, 'je'),
    ('tree_empty', 0x3c1ac41, 'je'),
    ('tree_alloc_failure', 0x37109d5, 'je'),
    ('tree_node_full', 0x37109ff, 'jae'),
    ('tree_remove_empty', 0x3901f24, 'je'),
    ('tree_remove_equal', 0x3901fa5, 'je'),
    ('tree_remove_absent', 0x3901fbe, 'jb'),
    ('tree_remove_no_repair', 0x390201b, 'jne'),
    ('tree_remove_null_root', 0x3902023, 'je'),
    ('tree_remove_zero_height', 0x390202c, 'je'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_target(data):
    if digest(data) != SHA256:
        raise ValueError('node 115 SHA-256 mismatch')


def file_offset(secs, va, size=1, executable=False):
    if type(va) is not int or type(size) is not int or va < 0 or size < 0:
        raise ValueError('invalid address or length')
    if va + size > 1 << 64:
        raise ValueError('address range overflows')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] <= va and va + size <= s['address'] + s['size'] and
               (not executable or s['flags'] & 4)]
    if len(matches) != 1:
        raise ValueError('range lacks one file-backed section')
    sec = matches[0]
    return sec['offset'] + va - sec['address']


class Image:
    def __init__(self, data, secs):
        self.data, self.secs = data, secs

    def read(self, va, size, executable=False):
        off = file_offset(self.secs, va, size, executable)
        if off + size > len(self.data):
            raise ValueError('range extends beyond file')
        return self.data[off:off + size]

    def offset(self, va, size=1, executable=False):
        return file_offset(self.secs, va, size, executable)


def assert_window(raw, expected):
    if digest(raw) != expected:
        raise ValueError('reviewed instruction window changed')


def select_fdes(table, fdes, selected):
    index = {r['start']: r for r in table}
    if len(index) != len(table):
        raise ValueError('duplicate unwind index start')
    by_start = {}
    for row in fdes:
        by_start.setdefault(row['start'], []).append(row)
    out = []
    for name, start in selected:
        if start not in index or len(by_start.get(start, ())) != 1:
            raise ValueError('selected entry lacks one indexed FDE')
        fde = by_start[start][0]
        if index[start]['fde'] != fde['fde'] or fde['end'] <= start:
            raise ValueError('FDE and unwind index disagree')
        out.append((name, index[start], fde))
    return out


def decode_switch_header(raw, va):
    if len(raw) != 31:
        raise ValueError('truncated switch header')
    if not (raw[:2] == b'\x48\x2d' and raw[6] == 0xb9 and
            raw[11:18] == bytes.fromhex('480f43c8488d05') and
            raw[22:] == bytes.fromhex('48630c884801c1ffe1')):
        raise ValueError('unsupported switch instruction pattern')
    bias = struct.unpack_from('<I', raw, 2)[0]
    fallback = struct.unpack_from('<I', raw, 7)[0]
    table = va + 22 + struct.unpack_from('<i', raw, 18)[0]
    return bias, fallback, table


def switch_entry(image, table, index):
    # These are the only reviewed ordinals; this is not a table-size claim.
    if type(index) is not int or index not in (54, 70):
        raise ValueError('ordinal outside the selected cases')
    slot = table + index * 4
    raw = image.read(slot, 4)
    return slot, raw, table + struct.unpack('<i', raw)[0]


def rel32_target(raw, va):
    if len(raw) != 5 or raw[0] not in (0xe8, 0xe9):
        raise ValueError('unsupported relative transfer')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def indirect_slot(raw, va):
    if len(raw) != 6 or raw[:2] != b'\xff\x15':
        raise ValueError('unsupported indirect call')
    return va + 6 + struct.unpack_from('<i', raw, 2)[0]


def decode_branch(raw, va):
    conditions = {0x70: 'jo', 0x71: 'jno', 0x72: 'jb', 0x73: 'jae', 0x74: 'je',
                  0x75: 'jne', 0x77: 'ja', 0x7f: 'jg'}
    if len(raw) >= 2 and raw[0] in conditions:
        return conditions[raw[0]], va + 2 + struct.unpack_from('<b', raw, 1)[0], 2
    if len(raw) >= 6 and raw[0] == 0x0f and raw[1] - 0x10 in conditions:
        return conditions[raw[1] - 0x10], va + 6 + struct.unpack_from('<i', raw, 2)[0], 6
    raise ValueError('unsupported or truncated conditional branch')


def read_relocations(data, secs, required):
    found = {}
    for sec in secs:
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError('invalid RELA record size')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if slot in required:
                if slot in found:
                    raise ValueError('duplicate relocation')
                found[slot] = {'offset': off, 'type': info & 0xffffffff,
                               'symbol': info >> 32, 'addend': addend,
                               'raw': data[off:off + 24]}
    if set(found) != set(required):
        raise ValueError('missing relocation')
    return found


def relative_relocation(row, target):
    if row['type'] != 8 or row['symbol'] != 0 or row['addend'] != target:
        raise ValueError('not the expected RELATIVE relocation')


def dynamic_symbol_name(data, secs, symbol_index):
    tables = {s['name']: s for s in secs}
    sym, strings = tables.get('.dynsym'), tables.get('.dynstr')
    if sym is None or strings is None or sym['type'] == 8 or strings['type'] == 8:
        raise ValueError('missing file-backed dynamic symbol tables')
    if type(symbol_index) is not int or symbol_index < 0 or (symbol_index + 1) * 24 > sym['size']:
        raise ValueError('dynamic symbol index outside table')
    pos = sym['offset'] + symbol_index * 24
    name_off = struct.unpack_from('<I', data, pos)[0]
    if name_off >= strings['size']:
        raise ValueError('dynamic symbol name outside string table')
    begin = strings['offset'] + name_off
    end = data.find(b'\0', begin, strings['offset'] + strings['size'])
    if end < 0:
        raise ValueError('unterminated dynamic symbol name')
    return data[begin:end].decode('ascii')


def rip_lea_target(image, va, expected_register):
    raw = image.read(va, 7, True)
    if raw[:3] != expected_register:
        raise ValueError('unexpected RIP-relative lea')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def name_from_arm(image, arm, lea_offset, length_stack_offset):
    lea = arm + lea_offset
    ptr = rip_lea_target(image, lea, b'\x48\x8d\x05')
    inst = image.read(lea + 12, 9, True)
    if inst[:5] != bytes((0x48, 0xc7, 0x44, 0x24, length_stack_offset)):
        raise ValueError('unexpected name length instruction')
    size = struct.unpack_from('<I', inst, 5)[0]
    if size > 100:
        raise ValueError('unexpected name length')
    return lea, ptr, image.read(ptr, size).decode('ascii')


def constant(image, va, prefix, fmt):
    size = struct.calcsize(fmt)
    raw = image.read(va, len(prefix) + size, True)
    if not raw.startswith(prefix):
        raise ValueError('constant instruction changed')
    return struct.unpack_from(fmt, raw, len(prefix))[0]


def status_info(image, table, code, start, end):
    slot = table + 4 * code
    raw = image.read(slot, 4)
    arm = table + struct.unpack('<i', raw)[0]
    if not start <= arm < end:
        raise ValueError('status table target outside formatter FDE')
    prefix = image.read(arm, 11, True)
    if prefix != bytes.fromhex('488b3e488b4608488b4018'):
        raise ValueError('unexpected status formatter arm')
    lea = arm + 11
    text_va = rip_lea_target(image, lea, b'\x48\x8d\x35')
    size_inst = image.read(lea + 7, 5, True)
    if size_inst[0] != 0xba:
        raise ValueError('unexpected status text length instruction')
    size = struct.unpack_from('<I', size_inst, 1)[0]
    if size > 256:
        raise ValueError('unexpected status text length')
    return {'slot': slot, 'raw': raw, 'arm': arm, 'lea': lea,
            'text_va': text_va, 'text': image.read(text_va, size).decode('ascii')}


def system_model(c, q, has_root, balance, count, present, row_exists=True,
                 preflight='pass'):
    """Selected normal-path predicate model; it never executes node bytes."""
    if not 0 <= q < 1 << 64 or not -(1 << 63) <= balance < 1 << 63:
        raise ValueError('input outside machine integer width')
    if not 0 <= count < 1 << 64 or (present and count == 0) or (not row_exists and count != 0):
        raise ValueError('inconsistent synthetic row')
    if preflight == 'identity_equal':
        return c['identity_error'], 'identity_error', False
    if preflight != 'pass':
        return None, 'preflight_error', False
    if q >= c['system_limit']:
        return c['number_error'], 'number_error', False
    return shared_model(c, q, has_root, balance, count, present, row_exists)


def shared_model(c, q, has_root, balance, count, present, row_exists):
    if q and not has_root:
        return None, 'panic_missing_root', False
    if q and balance <= c['balance_limit']:
        return c['balance_error'], 'balance_error', False
    # This selected normal-path model assumes the outer hash-table operations
    # succeed and a missing row uses the measured spare-vector-capacity path.
    # Allocation failure, rollback and persistence are deliberately excluded.
    created = not row_exists
    if not q:
        return c['success'], 'remove' if present else 'remove_absent', created
    if count > c['count_limit']:
        return c['count_error'], 'count_error', created
    return c['success'], 'replace' if present else 'insert', created


def user_word_model(c, q, has_root, balance, count, present, row_exists=True):
    # Conditional on the earlier decimal helper yielding the given word.
    # This does not assert that any particular input text is accepted.
    if not 0 <= q < 1 << 64 or not -(1 << 63) <= balance < 1 << 63:
        raise ValueError('input outside machine integer width')
    if not 0 <= count < 1 << 64 or (present and count == 0) or (not row_exists and count != 0):
        raise ValueError('inconsistent synthetic row')
    if q >= c['parsed_word_upper_exclusive']:
        return c['percentage_error'], 'parser_bound', False
    return shared_model(c, q, has_root, balance, count, present, row_exists)


def caller_model(c, preflight_tag, mode, counter):
    # Only the selected caller continuation is represented here.
    if not (0 <= preflight_tag <= 255 and 0 <= mode <= 255 and 0 <= counter < 1 << 64):
        raise ValueError('caller model input outside machine width')
    if preflight_tag == c['caller_special_tag']:
        return 'special_or_error_unresolved', counter, None, None
    if preflight_tag != c['caller_dispatch_tag']:
        return 'propagate', counter, None, None
    if mode == c['caller_direct_mode']:
        return 'direct', counter, None, None
    return ('flagged', min(counter + 1, (1 << 64) - 1),
            c['caller_flag_set_value'], c['caller_flag_clear_value'])


def text_route(c, text):
    if len(text) >= c['length_limit']:
        return c['length_error'], 'length_error'
    if not text or text[-1] != c['suffix']:
        return c['percentage_error'], 'suffix_error'
    return None, 'delegate_decimal'


def tsv(rows):
    buf = io.StringIO(newline='')
    w = csv.writer(buf, delimiter='\t', lineterminator='\n')
    w.writerows(rows)
    return buf.getvalue().encode('utf-8')


def hx(value):
    return '' if value is None else hex(value)


def generate(data, out):
    verify_target(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    selected = select_fdes(index, fdes, FUNCTIONS)
    image = Image(data, secs)
    fde_by_role = {role: fde for role, _, fde in selected}
    function_rows = [['role', 'start_va', 'end_va_exclusive', 'file_offset',
                      'fde_va', 'cie_va', 'lsda_va', 'unwind_index',
                      'byte_count', 'body_sha256', 'body_hex']]
    for role, entry, fde in selected:
        start, end = fde['start'], fde['end']
        body = image.read(start, end - start, True)
        function_rows.append([role, hx(start), hx(end), hx(image.offset(start, len(body), True)),
                              hx(fde['fde']), hx(fde['cie']), hx(fde['lsda']),
                              entry['index'], len(body), digest(body), body.hex()])
    window_rows = [['name', 'start_va', 'end_va_exclusive', 'file_offset',
                    'owner_entry_va', 'sha256', 'raw_hex']]
    for name, start, end, expected in WINDOWS:
        owners = [f for _, _, f in selected if f['start'] <= start < end <= f['end']]
        if len(owners) != 1:
            raise ValueError('window does not have one selected FDE owner')
        raw = image.read(start, end - start, True)
        assert_window(raw, expected)
        window_rows.append([name, hx(start), hx(end), hx(image.offset(start, len(raw), True)),
                            hx(owners[0]['start']), digest(raw), raw.hex()])

    disp_va, fmt_va = 0x54a3a6d, 0x2bd0ef7
    dbias, ddefault, dtable = decode_switch_header(image.read(disp_va, 31, True), disp_va)
    fbias, fdefault, ftable = decode_switch_header(image.read(fmt_va, 31, True), fmt_va)
    if (dbias, ddefault) != (fbias, fdefault):
        raise ValueError('selected switches do not use the same bias')
    dispatch_rows = [['role', 'ordinal', 'derived_tag', 'dispatcher_table_va',
                      'dispatcher_slot_va', 'dispatcher_slot_file_offset', 'dispatcher_slot_hex',
                      'dispatcher_arm_va', 'call_va', 'call_hex', 'call_target_va',
                      'formatter_table_va', 'formatter_slot_va', 'formatter_slot_hex',
                      'formatter_arm_va', 'type_lea_va', 'type_literal_va', 'type_name',
                      'wire_lea_va', 'wire_literal_va', 'wire_name']]
    for role, ordinal, expected_handler, type_name, wire_name in (
        ('user', 54, 0x5533140, 'ApproveBuilderFee', 'approveBuilderFee'),
        ('system', 70, 0x5520ca0, 'SystemApproveBuilderFee', 'SystemApproveBuilderFeeAction'),
    ):
        ds, dr, arm = switch_entry(image, dtable, ordinal)
        fs, fr, farm = switch_entry(image, ftable, ordinal)
        df, ff = fde_by_role['action_dispatch'], fde_by_role['name_formatter']
        if not (df['start'] < arm < df['end'] and ff['start'] < farm < ff['end']):
            raise ValueError('selected switch target outside its FDE')
        if image.read(arm, 16, True) != bytes.fromhex('4983c7084889e74c89ee4c89e24c89f9'):
            raise ValueError('unexpected dispatch argument moves')
        call = arm + 16
        insn = image.read(call, 5, True)
        target = rel32_target(insn, call)
        if target != expected_handler:
            raise ValueError('unexpected selected handler')
        tl, tp, tn = name_from_arm(image, farm, 0x18, 0x18)
        wl, wp, wn = name_from_arm(image, farm, 0x42, 0x38)
        if (tn, wn) != (type_name, wire_name):
            raise ValueError('selected name literals changed')
        dispatch_rows.append([role, ordinal, hx(dbias + ordinal), hx(dtable), hx(ds),
                              hx(image.offset(ds, 4)), dr.hex(), hx(arm), hx(call),
                              insn.hex(), hx(target), hx(ftable), hx(fs), fr.hex(), hx(farm),
                              hx(tl), hx(tp), tn, hx(wl), hx(wp), wn])

    # A distinct #115 decoder copy independently ties the selected ordinal,
    # payload type name and resulting in-memory tag together.
    decoder_switch = image.read(0x2b84435, 16, True)
    if (decoder_switch[:3] != bytes.fromhex('488d0d') or
            decoder_switch[7:] != bytes.fromhex('486304814801c8ffe0')):
        raise ValueError('unexpected decoder switch instruction pattern')
    decoder_table = 0x2b84435 + 7 + struct.unpack_from('<i', decoder_switch, 3)[0]
    decoder_rows = [['role', 'ordinal', 'decoder_table_va', 'slot_va', 'slot_file_offset',
                     'slot_hex', 'arm_va', 'type_literal_va', 'type_name',
                     'payload_call_va', 'payload_call_hex', 'payload_target_va',
                     'tag_assignment_va', 'tag_assignment_hex', 'decoded_tag',
                     'tag_store_va', 'staging_offset', 'box_allocation_size',
                     'box_copy_size', 'result_marker']]
    dfde = fde_by_role['action_decoder']
    tag_store_offset = constant(image, 0x2b86d6b, bytes.fromhex('4c89a424'), '<I')
    box_alloc_size = constant(image, 0x2b86df4, b'\xbf', '<I')
    box_copy_size = constant(image, 0x2b86e13, b'\xba', '<I')
    result_marker = constant(image, 0x2b86e25, bytes.fromhex('c603'), '<B')
    if constant(image, 0x2b86e0b, bytes.fromhex('488db424'), '<I') != tag_store_offset:
        raise ValueError('box source does not begin with staged tag')
    if image.read(0x2b86e21, 4, True) != bytes.fromhex('4c897308'):
        raise ValueError('boxed action pointer is not returned at the selected offset')
    if box_alloc_size != box_copy_size or result_marker != 9:
        raise ValueError('unexpected boxed action result')
    for role, ordinal, expected_arm, expected_name, tag_site, call_site, target in (
        ('user', 54, 0x2b864e7, 'ApproveBuilderFeeAction', 0x2b86556, 0x2b8650b, 0x207f3d0),
        ('system', 70, 0x2b845db, 'SystemApproveBuilderFeeAction', 0x2b84630, 0x2b845ff, 0x2066ab0),
    ):
        slot, raw_slot, arm = switch_entry(image, decoder_table, ordinal)
        if arm != expected_arm or not dfde['start'] < arm < dfde['end']:
            raise ValueError('unexpected decoder arm')
        type_va = rip_lea_target(image, arm, b'\x48\x8d\x15')
        type_len = constant(image, arm + 25, b'\xb9', '<I')
        if type_len > 100:
            raise ValueError('unexpected decoder type length')
        type_name = image.read(type_va, type_len).decode('ascii')
        if type_name != expected_name:
            raise ValueError('unexpected decoder type name')
        tag = constant(image, tag_site, b'\x41\xbc', '<I')
        if tag != dbias + ordinal:
            raise ValueError('decoded tag does not match selected dispatch tag')
        call = image.read(call_site, 5, True)
        if rel32_target(call, call_site) != target:
            raise ValueError('unexpected payload decoder call')
        decoder_rows.append([role, ordinal, hx(decoder_table), hx(slot), hx(image.offset(slot, 4)),
                             raw_slot.hex(), hx(arm), hx(type_va), type_name, hx(call_site),
                             call.hex(), hx(target), hx(tag_site), image.read(tag_site, 6, True).hex(),
                             hx(tag), hx(0x2b86d6b), hx(tag_store_offset), box_alloc_size,
                             box_copy_size, result_marker])

    code_specs = (
        ('identity_error', 0x5521204, bytes.fromhex('66c74010')),
        ('balance_error', 0x55f446a, bytes.fromhex('66c703')),
        ('percentage_error', 0x421e251, bytes.fromhex('66bb')),
        ('count_error', 0x3c1a607, bytes.fromhex('66b9')),
        ('number_error', 0x552141e, bytes.fromhex('66c74110')),
        ('missing_root_error', 0x55f4536, bytes.fromhex('66c7442420')),
        ('length_error', 0x5533764, bytes.fromhex('66c74110')),
        ('success', 0x55f448f, bytes.fromhex('66c703')),
    )
    c = {name: constant(image, va, prefix, '<H') for name, va, prefix in code_specs}
    c['system_limit'] = constant(image, 0x55212c4, b'\x48\xb8', '<Q')
    c['length_limit'] = constant(image, 0x5533755, bytes.fromhex('4883fa'), '<B')
    c['balance_limit'] = constant(image, 0x55f4456, bytes.fromhex('48817c2420'), '<i')
    c['count_limit'] = constant(image, 0x3c1a60b, bytes.fromhex('4883f8'), '<B')
    c['suffix'] = constant(image, 0x421e25e, bytes.fromhex('807c16ff'), '<B')
    c['scale_operand'] = constant(image, 0x421e299, bytes.fromhex('48c7442418'), '<I')
    c['parsed_word_upper_exclusive'] = constant(image, 0x421e4ba, b'\x48\xb8', '<Q')
    c['node_size'] = constant(image, 0x37109c7, b'\xbf', '<I')
    c['node_entry_bound'] = constant(image, 0x37109fb, bytes.fromhex('4883f9'), '<B')
    c['tree_to_compact_below'] = constant(image, 0x3c1a6cb, bytes.fromhex('4883fb'), '<B')
    c['compact_to_tree_at_least'] = constant(image, 0x3c1a900, bytes.fromhex('4883fe'), '<B')
    c['row_map_offset'] = constant(image, 0x3c1a5ed, bytes.fromhex('4c8da8'), '<I')
    c['row_count_offset'] = constant(image, 0x3c1a600, bytes.fromhex('498b86'), '<I')
    c['compact_entry_stride'] = 1 << constant(image, 0x3c1ab6a, bytes.fromhex('48c1e0'), '<B')
    c['tree_key_bytes'] = constant(image, 0x3c1ac9e, b'\xba', '<I')
    c['outer_default_copy_bytes'] = constant(image, 0x3ec8d00, b'\xba', '<I')
    c['outer_record_copy_bytes'] = constant(image, 0x3ec8d46, b'\xba', '<I')
    c['outer_record_stride'] = 1 << constant(image, 0x3ec8d3a, bytes.fromhex('48c1e7'), '<B')
    c['outer_vector_length_offset'] = constant(image, 0x3ec8d58, bytes.fromhex('488969'), '<B')
    if c['outer_record_stride'] != c['outer_record_copy_bytes']:
        raise ValueError('outer row copy and stride disagree')
    if image.read(0x3ec8d51, 3, True) != bytes.fromhex('48ffc5'):
        raise ValueError('outer row count is not incremented')
    c['container_sequence_kind'] = constant(image, 0x20bc86a, bytes.fromhex('83fd'), '<B')
    c['container_field_count'] = constant(image, 0x20bd206, bytes.fromhex('4883fb'), '<B')
    c['caller_counter_offset'] = constant(image, 0x55f525a, bytes.fromhex('498b46'), '<B')
    c['caller_flag_offset'] = constant(image, 0x55f5270, bytes.fromhex('41c646'), '<B')
    c['caller_flag_set_value'] = constant(image, 0x55f5270, bytes.fromhex('41c64678'), '<B')
    c['caller_flag_clear_value'] = constant(image, 0x55f5286, bytes.fromhex('41c64678'), '<B')
    c['caller_special_tag'] = constant(image, 0x55f508e, b'\x3c', '<B')
    c['caller_dispatch_tag'] = constant(image, 0x55f5096, b'\x3c', '<B')
    c['caller_direct_mode'] = constant(image, 0x55f509e, bytes.fromhex('807d00'), '<B')

    # Selected sequence-container output offsets are instruction operands.
    ptr_stack = constant(image, 0x20bd154, bytes.fromhex('488b4424'), '<B')
    decoder_result_stack = constant(image, 0x20bd135, bytes.fromhex('488d7c24'), '<B')
    field_a = constant(image, 0x20bd170, bytes.fromhex('410f114424'), '<B')
    field_a_tail = constant(image, 0x20bd163, bytes.fromhex('41894c24'), '<B')
    field_b = constant(image, 0x20bd18a, bytes.fromhex('410f114424'), '<B')
    field_b_tail = constant(image, 0x20bd17d, bytes.fromhex('41894c24'), '<B')
    container_marker = constant(image, 0x20bd14c, b'\x3c', '<B')
    if (container_marker != result_marker or ptr_stack - decoder_result_stack != 8 or field_a_tail != field_a + 16 or
            field_b_tail != field_b + 16 or image.read(0x20bd190, 4, True) != bytes.fromhex('49890424')):
        raise ValueError('unexpected decoder container output layout')
    container_rows = [['component', 'site_va', 'raw_hex', 'observed_value']]
    for role, va, size, value in (
        ('sequence_kind', 0x20bc86a, 3, c['container_sequence_kind']),
        ('field_count', 0x20bd206, 4, c['container_field_count']),
        ('decoder_result_marker', 0x20bd14c, 2, container_marker),
        ('decoder_pointer_source', 0x20bd154, 5, ptr_stack - decoder_result_stack),
        ('output_pointer_store', 0x20bd190, 4, 0),
        ('first_key_start', 0x20bd170, 6, field_a),
        ('first_key_tail', 0x20bd163, 5, field_a_tail),
        ('second_key_start', 0x20bd18a, 6, field_b),
        ('second_key_tail', 0x20bd17d, 5, field_b_tail),
        ('caller_counter_offset', 0x55f525a, 4, c['caller_counter_offset']),
        ('caller_flag_offset', 0x55f5270, 5, c['caller_flag_offset']),
        ('caller_flag_reset', 0x55f5286, 5, c['caller_flag_offset']),
        ('outer_default_copy_length', 0x3ec8d00, 5, c['outer_default_copy_bytes']),
        ('outer_record_copy_length', 0x3ec8d46, 5, c['outer_record_copy_bytes']),
        ('outer_record_stride', 0x3ec8d3a, 4, c['outer_record_stride']),
        ('outer_vector_length_store_offset', 0x3ec8d58, 4, c['outer_vector_length_offset']),
    ):
        container_rows.append([role, hx(va), image.read(va, size, True).hex(), hx(value)])

    st_lea = 0x46ef717
    stable = rip_lea_target(image, st_lea, b'\x48\x8d\x0d')
    status_rows = [['role', 'producer_va', 'status_word', 'table_va', 'slot_va',
                    'slot_file_offset', 'slot_hex', 'arm_va', 'literal_lea_va',
                    'literal_va', 'literal_file_offset', 'length', 'text']]
    sfde = fde_by_role['status_formatter']
    for role, va, _ in code_specs:
        if role == 'success':
            continue
        s = status_info(image, stable, c[role], sfde['start'], sfde['end'])
        status_rows.append([role, hx(va), hx(c[role]), hx(stable), hx(s['slot']),
                            hx(image.offset(s['slot'], 4)), s['raw'].hex(), hx(s['arm']),
                            hx(s['lea']), hx(s['text_va']), hx(image.offset(s['text_va'], len(s['text']))),
                            len(s['text']), s['text']])

    call_rows = [['role', 'site_va', 'site_file_offset', 'raw_hex', 'kind',
                  'slot_va', 'rela_file_offset', 'rela_hex', 'target_va', 'target_scope']]
    selected_starts = {a for _, a in FUNCTIONS}
    for role, site, expected in DIRECT_CALLS:
        raw = image.read(site, 5, True)
        target = rel32_target(raw, site)
        if target != expected:
            raise ValueError('unexpected direct call target')
        call_rows.append([role, hx(site), hx(image.offset(site, 5, True)), raw.hex(), 'rel32',
                          '', '', '', hx(target), 'selected' if target in selected_starts else 'external'])
    for role, site, expected in DIRECT_JUMPS:
        raw = image.read(site, 5, True)
        target = rel32_target(raw, site)
        if raw[0] != 0xe9 or target != expected:
            raise ValueError('unexpected direct jump target')
        call_rows.append([role, hx(site), hx(image.offset(site, 5, True)), raw.hex(), 'rel32_jump',
                          '', '', '', hx(target), 'interior'])
    rels = read_relocations(data, secs, {slot for _, _, slot, _ in INDIRECT_CALLS})
    for role, site, expected_slot, expected_target in INDIRECT_CALLS:
        raw = image.read(site, 6, True)
        slot = indirect_slot(raw, site)
        if slot != expected_slot:
            raise ValueError('unexpected indirect call slot')
        row = rels[slot]
        relative_relocation(row, expected_target)
        call_rows.append([role, hx(site), hx(image.offset(site, 6, True)), raw.hex(), 'R_X86_64_RELATIVE',
                          hx(slot), hx(row['offset']), row['raw'].hex(), hx(row['addend']),
                          'selected' if row['addend'] in selected_starts else 'external'])
    # This relocation supplies the indirect comparison used in the tree loop.
    load_va = 0x3c1ac58
    load = image.read(load_va, 7, True)
    if load[:3] != bytes.fromhex('488b2d'):
        raise ValueError('unexpected imported comparison load')
    compare_slot = load_va + 7 + struct.unpack_from('<i', load, 3)[0]
    import_row = read_relocations(data, secs, {compare_slot})[compare_slot]
    if import_row['type'] != 6 or import_row['addend'] != 0:
        raise ValueError('unexpected imported comparison relocation')
    compare_name = dynamic_symbol_name(data, secs, import_row['symbol'])
    if compare_name != 'memcmp' or image.read(0x3c1aca8, 2, True) != b'\xff\xd5':
        raise ValueError('unexpected indirect comparison call')
    import_rows = [['role', 'load_va', 'load_hex', 'slot_va', 'rela_file_offset',
                    'rela_hex', 'symbol_index', 'symbol_name', 'register_call_va',
                    'register_call_hex']]
    import_rows.append(['tree_key_comparison', hx(load_va), load.hex(), hx(compare_slot),
                        hx(import_row['offset']), import_row['raw'].hex(), import_row['symbol'],
                        compare_name, hx(0x3c1aca8), image.read(0x3c1aca8, 2, True).hex()])
    move_va = 0x456fbe9
    move_insn = image.read(move_va, 6, True)
    move_slot = indirect_slot(move_insn, move_va)
    move_rela = read_relocations(data, secs, {move_slot})[move_slot]
    if move_rela['type'] != 6 or move_rela['addend'] != 0:
        raise ValueError('unexpected ring move relocation')
    move_name = dynamic_symbol_name(data, secs, move_rela['symbol'])
    if move_name != 'memmove':
        raise ValueError('unexpected ring move symbol')
    import_rows.append(['ring_move', hx(move_va), move_insn.hex(), hx(move_slot),
                        hx(move_rela['offset']), move_rela['raw'].hex(), move_rela['symbol'],
                        move_name, hx(move_va), move_insn.hex()])

    copy_va = 0x2b86e1b
    copy_insn = image.read(copy_va, 6, True)
    copy_slot = indirect_slot(copy_insn, copy_va)
    copy_rela = read_relocations(data, secs, {copy_slot})[copy_slot]
    if copy_rela['type'] != 6 or copy_rela['addend'] != 0:
        raise ValueError('unexpected decoder box copy relocation')
    copy_name = dynamic_symbol_name(data, secs, copy_rela['symbol'])
    if copy_name != 'memcpy':
        raise ValueError('unexpected decoder box copy symbol')
    import_rows.append(['decoder_box_copy', hx(copy_va), copy_insn.hex(), hx(copy_slot),
                        hx(copy_rela['offset']), copy_rela['raw'].hex(), copy_rela['symbol'],
                        copy_name, hx(copy_va), copy_insn.hex()])
    for role, copy_va in (('outer_default_copy', 0x3ec8d0a),
                          ('outer_record_copy', 0x3ec8d4b)):
        copy_insn = image.read(copy_va, 6, True)
        if indirect_slot(copy_insn, copy_va) != copy_slot:
            raise ValueError('unexpected outer row copy slot')
        import_rows.append([role, hx(copy_va), copy_insn.hex(), hx(copy_slot),
                            hx(copy_rela['offset']), copy_rela['raw'].hex(), copy_rela['symbol'],
                            copy_name, hx(copy_va), copy_insn.hex()])

    branch_rows = [['role', 'site_va', 'file_offset', 'raw_hex', 'condition',
                    'fallthrough_va', 'taken_va']]
    for role, site, expected_kind in BRANCHES:
        kind, target, size = decode_branch(image.read(site, 6, True), site)
        if kind != expected_kind:
            raise ValueError('conditional branch changed')
        branch_rows.append([role, hx(site), hx(image.offset(site, size, True)),
                            image.read(site, size, True).hex(), kind, hx(site + size), hx(target)])

    model_rows = [['case', 'quantity', 'root_present', 'balance', 'count', 'key_present',
                   'row_exists', 'preflight', 'status', 'outcome', 'outer_row_inserted_before_value_check']]
    qcap, bmax, nmax = c['system_limit'], c['balance_limit'], c['count_limit']
    scenarios = (
        ('zero_remove', 0, False, 0, 12, True, True, 'pass'),
        ('zero_absent', 0, False, 0, 0, False, True, 'pass'),
        ('zero_missing_row', 0, False, 0, 0, False, False, 'pass'),
        ('cap_below', qcap - 1, True, bmax + 1, nmax, False, True, 'pass'),
        ('cap_equal', qcap, True, bmax + 1, 0, False, True, 'pass'),
        ('cap_over', qcap + 1, True, bmax + 1, 0, False, True, 'pass'),
        ('no_root', 1, False, bmax + 1, 0, False, True, 'pass'),
        ('negative_balance', 1, True, -1, 0, False, True, 'pass'),
        ('balance_equal', 1, True, bmax, 0, False, True, 'pass'),
        ('balance_above', 1, True, bmax + 1, 0, False, True, 'pass'),
        ('count_equal', 1, True, bmax + 1, nmax, False, True, 'pass'),
        ('count_over_insert', 1, True, bmax + 1, nmax + 1, False, True, 'pass'),
        ('count_over_replace', 1, True, bmax + 1, nmax + 1, True, True, 'pass'),
        ('replace', 1, True, bmax + 1, nmax, True, True, 'pass'),
        ('new_row', 1, True, bmax + 1, 0, False, False, 'pass'),
        ('balance_precedes_count', 1, True, bmax, nmax + 1, True, True, 'pass'),
        ('identity_precedes_limit', qcap, False, 0, 0, False, True, 'identity_equal'),
        ('gate_precedes_limit', qcap, False, 0, 0, False, True, 'gate_failure'),
    )
    for name, q, root, bal, count, present, row_exists, preflight in scenarios:
        status, result, created = system_model(c, q, root, bal, count, present, row_exists, preflight)
        model_rows.append([name, q, int(root), bal, count, int(present), int(row_exists),
                           preflight, hx(status), result, int(created)])
    user_rows = [['case', 'conditional_parsed_word', 'status', 'outcome', 'outer_row_inserted_before_value_check']]
    for name, q in (('zero', 0), ('system_limit_below', qcap - 1),
                    ('system_limit_equal', qcap),
                    ('parsed_upper_below', c['parsed_word_upper_exclusive'] - 1),
                    ('parsed_upper_equal', c['parsed_word_upper_exclusive'])):
        status, result, created = user_word_model(c, q, True, bmax + 1, 0, False)
        user_rows.append([name, q, hx(status), result, int(created)])
    caller_rows = [['case', 'preflight_tag', 'mode_byte', 'counter_before', 'outcome',
                    'counter_after', 'flag_during', 'flag_after_normal_return']]
    for name, tag, mode, count in (
        ('direct', c['caller_dispatch_tag'], c['caller_direct_mode'], 0),
        ('flagged_zero', c['caller_dispatch_tag'], 0, 0),
        ('flagged_other', c['caller_dispatch_tag'], 2, 100),
        ('flagged_below_max', c['caller_dispatch_tag'], 0, (1 << 64) - 2),
        ('flagged_max', c['caller_dispatch_tag'], 0, (1 << 64) - 1),
        ('other_tag', 0, 0, 0),
        ('special_tag', c['caller_special_tag'], 0, 0),
    ):
        outcome, after, during, cleared = caller_model(c, tag, mode, count)
        caller_rows.append([name, hx(tag), hx(mode), count, outcome, after,
                            hx(during), hx(cleared)])

    text_rows = [['input_hex', 'length', 'status', 'route']]
    for example in (b'', b'1', b'%', b'1%', b'x' * (c['length_limit'] - 1),
                    b'x' * (c['length_limit'] - 2) + b'%', b'x' * c['length_limit'],
                    b'x' * (c['length_limit'] - 1) + b'%'):
        status, route = text_route(c, example)
        text_rows.append([example.hex(), len(example), hx(status), route])

    summary = {'target_sha256': SHA256, 'coordinate_system': 'linked ELF virtual address',
               'dispatcher_bias': dbias, 'dispatcher_below_bias_index': ddefault,
               'decoder_box_size': box_alloc_size, 'decoder_result_marker': result_marker,
               'action_names_are_formatter_associations': True,
               'constants': dict(sorted(c.items())),
               'selected_fdes': len(selected), 'selected_windows': len(WINDOWS),
               'selected_direct_calls': len(DIRECT_CALLS),
               'selected_direct_jumps': len(DIRECT_JUMPS),
               'selected_indirect_calls': len(INDIRECT_CALLS),
               'selected_branches': len(BRANCHES), 'status_mappings': len(status_rows) - 1,
               'selected_imports': len(import_rows) - 1,
               'synthetic_system_scenarios': len(model_rows) - 1,
               'synthetic_user_word_scenarios': len(user_rows) - 1,
               'synthetic_caller_scenarios': len(caller_rows) - 1,
               'synthetic_text_scenarios': len(text_rows) - 1,
               'limitations': ['FDE ranges are not complete source function boundaries',
                               'selected predicates and calls are not a whole-program execution',
                               'runtime relocation interposition and external wire handoff are unverified']}
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    outputs = {'functions.tsv': tsv(function_rows), 'windows.tsv': tsv(window_rows),
               'dispatch.tsv': tsv(dispatch_rows), 'decoder.tsv': tsv(decoder_rows),
               'container.tsv': tsv(container_rows),
               'statuses.tsv': tsv(status_rows),
               'calls.tsv': tsv(call_rows), 'imports.tsv': tsv(import_rows),
               'branches.tsv': tsv(branch_rows),
               'system-vectors.tsv': tsv(model_rows), 'user-word-vectors.tsv': tsv(user_rows),
               'caller-vectors.tsv': tsv(caller_rows),
               'text-vectors.tsv': tsv(text_rows),
               'summary.json': (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode()}
    for name, payload in outputs.items():
        (out / name).write_bytes(payload)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    summary = generate(TARGET.read_bytes(), args.out)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
