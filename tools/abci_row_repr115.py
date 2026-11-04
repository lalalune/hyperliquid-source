"""Reproduce a bounded #115 ABCI row-representation investigation.

This is static evidence extraction, not an x86 disassembler or a node emulator.
Selected instruction starts were inspected separately. Their complete containing
FDE bytes are pinned; branch and operand values below come from ELF bytes.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

import elf_index
import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# FDE intervals and raw-byte digests are separately pinned, so even an input
# with a recomputed outer digest does not silently change a selected body.
BODIES = (
    ('source_cursor', 0x5135c50, 0x5135e66, '53661ab25528fa03176ab8cf8ccb98ece3851ebf25bf33449bc3e4842580a686'),
    ('first_tree_entry', 0x51695e0, 0x5169760, '130ebf79feda28636704797de8dc8256ca861e8e05ffcd25ec3dd283fdb415d0'),
    ('second_tree_entry', 0x5160b30, 0x5160cac, '2d05fab97147e75a7841dbab9c1df977c58df4a42434764a29d59cb94bdae6ad'),
    ('first_shrink', 0x58027b0, 0x58028fe, '1bb7da4e100f08447e99fbdb91d3fd9d37636b2ca31d0cc92e913039a5551599'),
    ('second_shrink', 0x58046d0, 0x580481e, '38c5b8acaa869df35b74673a0200ca74eb53e3c090a9e674ef087603de3b2e40'),
    ('first_drain', 0x5ad6460, 0x5ad65c6, '3acd3997dc9b512a92c93539ec7028dab889dfbd719da4368f92d34ce5ae4a7d'),
    ('second_drain', 0x5ad6780, 0x5ad68e6, '8ef1db8c9cd54956f4f2b7f57f0f6fd48e185dde45cba1ed4950218a553a65c1'),
    ('first_builder', 0x4cb4ec0, 0x4cb563f, 'abc7bd9ff2429969ebeb12c8b65936a3cd25054a7d14126a45fdb751f287f438'),
    ('second_builder', 0x4cd7440, 0x4cd7c5a, 'd7b6f672fe2524cbb735b897f3de240995c6ef00477510733d5df5581ee8db2d'),
    ('first_guard', 0x57bc780, 0x57bc809, '0971eeb64d5d24c9704782b29dca2639fc08bacea4a65ef4d24f4fb8bdd36bd7'),
    ('second_guard', 0x57bcd30, 0x57bcdb9, 'cd2f20ff07ae243fae55d2ea820379af53856b121dfb5785fa13bd5d16dd7d48'),
    ('first_dedup', 0x4d57b60, 0x4d57cee, '936c7aec5d1ec5a2c58d3477b49f3f4bf5ecaf507051700aa87e0c5ce7eadd3a'),
    ('second_dedup', 0x4d5a620, 0x4d5a7c6, '0e5b024a8d72b033bd8efe44b400aad822823d0436ea5f636040c08153499ae6'),
    ('first_short_sort', 0x53e5db0, 0x53e5eb1, '252007339f8ded9963531d84afa6c520f7e9dbd680ce9a8b00c958cb06bc8d54'),
    ('first_long_wrapper', 0x4f42430, 0x4f42544, 'e3d7cf7b5b62ef2916e86c1004c458d9389c63d2336b172cb5d879e19b4a99f0'),
    ('second_long_wrapper', 0x4f3e930, 0x4f3ea44, '178216665c0cedce77a39ec5b755920eef2629b5e64f8a3904a79f18b85fdc5c'),
    ('first_run_driver', 0x4f774c0, 0x4f77b53, '01bc4c622fd29a89e538d1b2c7f57cea36c648274bbcd8bcd34d9f08340eebb5'),
    ('second_run_driver', 0x4f627e0, 0x4f62e73, '2e86ad6b74f09b52c7aa1e47bca402db19c114a62e469dda179c8599e2ccee0d'),
    ('first_partition', 0x4eb18b0, 0x4eb1e94, '42a77abdbb2777fcba3f64d0efc26eefb11629dd1a3566b8e00da1510e05a6e2'),
    ('second_partition', 0x4e7be10, 0x4e7c3f4, 'f418b027fcb8893e88e8055f185ded04de7e832da7b030d99a976d048b77b50e'),
    ('key_owner_constructor', 0x4dfe550, 0x4dfe6c6, '140e56f4f76d49026202d50ddc0e62eaf603aea59d87d187f294b8aca3621e85'),
)

# Previously proposed functions are boundary context only, not claimed FDEs.
CONTEXT = (
    ('state_location', 0x3c1352f, '488d1572328602'),
    ('state_compare', 0x3c1353b, '4883f801'),
    ('parent_a_source', 0x2af0e1f, 'f30f6f8358010000f30f7f83400500008b8368010000898350050000'),
    ('parent_b_source', 0x2cbc421, 'f30f6f8358010000f30f7f83400500008b8368010000898350050000'),
    ('parent_a_key', 0x2af1130, '488d93400500008b721089b42420250000f30f6f02660f7f842410250000'),
    ('parent_a_call', 0x2af116a, '488dbb08020000488db424f00500004c8dac24102500004889c24d89e941534152ff15e7629f034883c410'),
    ('parent_b_key', 0x2cbc805, '488d93400500008b721089b42480210000f30f6f02660f7f842470210000'),
    ('parent_b_call', 0x2cbc83f, '488dbb08020000488db424a00600004c8da424702100004889c24d89e141534152ff1512ac82034883c410'),
    ('parent_b_save_output', 0x2cbbc1e, '4889d54889f34889bc2498000000'),
    ('parent_b_first_copy', 0x2cbe96f, '488db310020000488dbc2408310000bad8020000ff157f0b8203'),
    ('parent_b_second_copy', 0x2cbea7d, '4983ff020f8478f0ffff48897c2420488dbc24582d0000488db42408310000ba00030000ff15610a8203'),
    ('parent_b_result_copy', 0x2cbc53b, '4885c00f852f290000488db424502d0000bab8030000488bbc2498000000ff15a92f8203'),
    ('parent_b_result_join', 0x2cbeb84, '488b7c2408e862a4feffe99ad9ffff'),
    ('upper_parent_and_copy', 0x2cb7761, '488dbc24300700004c89f6488b542408e86a44000083bc243007000002750941c60703e994080000488dbc24d01b0000488db42430070000ba80030000ff15647d8203'),
    ('upper_copy_two', 0x2cb7858, '488dbc24302f0000488db424d01b0000bae0020000ff15957c8203'),
    ('upper_memcpy_register', 0x2cb7cbc, '488b2d45788203ba60020000ffd5'),
    ('upper_copy_three', 0x2cb7d52, '488dbc24d0090000488db424302f0000bae0020000ffd5'),
    ('upper_copy_four', 0x2cb7e64, '4c8ba42430070000488db424380700004c8dbc2410320000bab80600004c89ffffd5'),
    ('upper_copy_five', 0x2cb7ffe, '488dbc2440270000baf00700004c89feffd5'),
    ('upper_copy_six', 0x2cb8039, '488dbc24501f0000488db42440270000baf0070000ff15b4748203'),
    ('upper_copy_seven', 0x2cb8068, '4c89a398010000488dbba0010000488db424501f0000bab8060000ffd5'),
    ('upper_copy_eight', 0x2cb97aa, '488db3980100004c89bc2440270000c683e20a000000c683dc0a000000c683da0a000000488dbc2430070000bac0060000ff15275d8203'),
    ('upper_alloc_copy', 0x2cb984d, 'bf18070000ff15285c82034885c00f84870500004989c6488db42430070000ba180700004889c7ff158e5c8203'),
    ('upper_publish', 0x2cb987a, '488d3da05795fd488d0d18d97803be190000004c89f2ff15ba7e8203'),
    ('worker_argument', 0x5a6e203, '4889fb'),
    ('worker_subobject', 0x5a6e255, '488d83a002000048898424a8030000'),
    ('worker_dispatch', 0x5a6eaa6, '4c89742460488b8424a80300004889442468488d84249002000048894424704889df488d74246031d2488d0d22a1a400e835014bff'),
    ('flag_select', 0x4dfe700, '410fb68424600200008844240f3c014c896424184c89bc24b802000075084d8b0fe97a020000498d9c2478020000'),
    ('key_load', 0x4dfe72e, '418b842471020000898424d0010000410f108424610200000f298424c0010000'),
    ('key_join', 0x4dfe94c, '660f288424c0010000660f298424e00100008b8424d0010000898424f0010000eb2d8b8424d0010000898424f0010000660f288424c0010000660f298424e0010000'),
    ('key_gate_copy', 0x4dfef5d, '807c240f00741248b8000000000000008048ffc0e9ac0200008b8424f001000089842410020000660f288424e0010000660f29842400020000'),
    ('key_argument', 0x4dff067, '488d8424000200004889442468488dbc2410010000488d742420e8aa6df5ff'),
    ('source_cursor_call', 0x5ba4700, '4c89ffe8481559ff4889d14885c074254c89f74c89e64889c2e8a23183ff'),
    ('first_select', 0x4d55e9d, '488b4c2408488b442410488b5424184883fa40763848c1e2054801c2488944242048894c243048894424284889542438488d7b08488d742420e80537410048b80000000000000080488903eb3548c744243000000000488954243848894c24204889442428488d7c242031f6e8a2c8aa000f104424200f104c24300f114b100f1103'),
    ('second_select', 0x4dff177, '4883fa40763948c1e2054801c2488944242048894c243048894424284889542438488dbc2418010000488d742420e88619360048b80000000000000080eb4a48c744243000000000488954243848894c24204889442428488d7c242031f6e8f654a000660f10442420660f104c2430660f298c2420010000660f29842410010000'),
    ('result_projection', 0x4dff200, '660f10842418010000660f29842400030000488b8c242801000048898c2410030000498b5d30488b8c24f000000048898c24e00200000f108424e00000000f298424d0020000488b8c240801000048898c24500300000f108424f80000000f298424400300004889842400020000660f28842400030000660f11842408020000488b8424100300004889842418020000'),
)

# End-exclusive selected windows, all confined to the full checked FDEs.
WINDOWS = (
    ('cursor_count_tag', 0x5135c50, 0x5135c6a),
    ('cursor_current_or_empty', 0x5135c6a, 0x5135c97),
    ('cursor_initial_remainder', 0x5135c97, 0x5135ce0),
    ('cursor_initial_eight_steps', 0x5135ce0, 0x5135d1e),
    ('cursor_install_initial', 0x5135d1e, 0x5135d43),
    ('cursor_climb', 0x5135d50, 0x5135d82),
    ('cursor_successor_descent', 0x5135d82, 0x5135e11),
    ('cursor_result_and_advance', 0x5135e11, 0x5135e36),
    ('cursor_failure', 0x5135e48, 0x5135e66),
    ('first_entry_drain_and_sort', 0x51695e0, 0x5169627),
    ('first_entry_leaf_and_builder', 0x5169627, 0x51696ae),
    ('first_entry_empty', 0x51696b0, 0x51696ec),
    ('first_entry_sort_failure', 0x51696ec, 0x5169734),
    ('first_entry_unwind', 0x5169734, 0x5169760),
    ('second_entry_drain_and_sort', 0x5160b30, 0x5160b77),
    ('second_entry_leaf_and_builder', 0x5160b77, 0x5160bfc),
    ('second_entry_empty', 0x5160bfc, 0x5160c38),
    ('second_entry_sort_failure', 0x5160c38, 0x5160c80),
    ('second_entry_unwind', 0x5160c80, 0x5160cac),
    ('first_shrink_decision', 0x58027b0, 0x5802803),
    ('first_shrink_reposition', 0x5802803, 0x5802883),
    ('first_shrink_release_reallocate', 0x5802883, 0x58028e9),
    ('first_shrink_landing', 0x58028e9, 0x58028fe),
    ('second_shrink_decision', 0x58046d0, 0x5804723),
    ('second_shrink_reposition', 0x5804723, 0x58047a3),
    ('second_shrink_release_reallocate', 0x58047a3, 0x5804809),
    ('second_shrink_landing', 0x5804809, 0x580481e),
    ('first_drain_decision', 0x5ad6460, 0x5ad649d),
    ('first_drain_fresh_buffer', 0x5ad649d, 0x5ad64f9),
    ('first_drain_reuse', 0x5ad64f9, 0x5ad6536),
    ('first_drain_copy_and_landing', 0x5ad6536, 0x5ad65c6),
    ('second_drain_decision', 0x5ad6780, 0x5ad67bd),
    ('second_drain_fresh_buffer', 0x5ad67bd, 0x5ad6819),
    ('second_drain_reuse', 0x5ad6819, 0x5ad6856),
    ('second_drain_copy_and_landing', 0x5ad6856, 0x5ad68e6),
    ('first_build_next_and_store', 0x4cb4fe4, 0x4cb5076),
    ('first_build_full_and_allocate', 0x4cb5076, 0x4cb515d),
    ('first_build_parent_link', 0x4cb515d, 0x4cb51ad),
    ('first_build_repair', 0x4cb52a4, 0x4cb5545),
    ('first_build_failures', 0x4cb5569, 0x4cb563f),
    ('second_build_next_and_store', 0x4cd7580, 0x4cd75fe),
    ('second_build_full_and_allocate', 0x4cd75fe, 0x4cd76dd),
    ('second_build_parent_link', 0x4cd76dd, 0x4cd774a),
    ('second_build_failures', 0x4cd7b85, 0x4cd7c5a),
    ('first_dedup_candidate', 0x4d57b60, 0x4d57bc6),
    ('first_dedup_lookahead', 0x4d57bc6, 0x4d57c14),
    ('first_dedup_equality', 0x4d57c14, 0x4d57c45),
    ('first_dedup_repeat_and_emit', 0x4d57c50, 0x4d57cee),
    ('second_dedup_candidate', 0x4d5a620, 0x4d5a68b),
    ('second_dedup_lookahead', 0x4d5a68b, 0x4d5a6e3),
    ('second_dedup_equality', 0x4d5a6e3, 0x4d5a714),
    ('second_dedup_repeat_and_emit', 0x4d5a720, 0x4d5a7c6),
    ('short_sort_compare_and_shift', 0x53e5df7, 0x53e5eb1),
    ('first_guard_all', 0x57bc780, 0x57bc809),
    ('second_guard_all', 0x57bcd30, 0x57bcdb9),
    ('first_long_wrapper_all', 0x4f42430, 0x4f42544),
    ('second_long_wrapper_all', 0x4f3e930, 0x4f3ea44),
    ('first_run_classification', 0x4f776a0, 0x4f77778),
    ('first_run_reversal', 0x4f77778, 0x4f777b9),
    ('first_run_merge_dispatch', 0x4f77886, 0x4f77940),
    ('second_run_classification', 0x4f629c0, 0x4f62a98),
    ('second_run_reversal', 0x4f62a98, 0x4f62ad9),
    ('second_run_merge_dispatch', 0x4f62ba6, 0x4f62c60),
    ('first_partition_entry', 0x4eb18b0, 0x4eb19b3),
    ('first_partition_capacity_and_move', 0x4eb19dc, 0x4eb1aa7),
    ('first_partition_reverse_move', 0x4eb1c20, 0x4eb1cbb),
    ('first_partition_exits', 0x4eb1dfd, 0x4eb1e94),
    ('second_partition_entry', 0x4e7be10, 0x4e7bf13),
    ('second_partition_capacity_and_move', 0x4e7bf3c, 0x4e7c007),
    ('second_partition_reverse_move', 0x4e7c180, 0x4e7c21b),
    ('second_partition_exits', 0x4e7c35d, 0x4e7c3f4),
    ('key_constructor_arguments', 0x4dfe550, 0x4dfe591),
    ('key_constructor_initialize', 0x4dfe591, 0x4dfe5fc),
    ('key_constructor_store', 0x4dfe5fc, 0x4dfe61b),
    ('key_constructor_publish', 0x4dfe61b, 0x4dfe663),
    ('key_constructor_unwind', 0x4dfe663, 0x4dfe6c6),
)

# Explicit instruction starts and forms. There is no speculative whole-section
# opcode scan and these records are not a complete branch/caller census.
# An optional target is checked where an edge connects selected stages.
TRANSFERS = (
    ('context_parent_a_constructor', 0x2af118b, 'slotcall', 0x64e7478),
    ('context_parent_b_constructor', 0x2cbc860, 'slotcall', 0x64e7478),
    ('context_parent_copy_one', 0x2cbe983, 'slotcall', 0x64df508),
    ('context_parent_copy_two', 0x2cbeaa1, 'slotcall', 0x64df508),
    ('context_parent_result', 0x2cbc559, 'slotcall', 0x64df508),
    ('context_parent_tag_exit', 0x2cbea81, 'jcc', 0x2cbdaff),
    ('context_parent_result_join', 0x2cbeb8e, 'jump', 0x2cbc52d),
    ('context_parent_validation_fail', 0x2cbc53e, 'jcc', 0x2cbee73),
    ('context_upper_parent', 0x2cb7771, 'call', 0x2cbbbe0),
    ('context_upper_copy_one', 0x2cb779e, 'slotcall', 0x64df508),
    ('context_upper_copy_two', 0x2cb786d, 'slotcall', 0x64df508),
    ('context_upper_copy_six', 0x2cb804e, 'slotcall', 0x64df508),
    ('context_upper_copy_eight', 0x2cb97db, 'slotcall', 0x64df508),
    ('context_upper_allocation', 0x2cb9852, 'slotcall', 0x64df480),
    ('context_callback_copy', 0x2cb9874, 'slotcall', 0x64df508),
    ('context_callback_publish', 0x2cb9890, 'slotcall', 0x64e1750),
    ('context_worker_dispatch', 0x5a6ead6, 'call', 0x4f1ec10),
    ('context_source_cursor', 0x5ba4703, 'call', 0x5135c50),
    ('context_first_tree', 0x4d55ed6, 'call', 0x51695e0),
    ('context_first_shrink', 0x4d55f09, 'call', 0x58027b0),
    ('context_second_tree', 0x4dff1a5, 'call', 0x5160b30),
    ('context_second_shrink', 0x4dff1d5, 'call', 0x58046d0),
    ('cursor_empty', 0x5135c58, 'jcc', 0x5135c93),
    ('cursor_bad_tag', 0x5135c64, 'jcc', 0x5135e57),
    ('cursor_start', 0x5135c71, 'jcc', 0x5135c97),
    ('cursor_climb_required', 0x5135c85, 'jcc', 0x5135d50),
    ('cursor_missing_parent', 0x5135d56, 'jcc', 0x5135e48),
    ('cursor_parent_error_call', 0x5135e4f, 'slotcall', 0x64df830),
    ('cursor_tag_error_call', 0x5135e5e, 'slotcall', 0x64df830),
    ('first_drain_call', 0x51695f6, 'call', 0x5ad6460),
    ('first_empty', 0x5169603, 'jcc', 0x51696b0),
    ('first_needs_sort', 0x516961c, 'jcc', 0x51696ec),
    ('first_leaf_allocate', 0x516962c, 'slotcall', 0x64df480),
    ('first_leaf_null', 0x5169635, 'jcc', 0x516970c),
    ('first_builder_call', 0x5169698, 'call', 0x4cb4ec0),
    ('first_long_sort_select', 0x51696f0, 'jcc', 0x516971e),
    ('first_short_sort', 0x5169702, 'call', 0x53e5db0),
    ('first_leaf_failure', 0x5169716, 'slotcall', 0x64df490),
    ('first_long_sort', 0x5169729, 'slotcall', 0x64e51e8),
    ('second_drain_call', 0x5160b46, 'call', 0x5ad6780),
    ('second_empty', 0x5160b53, 'jcc', 0x5160bfc),
    ('second_needs_sort', 0x5160b6c, 'jcc', 0x5160c38),
    ('second_leaf_allocate', 0x5160b7c, 'slotcall', 0x64df480),
    ('second_leaf_null', 0x5160b85, 'jcc', 0x5160c58),
    ('second_builder_call', 0x5160be4, 'call', 0x4cd7440),
    ('second_long_sort_select', 0x5160c3c, 'jcc', 0x5160c6a),
    ('second_short_sort_boundary', 0x5160c4e, 'call', 0x53ec830),
    ('second_leaf_failure', 0x5160c62, 'slotcall', 0x64df490),
    ('second_long_sort', 0x5160c75, 'slotcall', 0x64e5720),
    ('first_shrink_noop', 0x58027d1, 'jcc', 0x58028db),
    ('first_shrink_empty', 0x58027f5, 'jcc', 0x580283c),
    ('first_shrink_no_shift', 0x580284f, 'jcc', 0x5802883),
    ('first_shrink_zero', 0x5802899, 'jcc', 0x58028c0),
    ('first_shrink_resize', 0x58028a5, 'slotcall', 0x64df588),
    ('first_shrink_null', 0x58028ae, 'jcc', 0x58028d4),
    ('first_shrink_failure', 0x58028b8, 'slotcall', 0x64df498),
    ('first_shrink_release', 0x58028c9, 'slotcall', 0x64df4a0),
    ('first_shrink_landing', 0x58028f1, 'call', 0x57bc780),
    ('second_shrink_noop', 0x58046f1, 'jcc', 0x58047fb),
    ('second_shrink_empty', 0x5804715, 'jcc', 0x580475c),
    ('second_shrink_no_shift', 0x580476f, 'jcc', 0x58047a3),
    ('second_shrink_zero', 0x58047b9, 'jcc', 0x58047e0),
    ('second_shrink_resize', 0x58047c5, 'slotcall', 0x64df588),
    ('second_shrink_null', 0x58047ce, 'jcc', 0x58047f4),
    ('second_shrink_failure', 0x58047d8, 'slotcall', 0x64df498),
    ('second_shrink_release', 0x58047e9, 'slotcall', 0x64df4a0),
    ('second_shrink_landing', 0x5804811, 'call', 0x57bcd30),
    ('first_drain_reuse_base', 0x5ad647b, 'jcc', 0x5ad64f9),
    ('first_drain_reuse_half', 0x5ad649b, 'jcc', 0x5ad650a),
    ('first_drain_allocate', 0x5ad64c0, 'jcc', 0x5ad6536),
    ('second_drain_reuse_base', 0x5ad679b, 'jcc', 0x5ad6819),
    ('second_drain_reuse_half', 0x5ad67bb, 'jcc', 0x5ad682a),
    ('second_drain_allocate', 0x5ad67e0, 'jcc', 0x5ad6856),
    ('first_builder_iterator', 0x4cb4fee, 'call', 0x4d57b60),
    ('first_builder_end', 0x4cb4ffb, 'jcc', 0x4cb52a4),
    ('first_builder_room', 0x4cb5074, 'jcc', 0x4cb5020),
    ('first_builder_root_null', 0x4cb50b3, 'jcc', 0x4cb55da),
    ('first_builder_leaf_null', 0x4cb50fd, 'jcc', 0x4cb5594),
    ('first_builder_parent_full', 0x4cb5169, 'jcc', 0x4cb55a6),
    ('first_builder_alloc_failure', 0x4cb559e, 'slotcall', 0x64df490),
    ('second_builder_iterator', 0x4cd75e0, 'call', 0x4d5a620),
    ('second_builder_end', 0x4cd75ea, 'jcc', 0x4cd7855),
    ('second_builder_room', 0x4cd75fc, 'jcc', 0x4cd7580),
    ('second_builder_root_null', 0x4cd7633, 'jcc', 0x4cd7bf6),
    ('second_builder_leaf_null', 0x4cd767f, 'jcc', 0x4cd7bb0),
    ('second_builder_parent_full', 0x4cd76e9, 'jcc', 0x4cd7bc2),
    ('second_builder_alloc_failure', 0x4cd7bba, 'slotcall', 0x64df490),
    ('first_dedup_end', 0x4d57b96, 'jcc', 0x4d57cde),
    ('first_dedup_zero_value', 0x4d57bc0, 'jcc', 0x4d57cde),
    ('first_dedup_different_key', 0x4d57c3d, 'jcc', 0x4d57cc5),
    ('second_dedup_end', 0x4d5a659, 'jcc', 0x4d5a7b7),
    ('second_dedup_zero_value', 0x4d5a685, 'jcc', 0x4d5a7b7),
    ('second_dedup_different_key', 0x4d5a70c, 'jcc', 0x4d5a79e),
    ('short_sort_bad_start', 0x53e5db7, 'jcc', 0x53e5eaf),
    ('short_sort_ordered', 0x53e5e47, 'jcc', 0x53e5e29),
    ('first_wrapper_heap', 0x4f4246d, 'jcc', 0x4f42479),
    ('first_wrapper_size_ok', 0x4f42499, 'jcc', 0x4f424a6),
    ('first_wrapper_size_failure', 0x4f424a0, 'slotcall', 0x64df498),
    ('first_wrapper_allocate', 0x4f424af, 'slotcall', 0x64df480),
    ('first_wrapper_null', 0x4f424c4, 'jcc', 0x4f42508),
    ('first_wrapper_driver', 0x4f424d7, 'call', 0x4f774c0),
    ('first_wrapper_allocation_failure', 0x4f42510, 'slotcall', 0x64df498),
    ('second_wrapper_heap', 0x4f3e96d, 'jcc', 0x4f3e979),
    ('second_wrapper_size_ok', 0x4f3e999, 'jcc', 0x4f3e9a6),
    ('second_wrapper_size_failure', 0x4f3e9a0, 'slotcall', 0x64df498),
    ('second_wrapper_allocate', 0x4f3e9af, 'slotcall', 0x64df480),
    ('second_wrapper_null', 0x4f3e9c4, 'jcc', 0x4f3ea08),
    ('second_wrapper_driver', 0x4f3e9d7, 'call', 0x4f627e0),
    ('second_wrapper_allocation_failure', 0x4f3ea10, 'slotcall', 0x64df498),
    ('first_run_compare', 0x4f776b0, 'slotcall', 0x64dfb50),
    ('first_run_decreasing', 0x4f776b8, 'jcc', 0x4f77704),
    ('first_run_stop_decreasing', 0x4f77744, 'jcc', 0x4f77755),
    ('first_run_partition', 0x4f77913, 'slotcall', 0x64eb858),
    ('second_run_compare', 0x4f629d0, 'slotcall', 0x64dfb50),
    ('second_run_decreasing', 0x4f629d8, 'jcc', 0x4f62a24),
    ('second_run_stop_decreasing', 0x4f62a64, 'jcc', 0x4f62a75),
    ('second_run_partition', 0x4f62c33, 'slotcall', 0x64eb470),
    ('first_partition_large', 0x4eb18d8, 'jcc', 0x4eb18e2),
    ('first_partition_depth_zero', 0x4eb1912, 'jcc', 0x4eb1dfd),
    ('first_partition_compare', 0x4eb197e, 'slotcall', 0x64dfb50),
    ('first_partition_insufficient_scratch', 0x4eb1a15, 'jcc', 0x4eb1e63),
    ('first_partition_recursive', 0x4eb1bff, 'slotcall', 0x64eb858),
    ('first_partition_fallback_driver', 0x4eb1e1b, 'call', 0x4f774c0),
    ('second_partition_large', 0x4e7be38, 'jcc', 0x4e7be42),
    ('second_partition_depth_zero', 0x4e7be72, 'jcc', 0x4e7c35d),
    ('second_partition_compare', 0x4e7bede, 'slotcall', 0x64dfb50),
    ('second_partition_insufficient_scratch', 0x4e7bf75, 'jcc', 0x4e7c3c3),
    ('second_partition_recursive', 0x4e7c15f, 'slotcall', 0x64eb470),
    ('second_partition_fallback_driver', 0x4e7c37b, 'call', 0x4f627e0),
    ('key_constructor_initialize_call', 0x4dfe5ac, 'slotcall', 0x64e1020),
    ('key_constructor_prefix_copy', 0x4dfe5ef, 'slotcall', 0x64df508),
    ('key_constructor_cleanup_a', 0x4dfe678, 'slotcall', 0x64e72b8),
    ('key_constructor_cleanup_b', 0x4dfe694, 'slotcall', 0x64e6f20),
    ('key_constructor_cleanup_c', 0x4dfe6aa, 'slotcall', 0x64e7240),
)

# Values extracted from fixed instruction encodings: label, VA, prefix, format,
# expected value. Prefix checking prevents reading an unrelated immediate.
OPERANDS = (
    ('context_flag_offset', 0x4dfe700, '410fb68424', 'I', 0x260),
    ('context_key_first_offset', 0x4dfe73d, '410f108424', 'I', 0x261),
    ('context_key_tail_offset', 0x4dfe72e, '418b8424', 'I', 0x271),
    ('parent_input_key_first', 0x2cbc421, 'f30f6f83', 'I', 0x158),
    ('parent_input_key_tail', 0x2cbc431, '8b83', 'I', 0x168),
    ('parent_intermediate_key', 0x2cbc805, '488d93', 'I', 0x540),
    ('parent_constructed_object', 0x2cbc83f, '488dbb', 'I', 0x208),
    ('constructor_flag_offset', 0x4dfe5fc, '41c686', 'I', 0x260),
    ('constructor_key_first_offset', 0x4dfe608, '410f1186', 'I', 0x261),
    ('constructor_key_tail_offset', 0x4dfe614, '418986', 'I', 0x271),
    ('copy_1_src', 0x2cbe96f, '488db3', 'I', 0x210),
    ('copy_1_dst', 0x2cbe976, '488dbc24', 'I', 0x3108),
    ('copy_1_len', 0x2cbe97e, 'ba', 'I', 0x2d8),
    ('copy_2_src', 0x2cbea94, '488db424', 'I', 0x3108),
    ('copy_2_dst', 0x2cbea8c, '488dbc24', 'I', 0x2d58),
    ('copy_2_len', 0x2cbea9c, 'ba', 'I', 0x300),
    ('copy_3_src', 0x2cbc544, '488db424', 'I', 0x2d50),
    ('copy_3_len', 0x2cbc54c, 'ba', 'I', 0x3b8),
    ('copy_4_src', 0x2cb7791, '488db424', 'I', 0x730),
    ('copy_4_dst', 0x2cb7789, '488dbc24', 'I', 0x1bd0),
    ('copy_4_len', 0x2cb7799, 'ba', 'I', 0x380),
    ('copy_5_src', 0x2cb7860, '488db424', 'I', 0x1bd0),
    ('copy_5_dst', 0x2cb7858, '488dbc24', 'I', 0x2f30),
    ('copy_5_len', 0x2cb7868, 'ba', 'I', 0x2e0),
    ('copy_6_src', 0x2cb7d5a, '488db424', 'I', 0x2f30),
    ('copy_6_dst', 0x2cb7d52, '488dbc24', 'I', 0x9d0),
    ('copy_6_len', 0x2cb7d62, 'ba', 'I', 0x2e0),
    ('copy_7_src', 0x2cb7e6c, '488db424', 'I', 0x738),
    ('copy_7_dst', 0x2cb7e74, '4c8dbc24', 'I', 0x3210),
    ('copy_7_len', 0x2cb7e7c, 'ba', 'I', 0x6b8),
    ('copy_8_dst', 0x2cb7ffe, '488dbc24', 'I', 0x2740),
    ('copy_8_len', 0x2cb8006, 'ba', 'I', 0x7f0),
    ('copy_9_src', 0x2cb8041, '488db424', 'I', 0x2740),
    ('copy_9_dst', 0x2cb8039, '488dbc24', 'I', 0x1f50),
    ('copy_9_len', 0x2cb8049, 'ba', 'I', 0x7f0),
    ('copy_10_src', 0x2cb8076, '488db424', 'I', 0x1f50),
    ('copy_10_dst', 0x2cb806f, '488dbb', 'I', 0x1a0),
    ('copy_10_len', 0x2cb807e, 'ba', 'I', 0x6b8),
    ('copy_11_src', 0x2cb97aa, '488db3', 'I', 0x198),
    ('copy_11_dst', 0x2cb97ce, '488dbc24', 'I', 0x730),
    ('copy_11_len', 0x2cb97d6, 'ba', 'I', 0x6c0),
    ('copy_12_src', 0x2cb9864, '488db424', 'I', 0x730),
    ('copy_12_len', 0x2cb986c, 'ba', 'I', 0x718),
    ('worker_subobject_offset', 0x5a6e255, '488d83', 'I', 0x2a0),
    ('context_first_conversion_cutoff', 0x4d55eac, '4883fa', 'B', 64),
    ('context_second_conversion_cutoff', 0x4dff177, '4883fa', 'B', 64),
    ('cursor_remaining_offset', 0x5135c51, '488b47', 'B', 0x40),
    ('cursor_node_length_offset', 0x5135c7b, '0fb791', 'I', 0x29e),
    ('cursor_parent_index_offset', 0x5135d5f, '0fb781', 'I', 0x29c),
    ('cursor_initial_child_offset', 0x5135cc0, '488b89', 'I', 0x2a0),
    ('cursor_key_base_offset', 0x5135e19, '4805', 'I', 0x1c0),
    ('first_leaf_allocation_size', 0x5169627, 'bf', 'I', 0x140),
    ('second_leaf_allocation_size', 0x5160b77, 'bf', 'I', 0x170),
    ('first_internal_allocation_size', 0x4cb50a8, 'bf', 'I', 0x1a0),
    ('second_internal_allocation_size', 0x4cd7628, 'bf', 'I', 0x1d0),
    ('first_leaf_count_offset', 0x4cb5068, '410fb787', 'I', 0x13e),
    ('second_leaf_count_offset', 0x4cd75f0, '410fb787', 'I', 0x16a),
    ('first_node_capacity', 0x4cb5070, '4883f8', 'B', 11),
    ('second_node_capacity', 0x4cd75f8, '4883f8', 'B', 11),
    ('first_leaf_key_base', 0x4cb503d, '410f11448f', 'B', 0x60),
    ('first_leaf_pointer_base', 0x4cb5043, '4d8974c7', 'B', 8),
    ('second_leaf_key_base', 0x4cd75b1, '410f11448f', 'B', 8),
    ('second_leaf_payload_base', 0x4cd75cc, '49898c87', 'I', 0xe4),
    ('second_leaf_payload_tail', 0x4cd75bf, '41898c87', 'I', 0xec),
    ('first_dedup_value_offset', 0x4d57bb6, '498b79', 'B', 0x18),
    ('second_dedup_value_offset', 0x4d5a678, '418b7a', 'B', 0x14),
    ('first_compare_mask', 0x4d57c36, '4181f9', 'I', 0xffff),
    ('second_compare_mask', 0x4d5a705, '4181fa', 'I', 0xffff),
    ('short_sort_key_bytes', 0x53e5e3b, 'ba', 'I', 20),
    ('first_sort_cutoff', 0x51696ec, '4983ff', 'B', 21),
    ('second_sort_cutoff', 0x5160c38, '4983ff', 'B', 21),
    ('first_empty_pointer', 0x58028cf, 'b8', 'I', 8),
    ('second_empty_pointer', 0x58047ef, 'b8', 'I', 4),
    ('first_null_size_argument', 0x58028b0, 'bf', 'I', 8),
    ('second_null_size_argument', 0x58047d0, 'bf', 'I', 4),
    ('first_scratch_clamp', 0x4f4244f, '4881fe', 'I', 250000),
    ('second_scratch_clamp', 0x4f3e94f, '4881fe', 'I', 250000),
    ('first_scratch_heap_at', 0x4f42466, '4881fb', 'I', 129),
    ('second_scratch_heap_at', 0x4f3e966, '4881fb', 'I', 129),
    ('first_stack_scratch_rows', 0x4f42472, 'b9', 'I', 128),
    ('second_stack_scratch_rows', 0x4f3e972, 'b9', 'I', 128),
    ('first_size_guard', 0x4f42487, '48b9', 'Q', 0x7ffffffffffffff8),
    ('second_size_guard', 0x4f3e987, '48b9', 'Q', 0x7ffffffffffffffc),
    ('first_partition_cutoff', 0x4eb18cf, '4883fe', 'B', 33),
    ('second_partition_cutoff', 0x4e7be2f, '4883fe', 'B', 33),
)

# Static relocations used by the selected functions. A GLOB_DAT name is an
# ELF symbol observation; the dynamic loader can still choose its binding.
SLOTS = {
    0x64df480: (8, 0x6355830),
    0x64df490: (8, 0x141e251),
    0x64df498: (8, 0x141e264),
    0x64df4a0: (8, 0x635de30),
    0x64df588: (8, 0x635a7a0),
    0x64df830: (8, 0x1680c10),
    0x64e51e8: (8, 0x4f42430),
    0x64e5720: (8, 0x4f3e930),
    0x64eb858: (8, 0x4eb18b0),
    0x64eb470: (8, 0x4e7be10),
    0x64e7478: (8, 0x4dfe550),
    0x64df508: (6, 'memcpy'),
    0x64df568: (6, 'memmove'),
    0x64dfb50: (6, 'memcmp'),
    0x64767a8: (8, None),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(data, expected=SHA115):
    require(hashlib.sha256(data).hexdigest() == expected, 'input digest mismatch')


def section_named(sections, name):
    found = [s for s in sections if s['name'] == name and s['type'] != 8]
    require(len(found) == 1, 'missing, duplicate, or NOBITS section: ' + name)
    return found[0]


def mapping(sections, va, size, executable=False):
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
            'invalid address or length')
    matches = [s for s in sections if s['type'] != 8 and s['size'] and
               (not executable or s['flags'] & 4) and s['address'] <= va and
               va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'address is not uniquely file-backed')
    s = matches[0]
    return s, s['offset'] + va - s['address']


def read_va(data, sections, va, size, executable=False):
    _, offset = mapping(sections, va, size, executable)
    require(offset + size <= len(data), 'file bytes outside input')
    return bytes(data[offset:offset + size])


def checked_body(raw, expected):
    require(hashlib.sha256(raw).hexdigest() == expected, 'selected body digest mismatch')


def project_span(source, destination, length, position, width):
    """Project one complete field through a bounded copy, in offset coordinates."""
    require(min(source, destination, length, position) >= 0 and width > 0,
            'invalid copy projection')
    require(source <= position and position + width <= source + length,
            'field not fully contained in copy')
    return destination + position - source


def key_flow(values):
    """Join only decoded copy operands; inter-call identity remains conditional."""
    get = values.__getitem__
    width = get('constructor_key_tail_offset') - get('constructor_key_first_offset') + 4
    require(width == get('short_sort_key_bytes'), 'key width mismatch')
    key = get('parent_constructed_object') + get('constructor_key_first_offset')
    flag = get('parent_constructed_object') + get('constructor_flag_offset')
    result = []

    def add(label, source_space, destination_space, src, dst, count):
        nonlocal key, flag
        before_key, before_flag = key, flag
        key = project_span(src, dst, count, key, width)
        flag = project_span(src, dst, count, flag, 1)
        result.append((label, source_space, destination_space, hex(src), hex(dst),
                       count, hex(before_key), hex(key), hex(before_flag), hex(flag)))

    add('parent_to_frame', 'parent_object', 'parent_frame', get('copy_1_src'), get('copy_1_dst'), get('copy_1_len'))
    add('frame_repack', 'parent_frame', 'parent_frame', get('copy_2_src'), get('copy_2_dst'), get('copy_2_len'))
    add('parent_result', 'parent_frame', 'parent_result', get('copy_3_src'), 0, get('copy_3_len'))
    require(key == get('constructor_key_first_offset') and flag == get('constructor_flag_offset'),
            'parent result field offset mismatch')
    # The earlier parent call's output pointer is upper-frame copy_4_src.
    key += get('copy_4_src')
    flag += get('copy_4_src')
    for n in (4, 5, 6, 7):
        add('upper_copy_' + str(n), 'upper_frame', 'upper_frame',
            get('copy_' + str(n) + '_src'), get('copy_' + str(n) + '_dst'), get('copy_' + str(n) + '_len'))
    add('upper_copy_8', 'upper_frame', 'upper_frame', get('copy_7_dst'), get('copy_8_dst'), get('copy_8_len'))
    add('upper_copy_9', 'upper_frame', 'upper_frame', get('copy_9_src'), get('copy_9_dst'), get('copy_9_len'))
    add('upper_store', 'upper_frame', 'upper_parent', get('copy_10_src'), get('copy_10_dst'), get('copy_10_len'))
    add('callback_staging', 'upper_parent', 'upper_frame', get('copy_11_src'), get('copy_11_dst'), get('copy_11_len'))
    add('callback_allocation', 'upper_frame', 'callback_allocation', get('copy_12_src'), 0, get('copy_12_len'))
    require(key == get('worker_subobject_offset') + get('context_key_first_offset') and
            flag == get('worker_subobject_offset') + get('context_flag_offset'),
            'callback-to-consumer offset mismatch')
    return result


def check_context(data, sections, specs=CONTEXT):
    rows = []
    for label, va, expected_hex in specs:
        expected = bytes.fromhex(expected_hex)
        raw = read_va(data, sections, va, len(expected), executable=True)
        require(raw == expected, 'context bytes mismatch: ' + label)
        _, offset = mapping(sections, va, len(raw), executable=True)
        rows.append((label, 'context', hex(va), hex(va + len(raw)), hex(offset), raw.hex()))
    return rows


def branch_bytes(raw, va, form, expected=None):
    """Decode only an explicitly selected x86-64 branch/call form."""
    require(len(raw) >= 2, 'truncated branch')
    op = raw[0]
    if form == 'call':
        require(op == 0xe8 and len(raw) >= 5, 'bad rel32 call')
        length, disp = 5, struct.unpack_from('<i', raw, 1)[0]
    elif form in ('slotcall', 'slotjump'):
        require(raw[:2] == (b'\xff\x15' if form == 'slotcall' else b'\xff\x25') and len(raw) >= 6,
                'bad RIP-relative slot transfer')
        length, disp = 6, struct.unpack_from('<i', raw, 2)[0]
    elif form == 'jcc':
        if 0x70 <= op <= 0x7f:
            length, disp = 2, struct.unpack_from('<b', raw, 1)[0]
        else:
            require(op == 0x0f and 0x80 <= raw[1] <= 0x8f and len(raw) >= 6,
                    'bad conditional branch')
            length, disp = 6, struct.unpack_from('<i', raw, 2)[0]
    elif form == 'jump':
        if op == 0xeb:
            length, disp = 2, struct.unpack_from('<b', raw, 1)[0]
        else:
            require(op == 0xe9 and len(raw) >= 5, 'bad relative jump')
            length, disp = 5, struct.unpack_from('<i', raw, 1)[0]
    else:
        raise ValueError('unsupported transfer form')
    target = va + length + disp
    require(expected is None or target == expected, 'transfer destination mismatch')
    return length, target


def operand_bytes(raw, prefix_hex, fmt, expected=None):
    prefix = bytes.fromhex(prefix_hex)
    require(raw.startswith(prefix), 'operand opcode mismatch')
    n = struct.calcsize('<' + fmt)
    require(len(raw) >= len(prefix) + n, 'truncated operand')
    value = struct.unpack_from('<' + fmt, raw, len(prefix))[0]
    require(expected is None or value == expected, 'operand value mismatch')
    return value, len(prefix) + n


def lsda_rows(data, offset, limit, fde):
    """Read omit-base, optional type-table pointer and ULEB call-site records."""
    require(0 <= offset < limit <= len(data) and offset + 4 <= limit, 'truncated LSDA')
    require(data[offset] == 0xff and data[offset + 1] in (0xff, 0x9b), 'unsupported LSDA encodings')
    pos = offset + 2
    if data[offset + 1] == 0x9b:
        type_offset, pos = fde_extents.uleb(data, pos, limit)
        require(pos + type_offset <= limit, 'LSDA type table pointer outside section')
    require(pos < limit and data[pos] == 1, 'unsupported LSDA call-site encoding')
    length, pos = fde_extents.uleb(data, pos + 1, limit)
    end = pos + length
    require(pos < end <= limit, 'invalid LSDA table length')
    span = fde['end'] - fde['start']
    rows = []
    previous_end = 0
    while pos < end:
        begin = pos
        fields = []
        for _ in range(4):
            value, pos = fde_extents.uleb(data, pos, end)
            fields.append(value)
        relative, size, landing, action = fields
        require(size > 0 and previous_end <= relative and relative + size <= span,
                'LSDA call-site range outside FDE or overlaps')
        require(landing == 0 or landing < span, 'LSDA landing outside FDE')
        previous_end = relative + size
        rows.append({'record_file_offset': begin, 'raw': bytes(data[begin:pos]),
                     'start': fde['start'] + relative,
                     'end': fde['start'] + relative + size,
                     'landing': None if landing == 0 else fde['start'] + landing,
                     'action': action})
    require(pos == end and rows, 'empty or malformed LSDA table')
    return rows


def relocations(data, sections, wanted):
    rela = section_named(sections, '.rela.dyn')
    dynsym = section_named(sections, '.dynsym')
    dynstr = section_named(sections, '.dynstr')
    require(rela['size'] % 24 == 0 and dynsym['size'] % 24 == 0, 'bad relocation/symbol size')
    found = {}
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        require(slot not in found, 'duplicate selected relocation')
        typ, symbol = info & 0xffffffff, info >> 32
        require(typ == wanted[slot][0], 'unexpected relocation type')
        symbol_name = ''
        if typ == 8:
            require(symbol == 0, 'RELATIVE relocation has a symbol')
            expected_addend = wanted[slot][1]
            require(expected_addend is None or addend == expected_addend, 'unexpected relocation addend')
        elif typ == 6:
            require(symbol < dynsym['size'] // 24 and addend == 0, 'bad dynamic symbol')
            symbol_off = dynsym['offset'] + symbol * 24
            name_off = struct.unpack_from('<I', data, symbol_off)[0]
            require(name_off < dynstr['size'], 'dynamic symbol name out of range')
            start = dynstr['offset'] + name_off
            end = data.find(b'\0', start, dynstr['offset'] + dynstr['size'])
            require(end >= 0, 'unterminated dynamic symbol name')
            symbol_name = bytes(data[start:end]).decode('ascii')
            require(symbol_name == wanted[slot][1], 'unexpected dynamic symbol name')
        else:
            raise ValueError('unsupported selected relocation')
        _, slot_off = mapping(sections, slot, 8)
        found[slot] = {'slot': hex(slot), 'slot_file_offset': hex(slot_off),
                       'rela_file_offset': hex(off), 'type': typ, 'symbol_index': symbol,
                       'symbol_name': symbol_name, 'addend': hex(addend)}
    require(set(found) == set(wanted), 'missing selected relocation')
    return found


def location(data, sections, relocs, va, line, column):
    pointer, length, actual_line, actual_column = struct.unpack('<QQII', read_va(data, sections, va, 24))
    require(pointer == 0 and 0 < length <= 256 and (actual_line, actual_column) == (line, column),
            'invalid Location record')
    require(va in relocs and relocs[va]['type'] == 8, 'missing Location relocation')
    target = int(relocs[va]['addend'], 16)
    path = read_va(data, sections, target, length)
    suffix = b'l1/src/abci/state.rs'
    require(path.endswith(suffix), 'unexpected Location source suffix')
    _, file_offset = mapping(sections, va, 24)
    _, string_offset = mapping(sections, target, length)
    return {'record_va': hex(va), 'record_file_offset': hex(file_offset),
            'path_va': hex(target), 'path_file_offset': hex(string_offset),
            'full_path_bytes': length, 'source_suffix': suffix.decode('ascii'),
            'line': actual_line, 'column': actual_column}


def verify_historical(data):
    """Optional release-separated check; it does not add historical output."""
    identity(data, SHA94)
    secs = elf_index.sections(data)
    rel = relocations(data, secs, {0x57755a8: (8, 0x3273810), 0x56dfbf8: (8, None)})
    location(data, secs, rel, 0x56dfbf8, 107, 37)
    require(read_va(data, secs, 0x3272785, 6, True) == bytes.fromhex('ff151d2e5002'),
            'historical call bytes mismatch')
    branch_bytes(read_va(data, secs, 0x3272785, 6, True), 0x3272785, 'slotcall', 0x57755a8)
    require(read_va(data, secs, 0x3273856, 7, True) == bytes.fromhex('488d0d9bc34602'),
            'historical Location reference mismatch')
    require(read_va(data, secs, 0x3273871, 6, True) == bytes.fromhex('4983fd027541'),
            'historical result comparison mismatch')
    _, fs = fde_extents.eh_frame_records(data, secs)
    for start, end in ((0x32725d0, 0x3272b3a), (0x3273810, 0x327396c)):
        matches = [f for f in fs if f['start'] == start]
        require(len(matches) == 1 and matches[0]['end'] == end, 'historical FDE mismatch')


def tsv(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def encoded_json(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def extract(data):
    identity(data)
    secs, index = elf_index.unwind_index(data)
    _, fdes = fde_extents.eh_frame_records(data, secs)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    indexed = {i['start']: i for i in index}
    body_rows, body_bytes, extents, selected_fdes = [], {}, [], {}
    for label, start, end, digest in BODIES:
        matches = by_start.get(start, [])
        require(len(matches) == 1 and start in indexed, 'missing or duplicate selected FDE')
        fde, item = matches[0], indexed[start]
        require(fde['end'] == end and fde['fde'] == item['fde'], 'FDE/header range mismatch')
        raw = read_va(data, secs, start, end - start, True)
        checked_body(raw, digest)
        section, off = mapping(secs, start, len(raw), True)
        require(section['name'] == '.text', 'selected body outside text')
        body_rows.append((label, hex(start), hex(end), hex(off), len(raw),
                          hex(fde['fde']), hex(fde['cie']), '-' if fde['lsda'] is None else hex(fde['lsda']),
                          hashlib.sha256(raw).hexdigest(), raw.hex()))
        body_bytes[label] = raw
        extents.append((start, end))
        selected_fdes[label] = fde
    ordered = sorted(extents)
    require(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), 'selected FDEs overlap')
    windows = check_context(data, secs)
    for label, start, end in WINDOWS:
        owners = [x for x in BODIES if x[1] <= start < end <= x[2]]
        require(len(owners) == 1, 'window outside selected FDE')
        raw = read_va(data, secs, start, end - start, True)
        _, off = mapping(secs, start, end - start, True)
        windows.append((label, owners[0][0], hex(start), hex(end), hex(off), raw.hex()))
    transfers = []
    for label, va, form, expected in TRANSFERS:
        raw = read_va(data, secs, va, 6, True)
        length, target = branch_bytes(raw, va, form, expected)
        _, off = mapping(secs, va, length, True)
        owners = [x[0] for x in BODIES if x[1] <= va and va + length <= x[2]]
        context = any(v <= va and va + length <= v + len(bytes.fromhex(h)) for _, v, h in CONTEXT)
        require(len(owners) == 1 or (not owners and context), 'transfer outside selected evidence')
        transfers.append((label, owners[0] if owners else 'context', hex(va), hex(off),
                          form, raw[:length].hex(), hex(target)))
    operands, operand_values = [], {}
    for label, va, prefix, fmt, expected in OPERANDS:
        size = len(bytes.fromhex(prefix)) + struct.calcsize('<' + fmt)
        raw = read_va(data, secs, va, size, True)
        value, _ = operand_bytes(raw, prefix, fmt, expected)
        require(label not in operand_values, 'duplicate operand label')
        operand_values[label] = value
        _, off = mapping(secs, va, size, True)
        operands.append((label, hex(va), hex(off), raw.hex(), value, hex(value)))
    flow = key_flow(operand_values)
    relocs = relocations(data, secs, SLOTS)
    loc = location(data, secs, relocs, 0x64767a8, 123, 37)
    lea = read_va(data, secs, 0x3c1352f, 7, True)
    require(lea[:3] == bytes.fromhex('488d15') and
            0x3c1352f + 7 + struct.unpack_from('<i', lea, 3)[0] == 0x64767a8,
            'context Location reference mismatch')
    move = read_va(data, secs, 0x2cb7cbc, 7, True)
    require(move[:3] == bytes.fromhex('488b2d') and
            0x2cb7cbc + 7 + struct.unpack_from('<i', move, 3)[0] == 0x64df508,
            'context copy-register target mismatch')
    comparisons = []
    for a, b in (('first_shrink', 'second_shrink'), ('first_drain', 'second_drain'),
                 ('first_guard', 'second_guard'), ('first_long_wrapper', 'second_long_wrapper'),
                 ('first_run_driver', 'second_run_driver'), ('first_partition', 'second_partition')):
        x, y = body_bytes[a], body_bytes[b]
        require(len(x) == len(y), 'family extent lengths differ')
        diffs = [{'offset': hex(i), 'first': x[i], 'second': y[i]}
                 for i in range(len(x)) if x[i] != y[i]]
        comparisons.append({'first': a, 'second': b, 'size': len(x),
                            'raw_equal': not diffs, 'difference_count': len(diffs),
                            'normalization_masks': [], 'differences': diffs})
    exception = section_named(secs, '.gcc_except_table')
    unwind_records, unwind_by_owner = [], {}
    for label, fde in selected_fdes.items():
        if fde['lsda'] is None:
            continue
        sec, offset = mapping(secs, fde['lsda'], 1)
        require(sec['name'] == exception['name'], 'LSDA outside exception table')
        rows = lsda_rows(data, offset, exception['offset'] + exception['size'], fde)
        unwind_by_owner[label] = rows
        for row in rows:
            unwind_records.append((label, hex(fde['lsda']), hex(row['record_file_offset']),
                                   row['raw'].hex(), hex(row['start']), hex(row['end']),
                                   '-' if row['landing'] is None else hex(row['landing']),
                                   row['action']))
    links = []
    for label, owner, site, off, form, raw_hex, target in transfers:
        if owner == 'context' or form not in ('call', 'slotcall', 'slotjump'):
            continue
        address, length = int(site, 16), len(bytes.fromhex(raw_hex))
        matches = [r for r in unwind_by_owner.get(owner, [])
                   if r['start'] <= address and address + length <= r['end']]
        require(len(matches) <= 1, 'overlapping LSDA call-site matches')
        row = matches[0] if matches else None
        links.append((label, owner, site, target,
                      'no_lsda' if owner not in unwind_by_owner else ('matched' if row else 'no_match'),
                      '-' if row is None else hex(row['start']),
                      '-' if row is None else hex(row['end']),
                      '-' if row is None or row['landing'] is None else hex(row['landing']),
                      '-' if row is None else row['action']))
    summary = {'artifact': 'artifacts/node/115/hl-node', 'sha256': SHA115,
               'new_fdes': len(body_rows), 'new_fde_bytes': sum(len(v) for v in body_bytes.values()),
               'context_windows': len(CONTEXT), 'new_windows': len(WINDOWS),
               'selected_transfers': len(transfers), 'selected_operands': len(operands),
               'selected_relocations': len(relocs), 'raw_family_comparisons': len(comparisons),
               'selected_key_copy_projections': len(flow),
               'lsda_call_site_rows': len(unwind_records), 'selected_call_links': len(links),
               'selected_calls_with_lsda_match': sum(row[4] == 'matched' for row in links),
               'limitations': 'Selected static evidence only; FDEs are unwind ranges, not a complete function census.'}
    files = {
        'functions.tsv': tsv(('role', 'start_va', 'end_va_exclusive', 'file_offset', 'size',
                              'fde_va', 'cie_va', 'lsda_va', 'sha256', 'raw_hex'), body_rows),
        'windows.tsv': tsv(('label', 'owner_or_context', 'start_va', 'end_va_exclusive',
                            'file_offset', 'raw_hex'), windows),
        'transfers.tsv': tsv(('label', 'owner_or_context', 'site_va', 'file_offset', 'form',
                              'raw_hex', 'target_va_or_slot'), transfers),
        'operands.tsv': tsv(('label', 'instruction_va', 'file_offset', 'raw_hex', 'value',
                             'value_hex'), operands),
        'key-flow.tsv': tsv(('copy', 'source_space', 'destination_space', 'source_base',
                              'destination_base', 'copy_bytes', 'key_source', 'key_destination',
                              'flag_source', 'flag_destination'), flow),
        'relocations.tsv': tsv(('slot', 'slot_file_offset', 'rela_file_offset', 'type', 'symbol_index',
                                'symbol_name', 'addend'),
                               [tuple(relocs[k][key] for key in ('slot', 'slot_file_offset',
                                'rela_file_offset', 'type', 'symbol_index', 'symbol_name', 'addend'))
                                for k in sorted(relocs)]),
        'unwind.tsv': tsv(('owner', 'lsda_va', 'record_file_offset', 'raw_hex', 'range_start_va',
                           'range_end_va_exclusive', 'landing_va_or_dash', 'action'), unwind_records),
        'unwind-links.tsv': tsv(('label', 'owner', 'call_va', 'target', 'status', 'range_start_va',
                                 'range_end_va_exclusive', 'landing_va_or_dash', 'action'), links),
        'location.json': encoded_json(loc),
        'family-differences.json': encoded_json(comparisons),
        'summary.json': encoded_json(summary),
    }
    return files


def generate(data, out):
    files = extract(data)  # All identity, range and byte checks precede any output.
    out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(files.items()):
        (out / name).write_bytes(content)
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--historical', type=Path, help='optional separately authenticated node #94')
    args = parser.parse_args()
    if args.historical is not None:
        verify_historical(args.historical.read_bytes())
    generate(TARGET.read_bytes(), args.out)


if __name__ == '__main__':
    main()
