#!/usr/bin/env python3
"""Extract selected #115 internal dispatch and batch-state evidence from ELF bytes.

This is a deliberately bounded extractor, not a disassembler or a node emulator.
It never executes the target. Instruction sites were selected by static inspection;
the file, FDE bodies, opcodes, transfers and selected constants are checked again.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct

from elf_index import unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Start, expected half-open FDE end and independent full-body SHA-256.
# These identify *selected* machine-code bodies, not Rust source boundaries.
FUNCTIONS = {
    'subaction_dispatch': (0x2c47660, 0x2c4d2e9, '60f6a969d83d1731dcdf772db78d46517cfaffe2b5e8c380fee66e3910291910'),
    'tag17_handler': (0x2c4d2f0, 0x2c4e2b8, '1c5185cee3ee88627b90d4335e7c2b0c806d84f2070b4b593967db0aed4bae29'),
    'tag17_subpath_entry': (0x2c36770, 0x2c36937, '72534d2d1e3976fc5512e855a37f8642429eb6c3696a75f24baf9f0655cd95e6'),
    'tag17_state_core': (0x2c343b0, 0x2c36328, 'e931996f2c7ee01de255708000674b5ac6d2a03c85f72ec7eb15c041802a930c'),
    'tag17_item_check': (0x2c4eed0, 0x2c4ef9f, '0447d2df18e2320d54966892fdaa3a81fc927fa057840710a7a1d8f6031ec936'),
    'group_collector': (0x2608f40, 0x2609174, '6c3a9ab21de8aa82819125875f73f213df0e4e102505708796ee33374c20d110'),
    'asset_selector': (0x46aac00, 0x46aae2e, '9be82a6d47bf4eedbb4ca8d9f9be69f7bea12c14fc34b8d7972b8e7801868354'),
    'set_insert_adapter': (0x26d59a0, 0x26d5a8c, '76420a0802848c58ad22524231a03101ac3b959cb5123c24cb52972263c55cb6'),
    'set_insert_nonempty': (0x1cb5110, 0x1cb58b7, '7876455cf0bf328a8ff77e8e99068a52b1c860c4c85d30d2ce996f3aab860b23'),
    'batch_core': (0x2c2c470, 0x2c2c5bb, '13c3cfe982c11e4d3e192a4d7e74609bd16cdddd7d8cd3a09f456164660ba7af'),
    'item_conversion': (0x231c580, 0x231c6ac, '1a1e571ce6e815edfd6a51e418f5c665690ac434497922692143c7613b9365cb'),
    'result_allocation': (0x231d1c0, 0x231d2df, '3eb019fcb3b7a6a9e99fd1fd54bc2444f39b332c3df6f4b11868596f12ccdaf4'),
    'item_loop': (0x2704e50, 0x2705063, '9760c8aa9913b2ec4a286a9971ef435f4bd65f8345d087f92da53ce5299d68f4'),
    'item_router': (0x2c6ad70, 0x2c6b3a5, '67867f51c288457b0028d9d8244f69545120e4556e952f4b443065a076f31c87'),
    'zero_finalizer': (0x23ce3e0, 0x23d05fa, 'f368a91f2695393be27d5e8c118f054a5bfeb35385651a5b69e329909d83c0db'),
    'one_finalizer': (0x23d0600, 0x23d278a, '474b529d63960b7e1a07a68047b2451b51582989ca4731dbbc2ac520ccfacca3'),
    'zero_link_clear': (0x23d4140, 0x23d4784, '8f464e112ecf7b078609433d3844ca82cbf7066c0d863cc5b8d4a00dd91fcc1c'),
    'one_link_clear': (0x23d3af0, 0x23d4134, '7841785d04f48cc515ac247ac4fd2c79cdd1f0263932996db692fb78df855c10'),
    'zero_lookup_walk': (0x23cdb30, 0x23cdf69, 'd561d741b6f2c7f7caa935533925b623e36571e7ab4978d764e298755e4bf299'),
    'one_lookup_walk': (0x23cdf70, 0x23ce3d6, 'd7135add3c2487fadd51dc4e71f66d10a465d6258cd6a7443fcaa10842049f0b'),
    'route_zero': (0x2c31910, 0x2c31ad6, '713a403f7bfd852c6dca8fb7a9eccef266046d49a27203e2a957aae66f445ca4'),
    'route_one': (0x2c31ae0, 0x2c31c68, '7290597b900541f682085bd5e458a6cccdc4bd71bf5fe6c8ff356fe09861c272'),
}

# Independently selected instruction windows. Each is wholly inside a selected FDE.
WINDOWS = [
    ('dispatch_entry', 0x2c47690, 30),
    ('dispatch_tag17_first_guard', 0x2c479ad, 26),
    ('dispatch_lookup_result', 0x2c47a0d, 25),
    ('dispatch_second_switch', 0x2c47a3c, 43),
    ('dispatch_tag17_second_arm', 0x2c48325, 26),
    ('dispatch_check_and_resume', 0x2c485b2, 98),
    ('dispatch_third_switch', 0x2c48791, 25),
    ('dispatch_tag17_third_arm', 0x2c492d1, 122),
    ('dispatch_handler_call', 0x2c49f14, 153),
    ('handler_initial_gate', 0x2c4d301, 51),
    ('handler_inner_limit', 0x2c4d418, 36),
    ('handler_item_checks', 0x2c4de2b, 113),
    ('handler_nested_discriminant', 0x2c4d7c5, 52),
    ('handler_nested_switch', 0x2c4d8ed, 28),
    ('handler_nested_arm_zero', 0x2c4d909, 49),
    ('handler_nested_arm_three', 0x2c4dd6b, 68),
    ('subpath_entry_guards', 0x2c36770, 98),
    ('subpath_entry_call_and_error', 0x2c36862, 40),
    ('subpath_index_panic', 0x2c368ee, 46),
    ('state_core_entry', 0x2c343b0, 64),
    ('state_core_save_state', 0x2c3448f, 42),
    ('state_core_restore_state', 0x2c356a0, 8),
    ('state_core_preconditions', 0x2c356d7, 65),
    ('state_core_checked_call', 0x2c3572a, 42),
    ('state_word_increment', 0x2c3578b, 30),
    ('state_word_callback_and_decrement', 0x2c357c7, 49),
    ('item_check_classifier', 0x2c4eed0, 67),
    ('item_check_group_test', 0x2c4ef6f, 48),
    ('preflight_limit', 0x2608f40, 47),
    ('preflight_iterator', 0x2608f85, 90),
    ('preflight_classifier', 0x2608ff1, 58),
    ('preflight_quotient', 0x260901f, 34),
    ('preflight_search', 0x2609048, 103),
    ('preflight_insert', 0x2608fb0, 52),
    ('preflight_result', 0x26090b4, 42),
    ('preflight_errors', 0x26090de, 102),
    ('asset_range_split', 0x46aac17, 15),
    ('asset_high_result', 0x46aacc0, 27),
    ('asset_range_offsets', 0x46aacdb, 62),
    ('asset_low_lookup', 0x46aad08, 55),
    ('asset_low_result', 0x46aadc1, 69),
    ('empty_set_allocate', 0x26d59f9, 75),
    ('existing_set_insert', 0x26d59af, 74),
    ('set_insert_leaf', 0x1cb511e, 98),
    ('batch_limit', 0x2c2c480, 73),
    ('batch_conversion', 0x2c2c4b8, 53),
    ('batch_counter_update', 0x2c2c4e8, 56),
    ('batch_conditional_state', 0x2c2c520, 48),
    ('batch_collect_results', 0x2c2c550, 90),
    ('convert_each_item', 0x231c620, 45),
    ('result_capacity', 0x231d1ce, 48),
    ('result_loop_call', 0x231d26d, 26),
    ('item_loop_head', 0x2704f26, 113),
    ('item_loop_status', 0x2704f87, 43),
    ('item_loop_advance', 0x2704f10, 22),
    ('item_classifier_call', 0x2c6ae16, 55),
    ('item_kind_one_gate', 0x2c6ae68, 45),
    ('item_kind_zero_route', 0x2c6b0fa, 69),
    ('item_kind_one_route', 0x2c6b190, 61),
    ('item_success_counter', 0x2c6b208, 36),
    ('zero_finalizer_link_call', 0x23ce746, 55),
    ('one_finalizer_link_call', 0x23d0977, 53),
    ('zero_link_lookup', 0x23d416f, 65),
    ('zero_link_owner_compare', 0x23d4207, 61),
    ('zero_link_first_clear', 0x23d446d, 28),
    ('zero_link_second_clear', 0x23d4735, 21),
    ('one_link_lookup', 0x23d3b1f, 65),
    ('one_link_owner_compare', 0x23d3bb7, 61),
    ('one_link_first_clear', 0x23d3e1d, 28),
    ('one_link_second_clear', 0x23d40e5, 21),
    ('zero_lookup_initial', 0x23cdb69, 64),
    ('zero_lookup_owner_compare', 0x23cdc06, 61),
    ('zero_lookup_failure', 0x23cde4e, 14),
    ('zero_child_snapshot', 0x23cde68, 70),
    ('zero_child_loop', 0x23cdec0, 42),
    ('zero_final_handoff', 0x23cdefc, 33),
    ('one_lookup_initial', 0x23cdfa6, 66),
    ('one_lookup_owner_compare', 0x23ce053, 55),
    ('one_lookup_failure', 0x23ce2ae, 14),
    ('one_child_snapshot', 0x23ce2cc, 64),
    ('one_child_loop', 0x23ce320, 59),
    ('one_final_handoff', 0x23ce369, 33),
    ('route_zero_call', 0x2c3195c, 24),
    ('route_zero_prepare_status', 0x2c319e7, 28),
    ('route_zero_status', 0x2c319f7, 92),
    ('route_one_call', 0x2c31b4a, 29),
    ('route_one_prepare_status', 0x2c31bc8, 26),
    ('route_one_status', 0x2c31bd5, 47),
]

# Sites are instruction starts chosen by static inspection. Decode only Jcc forms.
BRANCHES = [
    ('dispatch_tag17_first_over_limit', 0x2c479bf, 'a'),
    ('dispatch_lookup_failed', 0x2c47a20, 'ne'),
    ('dispatch_tag17_shape_match', 0x2c4832e, 'e'),
    ('dispatch_initial_predicate', 0x2c48358, 'e'),
    ('dispatch_initial_missing', 0x2c4835d, 'e'),
    ('dispatch_initial_mode', 0x2c48366, 'e'),
    ('dispatch_next_predicate', 0x2c48378, 'ne'),
    ('dispatch_owner_match', 0x2c483d1, 'e'),
    ('dispatch_no_validation_items', 0x2c485d5, 'e'),
    ('dispatch_item_validation_failed', 0x2c485f9, 'ne'),
    ('dispatch_item_validation_same', 0x2c4860b, 'e'),
    ('dispatch_optional_record', 0x2c4864a, 'ne'),
    ('dispatch_tag17_second_under_limit', 0x2c49345, 'b'),
    ('dispatch_no_free', 0x2c49353, 'e'),
    ('handler_initial_state_gate', 0x2c4d320, 'ne'),
    ('handler_inner_under_limit', 0x2c4d424, 'b'),
    ('handler_no_items', 0x2c4de2e, 'e'),
    ('handler_item_check_error', 0x2c4de6f, 'ne'),
    ('handler_item_loop_more', 0x2c4de7f, 'ne'),
    ('nested_other_discriminant', 0x2c4d7f3, 'ne'),
    ('nested_parent_lookup_failed', 0x2c4d8ef, 'e'),
    ('nested_arm_zero_under_limit', 0x2c4d934, 'be'),
    ('nested_call_failed', 0x2c4dda9, 'ne'),
    ('subpath_index_out_of_range', 0x2c3678d, 'ae'),
    ('subpath_batch_too_large', 0x2c367bf, 'ae'),
    ('subpath_precheck_failed', 0x2c367f3, 'ne'),
    ('state_core_type_other', 0x2c356e6, 'ne'),
    ('state_core_flag_set', 0x2c356f4, 'e'),
    ('state_core_precheck_failed', 0x2c3573c, 'ne'),
    ('item_check_classifier_error', 0x2c4ef02, 'ne'),
    ('item_check_kind_not_one', 0x2c4ef09, 'ne'),
    ('item_check_group_mismatch', 0x2c4ef8b, 'ne'),
    ('preflight_too_large_fallthrough', 0x2608f5f, 'b'),
    ('preflight_empty_batch', 0x2608f88, 'e'),
    ('preflight_classifier_error', 0x260900e, 'ne'),
    ('preflight_kind_one_error', 0x2609019, 'e'),
    ('preflight_search_continue', 0x260907d, 'e'),
    ('preflight_duplicate_skip', 0x2609085, 'e'),
    ('preflight_loop_done', 0x2608feb, 'e'),
    ('asset_range_first', 0x46aac1d, 'be'),
    ('asset_lookup_absent', 0x46aac36, 'e'),
    ('asset_lookup_bound', 0x46aac4f, 'ae'),
    ('asset_mismatch', 0x46aacc3, 'ne'),
    ('asset_lower_boundary', 0x46aace1, 'b'),
    ('asset_middle_boundary', 0x46aace9, 'ae'),
    ('asset_group_absent', 0x46aad1a, 'be'),
    ('asset_member_absent', 0x46aadd8, 'be'),
    ('insert_empty_root', 0x26d59b4, 'e'),
    ('insert_allocation_failed', 0x26d5a0a, 'e'),
    ('insert_bounds_failure', 0x26d5a2c, 'ae'),
    ('insert_leaf_split', 0x1cb512c, 'ae'),
    ('insert_leaf_at_end', 0x1cb5139, 'a'),
    ('batch_limit', 0x2c2c498, 'b'),
    ('batch_large_deallocation', 0x2c2c49d, 'e'),
    ('batch_first_predicate', 0x2c2c52b, 'ne'),
    ('batch_second_predicate', 0x2c2c538, 'e'),
    ('convert_size_guard', 0x231c5bc, 'e'),
    ('convert_empty', 0x231c5ce, 'e'),
    ('convert_alloc_failed', 0x231c601, 'e'),
    ('convert_loop_empty', 0x231c614, 'e'),
    ('convert_loop_more', 0x231c64b, 'ne'),
    ('result_allocation_empty', 0x231d200, 'e'),
    ('result_allocation_nonnull', 0x231d211, 'ne'),
    ('item_loop_empty', 0x2704e7a, 'e'),
    ('item_loop_success', 0x2704f99, 'e'),
    ('item_loop_last', 0x2704f20, 'e'),
    ('item_selector_error', 0x2c6ae42, 'ne'),
    ('item_kind_zero', 0x2c6ae6c, 'ne'),
    ('item_kind_one_allowed', 0x2c6ae7a, 'e'),
    ('item_key_mode', 0x2c6af7f, 'ne'),
    ('item_second_gate', 0x2c6b004, 'ne'),
    ('item_observer_present', 0x2c6b151, 'ne'),
    ('item_precheck_zero_failed', 0x2c6b117, 'ne'),
    ('item_precheck_failed', 0x2c6b1aa, 'ne'),
    ('item_observer_absent', 0x2c6b1df, 'e'),
    ('item_failure_no_counter', 0x2c6b20e, 'ne'),
    ('zero_link_owner_mismatch', 0x23d4238, 'ne'),
    ('zero_link_tag_not_one', 0x23d447f, 'ne'),
    ('zero_link_peer_empty', 0x23d4491, 'e'),
    ('zero_link_peer_mismatch', 0x23d4548, 'ne'),
    ('one_link_owner_mismatch', 0x23d3be8, 'ne'),
    ('one_link_tag_not_one', 0x23d3e2f, 'ne'),
    ('one_link_peer_empty', 0x23d3e41, 'e'),
    ('one_link_peer_mismatch', 0x23d3ef8, 'ne'),
    ('zero_lookup_empty_fast', 0x23cdb75, 'e'),
    ('zero_lookup_multi_fast', 0x23cdb7f, 'ne'),
    ('zero_lookup_single_miss', 0x23cdb89, 'ne'),
    ('zero_lookup_hash_bounds', 0x23cdbce, 'ae'),
    ('zero_lookup_record_bounds', 0x23cdbe8, 'ae'),
    ('zero_lookup_tombstone', 0x23cdc00, 'e'),
    ('zero_lookup_owner_mismatch', 0x23cdc37, 'ne'),
    ('zero_compact_key_miss', 0x23cdd4e, 'ne'),
    ('zero_compact_bounds', 0x23cdd5b, 'ae'),
    ('zero_compact_item_miss', 0x23cde22, 'ne'),
    ('zero_compact_item_bounds', 0x23cde28, 'ae'),
    ('zero_no_children', 0x23cde7c, 'e'),
    ('zero_child_allocation_failure', 0x23cde8e, 'e'),
    ('zero_child_loop_done', 0x23cdec3, 'e'),
    ('zero_no_child_free', 0x23cdeec, 'e'),
    ('one_lookup_empty_fast', 0x23cdfb2, 'e'),
    ('one_lookup_multi_fast', 0x23cdfbc, 'ne'),
    ('one_lookup_single_miss', 0x23cdfc6, 'ne'),
    ('one_lookup_hash_bounds', 0x23ce018, 'ae'),
    ('one_lookup_tombstone', 0x23ce04d, 'e'),
    ('one_lookup_owner_mismatch', 0x23ce084, 'ne'),
    ('one_compact_key_miss', 0x23ce1ae, 'ne'),
    ('one_compact_bounds', 0x23ce1bb, 'ae'),
    ('one_compact_item_miss', 0x23ce282, 'ne'),
    ('one_compact_item_bounds', 0x23ce288, 'ae'),
    ('one_no_children', 0x23ce2d7, 'e'),
    ('one_child_allocation_failure', 0x23ce2f1, 'e'),
    ('one_child_loop_more', 0x23ce359, 'ne'),
    ('route_zero_outcome', 0x2c31a04, 'e'),
    ('route_one_outcome', 0x2c31bdd, 'e'),
]

# Call targets are validated, with selected RIP slots resolved from .rela.dyn.
CALLS = [
    ('dispatch_initial_lookup', 0x2c47a0d, 0x446af70),
    ('dispatch_to_tag17_handler', 0x2c49fa8, 0x2c4d2f0),
    ('subpath_prepare', 0x2c367e3, 0x3c4a730),
    ('handler_item_check', 0x2c4de60, 0x2c4eed0),
    ('nested_to_subpath', 0x2c4dd9d, 0x2c36770),
    ('subpath_to_state_core', 0x2c36878, 0x2c343b0),
    ('state_core_callback', 0x2c357e3, 0x2c36af0),
    ('item_check_to_asset', 0x2c4eef3, 0x46aac00),
    ('preflight_to_asset', 0x2608ffe, 0x46aac00),
    ('preflight_to_insert', 0x2608fdf, 0x26d59a0),
    ('insert_to_nonempty', 0x26d59e0, 0x1cb5110),
    ('batch_to_conversion', 0x2c2c4e3, 0x231c580),
    ('batch_to_result_allocation', 0x2c2c59b, 0x231d1c0),
    ('allocation_to_item_loop', 0x231d27c, 0x2704e50),
    ('loop_to_item_router', 0x2704f87, 0x2c6ad70),
    ('router_to_asset', 0x2c6ae2f, 0x46aac00),
    ('router_to_zero', 0x2c6b13a, 0x2c31910),
    ('router_to_one', 0x2c6b1c8, 0x2c31ae0),
    ('zero_external_handoff', 0x2c3196b, 0x23cdb30),
    ('zero_fast_lookup', 0x23cdbc2, 0x26f5c10),
    ('zero_child_walk', 0x23cdee2, 0x23cdb30),
    ('zero_finalizer', 0x23cdf16, 0x23ce3e0),
    ('zero_finalizer_to_link_clear', 0x23ce773, 0x23d4140),
    ('one_fast_lookup', 0x23ce005, 0x26f5c10),
    ('one_child_walk', 0x23ce34d, 0x23cdf70),
    ('one_finalizer', 0x23ce383, 0x23d0600),
    ('one_finalizer_to_link_clear', 0x23d09a7, 0x23d3af0),
    ('one_external_handoff', 0x2c31b5f, 0x23cdf70),
]

# Immediate values and displacements are decoded from the selected instructions.
# Each prefix is fixed, and the extraction is confined to the owning FDE.
CONSTANTS = [
    ('dispatch_tag17_payload_offset', 0x2c479ad, 'bd', 4, False),
    ('dispatch_tag17_count_relative_offset', 0x2c479b6, '498b4c28', 1, False),
    ('dispatch_tag17_count_absolute_offset', 0x2c492dc, '498b9a', 4, False),
    ('dispatch_first_over_limit_status', 0x2c479a3, '6641bd', 2, False),
    ('handler_state_byte_offset', 0x2c4d311, '80be', 4, False),
    ('handler_state_failure_status', 0x2c4d322, '6641c74610', 2, False),
    ('dispatch_tag17_first_limit_inclusive', 0x2c479bb, '4883f9', 1, False),
    ('dispatch_tag17_second_limit_exclusive', 0x2c49341, '4883fb', 1, False),
    ('dispatch_tag17_over_limit_status', 0x2c49361, '6641c74610', 2, False),
    ('handler_inner_limit', 0x2c4d418, '4881bc24b8000000', 4, False),
    ('nested_switch_bias', 0x2c4d8f5, '4983c5', 1, True),
    ('nested_arm_zero_limit_inclusive', 0x2c4d92d, '4981ff', 4, False),
    ('subpath_context_bound_offset', 0x2c36786, '483b8e', 4, False),
    ('subpath_limit_exclusive', 0x2c367ba, '48837d10', 1, False),
    ('subpath_limit_status', 0x2c3687f, '66c703', 2, False),
    ('state_core_word_offset', 0x2c35793, '498b47', 1, False),
    ('state_core_decrement_offset', 0x2c357e8, '498b46', 1, False),
    ('handler_inner_limit_status', 0x2c4d42a, '6641bd', 2, False),
    ('item_check_success_compare', 0x2c4eefd, '3d', 4, False),
    ('item_check_forbidden_kind', 0x2c4ef04, '837c2408', 1, False),
    ('item_check_forbidden_status', 0x2c4ef0b, '66c703', 2, False),
    ('item_check_multiplier', 0x2c4ef74, '48ba', 8, False),
    ('item_check_shift', 0x2c4ef84, '48c1ea', 1, False),
    ('item_check_wrong_group_status', 0x2c4ef98, '66c703', 2, False),
    ('preflight_limit', 0x2608f58, '4881fd', 4, False),
    ('preflight_length_status', 0x2608f61, '66c703', 2, False),
    ('preflight_success_status', 0x26090d7, '66c703', 2, False),
    ('preflight_kind_one_status', 0x2609135, '66c703', 2, False),
    ('input_record_stride', 0x2608fe4, '4983c5', 1, False),
    ('input_item_field_offset', 0x2608ff1, '418b75', 1, False),
    ('quotient_multiplier', 0x2609024, '48b9', 8, False),
    ('quotient_high_shift', 0x2609031, '48c1ea', 1, False),
    ('set_initial_allocation_bytes', 0x26d59fc, 'bf', 4, False),
    ('set_node_capacity', 0x26d5a28, '4883f9', 1, False),
    ('set_size_field_offset', 0x26d5a40, '49ff47', 1, False),
    ('set_node_count_offset', 0x1cb5124, '0fb75d', 1, False),
    ('conversion_input_stride', 0x231c644, '4883c0', 1, False),
    ('conversion_key_mode', 0x231c62e, '41c6444708', 1, False),
    ('conversion_order_field_offset', 0x231c634, '49894c47', 1, False),
    ('result_entry_stride', 0x231d1dd, '496bf7', 1, False),
    ('batch_counter_offset', 0x2c2c4fb, '498b87', 4, False),
    ('success_counter_offset', 0x2c6b210, '498b87', 4, False),
    ('kind_one_gate_offset', 0x2c6ae72, '4180bf', 4, False),
    ('kind_one_gate_status', 0x2c6ae80, '66c78424a0000000', 2, False),
    ('item_lookup_failure_status', 0x2c6b15e, '66c7842410010000', 2, False),
    ('item_success_status', 0x2c6b208, '81fd', 4, False),
    ('zero_first_clear_value', 0x23d4474, '48c74020', 4, False),
    ('zero_first_link_kind', 0x23d447c, '83f9', 1, False),
    ('zero_second_clear_value', 0x23d4741, '48c74020', 4, False),
    ('one_first_clear_value', 0x23d3e24, '48c74020', 4, False),
    ('one_first_link_kind', 0x23d3e2c, '83f9', 1, False),
    ('one_second_clear_value', 0x23d40f1, '48c74020', 4, False),
    ('zero_lookup_key_count_offset', 0x23cdb69, '488b5f', 1, False),
    ('zero_lookup_record_stride', 0x23cdbf5, '4869c9', 4, False),
    ('zero_lookup_key_bytes', 0x23cdcc9, 'ba', 4, False),
    ('zero_child_stride', 0x23cdec9, '4983c7', 1, False),
    ('zero_walk_success_code', 0x23cdf1b, 'b0', 1, False),
    ('one_child_stride', 0x23ce352, '4983c5', 1, False),
    ('one_walk_success_code', 0x23ce388, 'b0', 1, False),
    ('route_zero_accepted_variant', 0x2c319fb, '4080fd', 1, False),
    ('route_one_accepted_variant', 0x2c31bd9, '4080fd', 1, False),
    ('asset_upper_first_range', 0x46aac17, '81fe', 4, False),
    ('asset_low_boundary', 0x46aacdb, '81fe', 4, False),
    ('asset_middle_boundary', 0x46aace3, '81fe', 4, False),
    ('asset_middle_adjustment', 0x46aaceb, '4981c6', 4, True),
    ('asset_high_adjustment', 0x46aad01, '4981c6', 4, True),
    ('asset_divide_multiplier', 0x46aad08, '41bf', 4, False),
    ('asset_divide_shift', 0x46aad12, '49c1ef', 1, False),
    ('asset_group_error_status', 0x46aadf7, '66c703', 2, False),
    ('asset_lookup_error_status', 0x46aacf7, '66c703', 2, False),
    ('item_result_stride', 0x2704f13, '4983c6', 1, False),
    ('item_input_stride', 0x2704f17, '4883c3', 1, False),
    ('execution_limit', 0x2c2c491, '4981fd', 4, False),
]

JCC = {0x2: 'b', 0x3: 'ae', 0x4: 'e', 0x5: 'ne', 0x6: 'be', 0x7: 'a'}


def verify_digest(data):
    actual = hashlib.sha256(data).hexdigest()
    if actual != SHA256:
        raise ValueError('node #115 SHA-256 mismatch')
    return actual


def file_offset(secs, va, length):
    if not isinstance(va, int) or not isinstance(length, int) or va < 0 or length <= 0:
        raise ValueError('invalid virtual-address range')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('range is not in exactly one file-backed section')
    sec = matches[0]
    return sec['offset'] + va - sec['address']


def at(data, secs, va, length):
    off = file_offset(secs, va, length)
    result = data[off:off + length]
    if len(result) != length:
        raise ValueError('truncated file-backed address range')
    return result


def u32(data, secs, va):
    return struct.unpack('<I', at(data, secs, va, 4))[0]


def u64(data, secs, va):
    return struct.unpack('<Q', at(data, secs, va, 8))[0]


def lea_target(data, secs, site):
    code = at(data, secs, site, 7)
    if code[:3] not in (b'\x48\x8d\x05', b'\x48\x8d\x0d', b'\x48\x8d\x3d'):
        raise ValueError('unexpected selected RIP-relative lea')
    return site + 7 + struct.unpack('<i', code[3:])[0]


def table_target(data, secs, table, index, expected=None):
    if not isinstance(index, int) or not 0 <= index < 18:
        raise ValueError('selected ordinal outside extractor scope')
    raw = at(data, secs, table + index * 4, 4)
    target = table + struct.unpack('<i', raw)[0]
    if expected is not None and target != expected:
        raise ValueError('selected jump-table target mismatch')
    return target


def branch(data, secs, site, condition=None, target=None):
    first = at(data, secs, site, 2)
    if 0x70 <= first[0] <= 0x7f:
        opcode, length, displacement = first[0] & 0xf, 2, struct.unpack('<b', first[1:])[0]
    elif first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
        opcode, length = first[1] & 0xf, 6
        displacement = struct.unpack('<i', at(data, secs, site + 2, 4))[0]
    else:
        raise ValueError('selected site is not a supported conditional branch')
    kind = JCC.get(opcode)
    if kind is None or (condition is not None and kind != condition):
        raise ValueError('selected conditional branch has an unexpected condition')
    dest = site + length + displacement
    if target is not None and target != dest:
        raise ValueError('selected conditional branch target mismatch')
    return kind, dest, at(data, secs, site, length)


def relocs(data, secs):
    matches = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(matches) != 1 or matches[0]['size'] % 24:
        raise ValueError('missing or invalid dynamic relocation section')
    s = matches[0]
    result = {}
    for pos in range(s['offset'], s['offset'] + s['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot in result:
            raise ValueError('duplicate dynamic relocation target')
        result[slot] = (info, addend, pos)
    return result


def call(data, secs, relocations, site, expected=None):
    op = at(data, secs, site, 2)
    if op[:1] == b'\xe8':
        raw = at(data, secs, site, 5)
        dest = site + 5 + struct.unpack('<i', raw[1:])[0]
        kind, slot = 'rel32', None
    elif op == b'\xff\x15':
        raw = at(data, secs, site, 6)
        slot = site + 6 + struct.unpack('<i', raw[2:])[0]
        record = relocations.get(slot)
        if record is None or record[0] != 8:
            raise ValueError('RIP-slot call lacks a unique R_X86_64_RELATIVE record')
        kind, dest = 'relative_slot', record[1]
    else:
        raise ValueError('selected site is not a supported direct or RIP-slot call')
    if expected is not None and dest != expected:
        raise ValueError('selected call target mismatch')
    return kind, dest, slot, raw


def checked_functions(data, secs, index, fdes):
    indexed = {x['start']: x for x in index}
    result = {}
    for name, (start, expected_end, digest) in FUNCTIONS.items():
        found = [f for f in fdes if f['start'] == start]
        if len(found) != 1 or start not in indexed:
            raise ValueError('selected start does not have one indexed FDE')
        fde = found[0]
        if fde['fde'] != indexed[start]['fde'] or fde['end'] != expected_end:
            raise ValueError('selected FDE bounds or header reference mismatch')
        raw = at(data, secs, start, fde['end'] - start)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('selected FDE body hash mismatch')
        result[name] = fde
    return result


def within_function(site, size, selected):
    found = [name for name, f in selected.items() if f['start'] <= site and site + size <= f['end']]
    if len(found) != 1:
        raise ValueError('selected window is not inside one selected FDE')
    return found[0]


def divide_magic(value, multiplier):
    if not isinstance(value, int) or not 0 <= value <= 0xffffffff:
        raise ValueError('selected quotient model requires a u32')
    return (value * multiplier) >> 75


def candidate_partition(value, low, middle, high):
    """Model the four range branches before state-dependent lookup."""
    if not isinstance(value, int) or not 0 <= value <= 0xffffffff:
        raise ValueError('candidate input is not a u32')
    if value < low:
        return 0, value
    if value < middle:
        return 1, value - low
    if value < high:
        return 0, value - (middle - low)
    return 1, value


def item_check_model(status, kind, candidate, expected_group, success, forbidden, wrong_group, magic):
    """Abstract normal-return classifier check; classification is supplied."""
    if status != success:
        return status, None
    if kind == 1:
        return forbidden, None
    if kind != 0:
        raise ValueError('classifier kind outside selected normal outcomes')
    if not isinstance(expected_group, int) or not 0 <= expected_group < 1 << 64:
        raise ValueError('expected group is not a u64')
    if divide_magic(candidate, magic) != expected_group:
        return wrong_group, None
    return success, candidate


def preflight_model(length, items, limit, success, forbidden, magic):
    """Abstract normal-return model, with classifier outputs supplied by caller."""
    if not isinstance(length, int) or length < 0:
        raise ValueError('invalid length')
    if length >= limit:
        return 0x158, ()
    if length != len(items):
        raise ValueError('synthetic item count mismatch')
    keys = set()
    for status, kind, value in items:
        if status != success:
            return status, ()
        if kind == 1:
            return forbidden, ()
        if kind != 0:
            raise ValueError('classifier kind outside the selected normal outcomes')
        keys.add(divide_magic(value, magic))
    return success, tuple(sorted(keys))


def walk_model(root, graph):
    """Model selected snapshot-first child ordering on a finite acyclic fixture."""
    trace = []
    def visit(key):
        if key not in graph:
            return 0
        children = tuple(graph[key])
        for child in children:
            visit(child)  # The observed caller does not branch on the child return.
        trace.append(key)  # Finalizer invocation, not proof of committed state.
        return 2
    return visit(root), tuple(trace)


def clear_model(found_first, first_word, found_second, second_word):
    """Model two selected normal-return stores, with lookups supplied as inputs."""
    if not isinstance(first_word, int) or not isinstance(second_word, int):
        raise ValueError('link word is not an integer')
    if not (0 <= first_word < 1 << 64 and 0 <= second_word < 1 << 64):
        raise ValueError('link word is not a u64')
    if not found_first:
        return first_word, second_word
    old_kind = first_word & 0xffffffff
    return 0, 0 if old_kind == 1 and found_second else second_word


def guarded_state_word_model(before, after_callback):
    """Model the two selected stores with the intervening callback word supplied."""
    maximum = (1 << 64) - 1
    if any(not isinstance(v, int) or not 0 <= v <= maximum for v in (before, after_callback)):
        raise ValueError('state word is not a u64')
    return min(maximum, before + 1), max(0, after_callback - 1)


def counter_model(length, old_batch, old_success, successful, limit, success):
    """Abstract normal-return counter model; item statuses are caller inputs."""
    maximum = (1 << 64) - 1
    if any(not isinstance(v, int) or v < 0 for v in (length, old_batch, old_success, successful)):
        raise ValueError('invalid counter input')
    if old_batch > maximum or old_success > maximum or successful > length:
        raise ValueError('counter input outside model domain')
    if length >= limit:
        return 0x158, old_batch, old_success
    return success, min(maximum, old_batch + length), min(maximum, old_success + successful)


def emit_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def build(data):
    digest = verify_digest(data)
    secs, index = unwind_index(data)
    _, all_fdes = eh_frame_records(data, secs)
    selected = checked_functions(data, secs, index, all_fdes)
    relocation_map = relocs(data, secs)

    # One-byte internal dispatch tag; its relationship to Action tags is unresolved.
    dispatch_tables = (lea_target(data, secs, 0x2c47699),
                       lea_target(data, secs, 0x2c47a4a),
                       lea_target(data, secs, 0x2c4879a))
    if dispatch_tables != (0x60a7a8, 0x60a800, 0x60a848):
        raise ValueError('selected internal dispatch tables differ')
    nested_table = lea_target(data, secs, 0x2c4d8f9)
    if nested_table != 0x60ae4c:
        raise ValueError('selected nested table differs')
    table_target(data, secs, nested_table, 0, 0x2c4d909)
    table_target(data, secs, nested_table, 3, 0x2c4dd6b)
    expected_arms = (0x2c479ad, 0x2c48325, 0x2c492d1)
    for table, expected in zip(dispatch_tables, expected_arms):
        table_target(data, secs, table, 17, expected)
    first_limit = at(data, secs, 0x2c479be, 1)[0]
    second_limit = at(data, secs, 0x2c49344, 1)[0]
    if first_limit != 100 or second_limit != first_limit + 1:
        raise ValueError('dispatch length comparisons differ')

    if at(data, secs, 0x2608f58, 3) != b'\x48\x81\xfd':
        raise ValueError('batch comparison opcode mismatch')
    limit = u32(data, secs, 0x2608f5b)
    if at(data, secs, 0x2c2c491, 3) != b'\x49\x81\xfd' or u32(data, secs, 0x2c2c494) != limit:
        raise ValueError('batch limits do not match')
    if at(data, secs, 0x2609024, 2) != b'\x48\xb9':
        raise ValueError('quotient multiplier opcode mismatch')
    magic = u64(data, secs, 0x2609026)
    if (limit, magic) != (10001, 0x346dc5d63886594b):
        raise ValueError('selected constant mismatch')
    success = struct.unpack('<H', at(data, secs, 0x26090da, 2))[0]
    forbidden = struct.unpack('<H', at(data, secs, 0x2609138, 2))[0]
    too_large = struct.unpack('<H', at(data, secs, 0x2608f64, 2))[0]
    if (success, forbidden, too_large) != (0x1a2, 0x174, 0x158):
        raise ValueError('selected status immediate mismatch')

    function_rows, body_rows = [], []
    for name, f in selected.items():
        raw = at(data, secs, f['start'], f['end'] - f['start'])
        function_rows.append((name, hex(f['start']), hex(f['end']), len(raw), hex(f['fde']),
                              hex(f['cie']), '' if f['lsda'] is None else hex(f['lsda']),
                              hex(file_offset(secs, f['start'], len(raw))), hashlib.sha256(raw).hexdigest()))
        body_rows.append((name, hex(f['start']), raw.hex()))

    window_rows = []
    for label, site, size in WINDOWS:
        owner = within_function(site, size, selected)
        raw = at(data, secs, site, size)
        window_rows.append((label, owner, hex(site), hex(file_offset(secs, site, size)), size, raw.hex()))

    branch_rows = []
    for label, site, expected in BRANCHES:
        kind, dest, raw = branch(data, secs, site, expected)
        owner = within_function(site, len(raw), selected)
        branch_rows.append((label, owner, hex(site), hex(file_offset(secs, site, len(raw))), raw.hex(), kind, hex(dest)))

    call_rows, slots = [], set()
    for label, site, expected in CALLS:
        kind, dest, slot, raw = call(data, secs, relocation_map, site, expected)
        owner = within_function(site, len(raw), selected)
        call_rows.append((label, owner, hex(site), hex(file_offset(secs, site, len(raw))), raw.hex(), kind,
                          '' if slot is None else hex(slot), hex(dest)))
        if slot is not None:
            slots.add(slot)
    relocation_rows = []
    for slot in sorted(slots):
        info, addend, pos = relocation_map[slot]
        relocation_rows.append((hex(slot), hex(info), hex(addend), hex(pos), data[pos:pos + 24].hex()))

    constant_rows = []
    for label, site, prefix_hex, width, signed in CONSTANTS:
        prefix = bytes.fromhex(prefix_hex)
        whole = at(data, secs, site, len(prefix) + width)
        if not whole.startswith(prefix):
            raise ValueError('selected immediate opcode mismatch')
        owner = within_function(site, len(whole), selected)
        value = int.from_bytes(whole[len(prefix):], 'little', signed=signed)
        constant_rows.append((label, owner, hex(site), hex(file_offset(secs, site, len(whole))),
                              whole.hex(), str(signed).lower(), value))

    table_rows = []
    for label, table in zip(('entry', 'validation', 'resume'), dispatch_tables):
        ordinal = 17
        entry = table + 4 * ordinal
        target = table_target(data, secs, table, ordinal)
        if within_function(target, 1, selected) != 'subaction_dispatch':
            raise ValueError('selected table target not in expected FDE')
        table_rows.append((label, hex(table), ordinal, hex(entry), hex(file_offset(secs, entry, 4)),
                           at(data, secs, entry, 4).hex(), hex(target)))
    for ordinal in (0, 3):
        nested_entry = nested_table + 4 * ordinal
        nested_target = table_target(data, secs, nested_table, ordinal)
        if within_function(nested_target, 1, selected) != 'tag17_handler':
            raise ValueError('nested target not in expected FDE')
        table_rows.append(('nested_index_' + str(ordinal), hex(nested_table), ordinal, hex(nested_entry),
                           hex(file_offset(secs, nested_entry, 4)),
                           at(data, secs, nested_entry, 4).hex(), hex(nested_target)))
    dispatch_vectors = [(length, str(length <= first_limit).lower(),
                         str(length < second_limit).lower())
                        for length in (0, 1, first_limit - 1, first_limit,
                                       second_limit, second_limit + 1)]

    low = u32(data, secs, 0x46aacdd)
    middle = u32(data, secs, 0x46aace5)
    high = u32(data, secs, 0x46aac19) + 1
    group_magic = u32(data, secs, 0x46aad0a)
    group_shift = at(data, secs, 0x46aad15, 1)[0]
    if (low, middle, high, group_magic, group_shift) != (10000, 110000, 100000000, 0xd1b71759, 45):
        raise ValueError('selected asset range or quotient instruction mismatch')
    partition_rows = []
    partition_values = {0, 0xffffffff}
    for boundary in (low, middle, high):
        partition_values.update((boundary - 1, boundary, boundary + 1))
    for value in sorted(partition_values):
        kind, candidate = candidate_partition(value, low, middle, high)
        partition_rows.append((value, kind, candidate,
                               candidate * group_magic >> group_shift if kind == 0 else '',
                               candidate // low if kind == 0 else ''))
    values = {0, 1, 99899999, 0xffffffff}
    for quotient in (0, 1, 2, 9, 10, 100, 999, 9990, 429496):
        for delta in (-1, 0, 1):
            value = quotient * 10000 + delta
            if 0 <= value <= 0xffffffff:
                values.add(value)
    values = sorted(values)
    quotient_rows = [(v, hex(magic), divide_magic(v, magic), v // 10000) for v in values]
    for v, _, actual, reference in quotient_rows:
        if actual != reference:
            raise ValueError('selected quotient vectors disagree with integer division')
    check_wrong_group = struct.unpack('<H', at(data, secs, 0x2c4ef9b, 2))[0]
    if check_wrong_group != 0x156 or u64(data, secs, 0x2c4ef76) != magic:
        raise ValueError('selected item-check immediates mismatch')
    check_cases = [(success, 0, 9999, 0), (success, 0, 10000, 1),
                   (success, 0, 10000, 0), (success, 1, 0, 0),
                   (0x64, 0, 0, 0), (success, 0, 0xffffffff, 429496)]
    check_rows = []
    for status, kind, candidate, expected_group in check_cases:
        out_status, out_candidate = item_check_model(status, kind, candidate, expected_group,
                                                      success, forbidden, check_wrong_group, magic)
        check_rows.append((hex(status), kind, candidate, expected_group, hex(out_status),
                           '' if out_candidate is None else out_candidate))
    preflight_cases = [
        ('empty', []),
        ('single', [(success, 0, 0)]),
        ('same_group', [(success, 0, 1), (success, 0, 9999)]),
        ('two_groups', [(success, 0, 9999), (success, 0, 10000)]),
        ('unordered_groups', [(success, 0, 20000), (success, 0, 1), (success, 0, 20001)]),
        ('classified_error', [(success, 0, 1), (0x64, 0, 0)]),
        ('kind_one', [(success, 0, 1), (success, 1, 0)]),
    ]
    preflight_rows = []
    for label, items in preflight_cases:
        status, keys = preflight_model(len(items), items, limit, success, forbidden, magic)
        preflight_rows.append((label, len(items), json.dumps(items, separators=(',', ':')),
                               hex(status), ','.join(str(x) for x in keys)))
    boundary_rows = []
    repeat_item = (success, 0, 10000)
    for count in (0, limit - 1, limit, limit + 1):
        # For the rejected sizes the first guard does not inspect the supplied items.
        items = [repeat_item] * min(count, limit - 1)
        status, keys = preflight_model(count, items, limit, success, forbidden, magic)
        boundary_rows.append((count, str(repeat_item), hex(status), ','.join(str(k) for k in keys)))
    clear_rows = []
    for found_first in (False, True):
        for first in (0, 1, 2, (1 << 32) + 1):
            for found_second in (False, True):
                after_first, after_second = clear_model(found_first, first, found_second, 99)
                clear_rows.append((str(found_first).lower(), first, str(found_second).lower(), 99,
                                   after_first, after_second))
    walk_cases = [
        ('missing_root', 1, {}),
        ('single', 1, {1: []}),
        ('chain', 1, {1: [2], 2: [3], 3: []}),
        ('branch', 1, {1: [2, 3], 2: [4], 3: [], 4: []}),
        ('missing_child', 1, {1: [2, 3], 2: [4], 4: []}),
    ]
    walk_rows = []
    for label, root, graph in walk_cases:
        code, trace = walk_model(root, graph)
        walk_rows.append((label, root, json.dumps(graph, sort_keys=True, separators=(',', ':')),
                          code, ','.join(str(x) for x in trace)))
    maximum = (1 << 64) - 1
    state_word_rows = []
    for before in (0, 1, 10, maximum - 1, maximum):
        incremented = min(maximum, before + 1)
        for after_callback in sorted({0, incremented, maximum}):
            first_store, second_store = guarded_state_word_model(before, after_callback)
            state_word_rows.append((before, after_callback, first_store, second_store))
    counter_rows = []
    for count in (0, 1, limit - 1, limit, limit + 1):
        for before in (0, maximum - 1, maximum):
            for successful in sorted({0, min(count, 2)}):
                status, total, done = counter_model(count, before, before, successful, limit, success)
                counter_rows.append((count, before, before, successful, hex(status), total, done))
    summary = {
        'artifact_sha256': digest,
        'coordinate_system': 'linked ELF virtual address; file offsets are zero based',
        'selected_fde_count': len(function_rows),
        'selected_window_count': len(window_rows),
        'selected_branch_count': len(branch_rows),
        'selected_call_count': len(call_rows),
        'selected_relocation_count': len(relocation_rows),
        'selected_constant_count': len(constant_rows),
        'selected_table_entry_count': len(table_rows),
        'selected_internal_tag': 17,
        'dispatch_limit_inclusive': first_limit,
        'dispatch_limit_vector_count': len(dispatch_vectors),
        'batch_limit_exclusive': limit, 'success_word': success,
        'preflight_kind_one_word': forbidden, 'batch_too_large_word': too_large,
        'quotient_multiplier': hex(magic),
        'quotient_vector_count': len(quotient_rows),
        'asset_partition_vector_count': len(partition_rows),
        'item_check_vector_count': len(check_rows),
        'preflight_vector_count': len(preflight_rows),
        'preflight_limit_vector_count': len(boundary_rows),
        'counter_vector_count': len(counter_rows),
        'guarded_state_word_vector_count': len(state_word_rows),
        'walk_vector_count': len(walk_rows),
        'clear_vector_count': len(clear_rows),
        'caveat': 'Selected facts and synthetic models only; no captured code is executed.',
    }
    return {
        'summary.json': summary,
        'functions.tsv': (['role', 'start_va', 'end_va_exclusive', 'bytes', 'fde_va', 'cie_va', 'lsda_va', 'file_offset', 'sha256'], function_rows),
        'bodies.tsv': (['role', 'start_va', 'body_hex'], body_rows),
        'windows.tsv': (['label', 'owner', 'va', 'file_offset', 'length', 'bytes_hex'], window_rows),
        'branches.tsv': (['label', 'owner', 'site_va', 'file_offset', 'bytes_hex', 'condition', 'target_va'], branch_rows),
        'calls.tsv': (['label', 'owner', 'site_va', 'file_offset', 'bytes_hex', 'kind', 'slot_va', 'target_va'], call_rows),
        'relocations.tsv': (['slot_va', 'info', 'addend_va', 'record_file_offset', 'record_hex'], relocation_rows),
        'tables.tsv': (['label', 'table_va', 'ordinal', 'entry_va', 'file_offset', 'entry_hex', 'target_va'], table_rows),
        'dispatch-limit-vectors.tsv': (['synthetic_length', 'first_guard_pass', 'second_guard_pass'], dispatch_vectors),
        'constants.tsv': (['label', 'owner', 'instruction_va', 'file_offset', 'bytes_hex', 'signed', 'value'], constant_rows),
        'asset-partition-vectors.tsv': (['u32_input', 'prelookup_path', 'prelookup_value', 'kind_zero_multiply_shift', 'kind_zero_integer_quotient'], partition_rows),
        'quotient-vectors.tsv': (['u32_input', 'multiplier', 'multiply_shift', 'integer_division'], quotient_rows),
        'item-check-vectors.tsv': (['synthetic_classifier_status', 'synthetic_kind', 'synthetic_candidate', 'synthetic_expected_group', 'model_status', 'model_candidate'], check_rows),
        'preflight-vectors.tsv': (['case', 'length', 'synthetic_classifier_results', 'model_status', 'model_sorted_keys'], preflight_rows),
        'preflight-limit-vectors.tsv': (['length', 'repeated_synthetic_item', 'model_status', 'model_sorted_keys'], boundary_rows),
        'clear-vectors.tsv': (['first_found', 'first_word', 'second_found', 'second_word', 'model_first_after', 'model_second_after'], clear_rows),
        'walk-vectors.tsv': (['case', 'synthetic_root', 'synthetic_graph', 'model_return_code', 'model_finalizer_order'], walk_rows),
        'guarded-state-word-vectors.tsv': (['synthetic_before', 'synthetic_after_callback', 'model_first_store', 'model_second_store'], state_word_rows),
        'counter-vectors.tsv': (['length', 'prior_batch_counter', 'prior_success_counter', 'successful_items', 'model_status', 'model_batch_counter', 'model_success_counter'], counter_rows),
    }


def write_output(output, artifacts):
    output.mkdir(parents=True, exist_ok=True)
    for filename, value in artifacts.items():
        if filename.endswith('.json'):
            (output / filename).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        else:
            header, rows = value
            emit_tsv(output / filename, header, rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    data = BINARY.read_bytes()
    write_output(args.out, build(data))


if __name__ == '__main__':
    main()
