#!/usr/bin/env python3
"""Extract the two selected node-115 reverse-cursor bodies and their context.

All observations are static. The target is authenticated before any output;
common repository ELF and unwind readers supply section and FDE metadata.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Expected digests validate the full unwind-described bodies, not only the
# selected semantic windows. Their names are roles, not recovered symbols.
BODIES = (
    ('cursor_a', 0x514e3c0, 0x514e674, '7b7c17abf3b9824724b40878c1e90dc8bb6b759be277038674fcb45b5875b5ba'),
    ('cursor_b', 0x514e680, 0x514e934, '46027d848e70f964bec86de959587ac7df303ab1459ee2254b1a8fd728dc9df2'),
)

# The third state collection continues through two related row pipelines.
# These selected bodies have no prior ownership in the available local records.
EXTRA_BODIES = (
    ('nested_lookup', 0x53d78c0, 0x53d7af1, '50a77c6890d34d9209b010e50089e197f5f00f2dedcadfd08015a1e19d3331a8'),
    ('ring_search', 0x57fc1b0, 0x57fc37b, 'ec6528497a68a3b4bbb2a3b63a18cc05c26ff861aa356bff6a65550aaf405216'),
    ('first_pipeline', 0x4d55e30, 0x4d55f92, '63546738fdd40bb9d401161a6ce87fd56da842873527dfa28f1f3f52da07db8b'),
    ('first_collector', 0x5ba4680, 0x5ba4999, 'a38ddd0621d25818a5914096d440fd8d263fd64558ca3074a83cf69df43560d3'),
    ('second_collector', 0x5ba41c0, 0x5ba4680, 'abc43a6001422d79dce20ea8a0b1d1f77124c03c2a0e2cb14285ceaf7ea0f84a'),
    ('first_short_sort', 0x53efb10, 0x53efc11, 'eb061a8e3f39c9447ecc4a85aec1769f7bf421a84c9e5d5ee990015ac70304cf'),
    ('second_short_sort', 0x53ec830, 0x53ec931, '019c4f2556ced06626376d9e367bb25b1ea7bb4b82771644cde2f2247d5844e8'),
    ('first_compact', 0x5b2d1d0, 0x5b2d308, 'b0da65b42a0b5f1bea941c34249f63d6cfea9f27fb6ac0cf4e6c81290af3fbe4'),
    ('second_compact', 0x5b2d510, 0x5b2d648, 'b0da65b42a0b5f1bea941c34249f63d6cfea9f27fb6ac0cf4e6c81290af3fbe4'),
)

# Exact windows are checked before being recorded; branch destinations below
# are derived from their actual relative operands, not a disassembler export.
EXTRA_POINTS = (
    ('nested_lookup', 'shared_key_and_repr', 0x53d78d1, '488b064c8b38488b014889c648f7de714d4c8b61084d', None),
    ('nested_lookup', 'root_empty_and_descend', 0x53d78e2, '4c8b61084d85e40f8488010000664183bc24ca020000000f85a20000', None),
    ('nested_lookup', 'array_selection', 0x53d792f, '4c8b41184d85c07445488b71104531e44839c64c0f43e04929f44901c4', None),
    ('nested_lookup', 'selected_entry_kind', 0x53d79a1, '488954242048b80000000000000080498b1c244839c3', None),
    ('nested_lookup', 'tree_comparator_load', 0x53d79d9, '4c8b3570811001', 0x64dfb50),
    ('nested_lookup', 'tree_compare_twenty', 0x53d7a15, '488d6e14ba140000004c89ff41ffd6489848', None),
    ('nested_lookup', 'tree_value_stride', 0x53d7a31, '4983c50c48ffc34983c4ec', None),
    ('nested_lookup', 'ring_lookup_call', 0x53d7a82, 'e829474200', 0x57fc1b0),
    ('nested_lookup', 'ring_result_checks', 0x53d7a87, '4531eda8017544493b542418733d', None),
    ('nested_lookup', 'ring_value_address', 0x53d7a99, '490354241031c04839da480f43c34829c2498b44240848c1e2054c8d2c104983c514', None),
    ('nested_lookup', 'result_key_and_pointer', 0x53d7abb, '488b4c24208b41104c8b3424418946100f1001410f11064d896e184c89f048', None),
    ('ring_search', 'length_and_empty', 0x57fc1bb, '488b47184885c0488934247469', None),
    ('ring_search', 'split_counts', 0x57fc1c8, '4c8b374c8b7f1031c94d39f7490f43ce4929cf4d29fe4989c44d29f47653', None),
    ('ring_search', 'split_compare', 0x57fc1ea, 'ba140000004c89efff155839ce00', None),
    ('ring_search', 'split_compare_slot', 0x57fc1f2, 'ff155839ce00', 0x64dfb50),
    ('ring_search', 'second_segment_setup', 0x57fc239, '4c01f84989c64d29fe49c1e7054c037f08b801', None),
    ('ring_search', 'binary_comparator_load', 0x57fc261, '488b2de838ce00', 0x64dfb50),
    ('ring_search', 'binary_middle', 0x57fc270, '4d89ec4c89f348d1eb4901dd4c89ef48c1e7054c01ffba14000000488b3424ffd5', None),
    ('ring_search', 'first_final_compare', 0x57fc2ae, 'ba140000004c89ffff159438ce00', None),
    ('ring_search', 'first_final_slot', 0x57fc2b6, 'ff159438ce00', 0x64dfb50),
    ('ring_search', 'first_result_flags', 0x57fc2bc, '85c07413c1e81f4901c54d89eeb801000000e99600000031c04d89eee98c', None),
    ('ring_search', 'second_segment_middle', 0x57fc300, '4c89fb4c89e548d1ed4901ef4c89ff48c1e7054c01efba14000000488b3424ff152b38ce00', None),
    ('ring_search', 'second_final_slot', 0x57fc34a, 'ff150038ce00', 0x64dfb50),
    ('ring_search', 'final_flags_and_index', 0x57fc350, '85c0740889c1c1e91f4901cf85c0b8000000000f95c04d01fe4c89f2', None),
    ('first_pipeline', 'collect_call', 0x4d55e70, 'e80be8e400', 0x5ba4680),
    ('first_pipeline', 'count_two', 0x4d55e89, '4883fe020f8397000000', None),
    ('first_pipeline', 'compact_call', 0x4d55e98, 'e83373dd00', 0x5b2d1d0),
    ('first_pipeline', 'representation_limit', 0x4d55eac, '4883fa407638', None),
    ('first_pipeline', 'sort_count_twenty_one', 0x4d55f2a, '4883fe157317', None),
    ('first_pipeline', 'short_sort_call', 0x4d55f3d, 'e8ce9b6900', 0x53efb10),
    ('first_pipeline', 'large_sort_slot', 0x4d55f4f, 'ff156b207901', 0x64e7fc0),
    ('first_collector', 'source_mode', 0x5ba46c0, '41833f02753a', None),
    ('first_collector', 'source_stride', 0x5ba46ed, '488d484048890b', None),
    ('first_collector', 'candidate_call', 0x5ba4719, 'e8a23183ff', 0x53d78c0),
    ('first_collector', 'candidate_null', 0x5ba471e, '488b6c24484885ed7498', None),
    ('first_collector', 'initial_allocation', 0x5ba4770, 'bf80000000ff1505ad93004885c00f84de010000', None),
    ('first_collector', 'first_candidate', 0x5ba4784, '488b8c24b0000000488948100f288424a00000000f110048896818', None),
    ('first_collector', 'subsequent_row', 0x5ba4901, '48c1e005488b8c24d0000000488b54241848894c02100f288424c00000000f11040248895c0218', None),
    ('first_collector', 'allocation_failure_call', 0x5ba496c, 'ff1526ab9300', 0x64df498),
    ('second_collector', 'source_mode', 0x5ba41d7, '833e027566', None),
    ('second_collector', 'first_pointer_zero', 0x5ba4233, 'b8020000004885c97560e9e5000000', None),
    ('second_collector', 'first_dword_zero', 0x5ba429d, '8b29488b5104', None),
    ('second_collector', 'first_dword_test', 0x5ba42ba, '85ed7469', None),
    ('second_collector', 'size_guard', 0x5ba42d3, '48ffc048c7c1ffffffff480f45c84883f90541bc04000000bb04000000480f43d94989dd49c1e50548c1e93b0f95c048b9fcffffffffffff7f4939cd0f97c108c17472', None),
    ('second_collector', 'allocation_failure_call', 0x5ba431f, 'ff1573b19300', 0x64df498),
    ('second_collector', 'allocation_failure_ud2', 0x5ba4325, '0f0b', None),
    ('second_collector', 'empty_result', 0x5ba4327, '48c7030000000048c743080400000048c7431000000000', None),
    ('second_collector', 'first_output_row', 0x5ba43a5, '8b8424c0000000418947100f288424b0000000410f110741896f14488b8424a800000049894718', None),
    ('second_collector', 'subsequent_dword_test', 0x5ba4554, '85ed7453', None),
    ('first_short_sort', 'comparator_slot_load', 0x53efb57, '488b2df2ff0e01', 0x64dfb50),
    ('second_short_sort', 'comparator_slot_load', 0x53ec877, '488b2dd2320f01', 0x64dfb50),
    ('first_short_sort', 'compare_twenty', 0x53efb96, '498d7424e0ba140000004c89e7ffd585c079e0', None),
    ('second_short_sort', 'compare_twenty', 0x53ec8b6, '498d7424e0ba140000004c89e7ffd585c079e0', None),
    ('first_compact', 'count_guard', 0x5b2d1d0, '488b47104883f8027263', None),
    ('second_compact', 'count_guard', 0x5b2d510, '488b47104883f8027263', None),
    ('first_compact', 'first_twenty_comparison', 0x5b2d200, 'f30f6f0431f30f6f4c3120660f74c8660f6e443130660f6e543110660f74d0660fdbd166440fd7ca4181f9ffff0000740d', None),
    ('second_compact', 'first_twenty_comparison', 0x5b2d540, 'f30f6f0431f30f6f4c3120660f74c8660f6e443130660f6e543110660f74d0660fdbd166440fd7ca4181f9ffff0000740d', None),
    ('first_compact', 'first_duplicate_swap', 0x5b2d23e, '0f1004310f104c3110f30f6f5431200f105c31300f11443120f30f7f14310f114c31300f115c3110', None),
    ('first_compact', 'different_key_copy', 0x5b2d280, '0f10060f104e10410f114810410f110048ffc24883c620', None),
    ('first_compact', 'subsequent_twenty_comparison', 0x5b2d29c, '4989d149c1e1054e8d0409f30f6f06f3420f6f4c09e0660f74c8660f6e461066420f6e5409f0660f74d0660fdbd166440fd7ca4181f9ffff0000', None),
    ('first_compact', 'last_duplicate_swap', 0x5b2d2d8, '0f1006410f1048e00f110e410f1140e00f104610410f1048f00f114e10410f1140f048', None),
    ('second_compact', 'first_duplicate_swap', 0x5b2d57e, '0f1004310f104c3110f30f6f5431200f105c31300f11443120f30f7f14310f114c31300f115c3110', None),
    ('second_compact', 'different_key_copy', 0x5b2d5c0, '0f10060f104e10410f114810410f110048ffc24883c620', None),
    ('second_compact', 'subsequent_twenty_comparison', 0x5b2d5dc, '4989d149c1e1054e8d0409f30f6f06f3420f6f4c09e0660f74c8660f6e461066420f6e5409f0660f74d0660fdbd166440fd7ca4181f9ffff0000', None),
    ('second_compact', 'last_duplicate_swap', 0x5b2d618, '0f1006410f1048e00f110e410f1140e00f104610410f1048f00f114e10410f1140f048', None),
    ('first_short_sort', 'stable_shift', 0x53efbd0, '410f10441fe0410f104c1ff0410f114c1f10410f11041f4883fb207483498d341f4883c6c0ba140000004c89efffd54883c3e085c078c9', None),
    ('first_short_sort', 'range_guard', 0x53efb10, '488d42ff4839f00f83f2000000', None),
    ('first_short_sort', 'row_stride', 0x53efb45, '4989ff48c1e3054801fb49c1e6054e8d2437', None),
    ('second_short_sort', 'stable_shift', 0x53ec8f0, '410f10441fe0410f104c1ff0410f114c1f10410f11041f4883fb207483498d341f4883c6c0ba140000004c89efffd54883c3e085c078c9', None),
    ('second_short_sort', 'range_guard', 0x53ec830, '488d42ff4839f00f83f2000000', None),
    ('second_short_sort', 'row_stride', 0x53ec865, '4989ff48c1e3054801fb49c1e6054e8d2437', None),
    ('first_compact', 'prefix_length_store', 0x5b2d303, '48895710c3', None),
    ('second_compact', 'prefix_length_store', 0x5b2d643, '48895710c3', None),
)

FAMILY_EDGES = {
    'ring_search': ('search', 0x57fc1b0),
    'first_compact': ('compact', 0x5b2d1d0),
    'second_compact': ('compact', 0x5b2d510),
    'first_short_sort': ('sort', 0x53efb10),
    'second_short_sort': ('sort', 0x53ec830),
}
EDGE_FAMILY_SPECS = {
    'search': (('empty', 0x016, '74', 0x081),
               ('single_segment', 0x034, '76', 0x089),
               ('pivot_equal', 0x05a, '0f84', 0x1b9),
               ('pivot_greater', 0x065, '0f85', 0x12d),
               ('second_needs_loop', 0x073, '0f85', 0x148),
               ('second_single', 0x07c, 'e9', 0x188),
               ('empty_to_result', 0x087, 'eb', 0x08f),
               ('first_empty', 0x0a2, '0f84', 0x1b9),
               ('first_single', 0x0af, '74', 0x0f4),
               ('first_loop', 0x0f2, '77', 0x0c0),
               ('first_equal', 0x10e, '74', 0x123),
               ('first_miss_exit', 0x11e, 'e9', 0x1b9),
               ('first_hit_exit', 0x128, 'e9', 0x1b9),
               ('first_multi', 0x140, '0f85', 0x0a8),
               ('first_empty_exit', 0x146, 'eb', 0x1b9),
               ('second_loop', 0x186, '77', 0x150),
               ('second_equal', 0x1a2, '74', 0x1ac)),
    'compact': (('length_below_two', 0x008, '72', 0x06d),
                ('first_equal', 0x05f, '74', 0x06e),
                ('scan_next_pair', 0x06b, '75', 0x030),
                ('no_remaining_rows', 0x09d, '0f86', 0x133),
                ('compare_next', 0x0aa, 'eb', 0x0cc),
                ('copy_last_row', 0x0ca, '74', 0x133),
                ('different_key', 0x106, '75', 0x0b0),
                ('repeat_compaction', 0x131, '75', 0x0cc)),
    'sort': (('bad_start', 0x007, '0f83', 0x0ff),
             ('work_remains', 0x024, '75', 0x035),
             ('scan_next', 0x058, 'eb', 0x086),
             ('sort_complete', 0x084, '74', 0x026),
             ('already_ordered', 0x097, '79', 0x079),
             ('reached_front', 0x0db, '74', 0x060),
             ('shift_again', 0x0f5, '78', 0x0c0),
             ('place_candidate', 0x0fa, 'e9', 0x063)),
}

# Relative offsets identify instruction starts in each independently pinned
# body. The target is decoded from the actual displacement, and also checked
# against an expected in-body destination (or shared indirect slot).
EDGES = (
    ('empty_return', 0x008, '74', 0x03d),
    ('unexpected_tag', 0x015, '0f85', 0x2a5),
    ('initial_cursor', 0x026, '74', 0x041),
    ('walk_parent', 0x02f, '0f84', 0x140),
    ('select_existing', 0x038, 'e9', 0x15e),
    ('initial_zero_depth', 0x048, '0f84', 0x10e),
    ('initial_zero_remainder', 0x055, '0f84', 0x284),
    ('initial_remainder_loop', 0x076, '75', 0x060),
    ('initial_less_than_eight', 0x082, '0f82', 0x10e),
    ('initial_eight_loop', 0x10c, '75', 0x090),
    ('initial_nonempty_node', 0x132, '0f85', 0x035),
    ('missing_parent', 0x146, '0f84', 0x296),
    ('continue_up', 0x15c, '74', 0x140),
    ('direct_node', 0x16b, '0f84', 0x262),
    ('sibling_is_leaf', 0x17f, '0f84', 0x25a),
    ('sibling_zero_remainder', 0x190, '74', 0x1bb),
    ('sibling_remainder_loop', 0x1b6, '75', 0x1a0),
    ('sibling_less_than_eight', 0x1bf, '0f82', 0x25a),
    ('sibling_eight_loop', 0x254, '0f85', 0x1d0),
    ('initial_at_least_eight', 0x28b, '0f83', 0x090),
    ('initial_tail', 0x291, 'e9', 0x10e),
    ('missing_parent_boundary', 0x29d, 'ff15', 0x64df830),
    ('unexpected_tag_boundary', 0x2ac, 'ff15', 0x64df830),
)

# These chunks partition both complete FDE ranges; labels make the CFG easy to
# review, but are not assertions about source-level function boundaries.
CHUNKS = (
    ('entry_and_tag', 0x000, 0x01b),
    ('existing_or_initial', 0x01b, 0x03d),
    ('empty_return', 0x03d, 0x041),
    ('initial_descent_setup', 0x041, 0x060),
    ('initial_remainder', 0x060, 0x090),
    ('initial_eight_step_loop', 0x090, 0x10e),
    ('initialize_cursor', 0x10e, 0x140),
    ('climb_parents', 0x140, 0x15e),
    ('select_predecessor', 0x15e, 0x190),
    ('sibling_descent_setup', 0x190, 0x1a0),
    ('sibling_remainder', 0x1a0, 0x1d0),
    ('sibling_eight_step_loop', 0x1d0, 0x25a),
    ('sibling_length', 0x25a, 0x262),
    ('return_pair_and_cursor', 0x262, 0x284),
    ('initial_multiple_of_eight', 0x284, 0x296),
    ('invariant_failures', 0x296, 0x2b4),
)

# Context belongs to the earlier loader/post-block proposals. These are small
# joins only, not newly owned functions, loader slots, or prior call sites.
CONTEXT = (
    ('state_location_ref', 0x3c1352f, '488d1572328602'),
    ('state_location_compare', 0x3c1353b, '4883f801'),
    ('a_container_head', 0x4dfe9dc, '498b81481a0000'),
    ('a_tree_root', 0x4dfe9eb, '498b81501a0000'),
    ('a_tree_total', 0x4dfe9ff, '498bb9601a0000'),
    ('a_tree_depth', 0x4dfea06, '498bb1581a0000'),
    ('a_tree_call', 0x4dfeba8, 'e813f83400'),
    ('a_null_test', 0x4dfebad, '4885c0'),
    ('a_null_branch', 0x4dfebb0, '0f84be000000'),
    ('a_key_load', 0x4dfebb6, '4c8b20'),
    ('a_unsigned_cutoff', 0x4dfebb9, '4939dc0f86b2000000'),
    ('a_publish', 0x4dff3e3, '49898424d0020000'),
    ('b_container_head', 0x4dfec9d, '498b8040190000'),
    ('b_tree_root', 0x4dfecb3, '498b8048190000'),
    ('b_tree_total', 0x4dfecc8, '498bb858190000'),
    ('b_tree_depth', 0x4dfeccf, '498b8850190000'),
    ('b_tree_call', 0x4dfee43, 'e838f83400'),
    ('b_null_test', 0x4dfee48, '4885c0'),
    ('b_null_branch', 0x4dfee4b, '0f849c000000'),
    ('b_key_load', 0x4dfee51, '4c8b20'),
    ('b_unsigned_cutoff', 0x4dfee54, '4c3ba424c80200000f868b000000'),
    ('b_optional_value', 0x4dfee62, '48837a2800748c'),
    ('b_publish', 0x4dff473, '49898424d8020000'),
    ('a_tree_switch', 0x4dfeb3f, '4983f802755b'),
    ('b_tree_switch', 0x4dfedfa, '4983f8027540'),
    ('third_flag_gate', 0x4dfef5d, '807c240f007412'),
    ('a_publish_gate', 0x4dff366, '488b8424200100004885c0747d'),
    ('b_publish_gate', 0x4dff3f0, '488b8424380100004885c00f847f000000'),
    ('third_container_head', 0x4dfef96, '498b85a8190000'),
    ('third_prepare', 0x4dff081, 'e8aa6df5ff'),
    ('third_collect', 0x4dff129, 'e89250da00'),
    ('third_sort_threshold', 0x4dff148, '4883fe020f83dc060000'),
    ('third_compact', 0x4dff15a, 'e8b1e3d200'),
    ('third_representation_limit', 0x4dff177, '4883fa407639'),
    ('third_small_sort_threshold', 0x4dff82e, '4883fe157324'),
    ('third_small_sort', 0x4dff841, 'e8eacf5e00'),
    ('third_large_sort', 0x4dff860, 'ff15ea876e01'),
    ('third_result_projection', 0x4dff266, '4889842400020000660f28842400030000660f11842408020000488b8424100300004889842418020000'),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked_hash(data, expected):
    actual = hashlib.sha256(data).hexdigest()
    require(actual == expected, 'artifact SHA-256 mismatch')
    return actual


def read_va(data, secs, va, size):
    """Resolve a nonempty span only when exactly one file-backed section covers it."""
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
            'invalid virtual-address span')
    end = va + size
    require(end <= 1 << 64, 'virtual-address span overflows')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] < end and va < s['address'] + s['size']]
    require(len(matches) == 1 and matches[0]['address'] <= va and
            end <= matches[0]['address'] + matches[0]['size'],
            'span lacks one unambiguous file-backed section')
    section = matches[0]
    off = section['offset'] + va - section['address']
    require(off >= 0 and off + size <= len(data), 'file span is outside input')
    return data[off:off + size], off, section['name']


def check_exact(actual, expected_hex, label):
    expected = bytes.fromhex(expected_hex)
    require(actual == expected, 'unexpected bytes: ' + label)


def displacement(site, raw, opcode):
    """Decode only the explicitly selected x86 encodings, not arbitrary bytes."""
    prefix = bytes.fromhex(opcode)
    require(raw.startswith(prefix), 'unexpected transfer opcode')
    if opcode in ('72', '73', '74', '75', '76', '77', '78', '79', 'eb'):
        require(len(raw) == 2, 'invalid short conditional length')
        disp = struct.unpack_from('<b', raw, 1)[0]
    elif opcode in ('0f82', '0f83', '0f84', '0f85', '0f86', 'ff15'):
        require(len(raw) == 6, 'invalid near transfer length')
        disp = struct.unpack_from('<i', raw, 2)[0]
    elif opcode in ('e8', 'e9'):
        require(len(raw) == 5, 'invalid relative transfer length')
        disp = struct.unpack_from('<i', raw, 1)[0]
    else:
        raise ValueError('unsupported transfer opcode')
    return site + len(raw) + disp


def selected_relocations(data, secs, wanted):
    names = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    require(len(names) == 1, 'missing or duplicate relocation section')
    rel = names[0]
    require(rel['size'] % 24 == 0, 'invalid relocation size')
    found = {a: [] for a in wanted}
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', data, off)
        if target in found:
            found[target].append((off, info & 0xffffffff, info >> 32, addend))
    out = {}
    for target, rows in found.items():
        require(len(rows) == 1, 'missing or duplicate selected relocation')
        off, kind, sym, addend = rows[0]
        require(kind == 8 and sym == 0 and addend >= 0, 'unexpected relocation type')
        out[target] = {'slot_va': hex(target), 'file_offset': hex(off),
                       'type': kind, 'symbol_index': sym, 'addend': hex(addend)}
    return out


def symbol_relocation(data, secs, target, expected_name):
    def unique(name, typ):
        matches = [s for s in secs if s['name'] == name and s['type'] == typ]
        require(len(matches) == 1, 'missing or duplicate symbol section')
        return matches[0]
    rel = unique('.rela.dyn', 4)
    sym = unique('.dynsym', 11)
    strings = unique('.dynstr', 3)
    require(rel['size'] % 24 == 0 and sym['size'] % 24 == 0, 'invalid dynamic table size')
    found = []
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, off)
        if where == target:
            found.append((off, info, addend))
    require(len(found) == 1, 'missing or duplicate symbol relocation')
    off, info, addend = found[0]
    kind, index = info & 0xffffffff, info >> 32
    require(kind == 6 and index > 0 and index * 24 + 24 <= sym['size'] and addend == 0,
            'unexpected dynamic symbol relocation')
    name_offset = struct.unpack_from('<I', data, sym['offset'] + index * 24)[0]
    require(name_offset < strings['size'], 'dynamic string offset outside table')
    begin = strings['offset'] + name_offset
    end = data.find(b'\0', begin, strings['offset'] + strings['size'])
    require(end >= begin, 'unterminated dynamic symbol')
    name = bytes(data[begin:end]).decode('ascii')
    require(name == expected_name, 'unexpected dynamic symbol')
    return {'slot_va': hex(target), 'record_file_offset': hex(off), 'type': kind,
            'symbol_index': index, 'symbol': name, 'addend': addend}


def location(data, secs, relocs, addr, suffix):
    raw, off, secname = read_va(data, secs, addr, 24)
    pointer_word, length, line, column = struct.unpack('<QQII', raw)
    require(pointer_word == 0 and 0 < length <= 256, 'invalid Location record')
    target = int(relocs[addr]['addend'], 16)
    path, pathoff, pathsec = read_va(data, secs, target, length)
    suffix_bytes = suffix.encode('ascii')
    require(path.endswith(suffix_bytes), 'unexpected Location suffix')
    # The original may include a build-root prefix: publish only the suffix and
    # a hash of the complete byte string so no local build path is disclosed.
    return {'va': hex(addr), 'file_offset': hex(off), 'section': secname,
            'raw_hex': raw.hex(), 'path_va': hex(target),
            'path_file_offset': hex(pathoff), 'path_section': pathsec,
            'path_length': length, 'path_suffix': suffix,
            'full_path_sha256': hashlib.sha256(path).hexdigest(),
            'line': line, 'column': column}


def selected_lsda(data, secs, fde):
    """Read the selected omit/omit/ULEB call-site tables only; no action decoding."""
    addr = fde['lsda']
    require(addr is not None, 'selected FDE lacks LSDA')
    head, off, name = read_va(data, secs, addr, 4)
    require(name == '.gcc_except_table' and head[0] == 0xff and head[1] in (0xff, 0x9b),
            'unexpected LSDA encodings')
    matches = [s for s in secs if s['name'] == name and s['type'] != 8]
    require(len(matches) == 1, 'missing or duplicate exception section')
    section = matches[0]
    limit = section['offset'] + section['size']
    pos = off + 2
    if head[1] != 0xff:
        type_offset, pos = uleb(data, pos, limit)
        require(pos + type_offset <= limit, 'invalid LSDA type table offset')
    require(pos < limit and data[pos] == 1, 'unexpected LSDA call-site encoding')
    length, pos = uleb(data, pos + 1, limit)
    end = pos + length
    require(end <= limit and end <= len(data), 'truncated LSDA call-site table')
    rows = []
    while pos < end:
        record_start = pos
        fields = []
        for _ in range(4):
            value, pos = uleb(data, pos, end)
            fields.append(value)
        start, size, landing, action = fields
        require(size > 0 and start + size <= fde['end'] - fde['start'],
                'invalid LSDA call-site range')
        require(landing == 0 or landing < fde['end'] - fde['start'],
                'invalid LSDA landing')
        rows.append({'lsda_va': hex(addr), 'record_file_offset': hex(record_start),
                     'raw_hex': data[record_start:pos].hex(),
                     'start_va': hex(fde['start'] + start),
                     'end_va_exclusive': hex(fde['start'] + start + size),
                     'landing_va': hex(fde['start'] + landing) if landing else '-',
                     'action': action})
    require(pos == end and rows, 'empty or malformed LSDA call-site table')
    return rows


def parse_fields(body):
    """Decode the selected, pinned instruction operands shared by the two bodies."""
    require(len(body) == 0x2b4, 'unexpected body length')
    # Prefix and suffix checks prevent decoding an unrelated byte sequence.
    def extract(offset, prefix, size, suffix=b''):
        p = bytes.fromhex(prefix)
        actual = body[offset:offset + len(p) + size + len(suffix)]
        require(actual.startswith(p) and (not suffix or actual.endswith(suffix)),
                'unexpected field instruction')
        return int.from_bytes(actual[len(p):len(p) + size], 'little')
    fields = {
        'remaining_offset': extract(1, '488b47', 1),
        'tag_offset': extract(0x11, '837f', 1, b'\x01'),
        'tag_value': body[0x14],
        'current_offset': extract(0x1b, '488b57', 1),
        'index_offset': extract(0x1f, '488b47', 1),
        'root_or_depth_offset': extract(0x41, '488b57', 1),
        'node_len_offset': extract(0x60, '440fb782', 4),
        'child_base_offset': extract(0x68, '4a8b94c2', 4),
        'parent_index_offset': extract(0x14f, '0fb782', 4),
        'sibling_base_offset': extract(0x171, '4c8b8cc1', 4),
        'value_base_offset': extract(0x26e, '4883c2', 1),
        'key_index_scale': 1 << (body[0x265] >> 6),
    }
    check_exact(body[0x262:0x265], '488d04', 'key address opcode')
    require(body[0x265] == 0xc1, 'unexpected key address registers')
    check_exact(body[0x266:0x269], '488d14', 'value multiply opcode')
    sib = body[0x269]
    require((sib & 7) == 2 and ((sib >> 3) & 7) == 2,
            'unexpected value multiply registers')
    check_exact(body[0x26a:0x26e], '488d14d1', 'value address opcode')
    fields['value_stride'] = (1 + (1 << (sib >> 6))) * 8
    require(fields['node_len_offset'] == fields['parent_index_offset'] + 2 and
            fields['child_base_offset'] == fields['parent_index_offset'] + 8 and
            fields['sibling_base_offset'] == fields['parent_index_offset'],
            'inconsistent node layout')
    require((fields['remaining_offset'], fields['tag_offset'], fields['tag_value'],
             fields['current_offset'], fields['root_or_depth_offset'], fields['index_offset'],
             fields['key_index_scale'], fields['value_base_offset']) ==
            (0x40, 0x20, 1, 0x28, 0x30, 0x38, 8, 0x60), 'unexpected cursor layout')
    return fields


def search_layout(data, secs):
    # Offsets are decoded from the exact selected instructions; zero capacity
    # displacement is implied by the base-register ModRM encoding.
    specs = (
        ('capacity_offset', 0x57fc1c8, '4c8b37', 0, 0),
        ('buffer_offset', 0x57fc1e6, '4c8b6f', 1, 8),
        ('head_offset', 0x57fc1cb, '4c8b7f', 1, 16),
        ('length_offset', 0x57fc1bb, '488b47', 1, 24),
        ('key_bytes', 0x57fc1ea, 'ba', 4, 20),
        ('row_shift', 0x57fc2a7, '48c1e0', 1, 5),
        ('matched_value_offset', 0x53d7ab7, '4983c5', 1, 20),
    )
    out = []
    for label, va, prefix, width, expected in specs:
        pfx = bytes.fromhex(prefix)
        raw, off, name = read_va(data, secs, va, len(pfx) + width)
        require(name == '.text' and raw.startswith(pfx), 'unexpected search layout instruction')
        value = int.from_bytes(raw[len(pfx):], 'little') if width else 0
        require(value == expected, 'unexpected search layout operand')
        out.append({'field': label, 'instruction_va': hex(va), 'file_offset': hex(off),
                    'raw_hex': raw.hex(), 'value': value})
    return out


def tsv(columns, rows):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, columns, delimiter='\t', lineterminator='\n', extrasaction='raise')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def analyse(data, expected_sha=SHA115):
    digest = checked_hash(data, expected_sha)
    secs, table = unwind_index(data)
    _, all_fdes = eh_frame_records(data, secs)
    indexed = {x['start']: x for x in table}
    fdes_by_start = {}
    for fde in all_fdes:
        fdes_by_start.setdefault(fde['start'], []).append(fde)
    functions, windows, transfers, layouts, unwind, bodies, descent, unwind_calls = [], [], [], [], [], [], [], []
    extra_functions, extra_points, extra_unwind, extra_bodies, family_edges = [], [], [], {}, []
    for role, start, expected_end, expected_body_sha in BODIES:
        found = fdes_by_start.get(start, [])
        require(len(found) == 1 and start in indexed, 'missing or ambiguous FDE')
        fde = found[0]
        require(fde['end'] == expected_end and indexed[start]['fde'] == fde['fde'],
                'unwind header/FDE mismatch')
        body, off, name = read_va(data, secs, start, fde['end'] - start)
        require(name == '.text' and hashlib.sha256(body).hexdigest() == expected_body_sha,
                'selected body mismatch')
        bodies.append(body)
        functions.append({'role': role, 'start_va': hex(start), 'end_va_exclusive': hex(fde['end']),
                          'file_offset': hex(off), 'size': len(body), 'fde_va': hex(fde['fde']),
                          'cie_va': hex(fde['cie']), 'lsda_va': hex(fde['lsda']),
                          'unwind_index': indexed[start]['index'],
                          'sha256': hashlib.sha256(body).hexdigest(), 'raw_hex': body.hex()})
        fields = parse_fields(body)
        layouts.append(dict(role=role, **fields))
        # Read each unrolled step from target bytes, including both register
        # variants at the loop edges. The abstract count is not a byte scan.
        for phase, base_rel, item_size in (('initial', 0x90, 15), ('sibling', 0x1d0, 16)):
            for step in range(8):
                rel = base_rel + step * item_size
                prefix_len = 3 if phase == 'initial' else 4
                load_prefix = (b'\x0f\xb7\x82' if step == 0 else b'\x0f\xb7\x90') if phase == 'initial' else (b'\x41\x0f\xb7\xb1' if step == 0 else b'\x44\x0f\xb7\x8e')
                link_prefix = (b'\x48\x8b\x84\xc2' if step == 0 else (b'\x48\x8b\x94\xd0' if step == 7 else b'\x48\x8b\x84\xd0')) if phase == 'initial' else (b'\x49\x8b\xb4\xf1' if step == 0 else (b'\x4e\x8b\x8c\xce' if step == 7 else b'\x4a\x8b\xb4\xce'))
                load = body[rel:rel + prefix_len + 4]
                link = body[rel + prefix_len + 4:rel + item_size]
                require(load.startswith(load_prefix) and link.startswith(link_prefix), 'unexpected unrolled descent instruction')
                len_offset = struct.unpack_from('<I', load, prefix_len)[0]
                child_offset = struct.unpack_from('<I', link, 4)[0]
                require((len_offset, child_offset) == (fields['node_len_offset'], fields['child_base_offset']), 'inconsistent descent operands')
                descent.append({'role': role, 'phase': phase, 'step': step,
                                'length_load_va': hex(start + rel),
                                'length_load_hex': load.hex(), 'length_offset': len_offset,
                                'child_load_va': hex(start + rel + prefix_len + 4),
                                'child_load_hex': link.hex(), 'child_base_offset': child_offset})
        require(CHUNKS[0][1] == 0 and CHUNKS[-1][2] == len(body) and
                all(a[2] == b[1] for a, b in zip(CHUNKS, CHUNKS[1:])),
                'chunks do not partition selected body')
        for label, lo, hi in CHUNKS:
            raw = body[lo:hi]
            require(len(raw) == hi - lo and lo < hi, 'invalid selected chunk')
            windows.append({'role': role, 'label': label, 'start_va': hex(start + lo),
                            'end_va_exclusive': hex(start + hi), 'file_offset': hex(off + lo),
                            'size': len(raw), 'raw_hex': raw.hex()})
        for label, relative, opcode, expected_target in EDGES:
            n = 2 if opcode in ('74', '75') else 5 if opcode in ('e8', 'e9') else 6
            raw = body[relative:relative + n]
            target = displacement(start + relative, raw, opcode)
            expected = expected_target if opcode == 'ff15' else start + expected_target
            require(target == expected, 'unexpected selected transfer target')
            transfers.append({'role': role, 'label': label, 'site_va': hex(start + relative),
                              'file_offset': hex(off + relative), 'raw_hex': raw.hex(),
                              'form': opcode, 'target_va_or_slot': hex(target)})
        rows = selected_lsda(data, secs, fde)
        require(len(rows) == 2, 'unexpected cursor LSDA row count')
        for row in rows:
            row['role'] = role
            unwind.append(row)
        for call_rel in (0x29d, 0x2ac):
            call = start + call_rel
            matching = [row for row in rows if int(row['start_va'], 16) <= call < int(row['end_va_exclusive'], 16)]
            require(len(matching) == 1, 'panic call not covered by a single LSDA row')
            match = matching[0]
            landing = match['landing_va']
            if landing != '-':
                landing_raw, _, _ = read_va(data, secs, int(landing, 16), 2)
                check_exact(landing_raw, '0f0b', 'selected LSDA landing')
            unwind_calls.append({'role': role, 'call_va': hex(call),
                                 'range_start': match['start_va'], 'range_end': match['end_va_exclusive'],
                                 'landing_va': landing, 'landing_bytes': '0f0b' if landing != '-' else '-',
                                 'action': match['action']})
        check_exact(body[0x2a3:0x2a5], '0f0b', 'first returning panic')
        check_exact(body[0x2b2:0x2b4], '0f0b', 'second returning panic')
    require(layouts[0]['value_stride'] == 24 and layouts[1]['value_stride'] == 72,
            'unexpected value strides')
    require((layouts[0]['node_len_offset'], layouts[0]['child_base_offset'], layouts[0]['parent_index_offset']) == (0x16a, 0x170, 0x168), 'unexpected cursor A layout')
    require((layouts[1]['node_len_offset'], layouts[1]['child_base_offset'], layouts[1]['parent_index_offset']) == (0x37a, 0x380, 0x378), 'unexpected cursor B layout')
    context = []
    for label, va, expected in CONTEXT:
        raw, off, section = read_va(data, secs, va, len(bytes.fromhex(expected)))
        require(section == '.text', 'context outside text')
        check_exact(raw, expected, label)
        row = {'label': label, 'va': hex(va), 'file_offset': hex(off), 'raw_hex': raw.hex(), 'target': '-'}
        if label in ('a_tree_call', 'b_tree_call'):
            target = displacement(va, raw, 'e8')
            require(target == (BODIES[0][1] if label.startswith('a_') else BODIES[1][1]),
                    'context call target mismatch')
            row['target'] = hex(target)
        extra_calls = {'third_prepare': 0x4d55e30, 'third_collect': 0x5ba41c0,
                       'third_compact': 0x5b2d510, 'third_small_sort': 0x53ec830}
        if label in extra_calls:
            target = displacement(va, raw, 'e8')
            require(target == extra_calls[label], 'third-stage call target mismatch')
            row['target'] = hex(target)
        if label == 'third_large_sort':
            target = displacement(va, raw, 'ff15')
            require(target == 0x64e8050, 'third-stage large-sort slot mismatch')
            row['target'] = hex(target)
        if label == 'state_location_ref':
            require(va + len(raw) + struct.unpack_from('<i', raw, 3)[0] == 0x64767a8,
                    'state Location context does not join')
            row['target'] = hex(0x64767a8)
        context.append(row)
    for role, start, end, body_sha in EXTRA_BODIES:
        found = fdes_by_start.get(start, [])
        require(len(found) == 1 and start in indexed, 'missing or ambiguous extra FDE')
        fde = found[0]
        require(fde['end'] == end and indexed[start]['fde'] == fde['fde'], 'extra unwind mismatch')
        body, off, name = read_va(data, secs, start, end - start)
        require(name == '.text' and hashlib.sha256(body).hexdigest() == body_sha, 'extra body mismatch')
        extra_bodies[role] = body
        extra_functions.append({'role': role, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                                'file_offset': hex(off), 'size': len(body), 'fde_va': hex(fde['fde']),
                                'cie_va': hex(fde['cie']), 'lsda_va': hex(fde['lsda']) if fde['lsda'] is not None else '-',
                                'unwind_index': indexed[start]['index'], 'sha256': hashlib.sha256(body).hexdigest(),
                                'raw_hex': body.hex()})
        if fde['lsda'] is not None:
            for item in selected_lsda(data, secs, fde):
                item['role'] = role
                extra_unwind.append(item)
    extra_by_role = {role: (start, end) for role, start, end, _ in EXTRA_BODIES}
    for role, label, va, expected, expected_target in EXTRA_POINTS:
        start, end = extra_by_role[role]
        raw, off, section = read_va(data, secs, va, len(bytes.fromhex(expected)))
        require(start <= va and va + len(raw) <= end and section == '.text', 'extra window outside FDE')
        check_exact(raw, expected, label)
        target = '-'
        if expected_target is not None:
            if raw[:1] == b'\xe8':
                decoded = displacement(va, raw, 'e8')
            elif raw[:2] == b'\xff\x15':
                decoded = displacement(va, raw, 'ff15')
            else:
                require(raw[:3] in (b'\x48\x8b\x2d', b'\x4c\x8b\x35') and len(raw) == 7, 'unexpected comparator load')
                decoded = va + 7 + struct.unpack_from('<i', raw, 3)[0]
            require(decoded == expected_target, 'extra transfer target mismatch')
            target = hex(decoded)
        extra_points.append({'role': role, 'label': label, 'va': hex(va),
                             'file_offset': hex(off), 'size': len(raw), 'raw_hex': raw.hex(),
                             'target_va_or_slot': target})
    for role, (family, start) in FAMILY_EDGES.items():
        body = extra_bodies[role]
        for label, relative, opcode, expected_target in EDGE_FAMILY_SPECS[family]:
            size = 2 if len(opcode) == 2 and opcode not in ('e8', 'e9') else 5 if opcode in ('e8', 'e9') else 6
            raw = body[relative:relative + size]
            target = displacement(start + relative, raw, opcode)
            require(target == start + expected_target, 'unexpected family transfer target')
            _, off, section = read_va(data, secs, start + relative, size)
            require(section == '.text', 'family transfer outside text')
            family_edges.append({'role': role, 'label': label, 'site_va': hex(start + relative),
                                 'file_offset': hex(off), 'raw_hex': raw.hex(), 'form': opcode,
                                 'target_va': hex(target)})
    require(extra_bodies['first_compact'] == extra_bodies['second_compact'], 'compactor bodies differ')
    a, b = bytearray(extra_bodies['first_short_sort']), bytearray(extra_bodies['second_short_sort'])
    for data_body in (a, b):
        data_body[0x4a:0x4e] = bytes(4)
    require(a == b, 'sorter bodies differ outside their comparator displacement')
    extra_unwind_calls = []
    for role, call in (('first_pipeline', 0x4d55f4f), ('first_collector', 0x5ba48ec),
                       ('first_collector', 0x5ba496c), ('second_collector', 0x5ba431f),
                       ('second_collector', 0x5ba44e8), ('second_collector', 0x5ba459c)):
        matches = [row for row in extra_unwind if row['role'] == role and
                   int(row['start_va'], 16) <= call < int(row['end_va_exclusive'], 16)]
        require(len(matches) == 1, 'selected extra call has no unique LSDA range')
        row = matches[0]
        raw, off, section = read_va(data, secs, call, 6 if call in (0x4d55f4f, 0x5ba496c, 0x5ba431f) else 5)
        require(section == '.text' and (raw[:1] == b'\xe8' or raw[:2] == b'\xff\x15'), 'unexpected LSDA call bytes')
        extra_unwind_calls.append({'role': role, 'call_va': hex(call), 'call_hex': raw.hex(),
                                   'range_start': row['start_va'], 'range_end': row['end_va_exclusive'],
                                   'landing_va': row['landing_va'], 'action': row['action']})
    search_fields = search_layout(data, secs)
    families = [
        {'family': 'compactors', 'size': len(extra_bodies['first_compact']), 'normalization': 'none',
         'normalized_sha256': hashlib.sha256(extra_bodies['first_compact']).hexdigest()},
        {'family': 'short_sorters', 'size': len(a), 'normalization': 'zero relative offsets 0x4a..0x4d',
         'normalized_sha256': hashlib.sha256(a).hexdigest()},
    ]
    relocs = selected_relocations(data, secs, (0x64767a8, 0x64a3730, 0x64a2b10, 0x64df830,
                                              0x64df480, 0x64df498, 0x64e7fc0, 0x64e8050))
    symbol_binding = symbol_relocation(data, secs, 0x64dfb50, 'memcmp')
    locations = [location(data, secs, relocs, 0x64767a8, 'l1/src/abci/state.rs'),
                 location(data, secs, relocs, 0x64a3730, 'library/alloc/src/collections/btree/navigate.rs'),
                 location(data, secs, relocs, 0x64a2b10, 'library/alloc/src/collections/btree/navigate.rs')]
    require([(x['line'], x['column']) for x in locations] == [(123, 37), (546, 52), (166, 35)],
            'unexpected Location fields')
    for relative, expected_va in ((0x296, 0x64a3730), (0x2a5, 0x64a2b10)):
        for body, (_, start, _, _) in zip(bodies, BODIES):
            raw = body[relative:relative + 7]
            require(raw[:3] == bytes.fromhex('488d3d'), 'unexpected Location LEA')
            dest = start + relative + 7 + struct.unpack_from('<i', raw, 3)[0]
            require(dest == expected_va, 'Location target mismatch')
    # A byte-difference list retains the raw differences; no equivalence mask
    # or cross-build comparison is asserted.
    diffs = []
    pos = 0
    while pos < len(bodies[0]):
        if bodies[0][pos] == bodies[1][pos]:
            pos += 1
            continue
        begin = pos
        while pos < len(bodies[0]) and bodies[0][pos] != bodies[1][pos]:
            pos += 1
        diffs.append({'relative_offset': hex(begin), 'length': pos - begin,
                      'cursor_a_hex': bodies[0][begin:pos].hex(),
                      'cursor_b_hex': bodies[1][begin:pos].hex()})
    summary = {'target_release': 115, 'binary_sha256': digest,
               'coordinate_system': 'linked ELF virtual addresses',
               'body_count': len(functions), 'body_bytes': sum(x['size'] for x in functions),
               'partition_windows': len(windows), 'selected_transfers': len(transfers),
               'context_windows': len(context), 'unrolled_descent_steps': len(descent),
               'lsda_rows': len(unwind), 'linked_panic_calls': len(unwind_calls),
               'location_records': len(locations), 'extra_body_count': len(extra_functions),
               'extra_body_bytes': sum(row['size'] for row in extra_functions),
               'extra_selected_windows': len(extra_points), 'family_branch_count': len(family_edges),
               'extra_lsda_rows': len(extra_unwind), 'extra_linked_calls': len(extra_unwind_calls),
               'relative_differing_runs': len(diffs),
               'relative_differing_bytes': sum(x['length'] for x in diffs),
               'limits': 'Selected static records; no runtime execution, function census, component gate, or cross-build equivalence.'}
    return {
        'extra-functions.tsv': tsv(['role','start_va','end_va_exclusive','file_offset','size','fde_va','cie_va','lsda_va','unwind_index','sha256','raw_hex'], extra_functions),
        'extra-points.tsv': tsv(['role','label','va','file_offset','size','raw_hex','target_va_or_slot'], extra_points),
        'extra-unwind.tsv': tsv(['role','lsda_va','record_file_offset','raw_hex','start_va','end_va_exclusive','landing_va','action'], extra_unwind),
        'extra-unwind-calls.tsv': tsv(['role','call_va','call_hex','range_start','range_end','landing_va','action'], extra_unwind_calls),
        'search-layout.tsv': tsv(['field','instruction_va','file_offset','raw_hex','value'], search_fields),
        'families.tsv': tsv(['family','size','normalization','normalized_sha256'], families),
        'family-edges.tsv': tsv(['role','label','site_va','file_offset','raw_hex','form','target_va'], family_edges),
        'symbol-binding.json': (json.dumps(symbol_binding, indent=2) + '\n').encode(),
        'functions.tsv': tsv(['role','start_va','end_va_exclusive','file_offset','size','fde_va','cie_va','lsda_va','unwind_index','sha256','raw_hex'], functions),
        'windows.tsv': tsv(['role','label','start_va','end_va_exclusive','file_offset','size','raw_hex'], windows),
        'transfers.tsv': tsv(['role','label','site_va','file_offset','raw_hex','form','target_va_or_slot'], transfers),
        'layout.tsv': tsv(['role','remaining_offset','tag_offset','tag_value','current_offset','index_offset','root_or_depth_offset','node_len_offset','child_base_offset','parent_index_offset','sibling_base_offset','value_base_offset','key_index_scale','value_stride'], layouts),
        'context.tsv': tsv(['label','va','file_offset','raw_hex','target'], context),
        'unwind.tsv': tsv(['role','lsda_va','record_file_offset','raw_hex','start_va','end_va_exclusive','landing_va','action'], unwind),
        'unwind-calls.tsv': tsv(['role','call_va','range_start','range_end','landing_va','landing_bytes','action'], unwind_calls),
        'descent.tsv': tsv(['role','phase','step','length_load_va','length_load_hex','length_offset','child_load_va','child_load_hex','child_base_offset'], descent),
        'differences.tsv': tsv(['relative_offset','length','cursor_a_hex','cursor_b_hex'], diffs),
        'locations.json': (json.dumps(locations, indent=2) + '\n').encode(),
        'relocations.json': (json.dumps([relocs[x] for x in sorted(relocs)], indent=2) + '\n').encode(),
        'summary.json': (json.dumps(summary, indent=2) + '\n').encode(),
    }


def historical(data):
    """Optional independent #94 identity/navigation check; never changes output."""
    checked_hash(data, SHA94)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    for start, end in ((0x32725d0, 0x3272b3a), (0x3273810, 0x327396c)):
        fs = [f for f in fdes if f['start'] == start]
        ti = [row for row in index if row['start'] == start]
        require(len(fs) == len(ti) == 1 and fs[0]['end'] == end and
                fs[0]['fde'] == ti[0]['fde'], 'historical FDE mismatch')
    rel = selected_relocations(data, secs, (0x56dfbf8, 0x57755a8))
    require(int(rel[0x57755a8]['addend'], 16) == 0x3273810, 'historical slot target mismatch')
    loc = location(data, secs, rel, 0x56dfbf8, 'l1/src/abci/state.rs')
    require((loc['line'], loc['column']) == (107, 37), 'unexpected historical Location')
    for va, expected in ((0x3272785, 'ff151d2e5002'), (0x3273856, '488d0d9bc34602'),
                         (0x3273871, '4983fd02')):
        raw, _, _ = read_va(data, secs, va, len(bytes.fromhex(expected)))
        check_exact(raw, expected, 'historical context')
        if va == 0x3272785:
            require(displacement(va, raw, 'ff15') == 0x57755a8, 'historical call slot mismatch')
        if va == 0x3273856:
            require(va + len(raw) + struct.unpack_from('<i', raw, 3)[0] == 0x56dfbf8,
                    'historical Location reference mismatch')
    return loc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--historical', type=Path)
    args = parser.parse_args()
    # Both inputs are authenticated before the output directory is created.
    result = analyse(TARGET.read_bytes())
    if args.historical is not None:
        old = historical(args.historical.read_bytes())
        print('historical Location:', json.dumps(old, sort_keys=True))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(result.items()):
        (args.out / name).write_bytes(content)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print('abci_tree_cursor115:', error, file=sys.stderr)
        raise SystemExit(1)
