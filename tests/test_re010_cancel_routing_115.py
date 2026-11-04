"""Target-bound static controls for the selected #115 action path."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_cancel_routing_115 as packet
from elf_index import unwind_index
from fde_extents import eh_frame_records


def synthetic_section(address, data):
    return [{'name': 'synthetic', 'type': 1, 'flags': 6,
             'address': address, 'offset': 0, 'size': len(data)}]


class CancelRoutingEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = packet.BINARY.read_bytes()
        packet.verify_digest(cls.binary)
        cls.sections, cls.index = unwind_index(cls.binary)
        _, cls.fdes = eh_frame_records(cls.binary, cls.sections)
        cls.selected = packet.checked_functions(cls.binary, cls.sections, cls.index, cls.fdes)
        cls.relocations = packet.relocs(cls.binary, cls.sections)
        cls.success = 0x1a2
        cls.forbidden = 0x174
        cls.limit = 10001
        cls.magic = 0x346dc5d63886594b

    def test_target_digest_is_exact(self):
        self.assertEqual(hashlib.sha256(self.binary).hexdigest(), packet.SHA256)

    def test_digest_rejects_wrong_input(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            packet.verify_digest(b'not the authenticated ELF')

    def test_digest_rejects_single_byte_corruption(self):
        corrupt = bytearray(self.binary)
        corrupt[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            packet.verify_digest(corrupt)

    def test_every_selected_body_matches_its_fde_and_index(self):
        self.assertEqual(len(self.selected), 22)
        for role, (start, end, digest) in packet.FUNCTIONS.items():
            with self.subTest(role=role):
                record = self.selected[role]
                self.assertEqual((record['start'], record['end']), (start, end))
                raw = packet.at(self.binary, self.sections, start, end - start)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)

    def test_fde_end_corruption_is_rejected(self):
        start = packet.FUNCTIONS['batch_core'][0]
        changed = [dict(f, end=f['end'] + 1) if f['start'] == start else f for f in self.fdes]
        with self.assertRaisesRegex(ValueError, 'FDE bounds'):
            packet.checked_functions(self.binary, self.sections, self.index, changed)

    def test_fde_pointer_corruption_is_rejected(self):
        start = packet.FUNCTIONS['batch_core'][0]
        changed = [dict(row, fde=row['fde'] + 1) if row['start'] == start else row for row in self.index]
        with self.assertRaisesRegex(ValueError, 'header reference'):
            packet.checked_functions(self.binary, self.sections, changed, self.fdes)

    def test_missing_and_duplicate_fde_are_rejected(self):
        start = packet.FUNCTIONS['batch_core'][0]
        record = next(row for row in self.fdes if row['start'] == start)
        for edited in ([row for row in self.fdes if row['start'] != start], self.fdes + [record]):
            with self.subTest(size=len(edited)):
                with self.assertRaisesRegex(ValueError, 'one indexed FDE'):
                    packet.checked_functions(self.binary, self.sections, self.index, edited)

    def test_body_corruption_is_rejected_without_digest_shortcut(self):
        corrupt = bytearray(self.binary)
        start, _, _ = packet.FUNCTIONS['group_collector']
        off = packet.file_offset(self.sections, start + 5, 1)
        corrupt[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'body hash mismatch'):
            packet.checked_functions(corrupt, self.sections, self.index, self.fdes)

    def test_selected_ranges_do_not_cross_fde_boundary(self):
        for _, va, size in packet.WINDOWS:
            self.assertIn(packet.within_function(va, size, self.selected), self.selected)
        start, end, _ = packet.FUNCTIONS['group_collector']
        with self.assertRaisesRegex(ValueError, 'inside one selected FDE'):
            packet.within_function(end - 1, 2, self.selected)
        with self.assertRaisesRegex(ValueError, 'inside one selected FDE'):
            packet.within_function(start - 1, 1, self.selected)

    def test_nobits_range_rejected(self):
        bss = next(s for s in self.sections if s['name'] == '.bss')
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            packet.file_offset(self.sections, bss['address'], 1)

    def test_unmapped_and_zero_length_rejected(self):
        for va, length in ((0xffffffffffffffff, 4), (0, 1), (0x2608f40, 0), (-1, 1)):
            with self.subTest(va=va, length=length):
                with self.assertRaises(ValueError):
                    packet.file_offset(self.sections, va, length)

    def test_ambiguous_mapping_rejected(self):
        raw = b'12345678'
        one = synthetic_section(0x1000, raw)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            packet.file_offset(one + one, 0x1000, 1)

    def test_section_end_is_exclusive(self):
        sec = synthetic_section(0x1000, b'abcd')
        self.assertEqual(packet.at(b'abcd', sec, 0x1003, 1), b'd')
        with self.assertRaises(ValueError):
            packet.at(b'abcd', sec, 0x1003, 2)

    def test_internal_tag_seventeen_tables_and_handler(self):
        sites = (0x2c47699, 0x2c47a4a, 0x2c4879a)
        tables = (0x60a7a8, 0x60a800, 0x60a848)
        targets = (0x2c479ad, 0x2c48325, 0x2c492d1)
        for site, table, target in zip(sites, tables, targets):
            with self.subTest(site=site):
                self.assertEqual(packet.lea_target(self.binary, self.sections, site), table)
                self.assertEqual(packet.table_target(self.binary, self.sections, table, 17), target)
                self.assertEqual(packet.within_function(target, 1, self.selected), 'subaction_dispatch')
        self.assertEqual(packet.call(self.binary, self.sections, self.relocations,
                                     0x2c49fa8, 0x2c4d2f0)[1], 0x2c4d2f0)

    def test_nested_selected_branch_reaches_guarded_state_core(self):
        nested = packet.lea_target(self.binary, self.sections, 0x2c4d8f9)
        self.assertEqual(nested, 0x60ae4c)
        self.assertEqual(packet.table_target(self.binary, self.sections, nested, 0), 0x2c4d909)
        self.assertEqual(packet.table_target(self.binary, self.sections, nested, 3), 0x2c4dd6b)
        for site, target in ((0x2c4dd9d, 0x2c36770), (0x2c36878, 0x2c343b0),
                             (0x2c357e3, 0x2c36af0)):
            with self.subTest(site=site):
                self.assertEqual(packet.call(self.binary, self.sections, self.relocations, site, target)[1], target)

    def test_subpath_rejects_length_and_bounds_failure_is_nonreturning(self):
        self.assertEqual(packet.branch(self.binary, self.sections, 0x2c3678d, 'ae', 0x2c368ee)[1], 0x2c368ee)
        self.assertEqual(packet.branch(self.binary, self.sections, 0x2c367bf, 'ae', 0x2c3687f)[1], 0x2c3687f)
        self.assertEqual(packet.at(self.binary, self.sections, 0x2c3687f, 5), bytes.fromhex('66c7035801'))
        self.assertEqual(packet.at(self.binary, self.sections, 0x2c3691a, 2), bytes.fromhex('0f0b'))

    def test_guarded_state_word_store_opcodes(self):
        for site, code in ((0x2c35793, '498b475848ffc048c7c1ffffffff480f45c849894f58'),
                           (0x2c357e8, '498b46584883f8014883d0ff49894658')):
            with self.subTest(site=site):
                expected = bytes.fromhex(code)
                self.assertEqual(packet.at(self.binary, self.sections, site, len(expected)), expected)

    def test_guarded_state_word_saturates_and_floors(self):
        maximum = (1 << 64) - 1
        f = packet.guarded_state_word_model
        self.assertEqual(f(0, 0), (1, 0))
        self.assertEqual(f(9, 10), (10, 9))
        self.assertEqual(f(maximum, maximum), (maximum, maximum - 1))
        self.assertNotEqual(f(maximum, maximum)[1], maximum)
        self.assertEqual(f(9, 3), (10, 2))

    def test_guarded_state_word_rejects_invalid_inputs(self):
        for pair in ((-1, 0), (0, -1), (1 << 64, 0), (0, 1 << 64), ('x', 0)):
            with self.subTest(pair=pair):
                with self.assertRaises(ValueError):
                    packet.guarded_state_word_model(*pair)

    def test_internal_tag_seventeen_length_boundaries(self):
        first = packet.at(self.binary, self.sections, 0x2c479bb, 4)
        second = packet.at(self.binary, self.sections, 0x2c49341, 4)
        self.assertEqual(first, bytes.fromhex('4883f964'))
        self.assertEqual(second, bytes.fromhex('4883fb65'))
        self.assertEqual(packet.branch(self.binary, self.sections, 0x2c479bf, 'a', 0x2c479a3)[1], 0x2c479a3)
        self.assertEqual(packet.branch(self.binary, self.sections, 0x2c49345, 'b', 0x2c49f14)[1], 0x2c49f14)
        for length in (0, 1, 99, 100, 101, 102):
            with self.subTest(length=length):
                self.assertEqual(length <= first[-1], length < second[-1])
        self.assertNotEqual(101 <= first[-1], 101 <= second[-1])

    def test_bad_lea_opcode_is_rejected(self):
        code = b'\x90\x8d\x05\0\0\0\0'
        with self.assertRaisesRegex(ValueError, 'lea'):
            packet.lea_target(code, synthetic_section(0x1000, code), 0x1000)

    def test_jump_table_mutation_is_rejected(self):
        table = 0x1000
        code = bytearray(16)
        struct.pack_into('<i', code, 12, 0x30)
        secs = synthetic_section(table, code)
        self.assertEqual(packet.table_target(code, secs, table, 3, 0x1030), 0x1030)
        code[12] ^= 1
        with self.assertRaisesRegex(ValueError, 'table target mismatch'):
            packet.table_target(code, secs, table, 3, 0x1030)

    def test_jump_table_ordinal_bounds(self):
        for index in (-1, 18, 100000):
            with self.subTest(index=index):
                with self.assertRaisesRegex(ValueError, 'ordinal'):
                    packet.table_target(self.binary, self.sections, 0x60a7a8, index)

    def test_all_selected_branches_have_pinned_conditions(self):
        for label, site, condition in packet.BRANCHES:
            with self.subTest(label=label):
                kind, target, raw = packet.branch(self.binary, self.sections, site, condition)
                self.assertEqual(kind, condition)
                self.assertEqual(packet.within_function(site, len(raw), self.selected),
                                 packet.within_function(target, 1, self.selected))

    def test_branch_displacement_corruption_is_rejected(self):
        site = 0x1000
        raw = bytearray(b'\x0f\x85\x04\x00\x00\x00')
        sections = synthetic_section(site, raw)
        self.assertEqual(packet.branch(raw, sections, site, 'ne', 0x100a)[1], 0x100a)
        raw[2] ^= 1
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            packet.branch(raw, sections, site, 'ne', 0x100a)

    def test_branch_condition_corruption_is_rejected(self):
        site = 0x1000
        raw = b'\x74\x04'
        with self.assertRaisesRegex(ValueError, 'condition'):
            packet.branch(raw, synthetic_section(site, raw), site, 'ne')

    def test_direct_call_corruption_is_rejected(self):
        site = 0x1000
        raw = bytearray(b'\xe8\x05\x00\x00\x00')
        sections = synthetic_section(site, raw)
        self.assertEqual(packet.call(raw, sections, {}, site, 0x100a)[1], 0x100a)
        raw[1] ^= 1
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            packet.call(raw, sections, {}, site, 0x100a)

    def test_all_selected_calls_and_relocations(self):
        for label, site, target in packet.CALLS:
            with self.subTest(label=label):
                kind, actual, slot, raw = packet.call(self.binary, self.sections, self.relocations, site, target)
                self.assertEqual(actual, target)
                self.assertIn(packet.within_function(site, len(raw), self.selected), self.selected)
                if kind == 'relative_slot':
                    self.assertEqual(self.relocations[slot][0], 8)
                    self.assertEqual(self.relocations[slot][1], target)

    def test_wrong_relocation_and_missing_slot_are_rejected(self):
        site = 0x1000
        raw = b'\xff\x15\x00\x00\x00\x00'
        sections = synthetic_section(site, raw)
        for records in ({}, {0x1006: (7, 0x3000, 0)}, {0x1006: (8, 0x3001, 0)}):
            with self.subTest(records=records):
                with self.assertRaises(ValueError):
                    packet.call(raw, sections, records, site, 0x3000)

    def test_magic_division_boundaries(self):
        for n in (0, 1, 9999, 10000, 10001, 99999, 100000, 99900255, 0xffffffff):
            with self.subTest(n=n):
                self.assertEqual(packet.divide_magic(n, self.magic), n // 10000)

    def test_magic_division_synthetic_wide_grid(self):
        for n in range(0, 1 << 24, 997):
            self.assertEqual(packet.divide_magic(n, self.magic), n // 10000)
        # M*10000 = 2**75 + 432. The excess is smaller than one
        # remainder step for every u32, proving the floor cannot cross it.
        self.assertEqual(self.magic * 10000 - (1 << 75), 432)
        self.assertLess(((1 << 32) - 1) * 432, 1 << 75)

    def test_magic_corruption_has_negative_control(self):
        self.assertNotEqual(packet.divide_magic(10000, self.magic - 1), 10000 // 10000)
        with self.assertRaises(ValueError):
            packet.divide_magic(1 << 32, self.magic)

    def test_asset_partition_boundary_cases(self):
        low, middle, high = 10000, 110000, 100000000
        cases = ((0, (0, 0)), (9999, (0, 9999)), (10000, (1, 0)),
                 (109999, (1, 99999)), (110000, (0, 10000)),
                 (99999999, (0, 99899999)), (100000000, (1, 100000000)))
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(packet.candidate_partition(raw, low, middle, high), expected)
        for raw in (-1, 1 << 32):
            with self.assertRaises(ValueError):
                packet.candidate_partition(raw, low, middle, high)

    def test_second_multiply_shift_on_u32_domain(self):
        multiplier = packet.u32(self.binary, self.sections, 0x46aad0a)
        self.assertEqual(multiplier, 0xd1b71759)
        for n in range(0, 1 << 24, 997):
            self.assertEqual((n * multiplier) >> 45, n // 10000)
        self.assertEqual(multiplier * 10000 - (1 << 45), 1168)
        self.assertLess(((1 << 32) - 1) * 1168, 1 << 45)
        self.assertLess(((1 << 32) - 1) * multiplier, 1 << 64)
        self.assertNotEqual((10000 * (multiplier - 1)) >> 45, 1)

    def test_wrong_range_boundary_changes_decision(self):
        actual = packet.candidate_partition(10000, 10000, 110000, 100000000)
        corrupt = packet.candidate_partition(10000, 10001, 110000, 100000000)
        self.assertNotEqual(actual, corrupt)

    def test_item_check_classifier_transfer(self):
        kind, target, slot, raw = packet.call(self.binary, self.sections, self.relocations,
                                               0x2c4eef3, 0x46aac00)
        self.assertEqual((kind, target, slot), ('relative_slot', 0x46aac00, 0x64e5b38))
        self.assertEqual(packet.within_function(0x2c4eef3, len(raw), self.selected), 'tag17_item_check')

    def test_item_check_success_and_wrong_group(self):
        f = packet.item_check_model
        args = (self.success, self.forbidden, 0x156, self.magic)
        self.assertEqual(f(self.success, 0, 9999, 0, *args), (self.success, 9999))
        self.assertEqual(f(self.success, 0, 10000, 1, *args), (self.success, 10000))
        self.assertEqual(f(self.success, 0, 10000, 0, *args), (0x156, None))
        self.assertNotEqual(f(self.success, 0, 10000, 0, *args), (self.success, 10000))

    def test_item_check_propagates_error_and_forbids_kind_one(self):
        f = packet.item_check_model
        args = (self.success, self.forbidden, 0x156, self.magic)
        self.assertEqual(f(0x64, 0, 0, 0, *args), (0x64, None))
        self.assertEqual(f(self.success, 1, 0, 0, *args), (self.forbidden, None))
        with self.assertRaisesRegex(ValueError, 'kind'):
            f(self.success, 2, 0, 0, *args)
        with self.assertRaisesRegex(ValueError, 'expected group'):
            f(self.success, 0, 1, -1, *args)

    def test_preflight_empty_and_duplicate_groups(self):
        model = packet.preflight_model
        self.assertEqual(model(0, [], self.limit, self.success, self.forbidden, self.magic), (self.success, ()))
        items = [(self.success, 0, 1), (self.success, 0, 9999), (self.success, 0, 10000)]
        self.assertEqual(model(3, items, self.limit, self.success, self.forbidden, self.magic), (self.success, (0, 1)))

    def test_preflight_rejects_classifier_error_before_later_items(self):
        items = [(self.success, 0, 2), (0x64, 0, 0), (self.success, 1, 0)]
        self.assertEqual(packet.preflight_model(3, items, self.limit, self.success, self.forbidden, self.magic), (0x64, ()))

    def test_preflight_rejects_kind_one(self):
        items = [(self.success, 1, 0)]
        self.assertEqual(packet.preflight_model(1, items, self.limit, self.success, self.forbidden, self.magic), (self.forbidden, ()))

    def test_preflight_length_limit_precedes_items(self):
        self.assertEqual(packet.preflight_model(self.limit, [], self.limit, self.success, self.forbidden, self.magic), (0x158, ()))
        with self.assertRaisesRegex(ValueError, 'count mismatch'):
            packet.preflight_model(self.limit - 1, [], self.limit, self.success, self.forbidden, self.magic)

    def test_preflight_rejects_unknown_kind(self):
        with self.assertRaisesRegex(ValueError, 'kind'):
            packet.preflight_model(1, [(self.success, 2, 0)], self.limit, self.success, self.forbidden, self.magic)

    def test_walk_invokes_finalizers_after_children(self):
        graph = {1: [2, 3], 2: [4], 3: [], 4: []}
        self.assertEqual(packet.walk_model(1, graph), (2, (4, 2, 3, 1)))
        self.assertNotEqual(packet.walk_model(1, graph)[1], (1, 2, 4, 3))

    def test_walk_missing_root_and_missing_child(self):
        self.assertEqual(packet.walk_model(1, {}), (0, ()))
        graph = {1: [2, 3], 2: [4], 4: []}
        self.assertEqual(packet.walk_model(1, graph), (2, (4, 2, 1)))

    def test_walk_real_transfer_sites_and_return_immediates(self):
        for site, expected in ((0x23cdee2, 0x23cdb30), (0x23ce34d, 0x23cdf70),
                               (0x23cdf16, 0x23ce3e0), (0x23ce383, 0x23d0600)):
            with self.subTest(site=site):
                self.assertEqual(packet.call(self.binary, self.sections, self.relocations, site, expected)[1], expected)
        self.assertEqual(packet.at(self.binary, self.sections, 0x23cdf1b, 2), b'\xb0\x02')
        self.assertEqual(packet.at(self.binary, self.sections, 0x23ce388, 2), b'\xb0\x02')

    def test_link_clear_missing_first_leaves_both_words_unchanged(self):
        self.assertEqual(packet.clear_model(False, 1, True, 99), (1, 99))

    def test_link_clear_non_one_leaves_peer_unchanged(self):
        for first in (0, 2, (1 << 32) + 2):
            with self.subTest(first=first):
                self.assertEqual(packet.clear_model(True, first, True, 99), (0, 99))

    def test_link_clear_missing_peer_follows_first_store(self):
        self.assertEqual(packet.clear_model(True, 1, False, 99), (0, 99))
        self.assertNotEqual(packet.clear_model(True, 1, False, 99), (1, 99))

    def test_link_clear_uses_only_low_u32_for_peer(self):
        for first in (1, (1 << 32) + 1):
            with self.subTest(first=first):
                self.assertEqual(packet.clear_model(True, first, True, 99), (0, 0))

    def test_link_clear_rejects_invalid_words(self):
        for first, second in ((-1, 0), (1 << 64, 0), (1, -1), (1, 1 << 64), ('1', 2)):
            with self.subTest(first=first, second=second):
                with self.assertRaises(ValueError):
                    packet.clear_model(True, first, True, second)

    def test_link_clear_store_bytes_and_finalizer_calls(self):
        for first, second in ((0x23d4474, 0x23d4741), (0x23d3e24, 0x23d40f1)):
            with self.subTest(first=first):
                self.assertEqual(packet.at(self.binary, self.sections, first, 8),
                                 b'\x48\xc7\x40\x20\x00\x00\x00\x00')
                self.assertEqual(packet.at(self.binary, self.sections, second, 8),
                                 b'\x48\xc7\x40\x20\x00\x00\x00\x00')
        for site, destination in ((0x23ce773, 0x23d4140), (0x23d09a7, 0x23d3af0)):
            with self.subTest(site=site):
                self.assertEqual(packet.call(self.binary, self.sections, self.relocations,
                                             site, destination)[1], destination)

    def test_counters_include_failures_in_batch_but_not_success_count(self):
        got = packet.counter_model(3, 7, 11, 1, self.limit, self.success)
        self.assertEqual(got, (self.success, 10, 12))

    def test_counters_saturate_without_wrapping(self):
        maximum = (1 << 64) - 1
        got = packet.counter_model(2, maximum - 1, maximum, 2, self.limit, self.success)
        self.assertEqual(got, (self.success, maximum, maximum))

    def test_batch_limit_prevents_counter_change(self):
        got = packet.counter_model(self.limit, 4, 9, 1, self.limit, self.success)
        self.assertEqual(got, (0x158, 4, 9))
        self.assertEqual(packet.counter_model(self.limit - 1, 4, 9, 0, self.limit, self.success),
                         (self.success, 10004, 9))

    def test_counter_inputs_reject_impossible_state(self):
        for args in [(-1, 0, 0, 0), (1, -1, 0, 0), (1, 1 << 64, 0, 0), (1, 0, 0, 2)]:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    packet.counter_model(*args, self.limit, self.success)


if __name__ == '__main__':
    unittest.main()
