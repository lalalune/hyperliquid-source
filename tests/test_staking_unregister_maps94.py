"""Target-grounded controls for validator map removal, without native execution."""
import copy
import hashlib
import unittest

from tools import staking_unregister_maps94 as m


class ValidatorRemovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = m.load_image()

    def test_authentic_digest(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), m.SHA256)

    def test_corrupted_digest_is_rejected_before_parsing(self):
        altered = bytearray(self.image.blob)
        altered[-1] ^= 1
        with self.assertRaisesRegex(m.EvidenceError, 'SHA-256 mismatch'):
            m.image_from_blob(altered)

    def test_context_pins_match_input(self):
        self.assertEqual(len(m.verify_pins(self.image)), len(m.PINS))

    def test_corrupt_context_bytes_are_rejected(self):
        altered = copy.copy(self.image)
        data = bytearray(self.image.blob)
        data[self.image.offset(m.PINS[0][1])] ^= 1
        altered.blob = bytes(data)
        with self.assertRaisesRegex(m.EvidenceError, 'context bytes changed'):
            m.verify_pins(altered)

    def test_out_of_section_address_is_rejected(self):
        with self.assertRaises(m.EvidenceError):
            self.image.offset(0xffffffffffffffff, 8)

    def test_nobits_address_is_not_a_file_mapping(self):
        sec = next(s for s in self.image.sections if s['type'] == 8 and s['name'] == '.bss' and s['size'])
        with self.assertRaises(m.EvidenceError):
            self.image.offset(sec['address'], 1)

    def test_dynamic_copy_and_compare_slots_are_symbol_bound(self):
        rows = m.slot_rows(self.image)
        self.assertEqual({row[3] for row in rows}, {'', 'memcmp', 'memmove', 'memcpy'})
        self.assertEqual(len(rows), 4)

    def test_refusal_status_text_is_loaded_from_the_binary(self):
        tag, _, _, _, size, text = m.status_text(self.image)
        self.assertEqual(tag, 0x12f)
        self.assertEqual(size, len(text))
        self.assertEqual(text, 'Cannot unregister validator with delegations')

    def test_mid_function_is_not_exact_fde(self):
        with self.assertRaises(m.EvidenceError):
            self.image.exact_fde(m.STATE_REMOVE + 1)

    def test_every_selected_window_decodes_without_branch_interiors(self):
        instructions, transfers, branches = m.function_rows(self.image)
        self.assertGreater(len(instructions), 2500)
        self.assertGreater(len(transfers), 300)
        self.assertGreater(len(branches), 150)

    def test_branch_into_operand_is_rejected(self):
        altered = copy.copy(self.image)
        data = bytearray(self.image.blob)
        site = m.STATE_REMOVE + 0x19
        data[self.image.offset(site + 2, 4):self.image.offset(site + 2, 4) + 4] = (-4).to_bytes(4, 'little', signed=True)
        altered.blob = bytes(data)
        with self.assertRaisesRegex(m.EvidenceError, 'branch lands inside'):
            m.function_rows(altered)

    def test_context_edges_bind_the_distinct_removal_roots(self):
        def decode_at(address):
            return m.decode(lambda a, n: self.image.blob[self.image.offset(a, n):self.image.offset(a, n) + n], address)
        self.assertEqual(decode_at(0x39951a0).target, m.PROFILE_REMOVE)
        self.assertEqual(decode_at(0x39951f9).target, m.STATE_REMOVE)
        self.assertEqual(decode_at(0x3995184).target, m.STAKE_SEARCH)

    def test_null_and_empty_roots_are_misses(self):
        for kind in ('state', 'profile'):
            for shape in (None, 0):
                with self.subTest(kind=kind, shape=shape):
                    case, before, after, result, _, _ = m.run_case(self.image, kind, shape, 1)
                    self.assertIsNone(result)
                    self.assertEqual(before, after)
                    self.assertEqual(case.events, [])

    def test_present_leaf_entries_return_exact_values(self):
        for kind in ('state', 'profile'):
            for number in (2, 12, 22):
                with self.subTest(kind=kind, number=number):
                    _, before, after, result, old_height, new_height = m.run_case(self.image, kind, 11, number)
                    self.assertEqual(result, m.value_bytes(kind, number))
                    self.assertEqual(len(after), len(before) - 1)
                    self.assertEqual((old_height, new_height), (0, 0))

    def test_state_removes_both_blocked_flag_values(self):
        for number, flag in ((2, 1), (4, 0)):
            with self.subTest(flag=flag):
                _, _, after, result, _, _ = m.run_case(self.image, 'state', 5, number)
                self.assertEqual(result[24], flag)
                self.assertNotIn(m.key_bytes(number), dict(after))

    def test_misses_at_both_ends_and_between_keys(self):
        for kind in ('state', 'profile'):
            for number in (1, 7, 23):
                with self.subTest(kind=kind, number=number):
                    _, before, after, result, _, _ = m.run_case(self.image, kind, 11, number)
                    self.assertIsNone(result)
                    self.assertEqual(after, before)

    def test_internal_entry_uses_predecessor_and_leaf_entry_does_not(self):
        for kind, cursor in (('state', m.STATE_CURSOR), ('profile', m.PROFILE_CURSOR)):
            with self.subTest(kind=kind):
                internal, *_ = m.run_case(self.image, kind, (5, 5), 12)
                leaf, *_ = m.run_case(self.image, kind, (5, 5), 2)
                row = m.decode(internal.machine.read_code, cursor + 0x19)
                self.assertIn((row.va, row.next), internal.machine.edges)
                self.assertIn((row.va, row.target), leaf.machine.edges)

    def test_merge_shrinks_root_and_frees_two_nodes(self):
        for kind in ('state', 'profile'):
            with self.subTest(kind=kind):
                case, _, _, _, old, new = m.run_case(self.image, kind, (5, 5), 2)
                self.assertEqual((old, new), (1, 0))
                self.assertEqual(len(case.events), 2)
                self.assertEqual(sorted(size for action, size in case.events),
                                 sorted((case.g['leaf_size'], case.g['inner_size'])))

    def test_merge_borrow_boundary_is_twelve(self):
        for kind in ('state', 'profile'):
            for shape, number, wanted in (((5, 6), 2, 'right_merge'),
                                           ((6, 5), 24, 'left_merge'),
                                           ((5, 7), 2, 'right_borrow'),
                                           ((7, 5), 26, 'left_borrow')):
                with self.subTest(kind=kind, shape=shape):
                    case, *_ = m.run_case(self.image, kind, shape, number)
                    self.assertEqual(case.first_repair, wanted)

    def test_three_level_cascade_and_sequence(self):
        for kind in ('state', 'profile'):
            with self.subTest(kind=kind):
                case, _, _, _, old, new = m.run_case(self.image, kind, m.DEEP_SHAPE, 2, pivot=None)
                self.assertEqual((old, new), (3, 2))
                self.assertEqual(len(case.events), 4)
                case, before, drops = m.run_sequence(self.image, kind, m.DEEP_SHAPE,
                                                     list(range(431, 0, -1)), pivot=None)
                self.assertEqual((len(before), drops), (431, 3))
                self.assertEqual(case.contents()[0], [])

    def test_right_borrow_preserves_height(self):
        for kind, helper in (('state', m.STATE_RIGHT), ('profile', m.PROFILE_RIGHT)):
            with self.subTest(kind=kind):
                case, _, _, _, old, new = m.run_case(self.image, kind, (5, 7), 2)
                self.assertEqual((old, new), (1, 1))
                self.assertIn(helper, case.machine.seen)
                self.assertEqual(case.events, [])

    def test_left_borrow_preserves_height(self):
        for kind, helper in (('state', m.STATE_LEFT), ('profile', m.PROFILE_LEFT)):
            with self.subTest(kind=kind):
                case, _, _, _, old, new = m.run_case(self.image, kind, (7, 5), 26)
                self.assertEqual((old, new), (1, 1))
                self.assertIn(helper, case.machine.seen)
                self.assertEqual(case.events, [])

    def test_two_level_cascading_merge(self):
        shape = ((5, 5, 5, 5, 5, 5), (5, 5, 5, 5, 5, 5))
        for kind in ('state', 'profile'):
            with self.subTest(kind=kind):
                case, _, _, _, old, new = m.run_case(self.image, kind, shape, 2)
                self.assertEqual((old, new), (2, 1))
                self.assertEqual(len(case.events), 3)

    def test_full_sequential_removal_keeps_tree_valid(self):
        shape = ((5, 5, 5, 5, 5, 5), (5, 5, 5, 5, 5, 5))
        for kind in ('state', 'profile'):
            with self.subTest(kind=kind):
                case, before, drops = m.run_sequence(self.image, kind, shape, list(range(1, 72)))
                self.assertEqual(len(before), 71)
                self.assertEqual(drops, 2)
                self.assertEqual(case.contents()[0], [])

    def test_sequence_requires_permutation(self):
        with self.assertRaisesRegex(ValueError, 'permutation'):
            m.run_sequence(self.image, 'state', 5, [1, 2, 2, 4, 5])

    def test_each_key_byte_controls_comparison(self):
        for pivot in range(20):
            with self.subTest(byte=pivot):
                for kind in ('state', 'profile'):
                    _, _, _, result, _, _ = m.run_case(self.image, kind, (5, 7), 12, pivot=pivot)
                    self.assertEqual(result, m.value_bytes(kind, 12))
                    _, before, after, result, _, _ = m.run_case(self.image, kind, (5, 7), 11, pivot=pivot)
                    self.assertIsNone(result)
                    self.assertEqual(before, after)
                _, result, _, _ = m.run_stake_probe(self.image, (5, 7), 12, pivot)
                self.assertEqual(result, 'boundary')

    def test_bad_fixture_key_pivot_is_rejected(self):
        with self.assertRaises(ValueError):
            m.key_bytes(2, 20)
        with self.assertRaises(ValueError):
            m.key_bytes(256)

    def test_stake_miss_or_real_cursor_boundary(self):
        for key, wanted in ((1, 'miss'), (2, 'boundary'), (12, 'boundary'), (23, 'miss')):
            with self.subTest(key=key):
                _, result, count, _ = m.run_stake_probe(self.image, (5, 5), key)
                self.assertEqual(result, wanted)
                self.assertEqual(count, 11)

    def test_corrupt_fixture_parent_and_occupancy_detected(self):
        c = m.TreeCase(self.image, 'state')
        c.build((5, 5))
        root = c.mem.read(m.MAP_AT, 8)
        child = c.mem.read(root + c.g['children'], 8)
        c.mem.write(child + c.g['parent'], 8, 0)
        with self.assertRaisesRegex(m.Halt, 'wrong parent pointer'):
            c.contents()
        c.mem.write(child + c.g['parent'], 8, root)
        c.mem.write(child + c.g['length'], 2, 12)
        with self.assertRaisesRegex(m.Halt, 'occupancy'):
            c.contents()

    def test_borrow_and_merge_failure_boundaries(self):
        rows = m.failure_controls(self.image)
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(row[-1] == 'panic' for row in rows))
        self.assertEqual({row[2] for row in rows}, {'capacity', 'source_underflow', 'cursor'})

    def test_independent_negative_byte_controls(self):
        rows = m.mutation_controls(self.image)
        self.assertEqual(len(rows), 8)
        self.assertTrue(all(row[2] != row[3] for row in rows))
        self.assertEqual({row[-1] for row in rows}, {'EvidenceError', 'Panicked'})


if __name__ == '__main__':
    unittest.main()
