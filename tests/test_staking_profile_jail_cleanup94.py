"""Controls for the node 94 signer projection and jail reconciliation packet."""
import unittest

from tools import staking_profile_jail_cleanup94 as subject


class ProfileJailCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()
        cls.cases = subject.scenario_specs()

    def run_named(self, name):
        case = next(row for row in self.cases if row[0] == name)
        return subject.run_case(self.image, *case)

    def test_target_digest_is_required(self):
        with self.assertRaisesRegex(subject.EvidenceError, 'SHA-256 mismatch'):
            subject.image_from_blob(b'not the pinned target')
        with self.assertRaisesRegex(subject.EvidenceError, 'SHA-256 mismatch'):
            subject.load_image(expected='0' * 64)

    def test_subject_fdes_and_byte_pins(self):
        functions, rows, relocations = subject.static_data(self.image)
        self.assertEqual(len(functions), 9)
        self.assertEqual(sum(row[5] for row in functions), 2444)
        self.assertEqual(len({row[1] for row in functions}), 9)
        self.assertTrue(all(start < end for _, start, end, *_ in functions))
        self.assertGreater(len(rows), 2444)
        self.assertEqual(len(relocations), 8)

    def test_corrupt_instruction_is_rejected(self):
        subject.check_pins(self.image)
        with self.assertRaisesRegex(subject.EvidenceError, 'signer_head'):
            subject.check_pins(self.image, {0x3BE4020: 0x41})

    def test_no_nobits_or_outside_address(self):
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(-1)
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(1 << 64)
        section = self.image.named['.text']
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(section['address'] + section['size'] - 1, 2)
        bss = self.image.named['.bss']
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(bss['address'])

    def test_capacity_edges(self):
        max_count = ((1 << 63) - 1) // 20
        self.assertEqual(subject.checked_capacity(0), 0)
        self.assertEqual(subject.checked_capacity(max_count), max_count * 20)
        self.assertIsNone(subject.checked_capacity(max_count + 1))
        self.assertIsNone(subject.checked_capacity((1 << 64) - 1))
        for bad in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                subject.checked_capacity(bad)

    def test_failure_paths_are_reached_before_return(self):
        rows = subject.failure_controls(self.image)
        self.assertEqual([r['case'] for r in rows], [
            'signed_size_overflow', 'u64_product_overflow',
            'vector_allocation_failure', 'tree_allocation_failure',
            'profile_node_allocation_failure'])
        self.assertTrue(all(r['failure_reached'] for r in rows))
        self.assertEqual(rows[0]['calls'][0][0], 'failure')
        self.assertEqual(rows[1]['calls'][0][0], 'failure')
        self.assertEqual([r[0] for r in rows[2]['calls']], ['allocate', 'failure'])
        self.assertEqual([r[0] for r in rows[3]['calls']], ['allocate', 'allocate', 'failure'])

    def test_null_profile_root_ignores_stale_count(self):
        fixture = subject.Fixture(self.image)
        fixture.profiles([])
        fixture.write(subject.STATE + 0x160, 123)
        self.assertEqual(fixture.projected(), [])
        self.assertEqual(fixture.boundary, [])

    def test_empty_jail_calls_no_removal(self):
        row = self.run_named('empty_jail')
        self.assertEqual(row['observed_removed'], [])
        self.assertEqual(row['removal_call_keys'], [])
        self.assertTrue(subject.matches(row))

    def test_all_present_or_all_absent(self):
        kept = self.run_named('all_kept')
        removed = self.run_named('all_removed')
        self.assertEqual(kept['observed_removed'], [])
        self.assertEqual(len(removed['observed_removed']), 11)
        self.assertEqual(removed['removal_call_keys'], removed['expected_removed'])
        self.assertTrue(subject.matches(kept) and subject.matches(removed))

    def test_duplicate_signer_is_a_single_set_key(self):
        row = self.run_named('shared_signer')
        self.assertEqual(row['profiles'], 11)
        self.assertEqual(len(row['observed_signers']), 1)
        self.assertEqual(len(row['observed_removed']), 1)
        self.assertTrue(subject.matches(row))

    def test_two_profiles_sharing_signer_preserve_jail_key(self):
        def key(last):
            return bytes(19) + bytes([last])
        pairs = [(key(10), key(1)), (key(11), key(2)), (key(12), key(1))]
        result = subject.run_case(self.image, 'shared_last_byte', pairs, [key(1), key(3)])
        self.assertEqual(result['observed_signers'], [key(1).hex(), key(2).hex()])
        self.assertEqual(result['observed_removed'], [key(3).hex()])
        self.assertEqual(result['removal_call_keys'], [key(3).hex()])
        self.assertTrue(subject.matches(result))

    def test_short_and_long_sort_branch_edges(self):
        twenty = self.run_named('size_20_variant_0')
        twenty_one = self.run_named('size_21_variant_0')
        self.assertIn((0x3BB2933, 0x3BB2935), twenty['edges'])
        self.assertIn((0x3BB2933, 0x3BB296F), twenty_one['edges'])
        self.assertIn(['sort', 21], twenty_one['allocations'])
        self.assertNotIn(['sort', 20], twenty['allocations'])
        self.assertTrue(subject.matches(twenty) and subject.matches(twenty_one))

    def test_small_set_builder_rebalances(self):
        row = self.run_named('size_12_variant_0')
        self.assertIn(subject.REBALANCE, row['reached'])
        self.assertEqual(len(row['observed_signers']), 12)
        self.assertTrue(subject.matches(row))

    def test_jail_vector_growth(self):
        row = self.run_named('all_removed')
        self.assertIn(['grow', 8], row['allocations'])
        self.assertIn(['grow', 16], row['allocations'])
        self.assertTrue(subject.matches(row))

    def test_two_level_jailed_tree_and_vector_growth(self):
        row = self.run_named('jail_tree_23')
        self.assertEqual(row['jail'], 23)
        self.assertEqual(len(row['observed_removed']), 19)
        self.assertEqual(row['removal_call_keys'], row['expected_removed'])
        self.assertIn(['grow', 32], row['allocations'])
        self.assertTrue(subject.matches(row))

    def test_signer_projection_mutation_is_detected(self):
        case = next(row for row in self.cases if row[0] == 'size_05_variant_0')
        result = subject.run_case(self.image, *case, patches={0x3BE4020: 0x41})
        self.assertFalse(subject.matches(result))
        self.assertNotEqual(result['observed_signers'], result['expected_signers'])

    def test_membership_branch_mutation_is_detected(self):
        case = next(row for row in self.cases if row[0] == 'size_11_variant_0')
        result = subject.run_case(self.image, *case, patches={0x3BAC098: 0x85})
        self.assertFalse(subject.matches(result))
        self.assertNotEqual(result['observed_removed'], result['expected_removed'])

    def test_all_240_target_grounded_fixtures(self):
        self.assertEqual(len(self.cases), 240)
        for case in self.cases:
            with self.subTest(case=case[0]):
                result = subject.run_case(self.image, *case)
                self.assertTrue(subject.matches(result))

    def test_profile_replacement_copies_the_full_value_and_returns_old(self):
        row = subject.profile_copy_control(self.image)
        self.assertEqual(row['previous'], row['observed_return'])
        self.assertEqual(row['replacement'], row['observed_stored'])
        self.assertNotEqual(row['previous'], row['replacement'])
        self.assertEqual((row['before_count'], row['after_count']), (1, 1))

    def test_profile_update_changes_cleanup_candidates(self):
        def key(last):
            return bytes(19) + bytes([last])
        pairs = [(key(10), key(1)), (key(11), key(2))]
        result = subject.run_transition(self.image, 'change', pairs, key(10), key(3),
                                        [key(1), key(3), key(4)])
        self.assertEqual(result['observed_old'], key(1).hex())
        self.assertEqual(result['observed_signers'], [key(2).hex(), key(3).hex()])
        self.assertEqual(result['removal_call_keys'], [key(1).hex(), key(4).hex()])
        self.assertTrue(subject.transition_matches(result))

    def test_shared_old_signer_is_retained_after_update(self):
        def key(last):
            return bytes(19) + bytes([last])
        pairs = [(key(10), key(1)), (key(11), key(1))]
        result = subject.run_transition(self.image, 'shared', pairs, key(10), key(3),
                                        [key(1), key(3), key(4)])
        self.assertEqual(result['removal_call_keys'], [key(4).hex()])
        self.assertTrue(subject.transition_matches(result))

    def test_inserting_into_full_leaf_splits_the_profile_tree(self):
        case = next(row for row in subject.transition_specs() if row[0] == 'insert_11')
        result = subject.run_transition(self.image, *case)
        self.assertIsNone(result['observed_old'])
        self.assertEqual(result['profile_count_after'], 12)
        self.assertEqual(result['profile_height_after'], 1)
        self.assertIn(subject.PROFILE_INSERT, result['reached'])
        self.assertIn((0x2F65A42, 0x2F65A44), result['edges'])
        self.assertTrue(subject.transition_matches(result))

    def test_profile_write_mutation_is_detected(self):
        case = subject.transition_specs()[8]
        result = subject.run_transition(self.image, *case, patches={0x33A4747: 0x41})
        self.assertFalse(subject.transition_matches(result))

    def test_all_70_profile_write_transitions(self):
        cases = subject.transition_specs()
        self.assertEqual(len(cases), 70)
        for case in cases:
            with self.subTest(case=case[0]):
                self.assertTrue(subject.transition_matches(subject.run_transition(self.image, *case)))

    def test_fixture_rejects_ambiguous_or_oversize_data(self):
        k = subject.address('bad', 1)
        fixture = subject.Fixture(self.image)
        with self.assertRaises(ValueError):
            fixture.profiles([(k, k), (k, k)])
        with self.assertRaises(ValueError):
            fixture.profiles([(subject.address('too-many', i), k) for i in range(24)])
        with self.assertRaises(ValueError):
            fixture.profiles([(b'short', k)])
        fixture.profiles([])
        fixture.projected()
        with self.assertRaises(ValueError):
            fixture.difference([k, k], 0, 0)


if __name__ == '__main__':
    unittest.main()
