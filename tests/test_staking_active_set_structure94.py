"""Target-backed tests for the active-validator set structure path."""
import hashlib
import unittest

from tools import staking_active_set_structure94 as subject


class ActiveSetStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()
        cls.functions, cls.pins, cls.relocations, cls.decoded = subject.verify_static(cls.image)

    def test_full_digest_is_required(self):
        with self.assertRaisesRegex(subject.EvidenceError, 'SHA-256 mismatch'):
            subject.image_from_blob(self.image.blob, '0' * 64)

    def test_corrupted_selected_body_is_rejected_even_with_new_digest(self):
        data = bytearray(self.image.blob)
        data[self.image.offset(subject.CLONE)] ^= 1
        damaged = subject.image_from_blob(data, hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(subject.EvidenceError, 'body hash mismatch'):
            subject.verify_static(damaged)

    def test_corrupted_caller_anchor_is_rejected(self):
        data = bytearray(self.image.blob)
        data[self.image.offset(0x3c11d79)] ^= 1
        damaged = subject.image_from_blob(data, hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(subject.EvidenceError, 'pin mismatch'):
            subject.verify_static(damaged)

    def test_duplicate_relocation_is_rejected(self):
        section = self.image.named['.rela.dyn']
        data = bytearray(self.image.blob)
        locations = []
        target = None
        for pos in range(section['offset'], section['offset'] + section['size'], 24):
            if int.from_bytes(data[pos:pos+8], 'little') == subject.SLOT_ALLOC:
                target = pos
            else:
                locations.append(pos)
        self.assertIsNotNone(target)
        data[locations[0]:locations[0]+24] = data[target:target+24]
        damaged = subject.image_from_blob(data, hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(subject.EvidenceError, 'ambiguous slot relocation'):
            subject.verify_static(damaged)

    def test_nobits_and_unmapped_address_are_not_file_bytes(self):
        bss = self.image.named['.bss']
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(bss['address'])
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(0xffffffffffffffff)

    def test_fde_entry_and_machine_bounds_are_checked(self):
        with self.assertRaises(subject.EvidenceError):
            self.image.exact_fde(subject.CLONE + 1)
        f = subject.Fixture(self.image)
        with self.assertRaisesRegex(subject.Halt, 'left selected FDEs'):
            f.m.run(1, {})

    def test_clone_empty_leaf_allocates_a_distinct_empty_root(self):
        f = subject.Fixture(self.image)
        keys, height, length, shape, _ = f.clone(None, [0], 0)
        self.assertEqual((keys, height, length, shape), ([], 0, 0, [(0, 0)]))
        self.assertEqual(f.events, [('alloc', 0xe8)])

    def test_clone_retains_all_twenty_key_bytes(self):
        f = subject.Fixture(self.image)
        keys, height, length, _, _ = f.clone(None, [11], 0)
        self.assertEqual(keys, subject.key_sequence(11))
        self.assertEqual((height, length), (0, 11))

    def test_clone_retains_shape_and_repairs_parent_links(self):
        shape = [[None] * 6, [None] * 6]
        leaves = [5] * 12
        f = subject.Fixture(self.image)
        keys, h, n, actual, _ = f.clone(shape, leaves, 2)
        expected_shape, expected_count = subject.shape_expectation(shape, leaves)
        self.assertEqual((h, n, actual), (2, expected_count, expected_shape))
        self.assertEqual(keys, subject.key_sequence(expected_count))

    def test_binary_foundation_fixture_preserves_every_key_byte(self):
        rows = subject.foundation_inputs(self.image)
        self.assertEqual([sum(r[0] == chain for r in rows) for chain in (1, 2, 3)], [4, 4, 5])
        for chain in (1, 2, 3):
            expected = sorted(bytes.fromhex(row[3]) for row in rows if row[0] == chain)
            f = subject.Fixture(self.image)
            actual, height, count, _, _ = f.clone(None, [len(expected)], 0, keys=expected)
            self.assertEqual((actual, height, count), (expected, 0, len(expected)))

    def test_clone_rejects_too_many_keys_at_failure_boundary(self):
        f = subject.Fixture(self.image)
        f.leaf_count = [11]
        root, _, _ = f.source_tree(None, 'set')
        f.write(root + 0xe6, 12, 2)
        with self.assertRaises(subject.Panicked):
            f.m.run(subject.CLONE, {subject.RDI: subject.OUT, subject.RSI: root, subject.RDX: 0})
        self.assertEqual(f.m.last_pc, 0x33e4abf)

    def test_clone_allocation_failure_is_not_silently_accepted(self):
        f = subject.Fixture(self.image, fail_at=1)
        with self.assertRaises(subject.Panicked):
            f.clone(None, [5], 0)
        self.assertEqual(f.m.last_pc, 0x33e4b13)

    def test_empty_collector_produces_empty_set(self):
        f = subject.Fixture(self.image)
        keys, h, n, _, _ = f.collect(None, [0], 0)
        self.assertEqual((keys, h, n), ([], 0, 0))
        self.assertEqual(f.events, [])

    def test_singleton_collector_does_not_sort(self):
        f = subject.Fixture(self.image)
        keys, _, n, _, _ = f.collect(None, [1], 0)
        self.assertEqual((keys, n), (subject.key_sequence(1), 1))
        self.assertFalse(any(name.startswith('sort') for name, *_ in f.events))

    def test_collector_small_sort_boundary(self):
        f = subject.Fixture(self.image)
        keys, _, n, _, _ = f.collect([None, None], [9, 10], 1)
        self.assertEqual((keys, n), (subject.key_sequence(20), 20))
        self.assertIn(('sort_small', 20), f.events)

    def test_collector_large_sort_boundary(self):
        f = subject.Fixture(self.image)
        keys, _, n, _, _ = f.collect([None, None], [10, 10], 1)
        self.assertEqual((keys, n), (subject.key_sequence(21), 21))
        self.assertIn(('sort_large', 21), f.events)

    def test_bulk_builder_coalesces_adjacent_duplicate_keys(self):
        f = subject.Fixture(self.image)
        keys, _, n, _ = f.bulk([1, 1, 2, 2, 2, 3])
        self.assertEqual(keys, [x.to_bytes(20, 'big') for x in (1, 2, 3)])
        self.assertEqual(n, 3)

    def test_bulk_builder_multilevel_parent_links(self):
        f = subject.Fixture(self.image)
        keys, height, n, _ = f.bulk(list(range(2000)))
        self.assertEqual((height, n), (3, 2000))
        self.assertEqual(keys, [x.to_bytes(20, 'big') for x in range(2000)])

    def test_bulk_fixture_rejects_unsorted_keys(self):
        with self.assertRaises(ValueError):
            subject.Fixture(self.image).bulk([2, 1])

    def test_vector_capacity_edges(self):
        last = ((1 << 63) - 1) // 20
        self.assertEqual(subject.checked_capacity(last), last * 20)
        for value in (last + 1, (1 << 64) - 1, -1, 1 << 64):
            with self.assertRaises(ValueError):
                subject.checked_capacity(value)

    def test_invalid_iterator_tag_reaches_failure(self):
        f = subject.Fixture(self.image)
        f.put(subject.ITER, bytes(0x48))
        f.write(subject.ITER + 0x40, 1)
        with self.assertRaises(subject.Panicked):
            f.m.run(subject.NEXT, {subject.RDI: subject.ITER})
        self.assertEqual(f.m.last_pc, 0x330fb5c)

    def test_zero_iterator_count_returns_none(self):
        f = subject.Fixture(self.image)
        f.put(subject.ITER, bytes(0x48))
        self.assertEqual(f.m.run(subject.NEXT, {subject.RDI: subject.ITER}), 0)

    def test_byte_edits_and_allocation_controls_are_detected(self):
        controls, _ = subject.run_controls(self.image)
        self.assertEqual(len(controls), 28)
        self.assertEqual(sum(row[0] == 'mutation' for row in controls), 5)
        self.assertEqual(sum(row[0] == 'allocation' for row in controls), 20)
        self.assertEqual(sum(row[0] == 'capacity' for row in controls), 3)

    def test_all_scenarios_match_independent_expectations(self):
        rows, seen, edges = subject.run_scenarios(self.image)
        self.assertEqual(len(rows), 221)
        self.assertGreater(len(seen), 600)
        self.assertGreater(len(edges), 90)


if __name__ == '__main__':
    unittest.main()
