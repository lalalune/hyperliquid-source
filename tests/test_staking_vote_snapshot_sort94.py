"""Target-bound and adversarial controls for validator snapshot sorting."""
import copy
import hashlib
import itertools
import struct
import unittest

from tools import staking_vote_snapshot_sort94 as subject


class SnapshotSortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()
        subject.checked_pins(cls.image)

    def fixture(self, n=33):
        return [subject.row((i * 17) % 11, i) for i in range(n)]

    def test_digest(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), subject.SHA256)

    def test_wrong_digest_refused(self):
        with self.assertRaises(subject.EvidenceError):
            subject.load_image(subject.BINARY, '0' * 64)

    def test_unsupported_elf_refused(self):
        with self.assertRaises(ValueError):
            subject.Image(b'not an elf')

    def test_unmapped_address_refused(self):
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(1 << 63)

    def test_nobits_is_not_file_data(self):
        bss = next(sec for sec in self.image.sections if sec['name'] == '.bss')
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(bss['address'])

    def test_cross_section_address_refused(self):
        sec = self.image.named['.text']
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(sec['address'] + sec['size'] - 1, 2, executable=True)

    def test_interior_is_not_fde_start(self):
        with self.assertRaises(subject.EvidenceError):
            self.image.exact_fde(0x3bc2241)

    def test_fde_windows_decode_and_branches_are_aligned(self):
        for start in subject.FUNCTIONS:
            _, end = self.image.exact_fde(start)
            rows = subject.decode_range(self.image, start, end)
            starts = {r.va for r in rows}
            self.assertEqual(rows[-1].next, end)
            for row in rows:
                if row.op in ('jmp', 'jcc') and row.target is not None and start <= row.target < end:
                    self.assertIn(row.target, starts)

    def test_pins_match(self):
        pins, rels = subject.checked_pins(self.image)
        self.assertEqual(len(pins), 16)
        self.assertEqual(rels[0x5775ca0], (8, 0x3bc2240, 0))
        self.assertEqual(rels[0x5775f00], (8, 0x3885850, 0))

    def test_corrupted_instruction_is_refused(self):
        bad = copy.copy(self.image)
        bad.blob = bytearray(self.image.blob)
        bad.blob[self.image.offset(0x336d749) + 3] ^= 1
        with self.assertRaises(subject.EvidenceError):
            subject.checked_pins(bad)

    def test_corrupted_relocation_is_refused(self):
        bad = copy.copy(self.image)
        bad.blob = bytearray(self.image.blob)
        sec = self.image.named['.rela.dyn']
        for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
            if struct.unpack_from('<Q', bad.blob, pos)[0] == 0x5775f00:
                struct.pack_into('<q', bad.blob, pos + 16, 0x3885851)
                break
        else:
            self.fail('target relocation not found')
        with self.assertRaises(subject.EvidenceError):
            subject.checked_pins(bad)

    def test_compare_and_copy_imports(self):
        _, rels = subject.checked_pins(self.image)
        self.assertEqual(subject.dynamic_symbol(self.image, rels[0x576e488][2]), 'memcmp')
        self.assertEqual(subject.dynamic_symbol(self.image, rels[0x576dfe0][2]), 'memcpy')
        with self.assertRaises(subject.EvidenceError):
            subject.dynamic_symbol(self.image, 1 << 30)

    def test_minimum_long_input(self):
        rows = self.fixture(21)
        runner, result = subject.run_case(self.image, rows)
        self.assertEqual(result, sorted(rows, key=lambda r: r[:20]))
        self.assertEqual(runner.allocations, [])

    def test_outside_long_input_rejected(self):
        with self.assertRaises(ValueError):
            subject.Runner(self.image).run(self.fixture(20))
        with self.assertRaises(ValueError):
            subject.Runner(self.image).run([b'x'] * 21)

    def test_all_key_positions_affect_order(self):
        for byte in range(20):
            rows = [subject.row(((i * 13) % 23) << (8 * (19 - byte)), i) for i in range(33)]
            with self.subTest(byte=byte):
                _, result = subject.run_case(self.image, rows, magnitude=255)
                self.assertEqual(result, sorted(rows, key=lambda r: r[:20]))

    def test_equal_keys_keep_input_payload_order(self):
        rows = [subject.row(7, i) for i in range(129)]
        runner, result = subject.run_case(self.image, rows)
        self.assertEqual(result, rows)
        self.assertEqual(runner.allocations, [4128])

    def test_min_max_keys_and_repeated_keys(self):
        keys = [0, (1 << 160) - 1, 1, 0, (1 << 159)] * 7
        rows = [subject.row(k, i) for i, k in enumerate(keys)]
        _, result = subject.run_case(self.image, rows)
        self.assertEqual(result, sorted(rows, key=lambda r: r[:20]))

    def test_compare_magnitudes_do_not_change_result(self):
        rows = self.fixture(65)
        results = [subject.run_case(self.image, rows, magnitude=n)[1] for n in (1, 37, 255)]
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[1], results[2])
        with self.assertRaises(ValueError):
            subject.Runner(self.image, magnitude=0)

    def test_128_uses_stack_129_allocates(self):
        small, _ = subject.run_case(self.image, self.fixture(128))
        large, _ = subject.run_case(self.image, self.fixture(129))
        self.assertEqual(small.allocations, [])
        self.assertEqual(large.allocations, [4128])
        self.assertEqual(large.frees, [4128])

    def test_already_sorted_skips_partition_on_sample(self):
        rows = [subject.row(i, i) for i in range(129)]
        runner, result = subject.run_case(self.image, rows)
        self.assertEqual(result, rows)
        for entry in (0x3885850, 0x338b7f0, 0x38612f0):
            self.assertFalse(any(entry <= pc < self.image.fde_ends[entry] for pc in runner.machine.seen))
        self.assertEqual(runner.allocations, [4128])

    def test_driver_threshold_at_4097(self):
        for count, taken in ((4096, False), (4097, True)):
            rows = [subject.row(i, i) for i in range(count)]
            runner, result = subject.run_case(self.image, rows)
            self.assertEqual(result, rows)
            self.assertEqual(runner.machine.branch_outcomes[0x386393b], {taken})
            self.assertEqual(runner.allocations, [count * 32])

    def test_reversed_sample_is_reordered(self):
        rows = [subject.row(i, i) for i in reversed(range(65))]
        _, result = subject.run_case(self.image, rows)
        self.assertEqual(result, list(reversed(rows)))

    def test_large_mixed_reaches_pivot(self):
        runner, result = subject.run_case(self.image, self.fixture(129))
        self.assertIn(0x38612f0, runner.machine.seen)
        self.assertEqual(len(result), 129)

    def test_pivot_selects_a_median_with_equal_keys(self):
        for values in itertools.product(range(3), repeat=3):
            with self.subTest(values=values):
                index, key, _ = subject.pivot_probe(self.image, values)
                self.assertIn(index, (0, 1, 2))
                self.assertEqual(key, sorted(values)[1])
        index, _, _ = subject.pivot_probe(self.image, (0, 0, 0))
        self.assertEqual(index, 1)

    def test_pivot_recurses_over_three_groups(self):
        values = [(i * 7) % 17 for i in range(24)]
        index, key, seen = subject.pivot_probe(self.image, values, recursive=True)
        medians = [sorted(values[base + j] for j in (0, 4, 7))[1] for base in (0, 8, 16)]
        self.assertEqual(key, sorted(medians)[1])
        self.assertIn(index, [base + j for base in (0, 8, 16) for j in (0, 4, 7)])
        self.assertIn(0x386132a, seen)

    def test_partition_scratch_threshold_and_trap(self):
        for count in (2, 4, 32):
            outcome, visited = subject.small_partition_probe(self.image, count, count + 15)
            self.assertEqual(outcome, 'trap')
            self.assertIn(0x338be72, visited)
            outcome, visited = subject.small_partition_probe(self.image, count, count + 16)
            self.assertEqual(outcome, 'sorted')
            self.assertNotIn(0x338be72, visited)

    def test_singleton_skips_scratch_capacity_check(self):
        outcome, visited = subject.small_partition_probe(self.image, 1, 0)
        self.assertEqual(outcome, 'sorted')
        self.assertNotIn(0x338be72, visited)

    def test_allocation_failure_is_observed(self):
        alloc, args, _ = subject.capacity_probe(self.image, 129)
        self.assertEqual(alloc, [4128])
        self.assertEqual(args, (8, 4128))

    def test_scratch_size_clamps_then_grows(self):
        cases = ((250000, 8000000), (250001, 8000000),
                 (500000, 8000000), (500001, 8000032))
        for count, size in cases:
            with self.subTest(count=count):
                allocations, args, _ = subject.capacity_probe(self.image, count)
                self.assertEqual(allocations, [size])
                self.assertEqual(args, (8, size))

    def test_invalid_capacity_counts_refused(self):
        for count in (-1, 1 << 64):
            with self.subTest(count=count), self.assertRaises(ValueError):
                subject.capacity_probe(self.image, count)

    def test_huge_count_fails_before_allocation(self):
        allocations, args, _ = subject.capacity_probe(self.image, 1 << 60)
        self.assertEqual(allocations, [])
        self.assertEqual(args[0], 0)

    def test_branch_corruption_changes_result(self):
        rows = self.fixture(33)
        normal = sorted(rows, key=lambda r: r[:20])
        address = 0x338bbac
        replacement = self.image.blob[self.image.offset(address)] ^ 1
        altered = subject.Runner(self.image, patches={address: replacement})
        self.assertNotEqual(altered.run(rows), normal)

    def test_row_input_validation(self):
        for key, serial in ((-1, 0), (1 << 160, 0), (0, -1), (0, 1 << 64)):
            with self.subTest(key=key, serial=serial), self.assertRaises(ValueError):
                subject.row(key, serial)


if __name__ == '__main__':
    unittest.main()
