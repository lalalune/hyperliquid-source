"""Target-backed and negative controls for RE-017 result-row sorting."""
import bisect
import itertools
import unittest

from tools import abci_result_sort115 as research


class TargetEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = research.TARGET.read_bytes()
        research.require_digest(cls.data)
        cls.sections = research.sections(cls.data)
        cls.relocs = research.parse_relocations(cls.data, cls.sections, research.RELOCATIONS)
        cls.constants = research.constants(cls.data, cls.sections)
        cls.generated = research.produce(cls.data)

    def test_target_digest_and_wrong_digest(self):
        self.assertEqual(research.require_digest(self.data), research.TARGET_SHA256)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.require_digest(b'not the authenticated node')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.require_digest(b'not the historical node', research.HISTORICAL_SHA256)

    def test_every_selected_window_and_corruptions(self):
        altered = bytearray(self.data)
        for role, va, expected in research.WINDOWS:
            research.check_window(self.data, self.sections, va, expected)
            offset = research.mapped_offset(self.data, self.sections, va, len(bytes.fromhex(expected)))
            for position in (offset, offset + len(bytes.fromhex(expected)) - 1):
                with self.subTest(role=role, byte=position - offset):
                    altered[position] ^= 1
                    try:
                        with self.assertRaisesRegex(ValueError, 'window mismatch'):
                            research.check_window(altered, self.sections, va, expected)
                    finally:
                        altered[position] ^= 1

    def test_all_selected_transfers(self):
        rows = research.check_transfers(self.data, self.sections)
        self.assertEqual(len(rows), len(research.TRANSFERS))
        self.assertEqual(next(r['target'] for r in rows if r['role'] == 'run_driver'), 0x4f73c60)
        self.assertEqual(next(r['target'] for r in rows if r['role'] == 'small_run_callee'), 0x5417a80)

    def test_transfer_opcode_and_displacement_corruption(self):
        altered = bytearray(self.data)
        for role, va, opcode, expected in research.TRANSFERS:
            target, raw = research.decode_transfer(self.data, self.sections, va, opcode)
            self.assertEqual(target, expected)
            off = research.mapped_offset(self.data, self.sections, va, len(raw))
            for pos in (off, off + len(raw) - 1):
                with self.subTest(role=role, byte=pos - off):
                    altered[pos] ^= 1
                    try:
                        with self.assertRaises(ValueError):
                            research.check_transfers(altered, self.sections)
                    finally:
                        altered[pos] ^= 1

    def test_selected_relocations_are_exact(self):
        self.assertEqual(len(self.relocs), len(research.RELOCATIONS))
        by_slot = {r['slot']: r for r in self.relocs}
        self.assertEqual(by_slot[0x64e5978]['addend'], 0x4f40550)
        self.assertEqual(by_slot[0x64eb8c8]['addend'], 0x4eb7970)
        self.assertEqual(by_slot[0x64df508]['symbol'], 'memcpy')

    def test_relocation_negative_controls(self):
        for field, value in [('type', 6), ('symbol_index', 3), ('addend', 0), ('symbol', 'bad')]:
            rows = [dict(r) for r in self.relocs]
            row = next(r for r in rows if r['slot'] == 0x64e5978)
            row[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                research.validate_relocations(rows, research.RELOCATIONS)
        with self.assertRaises(ValueError):
            research.validate_relocations(self.relocs[:-1], research.RELOCATIONS)
        with self.assertRaises(ValueError):
            research.validate_relocations(self.relocs + [dict(self.relocs[0])], research.RELOCATIONS)

    def test_bad_relocation_bytes_fail(self):
        row = next(r for r in self.relocs if r['slot'] == 0x64e5978)
        altered = bytearray(self.data)
        altered[row['file_offset'] + 16] ^= 1
        with self.assertRaises(ValueError):
            research.parse_relocations(altered, self.sections, research.RELOCATIONS)

    def test_location_record_and_corrupt_line(self):
        loc = research.location(self.data, self.sections, self.relocs, 0x64767a8,
                                123, 37, b'l1/src/abci/state.rs')
        self.assertEqual((loc['path_length'], loc['line'], loc['column']), (20, 123, 37))
        altered = bytearray(self.data)
        line = research.mapped_offset(self.data, self.sections, 0x64767b8, 4)
        altered[line] ^= 1
        with self.assertRaises(ValueError):
            research.location(altered, self.sections, self.relocs, 0x64767a8,
                              123, 37, b'l1/src/abci/state.rs')

    def test_bad_address_nobits_and_ambiguous_sections(self):
        sample = b'abcdefgh'
        valid = {'name': 'data', 'type': 1, 'flags': 2, 'address': 0x1000, 'offset': 0, 'size': 8}
        self.assertEqual(research.read_va(sample, [valid], 0x1002, 3), b'cde')
        nobits = dict(valid, name='bss', type=8)
        for va, size, secs in [(0x1000, 1, [nobits]), (0x1007, 2, [valid]),
                               (0x1000, 0, [valid]), (-1, 1, [valid]),
                               (0x1000, 1, [valid, dict(valid)])]:
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                research.read_va(sample, secs, va, size)

    def test_duplicate_or_missing_sections_are_rejected(self):
        section = research.only_section(self.sections, '.text')
        with self.assertRaises(ValueError):
            research.only_section(self.sections + [dict(section)], '.text')
        with self.assertRaises(ValueError):
            research.only_section(self.sections, '.not-present')

    def test_selected_fdes_and_mutated_range(self):
        rows = research.checked_fdes(self.data, self.sections)
        self.assertEqual(len(rows), 8)
        adapter = next(r for r in rows if r['role'] == 'sort_buffer_adapter')
        self.assertEqual((adapter['start'], adapter['end']), (0x4f40550, 0x4f40696))
        altered = bytearray(self.data)
        off = research.mapped_offset(self.data, self.sections, adapter['fde'] + 12, 4)
        altered[off] ^= 1
        with self.assertRaises(ValueError):
            research.checked_fdes(altered, self.sections)

    def test_generated_evidence_matches_packet(self):
        packet = research.ROOT / 'research/work-items/RE-017-abci-result-sort-115'
        self.assertEqual(len(self.generated), 16)
        for name, raw in sorted(self.generated.items()):
            with self.subTest(name=name):
                self.assertEqual((packet / name).read_bytes(), raw)

    def test_generated_truth_tables(self):
        compare = self.generated['synthetic-compare.tsv'].decode().splitlines()
        self.assertEqual(compare[1:], ['0\t1\t1\t0\t0xff\twrapped_search',
                                       '1\t1\t0\t0\t0x0\tequal',
                                       '2\t1\t0\t1\t0x1\tinitial_search'])
        threshold = self.generated['synthetic-threshold.tsv'].decode().splitlines()
        self.assertIn('63\t1\tinsert', threshold)
        self.assertIn('64\t0\treplace', threshold)
        self.assertIn('64\t1\tconvert', threshold)
        merged = self.generated['synthetic-merge-truth.tsv'].decode().splitlines()
        self.assertIn('1\t1\tL\tR', merged)
        fast = self.generated['synthetic-fast-path.tsv'].decode().splitlines()
        self.assertIn('lookup_existing\t0x57f8d5f\t64\t63\treplace', fast)

    def test_mutated_artifact_rejected_before_produce(self):
        altered = bytearray(self.data)
        altered[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.produce(altered)


class SyntheticBranchModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = research.TARGET.read_bytes()
        research.require_digest(data)
        cls.constants = research.constants(data, research.sections(data))

    def test_binary_immediates(self):
        c = self.constants
        self.assertEqual((c['context_sort_threshold'], c['stack_threshold'], c['row_shift']), (21, 65, 6))
        self.assertEqual((c['entry_count_cap'], c['partition_small_threshold']), (125000, 33))

    def test_stack_heap_boundary(self):
        a = research.classify_buffer(64, self.constants)
        b = research.classify_buffer(65, self.constants)
        self.assertEqual((a['storage'], a['scratch_elements'], a['small_mode']), ('stack', 64, True))
        self.assertEqual((b['storage'], b['scratch_elements'], b['bytes_wrapped'], b['small_mode']),
                         ('heap', 65, 4160, False))

    def test_buffer_cap_is_maximum_not_minimum(self):
        cases = {125000: 125000, 125001: 125000, 250000: 125000, 250001: 125001}
        for n, expected in cases.items():
            with self.subTest(n=n):
                self.assertEqual(research.classify_buffer(n, self.constants)['computed'], expected)

    def test_size_overflow_boundary(self):
        c = self.constants
        limit = 2 * (c['maximum_allocation_bytes'] >> c['row_shift'])
        self.assertFalse(research.classify_buffer(limit, c)['size_error'])
        self.assertTrue(research.classify_buffer(limit + 1, c)['size_error'])
        self.assertTrue(research.classify_buffer(research.U64_MAX, c)['size_error'])
        for bad in (-1, 1 << 64):
            with self.subTest(n=bad), self.assertRaises(ValueError):
                research.classify_buffer(bad, c)

    def test_minimum_run_boundaries(self):
        c = self.constants
        self.assertIsNone(research.min_run(1, c))
        for n, expected in [(21, 11), (32, 16), (63, 32), (64, 32),
                            (65, 33), (4096, 64), (4097, 64), (8191, 95)]:
            with self.subTest(n=n):
                self.assertEqual(research.min_run(n, c), expected)

    def test_run_direction_and_equal_stop(self):
        self.assertEqual(research.scan_run([]), (0, 'empty'))
        self.assertEqual(research.scan_run([(1, 0)]), (1, 'single'))
        self.assertEqual(research.scan_run([(1, 0), (1, 1), (2, 2), (0, 3)]), (3, 'nondecreasing'))
        self.assertEqual(research.scan_run([(3, 0), (2, 1), (2, 2)]), (2, 'strict_descending'))

    def test_ring_lookup_against_bisect_for_wrapped_and_linear_rings(self):
        tested = 0
        for capacity in range(9):
            for head in range(capacity or 1):
                for count in range(capacity + 1):
                    keys = [2 * i + 2 for i in range(count)]
                    for query in range(2 * capacity + 4):
                        found, position = research.ring_lookup_model(capacity, head, keys, query)
                        expected = bisect.bisect_left(keys, query)
                        expected_tag = 0 if expected < count and keys[expected] == query else 1
                        self.assertEqual((found, position), (expected_tag, expected),
                                         (capacity, head, count, query))
                        tested += 1
        self.assertEqual(tested, 3964)

    def test_ring_lookup_uses_unsigned_64_bit_keys(self):
        keys = [0, 1 << 63, research.U64_MAX]
        for query in [0, 1, (1 << 63) - 1, 1 << 63, (1 << 63) + 1, research.U64_MAX]:
            index = bisect.bisect_left(keys, query)
            expected_tag = int(index == len(keys) or keys[index] != query)
            self.assertEqual(research.ring_lookup_model(3, 2, keys, query), (expected_tag, index))

    def test_lookup_boundary_equal_in_wrapped_duplicate_fixture(self):
        # This malformed-for-uniqueness example only checks the local boundary
        # comparison; the selected duplicate need not be the first duplicate.
        self.assertEqual(research.ring_lookup_model(6, 4, [0, 2, 2, 2, 4], 2), (0, 2))

    def test_duplicate_key_lookup_preserves_hit_and_missing_position(self):
        tested = 0
        for capacity in range(1, 7):
            for head in range(capacity):
                for count in range(capacity + 1):
                    for sample in itertools.combinations_with_replacement(range(4), count):
                        keys = list(sample)
                        for query in range(5):
                            tag, position = research.ring_lookup_model(capacity, head, keys, query)
                            expected = bisect.bisect_left(keys, query)
                            if expected < len(keys) and keys[expected] == query:
                                self.assertEqual(tag, 0)
                                self.assertEqual(keys[position], query)
                            else:
                                self.assertEqual((tag, position), (1, expected))
                            tested += 1
        self.assertEqual(tested, 11550)

    def test_full_ring_all_heads_hit_miss_and_conversion(self):
        c = self.constants
        keys = [2 * i for i in range(64)]
        tested = 0
        for head in range(64):
            for query in range(129):
                position = bisect.bisect_left(keys, query)
                tag = int(position == len(keys) or keys[position] != query)
                actual = research.ring_lookup_model(64, head, keys, query)
                self.assertEqual(actual, (tag, position), (head, query))
                self.assertEqual(research.ring_decision(tag, 64, c), 'convert' if tag else 'replace')
                tested += 1
        self.assertEqual(tested, 8256)

    def test_lookup_rejects_invalid_ring_assumptions(self):
        cases = [(0, 1, [], 0), (2, 2, [], 0), (2, 0, [1, 2, 3], 2),
                 (2, 0, [2, 1], 2), (2, 0, [1], -1), (2, 0, [-1], 0)]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                research.ring_lookup_model(*case)

    def test_lookup_and_conversion_boundaries(self):
        c = self.constants
        self.assertEqual(research.ring_decision(0, 64, c), 'replace')
        self.assertEqual(research.ring_decision(1, 63, c), 'insert')
        self.assertEqual(research.ring_decision(1, 64, c), 'convert')
        with self.assertRaises(ValueError):
            research.ring_decision(2, 64, c)

    def test_sorted_64_case_and_mutant_hit_tag(self):
        keys = list(range(64))
        hit, hit_index = research.ring_lookup_model(64, 63, keys, 63)
        miss, miss_index = research.ring_lookup_model(64, 63, keys, 64)
        self.assertEqual((hit, hit_index, miss, miss_index), (0, 63, 1, 64))
        self.assertEqual(research.ring_decision(hit, 64, self.constants), 'replace')
        self.assertEqual(research.ring_decision(miss, 64, self.constants), 'convert')
        self.assertNotEqual(research.ring_decision(1 - hit, 64, self.constants), 'replace')
        self.assertEqual(research.scan_run([(key, key) for key in keys]), (64, 'nondecreasing'))
        self.assertEqual(research.min_run(64, self.constants), 32)

    def test_two_run_scheduler_powers(self):
        self.assertEqual(research.run_power(64, 0, 0, 32, self.constants), 2)
        self.assertEqual(research.run_power(64, 32, 32, 32, self.constants), 1)
        with self.assertRaises(ValueError):
            research.run_power(1, 0, 0, 1, self.constants)
        with self.assertRaises(ValueError):
            research.run_power(64, 1, 2, 32, self.constants)
        self.assertEqual(len(research.example_path(self.constants)), 8)

    def test_forward_merge_equal_prefers_left(self):
        left = [(0, 'L0'), (2, 'L2'), (2, 'L3')]
        right = [(0, 'R0'), (1, 'R1'), (2, 'R2')]
        expected = [(0, 'L0'), (0, 'R0'), (1, 'R1'), (2, 'L2'), (2, 'L3'), (2, 'R2')]
        self.assertEqual(research.merge_forward(left, right), expected)
        self.assertEqual(research.merge_backward(left, right), expected)
        self.assertEqual(research.reduce_last(expected), [(0, 'R0'), (1, 'R1'), (2, 'R2')])

    def test_merge_models_against_stable_sort_oracle(self):
        samples = [list(x) for n in range(5)
                   for x in itertools.combinations_with_replacement(range(3), n)]
        tested = 0
        for lkeys in samples:
            for rkeys in samples:
                left = [(key, ('left', i)) for i, key in enumerate(lkeys)]
                right = [(key, ('right', i)) for i, key in enumerate(rkeys)]
                expected = sorted(left + right, key=lambda row: row[0])
                self.assertEqual(research.merge_forward(left, right), expected)
                self.assertEqual(research.merge_backward(left, right), expected)
                tested += 1
        self.assertEqual(tested, 1225)

    def test_synthetic_two_run_result(self):
        input_rows, merged, survivors = research.two_run_example(self.constants)
        self.assertEqual((len(input_rows), len(merged), len(survivors)), (64, 64, 33))
        self.assertEqual(merged[:6], [(0, 0), (0, 32), (1, 1), (1, 33), (2, 2), (2, 34)])
        self.assertEqual(survivors, [(i, i + 32) for i in range(32)] + [(63, 31)])

    def test_mutant_tie_direction_changes_survivor(self):
        rows, actual, survivors = research.two_run_example(self.constants)
        mutant = research.merge_forward(rows[:32], rows[32:], left_wins_tie=False)
        self.assertNotEqual(mutant, actual)
        self.assertEqual(research.reduce_last(mutant)[0], (0, 0))
        self.assertEqual(survivors[0], (0, 32))

    def test_merge_rejects_corrupt_or_unsorted_models(self):
        for bad in [[(1, 'x'), (0, 'y')], [(-1, 'x')], [(1 << 64, 'x')]]:
            with self.subTest(rows=bad), self.assertRaises(ValueError):
                research.merge_forward(bad, [])
        self.assertEqual(research.merge_forward([], []), [])
        self.assertEqual(research.merge_backward([(0, 0)], []), [(0, 0)])

    def test_equal_and_unsigned_extreme_comparisons(self):
        maximum = research.U64_MAX
        left = [(0, 'a'), (maximum, 'b')]
        right = [(0, 'c'), (maximum, 'd')]
        self.assertEqual(research.merge_forward(left, right),
                         [(0, 'a'), (0, 'c'), (maximum, 'b'), (maximum, 'd')])
        self.assertEqual(research.merge_backward(left, right), research.merge_forward(left, right))


if __name__ == '__main__':
    unittest.main()
