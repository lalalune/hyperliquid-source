import csv
import io
import json
import unittest

from tools import staking_validator_state_insert94 as subject


class ValidatorStateInsertTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()
        subject.check_image(cls.image)

    def test_target_digest_is_required(self):
        with self.assertRaisesRegex(subject.EvidenceError, 'SHA-256 mismatch'):
            subject.load_image(expected='0' * 64)

    def test_unmapped_and_overlong_ranges_rejected(self):
        with self.assertRaises(subject.EvidenceError):
            subject.read_bytes(self.image, 0, 1)
        sec = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(subject.EvidenceError):
            subject.read_bytes(self.image, sec['address'] + sec['size'] - 1, 2)
        with self.assertRaises(subject.EvidenceError):
            subject.read_bytes(self.image, subject.INSERT, -1)

    def test_nobits_not_treated_as_file_bytes(self):
        sec = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaises(subject.EvidenceError):
            subject.read_bytes(self.image, sec['address'], 1)

    def test_fde_entry_must_be_exact(self):
        self.assertEqual(self.image.exact_fde(subject.INSERT), (subject.INSERT, 0x2f99816))
        with self.assertRaisesRegex(subject.EvidenceError, 'not an FDE start'):
            self.image.exact_fde(subject.INSERT + 1)

    def test_mutated_body_is_rejected(self):
        original = self.image.blob
        altered = bytearray(original)
        altered[self.image.offset(subject.INSERT + 3)] ^= 1
        try:
            self.image.blob = altered
            with self.assertRaisesRegex(subject.EvidenceError, 'unexpected body bytes'):
                subject.check_image(self.image)
        finally:
            self.image.blob = original

    def test_mutated_context_pin_is_rejected(self):
        original = self.image.blob
        altered = bytearray(original)
        altered[self.image.offset(0x3995825)] ^= 1
        try:
            self.image.blob = altered
            with self.assertRaisesRegex(subject.EvidenceError, 'instruction signature'):
                subject.check_image(self.image)
        finally:
            self.image.blob = original

    def test_relocations_prove_memory_routines(self):
        records = {slot: (typ, symbol) for slot, typ, _, symbol, _ in subject.relocation_rows(self.image)}
        self.assertEqual(records[subject.SLOT_MEMCMP], (6, 'memcmp'))
        self.assertEqual(records[subject.SLOT_MEMMOVE], (6, 'memmove'))
        self.assertEqual(records[subject.SLOT_MEMCPY], (6, 'memcpy'))

    def test_nonfull_leaf_and_cursor_at_boundaries(self):
        f = subject.Fixture(self.image)
        for count in (0, 1, 10):
            for index in range(count + 1):
                with self.subTest(count=count, index=index):
                    row, _, _, _ = subject.run_insert_case(f, None, count, index)
                    self.assertEqual(row['new_count'], count + 1)
                    self.assertEqual(row['new_height'], 0)
                    self.assertEqual(row['cursor_index'], index)
                    self.assertEqual(row['new_alloc_sizes'], [])

    def test_all_full_leaf_insert_positions_and_medians(self):
        f = subject.Fixture(self.image)
        for index in range(12):
            with self.subTest(index=index):
                row, _, mp, _ = subject.run_insert_case(f, None, 11, index)
                root = f.read(mp)
                left, right = f.read(root + 0x220), f.read(root + 0x228)
                actual = (f.read(left + 0x21a, 2), int.from_bytes(f.data(root + 8, 20), 'big'),
                          f.read(right + 0x21a, 2), row['cursor_path'], row['cursor_index'])
                if index < 5:
                    expected = (5, 10, 6, [0], index)
                elif index == 5:
                    expected = (6, 12, 5, [0], 5)
                elif index == 6:
                    expected = (5, 12, 6, [1], 0)
                else:
                    expected = (6, 14, 5, [1], index - 7)
                self.assertEqual(actual, expected)
                self.assertEqual(row['new_alloc_sizes'], [0x220, 0x280])

    def test_parent_split_and_root_growth(self):
        f = subject.Fixture(self.image)
        for child, index in ((0, 0), (5, 5), (6, 6), (7, 7), (11, 11)):
            with self.subTest(child=child, index=index):
                row, _, _, _ = subject.run_insert_case(f, 11, child, index)
                self.assertEqual(row['new_height'], 2)
                self.assertEqual(row['new_alloc_sizes'], [0x220, 0x280, 0x280])
                self.assertEqual(row['new_count'], row['old_count'] + 1)

    def test_two_full_ancestor_splits(self):
        f = subject.Fixture(self.image)
        row = subject.run_deep_case(f, 6, 6, 6)
        self.assertEqual((row['old_count'], row['new_count'], row['new_height']), (1727, 1728, 3))
        self.assertEqual(row['alloc_sizes'], [0x220, 0x280, 0x280, 0x280])

    def test_lookup_compares_each_key_byte_and_missing_keys(self):
        results = subject.lookup_controls(subject.Fixture(self.image))
        self.assertEqual(len(results), 24)
        self.assertTrue(all(x['found'] for x in results[1:21]))
        self.assertFalse(any(x['found'] for x in [results[0], *results[21:]]))

    def test_allocation_failure_edges(self):
        controls = subject.allocation_failures(self.image)
        self.assertEqual([r['calls'] for r in controls], [1, 2, 3])
        self.assertEqual([r['last_instruction'] for r in controls],
                         ['0x2f99775', '0x2f99731', '0x2f99792'])

    def test_branch_corruption_is_detected_by_model(self):
        for addr, shape in ((0x2f98876, (None, 11, 5)),
                            (0x2f989bf, (None, 11, 5)),
                            (0x33ade71, (None, 11, 5))):
            with self.subTest(address=hex(addr)):
                byte = subject.read_bytes(self.image, addr, 1)[0]
                f = subject.Fixture(self.image, {addr: byte ^ 1})
                with self.assertRaises((subject.EvidenceError, subject.Halt, subject.Panicked)):
                    subject.run_insert_case(f, *shape)

    def test_refuse_bad_fixture_indices(self):
        f = subject.Fixture(self.image)
        for shape in ((None, 10, 11), (None, 12, 0), (1, 2, 0), (11, 0, 12)):
            with self.subTest(shape=shape), self.assertRaises(subject.EvidenceError):
                subject.run_insert_case(f, *shape)

    def test_generated_summary_and_split_table(self):
        data = subject.generate(self.image)
        summary = json.loads(data['summary.json'])
        self.assertEqual((summary['functions'], summary['insertion_cases'], summary['deep_cases']), (2, 404, 576))
        self.assertEqual((summary['lookup_cases'], summary['allocation_failure_cases']), (24, 3))
        self.assertEqual((summary['mutations_killed'], summary['mutations_survived'], summary['mutations_unreached']), (46, 0, 0))
        mutants = json.loads(data['branch-mutations.json'])
        self.assertEqual(len(mutants), summary['conditional_branches'])
        self.assertTrue(all(row['witness'] is not None for row in mutants))
        rows = list(csv.DictReader(io.StringIO(data['leaf-splits.tsv'].decode()), delimiter='\t'))
        self.assertEqual([int(r['insert_index']) for r in rows], list(range(12)))
        self.assertEqual([int(r['left_count']) for r in rows], [5]*5 + [6,5] + [6]*5)


if __name__ == '__main__':
    unittest.main()
