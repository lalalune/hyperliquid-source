"""Controls for the digest-bound epoch snapshot path; no native execution."""
import csv
import tempfile
import unittest
from pathlib import Path

from tools import staking_epoch_snapshot94 as study


class CorruptPin:
    def __init__(self, image, address):
        self.image = image
        self.address = address

    def read(self, address, size, executable=False):
        value = bytearray(self.image.read(address, size, executable))
        if address <= self.address < address + size:
            value[self.address - address] ^= 1
        return bytes(value)


class EpochSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = study.Image(study.BINARY.read_bytes())

    def test_wrong_digest_fails_before_parsing(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            study.Image(b'not the authenticated artifact')

    def test_file_backed_address_bounds(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)
        with self.assertRaises(ValueError):
            self.image.read(0, 1)
        text = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            self.image.read(text['address'] + text['size'] - 1, 2, executable=True)
        with self.assertRaises(ValueError):
            self.image.read(text['address'], 0, executable=True)

    def test_fde_ranges_and_two_decoders_agree(self):
        for start, _ in study.FUNCTIONS:
            with self.subTest(start=hex(start)):
                end = self.image.fdes[start]['end']
                length_only = study.decode_function(self.image, start)
                interpreter = study.decode_range(self.image, start, end)
                self.assertEqual([(r['address'], r['size']) for r in length_only],
                                 [(r.va, r.size) for r in interpreter])
                self.assertEqual(length_only[-1]['address'] + length_only[-1]['size'], end)

    def test_unknown_and_truncated_instruction_rejected(self):
        with self.assertRaises(ValueError):
            study.decode_one(b'\x0f\xff', 0, 0x100)
        with self.assertRaises(ValueError):
            study.decode_one(b'\xe8\x01', 0, 0x100)
        row = study.decode_one(b'\xe8\xfb\xff\xff\xff', 0, 0x100)
        self.assertEqual(row['target'], 0x100)

    def test_pin_mutation_rejected(self):
        study.validate_pins(self.image)
        with self.assertRaisesRegex(ValueError, 'pin mismatch'):
            study.validate_pins(CorruptPin(self.image, 0x33e71da))

    def test_outer_and_nested_clone(self):
        rows = study.clone_cases(self.image)
        self.assertEqual(len(rows), 7)
        self.assertEqual(rows[0]['validator_rows'], 0)
        self.assertEqual(rows[3]['nested_rows'], 11)
        self.assertEqual(rows[-1]['height'], 1)
        self.assertEqual(rows[-1]['source_nodes'], rows[-1]['copied_nodes'])

    def test_insert_replacements_and_all_split_positions(self):
        rows = study.insert_cases(self.image)
        self.assertEqual(len(rows), 144)
        split = [r for r in rows if r['height'] == 1]
        self.assertEqual(len(split), 12)
        self.assertEqual([r['pivot_key'] for r in split], [10] * 5 + [12] * 2 + [14] * 5)
        self.assertEqual(sum(r['replaced'] for r in rows), 66)

    def test_unsigned_key_boundary(self):
        rows = study.unsigned_key_cases(self.image)
        self.assertEqual(len(rows), 7)
        self.assertEqual([r['replaced'] for r in rows], [1, 0, 0, 1, 0, 0, 1])

    def test_split_cascades_through_full_parent(self):
        rows = study.deep_cases(self.image)
        self.assertEqual(len(rows), 144)
        self.assertTrue(all(r['height'] == 2 and r['new_count'] == 144 for r in rows))
        self.assertEqual({r['root_pivot'] for r in rows}, {5000, 6000, 7000})

    def test_leaf_remove_merge_and_borrow(self):
        self.assertEqual(len(study.remove_cases(self.image)), 850)
        for edge in (0, 1):
            with self.subTest(edge=edge):
                merge = study.remove_case(self.image, 5, 0, 5, edge)
                borrow = study.remove_case(self.image, 5, 0, 7, edge)
                self.assertEqual(merge['root_collapsed'], 1)
                self.assertEqual(borrow['root_collapsed'], 0)
                self.assertTrue(merge['choice'].startswith('merge'))
                self.assertTrue(borrow['choice'].startswith('borrow'))

    def test_internal_cursor_removes_original_key(self):
        rows = study.internal_remove_cases(self.image)
        self.assertEqual(len(rows), 49)
        self.assertEqual(study.internal_remove_case(self.image, 5, 5)['collapsed'], 1)
        self.assertEqual(study.internal_remove_case(self.image, 5, 7)['collapsed'], 0)

    def test_removal_repairs_two_levels(self):
        rows = study.cascade_remove_cases(self.image)
        self.assertEqual(len(rows), 40)
        for r in rows:
            self.assertEqual(r['collapsed'], int(r['sibling_inner_count'] < 7))

    def test_iterator_walks_and_releases_nodes(self):
        rows = study.iterator_cases(self.image)
        self.assertEqual([r['yielded'] for r in rows], [0, 1, 11, 3])
        self.assertEqual([r['tree_nodes_freed'] for r in rows], [1, 1, 1, 3])

    def test_composed_lifecycle_and_active_guard(self):
        rows = study.lifecycle_cases(self.image)
        self.assertEqual([r['removed_epochs'] for r in rows], ['', '1', '1,2', ''])
        self.assertEqual([r['final_epochs'] for r in rows], [1002, 1001, 1000, 1001])
        self.assertEqual([r['disposed_validator_rows'] for r in rows], [0, 1, 1, 1])

    def test_injected_allocation_and_invalid_root_failures(self):
        rows = study.fault_cases(self.image)
        self.assertEqual(len(rows), 6)
        self.assertEqual([r['allocations_before_failure'] for r in rows], [0, 1, 1, 0, 0, 1])

    def test_selected_byte_mutations_detected(self):
        rows = study.mutation_cases(self.image)
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(r['detected'] == 1 for r in rows))

    def test_invalid_fixture_rejected(self):
        with self.assertRaises(ValueError):
            study.insert_case(self.image, 12, 0)
        with self.assertRaises(ValueError):
            study.remove_case(self.image, 5, 5)
        with self.assertRaises(ValueError):
            study.cascade_remove_case(self.image, 2, 5, 0)

    def test_generated_tables_and_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            summary = study.generate(self.image, out)
            with (out / 'functions.tsv').open(newline='', encoding='utf-8') as inp:
                functions = list(csv.DictReader(inp, delimiter='\t'))
            self.assertEqual(len(functions), 9)
            self.assertEqual(summary['remove_cases'], 850)
            self.assertEqual(summary['cascade_remove_cases'], 40)
            self.assertEqual(summary['lifecycle_cases'], 4)
            self.assertEqual(summary['selected_mutations_detected'], 5)


if __name__ == '__main__':
    unittest.main()
