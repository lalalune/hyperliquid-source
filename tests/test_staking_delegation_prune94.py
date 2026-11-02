"""Node 94 delegation deletion: byte, tree, cursor and corruption controls."""
import csv
import tempfile
import unittest
from pathlib import Path

from tools import staking_delegation_prune94 as p


class DelegationPruneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = p.load_image()

    def test_target_digest_rejected(self):
        with self.assertRaisesRegex(p.EvidenceError, 'SHA-256 mismatch'):
            p.load_image(expected='0' * 64)

    def test_non_file_backed_and_range_rejected(self):
        sec = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaises(p.EvidenceError):
            p.file_bytes(self.image, sec['address'], 1)
        with self.assertRaises(p.EvidenceError):
            p.file_bytes(self.image, 0xffffffffffffffff, 1)
        text = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(p.EvidenceError):
            p.file_bytes(self.image, text['address'] + text['size'] - 1, 2)

    def test_all_eight_fde_ranges_decode(self):
        for name, start in p.FUNCTIONS.items():
            with self.subTest(name=name):
                begin, end = self.image.exact_fde(start)
                rows = p.decode_range(self.image, begin, end)
                self.assertEqual(rows[0].va, start)
                self.assertEqual(rows[-1].next, end)
                targets = {r.va for r in rows}
                self.assertTrue(all(r.target in targets for r in rows if r.op == 'jcc'))

    def test_every_anchor_rejects_corruption(self):
        self.assertEqual(len(p.verify_pins(self.image)), 35)
        for name, va, expected in p.PINS:
            with self.subTest(name=name):
                changed = bytes.fromhex(expected)[0] ^ 1
                with self.assertRaises(p.EvidenceError):
                    p.verify_pins(self.image, {va: changed})

    def test_non_start_fde_rejected(self):
        with self.assertRaises(p.EvidenceError):
            self.image.exact_fde(p.FUNCTIONS['group_cursor'] + 1)

    def test_all_single_leaf_positions(self):
        cases = [s for s in p.case_specs() if s[0] == 'single']
        self.assertEqual(len(cases), 66)
        for layout in p.LAYOUTS:
            for spec in cases:
                with self.subTest(layout=layout, spec=spec):
                    result = p.run_case(self.image, layout, spec)
                    self.assertEqual(result['root_flag'], 0)
                    self.assertEqual(result['frees'], 0)

    def test_sibling_repairs_and_internal_predecessor(self):
        cases = [s for s in p.case_specs() if s[0] == 'pair']
        self.assertEqual(len(cases), 833)
        for layout in p.LAYOUTS:
            for spec in cases:
                with self.subTest(layout=layout, spec=spec):
                    p.run_case(self.image, layout, spec)

    def test_multilevel_merge_and_borrow(self):
        cases = [s for s in p.case_specs() if s[0] in ('deep', 'deep3', 'deep_borrow')]
        self.assertEqual(len(cases), 11)
        for layout in p.LAYOUTS:
            for spec in cases:
                with self.subTest(layout=layout, spec=spec):
                    result = p.run_case(self.image, layout, spec)
                    self.assertEqual(result['root_flag'], int(spec[0] != 'deep_borrow'))
                    if spec[0] == 'deep_borrow':
                        direction = 'right' if spec[3] == 'leftmost' else 'left'
                        self.assertIn(layout + '_borrow_' + direction, result['reached'])
                        site = {('user', 'left'): 0x2fc3dd8, ('user', 'right'): 0x2fc3df7,
                                ('group', 'left'): 0x2fce746, ('group', 'right'): 0x2fce76f}[(layout, direction)]
                        self.assertIn(site, result['seen'])

    def test_two_level_occupancy_matrix(self):
        cases = [s for s in p.case_specs() if s[0] == 'matrix2']
        self.assertEqual(len(cases), 196)
        for layout in p.LAYOUTS:
            for spec in cases:
                with self.subTest(layout=layout, spec=spec):
                    p.run_case(self.image, layout, spec)

    def test_predecessor_returns_original_row_and_successor(self):
        for layout in p.LAYOUTS:
            with self.subTest(layout=layout):
                result = p.run_case(self.image, layout, ('pair', 5, 5, 'root', 0))
                self.assertEqual(result['removed'], 80)
                self.assertEqual(result['next'], 110)
                self.assertEqual(result['root_flag'], 1)

    def test_all_borrow_guards_panic_before_mutation(self):
        self.assertEqual(len(p.GUARD_BRANCHES), 8)
        for layout, direction, failure in p.GUARD_BRANCHES:
            with self.subTest(layout=layout, direction=direction, failure=failure):
                site, target = p.guard_checked(self.image, layout, direction, failure)
                self.assertNotEqual(site, target)

    def test_threshold_mutations_are_detected(self):
        self.assertEqual(len(p.MUTANTS), 20)
        for mutant in p.MUTANTS:
            with self.subTest(mutant=mutant[0]):
                self.assertNotEqual(p.mutation_case(self.image, mutant), 'survived')

    def test_valid_bulk_transfers_preserve_rows_and_links(self):
        cases = list(p.transfer_specs())
        self.assertEqual(len(cases), 720)
        for spec in cases:
            with self.subTest(spec=spec):
                p.transfer_case(self.image, spec)

    def test_root_flag_is_only_written_on_collapse(self):
        specs = ((('single', 1, 0, 'leaf', 0), False),
                 (('pair', 6, 5, 'left', 2), False),
                 (('pair', 5, 5, 'left', 2), True))
        for layout in p.LAYOUTS:
            for spec, collapse in specs:
                for flag in (0, 1, 2, 255):
                    with self.subTest(layout=layout, spec=spec, flag=flag):
                        self.assertEqual(p.flag_case(self.image, layout, spec, flag), 1 if collapse else flag)

    def test_bad_cursor_index_rejected(self):
        fixture = p.Fixture(self.image, 'group')
        node = fixture.node([10, 20])
        with self.assertRaisesRegex(p.Halt, 'past node end'):
            p.successor(fixture, node, 0, 3)

    def test_generated_files_match_repository_packet(self):
        expected = p.ROOT / 'research/work-items/staking-delegation-prune-94'
        with tempfile.TemporaryDirectory() as dirname:
            out = Path(dirname)
            summary = p.generate(self.image, out)
            self.assertEqual(summary['cases'], 2212)
            self.assertEqual(summary['corruption_guards'], 8)
            self.assertEqual(summary['flag_controls'], 24)
            self.assertEqual(summary['transfer_cases'], 720)
            self.assertEqual(summary['mutations_killed'], 20)
            for file in out.iterdir():
                with self.subTest(name=file.name):
                    self.assertEqual(file.read_bytes(), (expected / file.name).read_bytes())


if __name__ == '__main__':
    unittest.main()
