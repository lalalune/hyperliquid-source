"""Node #115 prune_book_empty_user_states closures: real bytes against the written rule, with corruption controls; no execution."""
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import prune_user_states_115 as subject


class PruneUserStatesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()
        cls.cases = subject.structured_cases()

    def test_digest_is_checked(self):
        with self.assertRaisesRegex(subject.EvidenceError, 'SHA-256 mismatch'):
            subject.load_image(expected='0' * 64)
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), subject.SHA256)

    def test_structured_cases_agree_with_the_rule(self):
        harness = subject.Harness(self.image)
        for case in self.cases:
            self.assertEqual(subject.compare_run(harness, case), '', case.label)

    def test_random_cases_agree_with_the_rule(self):
        harness = subject.Harness(self.image)
        for closure, seed in (('row', 0xA11CE), ('list', 0xB0B)):
            for index, case in enumerate(subject.random_cases(closure, seed)):
                if index == 120:
                    break
                self.assertEqual(subject.compare_run(harness, case), '', case.label)

    def test_rule_table(self):
        rows = subject.rule_table()
        self.assertEqual(len(rows), 16)
        gone = [row for row in rows if row['entry_removed']]
        self.assertEqual(len(gone), 2)
        for row in gone:
            self.assertEqual((row['b_length'], row['u_length'], row['occupied_slot']), (0, 0, 0))

    def test_wrong_rules_are_caught(self):
        harness = subject.Harness(self.image)
        probe = self.cases[:300]
        answers = [harness.run(case) for case in probe]
        wrong = subject.wrong_specs()
        self.assertGreaterEqual(len(wrong), 18)
        for name, spec in wrong:
            self.assertTrue(any(spec(case) != answer for case, answer in zip(probe, answers)), name)

    def test_the_real_rule_is_not_flagged(self):
        harness = subject.Harness(self.image)
        for case in self.cases[:50]:
            self.assertEqual(harness.run(case), subject.spec_run(case))

    def test_flipped_vacant_immediate_changes_a_run(self):
        harness = subject.Harness(self.image)
        begin, body = subject.function_bytes(self.image, subject.ROW_CLOSURE)
        at = begin + body.find(bytes.fromhex('833802')) + 2
        harness.machine.patches = {at: 3}
        harness.machine.cache.clear()
        row_cases = [case for case in self.cases if case.closure == 'row'][:80]
        self.assertTrue(any(subject.compare_run(harness, case) for case in row_cases))

    def test_flipped_filter_displacement_changes_a_run(self):
        harness = subject.Harness(self.image)
        begin, body = subject.function_bytes(self.image, 0x29FA380)
        at = begin + body.find(bytes.fromhex('488b7238480b7250')) + 7
        harness.machine.patches = {at: 0x58}
        harness.machine.cache.clear()
        row_cases = [case for case in self.cases if case.closure == 'row'][:120]
        self.assertTrue(any(subject.compare_run(harness, case) for case in row_cases))

    def test_out_of_range_addresses_are_refused(self):
        for bad in (0x1, subject.ROW_CLOSURE + 4, 0x7FFFFFFF):
            with self.assertRaises(subject.EvidenceError):
                self.image.exact_fde(bad)
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(0x1)

    def test_anchors_and_step_names(self):
        rows = subject.anchor_rows(self.image)
        self.assertEqual(len(rows), len(subject.ANCHORS))
        self.assertTrue(all(row['occurrences'] >= 1 for row in rows))
        names = subject.step_name_rows(self.image)
        self.assertEqual([row['lea'] for row in names], ['0x2be191a', '0x54abd99', '0x54b8710'])

    def test_damaged_anchor_is_refused(self):
        saved = subject.ANCHORS
        try:
            subject.ANCHORS = ((subject.ROW_CLOSURE, 'damaged', '833803'),)
            with self.assertRaisesRegex(subject.EvidenceError, 'missing'):
                subject.anchor_rows(self.image)
        finally:
            subject.ANCHORS = saved

    def test_closures_are_distinct_twins(self):
        rows = subject.copy_table(self.image)
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0]['callees'], rows[1]['callees'])
        self.assertIn('0x231e650', rows[0]['callees'])
        self.assertIn('0x231e420', rows[1]['callees'])


if __name__ == '__main__':
    unittest.main()
