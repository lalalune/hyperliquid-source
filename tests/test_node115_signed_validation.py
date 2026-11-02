import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_signed_validation as subject


class SignedValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = subject.produce()
        cls.body = bytes.fromhex(cls.record['body_hex'])

    def test_exact_target_scope_and_evidence(self):
        self.assertEqual(self.record, json.loads((subject.PACKET / 'records.json').read_text()))
        self.assertEqual(len(self.body), 1323)
        self.assertEqual(self.record['native_instructions'], 257)
        self.assertEqual(self.record['source_locations'][0]['line'], 194)
        self.assertFalse(self.record['gates_changed'])

    def test_wrong_target(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.produce(b'not node115')

    def mutate(self, pc, original, altered):
        original, altered = bytes.fromhex(original), bytes.fromhex(altered)
        offset = pc - subject.START
        self.assertEqual(self.body[offset:offset + len(original)], original)
        body = self.body[:offset] + altered + self.body[offset + len(original):]
        with self.assertRaisesRegex(ValueError, 'Validation instruction changed'):
            subject.check_body(body)

    def test_helper_error_must_propagate(self):
        self.mutate(0x59d6c43, '0f8569020000', '0f8469020000')

    def test_twenty_byte_comparison_requires_tail(self):
        self.mutate(0x59d6c7f, '66410f6e972c010000', '66410f6e971c010000')

    def test_identity_halves_combine_with_and(self):
        self.mutate(0x59d6c95, '660fdbcb', '660febcb')

    def test_count_boundary_inclusive_at_one_hundred(self):
        self.mutate(0x59d6f0c, '7609', '7209')

    def test_duplicate_probe_hit_must_exit(self):
        self.mutate(0x59d6f83, '74cb', '75cb')

    def test_range_excludes_lower_endpoint(self):
        self.mutate(0x59d6ff1, '0f8681000000', '0f8281000000')

    def test_range_excludes_upper_endpoint(self):
        self.mutate(0x59d6ffe, '7378', '7778')

    def test_primary_failure_must_skip_secondary(self):
        self.mutate(0x59d701a, '7526', '7426')

    def test_truncated_body(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete native decode'):
            subject.check_body(self.body[:-1])


if __name__ == '__main__':
    unittest.main()
