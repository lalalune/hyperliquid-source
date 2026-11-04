import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_mempool_conflict as subject


class MempoolConflictTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = subject.produce()
        cls.body = bytes.fromhex(cls.record['body_hex'])

    def test_exact_target_scope_and_retained_evidence(self):
        expected = json.loads((subject.PACKET / 'records.json').read_text())
        self.assertEqual(self.record, expected)
        self.assertEqual(len(self.body), 535)
        self.assertEqual(self.record['native_instructions'], 117)
        self.assertEqual([x['line'] for x in self.record['source_locations']], [818, 826])
        self.assertFalse(self.record['gates_changed'])

    def test_other_target_rejected(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.produce(b'not node115')

    def mutate(self, pc, original, altered):
        offset = pc - subject.START
        original, altered = bytes.fromhex(original), bytes.fromhex(altered)
        self.assertEqual(self.body[offset:offset + len(original)], original)
        body = self.body[:offset] + altered + self.body[offset + len(original):]
        with self.assertRaisesRegex(ValueError, 'Disposition instruction changed'):
            subject.check_body(body)

    def test_equal_must_bypass_miss_call(self):
        self.mutate(0x2e1ff62, '0f84d2000000', '0f85d2000000')

    def test_mismatch_must_return_after_diagnostic(self):
        self.mutate(0x2e2001e, 'eb1a', 'eb07')

    def test_both_payload_halves_required(self):
        self.mutate(0x2e1ff48, 'f30f6f5a10', 'f30f6f5a00')

    def test_combine_is_and_not_or(self):
        self.mutate(0x2e1ff55, '660fdbd3', '660febd3')

    def test_flat_miss_bound_is_unsigned(self):
        self.mutate(0x2e1fef1, '0f8329010000', '0f8d29010000')

    def test_truncated_decode_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete native decode'):
            subject.check_body(self.body[:-1])


if __name__ == '__main__':
    unittest.main()
