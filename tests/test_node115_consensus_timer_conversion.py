import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_consensus_timer_conversion as subject


class ConsensusTimerConversionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = subject.produce()
        cls.body = bytes.fromhex(cls.record['body_hex'])

    def test_exact_target_scope_and_evidence(self):
        self.assertEqual(self.record, json.loads((subject.PACKET / 'records.json').read_text()))
        self.assertEqual(len(self.body), 604)
        self.assertEqual(self.record['native_instructions'], 150)
        self.assertEqual(self.record['source_locations'][0]['line'], 17)
        self.assertEqual(self.record['source_locations'][0]['column'], 30)
        self.assertFalse(self.record['gates_changed'])

    def test_wrong_target(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.produce(b'not node115')

    def mutate(self, pc, original, altered):
        original, altered = bytes.fromhex(original), bytes.fromhex(altered)
        offset = pc - subject.START
        self.assertEqual(self.body[offset:offset + len(original)], original)
        body = self.body[:offset] + altered + self.body[offset + len(original):]
        with self.assertRaisesRegex(ValueError, 'Conversion instruction changed'):
            subject.check_body(body)

    def test_negative_input_must_take_panic_arm(self):
        self.mutate(0x4eca5e7, '0f87f0010000', '0f85f0010000')

    def test_sub_minimum_exponent_boundary(self):
        self.mutate(0x4eca602, '81f9e0030000', '81f9e1030000')

    def test_fraction_regime_upper_boundary(self):
        self.mutate(0x4eca62c, '81faff030000', '81fafe030000')

    def test_nanos_multiplier_is_one_billion(self):
        self.mutate(0x4eca64d, 'b900ca9a3b', 'b901ca9a3b')

    def test_rounding_carry_requires_exact_billion(self):
        self.mutate(0x4eca6a0, '410f94c6', '410f95c6')

    def test_whole_seconds_regime_boundary(self):
        self.mutate(0x4eca6ad, '81fa33040000', '81fa32040000')

    def test_overflow_regime_boundary(self):
        self.mutate(0x4eca731, '81fa3f040000', '81fa3e040000')

    def test_boxed_object_lands_at_plus_0x10(self):
        self.mutate(0x4eca7b0, '48894310', '48894318')

    def test_overflow_flag_is_one(self):
        self.mutate(0x4eca7da, '41b701', '41b700')

    def test_constructor_argument_is_the_location(self):
        self.mutate(0x4eca743, '488d0dae355d01', '488d0daf355d01')

    def test_truncated_body(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete native decode'):
            subject.check_body(self.body[:-1])


if __name__ == '__main__':
    unittest.main()
