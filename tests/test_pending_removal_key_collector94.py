"""Synthetic boundary checks; no captured executable or instruction evaluator."""
import importlib.util
from pathlib import Path
import struct
import unittest

PACKET = Path(__file__).resolve().parents[1] / 'research/work-items/RE-006-pending-removal-key-collector-94'
spec = importlib.util.spec_from_file_location('pending_collector', PACKET / 'verify.py')
packet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)


class ProjectionTests(unittest.TestCase):
    def rows(self, words):
        return b''.join(struct.pack('<QQQQ', key, 11, 12, 13) for key in words)

    def test_unsigned_high_bit_and_duplicates(self):
        words = [2**64 - 1, 0, 2**63, 1, 2**63]
        self.assertEqual(packet.project_model(self.rows(words)), (sorted(words), 'inline'))

    def test_empty_and_singleton(self):
        self.assertEqual(packet.project_model(b''), ([], 'empty'))
        self.assertEqual(packet.project_model(self.rows([9])), ([9], 'single'))

    def test_twenty_one_delegates_without_inventing_sort_semantics(self):
        twenty = list(range(20, 0, -1))
        self.assertEqual(packet.project_model(self.rows(twenty)), (sorted(twenty), 'inline'))
        twenty_one = list(range(21, 0, -1))
        self.assertEqual(packet.project_model(self.rows(twenty_one)), (twenty_one, 'delegate'))

    def test_four_way_projection_and_tail_boundaries(self):
        for n in range(2, 25):
            words = list(range(n, 0, -1))
            expected = sorted(words) if n <= 20 else words
            with self.subTest(rows=n):
                self.assertEqual(packet.project_model(self.rows(words))[0], expected)

    def test_model_refuses_partial_rows(self):
        for n in [1, 7, 8, 24, 31, 33, 63]:
            with self.subTest(bytes=n), self.assertRaises(ValueError):
                packet.project_model(bytes(n))

    def test_target_operand_controls_below_digest_gate(self):
        data = packet.TARGET.read_bytes()
        self.assertEqual(packet.sha(data), packet.SHA)
        original = packet.Image(data)
        packet.local_obligations(original)
        for name, va, _ in packet.PINS:
            modified = bytearray(data)
            modified[original.offset(va, 1)] ^= 1
            with self.subTest(obligation=name), self.assertRaisesRegex(ValueError, 'operand/control mismatch'):
                packet.local_obligations(packet.Image(modified))


if __name__ == '__main__':
    unittest.main()
