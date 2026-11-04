import json
import mmap
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_record20_equality as subject

PACKET = ROOT / 'research/work-items/RE-001-node115-record20-equality'


class Record20EqualityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = subject.TARGET.open('rb')
        cls.data = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.record = subject.extract(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.stream.close()

    def test_retained_records_and_readme_counts(self):
        retained = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(retained, self.record)
        readme = (PACKET / 'README.md').read_text()
        self.assertEqual(readme, subject.readme(retained))
        self.assertIn(f"{len(retained['instructions'])}-instruction", readme)
        self.assertIn(f"{len(retained['callees'])} callees", readme)
        self.assertIn(f"{len(retained['direct_rel32_candidates'])} candidate sites", readme)
        self.assertIn(f"{retained['window']['size']} bytes", readme)
        self.assertIn(f"{len(bytes.fromhex(retained['window']['padding_bytes']))} bytes from", readme)

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            subject.generate(out)
            for name in ('README.md', 'records.json'):
                self.assertEqual((out / name).read_bytes(), (PACKET / name).read_bytes())

    def test_record_boundary_vectors(self):
        left = bytes(range(60))
        self.assertTrue(subject.model(b'', b'', 0))
        self.assertTrue(subject.model(left, left, 3))
        for position in range(60):
            changed = bytearray(left)
            changed[position] ^= 0x80
            self.assertFalse(subject.model(left, changed, 3), position)
            if position >= 20:
                self.assertTrue(subject.model(left, changed, 1), position)
        with self.assertRaises(ValueError):
            subject.model(left, left[:-1], 3)
        with self.assertRaises(ValueError):
            subject.model(left, left, -1)

    def test_simd_mask_argument_all_lane_positions(self):
        # Independently compute the actual two PCMPEQB lane masks, including
        # MOVD's zeroed upper lanes, then compare with the scalar model.
        left = bytes(range(20))
        for index in range(20):
            right = bytearray(left)
            right[index] ^= 1
            first = [a == b for a, b in zip(left[:16], right[:16])]
            tail = [a == b for a, b in zip(left[16:], right[16:])] + [True] * 12
            mask = sum((a and b) << i for i, (a, b) in enumerate(zip(first, tail)))
            self.assertEqual(mask == 0xffff, subject.model(left, right, 1))
            self.assertNotEqual(mask, 0xffff, index)

    def test_wrong_digest_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.extract(b'wrong binary')
        offset = subject.START - 0x1000
        self.data[offset] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                subject.extract(self.data)
        finally:
            self.data[offset] ^= 1

    def test_mutated_window_rejected_below_digest_gate(self):
        offset = subject.START - 0x1000 + 0x1e
        self.data[offset] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'instruction encoding changed'):
                subject.extract(self.data, authenticate=False)
        finally:
            self.data[offset] ^= 1

    def test_shifted_fde_rejected_below_digest_gate(self):
        offset = subject.FDE + 8
        self.data[offset] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'FDE changed'):
                subject.extract(self.data, authenticate=False)
        finally:
            self.data[offset] ^= 1

    def test_wrong_callee_target_rejected(self):
        offset = subject.CALLERS[0] - 0x1000 + 1
        self.data[offset] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'caller target changed'):
                subject.caller_target(self.data, offset - 1, subject.CALLERS[0])
            with self.assertRaisesRegex(ValueError, 'caller context instruction changed'):
                subject.extract(self.data, authenticate=False)
        finally:
            self.data[offset] ^= 1

    def test_padding_and_caller_opcode_rejected(self):
        offset = subject.END - 0x1000
        self.data[offset] = 0x90
        try:
            with self.assertRaisesRegex(ValueError, 'padding changed'):
                subject.extract(self.data, authenticate=False)
        finally:
            self.data[offset] = 0xcc
        with self.assertRaisesRegex(ValueError, 'caller opcode changed'):
            subject.caller_target(b'\x90\x00\x00\x00\x00', 0, subject.CALLERS[0])


if __name__ == '__main__':
    unittest.main()
