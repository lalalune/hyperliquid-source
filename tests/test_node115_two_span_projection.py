"""Target-bound controls for the two-span projection."""
import json
import mmap
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from tools import node115_two_span_projection as subject

PACKET = subject.ROOT / 'research/work-items/RE-001-node115-two-span-projection'


class RingSpansTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = subject.TARGET.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_READ)
        cls.body = cls.data[subject.START - 0x1000:subject.END - 0x1000]
        cls.cie = cls.data[subject.FRAME:subject.FRAME + 24]
        cls.fde = cls.data[subject.FRAME + subject.FDE:subject.FRAME + subject.FDE + 20]

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def test_reproduce_all_files(self):
        with tempfile.TemporaryDirectory() as d:
            subject.produce(d)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((Path(d) / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_all_instruction_bytes_are_checked(self):
        self.assertEqual(len(subject.decode(self.body)), 37)
        for i in range(len(self.body)):
            changed = bytearray(self.body)
            changed[i] ^= 1
            with self.subTest(offset=i), self.assertRaises(ValueError):
                subject.decode(changed)

    def test_shifted_fde_and_cie_rejected(self):
        for offset in (4, 8, 12, 16):
            fde = bytearray(self.fde)
            fde[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                subject.frame_record(self.cie, fde)
        cie = bytearray(self.cie)
        cie[16] ^= 1
        with self.assertRaises(ValueError):
            subject.frame_record(cie, self.fde)

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.collect(b'not the node #115 artifact')

    def test_mutated_file_and_redirected_caller_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / 'node'
            shutil.copyfile(subject.TARGET, target)
            with target.open('r+b') as f:
                f.seek(subject.EXPECTED_CALLS[0] - 0x1000 + 1)
                displacement = struct.unpack('<i', f.read(4))[0]
                f.seek(-4, 1)
                f.write(struct.pack('<i', displacement + 1))
                f.flush()
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as changed:
                    with self.assertRaisesRegex(ValueError, 'census changed'):
                        subject.scan_calls(changed)
                    with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                        subject.collect(changed)

    def test_mutated_window_fails_public_digest(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / 'node'
            shutil.copyfile(subject.TARGET, target)
            with target.open('r+b') as f:
                f.seek(subject.START - 0x1000)
                f.write(b'\x49')
                f.flush()
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as changed:
                    with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                        subject.collect(changed)

    def test_valid_ring_spans_cover_logical_indices(self):
        for capacity in range(1, 12):
            for head in range(2 * capacity):
                for count in range(capacity + 1):
                    a, b, c, d = subject.rule(capacity, 0, head, count)
                    actual = list(range(a // 80, b // 80)) + list(range(c // 80, d // 80))
                    expected = [(head + i) % capacity for i in range(count)]
                    self.assertEqual(actual, expected, (capacity, head, count))

    def test_zero_and_no_wrap(self):
        self.assertEqual(subject.rule(10, 1000, 8, 0), (1000,) * 4)
        self.assertEqual(subject.rule(10, 1000, 3, 4), (1240, 1560, 1000, 1000))
        self.assertEqual(subject.rule(10, 1000, 8, 2), (1640, 1800, 1000, 1000))

    def test_wrapping_and_single_normalization(self):
        self.assertEqual(subject.rule(10, 1000, 8, 5), (1640, 1800, 1000, 1240))
        self.assertEqual(subject.rule(10, 1000, 18, 5), (1640, 1800, 1000, 1240))
        self.assertEqual(subject.rule(10, 1000, 28, 3), (2440, 2680, 1000, 1000))

    def test_word_arithmetic_wraps(self):
        top = (1 << 64) - 1
        self.assertEqual(subject.rule(10, top - 79, 1, 1), (0, 80, top - 79, top - 79))

    def test_readme_counts_match_json(self):
        r = json.loads((PACKET / 'records.json').read_text())
        text = (PACKET / 'README.md').read_text()
        self.assertIn(f"({r['window']['size']} bytes)", text)
        self.assertIn(f"next {len(bytes.fromhex(r['window']['padding_hex']))} bytes", text)
        self.assertIn(f"has {len(r['instructions'])} instructions", text)
        self.assertIn(f"are {len(r['callees'])} callees", text)
        self.assertIn(f"yields {len(r['direct_rel32_candidates'])} candidate sites", text)
        self.assertEqual(text.count('| `0x'), len(r['instructions']))

    def test_section_mapping_and_rel32_census(self):
        subject.check_sections(self.data)
        hits = subject.scan_calls(self.data)
        self.assertEqual([h['site'] for h in hits], subject.EXPECTED_CALLS)
        self.assertEqual([h['opcode'] for h in hits], ['e8', 'e8'])


if __name__ == '__main__':
    unittest.main()
