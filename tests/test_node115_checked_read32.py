"""Static target-bound controls for the checked 32-byte read."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_checked_read32 as subject
PACKET = ROOT / 'research/work-items/RE-001-node115-checked-read32'


class CheckedRead32(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Keep one binary buffer resident; corrupt only small extracted windows.
        cls.data = subject.TARGET.read_bytes()
        cls.record = subject.extract(cls.data)

    def test_packet_reproduces(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)
            subject.generate(dest, self.data)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((dest / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_digest_rejects_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                subject.generate(Path(tmp), b'wrong target')
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_mutated_window_and_branch_are_rejected(self):
        off = self.record['window']['file_offset']
        body = self.data[off:off+subject.END-subject.START]
        for pos in (0, 7, 16, 56, 114):
            corrupted = bytearray(body)
            corrupted[pos] ^= 1
            with self.subTest(pos=pos), self.assertRaises(ValueError):
                subject.decode(corrupted)
        with self.assertRaises(ValueError):
            subject.decode(body[:-1])

    def test_shifted_fde_rejected(self):
        fde = copy.deepcopy(self.record['window']['fde'])
        before = {'start': subject.START - 20, 'end': subject.START - 11}
        after = {'start': subject.END + 13, 'end': subject.END + 30}
        subject.check_fde([before, fde, after])
        fde['end'] += 1
        with self.assertRaisesRegex(ValueError, 'FDE'):
            subject.check_fde([before, fde, after])

    def test_wrong_callee_target_rejected(self):
        row = self.record['raw_direct_branches_to_entry'][0]
        call = bytearray.fromhex(row['bytes'])
        subject.validate_caller(row['site'], call)
        call[1] ^= 1
        with self.assertRaisesRegex(ValueError, 'target'):
            subject.validate_caller(row['site'], call)

    def test_success_and_short_boundaries(self):
        p = bytes(range(32))
        for remaining, tag in ((0, 1), (31, 1), (32, 0), (33, 0)):
            with self.subTest(remaining=remaining):
                r = subject.model(0, 7, 0, remaining, p)
                self.assertEqual(r['tag'], tag)
                self.assertEqual(r['count'], 7)
                if tag:
                    self.assertEqual(r['missing'], 32 - remaining)
                    self.assertEqual(r['remaining'], remaining)
                else:
                    self.assertEqual(r['value'], p)
                    self.assertEqual(r['remaining'], remaining - 32)
                    self.assertEqual(r['advance'], 32)

    def test_counter_boundaries_and_order(self):
        m = (1 << 64) - 1
        p = bytes(range(32))
        # The increment is stored even when the limit or short-input test fails.
        r = subject.model(1, 4, 35, 0, p)
        self.assertEqual((r['error'], r['count'], r['remaining']), (2, 36, 0))
        r = subject.model(1, 4, 36, 0, p)
        self.assertEqual((r['error'], r['missing'], r['count']), (0, 32, 36))
        r = subject.model(1, m-32, m, 32, p)
        self.assertEqual((r['tag'], r['count']), (0, m))
        r = subject.model(1, m-31, m, 32, p)
        self.assertEqual((r['error'], r['count']), (2, m-31))
        self.assertEqual(subject.model(2, m, 0, 32, p)['tag'], 0)

    def test_readme_counts_match_json(self):
        text = (PACKET / 'README.md').read_text()
        r = json.loads((PACKET / 'records.json').read_text())
        w = r['window']
        for expected in (f"{r['target_size']} bytes", f"{w['size']} bytes, file offset",
                         f"end {w['padding_before_int3']} bytes before",
                         f"begin {w['padding_after_int3']} bytes after",
                         f"{len(r['callees'])} callees", f"The {len(r['instructions'])} instructions",
                         f"yields {len(r['raw_direct_branches_to_entry'])} matches"):
            self.assertIn(expected, text)
        self.assertEqual(text, subject.render_readme(r))


if __name__ == '__main__':
    unittest.main()
