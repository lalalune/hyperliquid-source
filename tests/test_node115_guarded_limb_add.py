import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_guarded_limb_add as bind


class GuardedLimbAddTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = bind.TARGET.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.packet = bind.PACKET
        cls.record = bind.collect(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def corrupt(self, offset, value, *, authenticate=False):
        old = self.data[offset]
        self.data[offset] = value
        try:
            with self.assertRaises(ValueError):
                bind.collect(self.data, authenticate=authenticate)
        finally:
            self.data[offset] = old

    def test_regeneration(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, str(ROOT / 'tools/node115_guarded_limb_add.py'),
                            '--out', out], check=True, capture_output=True)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((Path(out) / name).read_bytes(),
                                 (self.packet / name).read_bytes(), name)
        self.assertEqual(bind.render(self.record), (self.packet / 'records.json').read_bytes())

    def test_instruction_coverage_and_branch(self):
        rows = self.record['instructions']
        self.assertEqual(sum(len(bytes.fromhex(r['bytes'])) for r in rows), bind.END - bind.START)
        self.assertEqual(rows[2]['target'], rows[-2]['address'])
        self.assertEqual(len(self.record['callees']), 0)

    def test_readme_counts(self):
        text = (self.packet / 'README.md').read_text()
        for key, value in self.record['counts'].items():
            match = re.search(r'^\| ' + re.escape(key) + r' \| (\d+) \|$', text, re.M)
            self.assertIsNotNone(match, key)
            self.assertEqual(int(match.group(1)), value, key)

    def test_rule_boundaries_and_carries(self):
        mask = (1 << 256) - 1
        for n in (0, 1):
            self.assertEqual(bind.model(n, mask, 1), (n, mask, 44))
        for lo, hi, expected in ((0, 0, 0), (mask, 1, 0),
                                  ((1 << 64) - 1, 1, 1 << 64),
                                  ((1 << 128) - 1, 1, 1 << 128),
                                  ((1 << 192) - 1, 1, 1 << 192),
                                  (mask, mask, mask - 1)):
            self.assertEqual(bind.model(2, lo, hi), (1, expected, 0))
        self.assertEqual(bind.model(3, 5, 7), (2, 12, 0))
        with self.assertRaises(ValueError):
            bind.model(2, -1, 0)

    def test_wrong_digest_and_window_corruption(self):
        off = self.record['window']['file_offset']
        self.corrupt(off, self.data[off] ^ 1, authenticate=True)
        self.corrupt(off + 0x2f, self.data[off + 0x2f] ^ 1)

    def test_shifted_fde(self):
        # FDE's pcrel initial-location field, distinct from code bytes.
        off = bind.FDE['fde'] + 8
        self.corrupt(off, self.data[off] ^ 1)

    def test_branch_retarget_and_inserted_call(self):
        off = self.record['window']['file_offset']
        self.corrupt(off + 9, self.data[off + 9] ^ 1)
        # This is a leaf; changing the first instruction to a CALL opcode must fail.
        self.corrupt(off, 0xe8)

    def test_new_direct_transfer_is_detected(self):
        # Introduce a real rel32 candidate elsewhere in .text below the hash gate.
        off, site = 0x1418300, 0x1419300
        original = self.data[off:off + 5]
        try:
            for opcode in (0xe8, 0xe9):
                self.data[off:off + 5] = bytes([opcode]) + struct.pack('<i', bind.START - site - 5)
                with self.assertRaisesRegex(ValueError, 'direct rel32'):
                    bind.collect(self.data, authenticate=False)
        finally:
            self.data[off:off + 5] = original

    def test_relocation_and_padding_corruption(self):
        self.corrupt(0x61068 + 16, self.data[0x61068 + 16] ^ 1)
        off = self.record['window']['file_offset'] + self.record['window']['size']
        self.corrupt(off, 0x90)

    def test_rejects_wrong_input_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrong = Path(tmp) / 'wrong'; wrong.write_bytes(b'not the node')
            out = Path(tmp) / 'output'
            proc = subprocess.run([sys.executable, str(ROOT / 'tools/node115_guarded_limb_add.py'),
                                   '--binary', str(wrong), '--out', str(out)], capture_output=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
