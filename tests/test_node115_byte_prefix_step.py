import json
import mmap
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_byte_prefix_step as subject

PACKET = ROOT / 'research/work-items/RE-001-node115-byte-prefix-step'


class BytePrefixStepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = subject.TARGET.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.record = subject.inspect(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def corrupt(self, offset, authenticated=False):
        old = self.data[offset]
        try:
            self.data[offset] ^= 1
            with self.assertRaises(ValueError):
                subject.inspect(self.data, authenticate=authenticated)
        finally:
            self.data[offset] = old

    def test_regeneration(self):
        expected = json.dumps(self.record, indent=2) + '\n'
        self.assertEqual((PACKET / 'records.json').read_text(), expected)
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, str(ROOT / 'tools/node115_byte_prefix_step.py'), '--out', tmp], check=True)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes())

    def test_wrong_digest(self):
        self.corrupt(self.record['window']['file_offset'], authenticated=True)

    def test_wrong_public_input_creates_no_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'fake'
            fake.write_bytes(b'not the target')
            out = Path(tmp) / 'output'
            result = subprocess.run([sys.executable, str(ROOT / 'tools/node115_byte_prefix_step.py'),
                                     '--target', str(fake), '--out', str(out)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(out.exists())

    def test_mutated_instruction(self):
        self.corrupt(self.record['window']['file_offset'] + 0x30)

    def test_shifted_fde(self):
        self.corrupt(subject.FDE + 8)

    def test_redirected_call(self):
        self.corrupt(subject.CALLERS[0] - 0x1000 + 1)

    def test_descriptor_displacement(self):
        self.corrupt(self.record['window']['file_offset'] + 0x76)

    def test_rule_boundaries(self):
        d = subject.DESCRIPTOR
        cases = {0x00:(0,0), 0x7f:(0,0x7f), 0x80:(0x80,0), 0x8f:(0x80,15),
                 0x90:(0x90,0), 0x9f:(0x90,15), 0xa0:(0xa0,0),
                 0xbf:(0xa0,31), 0xc1:(0xc1,1), 0xdf:(0xdf,31),
                 0xe0:(0xe0,0xe0), 0xff:(0xe0,0xff)}
        for byte, (x, y) in cases.items():
            with self.subTest(byte=byte):
                self.assertEqual(subject.model(byte), {0:2, 1:x, 2:y, 8:d})
        self.assertEqual(subject.model(0xc0), {0:9})
        self.assertEqual(subject.model(None), {0:0, 8:d})
        for invalid in (-1, 256, 'x'):
            with self.assertRaises(ValueError):
                subject.model(invalid)

    def test_readme_counts(self):
        readme = (PACKET / 'README.md').read_text()
        m = re.search(r'Packet counts: (\d+) bytes; (\d+) instructions; (\d+) callees; (\d+) direct rel32 candidates; (\d+) padding bytes\.', readme)
        self.assertIsNotNone(m)
        w = self.record['window']
        self.assertEqual(tuple(map(int, m.groups())), (w['size'], len(self.record['instructions']),
                         len(self.record['callees']), len(self.record['direct_rel32_candidates']),
                         len(bytes.fromhex(w['padding_hex']))))


if __name__ == '__main__':
    unittest.main()
