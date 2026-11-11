"""Target-grounded and corruption controls for the #115 byte leaf."""
import json
import mmap
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

from tools import node115_gated_byte_consume as b


class GatedByteConsume(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = b.TARGET.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.sec = b.sections(cls.data)
        cls.record = b.extract(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def flip(self, offset, operation):
        before = self.data[offset]
        self.data[offset] ^= 1
        try:
            with self.assertRaises(ValueError):
                operation()
        finally:
            self.data[offset] = before

    def test_counts_and_record(self):
        self.assertEqual(self.record, json.loads((b.PACKET / 'records.json').read_text()))
        labels = {'Body bytes': 'body_bytes', 'Instructions': 'instructions',
                  'Padding bytes': 'padding_bytes', 'Callees': 'callees',
                  'Direct rel32 hits': 'direct_rel32_hits'}
        matches = re.findall(r'^- (Body bytes|Instructions|Padding bytes|Callees|Direct rel32 hits): (\d+)$',
                             (b.PACKET / 'README.md').read_text(), re.MULTILINE)
        self.assertEqual(len(matches), len(labels))
        self.assertEqual({labels[k]: int(v) for k, v in matches}, self.record['counts'])

    def test_rule_boundaries(self):
        m = 2**64-1
        vectors = [
            ((0, m, 0, 1, 255), (18, m, 1, 255, None)),
            ((1, 0, 1, 1, 0), (18, 1, 1, 0, None)),
            ((1, 1, 1, 1, 7), (2, 2, 0, None, None)),
            ((1, m, m, 1, 7), (2, m, 0, None, None)),
            ((1, m-1, m, 0, None), (0, m, 0, None, 1)),
            ((1, 0, 0, 0, None), (2, 1, 0, None, None)),
            ((2, 17, 0, 0, None), (0, 17, 0, None, 1)),
        ]
        for args, expected in vectors:
            with self.subTest(args=args):
                self.assertEqual(b.model(*args), expected)
        with self.assertRaises(ValueError):
            b.model(1, -1, 0, 0)

    def test_wrong_digest_no_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            bad = path / 'bad'
            bad.write_bytes(b'not the target')
            p = subprocess.run([sys.executable, str(b.ROOT / 'tools/node115_gated_byte_consume.py'),
                                '--binary', str(bad), '--out', str(path / 'out')], capture_output=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn(b'digest mismatch', p.stderr)
            self.assertFalse((path / 'out').exists())

    def test_body_mutation(self):
        off = b.START-0x1000
        self.flip(off+1, lambda: b.decode_body(b.read_va(self.data, self.sec['.text'], b.START, b.END-b.START)))

    def test_branch_displacement_mutation(self):
        off = b.START-0x1000
        self.flip(off+7, lambda: b.decode_body(b.read_va(self.data, self.sec['.text'], b.START, b.END-b.START)))

    def test_shifted_fde(self):
        self.flip(b.FDE+8, lambda: b.decode_fde(self.data, self.sec['.eh_frame']))

    def test_changed_fde_extent(self):
        self.flip(b.FDE+12, lambda: b.decode_fde(self.data, self.sec['.eh_frame']))

    def test_injected_caller_target(self):
        text = self.sec['.text']
        pos = text['offset']
        old = self.data[pos:pos+5]
        site = text['address']
        self.data[pos:pos+5] = b'\xe8' + struct.pack('<i', b.START-site-5)
        try:
            with self.assertRaises(ValueError):
                b.scan_calls(self.data, text)
        finally:
            self.data[pos:pos+5] = old

    def test_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'packet'
            subprocess.run([sys.executable, str(b.ROOT / 'tools/node115_gated_byte_consume.py'),
                            '--out', str(out)], check=True, capture_output=True)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((out / name).read_bytes(), (b.PACKET / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
