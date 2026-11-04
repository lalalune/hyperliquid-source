"""Controls for the authenticated node #115 four-limb arithmetic bind."""
import json
import mmap
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import unittest

from tools import node115_four_limb_carry as b


class FourLimbCarry(unittest.TestCase):
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

    def flip(self, pos, operation):
        old = self.data[pos]
        self.data[pos] = old ^ 1
        try:
            with self.assertRaises(ValueError):
                operation()
        finally:
            self.data[pos] = old

    def test_record_and_readme_counts(self):
        self.assertEqual(self.record, json.loads((b.PACKET / 'records.json').read_text()))
        readme = (b.PACKET / 'README.md').read_text()
        labels = {'Body bytes': 'body_bytes', 'Instructions': 'instructions',
                  'Padding bytes': 'padding_bytes', 'Callees': 'callees',
                  'Direct rel32 hits': 'direct_rel32_hits'}
        matches = re.findall(r'^- (Body bytes|Instructions|Padding bytes|Callees|Direct rel32 hits): (\d+)$',
                             readme, re.MULTILINE)
        self.assertEqual(len(matches), len(labels))
        self.assertEqual({labels[k]: int(v) for k, v in matches}, self.record['counts'])

    def test_boundary_vectors(self):
        m = 1 << 256
        vectors = [(0, 0, 0, 0), (m-1, 0, m-1, 0), (m-1, 1, 0, 1),
                   (m-1, m-1, m-2, 1), ((1 << 64)-1, 1, 1 << 64, 0),
                   ((1 << 192)-1, 1, 1 << 192, 0),
                   (1 << 255, 1 << 255, 0, 1)]
        for left, right, result, carry in vectors:
            self.assertEqual(b.model(left, right), (result, carry))
        for x in (-1, m):
            with self.assertRaises(ValueError):
                b.model(x, 0)

    def test_wrong_digest_fails_before_output(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t)
            bad = path / 'wrong'
            bad.write_bytes(b'incorrect target')
            result = subprocess.run([sys.executable, str(b.ROOT / 'tools/node115_four_limb_carry.py'),
                                     '--binary', str(bad), '--out', str(path / 'out')],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'digest mismatch', result.stderr)
            self.assertFalse((path / 'out').exists())

    def test_limb_carry_matches_integer_model(self):
        rng = random.Random(115)
        mask = (1 << 64) - 1
        for _ in range(1000):
            a, c = rng.getrandbits(256), rng.getrandbits(256)
            value = carry = 0
            for i in range(4):
                limb = ((a >> (64 * i)) & mask) + ((c >> (64 * i)) & mask) + carry
                value |= (limb & mask) << (64 * i)
                carry = limb >> 64
            self.assertEqual((value, carry), b.model(a, c))

    def test_mutated_body_decoder(self):
        offset = self.sec['.text']['offset'] + b.START - self.sec['.text']['address']
        self.flip(offset + 3, lambda: b.decode_body(b.read_va(self.data, self.sec['.text'], b.START, b.END - b.START)))

    def test_carry_opcode_mutation(self):
        offset = self.sec['.text']['offset'] + b.START - self.sec['.text']['address']
        self.flip(offset + 45, lambda: b.decode_body(b.read_va(self.data, self.sec['.text'], b.START, b.END - b.START)))

    def test_shifted_fde(self):
        frame = self.sec['.eh_frame']
        offset = frame['offset'] + b.FDE - frame['address']
        self.flip(offset + 8, lambda: b.decode_fde(self.data, frame))

    def test_wrong_call_target(self):
        text = self.sec['.text']
        va = 0x4fb85c7
        offset = text['offset'] + va - text['address']
        self.flip(offset + 1, lambda: b.decode_call(self.data, text, va))

    def test_changed_caller_census(self):
        text = self.sec['.text']
        va = 0x4fb93f7
        offset = text['offset'] + va - text['address']
        self.flip(offset + 1, lambda: b.scan_calls(self.data, text))

    def test_regeneration(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / 'packet'
            subprocess.run([sys.executable, str(b.ROOT / 'tools/node115_four_limb_carry.py'),
                            '--out', str(out)], check=True, capture_output=True)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((out / name).read_bytes(), (b.PACKET / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
