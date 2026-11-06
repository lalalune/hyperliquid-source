"""Target-grounded static controls for one node #115 leaf."""
import json
import mmap
from pathlib import Path
import random
import re
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_folded_product_update as bind

PACKET = ROOT / 'research/work-items/RE-001-node115-folded-product-update'


class FoldedProductUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((PACKET / 'records.json').read_text())
        with open(bind.TARGET, 'rb') as f:
            f.seek(cls.record['window']['file_offset'])
            cls.body = f.read(cls.record['window']['size'])

    def test_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            bind.generate(bind.TARGET, Path(tmp))
            self.assertEqual((Path(tmp) / 'records.json').read_bytes(), (PACKET / 'records.json').read_bytes())

    def test_wrong_digest_fails_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / 'wrong', Path(tmp) / 'result'
            source.write_bytes(b'not node 115')
            with self.assertRaisesRegex(ValueError, 'digest'):
                bind.generate(source, out)
            self.assertFalse(out.exists())

    def test_same_size_modified_target_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / 'modified', Path(tmp) / 'output'
            shutil.copyfile(bind.TARGET, source)
            with source.open('r+b') as f:
                f.seek(self.record['window']['file_offset'])
                first = f.read(1)
                f.seek(-1, 1)
                f.write(bytes([first[0] ^ 1]))
            with self.assertRaisesRegex(ValueError, 'digest'):
                bind.generate(source, out)
            self.assertFalse(out.exists())

    def test_each_window_byte_corruption_rejected(self):
        for index in range(len(self.body)):
            corrupt = bytearray(self.body)
            corrupt[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                bind.decode(corrupt, bind.FDE)

    def test_fde_and_injected_call_rejected(self):
        # Patch the PC-relative start in a private copy-on-write mapping and
        # reparse the actual frame. The captured file is never modified.
        with bind.TARGET.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_COPY) as data:
            data[bind.FDE['fde'] + 8] ^= 1
            _, frames = bind.eh_frame_records(data)
            altered = next(row for row in frames if row['fde'] == bind.FDE['fde'])
        with self.assertRaisesRegex(ValueError, 'FDE'):
            bind.decode(self.body, altered)
        corrupt = bytearray(self.body)
        corrupt[0:5] = b'\xe8\x00\x00\x00\x00'
        with self.assertRaises(ValueError):
            bind.decode(corrupt, bind.FDE)

    def test_target_vectors_for_all_three_routes(self):
        block = (1).to_bytes(8, 'little') + bytes(8) + (0x89abcdef).to_bytes(4, 'little')
        self.assertEqual(bind.model((1, 2, 3), 4, 0, block), (0x89abcdef, 0, 12, 32))
        self.assertEqual(bind.model((1, 2, 3), 4, 1, block), (0, 0x89abcdef, 0, 96))
        self.assertEqual(bind.model((1, 2, 3), 4, 64, block), (0, 0x89abcdef, 14, 96))
        self.assertEqual(bind.model((1, 2, 3), 4, 65, block), (0x89abcdef, 0, 52, 32))
        self.assertEqual(bind.model((1, 2, 3), 4, 255, block), (0x89abcdef, 0, 52, 32))

    def test_product_halves_boundaries(self):
        m = (1 << 64) - 1
        self.assertEqual(bind.fold(m, m), m)
        self.assertEqual(bind.fold(1 << 63, 2), 1)
        self.assertEqual(bind.fold(0, m), 0)
        rng = random.Random(115)
        for _ in range(1000):
            a, b = rng.getrandbits(64), rng.getrandbits(64)
            product = a * b
            self.assertEqual(bind.fold(a, b), int.from_bytes(product.to_bytes(16, 'little')[:8], 'little') ^ int.from_bytes(product.to_bytes(16, 'little')[8:], 'little'))

    def test_shift_boundaries_and_input_validation(self):
        block = (1 << 63).to_bytes(8, 'little') + bytes(12)
        self.assertEqual(bind.model((0, 0, 1), 1, 63, block)[2], (1 << 62) + 1)
        self.assertEqual(bind.model((0, 0, 1), 1, 64, block)[2], (1 << 63) | 1)
        with self.assertRaises(ValueError):
            bind.model((0, 0, 0), 0, 256, block)
        with self.assertRaises(ValueError):
            bind.model((0, 0, 0), 0, 1, block[:-1])

    def test_readme_counts_are_records_counts(self):
        text = (PACKET / 'README.md').read_text()
        counts = self.record['counts']
        for key, label in [('instructions', 'instructions'), ('callees', 'callees'), ('rel32_candidates', 'rel32 candidates')]:
            self.assertIn(f"**{counts[key]} {label}**", text)
        self.assertEqual(counts['instructions'], len(self.record['instructions']))
        self.assertEqual(counts['callees'], len(self.record['callees']))
        self.assertEqual(counts['rel32_candidates'], len(self.record['rel32_candidates']))
        self.assertEqual(counts['rel32_candidates'], self.record['census']['candidate_count'])
        self.assertEqual(int(re.search(r'\((\d+) bytes\)', text).group(1)), self.record['window']['size'])
        self.assertEqual(int(re.search(r'(\d+) `cc` bytes', text).group(1)), len(bytes.fromhex(self.record['window']['padding_hex'])))


if __name__ == '__main__':
    unittest.main()
