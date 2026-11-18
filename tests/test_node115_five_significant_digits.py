"""Controls for the #115 five-significant-digit truncation static evidence."""
import hashlib
import json
import mmap
from pathlib import Path
import random
import tempfile
import unittest

from tools import node115_five_significant_digits as bind

PACKET = bind.PACKET


class FiveSignificantDigitsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((PACKET / 'records.json').read_text())
        cls.rows = cls.record['function']['instructions']

    def test_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'packet'
            bind.generate(bind.TARGET, out)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((out / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_readme_counts_match_records(self):
        text = (PACKET / 'README.md').read_text()
        function = self.record['function']
        self.assertIn(f"**{function['size']} bytes**", text)
        self.assertIn(f"**{len(function['instructions'])} instructions**", text)
        self.assertIn(f"**{len(function['callees'])} callees**", text)
        self.assertIn(f"**{len(self.record['direct_references'])} direct-reference candidates**", text)
        self.assertIn(f"**{len(self.record['closed_form']['cells'])} cells**", text)
        self.assertEqual(len(bytes.fromhex(function['padding_hex'])), 3)
        self.assertIn('Three `cc` padding bytes', text)

    def test_instruction_coverage(self):
        f = self.record['function']
        body = bytes.fromhex(f['body_hex'])
        self.assertEqual(bind.decode(body), self.rows)
        self.assertEqual(hashlib.sha256(body).hexdigest(), f['body_sha256'])
        self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in self.rows), body)
        self.assertFalse(any('[' in i['op'] for i in self.rows))

    def test_certificate_matches_records(self):
        self.assertEqual(bind.certificate(self.rows), {
            'compares': self.record['closed_form']['compares'],
            'cells': self.record['closed_form']['cells']})
        cells = self.record['closed_form']['cells']
        self.assertEqual(cells[0]['start'], 0)
        self.assertEqual(cells[-1]['end'], 1 << 64)
        for a, b in zip(cells, cells[1:]):
            self.assertEqual(a['end'], b['start'])

    def test_vectors(self):
        values = [0, 1, 99_999, 100_000, 123_456, (1 << 32) - 1, 1 << 32, (1 << 64) - 1]
        for k in range(20):
            values += [10 ** k - 1, 10 ** k, 10 ** k + 1]
        rng = random.Random(115)
        values += [rng.getrandbits(rng.randrange(1, 65)) for _ in range(2000)]
        for x in values:
            x &= bind.MASK
            self.assertEqual(bind.run(self.rows, x)[0], bind.significant5(x)[1], x)
        self.assertEqual(bind.run(self.rows, 123_456)[0], 123_450)
        self.assertEqual(bind.run(self.rows, (1 << 64) - 1)[0], 18_446_000_000_000_000_000)

    def test_wrong_digest_fails_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary, out = Path(tmp) / 'wrong', Path(tmp) / 'out'
            with binary.open('wb') as f:
                f.truncate(105896032)
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.generate(binary, out)
            self.assertFalse(out.exists())

    def test_mutated_instruction_rejected(self):
        body = bytearray.fromhex(self.record['function']['body_hex'])
        body[0] ^= 1
        with self.assertRaises(ValueError):
            bind.decode(body)

    def test_mutated_compare_constant_breaks_certificate(self):
        body = bytearray.fromhex(self.record['function']['body_hex'])
        # Third byte of the imm32 in `cmp rdi, 0x186a0` (100000 -> 100000 ^ 0x10000).
        self.assertEqual(body[8:15], bytes.fromhex('4881ffa0860100'))
        body[13] ^= 0x01
        rows = bind.decode(body)
        with self.assertRaisesRegex(ValueError, 'closed form'):
            bind.certificate(rows)

    def test_shifted_fde_rejected(self):
        f = self.record['function']['frame']
        raw = bytearray.fromhex(f['fde_bytes'])
        raw[8] ^= 1
        with self.assertRaisesRegex(ValueError, 'FDE'):
            bind.frame(raw, bytes.fromhex(f['cie_bytes']))

    def test_redirected_call_rejected(self):
        call = self.record['direct_references'][0]
        raw = bytearray.fromhex(call['bytes'])
        self.assertEqual(bind.direct_target(call['site'], raw), bind.START)
        raw[1] ^= 1
        with self.assertRaisesRegex(ValueError, 'target'):
            bind.check_reference(call['site'], raw)
        with bind.TARGET.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_COPY) as data:
            data[call['site'] - 0x1000 + 1] ^= 1
            with self.assertRaisesRegex(ValueError, 'census'):
                bind.scan(data)


if __name__ == '__main__':
    unittest.main()
