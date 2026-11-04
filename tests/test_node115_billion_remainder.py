"""Controls for the #115 billion-remainder static evidence."""
import hashlib
import json
import mmap
from pathlib import Path
import random
import tempfile
import unittest

from tools import node115_billion_remainder as bind

PACKET = bind.PACKET


class BillionRemainderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((PACKET / 'records.json').read_text())

    def test_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'packet'
            bind.generate(bind.TARGET, out)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((out/name).read_bytes(), (PACKET/name).read_bytes(), name)

    def test_readme_counts_match_records(self):
        text = (PACKET/'README.md').read_text()
        function = self.record['function']
        self.assertIn(f"**{function['size']} bytes**", text)
        self.assertIn(f"**{len(function['instructions'])} instructions**", text)
        self.assertIn(f"**{len(function['callees'])} callees**", text)
        self.assertIn(f"**{len(self.record['direct_references'])} direct-reference candidates**", text)
        self.assertEqual(len(bytes.fromhex(function['padding_hex'])), 3)
        self.assertIn('Three `cc` padding bytes', text)

    def test_instruction_coverage(self):
        f = self.record['function']
        body = bytes.fromhex(f['body_hex'])
        self.assertEqual(bind.decode(body), f['instructions'])
        self.assertEqual(hashlib.sha256(body).hexdigest(), f['body_sha256'])
        self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']), body)

    def test_reciprocal_certificate_and_vectors(self):
        a = self.record['arithmetic']
        m, d, e = a['multiplier'], a['reduced_divisor'], a['reciprocal_error']
        self.assertEqual(m*d - (1 << a['reduced_shift']), e)
        self.assertGreaterEqual(e, 0)
        self.assertLess(a['maximum_reduced_input']*e, 1 << a['reduced_shift'])
        rng = random.Random(115)
        values = [0, 1, 511, 512, 999999999, 1000000000, 1000000001,
                  (1<<63)-1, 1<<63, (1<<64)-1]
        values += [rng.getrandbits(64) for _ in range(1000)]
        for x in values:
            q = ((x >> 9) * m >> 64) >> 11
            self.assertEqual(x - q*a['divisor'], x % a['divisor'])

    def test_wrong_digest_fails_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary, out = Path(tmp)/'wrong', Path(tmp)/'out'
            with binary.open('wb') as f:
                f.truncate(105896032)
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.generate(binary, out)
            self.assertFalse(out.exists())

    def test_mutated_instruction_rejected(self):
        body = bytearray.fromhex(self.record['function']['body_hex'])
        body[20] ^= 1
        with self.assertRaises(ValueError):
            bind.decode(body)

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
        self.assertNotEqual(bind.direct_target(call['site'], raw), bind.START)
        with self.assertRaisesRegex(ValueError, 'target'):
            bind.check_reference(call['site'], raw)
        with bind.TARGET.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_COPY) as data:
            data[call['site'] - 0x1000 + 1] ^= 1
            with self.assertRaisesRegex(ValueError, 'census'):
                bind.scan(data)
        with self.assertRaises(ValueError):
            bind.direct_target(call['site'], b'\x90' + raw[1:])


if __name__ == '__main__':
    unittest.main()
