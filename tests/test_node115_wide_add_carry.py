"""Static controls for the node #115 four-limb arithmetic certificate."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_wide_add_carry as subject

PACKET = ROOT / 'research/work-items/RE-001-node115-wide-add-carry'


class WideAddCarry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.record = subject.inspect(cls.data)

    def test_regeneration(self):
        encoded = json.dumps(self.record, indent=2) + '\n'
        self.assertEqual(encoded, (PACKET / 'records.json').read_text())
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.SHA)

    def test_model_boundary_vectors(self):
        m = 1 << 256
        vectors = [(0, 0, 0, 0), (m - 1, 1, 0, 1),
                   (m - 1, m - 1, m - 2, 1),
                   ((1 << 64) - 1, 1, 1 << 64, 0),
                   ((1 << 192) - 1, 1, 1 << 192, 0),
                   (1 << 255, 1 << 255, 0, 1)]
        for a, b, low, carry in vectors:
            with self.subTest(a=a, b=b):
                self.assertEqual(subject.model(a, b), (low, carry))
        for a, b in [(-1, 0), (0, m)]:
            with self.assertRaises(ValueError):
                subject.model(a, b)

    def test_wrong_digest_fails_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'bad'
            binary.write_bytes(b'not node 115')
            out = Path(tmp) / 'out'
            proc = subprocess.run([sys.executable, str(ROOT / 'tools/node115_wide_add_carry.py'),
                                   '--binary', str(binary), '--out', str(out)],
                                  capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('digest mismatch', proc.stderr)
            self.assertFalse(out.exists())

    def test_actual_body_mutation(self):
        data = bytearray(self.data)
        data[self.record['function']['file_offset'] + 2] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.inspect(data)
        with self.assertRaisesRegex(ValueError, 'body hash'):
            subject.inspect(data, authenticate=False)

    def test_shifted_fde(self):
        data = bytearray(self.data)
        data[0xd78358] ^= 1
        with self.assertRaisesRegex(ValueError, 'FDE'):
            subject.inspect(data, authenticate=False)

    def test_retargeted_call(self):
        data = bytearray(self.data)
        text_offset = 0x2a1e7b7 - 0x1000
        data[text_offset + 1] ^= 1
        with self.assertRaisesRegex(ValueError, 'census'):
            subject.inspect(data, authenticate=False)

    def test_instruction_decoder_rejects_changes(self):
        off = self.record['function']['file_offset']
        body = bytearray(self.data[off:off + self.record['function']['size']])
        for position in (0, 4, 13, 45, 48):
            mutant = body.copy()
            mutant[position] ^= 1
            with self.subTest(position=position), self.assertRaises(ValueError):
                subject.decode(mutant)
        with self.assertRaises(ValueError):
            subject.decode(body + b'\x90')

    def test_readme_counts(self):
        readme = (PACKET / 'README.md').read_text()
        line = next(line for line in readme.splitlines() if line.startswith('Counts:'))
        counts = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', line)}
        fn, census = self.record['function'], self.record['caller_census']
        self.assertEqual(counts, {'window_bytes': fn['size'], 'instructions': len(fn['instructions']),
                                  'padding_bytes': len(bytes.fromhex(fn['padding_bytes'])),
                                  'direct_callees': fn['callee_count'],
                                  'rel32_candidates': census['candidate_count'],
                                  'confirmed_direct_calls': census['confirmed_direct_calls']})


if __name__ == '__main__':
    unittest.main()
