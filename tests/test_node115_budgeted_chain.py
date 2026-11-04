"""Target-grounded static controls for the bounded chain leaf."""
import importlib.util
import json
import mmap
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
path = ROOT/'tools/node115_budgeted_chain.py'
spec = importlib.util.spec_from_file_location('budgeted_chain', path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
PACKET = m.PACKET


class BudgetedChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((PACKET/'records.json').read_text())
        cls.body = bytes.fromhex(cls.record['window']['body_hex'])
        cls.fde = bytes.fromhex(cls.record['window']['frame']['fde_bytes'])
        cls.cie = bytes.fromhex(cls.record['window']['frame']['cie_bytes'])

    def test_regeneration(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d)/'packet'
            m.generate(m.TARGET, dest)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((dest/name).read_bytes(), (PACKET/name).read_bytes())

    def test_wrong_digest_and_no_output(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d)/'bad'
            shutil.copyfile(m.TARGET, bad)
            with bad.open('r+b') as f:
                f.seek(m.START - 0x1000)
                byte = f.read(1)
                f.seek(m.START - 0x1000)
                f.write(bytes([byte[0] ^ 1]))
            dest = Path(d)/'out'
            with self.assertRaisesRegex(ValueError, 'digest'):
                m.generate(bad, dest)
            self.assertFalse(dest.exists())

    def test_mutated_body_rejected(self):
        bad = bytearray(self.body)
        bad[4] ^= 1
        with self.assertRaises(ValueError):
            m.decode(bad)
        with self.assertRaises(ValueError):
            m.decode(self.body[:-1])

    def test_shifted_fde_rejected(self):
        bad = bytearray(self.fde)
        bad[8] ^= 1
        with self.assertRaises(ValueError):
            m.frame(bad, self.cie)

    def test_wrong_callee_target_rejected(self):
        ref = self.record['direct_rel32_candidates'][0]
        ins = bytearray.fromhex(ref['bytes'])
        m.check_call(ref['site'], ins)
        ins[1] ^= 1
        with self.assertRaises(ValueError):
            m.check_call(ref['site'], ins)

    def test_boundary_rules(self):
        nodes = {10: (0, 20), 20: (0, 30), 30: (65535, 40), 40: (0, 40)}
        self.assertEqual(m.model(nodes, 10, 0), (1, 10, 0, 0))
        self.assertEqual(m.model(nodes, 10, 1), (1, 20, 0, 0))
        self.assertEqual(m.model(nodes, 10, 2), (0, 30, 0, 0))
        self.assertEqual(m.model(nodes, 10, 3), (0, 30, 1, 0))
        self.assertEqual(m.model(nodes, 30, 0), (0, 30, 0, 0))
        self.assertEqual(m.model(nodes, 40, 7), (1, 40, 0, 0))
        with self.assertRaises(ValueError):
            m.model(nodes, 10, -1)

    def test_readme_counts_match_json(self):
        r = self.record
        text = (PACKET/'README.md').read_text()
        for phrase in (f"**{r['window']['size']} bytes**",
                       f"**{len(r['instructions'])} instructions**",
                       f"**{len(bytes.fromhex(r['window']['padding_hex']))} padding bytes**",
                       f"**{len(r['callees'])} callees**",
                       f"**{len(r['direct_rel32_candidates'])} direct-reference candidate**",
                       f"({r['target']['size']:,} bytes)"):
            self.assertIn(phrase, text)
        self.assertIn(r['window']['body_sha256'], text)
        self.assertEqual(len([x for x in r['instructions'] if x['operation'] == 'ret']), 2)
        self.assertEqual(len([x for x in r['instructions'] if x['operation'].startswith(('jne ', 'je '))]), 3)
        self.assertEqual(r['rule']['output_size'], 32)
        self.assertEqual(r['window']['size'], r['window']['end']-r['window']['start'])
        self.assertEqual(sum(len(bytes.fromhex(i['bytes'])) for i in r['instructions']), r['window']['size'])

    def test_caller_context_corruption(self):
        raw = bytearray.fromhex(self.record['caller_context']['bytes'])
        self.assertEqual(m.decode_context(raw), self.record['caller_context']['instructions'])
        raw[9] ^= 1
        with self.assertRaises(ValueError):
            m.decode_context(raw)

    def test_frame_and_exact_decode(self):
        self.assertEqual(len(m.decode(self.body)), len(self.record['instructions']))
        self.assertEqual(m.frame(self.fde, self.cie), self.record['window']['frame'])


if __name__ == '__main__':
    unittest.main()
