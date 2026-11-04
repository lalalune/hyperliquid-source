"""Static certificate and independently selected traversal examples for node #115."""
import hashlib
import json
import mmap
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from tools import node115_tree_key_search as bind

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-tree-key-search'

class TreeKeySearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = bind.TARGET.open('rb')
        cls.data = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.record = json.loads((PACKET / 'records.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.stream.close()

    def test_authenticated_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            for name in ('README.md', 'verify.py'):
                shutil.copyfile(PACKET / name, out / name)
            subprocess.run([sys.executable, str(ROOT / 'tools/node115_tree_key_search.py'), '--out', str(out)], check=True)
            for name in ('README.md', 'verify.py', 'records.json', 'MANIFEST.sha256'):
                self.assertEqual((out / name).read_bytes(), (PACKET / name).read_bytes(), name)
            subprocess.run([sys.executable, str(out / 'verify.py')], check=True)
            (out / 'extra').write_text('unexpected')
            self.assertNotEqual(subprocess.run([sys.executable, str(out / 'verify.py')], capture_output=True).returncode, 0)

    def test_identity_corruption(self):
        with self.assertRaises(ValueError):
            bind.authenticate(b'wrong release')
        index = bind.START - 0x1000
        original = self.data[index]
        try:
            self.data[index] ^= 1
            with self.assertRaises(ValueError):
                bind.authenticate(self.data)
        finally:
            self.data[index] = original

    def test_window_corruption_and_branch_redirection(self):
        body = bytearray(self.data[bind.START-0x1000:bind.END-0x1000])
        self.assertEqual(len(bind.decode(body)), len(self.record['instructions']))
        for offset in (0, 0x3e, 0x69, 0x7a):
            corrupt = body.copy()
            corrupt[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                bind.decode(corrupt)

    def test_fde_and_cie_corruption(self):
        frame = bytearray(self.data[bind.FDE:bind.FDE+20])
        cie = bytearray(self.data[bind.CIE:bind.CIE+24])
        bind.check_frame(frame, cie)
        for index in (4, 8, 12, 16):
            corrupt = frame.copy()
            corrupt[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                bind.check_frame(corrupt, cie)
        cie[16] ^= 1
        with self.assertRaises(ValueError):
            bind.check_frame(frame, cie)

    def test_caller_target_and_full_census(self):
        hits = bind.direct_hits(self.data)
        self.assertEqual(hits, self.record['direct_rel32_scan']['hits'])
        for hit in hits:
            site = int(hit['site'], 16)
            code = bytearray.fromhex(hit['bytes'])
            self.assertEqual(bind.rel32_target(site, code), bind.START)
            code[1] ^= 1
            self.assertNotEqual(bind.rel32_target(site, code), bind.START)
            code[0] = 0x90
            with self.assertRaises(ValueError):
                bind.rel32_target(site, code)
        self.assertEqual(self.record['callees'], [])
        index = 0x28d37b2 - 0x1000 + 1
        old = self.data[index]
        try:
            self.data[index] ^= 1
            with self.assertRaises(ValueError):
                bind.check_callers(bind.direct_hits(self.data))
        finally:
            self.data[index] = old

    def test_target_grounded_vectors(self):
        # Keys in the root partition three children; zero-depth must not descend.
        nodes = {0x1000: ([10, 20], [0x2000, 0x3000, 0x4000]),
                 0x2000: ([0, 9], []), 0x3000: ([11, 19], []),
                 0x4000: ([21, (1 << 64) - 1], [])}
        cases = [(0, 0, 10, 0), (0x1000, 0, 10, 0x1064),
                 (0x1000, 0, 15, 0), (0x1000, 1, 0, 0x2064),
                 (0x1000, 1, 9, 0x2064), (0x1000, 1, 11, 0x3064),
                 (0x1000, 1, 19, 0x3064), (0x1000, 1, 20, 0x1064),
                 (0x1000, 1, 21, 0x4064),
                 (0x1000, 1, (1 << 64) - 1, 0x4064),
                 (0x1000, 1, 12, 0)]
        for root, depth, key, expected in cases:
            with self.subTest(root=root, depth=depth, key=key):
                self.assertEqual(bind.search(root, depth, key, nodes), expected)
        self.assertEqual(bind.search(0x5000, 0, 42, {0x5000: ([], [])}), 0)

    def test_readme_counts_match_records(self):
        readme = (PACKET / 'README.md').read_text()
        record = self.record
        self.assertIn(f"({record['window']['size']} bytes;", readme)
        self.assertIn(f"{len(bytes.fromhex(record['window']['padding']['bytes']))} bytes of `cc` padding", readme)
        for value, label in ((len(record['instructions']), 'instructions'),
                             (len(record['callees']), 'callees'),
                             (len(record['direct_rel32_scan']['hits']), 'candidate direct rel32 sites')):
            self.assertIn(f'**{value} {label}**', readme)
        self.assertIn(f"a {record['window']['size']}-byte range", readme)
        self.assertIn(record['window']['sha256'], readme)
        for frame in record['direct_rel32_scan']['caller_fdes']:
            self.assertIn(frame['start'] + '..' + frame['end'], readme)
        self.assertIn(record['caller_source_association']['path'] + ':' + str(record['caller_source_association']['line']) + ':' + str(record['caller_source_association']['column']), readme)

    def test_packet_verifier_rejects_hash_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            for path in PACKET.iterdir():
                shutil.copyfile(path, out / path.name)
            (out / 'records.json').write_text('{}\n')
            self.assertNotEqual(subprocess.run([sys.executable, str(out / 'verify.py')], capture_output=True).returncode, 0)

if __name__ == '__main__':
    unittest.main()
