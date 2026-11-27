"""Verification and negative controls for RE-002-node115-thinlto-wave2-census."""
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-node115-thinlto-wave2-census'
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress  # noqa: E402


def _load():
    spec = importlib.util.spec_from_file_location('thinlto_w2_census_115', PACKET / 'census.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ThinLtoWave2Census115Tests(unittest.TestCase):
    def setUp(self):
        self.mod = _load()
        self.census = json.loads((PACKET / 'census.json').read_text())
        self.components = json.loads((ROOT / 'research/components.json').read_text())['components']

    def test_packet_verifies_against_node115_and_manifest(self):
        self.mod.verify()
        lines = [l.strip() for l in (PACKET / 'MANIFEST.sha256').read_text().splitlines() if l.strip()]
        self.assertGreaterEqual(len(lines), 10)
        for line in lines:
            digest, rel = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((PACKET / rel).read_bytes()).hexdigest(), digest, rel)

    def test_windows_registered_strictly_as_dependencies(self):
        cov = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', self.components)
        rows = [r for r in cov['windows'] if r['id'].startswith('node115-w2-thinlto-')]
        self.assertEqual((len(rows), sum(r['bytes'] for r in rows)), (869, 583475))
        self.assertEqual(sum(int(r['raw_equal']) for r in rows), 30)
        self.assertTrue(all(r['relocation_qualified'] for r in rows))
        self.assertEqual(
            {r.get('dependency') for r in rows},
            {'vendored-crates', 'rust-std', 'rust-core', 'rust-alloc'},
        )
        self.assertTrue(all(r['component'] == 'foundation' for r in rows))
        other = [(r['start'], r['end']) for r in cov['windows'] if not r['id'].startswith('node115-w2-thinlto-')]
        for r in rows:
            for a, b in other:
                self.assertTrue(r['end'] <= a or r['start'] >= b, hex(r['start']))

    def test_defining_crate_and_license_gates(self):
        licenses = json.loads((PACKET / 'licenses.json').read_text())
        self.assertEqual(set(licenses.keys()), set(self.census['lock_packages'].keys()))
        for rec in self.census['records']:
            self.assertFalse(rec['native'])
            self.assertGreaterEqual(rec['end'] - rec['start'], 32)
            self.assertNotIn('thinlto_sv', rec['symbol'])
            self.assertNotIn('thinlto_w2', rec['symbol'])
            self.assertEqual(
                self.mod.extract_defining_crate_ident(rec['symbol']),
                rec['crate'].replace('-', '_'),
            )
        self.assertIsNone(self.mod.extract_defining_crate_ident('_ZN11thinlto_w2a4main17h0123456789abcdefE'))
        self.assertEqual(self.mod.extract_defining_crate_ident('_ZN6ark_ff6fields4test17h0123456789abcdefE'), 'ark_ff')

    def test_negative_control_byte_mutation(self):
        bodies = (PACKET / 'bodies.bin').read_bytes()
        rec = self.census['records'][0]
        n = rec['end'] - rec['start']
        src = bodies[rec['source_offset']:rec['source_offset'] + n]
        masked = set()
        for rel in rec['relocations']:
            masked.update(range(rel['offset'], rel['offset'] + rel['width']))
        i = next(k for k in range(n) if k not in masked)
        mut = bytearray(src)
        mut[i] ^= 0xff
        self.assertFalse(byte_progress.compare(bytes(mut), src, rec['relocations'])['relocation_qualified'])


if __name__ == '__main__':
    unittest.main()
