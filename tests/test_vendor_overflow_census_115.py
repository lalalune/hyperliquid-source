"""Verification and negative controls for RE-002-node115-vendor-overflow-census."""
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-node115-vendor-overflow-census'
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress  # noqa: E402


def _load_census_mod():
    spec = importlib.util.spec_from_file_location('vendor_ovf_census_115', PACKET / 'census.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class VendorOverflowCensus115Tests(unittest.TestCase):
    def setUp(self):
        self.mod = _load_census_mod()
        self.census = json.loads((PACKET / 'census.json').read_text())
        self.components = json.loads((ROOT / 'research/components.json').read_text())['components']

    def test_packet_verifies_against_node115_and_manifest(self):
        self.mod.verify()
        manifest_lines = [
            line.strip()
            for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines()
            if line.strip()
        ]
        self.assertGreaterEqual(len(manifest_lines), 8)
        for line in manifest_lines:
            digest, rel_path = line.split('  ', 1)
            actual = hashlib.sha256((PACKET / rel_path).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, f'digest mismatch for {rel_path}')

    def test_windows_registered_strictly_as_vendored_crates_dependencies(self):
        coverage = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', self.components)
        rows = [r for r in coverage['windows'] if r['id'].startswith('node115-ovf-vendor-')]
        self.assertEqual(len(rows), 237)
        self.assertEqual(sum(r['bytes'] for r in rows), 183902)
        self.assertEqual(sum(int(r['raw_equal']) for r in rows), 8)
        self.assertTrue(all(r['relocation_qualified'] for r in rows))
        self.assertTrue(all(r.get('dependency') == 'vendored-crates' for r in rows))
        self.assertTrue(all(r['component'] == 'foundation' for r in rows))
        # Must never award first-party credit or overlap other node115 windows.
        other = [(r['start'], r['end']) for r in coverage['windows'] if not r['id'].startswith('node115-ovf-vendor-')]
        for r in rows:
            for a, b in other:
                self.assertTrue(r['end'] <= a or r['start'] >= b, f"overlap at {hex(r['start'])}")

    def test_own_crate_and_license_gates(self):
        licenses = json.loads((PACKET / 'licenses.json').read_text())
        self.assertEqual(set(licenses.keys()), set(self.census['lock_packages'].keys()))
        for rec in self.census['records']:
            self.assertFalse(rec['native'])
            self.assertTrue(self.mod.own_crate_symbol(rec['crate'], rec['symbol']))
            self.assertGreaterEqual(rec['end'] - rec['start'], 32)
        # Negative controls on own_crate_symbol filter.
        self.assertFalse(self.mod.own_crate_symbol('revm-precompile', '_ZN4k25610arithmetic4test17h0123456789abcdefE'))
        self.assertFalse(self.mod.own_crate_symbol('tokio', '_ZN4core3ptr13drop_in_place17h0123456789abcdefE'))
        self.assertTrue(self.mod.own_crate_symbol('revm-precompile', '_ZN15revm_precompile3sec17h0123456789abcdefE'))

    def test_negative_control_byte_mutation_breaks_qualification(self):
        bodies = (PACKET / 'bodies.bin').read_bytes()
        rec = self.census['records'][0]
        n = rec['end'] - rec['start']
        src = bodies[rec['source_offset']:rec['source_offset'] + n]
        masked = set()
        for rel in rec['relocations']:
            masked.update(range(rel['offset'], rel['offset'] + rel['width']))
        unmasked_idx = next(i for i in range(n) if i not in masked)
        mutated = bytearray(src)
        mutated[unmasked_idx] ^= 0xff
        res = byte_progress.compare(bytes(mutated), src, rec['relocations'])
        self.assertFalse(res['relocation_qualified'])


if __name__ == '__main__':
    unittest.main()
