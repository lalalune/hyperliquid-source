"""Verification and negative controls for RE-002-node115-thinlto-std-vendor-census."""
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-node115-thinlto-std-vendor-census'
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress  # noqa: E402


def _load_census_mod():
    spec = importlib.util.spec_from_file_location('thinlto_sv_census_115', PACKET / 'census.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ThinLtoStdVendorCensus115Tests(unittest.TestCase):
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
        self.assertGreaterEqual(len(manifest_lines), 10)
        for line in manifest_lines:
            digest, rel_path = line.split('  ', 1)
            actual = hashlib.sha256((PACKET / rel_path).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, f'digest mismatch for {rel_path}')

    def test_windows_registered_strictly_as_dependencies(self):
        coverage = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', self.components)
        rows = [r for r in coverage['windows'] if r['id'].startswith('node115-thinlto-')]
        self.assertEqual(len(rows), 729)
        self.assertEqual(sum(r['bytes'] for r in rows), 536016)
        self.assertEqual(sum(int(r['raw_equal']) for r in rows), 11)
        self.assertTrue(all(r['relocation_qualified'] for r in rows))
        self.assertEqual(
            {r.get('dependency') for r in rows},
            {'vendored-crates', 'rust-std', 'rust-core', 'rust-alloc'},
        )
        self.assertTrue(all(r['component'] == 'foundation' for r in rows))
        other = [(r['start'], r['end']) for r in coverage['windows'] if not r['id'].startswith('node115-thinlto-')]
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
            self.assertNotIn('thinlto_sv', rec['symbol'])
        # Negative controls on own_crate_symbol (legacy and v0 mangling).
        self.assertFalse(self.mod.own_crate_symbol('sysinfo', '_ZN4core5slice4sort17h0123456789abcdefE'))
        self.assertFalse(self.mod.own_crate_symbol('clap', '_ZN5alloc3str7replace17h0123456789abcdefE'))
        self.assertTrue(self.mod.own_crate_symbol('std', '_RNvNtCs123_3std2fs4read'))
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
