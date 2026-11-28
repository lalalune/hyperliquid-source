"""Verification and negative controls for RE-002-node115-serde-monomorph-wave2-census."""
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-node115-serde-monomorph-wave2-census'
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress  # noqa: E402


def _load():
    spec = importlib.util.spec_from_file_location('serde_mono_w2_census_115', PACKET / 'census.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SerdeMonomorphWave2Census115Tests(unittest.TestCase):
    def setUp(self):
        self.mod = _load()
        self.census = json.loads((PACKET / 'census.json').read_text())
        self.components = json.loads((ROOT / 'research/components.json').read_text())['components']

    def test_packet_verifies_and_manifest(self):
        self.mod.verify()
        lines = [l for l in (PACKET / 'MANIFEST.sha256').read_text().splitlines() if l.strip()]
        self.assertGreaterEqual(len(lines), 15)
        for line in lines:
            digest, rel = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((PACKET / rel).read_bytes()).hexdigest(), digest, rel)

    def test_disjoint_from_registry_and_peers(self):
        bw = json.loads((ROOT / 'research/byte-windows.json').read_text())
        other = [
            (w['start'], w['end'])
            for w in bw['windows']
            if w['target'] == 'node115' and not w['id'].startswith('node115-serde-mono2-')
        ]
        other.extend(self.mod.collect_peer_intervals())
        merged, starts = self.mod._build_merged(other)
        for rec in self.census['records']:
            self.assertFalse(
                self.mod._overlaps(merged, starts, rec['start'], rec['end']),
                f"overlap at {hex(rec['start'])}",
            )
        reg_rows = [w for w in bw['windows'] if w['id'].startswith('node115-serde-mono2-')]
        if reg_rows:
            cov = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', self.components)
            rows = [r for r in cov['windows'] if r['id'].startswith('node115-serde-mono2-')]
            self.assertEqual(
                (len(rows), sum(r['bytes'] for r in rows)),
                (self.census['summary']['total_windows'], self.census['summary']['total_bytes']),
            )
            self.assertTrue(all('dependency' in r for r in rows))
            self.assertTrue(all(r['relocation_qualified'] for r in rows))

    def test_negative_controls_reject_drop_glue_harness_mutation_and_wrong_slice(self):
        self.assertFalse(self.mod.is_allowed_serde_json_symbol('_ZN4core3ptr13drop_in_place17h0000000000000000E'))
        self.assertFalse(self.mod.is_allowed_serde_json_symbol('_ZN13hl_mono_w2_e04main17h0000000000000000E'))
        data = (ROOT / self.mod.TARGET).read_bytes()
        _, rodata, datarelro, rel_map = self.mod.load_node115_sections_and_rela(data)
        bodies = (PACKET / 'bodies.bin').read_bytes()
        rec = self.census['records'][0]
        n = rec['end'] - rec['start']
        src = bodies[rec['source_offset']:rec['source_offset'] + n]
        masked = set()
        for r in rec['relocations']:
            masked.update(range(r['offset'], r['offset'] + r['width']))
        i = next(k for k in range(n) if k not in masked)
        mut = bytearray(src)
        mut[i] ^= 0xff
        self.assertFalse(byte_progress.compare(bytes(mut), src, rec['relocations'])['relocation_qualified'])
        self.assertFalse(
            self.mod.verify_slice_table_at(
                data, rodata, datarelro, rel_map, rec['table_va'], ['__wrong_variant__', '__wrong_2__']
            )
        )


if __name__ == '__main__':
    unittest.main()
