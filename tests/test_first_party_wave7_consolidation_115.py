"""Verification and negative controls for RE-001-node115-first-party-wave7-consolidation."""
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-first-party-wave7-consolidation'
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress  # noqa: E402


def _load():
    spec = importlib.util.spec_from_file_location('fp_w7_consol_115', PACKET / 'consolidate.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FirstPartyWave7Consolidation115Tests(unittest.TestCase):
    def setUp(self):
        self.mod = _load()
        self.census = json.loads((PACKET / 'census.json').read_text())
        self.components = json.loads((ROOT / 'research/components.json').read_text())['components']

    def test_packet_verifies_and_manifest(self):
        self.mod.verify()
        lines = [l for l in (PACKET / 'MANIFEST.sha256').read_text().splitlines() if l.strip()]
        self.assertEqual(len(lines), 4)
        for line in lines:
            digest, rel = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((PACKET / rel).read_bytes()).hexdigest(), digest, rel)

    def test_registered_as_first_party_windows_with_no_overlap(self):
        bw = json.loads((ROOT / 'research/byte-windows.json').read_text())
        other = [
            (w['start'], w['end'])
            for w in bw['windows']
            if w['target'] == 'node115' and not w['id'].startswith('node115-fp-w7-')
        ]
        for rec in self.census['records']:
            self.assertFalse(
                any(not (rec['end'] <= a or rec['start'] >= b) for a, b in other),
                f"overlap with byte-windows.json at {hex(rec['start'])}",
            )
        reg_rows = [w for w in bw['windows'] if w['id'].startswith('node115-fp-w7-')]
        if reg_rows:
            cov = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', self.components)
            rows = [r for r in cov['windows'] if r['id'].startswith('node115-fp-w7-')]
            self.assertEqual(
                (len(rows), sum(r['bytes'] for r in rows)),
                (self.census['summary']['total_windows'], self.census['summary']['total_bytes']),
            )
            self.assertTrue(all('dependency' not in r for r in rows))
            self.assertTrue(all(r['relocation_qualified'] for r in rows))

    def test_negative_control_rejects_unmasked_mutation(self):
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


if __name__ == '__main__':
    unittest.main()
