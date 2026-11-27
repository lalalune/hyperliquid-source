"""Verification and negative controls for RE-001-node115-first-party-serde-thinlto-census."""
import copy
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-first-party-serde-thinlto-census'
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress  # noqa: E402


def _load():
    spec = importlib.util.spec_from_file_location('fp_serde_census_115', PACKET / 'census.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FirstPartySerdeThinLtoCensus115Tests(unittest.TestCase):
    def setUp(self):
        self.mod = _load()
        self.census = json.loads((PACKET / 'census.json').read_text())
        self.components = json.loads((ROOT / 'research/components.json').read_text())['components']

    def test_packet_verifies_and_manifest(self):
        self.mod.verify()
        lines = [l for l in (PACKET / 'MANIFEST.sha256').read_text().splitlines() if l.strip()]
        self.assertGreaterEqual(len(lines), 7)
        for line in lines:
            digest, rel = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((PACKET / rel).read_bytes()).hexdigest(), digest, rel)

    def test_registry_rows_are_first_party_and_disjoint(self):
        cov = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', self.components)
        rows = [r for r in cov['windows'] if r['id'].startswith('node115-fp-serde-')]
        self.assertEqual((len(rows), sum(r['bytes'] for r in rows)), (162, 166298))
        self.assertTrue(all('dependency' not in r for r in rows))
        self.assertTrue(all(r['relocation_qualified'] for r in rows))
        other = sorted((r['start'], r['end']) for r in cov['windows'] if not r['id'].startswith('node115-fp-serde-'))
        for r in rows:
            for a, b in other:
                self.assertTrue(r['end'] <= a or r['start'] >= b, hex(r['start']))

    def test_third_party_families_never_admitted(self):
        banned = {'fromBlock', 'MovePrecompileToAddress', 'cellProofs', 'requireCanonical', 'Eip7702', 'OutOfGas'}
        for rec in self.census['records']:
            self.assertFalse(banned & set(rec['strings']), rec['label'])

    def test_negative_control_wrong_string_table_rejected(self):
        data = (ROOT / self.mod.TARGET).read_bytes()
        _, rodata, datarelro, rel_map = self.mod.load_node115_sections_and_rela(data)
        rec = self.census['records'][0]
        self.assertTrue(self.mod.verify_slice_table_at(data, rodata, datarelro, rel_map, rec['table_va'], rec['strings']))
        mutated = copy.deepcopy(rec['strings'])
        mutated[0] = mutated[0] + 'X'
        self.assertFalse(self.mod.verify_slice_table_at(data, rodata, datarelro, rel_map, rec['table_va'], mutated))
        self.assertFalse(self.mod.verify_slice_table_at(data, rodata, datarelro, rel_map, rec['table_va'], list(reversed(rec['strings']))) and len(set(rec['strings'])) > 1)

    def test_negative_control_byte_mutation(self):
        bodies = (PACKET / 'bodies.bin').read_bytes()
        rec = self.census['records'][0]
        src = bodies[rec['source_offset']:rec['source_offset'] + rec['bytes']]
        masked = set()
        for r in rec['relocations']:
            masked.update(range(r['offset'], r['offset'] + 4))
        i = next(k for k in range(len(src)) if k not in masked)
        mut = bytearray(src)
        mut[i] ^= 0xff
        self.assertFalse(byte_progress.compare(bytes(mut), src, rec['relocations'])['relocation_qualified'])


if __name__ == '__main__':
    unittest.main()
