"""Independent verification and negative controls for first-party node #115 byte census."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    'fp_byte_census_115',
    ROOT / 'research/work-items/RE-001-node115-first-party-byte-census/census.py',
)
fp_census = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(fp_census)


class FirstPartyByteCensus115Tests(unittest.TestCase):
    def test_committed_packet_verifies_against_authenticated_node115(self):
        result = fp_census.verify_committed(ROOT, rebuild=False)
        totals = result['totals']
        self.assertEqual(totals['windows'], 1008)
        self.assertEqual(totals['relocation_qualified_windows'], 1008)
        self.assertEqual(totals['components'], 23)
        self.assertEqual(totals['bytes'], 138449)
        self.assertEqual(totals['raw_equal_windows'], 6)

    def test_registry_registers_first_party_windows_separately_from_dependencies(self):
        components = json.loads((ROOT / 'research/components.json').read_text())['components']
        coverage = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', components)
        fp_rows = [r for r in coverage['windows'] if 'dependency' not in r]
        dep_rows = [r for r in coverage['windows'] if 'dependency' in r]
        self.assertEqual(len(fp_rows), 3311)
        self.assertTrue(all(r['id'].startswith('node115-fp-') for r in fp_rows))
        self.assertTrue(all(r['relocation_qualified'] for r in fp_rows))
        self.assertEqual(len(dep_rows), 15017)
        self.assertEqual(sum(c['windows'] for c in coverage['components'].values()), 3311)
        self.assertEqual(
            sum(c['bytes'] for c in coverage['components'].values()),
            sum(r['bytes'] for r in fp_rows),
        )

    def test_negative_controls_reject_non_relocation_byte_mutation(self):
        census_data = json.loads(
            (ROOT / 'research/work-items/RE-001-node115-first-party-byte-census/census.json').read_text()
        )
        bodies = (ROOT / 'research/work-items/RE-001-node115-first-party-byte-census/bodies.bin').read_bytes()
        # Pick one zero-relocation raw-equal window and one relocation-qualified window
        raw_rec = next(r for r in census_data['records'] if r['raw_equal'] and not r['relocations'])
        rel_rec = next(r for r in census_data['records'] if r['relocations'])
        for rec in (raw_rec, rel_rec):
            src = bytearray(bodies[rec['source_offset']:rec['source_offset'] + rec['bytes']])
            masked = set()
            for row in rec['relocations']:
                masked.update(range(row['offset'], row['offset'] + row['width']))
            unmasked_idx = next(i for i in range(len(src)) if i not in masked)
            mutated = bytes(src[:unmasked_idx]) + bytes([src[unmasked_idx] ^ 0xff]) + bytes(src[unmasked_idx + 1:])
            cmp = byte_progress.compare(mutated, bytes(src), rec['relocations'])
            self.assertFalse(cmp['relocation_qualified'])
            self.assertIn(unmasked_idx, cmp['non_relocation_difference_offsets'])


if __name__ == '__main__':
    unittest.main()
