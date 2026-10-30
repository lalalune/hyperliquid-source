"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_dual_table_lookup as dual_table_lookup
from elf_index import sections


class DualTableLookupEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not dual_table_lookup.TARGET.is_file() or dual_table_lookup.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = dual_table_lookup.inspect(dual_table_lookup.TARGET)
        cls.data = dual_table_lookup.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_identity_and_window(self):
        self.assertEqual(self.result['window'], (0x299e280, 0x299e29e))
        self.assertEqual(self.result['body_sha256'],
                         '12cc054b8ba7fff33c6fa92be4d12c323f674f991536fb37cb7b358229447cf1')
        self.assertEqual(self.result['relocation_slots'], [])
        self.assertEqual(self.result['direct_callers'],
                         [0x16511cc, 0x1651487, 0x167a6d5, 0x167a745, 0x167a8f6,
                          0x168214d])
        self.assertEqual(self.result['u64_head'], [6, 14, 15, 15])
        self.assertEqual(self.result['i32_head'], [-1664, -1658, -1644, -1629])

    def test_body_lock(self):
        bad = self.mutated(0x299e280, b'\x90')
        with self.assertRaises(ValueError):
            dual_table_lookup.analyze(bad)

    def test_u64_lea_lock(self):
        # u64-table lea displacement at offset 3: flipping it breaks the target.
        bad = self.mutated(0x299e280 + 3, b'\x00')
        with self.assertRaises(ValueError):
            dual_table_lookup.analyze(bad)

    def test_i32_lea_lock(self):
        # i32-table lea displacement at offset 18: flipping it breaks the target.
        bad = self.mutated(0x299e280 + 18, b'\x00')
        with self.assertRaises(ValueError):
            dual_table_lookup.analyze(bad)

    def test_index_extend_lock(self):
        # movzbl at offset 7: replacing it changes the index rule.
        bad = self.mutated(0x299e280 + 7, b'\x90')
        with self.assertRaises(ValueError):
            dual_table_lookup.analyze(bad)

    def test_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0xc2280 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            dual_table_lookup.analyze(bytes(bad))

    def test_next_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0xc2294 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            dual_table_lookup.analyze(bytes(bad))

    def test_padding_lock(self):
        bad = self.mutated(0x299e29e, b'\x90')
        with self.assertRaises(ValueError):
            dual_table_lookup.analyze(bad)

    def test_caller_lock(self):
        # Flipping a caller call target must change the incoming-call list.
        bad = self.mutated(0x16511cc + 1, b'\x01')
        with self.assertRaises(ValueError):
            dual_table_lookup.analyze(bad)

    def test_lookup_rule_edges(self):
        self.assertEqual(
            dual_table_lookup.lookup([6, 14, 15, 15], [-1664, -1658, -1644, -1629], 0),
            (0x3f7520, 6))
        self.assertEqual(
            dual_table_lookup.lookup([6, 14, 15, 15], [-1664, -1658, -1644, -1629], 3),
            (0x3f7543, 15))
        with self.assertRaises(ValueError):
            dual_table_lookup.lookup([6], [-1664], 0x100)

    def test_retained_json_matches(self):
        root = Path(__file__).resolve().parents[1]
        retained = json.loads((root / 'research/work-items'
                               / 'foundation-dual-table-lookup-94'
                               / 'evidence.json').read_text())
        self.assertEqual(retained['function']['sha256'],
                         self.result['body_sha256'])
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(c) for c in self.result['direct_callers']])
        self.assertEqual(retained['tables']['u64_first4'],
                         self.result['u64_head'])
        self.assertEqual(retained['tables']['i32_first4'],
                         self.result['i32_head'])


if __name__ == '__main__':
    unittest.main()
