"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_mixed_width_dual_table_lookup as mixed_width
from elf_index import sections


class MixedWidthDualTableLookupEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not mixed_width.TARGET.is_file() or mixed_width.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = mixed_width.inspect(mixed_width.TARGET)
        cls.data = mixed_width.TARGET.read_bytes()
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
        self.assertEqual(self.result['window'], (0x29d7fc0, 0x29d7fde))
        self.assertEqual(self.result['body_sha256'],
                         'c320ebc941f7dd2a2d48945e9a8dc8117bb63f8670974da35444c70187be366e')
        self.assertEqual(self.result['relocation_slots'], [])
        self.assertEqual(self.result['direct_callers'], [0x29d81b4])
        self.assertEqual(self.result['u64_head'], [6, 14, 15, 15, 13, 32, 28, 28])
        self.assertEqual(self.result['i32_head'],
                         [-3447, -3441, -3427, -3412, -3397, -2058120, -3384, -3356])

    def test_body_lock(self):
        bad = self.mutated(0x29d7fc0, b'\x90')
        with self.assertRaises(ValueError):
            mixed_width.analyze(bad)

    def test_u64_lea_lock(self):
        # u64-table lea displacement at offset 3: flipping it breaks the target.
        bad = self.mutated(0x29d7fc0 + 3, b'\x00')
        with self.assertRaises(ValueError):
            mixed_width.analyze(bad)

    def test_i32_lea_lock(self):
        # i32-table lea displacement at offset 18: flipping it breaks the target.
        bad = self.mutated(0x29d7fc0 + 18, b'\x00')
        with self.assertRaises(ValueError):
            mixed_width.analyze(bad)

    def test_index_extend_lock(self):
        # movzbl at offset 7: replacing it changes the index rule.
        bad = self.mutated(0x29d7fc0 + 7, b'\x90')
        with self.assertRaises(ValueError):
            mixed_width.analyze(bad)

    def test_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0xc52e4 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            mixed_width.analyze(bytes(bad))

    def test_next_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0xc52f8 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            mixed_width.analyze(bytes(bad))

    def test_padding_lock(self):
        bad = self.mutated(0x29d7fde, b'\x90')
        with self.assertRaises(ValueError):
            mixed_width.analyze(bad)

    def test_caller_lock(self):
        # Flipping a caller call target must change the incoming-call list.
        bad = self.mutated(0x29d81b4 + 1, b'\x01')
        with self.assertRaises(ValueError):
            mixed_width.analyze(bad)

    def test_caller_setup_lock(self):
        # Flipping the call-path edi load must fail the setup check.
        bad = self.mutated(0x29d81ad, b'\x90')
        with self.assertRaises(ValueError):
            mixed_width.analyze(bad)

    def test_lookup_rule_edges(self):
        u64 = [6, 14, 15, 15, 13, 32, 28, 28]
        i32 = [-3447, -3441, -3427, -3412, -3397, -2058120, -3384, -3356]
        self.assertEqual(mixed_width.lookup(u64, i32, 0), (0x4019b1, 6))
        self.assertEqual(mixed_width.lookup(u64, i32, 3), (0x4019d4, 15))
        self.assertEqual(mixed_width.lookup(u64, i32, 5), (0x20bfa0, 32))
        with self.assertRaises(ValueError):
            mixed_width.lookup([6], [-3447], 0x100)

    def test_retained_json_matches(self):
        root = Path(__file__).resolve().parents[1]
        retained = json.loads((root / 'research/work-items'
                               / 'foundation-mixed-width-dual-table-lookup-94'
                               / 'evidence.json').read_text())
        self.assertEqual(retained['function']['sha256'],
                         self.result['body_sha256'])
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(c) for c in self.result['direct_callers']])
        self.assertEqual(retained['tables']['u64_first8'],
                         self.result['u64_head'])
        self.assertEqual(retained['tables']['i32_first8'],
                         self.result['i32_head'])


if __name__ == '__main__':
    unittest.main()
