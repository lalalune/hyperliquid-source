"""Actual helper/caller bindings, corruption controls and scoped format interpretation."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import unique_value_static as unique


@unittest.skipUnless(unique.TARGET.stat().st_size == 91774280, 'materialize node94')
class UniqueValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = unique.TARGET.read_bytes()
        cls.report = unique.analyze(cls.data)

    def test_actual_specialization_and_tags(self):
        self.assertEqual([r['bytes'] for r in self.report['ranges']], [1084, 944])
        self.assertEqual((self.report['filter_bytes'], self.report['value_bytes']), (20, 32))
        self.assertEqual(set(self.report['return_tags'].values()), {'0x97', '0x2a', '0x186'})
        self.assertEqual(self.report['source']['line'], 132)
        self.assertFalse(self.report['captured_binary_executed'])

    def test_all_filter_bytes_contribute_to_mask_predicate(self):
        # Exhaust all 2^20 byte-equality patterns for the decoded mask reduction.
        # This is an architectural boolean proof, not execution of the target.
        for pattern in range(1 << 20):
            first16 = pattern & 0xffff
            last4_zero_extended_comparison = (pattern >> 16) | 0xfff0
            reduced = first16 & last4_zero_extended_comparison
            if (reduced == 0xffff) != (pattern == (1 << 20) - 1):
                self.fail('SSE mask predicate omitted a filter byte')

    def test_compact_descriptor_does_not_treat_length_as_punctuation(self):
        parts = self.report['diagnostic']['scoped_parts']
        self.assertEqual(parts[0]['literal'], 'ChamIterator::unique_elem: not unique elems: [')
        self.assertEqual([p['literal'] for p in parts if 'literal' in p],
                         ['ChamIterator::unique_elem: not unique elems: [', ', ', ', ...]'])
        self.assertEqual(sum('placeholder' in p for p in parts), 2)
        for malformed in [b'\x03ab', b'\xc1\0', b'\x01x', b'\0x']:
            with self.assertRaises(ValueError):
                unique.descriptor_parts(malformed)

    def test_actual_filter_payload_gate_and_source_changes_are_rejected(self):
        for va in [0x33690d5, 0x3369377, 0x3369388, 0x336939b, 0x33693a6,
                   0x33693df, 0x3369427, 0x336942d, 0x3369446, 0x3369464,
                   0x336949a, 0x336a54f, 0x1ed4ee, 0x56e9e48, 0x1ebfb7]:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                off, _ = unique.read(changed, va, 1)
                changed[off] ^= 1
                with self.assertRaises(ValueError):
                    unique.analyze(changed)

    @unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'), 'GNU binutils required')
    def test_native_regeneration_preserves_packet(self):
        packet = ROOT / 'research/work-items/RE-001-unique-value-helper-94'
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.assertEqual(unique.generate(unique.TARGET, out), self.report)
            for name in ['records.json', 'frames.txt', '33690c0.objdump.txt', '336a4e0.objdump.txt']:
                self.assertEqual((out / name).read_bytes(), (packet / name).read_bytes(), name)


if __name__ == '__main__':
    unittest.main()
