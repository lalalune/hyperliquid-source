"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_index_clamp_stride as clamp_stride
from elf_index import sections


class IndexClampStrideEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not clamp_stride.TARGET.is_file() or clamp_stride.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = clamp_stride.inspect(clamp_stride.TARGET)
        cls.data = clamp_stride.TARGET.read_bytes()
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
        self.assertEqual(self.result['window'], (0x2517660, 0x25176d2))
        self.assertEqual(self.result['body_sha256'],
                         '03498aac7c2644baab2ce7d76e131d62319f0ef9c5526c628aecf00d16f63666')
        self.assertEqual(self.result['relocation_slots'], [])
        self.assertEqual(self.result['direct_callers'],
                         [0x228149e, 0x2282484, 0x2285c23, 0x22866e3])

    def test_body_lock(self):
        bad = self.mutated(0x2517660, b'\x90')
        with self.assertRaises(ValueError):
            clamp_stride.analyze(bad)

    def test_count_load_lock(self):
        # Count load at offset 3: replacing it changes the clamp input.
        bad = self.mutated(0x2517660 + 3, b'\x90')
        with self.assertRaises(ValueError):
            clamp_stride.analyze(bad)

    def test_branch_lock(self):
        # Unsigned-above branch at offset 43: replacing it changes the clamp.
        bad = self.mutated(0x2517660 + 43, b'\x90')
        with self.assertRaises(ValueError):
            clamp_stride.analyze(bad)

    def test_stride_lock(self):
        # First stride lea at offset 65: replacing it changes the scale.
        bad = self.mutated(0x2517660 + 65, b'\x90')
        with self.assertRaises(ValueError):
            clamp_stride.analyze(bad)

    def test_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0x85a60 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            clamp_stride.analyze(bytes(bad))

    def test_next_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0x3e68d0 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            clamp_stride.analyze(bytes(bad))

    def test_padding_lock(self):
        bad = self.mutated(0x25176d2, b'\x90')
        with self.assertRaises(ValueError):
            clamp_stride.analyze(bad)

    def test_caller_lock(self):
        # First caller call bytes: replacing them breaks the call target.
        bad = self.mutated(0x228149e, b'\x90')
        with self.assertRaises(ValueError):
            clamp_stride.analyze(bad)

    def test_rule_edges(self):
        m = (1 << 64) - 1
        self.assertEqual(clamp_stride.compute(0, 10, 25, 100), (15, 115, 0))
        self.assertEqual(clamp_stride.compute(0, 10, 5, 100), (5, 10, 95))
        self.assertEqual(clamp_stride.compute(0, 10, 5, 3), (5, 10, m - 1))
        self.assertEqual(clamp_stride.compute(0, 10, 25, 5), (15, 20, 0))
        self.assertEqual(clamp_stride.compute(0, 10, 5, 10), (5, 15, 0))
        self.assertEqual(clamp_stride.compute(0, 10, 10, 7), (0, 10, m - 2))
        self.assertEqual(clamp_stride.compute(0, 0, 0, 5), (0, 0, 5))
        self.assertEqual(clamp_stride.compute(0, 10, 25, 0), (0, 0, 0))
        self.assertEqual(clamp_stride.outputs(0x1000, 10, 25, 100),
                         (0x1000 + 15 * 80, 0x1000 + 115 * 80, 0x1000, 0x1000))


if __name__ == '__main__':
    unittest.main()
