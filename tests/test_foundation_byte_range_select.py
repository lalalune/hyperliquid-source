"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_byte_range_select as byte_range_select
from elf_index import sections


class ByteRangeSelectEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not byte_range_select.TARGET.is_file() or byte_range_select.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = byte_range_select.inspect(byte_range_select.TARGET)
        cls.data = byte_range_select.TARGET.read_bytes()
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
        self.assertEqual(self.result['window'], (0x359be70, 0x359bebe))
        self.assertEqual(self.result['body_sha256'],
                         '97a69885f4ce8f473e5c0139e173b3c35bbee945b4519ffa9ad5d7e5bdbe1aaa')
        self.assertEqual(self.result['relocation_slots'], [])
        self.assertEqual(len(self.result['direct_callers']), 113)
        self.assertEqual(self.result['direct_callers'][0], 0x31ed745)
        self.assertEqual(self.result['direct_callers'][-1], 0x3ca0627)

    def test_body_lock(self):
        bad = self.mutated(0x359be70, b'\x90')
        with self.assertRaises(ValueError):
            byte_range_select.analyze(bad)

    def test_range_lea_lock(self):
        # lea displacement at offset 7: flipping it breaks the range base.
        bad = self.mutated(0x359be70 + 7, b'\x00')
        with self.assertRaises(ValueError):
            byte_range_select.analyze(bad)

    def test_range_width_lock(self):
        # cmp immediate at offset 13: flipping it breaks the range width.
        bad = self.mutated(0x359be70 + 13, b'\x21')
        with self.assertRaises(ValueError):
            byte_range_select.analyze(bad)

    def test_jae_target_lock(self):
        # jae rel8 at offset 15: flipping it breaks the out-of-range target.
        bad = self.mutated(0x359be70 + 15, b'\x02')
        with self.assertRaises(ValueError):
            byte_range_select.analyze(bad)

    def test_8f_compare_lock(self):
        # cmp immediate at offset 19: flipping it breaks the 0x8f class.
        bad = self.mutated(0x359be70 + 19, b'\x8e')
        with self.assertRaises(ValueError):
            byte_range_select.analyze(bad)

    def test_90_or_lock(self):
        # or immediate at offset 73: flipping it breaks the 0x90 class.
        bad = self.mutated(0x359be70 + 73, b'\x91')
        with self.assertRaises(ValueError):
            byte_range_select.analyze(bad)

    def test_a0_mask_lock(self):
        # and immediate at offset 43: flipping it breaks the 0xa0 class.
        bad = self.mutated(0x359be70 + 43, b'\x1e')
        with self.assertRaises(ValueError):
            byte_range_select.analyze(bad)

    def test_padding_lock(self):
        bad = self.mutated(0x359bebe, b'\x90\x90')
        with self.assertRaises(ValueError):
            byte_range_select.analyze(bad)

    def test_select_rule(self):
        self.assertEqual(byte_range_select.select(0xAABBCCDF, 0x12345678), 0xAABBCCDF)
        self.assertEqual(byte_range_select.select(0x000000C0, 0x12345678), 0x000000C0)
        self.assertEqual(byte_range_select.select(0x00000000, 0x12345678), 0x12345678)
        self.assertEqual(byte_range_select.select(0x00000041, 0x12345678), 0x12345688)
        self.assertEqual(byte_range_select.select(0x0000008F, 0x12345678), 0x12345688)
        self.assertEqual(byte_range_select.select(0x00000090, 0x12345678), 0x12345698)
        self.assertEqual(byte_range_select.select(0x000000A0, 0x12345678), 0x123456B8)
        self.assertEqual(byte_range_select.select(0x00000091, 0x12345678), 0x12345678)
        self.assertEqual(byte_range_select.select(0x000000BF, 0x12345678), 0x12345678)
        self.assertEqual(byte_range_select.select(0x000000E0, 0x12345678), 0x12345678)
        self.assertEqual(byte_range_select.select(0x000000FF, 0x12345678), 0x12345678)
        self.assertEqual(byte_range_select.select(0x00000041, 0xDEADBEEF), 0xDEADBE8F)


if __name__ == '__main__':
    unittest.main()
