import hashlib
import unittest
from tools import schema_cap_view94 as s


class SchemaCapViewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(s.BINARY.read_bytes())
        cls.image = s.Image(cls.data)

    def test_target_and_fdes(self):
        functions, pins = self.image.check()
        self.assertEqual(len(functions), 3)
        self.assertEqual(len(pins), 12)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), s.DIGEST)

    def test_digest_rejected_before_parsing(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            s.Image(b'not the target')

    def test_file_backing_and_bounds(self):
        with self.assertRaises(ValueError):
            self.image.read(-1, 8)
        with self.assertRaises(ValueError):
            self.image.read(0xffffffffffffffff, 8)
        bss = next(x for x in s.elf_index.sections(self.data) if x['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 8)

    def test_corrupted_function_byte(self):
        va = 0x26b3b11
        sec = next(x for x in self.image.sections if x['name'] == '.text')
        off = sec['offset'] + va - sec['address']
        self.data[off] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'function bytes'):
                self.image.check()
        finally:
            self.data[off] ^= 1

    def test_corrupted_divisor(self):
        va = 0x20ae60
        sec = next(x for x in self.image.sections if x['name'] == '.rodata')
        off = sec['offset'] + va - sec['address']
        self.data[off] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'divisor'):
                self.image.check()
        finally:
            self.data[off] ^= 1

    def test_fde_extent_rejected(self):
        fde = next(x for x in self.image.fdes if x['start'] == 0x27ed840)
        fde['end'] -= 1
        try:
            with self.assertRaisesRegex(ValueError, 'FDE mismatch'):
                self.image.check()
        finally:
            fde['end'] += 1

    def test_lookup_boundaries(self):
        self.assertTrue(s.model(9999, 0, 10000, 0)['lookup_valid'])
        self.assertFalse(s.model(9999, 0, 9999, 0)['lookup_valid'])
        self.assertFalse(s.model(10000, 0, 1, 0)['lookup_valid'])
        self.assertTrue(s.model(10000, 1, 1, 0)['lookup_valid'])
        with self.assertRaises(ValueError):
            s.model(1 << 64, 0, 1, 0)

    def test_reciprocal_bound_and_adversary(self):
        m = 0x346dc5d63886594b
        self.assertEqual(10000 * m - (1 << 75), 432)
        self.assertLess(((1 << 64) - 1) * 432, 1 << 75)
        self.assertLess(10000 * (m - 1), 1 << 75)
        for n in (0, 9999, 10000, 10001, (1 << 64) - 1):
            self.assertEqual((n * m) >> 75, n // 10000)

    def test_float_rounding_witness(self):
        self.assertEqual(s.model(0, 0, 1, (1 << 53))['value_bits'],
                         s.model(0, 0, 1, (1 << 53) + 1)['value_bits'])
        self.assertEqual(s.model(0, 0, 1, 1000000)['value_bits'], '000000000000f03f')


if __name__ == '__main__':
    unittest.main()
