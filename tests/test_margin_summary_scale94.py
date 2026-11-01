import hashlib
import math
from fractions import Fraction
import struct
import unittest
from tools import margin_summary_scale94 as m


class MarginSummaryScaleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.BINARY.read_bytes()
        cls.evidence = m.extract(cls.data)

    def test_path_and_layout(self):
        self.assertEqual(len(self.evidence['functions']), 3)
        self.assertEqual(len(self.evidence['decisions']), 9)
        self.assertEqual(self.evidence['decisions'][0]['taken_target'], '0x256528c')
        self.assertEqual(self.evidence['decisions'][-1]['taken_target'], '0x26b9f1b')
        self.assertEqual(len(m.FIELDS), 10)
        self.assertEqual([r[0] for r in m.FIELDS], list(range(0x18, 0x68, 8)))
        self.assertEqual([x[1] for x in m.FIELDS].count('signed'), 5)

    def test_hash_corruption(self):
        data = bytearray(self.data)
        data[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest'):
            m.checked_hash(data)

    def test_instruction_corruption_after_rebinding_digest(self):
        data = bytearray(self.data)
        off = int(self.evidence['functions'][1]['file_offset'], 16)
        data[off] ^= 1
        old = m.SHA
        try:
            m.SHA = hashlib.sha256(data).hexdigest()
            with self.assertRaisesRegex(ValueError, 'function byte mismatch'):
                m.extract(data)
        finally:
            m.SHA = old

    def test_divisor_corruption_after_rebinding_digest(self):
        data = bytearray(self.data)
        off = int(self.evidence['divisors'][0]['file_offset'], 16)
        data[off] ^= 1
        old = m.SHA
        try:
            m.SHA = hashlib.sha256(data).hexdigest()
            with self.assertRaisesRegex(ValueError, 'divisor byte mismatch'):
                m.extract(data)
        finally:
            m.SHA = old

    def test_invalid_address_and_inputs(self):
        with self.assertRaises(ValueError):
            m.offset(m.elf_index.sections(self.data), (1 << 64)-1, 8)
        for value, signed in ((-1, False), (1 << 64, False), (1 << 63, True), (-(1 << 63)-1, True)):
            with self.assertRaises(ValueError):
                m.scaled_bits(value, signed)

    def test_division_against_exact_rational(self):
        for signed, values in ((True, (-(1 << 63), -1000001, -1, 0, 1, (1 << 63)-1)),
                               (False, (0, 1, 1000001, (1 << 53)+3, (1 << 64)-1))):
            for value in values:
                numerator = Fraction.from_float(float(value))
                result = float(numerator / 1000000)
                reference = struct.unpack('<Q', struct.pack('<d', result))[0]
                self.assertEqual(m.scaled_bits(value, signed), reference)
        self.assertNotEqual(m.scaled_bits(-1, True), m.scaled_bits((1 << 64)-1, False))

    def test_packed_unsigned_conversion_and_bias_control(self):
        constants = {int(x['va'], 16): bytes.fromhex(x['bytes_hex']) for x in self.evidence['conversion_constants']}
        words = tuple(struct.unpack_from('<Q', constants[va])[0]
                      for va in (0x209020, 0x2076e0, 0x204c20, 0x204c30))
        scalar = (struct.unpack_from('<Q', constants[0x203e80])[0],
                  *struct.unpack('<QQ', constants[0x202ea0]))
        for high in (0, 1, 0x7fffffff, 0x80000000, 0xffffffff):
            for low in (0, 1, 0x7fffffff, 0x80000000, 0xffffffff):
                value = high << 32 | low
                self.assertEqual(m.unsigned_sse_bits(value, words), m.scaled_bits(value, False))
                self.assertEqual(m.unsigned_scalar_bits(value, scalar), m.scaled_bits(value, False))
        corrupted = words[:3] + (words[3] + 1,)
        self.assertNotEqual(m.unsigned_sse_bits(1 << 63, corrupted), m.scaled_bits(1 << 63, False))
        with self.assertRaises(ValueError):
            m.unsigned_sse_bits(-1, words)

    def test_integer_to_binary64_rounding(self):
        one = struct.unpack('<Q', struct.pack('<d', 1.0))[0]
        self.assertEqual(m.scaled_bits(1000000, False), one)
        self.assertEqual(m.scaled_bits(-1000000, True), one | 1 << 63)
        self.assertNotEqual(m.scaled_bits(0, False), one)
        # The cast precedes division: adjacent integers can collapse above 2^53.
        self.assertEqual(m.scaled_bits(1 << 53, False), m.scaled_bits((1 << 53) + 1, False))
        self.assertTrue(math.isfinite(struct.unpack('<d', struct.pack('<Q', m.scaled_bits((1 << 64)-1, False)))[0]))

if __name__ == '__main__':
    unittest.main()
