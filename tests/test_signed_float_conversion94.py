import hashlib
from fractions import Fraction
import math
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import signed_float_conversion94 as m


def bits(value):
    return struct.unpack('<Q', struct.pack('<d', value))[0]


class TestConversion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.BINARY.read_bytes()
        cls.image = m.checked_image(cls.data)

    def test_extents_and_branches(self):
        self.assertEqual([row['size'] for row in self.image['functions']], [170, 179])
        self.assertEqual(len(self.image['branches']), 10)
        self.assertEqual(self.image['branches'][0]['destination_va'], '0x3c061e4')
        self.assertEqual(self.image['branches'][5]['destination_va'], '0x4cda22d')

    def test_digest_rejects_corruption(self):
        bad = bytearray(self.data)
        bad[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.checked_digest(bad)

    def test_branch_corruption_rejected(self):
        sections = m.elf_index.sections(self.data)
        bad = bytearray(self.data)
        pos = m.resolve(sections, 0x3c06163, 1)
        bad[pos] = 0x79
        with self.assertRaisesRegex(ValueError, 'opcode'):
            m.branch(bad, sections, 0x3c06163, 'js')

    def test_outside_and_nobits_rejected(self):
        sections = m.elf_index.sections(self.data)
        with self.assertRaises(ValueError):
            m.resolve(sections, (1 << 64)-1, 8)
        bss = next(s for s in sections if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            m.resolve(sections, bss['address'], 1)

    def test_boundary_semantics(self):
        p = m.projection
        self.assertEqual(p(7, bits(-0.5)), 0)
        self.assertEqual(p(7, bits(1.5), True), -3)
        self.assertEqual(p(7, bits(0.5), True), 3)
        self.assertEqual(p(1 << 63, bits(0)), 'panic')
        self.assertEqual(p((1 << 63)-1, bits(1)), (1 << 63)-1)
        self.assertEqual(p(3, bits(math.inf)), 0)
        self.assertEqual(p(0, bits(math.inf), True), 0)
        self.assertEqual(p(3, 0x7ff8000000000001), 0)
        self.assertEqual(p((1 << 53)+1, bits(1)), 1 << 53)
        with self.assertRaises(ValueError):
            p(-1, bits(1))

    def test_finite_model_against_exact_rational_rounding(self):
        # Fraction computes each exact real operation; conversion to float
        # supplies the separately rounded binary64 result at each stage.
        amounts = (0, 1, 3, 7, (1 << 53)-1, (1 << 53)+1, (1 << 63)-1)
        factors = (0.0, -0.0, 0.1, -0.1, 0.5, 1.0, 1.5,
                   math.nextafter(1.0, 0.0), math.nextafter(1.0, math.inf),
                   float(1 << 63), -float(1 << 63))
        for raw in amounts:
            for factor in factors:
                for complement in (False, True):
                    staged = float(Fraction(1) - Fraction(factor)) if complement else factor
                    product = float(Fraction(float(raw)) * Fraction(staged))
                    integer = max(-(1 << 63), min((1 << 63)-1, int(product)))
                    expected = integer if complement else max(0, integer)
                    self.assertEqual(m.projection(raw, bits(factor), complement), expected)

    def test_deterministic_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp)/'a', Path(tmp)/'b'
            m.generate(self.data, a)
            m.generate(self.data, b)
            for name in ('evidence.json', 'vectors.tsv'):
                self.assertEqual((a/name).read_bytes(), (b/name).read_bytes())

    def test_function_window_corruption_after_digest_control(self):
        bad = bytearray(self.data)
        sections = m.elf_index.sections(bad)
        bad[m.resolve(sections, 0x3c0616a, 1)] ^= 1
        with mock.patch.object(m, 'SHA', hashlib.sha256(bad).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'function bytes'):
                m.checked_image(bad)


if __name__ == '__main__':
    unittest.main()
