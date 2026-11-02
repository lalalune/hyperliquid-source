import hashlib
import struct
import unittest
from pathlib import Path

from tools import asset_map_scale94 as m


class AssetMapScale94(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = m.Image((m.ROOT / m.BINARY).read_bytes())

    def test_target_path_and_branches(self):
        result = m.inspect(self.image)
        self.assertEqual(len(result['branches']), 17)
        self.assertEqual(result['fdes'][0]['end'], '0x26b3c17')
        self.assertEqual(result['fdes'][1]['end'], '0x27eda58')
        self.assertEqual(result['floating_constants']['0x20ae60'], '0000000080842e41')

    def test_digest_corruption(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.Image(b'wrong target')

    def test_instruction_corruption(self):
        class Patch:
            def __init__(self, parent):
                self.parent = parent
            def read(self, va, size):
                b = self.parent.read(va, size)
                if va == 0x26b3905:
                    return bytes([b[0] ^ 1]) + b[1:]
                return b
        with self.assertRaisesRegex(ValueError, 'instruction bytes'):
            m.checked_patterns(Patch(self.image))

    def test_branch_target_corruption(self):
        class Patch:
            def read(self, va, size):
                b = AssetMapScale94.image.read(va, size)
                return bytes([b[0] ^ 1]) + b[1:] if va == 0x26b38b2 else b
        self.assertNotEqual(m.branch(Patch(), 0x26b38b0)[1], 0x26b3bc2)

    def test_unmapped_and_cross_boundary_address(self):
        with self.assertRaises(ValueError):
            self.image.read(0, 8)
        text = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            self.image.read(text['address'] + text['size'] - 1, 2)

    def test_float_boundaries(self):
        self.assertEqual(m.scaled_bits(0), 0)
        self.assertEqual(m.scaled_bits(1), 0x3eb0c6f7a0b5ed8d)
        self.assertEqual(m.scaled_bits(1000000), 0x3ff0000000000000)
        self.assertEqual(m.binary64((1 << 53) + 1), m.binary64(1 << 53))
        self.assertNotEqual(m.scaled_bits((1 << 53) + 1), m.binary64((1 << 53) + 1, 1000000))
        self.assertEqual(m.binary64((1 << 53) + 3), m.binary64((1 << 53) + 4))
        self.assertEqual(m.scaled_bits(m.TOP), 0x42b0c6f7a0b5ed8d)
        for x in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                m.scaled_bits(x)

    def test_fraction_model_against_host_binary64(self):
        for k in range(20):
            for x in (10**k - 1, 10**k, 10**k + 1):
                if 0 <= x <= m.TOP:
                    host = struct.unpack('<Q', struct.pack('<d', float(x) / 1000000.0))[0]
                    self.assertEqual(m.scaled_bits(x), host)

    def test_reciprocal_quotient_boundaries(self):
        multiplier = 0x346dc5d63886594b
        for q in (0, 1, 2, 100, m.TOP // 10000):
            for r in (0, 1, 9998, 9999):
                x = q * 10000 + r
                if x <= m.TOP:
                    self.assertEqual((x * multiplier) >> 75, x // 10000)
        self.assertLess((m.TOP // 10000) * (multiplier*10000-(1<<75)) + 9999*multiplier, 1<<75)

    def test_fde_and_output_digest(self):
        result = m.inspect(self.image)
        first = result['fdes'][0]
        body = self.image.read(int(first['start'], 16), int(first['end'], 16)-int(first['start'],16))
        self.assertEqual(first['sha256'], hashlib.sha256(body).hexdigest())


if __name__ == '__main__':
    unittest.main()
