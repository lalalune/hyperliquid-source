import math
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import qty_float_clamp as q


class QtyFloatClampTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (q.ROOT / 'artifacts/node/94/hl-node').read_bytes()

    def test_target_and_fdes(self):
        e = q.inspect(self.data)
        self.assertEqual([x['size'] for x in e['functions']], [170, 179])
        self.assertEqual(len(e['constants']), 4)

    def test_digest_and_bytes_corruption(self):
        bad = bytearray(self.data)
        off, _ = q.resolve(bad, 0x3c06160, 1)
        bad[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest'):
            q.inspect(bad)
        with self.assertRaisesRegex(ValueError, 'function bytes'):
            q.inspect(bad, check_digest=False)

    def test_constant_corruption(self):
        bad = bytearray(self.data)
        off, _ = q.resolve(bad, 0x20a730, 1)
        bad[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'constant bytes'):
            q.inspect(bad, check_digest=False)

    def test_conversion_partition_and_damaged_threshold(self):
        proof = q.prove_conversion()
        self.assertEqual(proof['finite_interval_endpoints_checked'], 8188)
        self.assertEqual(sum(proof['finite_sign_exponent_classes'].values()), 4094)
        with patch.dict(q.CONSTANTS, {0x20a2c8: 0}):
            with self.assertRaises(AssertionError):
                q.prove_conversion()

    def test_unmapped_address(self):
        with self.assertRaises(ValueError):
            q.resolve(self.data, (1 << 64) - 1, 8)

    def test_product_boundaries(self):
        f = lambda n, x: q.model('product_nonnegative', n, x)
        self.assertEqual(f(3, .5), 1)
        self.assertEqual(f(3, -.5), 0)
        self.assertEqual(f((1 << 63) - 1, 1), (1 << 63) - 1)
        self.assertEqual(f(1 << 63, 0), 'panic')
        self.assertEqual(f(1, math.inf), 0)
        self.assertEqual(f(1, math.nan), 0)

    def test_complement_boundaries(self):
        f = lambda n, x: q.model('complement_signed', n, x)
        self.assertEqual(f(3, .5), 1)
        self.assertEqual(f(3, 1.5), -1)
        self.assertEqual(f(3, 2), -3)
        self.assertEqual(f((1 << 63) - 1, 2), -(1 << 63))
        self.assertEqual(f(1 << 63, 1), 'panic')
        self.assertEqual(f(1, -math.inf), 0)
        self.assertEqual(f(1, math.nan), 0)


if __name__ == '__main__':
    unittest.main()
