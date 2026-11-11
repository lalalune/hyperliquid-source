"""Tests for the node #115 shard refresh model
(tools/shard_refresh_605e170_115.py, routine 0x605e170, RE-001)."""
import unittest

from tools.shard_refresh_605e170_115 import (
    index_mask,
    park_miller_step,
    refresh,
)

ARRAY = 0x20000000


class TestParkMillerStep(unittest.TestCase):
    def test_canonical_sequence(self):
        # The published Park-Miller minimal-standard orbit of 1.
        seed = 1
        for want in (16807, 282475249, 1622650073, 984943658,
                     1144108930, 470211272, 101027544, 1457850878):
            seed = park_miller_step(seed)
            self.assertEqual(seed, want)

    def test_zero_is_a_fixed_point(self):
        self.assertEqual(park_miller_step(0), 0)

    def test_modulus_is_a_fixed_point_as_coded(self):
        # Exact modular arithmetic would give 0; the coded fold
        # leaves 2**31-1 because the sum has no sign bit.
        self.assertEqual(park_miller_step(0x7FFFFFFF), 0x7FFFFFFF)

    def test_high_bit_seed_uses_full_word(self):
        # The loaded word is not masked before the multiply.
        self.assertEqual(park_miller_step(0x80000000),
                         park_miller_step(0x80000000))
        self.assertNotEqual(park_miller_step(0x80000000),
                            park_miller_step(0))


class TestIndexMask(unittest.TestCase):
    def test_widths(self):
        self.assertEqual(index_mask(0), 0)
        self.assertEqual(index_mask(1), 1)
        self.assertEqual(index_mask(5), 31)
        self.assertEqual(index_mask(31), 0x7FFFFFFF)

    def test_count_wraps_at_32(self):
        self.assertEqual(index_mask(32), 0)
        self.assertEqual(index_mask(33), 1)
        self.assertEqual(index_mask(63), 0x7FFFFFFF)
        self.assertEqual(index_mask(64), 0)

    def test_only_low_bits_of_dword_matter(self):
        self.assertEqual(index_mask(0xDEADBE05), index_mask(5))


class TestRefreshFastPath(unittest.TestCase):
    def test_selector_masked_to_index(self):
        entry, tls, seed = refresh(ARRAY, 3, 0b101101, 999)
        self.assertEqual(entry, ARRAY + (0b101101 & 0b111) * 64)
        self.assertEqual(tls, (0b101101 & 0b111) + (1 << 3))
        self.assertEqual(seed, 999)  # fallback never consulted

    def test_zero_shift_selects_first_shard(self):
        entry, tls, _ = refresh(ARRAY, 0, 200, 1)
        self.assertEqual(entry, ARRAY)
        self.assertEqual(tls, 1)  # index 0 plus bit 0

    def test_shift_32_splits_mask_and_bit_widths(self):
        # Mask count wraps to 0 (index forced to 0) while the
        # TLS bit still uses the low 6 bits of the field.
        entry, tls, _ = refresh(ARRAY, 32, 200, 1)
        self.assertEqual(entry, ARRAY)
        self.assertEqual(tls, 1 << 32)

    def test_shift_33(self):
        entry, tls, _ = refresh(ARRAY, 33, 0xFF, 1)
        self.assertEqual(entry, ARRAY + 1 * 64)
        self.assertEqual(tls, 1 + (1 << 33))

    def test_apic_id_range(self):
        for apic in (0, 1, 37, 128, 255):
            entry, _, _ = refresh(ARRAY, 8, apic, 1)
            self.assertEqual(entry, ARRAY + (apic & 0xFF) * 64)


class TestRefreshFallback(unittest.TestCase):
    def test_negative_selector_advances_seed_and_uses_it(self):
        entry, tls, seed = refresh(ARRAY, 8, -1, 1)
        self.assertEqual(seed, 16807)
        self.assertEqual(entry, ARRAY + (16807 & 0xFF) * 64)
        self.assertEqual(tls, (16807 & 0xFF) + (1 << 8))

    def test_any_negative_selector_takes_fallback(self):
        _, _, seed = refresh(ARRAY, 8, -2147483648, 1)
        self.assertEqual(seed, 16807)

    def test_zero_selector_is_fast_path(self):
        entry, tls, seed = refresh(ARRAY, 8, 0, 1)
        self.assertEqual(entry, ARRAY)
        self.assertEqual(tls, 1 << 8)
        self.assertEqual(seed, 1)

    def test_fallback_seed_orbit(self):
        # Repeated refresh with no CPUID walks the seed orbit
        # and selects by the fresh word each time.
        seed = 1
        for want in (16807, 282475249, 1622650073):
            _, _, seed = refresh(ARRAY, 16, -1, seed)
            self.assertEqual(seed, want)


if __name__ == "__main__":
    unittest.main()
