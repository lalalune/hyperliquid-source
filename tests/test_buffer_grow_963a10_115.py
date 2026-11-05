"""Tests for the node #115 buffer growth model
(tools/buffer_grow_963a10_115.py, routine 0x5963a10, RE-001)."""
import unittest

from tools.buffer_grow_963a10_115 import (
    AllocFailure,
    Buffer,
    GrowthFailure,
    grow,
    min_capacity,
    new_capacity,
)


def ok_allocator(new_ptr=0x5000):
    def alloc(old_cap, old_ptr, cap, forwarded):
        return (0, new_ptr, 0)

    return alloc


class TestMinCapacity(unittest.TestCase):
    def test_table_boundaries(self):
        self.assertEqual(min_capacity(1), 8)
        self.assertEqual(min_capacity(2), 4)
        self.assertEqual(min_capacity(3), 4)
        self.assertEqual(min_capacity(0x400), 4)
        self.assertEqual(min_capacity(0x401), 1)
        self.assertEqual(min_capacity(0x402), 1)
        self.assertEqual(min_capacity(1 << 32), 1)


class TestNewCapacity(unittest.TestCase):
    def test_zero_element_size_fails(self):
        with self.assertRaises(GrowthFailure):
            new_capacity(0, 0, 1, 0)

    def test_needed_overflow_fails(self):
        with self.assertRaises(GrowthFailure):
            new_capacity(0, (1 << 64) - 1, 1, 1)
        with self.assertRaises(GrowthFailure):
            new_capacity(0, 1 << 63, 1 << 63, 8)

    def test_needed_at_max_is_allowed(self):
        self.assertEqual(
            new_capacity(0, (1 << 64) - 1, 0, 1), (1 << 64) - 1)

    def test_byte_buffer_from_empty(self):
        # The JSON writers' case: capacity 0, length 0, one more
        # byte, element size 1: max(0, 1, 8) = 8.
        self.assertEqual(new_capacity(0, 0, 1, 1), 8)

    def test_doubling_wins(self):
        self.assertEqual(new_capacity(16, 16, 1, 1), 32)

    def test_needed_wins_over_doubling(self):
        self.assertEqual(new_capacity(4, 4, 100, 1), 104)

    def test_minimum_floor_wins(self):
        self.assertEqual(new_capacity(1, 1, 1, 1), 8)
        self.assertEqual(new_capacity(0, 0, 1, 2), 4)
        self.assertEqual(new_capacity(0, 0, 1, 0x401), 1)

    def test_doubling_wraps_unchecked(self):
        # 2 * 2**63 wraps to 0 (bare lea); the max falls to the
        # other terms: length 5 + additional 1 = 6, floor 8.
        self.assertEqual(new_capacity(1 << 63, 5, 1, 1), 8)
        self.assertEqual(new_capacity((1 << 63) + 5, 0, 1, 1), 10)
        # The wrap is modular, not saturating: 2 * (2**64 - 1)
        # wraps to 2**64 - 2, which wins the max.
        self.assertEqual(
            new_capacity((1 << 64) - 1, 0, 0, 1), (1 << 64) - 2)


class TestGrow(unittest.TestCase):
    def test_success_stores_pointer_and_capacity(self):
        buf = Buffer(capacity=3, data_ptr=0x1000, length=3)
        seen = []

        def alloc(old_cap, old_ptr, cap, forwarded):
            seen.append((old_cap, old_ptr, cap, forwarded))
            return (0, 0x9000, 0xDEAD)

        out = grow(buf, 3, 1, 0x77, 1, alloc)
        self.assertEqual(out, 8)
        self.assertEqual(buf.capacity, 8)
        self.assertEqual(buf.data_ptr, 0x9000)
        # The allocator receives the old capacity, old pointer,
        # the computed capacity and the forwarded rcx verbatim.
        self.assertEqual(seen, [(3, 0x1000, 8, 0x77)])

    def test_length_field_never_touched(self):
        buf = Buffer(capacity=0, data_ptr=0, length=42)
        grow(buf, 0, 1, 1, 1, ok_allocator())
        self.assertEqual(buf.length, 42)

    def test_allocator_error_leaves_descriptor_unchanged(self):
        buf = Buffer(capacity=3, data_ptr=0x1000, length=3)

        def alloc(old_cap, old_ptr, cap, forwarded):
            return (1, 0xAAAA, 0xBBBB)

        with self.assertRaises(AllocFailure) as ctx:
            grow(buf, 3, 1, 1, 1, alloc)
        self.assertEqual(ctx.exception.word1, 0xAAAA)
        self.assertEqual(ctx.exception.word2, 0xBBBB)
        self.assertEqual(buf.capacity, 3)
        self.assertEqual(buf.data_ptr, 0x1000)

    def test_non_one_tag_is_success(self):
        buf = Buffer(capacity=0, data_ptr=0)
        grow(buf, 0, 1, 1, 1, lambda c, p, n, f: (2, 0x1234, 0))
        self.assertEqual(buf.data_ptr, 0x1234)
        self.assertEqual(buf.capacity, 8)

    def test_failures_happen_before_the_allocator(self):
        calls = []

        def alloc(*args):
            calls.append(args)
            return (0, 0, 0)

        with self.assertRaises(GrowthFailure):
            grow(Buffer(), 0, 1, 1, 0, alloc)
        with self.assertRaises(GrowthFailure):
            grow(Buffer(), (1 << 64) - 1, 1, 1, 1, alloc)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
