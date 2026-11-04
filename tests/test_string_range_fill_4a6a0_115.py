"""Tests for the node #115 string range-fill model 0x5d4a6a0 (RE-001)."""
import unittest

from tools.string_range_fill_4a6a0_115 import (
    StringObject,
    fresh_string,
    string_range_fill,
)


class TestStringRangeFill(unittest.TestCase):
    def test_empty_range(self):
        dest = fresh_string()
        string_range_fill(dest, b"")
        self.assertEqual(dest.data, b"")
        self.assertEqual(dest.size, 0)
        self.assertEqual(dest.terminator, 0)
        self.assertTrue(dest.inline)
        self.assertEqual(dest.capacity, 15)

    def test_single_byte_fast_path(self):
        dest = fresh_string()
        string_range_fill(dest, b"Z")
        self.assertEqual(dest.data, b"Z")
        self.assertEqual(dest.size, 1)
        self.assertEqual(dest.terminator, 0)
        self.assertTrue(dest.inline)

    def test_short_range(self):
        dest = fresh_string()
        string_range_fill(dest, b"hello")
        self.assertEqual(dest.data, b"hello")
        self.assertEqual(dest.size, 5)
        self.assertEqual(dest.terminator, 0)
        self.assertTrue(dest.inline)
        self.assertEqual(dest.capacity, 15)

    def test_sso_boundary_15_stays_inline(self):
        dest = fresh_string()
        payload = b"0123456789abcde"
        string_range_fill(dest, payload)
        self.assertEqual(dest.data, payload)
        self.assertTrue(dest.inline)
        self.assertEqual(dest.capacity, 15)
        self.assertEqual(dest.terminator, 0)

    def test_heap_boundary_16_allocates(self):
        dest = fresh_string()
        payload = b"0123456789abcdef"
        string_range_fill(dest, payload)
        self.assertEqual(dest.data, payload)
        self.assertFalse(dest.inline)
        self.assertGreaterEqual(dest.capacity, 16)
        self.assertEqual(dest.terminator, 0)
        self.assertFalse(dest.abandoned_heap_buffer)

    def test_long_range(self):
        dest = fresh_string()
        payload = bytes(range(256)) * 2
        string_range_fill(dest, payload)
        self.assertEqual(dest.data, payload)
        self.assertFalse(dest.inline)
        self.assertGreaterEqual(dest.capacity, len(payload))
        self.assertEqual(dest.terminator, 0)

    def test_embedded_nul_bytes_copied_by_length(self):
        dest = fresh_string()
        payload = b"a\x00b\x00c"
        string_range_fill(dest, payload)
        self.assertEqual(dest.data, payload)
        self.assertEqual(dest.size, 5)
        self.assertEqual(dest.terminator, 0)

    def test_short_copy_into_reused_heap_buffer_keeps_pointer(self):
        dest = StringObject(buffer=bytearray(64), size=3,
                            capacity=63, inline=False)
        string_range_fill(dest, b"xy")
        self.assertEqual(dest.data, b"xy")
        self.assertFalse(dest.inline)
        self.assertEqual(dest.capacity, 63)
        self.assertEqual(dest.terminator, 0)

    def test_long_copy_replaces_heap_buffer_without_free(self):
        dest = StringObject(buffer=bytearray(64), size=3,
                            capacity=63, inline=False)
        string_range_fill(dest, b"0123456789abcdefghij")
        self.assertEqual(dest.data, b"0123456789abcdefghij")
        self.assertTrue(dest.abandoned_heap_buffer)
        self.assertGreaterEqual(dest.capacity, 20)

    def test_source_not_modified(self):
        source = bytearray(b"unchanged")
        dest = fresh_string()
        string_range_fill(dest, bytes(source))
        self.assertEqual(bytes(source), b"unchanged")

    def test_short_overflow_is_a_model_guard(self):
        dest = StringObject(buffer=bytearray(4), size=0,
                            capacity=3, inline=True)
        with self.assertRaises(ValueError):
            string_range_fill(dest, b"1234567890")


if __name__ == "__main__":
    unittest.main()
