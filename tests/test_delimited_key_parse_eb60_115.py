"""Tests for the node #115 delimited-key parse model (0x606eb60).

Each case pins one observed branch of the routine: the no-separator
path, the bound gate (including the equality boundary), the prefix
parser's suffix letters and trailing-content rule, its throws, and
the suffix extraction.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from delimited_key_parse_eb60_115 import (
    SENTINEL,
    _extract_suffix,
    _parse_prefix_number,
    parse_delimited_key,
)


class DelimitedKeyParseTests(unittest.TestCase):
    def test_no_separator_plain_digits(self):
        self.assertEqual(parse_delimited_key("123", 0), (SENTINEL, ""))

    def test_no_separator_empty_input(self):
        self.assertEqual(parse_delimited_key("", 0), (SENTINEL, ""))

    def test_accept_and_suffix(self):
        self.assertEqual(parse_delimited_key("12#key", 0), (12, "key"))

    def test_bound_equality_accepts(self):
        self.assertEqual(parse_delimited_key("12#key", 12), (12, "key"))

    def test_bound_above_rejects(self):
        self.assertEqual(parse_delimited_key("12#key", 13), (SENTINEL, ""))

    def test_empty_suffix_when_hash_last(self):
        self.assertEqual(parse_delimited_key("12#", 12), (12, ""))

    def test_first_hash_wins(self):
        self.assertEqual(parse_delimited_key("12#a#b", 0), (12, "a#b"))

    def test_suffix_letters(self):
        cases = [
            ("1K#k", 1 << 10), ("1k#k", 1 << 10),
            ("1M#k", 1 << 20), ("1m#k", 1 << 20),
            ("1G#k", 1 << 30), ("1g#k", 1 << 30),
            ("1T#k", 1 << 40), ("1t#k", 1 << 40),
            ("12K#k", 12 << 10),
        ]
        for text, value in cases:
            with self.subTest(text=text):
                self.assertEqual(parse_delimited_key(text, 0), (value, "k"))

    def test_trailing_content_after_suffix_ignored(self):
        self.assertEqual(
            parse_delimited_key("12Kxyz#key", 0), (12 << 10, "key"))

    def test_non_suffix_trailing_character_ignored(self):
        self.assertEqual(parse_delimited_key("12x#key", 0), (12, "key"))

    def test_suffix_shift_wraps_64_bit(self):
        self.assertEqual(
            parse_delimited_key("18446744073709551615K#k", 0),
            ((0xFFFFFFFFFFFFFFFF << 10) & 0xFFFFFFFFFFFFFFFF, "k"))

    def test_empty_prefix_throws(self):
        with self.assertRaisesRegex(ValueError, "invalid_argument"):
            parse_delimited_key("#key", 0)

    def test_non_numeric_prefix_throws(self):
        with self.assertRaisesRegex(ValueError, "invalid_argument"):
            parse_delimited_key("abc#key", 0)

    def test_overflow_prefix_throws(self):
        with self.assertRaisesRegex(OverflowError, "out_of_range"):
            parse_delimited_key("99999999999999999999999#key", 0)

    def test_max_u64_prefix_parses(self):
        self.assertEqual(
            parse_delimited_key("18446744073709551615#k", 0),
            (0xFFFFFFFFFFFFFFFF, "k"))

    def test_leading_whitespace_and_sign(self):
        self.assertEqual(parse_delimited_key("  12#k", 0), (12, "k"))
        self.assertEqual(parse_delimited_key("+12#k", 0), (12, "k"))

    def test_negative_wraps_modulo_2_64(self):
        self.assertEqual(
            parse_delimited_key("-1#k", 0), (0xFFFFFFFFFFFFFFFF, "k"))

    def test_prefix_number_helper_directly(self):
        self.assertEqual(_parse_prefix_number("42"), 42)
        self.assertEqual(_parse_prefix_number("7m"), 7 << 20)
        with self.assertRaises(ValueError):
            _parse_prefix_number("")
        with self.assertRaises(OverflowError):
            _parse_prefix_number("99999999999999999999999")

    def test_suffix_bounds_check(self):
        self.assertEqual(_extract_suffix("abc", 3), "")
        with self.assertRaisesRegex(ValueError, "substr"):
            _extract_suffix("abc", 4)

    def test_input_guards(self):
        with self.assertRaises(TypeError):
            parse_delimited_key(None, 0)
        with self.assertRaises(TypeError):
            parse_delimited_key("12#k", "0")
        with self.assertRaises(ValueError):
            parse_delimited_key("12#k", -1)
        with self.assertRaises(ValueError):
            parse_delimited_key("12#k", 1 << 64)


if __name__ == "__main__":
    unittest.main()
