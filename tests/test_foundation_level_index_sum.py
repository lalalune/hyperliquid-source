#!/usr/bin/env python3
"""Tests for node #94's level-index sum formatter 0x514dce0 (RE-001)."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
from foundation_level_index_sum import (  # noqa: E402
    format_level_index_sum, level_index_sum, parse_decimal_view)

PACKET = REPO / "research" / "work-items" / "RE-001-level-index-sum-94"


class ParserTests(unittest.TestCase):
    def test_empty_view_fails(self):
        self.assertEqual(parse_decimal_view(b""), (False, 0, b""))

    def test_non_digit_first_fails(self):
        self.assertEqual(parse_decimal_view(b"x3"), (False, 0, b"x3"))

    def test_trailing_characters_fail(self):
        ok, value, remaining = parse_decimal_view(b"12a")
        self.assertFalse(ok)
        self.assertEqual((value, remaining), (12, b"a"))

    def test_overflow_fails_without_value(self):
        ok, value, _ = parse_decimal_view(b"18446744073709551616")
        self.assertFalse(ok)
        self.assertIsNone(value)

    def test_uint64_max_parses(self):
        self.assertEqual(parse_decimal_view(b"18446744073709551615"),
                         (True, 18446744073709551615, b""))

    def test_leading_zeros_parse(self):
        self.assertEqual(parse_decimal_view(b"007"), (True, 7, b""))


class SumTests(unittest.TestCase):
    def test_match_across_levels(self):
        levels = [[(3, 10), (4, 99)], [(3, 5), (3, 7)]]
        self.assertEqual(level_index_sum(levels, 3), 22)

    def test_no_match_is_zero(self):
        self.assertEqual(level_index_sum([[(1, 10)]], 250), 0)

    def test_index_above_255_never_matches(self):
        # A zero-extended byte can never equal an index >= 256.
        self.assertEqual(level_index_sum([[(255, 10)]], 256), 0)

    def test_empty_levels(self):
        self.assertEqual(level_index_sum([[], []], 3), 0)


class EndToEndTests(unittest.TestCase):
    def test_success_formats_sum(self):
        levels = [[(3, 40), (9, 1)], [(3, 2)]]
        self.assertEqual(format_level_index_sum(levels, b"3"), (1, "42"))

    def test_failure_leaves_destination_unchanged(self):
        self.assertEqual(format_level_index_sum([[(3, 40)]], b"3x"),
                         (0, None))
        self.assertEqual(format_level_index_sum([[(3, 40)]], b""),
                         (0, None))

    def test_no_match_still_returns_one_with_zero(self):
        self.assertEqual(format_level_index_sum([[(3, 40)]], b"9"),
                         (1, "0"))

    def test_negative_sum_is_unmodelled(self):
        with self.assertRaises(ValueError):
            format_level_index_sum([[(3, -5)]], b"3")


class PacketTests(unittest.TestCase):
    def test_verify_passes(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpt_regeneration(self):
        sys.path.insert(0, str(PACKET))
        import export_excerpts
        for name, ranges in export_excerpts.RANGES.items():
            regen = "".join(export_excerpts.excerpt(s, e)
                            for s, e in ranges)
            self.assertEqual(regen, (PACKET / name).read_text(),
                             name)

    def test_corruption_controls(self):
        # Tampering with the records or an excerpt must fail verify.
        for rel, patch in [
                ("records.json", lambda p: p.write_text(
                    p.read_text().replace("514dce0", "514dce1"))),
                ("window.objdump.txt", lambda p: p.write_text(
                    p.read_text().replace("514dd13", "514dd14")))]:
            with tempfile.TemporaryDirectory() as tmp:
                copy = Path(tmp) / "packet"
                shutil.copytree(PACKET, copy)
                patch(copy / rel)
                result = subprocess.run(
                    [sys.executable, str(copy / "verify.py")],
                    capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, rel)


if __name__ == "__main__":
    unittest.main()
