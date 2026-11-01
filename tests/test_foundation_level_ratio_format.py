#!/usr/bin/env python3
"""Tests for node #94's level-ratio formatter 0x514cc10 (RE-001).

Covers the decimal parser (including the UINT64_MAX boundary), the
per-level ratio (including empty entries, zero denominators and
wrapping sums), and the composed caller (full-consumption and range
gates, the unchecked -1.0 sentinel, destination preservation on
failure), plus the evidence packet: its verify script, excerpt
regeneration, and corruption controls.
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from foundation_level_ratio_format import (  # noqa: E402
    format_ratio,
    level_ratio,
    level_ratio_format,
    parse_decimal,
)

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-001-level-ratio-format-94"

LEVELS = [
    [(10, 100, 20)],                    # level 0: 120 / 10 = 12.0
    [(5, 7, 3), (5, 1, 1)],             # level 1: 12 / 10 = 1.2
    [],                                 # level 2: empty -> -1.0
    [(0, 9, 9)],                         # level 3: denominator 0 -> -1.0
]


class ParserTests(unittest.TestCase):
    def test_empty_and_nondigit(self):
        self.assertEqual(parse_decimal(b""), (False, 0, b""))
        self.assertEqual(parse_decimal(b"x42"), (False, 0, b"x42"))

    def test_digits_and_trailing(self):
        self.assertEqual(parse_decimal(b"0"), (True, 0, b""))
        self.assertEqual(parse_decimal(b"007"), (True, 7, b""))
        self.assertEqual(parse_decimal(b"42x"), (True, 42, b"x"))

    def test_uint64_boundary(self):
        self.assertEqual(parse_decimal(b"18446744073709551615"),
                         (True, 18446744073709551615, b""))
        self.assertFalse(parse_decimal(b"18446744073709551616")[0])
        self.assertFalse(parse_decimal(b"99999999999999999999")[0])


class RatioTests(unittest.TestCase):
    def test_simple_and_multi_record(self):
        self.assertEqual(level_ratio(LEVELS[0]), 12.0)
        self.assertAlmostEqual(level_ratio(LEVELS[1]), 1.2)

    def test_empty_and_zero_denominator(self):
        self.assertEqual(level_ratio(LEVELS[2]), -1.0)
        self.assertEqual(level_ratio(LEVELS[3]), -1.0)

    def test_wrapping_sums(self):
        # (2**64 - 1) + 1 wraps to a 0 numerator.
        self.assertEqual(level_ratio([(1, (1 << 64) - 1, 1)]), 0.0)
        # A denominator sum wrapping to exactly 0 is the -1.0 arm.
        self.assertEqual(level_ratio([(1, 0, 0), (-1, 0, 0)]), -1.0)

    def test_unsigned_conversion(self):
        # Numerator 2**63 as a signed sum is negative, but the binary
        # converts it as an unsigned value.
        self.assertEqual(level_ratio([(1, 1 << 63, 0)]), float(1 << 63))


class CallerTests(unittest.TestCase):
    def test_success_formats_ratio(self):
        ok, dest = level_ratio_format(4, LEVELS, "old", b"0")
        self.assertEqual((ok, dest), (True, "12.000000"))
        ok, dest = level_ratio_format(4, LEVELS, "old", b"1")
        self.assertEqual((ok, dest), (True, "1.200000"))

    def test_sentinel_not_checked(self):
        ok, dest = level_ratio_format(4, LEVELS, "old", b"2")
        self.assertEqual((ok, dest), (True, "-1.000000"))
        ok, dest = level_ratio_format(4, LEVELS, "old", b"3")
        self.assertEqual((ok, dest), (True, "-1.000000"))

    def test_failures_preserve_destination(self):
        for view in (b"", b"x", b"4", b"99", b"1x", b"18446744073709551616"):
            ok, dest = level_ratio_format(4, LEVELS, "keep", view)
            self.assertEqual((ok, dest), (False, "keep"), view)

    def test_format_shape(self):
        self.assertEqual(format_ratio(-1.0), "-1.000000")
        self.assertEqual(format_ratio(0.5), "0.500000")


class PacketTests(unittest.TestCase):
    def run_verify(self, packet):
        result = subprocess.run(
            [sys.executable, str(packet / "verify.py")],
            capture_output=True, text=True, cwd=str(REPO))
        return result

    def test_verify_passes(self):
        result = self.run_verify(PACKET)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpt_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            outdir = Path(tmp)
            result = subprocess.run(
                [sys.executable, str(PACKET / "export_excerpts.py"),
                 "--out", str(outdir)],
                capture_output=True, text=True, cwd=str(REPO),
                env={"PATH": "/usr/bin:/bin",
                     "HL_NODE94_BIN": str(REPO / "work" / "hl-node-94.bin")})
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "parser.objdump.txt",
                         "ratio.objdump.txt", "plt.objdump.txt"):
                self.assertEqual((outdir / name).read_bytes(),
                                 (PACKET / name).read_bytes(), name)

    def test_corruption_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "packet"
            shutil.copytree(PACKET, copy)
            # Tampering with an excerpt must fail verification.
            window = copy / "window.objdump.txt"
            text = window.read_text()
            window.write_text(text.replace("514cc10", "514cc11", 1))
            self.assertNotEqual(self.run_verify(copy).returncode, 0)
            shutil.copytree(PACKET, copy, dirs_exist_ok=True)
            # Tampering with a record must fail verification.
            records = copy / "records.json"
            text = records.read_text()
            records.write_text(text.replace("00ffb453", "00ffb454", 1))
            self.assertNotEqual(self.run_verify(copy).returncode, 0)


if __name__ == "__main__":
    unittest.main()
