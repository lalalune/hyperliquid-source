#!/usr/bin/env python3
"""Tests for node #94's 21-key map format line 0x514d0c0 (RE-001).

Covers the compact-int helper at every magnitude boundary including
negatives, the scaled-size helper at every unit boundary, the key-3
uint conversion including the 2^63 arm, a full end-to-end formatted
line, a missing key throwing, and the evidence packet: its verify
script, excerpt regeneration, and corruption controls.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from foundation_map_format_line import (  # noqa: E402
    format_int_compact,
    format_line,
    format_size_uint,
    uint_from_double,
)

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-001-map-format-line-94"
BINARY = REPO / "work" / "hl-node-94.bin"


class CompactTests(unittest.TestCase):
    def test_plain_range(self):
        self.assertEqual(format_int_compact(0), "0")
        self.assertEqual(format_int_compact(9999), "9999")
        self.assertEqual(format_int_compact(-9999), "-9999")

    def test_kilo_boundary(self):
        self.assertEqual(format_int_compact(10000), "10K")
        self.assertEqual(format_int_compact(15000), "15K")
        self.assertEqual(format_int_compact(-15000), "-15K")
        self.assertEqual(format_int_compact(9999999), "9999K")

    def test_mega_and_giga_boundaries(self):
        self.assertEqual(format_int_compact(10000000), "10M")
        self.assertEqual(format_int_compact(9999999999), "9999M")
        self.assertEqual(format_int_compact(10000000000), "10G")
        self.assertEqual(format_int_compact(-10000000000), "-10G")

    def test_truncation_toward_zero(self):
        self.assertEqual(format_int_compact(19999), "19K")
        self.assertEqual(format_int_compact(-19999), "-19K")


class SizeTests(unittest.TestCase):
    def test_unit_boundaries(self):
        self.assertEqual(format_size_uint(0), "0.00 KB")
        self.assertEqual(format_size_uint(1024), "1.00 KB")
        self.assertEqual(format_size_uint(1536), "1.50 KB")
        self.assertEqual(format_size_uint(1048576), "1.00 MB")
        self.assertEqual(format_size_uint(1073741824), "1.00 GB")
        self.assertEqual(format_size_uint(1099511627776), "1.00 TB")

    def test_key3_uint_conversion(self):
        self.assertEqual(uint_from_double(3.9), 3)
        self.assertEqual(uint_from_double(2048.0), 2048)
        # At 2^63 the code subtracts 2^63, converts and flips bit 63.
        self.assertEqual(uint_from_double(2 ** 63), 2 ** 63)
        # Double spacing at 2^63 is 2048, so +2048 is representable.
        self.assertEqual(uint_from_double(float(2 ** 63 + 2048)), 2 ** 63 + 2048)
        # A negative double is read as uint64 by the size helper.
        self.assertEqual(uint_from_double(-1.0), 2 ** 64 - 1)
        self.assertEqual(format_size_uint(uint_from_double(-1.0)),
                         "16777216.00 TB")


class LineTests(unittest.TestCase):
    def _values(self):
        values = {key: float(key) for key in range(1, 22)}
        values[1] = 12.9
        values[2] = 3.2
        values[3] = 2048.0
        values[16] = 42.7
        values[17] = 13.123
        values[18] = 15000.0
        values[19] = 42.0
        return values

    def test_full_line(self):
        line = format_line(self._values(), "ABCD")
        self.assertTrue(line.endswith("\n"))
        self.assertIn("ABCD", line)
        self.assertIn("    12/3  ", line)
        self.assertIn("  2.00 KB", line)
        self.assertIn("42", line)
        self.assertIn("15K", line)
        self.assertIn("13.123", line)
        # Keys 4..15 appear as floats in order, key 20/21 at the end.
        self.assertTrue(line.index("1.0") < line.index("15.0"))
        # Exact line, built piece by piece from the pinned format.
        expected = (
            "%4s %6d/%-3d %8s %5.1f %8.1f %7.1f %8.1f %9.1f %8.1f "
            "%9.1f %5.1f %8.1f %8.1f %9.2f %17.2f %9d %8.3f %7s %6s "
            "%9.1f %9.1f\n"
        ) % (
            "ABCD", 12, 3, "2.00 KB",
            4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0,
            14.0, 15.0, 42, 13.123, "15K", "42", 20.0, 21.0,
        )
        self.assertEqual(line, expected)

    def test_missing_key_throws(self):
        values = self._values()
        del values[17]
        with self.assertRaises(KeyError):
            format_line(values, "ABCD")


class PacketTests(unittest.TestCase):
    def test_verify_script_passes(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--binary", str(BINARY)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_records_shape(self):
        records = json.loads((PACKET / "records.json").read_text())
        sites = {caller["site"] for caller in records["callers"]}
        self.assertEqual(sites, {"0x5156554", "0x51567d9",
                                 "0x5156aae", "0x5156cad"})
        self.assertEqual(len(records["direct_map_at_calls"]), 14)
        self.assertEqual(len(records["inline_searches"]), 7)
        keys = {call["key"] for call in records["direct_map_at_calls"]}
        keys |= {search["key"] for search in records["inline_searches"]}
        self.assertEqual(keys, set(range(1, 22)))
        self.assertIn("%4s", records["format"]["string"])

    def test_excerpt_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            outdir = Path(tmp)
            result = subprocess.run(
                [sys.executable, str(PACKET / "export_excerpts.py"),
                 "--out", str(outdir)],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "helper_int.objdump.txt",
                         "helper_size.objdump.txt", "callers.objdump.txt",
                         "plt.objdump.txt"):
                self.assertEqual((outdir / name).read_text(),
                                 (PACKET / name).read_text(), name)

    def test_corruption_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "packet"
            shutil.copytree(PACKET, copy)
            # Tampered function SHA must fail verification.
            records = json.loads((copy / "records.json").read_text())
            records["functions"][0]["sha256"] = "0" * 64
            (copy / "records.json").write_text(json.dumps(records))
            result = subprocess.run(
                [sys.executable, str(copy / "verify.py"),
                 "--binary", str(BINARY)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            # Tampered excerpt must fail verification.
            shutil.copytree(PACKET, copy, dirs_exist_ok=True)
            window = (copy / "window.objdump.txt").read_text()
            (copy / "window.objdump.txt").write_text(window + "tampered\n")
            result = subprocess.run(
                [sys.executable, str(copy / "verify.py"),
                 "--binary", str(BINARY)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
