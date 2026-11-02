"""Tests for tools/foundation_compaction_entries.py (node #94 0x51599e0).

The expectations are transcribed from the window's disassembly
(see research/work-items/RE-001-compaction-entries-94/): the
signed int32 digit ladder and digit-pair fill, the "L" prefix,
the "Sum" text for the -1 group, the global map's at() lookup,
the saturating destination-map comparison, the segment-key
construction, and the insert-or-replace value store. The tests
pin the model, not an execution of the target binary (no
execution is available here).
"""

import os
import random
import subprocess
import sys
import tempfile
import unittest

from tools.foundation_compaction_entries import (
    KEY_PREFIX,
    SEGMENT_DOT,
    SEGMENT_PREFIX,
    SUM_TEXT,
    build_entries,
    build_via_wrapper,
    compare_keys,
    digit_count_magnitude,
    group_key_text,
    itoa_int32,
    lower_bound_index,
    names_at,
    saturate_length_diff,
    segment_key,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    REPO, "research", "work-items", "RE-001-compaction-entries-94")
# Relative path, run from the repo root: objdump embeds the path
# spelling in each excerpt header, so absolute and relative runs
# would not regenerate byte-for-byte.
BINARY = os.path.join("work", "hl-node-94.bin")

NAMES = {7: b"alpha", 8: b"beta", 9: b"gamma"}


class TestItoa(unittest.TestCase):
    def test_digit_count_boundaries(self):
        cases = [(0, 1), (9, 1), (10, 2), (99, 2), (100, 3),
                 (999, 3), (1000, 4), (9999, 4), (10000, 5),
                 (99999, 5), (100000, 6), (999999, 6), (1000000, 7),
                 (9999999, 7), (10000000, 8), (99999999, 8),
                 (100000000, 9), (999999999, 9), (1000000000, 10),
                 (2147483647, 10), (2147483648, 10)]
        for magnitude, count in cases:
            with self.subTest(magnitude=magnitude):
                self.assertEqual(digit_count_magnitude(magnitude), count)

    def test_itoa_boundaries(self):
        cases = [-2147483648, -1000000000, -100000, -9999, -1000,
                 -100, -99, -10, -2, -1, 0, 1, 9, 10, 99, 100, 999,
                 1000, 9999, 10000, 99999, 100000, 999999, 1000000,
                 9999999, 10000000, 99999999, 100000000, 999999999,
                 1000000000, 2147483647]
        for value in cases:
            with self.subTest(value=value):
                if value == -1:
                    continue
                self.assertEqual(itoa_int32(value), str(value))

    def test_itoa_random_int32(self):
        rng = random.Random(51599)
        for _ in range(2000):
            value = rng.randint(-2147483648, 2147483647)
            with self.subTest(value=value):
                self.assertEqual(itoa_int32(value), str(value))

    def test_itoa_rejects_out_of_int32(self):
        for value in (-2147483649, 2147483648):
            with self.subTest(value=value):
                self.assertRaises(ValueError, itoa_int32, value)


class TestGroupKey(unittest.TestCase):
    def test_sum_group(self):
        self.assertEqual(group_key_text(-1), SUM_TEXT)

    def test_level_prefix(self):
        cases = [(-2147483648, b"L-2147483648"), (-2, b"L-2"),
                 (0, b"L0"), (1, b"L1"), (9, b"L9"), (10, b"L10"),
                 (123, b"L123"), (2147483647, b"L2147483647")]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(group_key_text(value), expected)
                self.assertTrue(group_key_text(value).startswith(KEY_PREFIX))

    def test_segment_key_shape(self):
        self.assertEqual(segment_key(3, b"alpha"),
                         SEGMENT_PREFIX + b"L3" + SEGMENT_DOT + b"alpha")
        self.assertEqual(segment_key(-1, b"beta"),
                         SEGMENT_PREFIX + SUM_TEXT + SEGMENT_DOT + b"beta")


class TestCompare(unittest.TestCase):
    def test_saturate_edges(self):
        self.assertEqual(saturate_length_diff(1 << 31), (1 << 31) - 1)
        self.assertEqual(saturate_length_diff((1 << 31) - 1), (1 << 31) - 1)
        self.assertEqual(saturate_length_diff(-(1 << 31)), -(1 << 31))
        self.assertEqual(saturate_length_diff(-(1 << 31) - 1), -(1 << 31))

    def test_compare_keys(self):
        self.assertEqual(compare_keys(b"a", b"a"), 0)
        self.assertEqual(compare_keys(b"a", b"b"), -1)
        self.assertEqual(compare_keys(b"b", b"a"), 1)
        self.assertEqual(compare_keys(b"ab", b"a"), 1)
        self.assertEqual(compare_keys(b"a", b"ab"), -1)
        self.assertEqual(compare_keys(b"a\xff", b"a\x00"), 1)

    def test_lower_bound(self):
        keys = [b"a", b"compaction.L3.alpha", b"compaction.L3.beta",
                b"z"]
        self.assertEqual(lower_bound_index(keys, b"compaction.L3.alpha"), 1)
        self.assertEqual(lower_bound_index(keys, b"compaction.L3.aa"), 1)
        self.assertEqual(lower_bound_index(keys, b"compaction.L3.beta"), 2)
        self.assertIsNone(lower_bound_index(keys, b"zz"))


class TestNamesAt(unittest.TestCase):
    def test_found(self):
        self.assertEqual(names_at(NAMES, 7), b"alpha")

    def test_missing_raises_map_at(self):
        with self.assertRaises(KeyError) as ctx:
            names_at(NAMES, 42)
        self.assertEqual(str(ctx.exception), "'map::at'")


class TestBuildEntries(unittest.TestCase):
    def test_end_to_end(self):
        groups = [(3, [(7, 1.5), (8, 2.25)]), (-1, [(7, 0.5)])]
        target = {}
        build_entries(groups, NAMES, target)
        self.assertEqual(target, {
            b"compaction.L3.alpha": "%f" % 1.5,
            b"compaction.L3.beta": "%f" % 2.25,
            b"compaction.Sum.alpha": "%f" % 0.5,
        })

    def test_replace_on_duplicate_segment(self):
        groups = [(3, [(7, 1.0)]), (3, [(7, 2.0)])]
        target = {}
        build_entries(groups, NAMES, target)
        self.assertEqual(target, {b"compaction.L3.alpha": "%f" % 2.0})

    def test_empty_groups(self):
        self.assertEqual(build_entries([], NAMES, {}), {})

    def test_missing_name_raises(self):
        with self.assertRaises(KeyError):
            build_entries([(3, [(42, 1.0)])], NAMES, {})

    def test_percent_f_format(self):
        self.assertEqual("%f" % 1.5, "1.500000")
        self.assertEqual("%f" % 0.0, "0.000000")
        self.assertEqual("%f" % -2.25, "-2.250000")

    def test_wrapper_returns_one(self):
        target = {}
        self.assertEqual(
            build_via_wrapper([(0, [(9, 3.0)])], NAMES, target), 1)
        self.assertEqual(target, {b"compaction.L0.gamma": "%f" % 3.0})


class TestPacket(unittest.TestCase):
    def test_checker_passes(self):
        result = subprocess.run(
            [sys.executable, os.path.join(PACKET, "verify.py"),
             "--binary", BINARY],
            capture_output=True, text=True, cwd=REPO)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpts_regenerate(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, os.path.join(PACKET, "export_excerpts.py"),
                 "--binary", os.path.relpath(BINARY, REPO),
                 "--out", tmp],
                capture_output=True, text=True, cwd=REPO)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
            for name in os.listdir(PACKET):
                if not name.endswith(".objdump.txt"):
                    continue
                with open(os.path.join(PACKET, name), "rb") as fh:
                    expected = fh.read()
                with open(os.path.join(tmp, name), "rb") as fh:
                    actual = fh.read()
                self.assertEqual(actual, expected, name)

    def test_corruption_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            import shutil
            copied = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, copied)
            with open(os.path.join(copied, "records.json"), "ab") as fh:
                fh.write(b" ")
            result = subprocess.run(
                [sys.executable, os.path.join(copied, "verify.py"),
                 "--binary", BINARY],
                capture_output=True, text=True, cwd=REPO)
            self.assertNotEqual(result.returncode, 0)
        with tempfile.TemporaryDirectory() as tmp:
            import shutil
            copied = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, copied)
            with open(os.path.join(copied, "window.objdump.txt"), "ab") as fh:
                fh.write(b" ")
            result = subprocess.run(
                [sys.executable, os.path.join(copied, "verify.py"),
                 "--binary", BINARY],
                capture_output=True, text=True, cwd=REPO)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
