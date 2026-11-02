"""Tests for tools/foundation_counters_uptime.py (node #94 0x5159180).

The expectations are transcribed from the window's disassembly
(see research/work-items/RE-001-counters-uptime-94/): the itoa
threshold ladder and digit-pair fill, the map::at name lookup,
the 3-node clock dispatch chain, the unsigned elapsed
conversion, the "%f" uptime formatting, and the ordered
find-or-insert map. The tests pin the model, not an execution of
the target binary (no execution is available here).
"""

import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from tools.foundation_counters_uptime import (
    ENTRY_COUNT,
    UPTIME_KEY,
    ChainExhausted,
    build_report,
    clock_dispatch,
    compare_keys,
    digit_count,
    format_secs,
    itoa,
    lower_bound_index,
    names_at,
    report_via_wrapper,
    saturate_length_diff,
    unsigned_elapsed,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    REPO, "research", "work-items", "RE-001-counters-uptime-94")

NAMES = {i: ("name%d" % i).encode() for i in range(ENTRY_COUNT)}
SENTINEL = 0xDEADBEEF


class TestItoa(unittest.TestCase):
    def test_digit_count_boundaries(self):
        cases = [0, 1, 9, 10, 99, 100, 999, 1000, 9999, 10000,
                 99999, 100000, 999999, 1000000, 9999999, 10000000,
                 99999999, 100000000, 999999999, 10 ** 12,
                 10 ** 18, 2 ** 64 - 1, 2 ** 63, 2 ** 63 - 1]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(digit_count(value), len(str(value)))

    def test_digit_count_random(self):
        rng = random.Random(5159180)
        for _ in range(2000):
            value = rng.getrandbits(64)
            self.assertEqual(digit_count(value), len(str(value)))

    def test_itoa_boundaries(self):
        cases = [0, 1, 9, 10, 99, 100, 999, 1000, 9999, 10000,
                 99999, 100000, 999999, 1000000, 9999999, 10000000,
                 99999999, 100000000, 999999999, 10 ** 12,
                 10 ** 18, 2 ** 64 - 1, 2 ** 63, 2 ** 63 - 1]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(itoa(value), str(value))

    def test_itoa_random(self):
        rng = random.Random(99180)
        for _ in range(2000):
            value = rng.getrandbits(64)
            self.assertEqual(itoa(value), str(value))


class TestCompare(unittest.TestCase):
    def test_saturate_edges(self):
        self.assertEqual(saturate_length_diff(1 << 31), (1 << 31) - 1)
        self.assertEqual(saturate_length_diff((1 << 31) - 1), (1 << 31) - 1)
        self.assertEqual(saturate_length_diff(-(1 << 31) - 1), -(1 << 31))
        self.assertEqual(saturate_length_diff(-(1 << 31)), -(1 << 31))
        self.assertEqual(saturate_length_diff(0), 0)

    def test_compare_keys(self):
        self.assertEqual(compare_keys(b"abc", b"abd"), -1)
        self.assertEqual(compare_keys(b"abd", b"abc"), 1)
        self.assertEqual(compare_keys(b"abc", b"abc"), 0)
        self.assertEqual(compare_keys(b"ab", b"abc"), -1)
        self.assertEqual(compare_keys(b"abcd", b"abc"), 1)
        self.assertEqual(compare_keys(b"", b"a"), -1)
        self.assertEqual(compare_keys(b"a", b""), 1)
        self.assertEqual(compare_keys(b"", b""), 0)

    def test_lower_bound_positions(self):
        keys = [b"a", b"c", b"e", b"g"]
        self.assertEqual(lower_bound_index(keys, b"a"), 0)
        self.assertEqual(lower_bound_index(keys, b"b"), 1)
        self.assertEqual(lower_bound_index(keys, b"e"), 2)
        self.assertEqual(lower_bound_index(keys, b"h"), None)
        self.assertEqual(lower_bound_index([], b"a"), None)


class TestNamesAndClock(unittest.TestCase):
    def test_names_at_present_and_missing(self):
        self.assertEqual(names_at(NAMES, 0), b"name0")
        self.assertEqual(names_at(NAMES, 8), b"name8")
        with self.assertRaises(KeyError) as caught:
            names_at(NAMES, 9)
        self.assertEqual(str(caught.exception), "'map::at'")

    def test_clock_dispatch_positions(self):
        self.assertEqual(
            clock_dispatch([100, 200, 300], SENTINEL), 100)
        self.assertEqual(
            clock_dispatch([SENTINEL, 200, 300], SENTINEL), 200)
        self.assertEqual(
            clock_dispatch([SENTINEL, SENTINEL, 300], SENTINEL), 300)
        with self.assertRaises(ChainExhausted):
            clock_dispatch([100, 200], SENTINEL)

    def test_unsigned_elapsed(self):
        self.assertEqual(unsigned_elapsed(1500000, 0), 1500000)
        self.assertEqual(unsigned_elapsed(0, 1), 2 ** 64 - 1)
        self.assertEqual(unsigned_elapsed(5, 5), 0)

    def test_format_secs_exact_cases(self):
        self.assertEqual(format_secs(0, 0), "0.000000")
        self.assertEqual(format_secs(1000000, 0), "1.000000")
        self.assertEqual(format_secs(1500000, 0), "1.500000")
        self.assertEqual(format_secs(1234567, 0), "1.234567")


class TestBuild(unittest.TestCase):
    def test_end_to_end(self):
        counters = [0, 9, 10, 99, 100, 9999, 10000, 123456789,
                    2 ** 64 - 1]
        target = {}
        result = build_report(counters, NAMES, target,
                              [SENTINEL, SENTINEL, 2500000], SENTINEL,
                              1000000)
        self.assertIs(result, target)
        expected = {NAMES[i]: itoa(counters[i]) for i in range(9)}
        expected[UPTIME_KEY] = "1.500000"
        self.assertEqual(target, expected)

    def test_missing_name_raises_before_mutation_past_it(self):
        counters = [1] * 9
        names = {i: ("n%d" % i).encode() for i in range(5)}
        with self.assertRaises(KeyError):
            build_report(counters, names, {}, [1, 2, 3], SENTINEL, 0)

    def test_wrapper_returns_one(self):
        counters = [7] * 9
        target = {}
        self.assertEqual(
            report_via_wrapper(counters, NAMES, target,
                               [4242, 0, 0], SENTINEL, 0), 1)
        self.assertEqual(target[b"name0"], "7")
        self.assertEqual(target[UPTIME_KEY], "0.004242")


class TestPacket(unittest.TestCase):
    def test_verify_passes(self):
        result = subprocess.run(
            [sys.executable, os.path.join(PACKET, "verify.py"),
             "--binary", "work/hl-node-94.bin"],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_corruption_controls(self):
        # (a) A flipped byte in the window excerpt must fail.
        # (b) A changed record count must fail (via the manifest).
        tmp = tempfile.mkdtemp()
        try:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, copy)
            window = os.path.join(copy, "window.objdump.txt")
            with open(window, "r+") as fh:
                text = fh.read()
                fh.seek(0)
                fh.write(text.replace("endbr64", "endbr65", 1))
            result = subprocess.run(
                [sys.executable, os.path.join(copy, "verify.py"),
                 "--binary", "work/hl-node-94.bin"],
                cwd=REPO, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

            # (b) runs on a fresh copy, so it proves the record
            # check itself, not the leftover excerpt corruption.
            shutil.rmtree(copy, ignore_errors=True)
            shutil.copytree(PACKET, copy)
            records = os.path.join(copy, "records.json")
            with open(records) as fh:
                text = fh.read()
            with open(records, "w") as fh:
                fh.write(text.replace('"count":9', '"count":8', 1))
            result = subprocess.run(
                [sys.executable, os.path.join(copy, "verify.py"),
                 "--binary", "work/hl-node-94.bin"],
                cwd=REPO, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
