#!/usr/bin/env python3
"""Tests for tools/snapshot_consumer_8360_115.py.

Run directly (pytest is not installed on this VM):
    python3 tests/test_snapshot_consumer_8360_115.py
"""

import math
import random
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import snapshot_consumer_8360_115 as subject

MASK64 = (1 << 64) - 1


def snapshot(**over):
    base = {
        "name": "test@0x1234#56",
        "capacity": 1048576,
        "prev_value": 1000000000,
        "last_value": 1500000000,
        "counts": [3, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        "values": [2048, 0, 1048576, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    }
    base.update(over)
    return base


class TestElapsed(unittest.TestCase):
    def test_forward(self):
        self.assertEqual(subject.elapsed_ns(100, 30), 70)

    def test_else_branch_is_zero_not_last(self):
        # Correction to open PR #3082, whose model returns `last` here.
        # The code is `mov $0x0,%edx; cmovae %rdx,%rax` (elapsed.txt
        # 0x5eee59b/0x5eee5a0): the else branch returns 0.
        self.assertEqual(subject.elapsed_ns(30, 100), 0)
        self.assertEqual(subject.elapsed_ns(50, 50), 0)
        self.assertEqual(subject.elapsed_ns(0, 0), 0)

    def test_max(self):
        self.assertEqual(subject.elapsed_ns(2**64 - 1, 0), 2**64 - 1)


class TestDivideBy1e6(unittest.TestCase):
    def test_boundaries(self):
        for v, want in ((0, 0), (1, 0), (10**6 - 1, 0), (10**6, 1),
                        (2**63, 9223372036854), (2**64 - 1, 18446744073709)):
            self.assertEqual(subject.divide_by_1e6(v), want)

    def test_random_matches_floor_div(self):
        rng = random.Random(8360)
        for _ in range(200000):
            v = rng.getrandbits(64)
            self.assertEqual(subject.divide_by_1e6(v), v // 1000000)


class TestU64ToF64(unittest.TestCase):
    def test_matches_float(self):
        rng = random.Random(115)
        values = [0, 1, 2**53 - 1, 2**53, 2**53 + 1, 2**63 - 1, 2**63,
                  2**64 - 1]
        values += [rng.getrandbits(64) for _ in range(200000)]
        for v in values:
            self.assertEqual(subject.u64_to_f64(v), float(v))


class TestToString(unittest.TestCase):
    def test_boundaries(self):
        cases = {0: "0", 9: "9", 10: "10", 99: "99", 100: "100",
                 999: "999", 1000: "1000", 9999: "9999",
                 100000: "100000", 10**18: "1000000000000000000",
                 2**64 - 1: "18446744073709551615",
                 12345678901234567890: "12345678901234567890"}
        for v, want in cases.items():
            self.assertEqual(subject.to_string_u64(v), want)

    def test_random_matches_str(self):
        rng = random.Random(8360)
        for _ in range(200000):
            v = rng.getrandbits(64)
            self.assertEqual(subject.to_string_u64(v), str(v))


class TestFormatPct(unittest.TestCase):
    def test_plain_values(self):
        # Cross-checked against C printf("%f") during development.
        self.assertEqual(subject.format_pct(500.0), "500.000000")
        self.assertEqual(subject.format_pct(0.1953125), "0.195312")
        self.assertEqual(subject.format_pct(100.0), "100.000000")
        self.assertEqual(subject.format_pct(0.0), "0.000000")
        self.assertEqual(subject.format_pct(1.0 / 3.0), "0.333333")
        self.assertEqual(subject.format_pct(2.0 / 3.0), "0.666667")

    def test_inf_and_nan(self):
        self.assertEqual(subject.format_pct(math.inf), "inf")
        self.assertEqual(subject.format_pct(subject._QNAN_NEG), "-nan")
        self.assertEqual(subject.format_pct(float("nan")), "nan")


class TestBuildMap(unittest.TestCase):
    def test_spot_render(self):
        got = subject.build_map(snapshot(), 2000000000)
        self.assertEqual(len(got), 46)
        self.assertEqual(got["di"], "test@0x1234#56")
        self.assertEqual(got["capacity"], "1048576")
        self.assertEqual(got["secs_for_last_collection"], "500.000000")
        self.assertEqual(got["secs_since_last_collection"], "500")
        self.assertEqual(got["count.data-block"], "3")
        self.assertEqual(got["bytes.data-block"], "2048")
        self.assertEqual(got["percent.data-block"], "0.195312")
        self.assertEqual(got["count.filter-meta-block"], "5")
        self.assertEqual(got["bytes.filter-meta-block"], "1048576")
        self.assertEqual(got["percent.filter-meta-block"], "100.000000")

    def test_zero_slots_still_produce_entries(self):
        # Unlike the twin's text dump, the sibling inserts all three
        # entries for every slot, including zero counts.
        got = subject.build_map(snapshot(), 2000000000)
        self.assertEqual(got["count.filter-block"], "0")
        self.assertEqual(got["bytes.filter-block"], "0")
        self.assertEqual(got["percent.filter-block"], "0.000000")
        self.assertEqual(got["count.misc"], "0")
        self.assertEqual(got["bytes.misc"], "0")
        self.assertEqual(got["percent.misc"], "0.000000")

    def test_elapsed_else_branch_gives_zero_ratio(self):
        snap = snapshot(prev_value=1500000000, last_value=1500000000)
        got = subject.build_map(snap, 2000000000)
        self.assertEqual(got["secs_for_last_collection"], "0.000000")

    def test_zero_capacity(self):
        snap = snapshot(capacity=0, values=[2048] + [0] * 13)
        got = subject.build_map(snap, 2000000000)
        self.assertEqual(got["percent.data-block"], "inf")
        self.assertEqual(got["percent.filter-block"], "-nan")

    def test_role_names_in_slot_order(self):
        self.assertEqual(len(subject.ROLE_NAMES), 14)
        self.assertEqual(subject.ROLE_NAMES[0], "data-block")
        self.assertEqual(subject.ROLE_NAMES[7],
                         "compression-dictionary-building-buffer")
        self.assertEqual(subject.ROLE_NAMES[13], "misc")
        got = subject.build_map(snapshot(), 2000000000)
        for role in subject.ROLE_NAMES:
            self.assertIn("count." + role, got)
            self.assertIn("bytes." + role, got)
            self.assertIn("percent." + role, got)

    def test_secs_since_wraps(self):
        snap = snapshot(last_value=2000000000)
        got = subject.build_map(snap, 1000000000)
        # slot_now - last_value wraps unsigned: (2**64 - 10**9) // 10**6.
        self.assertEqual(got["secs_since_last_collection"], "18446744072709")


if __name__ == "__main__":
    unittest.main(verbosity=1)
