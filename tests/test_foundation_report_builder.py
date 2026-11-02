"""Tests for tools/foundation_report_builder.py (node #94 0x5157d30).

The expectations are transcribed from the window's disassembly
(see research/work-items/RE-001-report-builder-94/): the itoa
threshold ladder and digit-pair fill, the magic /1,000,000
division, the accessor clamp, the "%f" ratio formatting, and the
ordered find-or-insert map. The tests pin the model, not an
execution of the target binary (no execution is available here).
"""

import math
import random
import unittest

from tools.foundation_report_builder import (
    ENTRY_COUNT,
    ReportMap,
    Snapshot,
    accessor_window,
    build_report,
    compare_keys,
    digit_count,
    format_f,
    itoa,
    magic_div_1e6,
    unsigned_to_double,
)

NAMES = ["alpha", "beta", "gamma", "delta", "e1", "e2", "e3", "e4",
         "e5", "e6", "e7", "e8", "e9", "e10"]


class TestItoa(unittest.TestCase):
    def test_boundaries(self):
        cases = [0, 1, 9, 10, 99, 100, 999, 1000, 9999, 10000,
                 99999, 100000, 999999, 1000000, 9999999, 10000000,
                 99999999, 100000000, 999999999, 10 ** 18,
                 2 ** 64 - 1, 2 ** 63, 2 ** 63 - 1]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(itoa(value), str(value))
                self.assertEqual(digit_count(value), len(str(value)))

    def test_random_against_str(self):
        rng = random.Random(5157)
        for _ in range(2000):
            value = rng.getrandbits(rng.choice([4, 8, 16, 32, 64]))
            self.assertEqual(itoa(value), str(value))

    def test_digit_count_ladder(self):
        self.assertEqual([digit_count(v) for v in
                          (9, 10, 99, 100, 999, 1000, 9999, 10000)],
                         [1, 2, 2, 3, 3, 4, 4, 5])


class TestConversions(unittest.TestCase):
    def test_magic_div(self):
        cases = [0, 1, 999999, 1000000, 1999999, 2000000, 10 ** 12,
                 2 ** 63, 2 ** 64 - 1, 123456789012345678]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(magic_div_1e6(value), value // 1000000)
        rng = random.Random(94)
        for _ in range(2000):
            value = rng.getrandbits(64)
            self.assertEqual(magic_div_1e6(value), value // 1000000)

    def test_unsigned_to_double(self):
        self.assertEqual(unsigned_to_double(0), 0.0)
        self.assertEqual(unsigned_to_double(2 ** 63), float(2 ** 63))
        self.assertEqual(unsigned_to_double(2 ** 64 - 1),
                         float(2 ** 64 - 1))

    def test_accessor_window(self):
        snap = Snapshot(commit=1000, last_secs_raw=400)
        self.assertEqual(accessor_window(snap), 600)
        snap = Snapshot(commit=400, last_secs_raw=1000)
        self.assertEqual(accessor_window(snap), 0)
        snap = Snapshot(commit=1000, last_secs_raw=1000)
        self.assertEqual(accessor_window(snap), 0)
        # Unsigned wrap: commit smaller as unsigned is clamped, not
        # a huge wrapped difference.
        snap = Snapshot(commit=0, last_secs_raw=2 ** 64 - 1)
        self.assertEqual(accessor_window(snap), 0)

    def test_format_f(self):
        self.assertEqual(format_f(12.5), "12.500000")
        self.assertEqual(format_f(0.0), "0.000000")
        self.assertEqual(format_f(float("inf")), "inf")
        self.assertTrue(math.isnan(float(format_f(float("nan")))) or
                        format_f(float("nan")) == "nan")


class TestCompareAndMap(unittest.TestCase):
    def test_compare_matches_bytes_order(self):
        keys = [b"a", b"ab", b"b", b"count.alpha", b"count.beta",
                b"bytes.alpha", b"percent.alpha", b""]
        for a in keys:
            for b in keys:
                sign = (a > b) - (a < b)
                self.assertEqual(compare_keys(a, b), sign)

    def test_map_keeps_ascending_order(self):
        m = ReportMap()
        for key in ["percent.gamma", "id", "count.alpha", "capacity",
                    "bytes.alpha", "count.alpha"]:
            m.find_or_insert(key)
        self.assertEqual([k for k, _ in m.items()],
                         sorted(["percent.gamma", "id", "count.alpha",
                                 "capacity", "bytes.alpha"]))

    def test_find_or_insert_reuses(self):
        m = ReportMap()
        _, new1 = m.find_or_insert("count.alpha")
        _, new2 = m.find_or_insert("count.alpha")
        self.assertTrue(new1)
        self.assertFalse(new2)


class TestBuildReport(unittest.TestCase):
    def test_header_entries(self):
        snap = Snapshot(denominator=2500, identity="node@0x1#42",
                        last_secs_raw=100, commit=1300100)
        # clock - commit = 2,000,000 -> secs_since = 2
        report = build_report(snap, NAMES, clock_value=3300100)
        d = report.as_dict()
        self.assertEqual(d["id"], "node@0x1#42")
        self.assertEqual(d["capacity"], "2500")
        # window = 1300000 us -> 1.3 s, formatted "%f"
        self.assertEqual(d["secs_for_last_collection"], "1.300000")
        self.assertEqual(d["secs_since_last_collection"], "2")

    def test_entry_phases(self):
        snap = Snapshot(denominator=200, identity="x",
                        values=[50] + [0] * 13,
                        counters=[7] + [0] * 13)
        d = build_report(snap, NAMES, clock_value=0).as_dict()
        self.assertEqual(d["count.alpha"], "7")
        self.assertEqual(d["bytes.alpha"], "50")
        # 50 * 100.0 / 200 = 25.0
        self.assertEqual(d["percent.alpha"], "25.000000")
        self.assertEqual(d["count.beta"], "0")
        self.assertEqual(d["percent.beta"], "0.000000")

    def test_zero_denominator_gives_inf(self):
        snap = Snapshot(denominator=0, identity="x",
                        values=[5] + [0] * 13)
        d = build_report(snap, NAMES, clock_value=0).as_dict()
        self.assertEqual(d["percent.alpha"], "inf")
        snap = Snapshot(denominator=0, identity="x")
        d = build_report(snap, NAMES, clock_value=0).as_dict()
        self.assertEqual(d["percent.alpha"], "nan")

    def test_loop_covers_all_entries(self):
        snap = Snapshot(denominator=1000, identity="x",
                        values=list(range(14)),
                        counters=[100 + i for i in range(14)])
        d = build_report(snap, NAMES, clock_value=0).as_dict()
        for i, name in enumerate(NAMES):
            self.assertEqual(d["count." + name], str(100 + i))
            self.assertEqual(d["bytes." + name], str(i))
            self.assertEqual(d["percent." + name],
                             "%f" % (i * 100.0 / 1000))
        self.assertEqual(len(d), 4 + 3 * ENTRY_COUNT)

    def test_large_values(self):
        snap = Snapshot(denominator=2 ** 64 - 1, identity="x",
                        values=[2 ** 64 - 1] + [0] * 13,
                        counters=[2 ** 64 - 1] + [0] * 13)
        d = build_report(snap, NAMES, clock_value=0).as_dict()
        self.assertEqual(d["count.alpha"], str(2 ** 64 - 1))
        self.assertEqual(d["bytes.alpha"], str(2 ** 64 - 1))
        self.assertEqual(d["percent.alpha"], "100.000000")

    def test_name_count_validation(self):
        snap = Snapshot()
        with self.assertRaises(ValueError):
            build_report(snap, NAMES[:13], clock_value=0)


if __name__ == "__main__":
    unittest.main()
