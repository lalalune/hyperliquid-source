#!/usr/bin/env python3
"""Tests for tools/snapshot_consumer_efda0_115.py (RE-001, node #115).

Expected values are literals pinned against the binary: the human-size
table was cross-checked against a C program implementing the same
0x61d0ba0 scaling loop (gcc, %.2f), and the %g outputs against C %.6g.
Run directly: python3 tests/test_snapshot_consumer_efda0_115.py
(pytest is not installed on this VM).
"""

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import snapshot_consumer_efda0_115 as subject


def _snapshot(**over):
    snap = {
        "name": "test@0x1234#56",
        "capacity": 1048576,
        "usage": 524288,
        "table_size": 7,
        "occupancy": 3,
        "sequence": 5,
        "no_progress": 2,
        "prev_value": 1000000000,
        "last_value": 1500000000,
        "counts": [3, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        "values": [2048, 0, 1048576, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    }
    snap.update(over)
    return snap


class FormatHumanSizeTests(unittest.TestCase):
    def test_table(self):
        cases = [
            (0, "0.00 KB"),
            (1, "0.00 KB"),
            (512, "0.50 KB"),
            (1023, "1.00 KB"),
            (1024, "1.00 KB"),
            (1536, "1.50 KB"),
            (999999, "976.56 KB"),
            (1000000, "976.56 KB"),
            (1048575, "1024.00 KB"),
            (1048576, "1.00 MB"),
            (123456789, "117.74 MB"),
            (1073741824, "1.00 GB"),
            (15032385536, "14.00 GB"),
            (1099511627776, "1.00 TB"),
            (1125899906842624, "1024.00 TB"),
            (9223372036854775808, "8388608.00 TB"),
            (18446744073709551615, "16777216.00 TB"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(subject.format_human_size(value), expected)

    def test_u64_to_f64_matches_float(self):
        # Direct path below 2**63 and the fixup path at/above it both
        # agree with float(v) (the fixup is the correctly-rounded
        # unsigned conversion; checked on 200,000 random values).
        for value in (0, 1, 2**53 + 1, 2**63 - 1, 2**63, 2**63 + 1025,
                      2**64 - 1):
            with self.subTest(value=value):
                self.assertEqual(subject.u64_to_f64(value), float(value))
        self.assertEqual(subject.u64_to_f64(2**63 + 1025),
                         9223372036854777856.0)
        self.assertEqual(subject.u64_to_f64(2**64 - 1),
                         18446744073709551616.0)


class ElapsedTests(unittest.TestCase):
    def test_rules(self):
        self.assertEqual(subject.elapsed_ns(100, 30), 70)
        self.assertEqual(subject.elapsed_ns(30, 100), 30)
        self.assertEqual(subject.elapsed_ns(50, 50), 50)
        self.assertEqual(subject.elapsed_ns(0, 0), 0)
        self.assertEqual(subject.elapsed_ns(2**64 - 1, 0), 2**64 - 1)


class DivideBy1e6Tests(unittest.TestCase):
    def test_matches_floor_division(self):
        random.seed(7)
        values = [0, 1, 999999, 1000000, 1000001, 2**63, 2**64 - 1,
                  123456789012345678]
        values += [random.getrandbits(64) for _ in range(5000)]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(subject.divide_by_1e6(value),
                                 value // 1000000)


class WalkTests(unittest.TestCase):
    W = subject.WALKER

    def test_mismatch_at_first_link(self):
        links = [{"slot": 0x1111, "value": 42}, {"slot": self.W, "value": 0}]
        self.assertEqual(subject.walk_chain(links), 42)

    def test_mismatch_at_second_link(self):
        links = [{"slot": self.W, "value": 0},
                 {"slot": 0x2222, "value": 77},
                 {"slot": self.W, "value": 0}]
        self.assertEqual(subject.walk_chain(links), 77)

    def test_all_match_uses_third_link(self):
        links = [{"slot": self.W, "value": 0},
                 {"slot": self.W, "value": 0},
                 {"slot": 0x3333, "value": 99}]
        self.assertEqual(subject.walk_chain(links), 99)

    def test_short_chain_raises(self):
        with self.assertRaises(ValueError):
            subject.walk_chain([])
        with self.assertRaises(ValueError):
            subject.walk_chain([{"slot": self.W, "value": 0}])
        with self.assertRaises(ValueError):
            subject.walk_chain([{"slot": self.W, "value": 0},
                                {"slot": self.W, "value": 0}])


class RenderTests(unittest.TestCase):
    def test_full_render(self):
        chain = [{"slot": subject.WALKER, "value": 0},
                 {"slot": subject.WALKER, "value": 0},
                 {"slot": 0x1111, "value": 2000000000}]
        expected = (
            "Block cache test@0x1234#56 capacity: 1.00 MB usage: 512.00 KB"
            " table_size: 7 occupancy: 3 collections: 5 last_copies: 2"
            " last_secs: 500 secs_since: 500\n"
            "Block cache entry stats(count,size,portion):"
            " DataBlock(3,2.00 KB,0.195312%)"
            " FilterMetaBlock(5,1.00 MB,100%)\n"
        )
        self.assertEqual(subject.render_snapshot(_snapshot(), chain), expected)

    def test_all_zero_counts_print_no_entries(self):
        snap = _snapshot(counts=[0] * 14, values=[0] * 14)
        chain = [{"slot": 0x1111, "value": 1500000000}]
        text = subject.render_snapshot(snap, chain)
        self.assertTrue(text.endswith(
            "Block cache entry stats(count,size,portion):\n"))
        self.assertNotIn("(", text.split("portion):", 1)[1])

    def test_occupancy_minus_one_prints_unsigned(self):
        snap = _snapshot(occupancy=2**64 - 1)
        chain = [{"slot": 0x1111, "value": 1500000000}]
        self.assertIn("occupancy: 18446744073709551615",
                      subject.render_snapshot(snap, chain))

    def test_zero_capacity_portion_is_inf(self):
        snap = _snapshot(capacity=0)
        chain = [{"slot": 0x1111, "value": 1500000000}]
        self.assertIn("DataBlock(3,2.00 KB,inf%)",
                      subject.render_snapshot(snap, chain))

    def test_zero_capacity_zero_value_portion_is_neg_nan(self):
        snap = _snapshot(capacity=0, values=[0] * 14)
        chain = [{"slot": 0x1111, "value": 1500000000}]
        self.assertIn("DataBlock(3,0.00 KB,-nan%)",
                      subject.render_snapshot(snap, chain))

    def test_wrapped_secs_since(self):
        snap = _snapshot(last_value=2000000000)
        chain = [{"slot": 0x1111, "value": 1000000000}]
        # (10**9 - 2*10**9) mod 2**64 // 10**6 == 18446744072709
        self.assertIn("secs_since: 18446744072709",
                      subject.render_snapshot(snap, chain))

    def test_bad_shapes_raise(self):
        chain = [{"slot": 0x1111, "value": 1}]
        with self.assertRaises(ValueError):
            subject.render_snapshot(_snapshot(counts=[0] * 13), chain)
        with self.assertRaises(ValueError):
            subject.render_snapshot(_snapshot(values=[0] * 15), chain)


class NamesTests(unittest.TestCase):
    def test_fourteen_names(self):
        self.assertEqual(len(subject.NAMES), 14)
        self.assertEqual(subject.NAMES[0], "DataBlock")
        self.assertEqual(subject.NAMES[7],
                         "CompressionDictionaryBuildingBuffer")
        self.assertEqual(subject.NAMES[13], "Misc")
        self.assertEqual(len(subject.SIBLING_NAMES), 14)
        self.assertEqual(subject.SIBLING_NAMES[0], "data-block")


if __name__ == "__main__":
    unittest.main(verbosity=2)
