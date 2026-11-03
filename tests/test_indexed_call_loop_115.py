"""Tests for the node #115 indexed call loop (0x5f6b520).

RE-001 work item. Runs under pytest or under plain python3 via the
__main__ runner below (pytest is not installed on this VM).
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import indexed_call_loop_115 as subject

PACKET = (Path(__file__).resolve().parent.parent / "research"
          / "work-items" / "RE-001-indexed-call-loop-115")


def recorder(calls):
    def callee(obj, a, b, c, flag, index):
        calls.append((a, b, c, flag, index))
    return callee


class LoopTests(unittest.TestCase):
    def test_zero_count_makes_no_call(self):
        calls = []
        self.assertIsNone(subject.indexed_call_loop(
            {"count": 0}, "a", "b", "c", 7, recorder(calls)))
        self.assertEqual(calls, [])

    def test_negative_count_makes_no_call(self):
        calls = []
        subject.indexed_call_loop(
            {"count": -3}, "a", "b", "c", 7, recorder(calls))
        self.assertEqual(calls, [])

    def test_stable_count_calls_indices_in_order_with_same_args(self):
        calls = []
        subject.indexed_call_loop(
            {"count": 3}, "a", "b", "c", 7, recorder(calls))
        self.assertEqual(calls, [("a", "b", "c", 7, 0),
                                 ("a", "b", "c", 7, 1),
                                 ("a", "b", "c", 7, 2)])

    def test_single_count_calls_index_zero_only(self):
        calls = []
        subject.indexed_call_loop(
            {"count": 1}, "a", "b", "c", 0, recorder(calls))
        self.assertEqual(calls, [("a", "b", "c", 0, 0)])

    def test_flag_passes_low_byte_only(self):
        calls = []
        subject.indexed_call_loop(
            {"count": 1}, "a", "b", "c", 0x1AB, recorder(calls))
        self.assertEqual(calls[0][3], 0xAB)

    def test_count_raised_mid_loop_extends_run(self):
        calls = []

        def callee(obj, a, b, c, flag, index):
            calls.append(index)
            if index == 0:
                obj["count"] = 5
        subject.indexed_call_loop(
            {"count": 2}, "a", "b", "c", 0, callee)
        self.assertEqual(calls, [0, 1, 2, 3, 4])

    def test_count_lowered_mid_loop_ends_run_early(self):
        calls = []

        def callee(obj, a, b, c, flag, index):
            calls.append(index)
            if index == 0:
                obj["count"] = 1
        subject.indexed_call_loop(
            {"count": 5}, "a", "b", "c", 0, callee)
        self.assertEqual(calls, [0])

    def test_count_zeroed_mid_loop_stops_after_current_call(self):
        calls = []

        def callee(obj, a, b, c, flag, index):
            calls.append(index)
            obj["count"] = 0
        subject.indexed_call_loop(
            {"count": 4}, "a", "b", "c", 0, callee)
        self.assertEqual(calls, [0])

    def test_count_lowered_to_next_index_stops(self):
        # After index 0, incremented index is 1; count 1 is not > 1.
        calls = []

        def callee(obj, a, b, c, flag, index):
            calls.append(index)
            if index == 0:
                obj["count"] = 1
        subject.indexed_call_loop(
            {"count": 9}, "a", "b", "c", 0, callee)
        self.assertEqual(calls, [0])

    def test_missing_count_raises(self):
        with self.assertRaises(ValueError):
            subject.indexed_call_loop(
                {}, "a", "b", "c", 0, recorder([]))

    def test_packet_checks(self):
        records = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(records["task"], "RE-001")
        self.assertEqual(records["node"], 115)
        self.assertEqual(
            records["census"]["driver_0x5f6b520"]["direct_calls"],
            ["0x5d607a9"])
        self.assertEqual(
            records["census"]["callee_0x5f6b000"]["direct_calls"],
            ["0x5f6b565"])
        main = (PACKET / "main.txt").read_text()
        self.assertIn("endbr64", main)
        self.assertIn("call   5f6b000", main)
        site = (PACKET / "caller-site.txt").read_text()
        self.assertIn("call   5f6b520", site)
        frames = (PACKET / "frames.txt").read_text()
        self.assertIn("pc=0000000005f6b520..0000000005f6b581", frames)


if __name__ == "__main__":
    unittest.main()
