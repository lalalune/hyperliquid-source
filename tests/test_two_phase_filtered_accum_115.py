"""Tests for the node #115 two-phase filtered accumulation model.

Runnable under plain python3 (pytest is not installed on this VM):
    python3 tests/test_two_phase_filtered_accum_115.py
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import two_phase_filtered_accum_115 as subject

PACKET = (
    Path(__file__).resolve().parents[1]
    / "research" / "work-items" / "RE-001-two-phase-filtered-accum-115"
)


def elt(f10=0, f80=0, f88=0, f90=0, f98=0):
    return {"f10": f10, "f80": f80, "f88": f88, "f90": f90,
            "f98": f98}


def run(groups, predicate=None, virtual=None):
    predicate = predicate or (lambda e: True)
    virtual = virtual or (lambda: subject.SENTINEL)
    return subject.scan(groups, predicate, virtual)


class TestAccumulatorLeaf(unittest.TestCase):
    def test_all_eight_updates(self):
        acc = subject.new_acc()
        subject.accumulate(acc, elt(f10=3, f80=10, f88=4, f90=7,
                                     f98=2))
        self.assertEqual(acc, {"f88": 3, "f90": 7, "f98": 2,
                               "fa0": 6, "fa8": 4, "fb0": 6,
                               "fb8": 4, "fc0": 1})

    def test_wrapping_subtraction(self):
        acc = subject.new_acc()
        acc["fa0"] = 5
        acc["fb0"] = 5
        subject.accumulate(acc, elt(f80=2, f88=9))
        wrap = (1 << 64) - 2
        self.assertEqual(acc["fa0"], wrap)
        self.assertEqual(acc["fb0"], wrap)
        self.assertEqual(acc["fa8"], 9)
        self.assertEqual(acc["fb8"], 9)

    def test_missing_field_is_guarded(self):
        acc = subject.new_acc()
        with self.assertRaises(ValueError):
            subject.accumulate(acc, {"f10": 1})


class TestScan(unittest.TestCase):
    def test_empty_count_runs_nothing(self):
        result = run([])
        self.assertEqual(result["phase2"], "not-run")
        self.assertEqual(result["log"]["predicate"], [])
        self.assertEqual(result["acc"], subject.new_acc())

    def test_predicate_false_never_accumulates_or_calls_virtual(self):
        seen = []
        result = run([[elt(f10=5), elt(f10=6)]],
                     predicate=lambda e: False,
                     virtual=lambda: seen.append(1) or 0)
        self.assertEqual(seen, [])
        self.assertEqual(result["acc"], subject.new_acc())
        # Phase 1 tests both elements, then phase 2 (f98 still 0)
        # tests both again in reverse; neither phase calls virtual.
        self.assertEqual(result["log"]["predicate"], [False] * 4)

    def test_phase2_reaccumulates_when_f98_stays_zero(self):
        # f98 == 0 throughout, so phase 2 runs the full reverse scan
        # and every match is accumulated a second time.
        groups = [[elt(f10=3, f88=1), elt(f10=4, f88=2)]]
        result = run(groups)
        self.assertEqual(result["phase2"], "complete")
        self.assertEqual(result["acc"]["f88"], 14)
        self.assertEqual(result["acc"]["fc0"], 4)
        self.assertEqual(len(result["log"]["accumulate"]), 4)

    def test_phase2_skipped_when_f98_nonzero(self):
        groups = [[elt(f10=3, f98=5)]]
        result = run(groups)
        self.assertEqual(result["phase2"], "skipped-f98-nonzero")
        self.assertEqual(result["acc"]["f98"], 5)
        self.assertEqual(result["acc"]["fc0"], 1)

    def test_phase2_stops_at_first_nonzero_f98_in_reverse(self):
        # Phase 1 caps at 20 matches before ever reaching the trailing
        # f98=7 element; phase 2 reverse-scans, hits that element
        # first, accumulates it, and stops at once without scanning
        # the 20 capped elements.
        groups = [[elt(f10=1)] * 20, [elt(f10=2, f98=7)]]
        result = run(groups, virtual=lambda: 7)
        self.assertEqual(result["phase2"], "stopped-at-nonzero-f98")
        self.assertEqual(result["acc"]["f98"], 7)
        self.assertEqual(result["acc"]["fc0"], 21)
        self.assertEqual(len(result["log"]["predicate"]), 21)

    def test_empty_groups_skipped_in_both_phases(self):
        groups = [[], [elt(f10=9)], []]
        result = run(groups)
        self.assertEqual(result["phase2"], "complete")
        self.assertEqual(result["acc"]["f88"], 18)
        self.assertEqual(result["acc"]["fc0"], 2)

    def test_nineteen_non_sentinel_do_not_cap(self):
        values = iter([1] * 19 + [subject.SENTINEL] * 40)
        groups = [[elt(f10=1)] * 19]
        result = run(groups, virtual=lambda: next(values))
        self.assertEqual(result["special"], 19)
        self.assertEqual(result["phase2"], "complete")

    def test_twentieth_non_sentinel_caps_phase1(self):
        # 25 matches, virtual returns non-sentinel every time: phase 1
        # stops after the 20th match, so the last 5 elements are never
        # phase-1 scanned; phase 2 then reverse-scans everything
        # (f98 stays 0) and accumulates all 25 once more.
        groups = [[elt(f10=1)] * 25]
        result = run(groups, virtual=lambda: 7)
        self.assertEqual(result["special"], 20)
        self.assertEqual(len(result["log"]["virtual"]), 20)
        self.assertEqual(result["acc"]["fc0"], 45)
        self.assertEqual(result["phase2"], "complete")

    def test_sentinel_does_not_count_toward_cap(self):
        values = iter([subject.SENTINEL] * 30 + [3] * 3)
        groups = [[elt(f10=1)] * 33]
        result = run(groups, virtual=lambda: next(values))
        self.assertEqual(result["special"], 3)
        self.assertEqual(result["phase2"], "complete")

    def test_cap_then_phase2_skipped_on_nonzero_f98(self):
        # Cap fires at the 20th match; that match carries f98=1, so
        # phase 2 is skipped at its entry gate.
        groups = [[elt(f10=1)] * 19 + [elt(f10=1, f98=1)]]
        result = run(groups, virtual=lambda: 7)
        self.assertEqual(result["special"], 20)
        self.assertEqual(result["phase2"], "skipped-f98-nonzero")
        self.assertEqual(result["acc"]["fc0"], 20)

    def test_packet_records(self):
        records = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(records["task"], "RE-001")
        self.assertEqual(records["windows"]["scan"]["start"], "0x5f77330")
        self.assertEqual(records["windows"]["leaf"]["start"], "0x5f6b590")
        self.assertEqual(records["sentinel"], "0x400000")
        self.assertEqual(records["special_cap"], 20)
        callers = (PACKET / "callers.tsv").read_text().splitlines()
        self.assertIn("scan\t0x5f88588\tcall", callers)
        self.assertIn("leaf\t0x5f773bd\tcall", callers)
        self.assertIn("leaf\t0x5f77508\tcall", callers)


if __name__ == "__main__":
    unittest.main()
