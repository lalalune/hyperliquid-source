"""Tests for the node #115 need-score predicate at 0x5dbd6d0 (RE-001).

Runs under pytest when available, and under plain python3 via the
``__main__`` runner below (pytest is not installed on this VM).
"""
import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from need_score_predicate_115 import (  # noqa: E402
    level_gate, need_sum, predicate)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-need-score-predicate-115")

ZERO_NEEDS = [(0, 0, 0)] * 5


def obj(needs=ZERO_NEEDS, flag=0, count=0, scores=None):
    return {"needs": list(needs), "flag": flag, "count": count,
            "scores": list(scores if scores is not None else [])}


def test_first_need_nonzero_returns_1():
    assert predicate(obj(needs=[(16, 0, 0)] + [(0, 0, 0)] * 4)) == 1


def test_each_later_need_nonzero_returns_1():
    for i in range(1, 5):
        needs = [(0, 0, 0)] * 5
        needs[i] = (0, 32, 0)
        assert predicate(obj(needs=needs)) == 1


def test_wrapped_need_summing_to_zero_does_not_trigger():
    # Native order is first minus second: (0 - 16) >> 4 = -1, + base 1
    # wraps to 0: the jne sees zero.
    assert predicate(obj(needs=[(0, 16, 1)] + [(0, 0, 0)] * 4,
                         flag=0, count=1, scores=[])) == 0


def test_need_shift_is_arithmetic_not_logical():
    # A negative difference shifts arithmetically: (0 - 32) >> 4 = -2,
    # + 2 = 0.
    assert need_sum(0, 32, 2) == 0
    # A positive difference: (48 - 0) >> 4 = 3.
    assert need_sum(48, 0, 0) == 3


def test_operand_order_matches_native():
    # Cases where first-minus-second and second-minus-first disagree
    # on the zero test, read straight off the native operand order
    # (mov first, sub second): both must fall through to the scan and
    # then return 0 via the negative bound, while the flipped order
    # would return 1 from the need sum.
    assert predicate(obj(needs=[(0, 16, 1)] + [(0, 0, 0)] * 4,
                         flag=0, count=1, scores=[])) == 0
    assert predicate(obj(needs=[(16, 0, -1)] + [(0, 0, 0)] * 4,
                         flag=0, count=1, scores=[])) == 0
    # And the same sums with a base that does not cancel must trigger.
    assert predicate(obj(needs=[(0, 16, 2)] + [(0, 0, 0)] * 4)) == 1
    assert predicate(obj(needs=[(16, 0, 0)] + [(0, 0, 0)] * 4)) == 1


def test_flag_set_bound_zero_scans_only_first_score():
    assert predicate(obj(flag=1, scores=[0.5])) == 0
    assert predicate(obj(flag=1, scores=[1.0])) == 1
    assert predicate(obj(flag=1, scores=[0.5, 9.0])) == 0


def test_score_at_threshold_returns_1():
    assert predicate(obj(flag=0, count=5, scores=[0.1, 0.2, 0.3, 1.0])) == 1
    assert predicate(obj(flag=0, count=5, scores=[0.1, 0.2, 0.3, 2.5])) == 1


def test_all_scores_below_threshold_returns_0():
    assert predicate(obj(flag=0, count=5, scores=[0.1, 0.2, 0.3, 0.9])) == 0


def test_negative_bound_reads_no_score():
    assert predicate(obj(flag=0, count=1, scores=[])) == 0
    assert predicate(obj(flag=0, count=0, scores=[])) == 0


def test_nan_score_does_not_satisfy_the_compare():
    nan = float("nan")
    assert predicate(obj(flag=1, scores=[nan])) == 0
    assert predicate(obj(flag=0, count=4, scores=[nan, 1.5])) == 1


def test_level_gate():
    assert level_gate({"flag": 1, "count": 100}) == 0
    assert level_gate({"flag": 0, "count": 5}) == 3
    assert level_gate({"flag": 0, "count": 1}) == -1
    # 32-bit wrap: count = -2**31, minus 2 wraps to 2**31 - 2 (positive).
    assert level_gate({"flag": 0, "count": -(1 << 31)}) == 2147483646
    # count = 2**31 - 1 is out of the signed 32-bit range in the model,
    # but the wrap arithmetic still holds: (2**31 - 1 - 2) = 2**31 - 3.
    assert level_gate({"flag": 0, "count": (1 << 31) - 1}) == 2147483645


def test_missing_field_guard():
    for bad in ({"flag": 0, "count": 0}, {"needs": ZERO_NEEDS, "count": 0},
                {"needs": [(0, 0, 0)] * 4, "flag": 0, "count": 0, "scores": []}):
        try:
            predicate(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for %r" % (bad,))


def test_score_scan_past_end_is_a_guard_error():
    try:
        predicate(obj(flag=0, count=10, scores=[0.5]))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_packet_files_present():
    for name in ("README.md", "records.json", "MANIFEST.sha256",
                 "verify.py", "export_excerpts.py", "census.py",
                 "frames.txt", "relocations.txt",
                 os.path.join("excerpts", "predicate.txt"),
                 os.path.join("excerpts", "helper.txt")):
        assert os.path.isfile(os.path.join(PACKET, name)), name
    records = json.load(open(os.path.join(PACKET, "records.json")))
    assert records["windows"]["predicate"]["start"] == "0x5dbd6d0"
    assert records["windows"]["gate"]["start"] == "0x5f6b720"


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for name, fn in tests:
        fn()
        print("ok:", name)
    print("ALL %d TESTS PASSED" % len(tests))
