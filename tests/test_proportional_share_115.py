"""Tests for the node #115 proportional share at 0x5f6ad70 (RE-001).

Runs under pytest when available; also runnable directly with plain
python3 (pytest is not installed on this VM), via the __main__ runner
below. Expectations are grounded in the verbatim excerpt in
research/work-items/RE-001-proportional-share-115/.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from proportional_share_115 import (  # noqa: E402
    MASK64,
    TWO63,
    ShareObject,
    proportional_share,
)


def share(total, hi, lo, count, entries):
    return proportional_share(ShareObject(total, hi, lo, count, entries))


def test_total_zero_returns_zero():
    assert share(0, 100, 0, 1, [(0, 800)]) == 0


def test_lo_ge_hi_returns_zero():
    assert share(10, 50, 50, 1, [(0, 800)]) == 0
    assert share(10, 50, 60, 1, [(0, 800)]) == 0


def test_nonpositive_count_returns_span():
    assert share(10, 100, 30, 0, [(0, 800)]) == 70
    assert share(10, 100, 30, -3, [(0, 800)]) == 70


def test_sum_not_above_total_returns_span():
    # One entry: (800 - 0) >> 3 == 100; total 100 >= 100, so span.
    assert share(100, 100, 30, 1, [(0, 800)]) == 70
    # Two entries summing to 50, below total 100.
    assert share(100, 100, 30, 2, [(0, 160), (10, 250)]) == 70


def test_proportional_truncation():
    # Sum 200 > total 100: 70 * 200 / 100 == 140 exactly.
    assert share(100, 100, 30, 1, [(0, 1600)]) == 140
    # Sum 150 > total 100: 70 * 150 / 100 == 105 exactly.
    assert share(100, 100, 30, 1, [(0, 1200)]) == 105
    # 70 * 101 / 100 == 70.7, truncated to 70.
    assert share(100, 100, 30, 1, [(0, 808)]) == 70


def test_negative_difference_uses_arithmetic_shift():
    # diff -8 >> 3 == -1, wrapping the running sum to 2**64 - 1, which
    # as an unsigned sum exceeds any small total, so the proportional
    # path runs: span * (2**64 - 1) / total overflows the u64 result
    # conversion and lands on 0 via the indefinite path.
    assert share(7, 100, 30, 1, [(8, 0)]) == 0


def test_wrapping_sum():
    # Each entry's signed difference is -8, so each contributes -1
    # after the arithmetic shift; the wrapping sum is 2**64 - 2, above
    # total 1, so the proportional value exceeds 2**64 and converts
    # to 0 via the indefinite path.
    big = (1 << 64) - 8
    assert share(1, 100, 30, 2, [(0, big), (0, big)]) == 0


def test_double_conversion_at_2_to_63_boundary():
    # span 2**63, sum 3, total 2: value 1.5 * 2**63 == 2**63 + 2**62,
    # which takes the subtract-then-set-bit-63 arm.
    assert share(2, TWO63, 0, 1, [(0, 24)]) == TWO63 + (1 << 62)
    # span 2**63, sum 2, total 1: value 2**64, at/above 2**64, so the
    # cvttsd2si indefinite flips to 0.
    assert share(1, TWO63, 0, 1, [(0, 16)]) == 0


def test_unsigned_double_rounding():
    # span 2**53 + 1 converts to the double 2**53 (round to nearest
    # even); sum 3, total 2 gives 3 * 2**52 exactly.
    assert share(2, (1 << 53) + 1, 0, 1, [(0, 24)]) == 3 * (1 << 52)


def test_only_first_count_entries_consumed():
    # count 1 ignores the second entry entirely.
    assert share(100, 100, 30, 1, [(0, 1600), (0, 8000)]) == 140


def test_short_entry_list_raises():
    try:
        share(100, 100, 30, 2, [(0, 1600)])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a short entry list")


def test_packet_records():
    packet = os.path.join(
        os.path.dirname(__file__), "..", "research", "work-items",
        "RE-001-proportional-share-115",
    )
    with open(os.path.join(packet, "records.json")) as fh:
        records = json.load(fh)
    assert records["windows"][0]["start"] == "0x5f6ad70"
    assert records["windows"][0]["end"] == "0x5f6aece"
    assert records["artifact"]["sha256_match"] is True
    excerpt = os.path.join(packet, records["windows"][0]["excerpt"])
    with open(excerpt) as fh:
        text = fh.read()
    assert "5f6ad70:" in text and "5f6aec9:" in text


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_")]
    for name, fn in tests:
        fn()
        print("PASS", name)
    print("ALL %d TESTS PASSED" % len(tests))
