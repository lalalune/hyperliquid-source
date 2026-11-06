"""Tests for tools/selector_dispatch_6a820_115.py (node #115 dispatch 0x5f6a820).

Run with pytest when available, or directly: python3 this file.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from selector_dispatch_6a820_115 import (
    FOOTER_TAG, LengthError, SelectorDispatch, user_slice)


def bytewise(a, b):
    """memcmp-style oracle over slice values (data, length)."""
    left = a[0][:a[1]]
    right = b[0][:b[1]]
    if left == right:
        return 0
    return -1 if left < right else 1


def key(user_bytes):
    """An entry key whose stored size covers the user bytes + 8 footer."""
    return (user_bytes + b"\x00" * 8, len(user_bytes) + 8)


def disp(flag, count, entries, smallest, largest, find=None, compare=None):
    return SelectorDispatch(flag, count, entries, smallest, largest,
                            compare or bytewise,
                            find or (lambda built: 0))


def test_user_slice_derivation():
    assert user_slice((b"abcd", 12)) == (b"abcd", 4)
    assert user_slice((b"abcd", 8)) == (b"abcd", 0)
    # Wrapping subtraction, stated literally in the packet.
    assert user_slice((b"abcd", 0))[1] == (1 << 64) - 8


def test_scan_count_zero_returns_zero_without_consulting():
    calls = []
    d = disp(0, 0, [], (b"a", 1), (b"z", 1),
             compare=lambda a, b: calls.append((a, b)) or 1)
    assert d.run() == 0
    assert calls == []


def test_scan_skips_files_below_range():
    entries = [(key(b"b"), key(b"d")), (key(b"f"), key(b"h"))]
    # smallest "e": file 0 largest "d" < "e" -> skip; file 1 largest
    # "h" >= "e" -> candidate; largest "g" >= file 1 smallest "f" -> hit.
    assert disp(0, 2, entries, (b"e", 1), (b"g", 1)).run() == 1


def test_scan_all_files_below_range_returns_zero():
    entries = [(key(b"b"), key(b"d")), (key(b"f"), key(b"h"))]
    assert disp(0, 2, entries, (b"x", 1), (b"z", 1)).run() == 0


def test_scan_candidate_then_later_file_hits():
    entries = [(key(b"m"), key(b"p")), (key(b"b"), key(b"d"))]
    # File 0 is the first candidate (largest "p" >= smallest "c") but
    # its smallest "m" > range end "e": scan continues; file 1 hits.
    assert disp(0, 2, entries, (b"c", 1), (b"e", 1)).run() == 1


def test_scan_candidate_miss_everywhere_returns_zero():
    entries = [(key(b"m"), key(b"p"))]
    assert disp(0, 1, entries, (b"c", 1), (b"e", 1)).run() == 0


def test_scan_candidate_with_null_largest_returns_one():
    entries = [(key(b"m"), key(b"p"))]
    assert disp(0, 1, entries, (b"c", 1), None).run() == 1


def test_scan_equal_bounds_count_as_overlap():
    entries = [(key(b"b"), key(b"d"))]
    # smallest == file largest, and largest == file smallest: both
    # boundary comparisons are inclusive in the native code.
    assert disp(0, 1, entries, (b"d", 1), (b"b", 1)).run() == 1


def test_null_start_null_largest_returns_one():
    entries = [(key(b"m"), key(b"p"))]
    assert disp(0, 1, entries, None, None).run() == 1


def test_null_start_scans_for_any_file_not_above_end():
    entries = [(key(b"m"), key(b"p")), (key(b"b"), key(b"d"))]
    assert disp(0, 2, entries, None, (b"c", 1)).run() == 1
    assert disp(0, 2, entries, None, (b"a", 1)).run() == 0


def test_find_arm_built_string_is_exact():
    seen = []
    entries = [(key(b"b"), key(b"d"))]
    d = disp(1, 1, entries, (b"key", 3), (b"z", 1),
             find=lambda built: seen.append(built) or 0)
    assert d.run() == 1
    assert seen == [b"key" + bytes([FOOTER_TAG]) + b"\xf8" + b"\xff" * 6]


def test_find_arm_index_past_count_returns_zero():
    entries = [(key(b"b"), key(b"d"))]
    assert disp(1, 1, entries, (b"a", 1), (b"z", 1),
                find=lambda built: 1).run() == 0
    assert disp(1, 1, entries, (b"a", 1), (b"z", 1),
                find=lambda built: 7).run() == 0


def test_find_arm_result_is_masked_to_32_bits():
    entries = [(key(b"b"), key(b"d"))]
    d = disp(1, 1, entries, (b"a", 1), (b"z", 1),
             find=lambda built: (1 << 32) | 0)
    assert d.run() == 1


def test_find_arm_null_largest_returns_the_flag():
    entries = [(key(b"b"), key(b"d"))]
    assert disp(1, 1, entries, (b"a", 1), None,
                find=lambda built: 0).run() == 1
    # Any nonzero flag takes this arm and is itself returned here.
    assert disp(2, 1, entries, (b"a", 1), None,
                find=lambda built: 0).run() == 2


def test_find_arm_single_file_compare_decides():
    entries = [(key(b"m"), key(b"p")), (key(b"b"), key(b"d"))]
    # find lands on file 1: its smallest "b" <= range end "c" -> 1.
    assert disp(1, 2, entries, (b"a", 1), (b"c", 1),
                find=lambda built: 1).run() == 1
    # find lands on file 0: its smallest "m" > range end "c" -> 0.
    assert disp(1, 2, entries, (b"a", 1), (b"c", 1),
                find=lambda built: 0).run() == 0


def test_find_arm_null_start_checks_file_zero_only():
    entries = [(key(b"m"), key(b"p")), (key(b"b"), key(b"d"))]
    # No find call happens; file 0 smallest "m" > end "c" -> 0 even
    # though file 1 would match.
    assert disp(1, 2, entries, None, (b"c", 1)).run() == 0
    assert disp(1, 2, entries, None, (b"n", 1)).run() == 1
    # Null end with a null start returns the flag at file 0.
    assert disp(1, 2, entries, None, None).run() == 1
    # Count 0 returns 0 before any of this.
    assert disp(1, 0, [], None, None).run() == 0


def test_build_length_guard():
    entries = [(key(b"b"), key(b"d"))]
    d = disp(1, 1, entries, (b"a", 0x4000000000000000), (b"z", 1),
             find=lambda built: 0)
    try:
        d.run()
    except LengthError:
        pass
    else:
        raise AssertionError("expected LengthError")


def test_packet_records_match_model_windows():
    here = os.path.dirname(os.path.abspath(__file__))
    rec = json.load(open(os.path.join(
        here, "..", "research", "work-items",
        "RE-001-selector-dispatch-6a820-115", "records.json")))
    assert rec["windows"]["dispatch"]["start"] == "0x5f6a820"
    assert rec["windows"]["dispatch"]["stop"] == "0x5f6abac"
    assert rec["census"]["dispatch"]["direct_calls"] == []
    assert rec["census"]["dispatch"]["tail_jumps"] == ["0x5f6c2d7"]
    assert rec["census"]["find"]["direct_calls"] == [
        "0x5f69d9d", "0x5f6a37d", "0x5f6a9a4"]


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]

if __name__ == "__main__":
    for fn in TESTS:
        fn()
    print("%d model checks pass" % len(TESTS))
