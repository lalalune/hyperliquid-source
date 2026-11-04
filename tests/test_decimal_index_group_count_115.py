"""Tests for the node #115 decimal-index group-count model.

Run with pytest, or directly with plain python3 (no pytest installed
on this VM): ``python3 tests/test_decimal_index_group_count_115.py``
prints ``N tests passed`` on success.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from decimal_index_group_count_115 import (  # noqa: E402
    decimal_index_group_count,
    parse_decimal_u64,
)

PACKET_DIR = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-decimal-index-group-count-115"

GROUPS = [(1000, 1000 + 8 * 3), (2000, 2000 + 8 * 5), (3000, 3000)]


def test_parse_plain_index():
    assert parse_decimal_u64(b"42") == (True, 42, b"")


def test_parse_leading_zeros():
    assert parse_decimal_u64(b"007") == (True, 7, b"")


def test_parse_max_u64():
    assert parse_decimal_u64(b"18446744073709551615") == (
        True,
        18446744073709551615,
        b"",
    )


def test_parse_overflow_rejects():
    ok, value, rest = parse_decimal_u64(b"18446744073709551616")
    assert ok is False and value is None and rest == b"6"


def test_parse_overflow_threshold_digit():
    ok, value, rest = parse_decimal_u64(b"184467440737095516150")
    assert ok is False and value is None


def test_parse_empty_and_nondigit_fail():
    assert parse_decimal_u64(b"") == (False, 0, b"")
    assert parse_decimal_u64(b"x") == (False, 0, b"x")


def test_parse_trailing_garbage_left_as_rest():
    assert parse_decimal_u64(b"12x") == (True, 12, b"x")


def test_caller_formats_indexed_group_count():
    assert decimal_index_group_count(10, GROUPS, b"1") == (True, "5")


def test_caller_zero_index_and_empty_group():
    assert decimal_index_group_count(10, GROUPS, b"0") == (True, "3")
    assert decimal_index_group_count(10, GROUPS, b"2") == (True, "0")


def test_caller_at_or_above_bound_fails_unchanged():
    assert decimal_index_group_count(2, GROUPS, b"2") == (False, None)
    assert decimal_index_group_count(2, GROUPS, b"9") == (False, None)


def test_caller_trailing_garbage_and_parse_failure_fail():
    assert decimal_index_group_count(10, GROUPS, b"1x") == (False, None)
    assert decimal_index_group_count(10, GROUPS, b"") == (False, None)
    assert decimal_index_group_count(10, GROUPS, b"18446744073709551616") == (
        False,
        None,
    )


def test_caller_odd_byte_span_shifts():
    groups = [(500, 500 + 8 * 3 + 4)]
    assert decimal_index_group_count(10, groups, b"0") == (True, "3")


def test_caller_negative_index32_guarded():
    try:
        decimal_index_group_count(10, GROUPS, b"2147483648")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative index32")


def test_caller_missing_group_guarded():
    try:
        decimal_index_group_count(100, GROUPS, b"7")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for out-of-range index")


def test_packet_records_match_model():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    )
    starts = [w["start"] for w in records["windows"]]
    assert "0x5eeb9c0" in starts and "0x61d0df0" in starts
    assert records["census"]["0x5eeb9c0"]["direct_calls"] == []
    assert "0x5eeba04" in records["census"]["0x61d0df0"]["direct_calls"]
    assert records["rodata_format"]["address"] == "0x4464ad"
    assert records["rodata_format"]["bytes"] == "%d"


def test_packet_excerpts_present():
    caller = (PACKET_DIR / "function_0x5eeb9c0.txt").read_text()
    assert "5eeb9c0:" in caller and "5eeba04" in caller
    parser = (PACKET_DIR / "function_0x61d0df0.txt").read_text()
    assert "61d0df0:" in parser and "61d0e0c" in parser


TESTS = [
    test_parse_plain_index,
    test_parse_leading_zeros,
    test_parse_max_u64,
    test_parse_overflow_rejects,
    test_parse_overflow_threshold_digit,
    test_parse_empty_and_nondigit_fail,
    test_parse_trailing_garbage_left_as_rest,
    test_caller_formats_indexed_group_count,
    test_caller_zero_index_and_empty_group,
    test_caller_at_or_above_bound_fails_unchanged,
    test_caller_trailing_garbage_and_parse_failure_fail,
    test_caller_odd_byte_span_shifts,
    test_caller_negative_index32_guarded,
    test_caller_missing_group_guarded,
    test_packet_records_match_model,
    test_packet_excerpts_present,
]


def main():
    for test in TESTS:
        test()
    print("%d tests passed" % len(TESTS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
