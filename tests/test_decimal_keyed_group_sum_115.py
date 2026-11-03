"""Tests for node #115's decimal-keyed group sum (tools/decimal_keyed_group_sum_115.py).

Pytest-style, with a plain-python __main__ runner (pytest is not
installed on this VM), matching the style of the neighbouring
test_decimal_index_group_count_115.py.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from decimal_keyed_group_sum_115 import (
    U64_MAX,
    format_result,
    keyed_group_sum,
    parse_decimal_u64,
)


def test_parse_basic():
    assert parse_decimal_u64(b"42") == (True, 42, b"")


def test_parse_leading_zeros():
    assert parse_decimal_u64(b"0007") == (True, 7, b"")


def test_parse_empty_and_nondigit():
    assert parse_decimal_u64(b"") == (False, 0, b"")
    assert parse_decimal_u64(b"abc") == (False, 0, b"abc")
    assert parse_decimal_u64(b"12x") == (True, 12, b"x")


def test_parse_max_u64_and_overflow():
    assert parse_decimal_u64(b"18446744073709551615") == (
        True, U64_MAX, b"",
    )
    assert parse_decimal_u64(b"18446744073709551616") == (
        False, None, b"6",
    )
    assert parse_decimal_u64(b"99999999999999999999") == (
        False, None, b"9",
    )


def test_sum_single_match():
    groups = [[(7, 10), (8, 20)], [(7, 5)]]
    assert keyed_group_sum(b"7", 2, groups) == (True, 15)


def test_sum_no_match_and_key_above_255():
    groups = [[(7, 10)]]
    assert keyed_group_sum(b"8", 1, groups) == (True, 0)
    # A parsed key above 255 can never equal a byte, but still succeeds.
    assert keyed_group_sum(b"300", 1, groups) == (True, 0)


def test_sum_first_count_groups_only():
    groups = [[(1, 10)], [(1, 20)], [(1, 40)]]
    assert keyed_group_sum(b"1", 2, groups) == (True, 30)


def test_sum_zero_and_negative_count():
    groups = [[(1, 10)]]
    assert keyed_group_sum(b"1", 0, groups) == (True, 0)
    assert keyed_group_sum(b"1", -3, groups) == (True, 0)


def test_sum_empty_group():
    assert keyed_group_sum(b"1", 1, [[]]) == (True, 0)


def test_sum_parse_failure_and_trailing_garbage():
    groups = [[(1, 10)]]
    assert keyed_group_sum(b"", 1, groups) == (False, None)
    assert keyed_group_sum(b"1x", 1, groups) == (False, None)
    assert keyed_group_sum(b"1 ", 1, groups) == (False, None)


def test_sum_wraps_64_bit():
    groups = [[(1, U64_MAX), (1, 2)]]
    assert keyed_group_sum(b"1", 1, groups) == (True, 1)


def test_format_result():
    groups = [[(3, 40), (4, 1)]]
    assert format_result(b"3", 1, groups) == "40"
    assert format_result(b"3x", 1, groups) is None
    assert format_result(b"9", 1, groups) == "0"


def test_missing_groups_guard():
    try:
        keyed_group_sum(b"1", 1, None)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_packet_checks():
    packet = Path(__file__).resolve().parents[1] / "research" / \
        "work-items" / "RE-001-decimal-keyed-group-sum-115"
    records = (packet / "records.json").read_text()
    assert "0x5eee310" in records
    assert "0x61d0df0" in records
    assert "mnemonic" not in records
    assert (packet / "function_0x5eee310.txt").read_text()
    assert (packet / "function_0x61d0df0.txt").read_text()
    assert (packet / "verify.py").read_text()
    assert (packet / "MANIFEST.sha256").read_text()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for test in tests:
        test()
    print("%d model tests pass" % len(tests))
