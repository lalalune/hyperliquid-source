"""Tests for node #115's decimal-index group ratio (tools/decimal_index_group_ratio_115.py).

Pytest-style, with a plain-python __main__ runner (pytest is not
installed on this VM), matching the style of the neighbouring
test_decimal_keyed_group_sum_115.py.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from decimal_index_group_ratio_115 import (
    U64_MAX,
    format_result,
    group_ratio,
    indexed_group_ratio,
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


def test_ratio_simple():
    # One element: numerator 3 + 2 = 5, divisor 10 -> 0.5.
    assert group_ratio([(10, 3, 2)]) == 0.5
    # Two elements: numerator (1 + 2) + (4 + 3) = 10, divisor 4 + 6 = 10.
    assert group_ratio([(4, 1, 2), (6, 4, 3)]) == 1.0


def test_ratio_empty_and_zero_divisor():
    assert group_ratio([]) == -1.0
    assert group_ratio([(0, 5, 5)]) == -1.0
    # Divisor sum wrapping to zero is also the -1.0 sentinel.
    assert group_ratio([(-1, 5, 5), (1, 7, 7)]) == -1.0


def test_ratio_negative():
    assert group_ratio([(4, -10, 2)]) == -2.0


def test_end_to_end():
    groups = [[(10, 3, 2)], [(4, 1, 1)], []]
    assert indexed_group_ratio(b"0", 3, groups) == (True, 0.5)
    assert indexed_group_ratio(b"1", 3, groups) == (True, 0.5)
    assert indexed_group_ratio(b"2", 3, groups) == (True, -1.0)


def test_bound_edge_and_failures():
    groups = [[(10, 3, 2)], [(4, 1, 1)]]
    # Parsed == bound fails (jae); parsed == bound - 1 succeeds.
    assert indexed_group_ratio(b"2", 2, groups) == (False, None)
    assert indexed_group_ratio(b"1", 2, groups) == (True, 0.5)
    # Trailing garbage and parse failure leave the output untouched.
    assert indexed_group_ratio(b"0x", 2, groups) == (False, None)
    assert indexed_group_ratio(b"", 2, groups) == (False, None)


def test_format_result():
    groups = [[(10, 3, 2)], []]
    assert format_result(b"0", 2, groups) == "0.500000"
    assert format_result(b"1", 2, groups) == "-1.000000"
    assert format_result(b"0x", 2, groups) is None
    assert format_result(b"2", 2, groups) is None


def test_missing_groups_guard():
    try:
        indexed_group_ratio(b"0", 1, None)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_packet_checks():
    packet = Path(__file__).resolve().parents[1] / "research" / \
        "work-items" / "RE-001-decimal-index-group-ratio-115"
    records = (packet / "records.json").read_text()
    assert "0x5eed240" in records
    assert "0x5f6aed0" in records
    assert "0x61d0df0" in records
    assert "mnemonic" not in records
    assert (packet / "function_0x5eed240.txt").read_text()
    assert (packet / "function_0x5f6aed0.txt").read_text()
    assert (packet / "function_0x61d0df0.txt").read_text()
    assert (packet / "verify.py").read_text()
    assert (packet / "MANIFEST.sha256").read_text()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for test in tests:
        test()
    print("%d model tests pass" % len(tests))
