"""Tests for the node #115 level-stats formatter (tools/level_stats_formatter_115.py).

Run with pytest, or directly: python3 tests/test_level_stats_formatter_115.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from level_stats_formatter_115 import (
    HEADER,
    format_levels,
    group_sum,
    leaf_sum,
    level_line,
)

HEADER_TEXT = "Level Files Size(MB)\n--------------------\n"


def group(sizes):
    """A level group: one element dict per pointer, None for a null pointer."""
    return {"elements": [
        None if size is None else {"size_field": size} for size in sizes
    ]}


def test_header_constant():
    assert HEADER == HEADER_TEXT


def test_zero_and_negative_count_yield_header_only():
    assert format_levels(0, []) == HEADER_TEXT
    assert format_levels(-3, []) == HEADER_TEXT


def test_single_level_line():
    # A null pointer ends the leaf walk: only the leading 1048576-byte
    # element counts toward the sum (1 MiB), while the printed count is
    # still the full pointer count (3).
    line = level_line(0, group([1048576, None, 1048576]))
    assert line == "%3d %8d %8.0f\n" % (0, 3, 1)


def test_leading_run_stops_at_first_null():
    # Two leading elements sum to 2 MiB; the trailing element after the
    # null is never reached.
    assert leaf_sum(group([1048576, 1048576, None, 1048576])) == 2 * 1048576
    assert level_line(0, group([1048576, 1048576, None, 1048576])) == (
        "%3d %8d %8.0f\n" % (0, 4, 2)
    )


def test_empty_group_line():
    assert level_line(1, group([])) == "%3d %8d %8.0f\n" % (1, 0, 0)


def test_null_only_group_sums_to_zero():
    assert leaf_sum(group([None, None])) == 0
    assert group_sum(group([None])) == 0


def test_multiple_levels_end_to_end():
    out = format_levels(3, [
        group([1048576]),
        group([]),
        group([524288, 524288]),
    ])
    assert out == HEADER_TEXT + (
        "%3d %8d %8.0f\n" % (0, 1, 1)
        + "%3d %8d %8.0f\n" % (1, 0, 0)
        + "%3d %8d %8.0f\n" % (2, 2, 1)
    )


def test_fractional_megabytes_round_to_nearest():
    # 1572864 bytes = 1.5 MiB -> %8.0f prints 2 (round-half-to-even).
    assert level_line(0, group([1572864])) == "%3d %8d %8.0f\n" % (0, 1, 2)
    # 262144 bytes = 0.25 MiB -> prints 0.
    assert level_line(0, group([262144])) == "%3d %8d %8.0f\n" % (0, 1, 0)


def test_wrapped_sum_read_as_unsigned_megabytes():
    # Two +0x10 fields summing past 2**63 wrap to a negative int64;
    # the formatter converts that wrapped value as unsigned, so the
    # size is huge, not negative.
    big = (1 << 63) + 1048576
    line = level_line(0, group([big, big]))
    total = ((big + big) & ((1 << 64) - 1))
    expected_mb = float(total) * (2.0 ** -20)
    assert line == "%3d %8d %8.0f\n" % (0, 2, expected_mb)
    assert float(line.split()[2]) > 0


def test_wide_level_index():
    assert level_line(100, group([1048576])).startswith("100 ")


def test_missing_group_raises():
    try:
        format_levels(2, [group([1])])
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError for a missing level group")


def test_missing_field_guards():
    try:
        leaf_sum({})
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for a missing elements field")


def test_packet_checks():
    packet = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-level-stats-formatter-115"
    assert (packet / "records.json").exists()
    assert (packet / "MANIFEST.sha256").exists()
    for name in ("getter_0x5eecbb0.objdump", "group_sum_0x5f6c300.objdump",
                 "leaf_0x5da4de0.objdump"):
        assert (packet / name).exists()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
    print(f"{len(tests)} tests passed")
