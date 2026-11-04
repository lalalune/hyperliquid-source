"""Tests for tools/group_report_formatter_115.py (node #115, RE-001).

Run with pytest when available, or directly: python3 this file.
"""

import json
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from group_report_formatter_115 import (
    _c_percent_d,
    _compaction_count,
    _group_element_count,
    format_group_report,
)

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-group-report-formatter-115"


def _obj(**over):
    obj = {
        "flag_a90": 1,
        "count": 0,
        "af8": 0.0,
        "af0": 0,
        "arr18": [0],
        "max_score": 0.0,
        "bd0": 0,
        "bc8": 0,
        "b38": 0,
    }
    obj.update(over)
    return obj


def test_normal_empty_count_strips_bracket():
    out = format_group_report(_obj(), [])
    assert out == "files] max score 0.00"


def test_normal_group_lines_and_max_score():
    out = format_group_report(
        _obj(count=3, max_score=1.5),
        [(0, 16), (16, 40), (40, 40)])
    assert out == "files[2 3 0] max score 1.50"


def test_special_prefix_line():
    out = format_group_report(
        _obj(flag_a90=0, count=2, af8=2.5, af0=1, arr18=[100, 200]),
        [(0, 8), (8, 32)])
    assert out == ("base level 1 level multiplier 2.50 max bytes base 200 "
                   "files[1 3] max score 0.00")


def test_special_gate_requires_flag_zero_count_gt1_nonzero_af8():
    base = dict(flag_a90=0, count=2, af8=2.5, af0=0, arr18=[7])
    # af8 == 0.0: normal path, no prefix.
    assert format_group_report(_obj(**{**base, "af8": 0.0}), [(0, 8), (8, 16)]) == \
        "files[1 1] max score 0.00"
    # -0.0 compares equal to +0.0: normal path.
    assert format_group_report(_obj(**{**base, "af8": -0.0}), [(0, 8), (8, 16)]) == \
        "files[1 1] max score 0.00"
    # Flag nonzero: normal path even with count > 1 and af8 != 0.
    assert format_group_report(_obj(**{**base, "flag_a90": 1}), [(0, 8), (8, 16)]) == \
        "files[1 1] max score 0.00"
    # Count 1: normal path even with flag 0 and af8 != 0.
    assert format_group_report(_obj(**{**base, "count": 1}), [(0, 8)]) == \
        "files[1] max score 0.00"


def test_special_gate_nan_takes_special_branch():
    out = format_group_report(
        _obj(flag_a90=0, count=1 + 1, af8=math.nan, af0=0, arr18=[9]),
        [(0, 8), (8, 16)])
    assert out.startswith("base level 0 level multiplier nan max bytes base 9 ")


def test_compaction_suffix_and_arithmetic():
    out = format_group_report(
        _obj(count=1, bd0=0x100, bc8=0x80, b38=5),
        [(0, 8)])
    assert out == "files[1] max score 0.00 (13 files need compaction)"
    assert _compaction_count(0x100, 0x80, 5) == 13


def test_compaction_negative_difference_wraps_unsigned():
    # (0 - 16) >> 4 arithmetic is -1, printed as %zu: 2**64 - 1.
    assert _compaction_count(0, 16, 0) == (1 << 64) - 1
    out = format_group_report(_obj(count=1, bd0=0, bc8=16, b38=0), [(0, 8)])
    assert out.endswith(" (18446744073709551615 files need compaction)")


def test_group_count_arithmetic_shift_and_percent_d_truncation():
    assert _group_element_count(0, 12) == 1
    assert _group_element_count(16, 0) == -2
    # A count above 2**32 prints as its low 32 bits under %d.
    assert _c_percent_d((1 << 32) + 5) == 5
    out = format_group_report(
        _obj(count=1), [(0, ((1 << 32) + 5) * 8)])
    assert out == "files[5] max score 0.00"


def test_only_first_count_groups_are_read():
    out = format_group_report(
        _obj(count=1), [(0, 8), (8, 80), (80, 800)])
    assert out == "files[1] max score 0.00"


def test_negative_count_reads_no_groups():
    out = format_group_report(_obj(count=-3), [(0, 8)])
    assert out == "files] max score 0.00"


def test_max_score_formatting():
    out = format_group_report(_obj(count=0, max_score=3.14159), [])
    assert out == "files] max score 3.14"
    out = format_group_report(_obj(count=0, max_score=2.5), [])
    assert out == "files] max score 2.50"


def test_packet_records_match_window_and_artifact():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["task"] == "RE-001"
    assert records["artifact"]["sha256"] == \
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    window = records["windows"]["formatter"]
    assert window["address"] == "0x5f6c320"
    assert window["end"] == "0x5f6c4d7"
    assert window["bytes"] == 439
    assert (PACKET / "formatter_0x5f6c320.objdump").exists()


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
    print(f"{len(tests)} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
