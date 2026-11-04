"""Tests for node #115 blob-file report getter 0x5ef0670 + leaf 0x5dd3570.

Run under pytest when available, or directly: python3 tests/test_blob_file_report_115.py
(pytest is not installed on this VM, so the __main__ runner below is the honest path.)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from blob_file_report_115 import (
    amplification,
    format_double,
    leaf_value,
    report,
    run_reporter,
    sums,
)

M64 = (1 << 64) - 1


def outer(entries):
    return {"member788": {"sub30": {"entries": entries}}}


def test_leaf_adds_62():
    assert leaf_value(0) == 62
    assert leaf_value(100) == 162
    assert leaf_value(M64) == 61  # wraps


def test_empty_range_report():
    assert run_reporter(outer([])) == (
        1,
        "Number of blob files: 0\nTotal size of blob files: 0"
        "\nTotal size of garbage in blob files: 0"
        "\nBlob file space amplification: 0\n",
    )


def test_single_entry_ratio():
    # leaf = 38 + 62 = 100, other = 25 -> ratio 100 / 75 = 1.33333
    assert report([{"f10": 38, "e50": 25}]) == (
        "Number of blob files: 1\nTotal size of blob files: 100"
        "\nTotal size of garbage in blob files: 25"
        "\nBlob file space amplification: 1.33333\n"
    )


def test_ratio_guard_other_ge_leaf():
    # other == leaf -> guard arm, ratio 0 (not a division)
    assert amplification(100, 100) == 0.0
    assert amplification(100, 101) == 0.0
    assert amplification(0, 0) == 0.0
    assert "amplification: 0\n" in report([{"f10": 38, "e50": 100}])


def test_ratio_is_leaf_over_leaf_minus_other():
    # Not leaf/other: 100 / (100 - 25) = 1.33333, while 100/25 would be 4.
    assert amplification(100, 25) == 100 / 75
    assert format_double(amplification(100, 25)) == "1.33333"


def test_multiple_entries_sums():
    entries = [{"f10": 0, "e50": 10}, {"f10": 38, "e50": 20}, {"f10": 1000, "e50": 30}]
    assert sums(entries) == (62 + 100 + 1062, 60)
    assert run_reporter(outer(entries))[0] == 1
    assert "Number of blob files: 3\n" in run_reporter(outer(entries))[1]


def test_sums_wrap_64bit():
    assert sums([{"f10": M64, "e50": M64}, {"f10": 1, "e50": 2}]) == ((61 + 63) & M64, 1)


def test_ratio_high_bit_difference():
    # leaf = 2**63, other = 2**62 -> ratio exactly 2, via the unsigned path.
    assert amplification(1 << 63, 1 << 62) == 2.0
    # Difference with the high bit set (leaf - other >= 2**63) still converts unsigned.
    assert amplification(M64, 1) == float(M64) / float(M64 - 1)


def test_format_double_default_ostream():
    assert format_double(0.0) == "0"
    assert format_double(1.0) == "1"
    assert format_double(2.0) == "2"
    assert format_double(100 / 75) == "1.33333"


def test_missing_fields_raise():
    for bad in ({}, {"e50": 1}, {"f10": 1}):
        try:
            sums([bad])
        except KeyError:
            pass
        else:
            raise AssertionError("sums should raise KeyError")
    try:
        run_reporter({})
    except KeyError:
        pass
    else:
        raise AssertionError("missing member should raise KeyError")


def test_packet_records_exist():
    packet = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-blob-file-report-115"
    for name in ("records.json", "MANIFEST.sha256", "verify.py", "export_excerpts.py", "census.py"):
        assert (packet / name).is_file(), f"missing packet file {name}"
    for name in ("reporter_0x5ef0670.objdump", "leaf_0x5dd3570.objdump"):
        assert (packet / name).is_file(), f"missing excerpt {name}"


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    for name, fn in tests:
        fn()
        print(f"PASS {name}")
    print(f"{len(tests)} tests passed")
