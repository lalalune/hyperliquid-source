"""Tests for node #115 small getter run 0x5eeb150..0x5eeb213.

Run under pytest when available, or directly:
python3 tests/test_entry_count_field_getters_115.py
(pytest is not installed on this VM, so the __main__ runner below is the
honest path.)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from entry_count_field_getters_115 import (
    count_getter,
    field_1228_getter,
    field_770_getter,
    guarded_field_getter,
    signed_field_getter,
)

M64 = (1 << 64) - 1
ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-entry-count-field-getters-115"


def member(begin, end):
    return {"sub30": {"begin": begin, "end": end}}


def test_count_empty_range():
    assert count_getter(member(0x1000, 0x1000)) == (1, 0)


def test_count_single_and_multiple_entries():
    assert count_getter(member(0x1000, 0x1010)) == (1, 1)
    assert count_getter(member(0x1000, 0x1050)) == (1, 5)


def test_count_odd_span_uses_arithmetic_shift():
    # 24 bytes is one whole entry plus a remainder: sar gives 1, not 2.
    assert count_getter(member(0x1000, 0x1018)) == (1, 1)


def test_count_negative_span_is_negative():
    # Malformed end < begin: the wrapped difference is -16, sar gives -1.
    assert count_getter(member(0x1000, 0xFF0)) == (1, -1)


def test_count_matches_blob_range_shape():
    # The range fields are the same [sub + 0xb18, sub + 0xb20) pair the
    # #2307/#2313 walk uses; the count is its entry count, not a byte size.
    assert count_getter(member(0, 16 * 7)) == (1, 7)


def test_signed_field_boundaries():
    assert signed_field_getter({"f1438": 0}) == (1, 0)
    assert signed_field_getter({"f1438": 0x7FFFFFFF}) == (1, 0x7FFFFFFF)
    assert signed_field_getter({"f1438": 0x80000000}) == (1, -(1 << 31))
    assert signed_field_getter({"f1438": 0xFFFFFFFF}) == (1, -1)


def test_field_770_plain_64_bit():
    assert field_770_getter({"f770": 0}) == (1, 0)
    assert field_770_getter({"f770": M64}) == (1, M64)


def test_field_1228_plain_64_bit():
    assert field_1228_getter({"f1228": 12345}) == (1, 12345)
    assert field_1228_getter({"f1228": 1 << 63}) == (1, 1 << 63)


def test_guarded_sentinel_arm_needs_no_field():
    # Sentinel arm stores 0 and never dereferences ptr.
    assert guarded_field_getter({"ptr": 0x2000, "sentinel": 0x2000}) == (1, 0)


def test_guarded_non_sentinel_reads_field30():
    assert guarded_field_getter(
        {"ptr": 0x3000, "sentinel": 0x2000, "field30": 99}) == (1, 99)


def test_guarded_non_sentinel_without_field_raises():
    try:
        guarded_field_getter({"ptr": 0x3000, "sentinel": 0x2000})
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for missing field30")


def test_all_getters_return_one():
    assert count_getter(member(0, 0))[0] == 1
    assert signed_field_getter({"f1438": 0})[0] == 1
    assert field_770_getter({"f770": 0})[0] == 1
    assert field_1228_getter({"f1228": 0})[0] == 1
    assert guarded_field_getter({"ptr": 0, "sentinel": 0})[0] == 1


def test_packet_windows():
    records = json.loads((PACKET / "records.json").read_text())
    expected = {
        "count": "0x5eeb150",
        "signed": "0x5eeb180",
        "field770": "0x5eeb1a0",
        "field1228": "0x5eeb1c0",
        "guarded": "0x5eeb1e0",
    }
    for label, address in expected.items():
        assert records["windows"][label]["address"] == address
        assert (PACKET / records["windows"][label]["excerpt"]).exists()


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


if __name__ == "__main__":
    for test in TESTS:
        test()
    print(f"{len(TESTS)} tests passed")
