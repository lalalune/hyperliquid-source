"""Tests for the node #115 twin signed-field getters model.

Covers both getters end to end, both leaves, the sign extension of
negative fields, the twin structure (same base, different field
offsets), and packet checks on
research/work-items/RE-001-twin-signed-field-getters-115.
Runs under plain python3 (pytest is not installed on this VM):

  python3 tests/test_twin_signed_field_getters_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from twin_signed_field_getters_115 import (  # noqa: E402
    getter_a,
    getter_b,
    leaf_a,
    leaf_b,
)

PACKET_DIR = Path(__file__).resolve().parents[1] / \
    "research" / "work-items" / "RE-001-twin-signed-field-getters-115"


def outer_for(field10, field28):
    inner = {"field10": field10, "field28": field28}
    return {"field788": {"field8f0": {"field8": inner}}}


def test_leaf_a_reads_field10_only():
    arg = {"field8": {"field10": 7, "field28": 99}}
    assert leaf_a(arg) == 7


def test_leaf_b_reads_field28_only():
    arg = {"field8": {"field10": 7, "field28": 99}}
    assert leaf_b(arg) == 99


def test_getter_a_end_to_end():
    out = [None]
    assert getter_a(outer_for(-5, 42), out) == 1
    assert out[0] == -5


def test_getter_b_end_to_end():
    out = [None]
    assert getter_b(outer_for(-5, 42), out) == 1
    assert out[0] == 42


def test_negative_and_boundary_values():
    for value in (-2147483648, -1, 0, 1, 2147483647):
        out = [None]
        assert getter_a(outer_for(value, 0), out) == 1
        assert out[0] == value
        out = [None]
        assert getter_b(outer_for(0, value), out) == 1
        assert out[0] == value


def test_twin_getters_share_base_but_differ():
    outer = outer_for(11, 22)
    out_a, out_b = [None], [None]
    assert getter_a(outer, out_a) == 1
    assert getter_b(outer, out_b) == 1
    assert (out_a[0], out_b[0]) == (11, 22)


def test_missing_field_guards():
    try:
        getter_a({"field788": {}}, [None])
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for missing sub-object")
    try:
        getter_b({"field788": {"field8f0": {"field8": {}}}}, [None])
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for missing field")


def test_out_of_range_field_rejected():
    try:
        leaf_a({"field8": {"field10": 2147483648, "field28": 0}})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for 32-bit overflow")


def test_packet_checks():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task"] == "RE-001"
    assert records["artifact_sha256"] == \
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    assert len(records["windows"]) == 4
    assert records["census"]["0x5f12a20"]["direct_calls"] == ["0x5eeb446"]
    assert len(records["census"]["0x5f12a10"]["direct_calls"]) == 16
    for name in ("function_0x5eeb400.txt", "function_0x5eeb430.txt",
                 "function_0x5f12a10.txt", "function_0x5f12a20.txt"):
        text = (PACKET_DIR / name).read_text()
        assert "endbr64" in text
        assert "ret" in text


TESTS = [
    test_leaf_a_reads_field10_only,
    test_leaf_b_reads_field28_only,
    test_getter_a_end_to_end,
    test_getter_b_end_to_end,
    test_negative_and_boundary_values,
    test_twin_getters_share_base_but_differ,
    test_missing_field_guards,
    test_out_of_range_field_rejected,
    test_packet_checks,
]


def main():
    for test in TESTS:
        test()
        print("ok %s" % test.__name__)
    print("%d tests passed" % len(TESTS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
