"""Tests for tools/plain_field_getters_115.py.

Run under pytest when available, or directly with plain python3 via
the ``__main__`` runner below (pytest is not installed on this VM).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from plain_field_getters_115 import (  # noqa: E402
    getter_a, getter_b, getter_c, getter_d, getter_e, getter_f)

PACKET_DIR = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-plain-field-getters-115"


def _outer():
    return {"field788": {
        "field30": {"fieldb30": -42, "field1008": 0x123456789ABCDEF0},
        "field8e8": {"fieldcd0": 7, "fielda70": 8, "fielda78": 9},
        "field928": 0xFFFFFFFFFFFFFFFF,
    }}


def test_getter_a_signed_field():
    out = [None]
    assert getter_a(_outer(), out) == 1
    assert out[0] == -42


def test_getter_a_boundary_values():
    for value in (-2147483648, -1, 0, 2147483647):
        outer = _outer()
        outer["field788"]["field30"]["fieldb30"] = value
        out = [None]
        assert getter_a(outer, out) == 1
        assert out[0] == value


def test_getter_b_sub30_field():
    out = [None]
    assert getter_b(_outer(), out) == 1
    assert out[0] == 0x123456789ABCDEF0


def test_getters_c_d_e_share_sub8e8_but_differ():
    outer = _outer()
    out_c, out_d, out_e = [None], [None], [None]
    assert getter_c(outer, out_c) == 1
    assert getter_d(outer, out_d) == 1
    assert getter_e(outer, out_e) == 1
    assert (out_c[0], out_d[0], out_e[0]) == (7, 8, 9)


def test_getter_f_direct_member_field():
    out = [None]
    assert getter_f(_outer(), out) == 1
    assert out[0] == 0xFFFFFFFFFFFFFFFF


def test_getters_read_only_their_own_field():
    outer = _outer()
    outer["field788"]["field8e8"]["fielda70"] = 12345
    out = [None]
    assert getter_e(outer, out) == 1
    assert out[0] == 9
    outer["field788"]["field30"]["field1008"] = 555
    assert getter_a(outer, out) == 1
    assert out[0] == -42


def test_missing_field_guards():
    try:
        getter_a({"field788": {}}, [None])
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for missing sub-object")
    try:
        getter_f({"field788": {}}, [None])
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for missing field")


def test_out_of_range_field_rejected():
    try:
        outer = _outer()
        outer["field788"]["field30"]["fieldb30"] = 2147483648
        getter_a(outer, [None])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for 32-bit overflow")
    try:
        outer = _outer()
        outer["field788"]["field928"] = 1 << 64
        getter_f(outer, [None])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for 64-bit overflow")


def test_packet_checks():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task"] == "RE-001"
    assert records["artifact_sha256"] == \
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    assert len(records["windows"]) == 6
    for target in ("0x5eeb250", "0x5eeb270", "0x5eeb2f0",
                   "0x5eeb320", "0x5eeb350", "0x5eeb380"):
        census = records["census"][target]
        assert census["direct_calls"] == []
        assert census["tail_jumps"] == []
        assert census["qword_hits_whole_file"] == []
    for name in ("function_0x5eeb250.txt", "function_0x5eeb270.txt",
                 "function_0x5eeb2f0.txt", "function_0x5eeb320.txt",
                 "function_0x5eeb350.txt", "function_0x5eeb380.txt"):
        text = (PACKET_DIR / name).read_text()
        assert "endbr64" in text
        assert "ret" in text


TESTS = [
    test_getter_a_signed_field,
    test_getter_a_boundary_values,
    test_getter_b_sub30_field,
    test_getters_c_d_e_share_sub8e8_but_differ,
    test_getter_f_direct_member_field,
    test_getters_read_only_their_own_field,
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
