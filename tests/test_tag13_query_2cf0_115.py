"""Model tests for the node #115 tag-13 inner query
(RE-001-tag13-query-2cf0-115).

Run directly (pytest is not installed on this VM):
    python3 tests/test_tag13_query_2cf0_115.py
or through the packet's verify.py, which imports every test_*
function here and runs it. Expectations are target-grounded: the
ULEB128 width boundaries, the flag-bit setter's changed flag, the
count-mismatch error record (code 2, exact message bytes), the
mismatch helper's ": " join, the gate's three skip conditions
and throttle cadence with tag 13's mask 0x10, the chain walk's
first-mismatch / tenth-link rule (three links shallower than the
tag-3/tag-4 queries), the exact tag-13 message and frame byte
layouts, and the zero-out path.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.tag13_query_2cf0_115 import (
    MISMATCH_MESSAGE, WALKER, LengthError, Obj, build_message_tag13,
    build_s2, build_s3, error_out_record, frame, gate,
    join_mismatch_message, limit_check, pick_handler, set_bit,
    tag13_query, uleb128, zero_out_record,
)


def _obj(**over):
    kw = dict(chain_head=[WALKER] * 10, limit8=10, limit10=1,
              flags18=0, target="target", slot20=lambda: 5)
    kw.update(over)
    return Obj(**kw)


def _decode_uleb128(data):
    value = 0
    shift = 0
    for i, byte in enumerate(data):
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, i + 1
    raise AssertionError("unterminated varint")


def test_uleb128_width_boundaries():
    assert uleb128(0x7F) == b"\x7f"
    assert uleb128(0x80) == b"\x80\x01"
    assert uleb128(0x3FFF) == b"\xff\x7f"
    assert uleb128(0x4000) == b"\x80\x80\x01"
    assert uleb128(0x1FFFFF) == b"\xff\xff\x7f"
    assert uleb128(0x200000) == b"\x80\x80\x80\x01"
    assert uleb128(0xFFFFFFF) == b"\xff\xff\xff\x7f"
    assert uleb128(0x10000000) == b"\x80\x80\x80\x80\x01"
    for n in (0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000,
              0xFFFFFFF, 0x10000000, 0xFFFFFFFF):
        value, used = _decode_uleb128(uleb128(n))
        assert value == n and used == len(uleb128(n))


def test_set_bit_reports_change():
    mask, changed = set_bit(0, 8)
    assert (mask, changed) == (0x100, 1)
    mask, changed = set_bit(mask, 9)
    assert (mask, changed) == (0x300, 1)
    mask, changed = set_bit(mask, 10)
    assert (mask, changed) == (0x700, 1)
    mask, changed = set_bit(mask, 10)
    assert (mask, changed) == (0x700, 0)


def test_mismatch_helper_join():
    # The 0x61cf670 helper joins with ": " only when the second
    # string is non-empty; the tag-13 query passes an empty
    # second string, so the message is the first string alone.
    assert join_mismatch_message(b"first", b"") == b"first"
    assert join_mismatch_message(b"first", b"second") == b"first: second"
    assert join_mismatch_message(MISMATCH_MESSAGE, b"") == MISMATCH_MESSAGE
    assert MISMATCH_MESSAGE == (
        b"the CFs size and keys size does not match!")
    assert len(MISMATCH_MESSAGE) == 0x2A


def test_error_out_record_shape():
    out = error_out_record()
    assert out["u32"] == 2
    assert out["u16"] == 0
    assert out["qword"] == MISMATCH_MESSAGE


def test_limit_check_direction():
    assert limit_check(_obj(limit8=10, slot20=lambda: 11)) == 1
    assert limit_check(_obj(limit8=10, slot20=lambda: 10)) == 0
    assert limit_check(_obj(limit8=10, slot20=lambda: 9)) == 0


def test_gate_skips_when_limit_exceeded():
    obj = _obj(limit8=10, slot20=lambda: 11, limit10=1)
    assert gate(obj, 13) is False
    assert obj.counter30 == 0


def test_gate_flag_mask_for_tag13():
    # Tag 13 selects mask 0x10 through the gate's jump table
    # at 0x97c5f4; the other family tags keep their masks.
    assert gate(_obj(flags18=0x10, limit10=1), 13) is False
    assert gate(_obj(flags18=0x08, limit10=1), 13) is True
    assert gate(_obj(flags18=0x02, limit10=1), 3) is False
    assert gate(_obj(flags18=0x01, limit10=1), 4) is False
    assert gate(_obj(flags18=0x04, limit10=1), 5) is False
    assert gate(_obj(flags18=0x08, limit10=1), 6) is False


def test_gate_throttle_cadence():
    obj = _obj(limit10=3)
    assert gate(obj, 13) is False
    assert obj.counter30 == 1
    assert gate(obj, 13) is False
    assert obj.counter30 == 2
    assert gate(obj, 13) is True
    assert obj.counter30 == 0
    assert gate(obj, 13) is False
    assert obj.counter30 == 1


def test_walk_first_mismatch_and_tenth_link():
    assert pick_handler([0x1111] + [WALKER] * 9) == 0
    assert pick_handler([WALKER, WALKER, 0x2222] + [WALKER] * 7) == 2
    assert pick_handler([WALKER] * 8 + [0x3333, WALKER]) == 8
    assert pick_handler([WALKER] * 10) == 9
    # The walk needs ten reachable links: nine is not enough
    # for this query (the tag-3/tag-4 queries need thirteen).
    try:
        pick_handler([WALKER] * 9)
    except ValueError:
        pass
    else:
        raise AssertionError("nine links must be rejected")


def test_build_s2_le32_per_element():
    assert build_s2([lambda: 0xAABBCCDD]) == b"\xdd\xcc\xbb\xaa"
    assert build_s2([lambda: 1, lambda: 2]) == (
        b"\x01\x00\x00\x00\x02\x00\x00\x00")
    assert build_s2([]) == b""


def test_build_s3_varint_and_data_per_record():
    assert build_s3([(b"AB", 2)]) == b"\x02AB"
    assert build_s3([(b"", 0)]) == b"\x00"
    assert build_s3([(b"A", 1), (b"BC", 2)]) == b"\x01A\x02BC"
    # A 200-byte record needs a two-byte varint.
    assert build_s3([(b"x" * 200, 200)])[:2] == b"\xc8\x01"


def test_build_message_tag13_exact_layout():
    message = build_message_tag13(
        [(b"AB", 2)], [lambda: 0xAABBCCDD])
    assert message == (
        struct.pack("<Q", 0x700)
        + struct.pack("<I", 1)
        + b"\x04" + b"\xdd\xcc\xbb\xaa"
        + b"\x03" + b"\x02AB")
    # Empty ranges still append one 0x00 varint byte per string.
    assert build_message_tag13([], []) == (
        struct.pack("<Q", 0x700) + struct.pack("<I", 0)
        + b"\x00" + b"\x00")
    # Two records, two elements: count 2, S2 has two LE32s.
    message = build_message_tag13(
        [(b"A", 1), (b"", 0)],
        [lambda: 0x11111111, lambda: 0x22222222])
    assert message == (
        struct.pack("<Q", 0x700)
        + struct.pack("<I", 2)
        + b"\x08" + b"\x11\x11\x11\x11\x22\x22\x22\x22"
        + b"\x03" + b"\x01A\x00")


def test_build_message_rejects_count_mismatch():
    try:
        build_message_tag13([(b"A", 1)], [])
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched counts must be rejected")


def test_query_count_mismatch_returns_error_record():
    seen = []
    obj = _obj()
    out, framed = tag13_query(
        obj, [(b"A", 1), (b"B", 1)], [lambda: 1],
        handler=lambda i: (seen.append(i), 0x42)[1],
        deliver=lambda o, t, f: o.update(
            {"u32": 1, "u16": 2, "qword": 3}))
    assert out == {"u32": 2, "u16": 0, "qword": MISMATCH_MESSAGE}
    assert framed is None
    # The mismatch path returns before the gate: the throttle
    # counter is untouched and no handler runs.
    assert obj.counter30 == 0
    assert seen == []


def test_query_gate_skip_zeroes_out_record():
    seen = []
    obj = _obj(limit10=2)
    out, framed = tag13_query(
        obj, [], [],
        handler=lambda i: (seen.append(i), 0x42)[1],
        deliver=lambda o, t, f: o.update(
            {"u32": 1, "u16": 2, "qword": 3}))
    assert out == {"u32": 0, "u16": 0, "qword": 0}
    assert framed is None
    assert seen == []
    assert obj.counter30 == 1


def test_query_end_to_end_tenth_link():
    seen = []
    out, framed = tag13_query(
        _obj(), [(b"AB", 2)], [lambda: 0xAABBCCDD],
        handler=lambda i: (seen.append(i), 0x42)[1],
        deliver=lambda o, t, f: o.update(
            {"u32": 1, "u16": 2, "qword": 3}))
    assert seen == [9]
    assert out == {"u32": 1, "u16": 2, "qword": 3}
    assert framed == (
        struct.pack("<Q", 0x42) + b"\x0d"
        + struct.pack("<I", 21)
        + struct.pack("<Q", 0x700)
        + struct.pack("<I", 1)
        + b"\x04" + b"\xdd\xcc\xbb\xaa"
        + b"\x03" + b"\x02AB")


def test_query_end_to_end_first_mismatch():
    seen = []
    obj = _obj(chain_head=[WALKER, WALKER, WALKER, 0x7777]
               + [WALKER] * 6)
    out, framed = tag13_query(
        obj, [], [],
        handler=lambda i: (seen.append(i), 0x99)[1],
        deliver=lambda o, t, f: o.update(
            {"u32": 1, "u16": 2, "qword": 3}))
    assert seen == [3]
    assert framed[:9] == struct.pack("<Q", 0x99) + b"\x0d"


def test_frame_layout_tag13():
    assert frame(0x99, 13, b"MSG") == (
        struct.pack("<Q", 0x99) + b"\x0d"
        + struct.pack("<I", 3) + b"MSG")


def test_length_guard_raises():
    try:
        from tools.tag13_query_2cf0_115 import check_append_room
        check_append_room(0x3FFFFFFFFFFFFFFF, 1)
    except LengthError as exc:
        assert str(exc) == "basic_string::append"
    else:
        raise AssertionError("guard must raise at the limit")


if __name__ == "__main__":
    passed = 0
    for name in sorted(dir()):
        if name.startswith("test_"):
            globals()[name]()
            passed += 1
    print(f"{passed} tests passed")
