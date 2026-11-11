"""Model tests for the node #115 twin inner queries
(RE-001-twin-inner-queries-21f0-2760-115).

Run directly (pytest is not installed on this VM):
    python3 tests/test_twin_inner_queries_21f0_2760_115.py
or through the packet's verify.py, which imports every test_*
function here and runs it. Expectations are target-grounded: the
ULEB128 width boundaries, the flag-bit setter's changed flag, the
gate's three skip conditions and throttle cadence, the chain
walk's first-mismatch / twelfth-link rule, the exact message and
frame byte layouts, the twins differing only in the tag byte, and
the zero-out path.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.twin_inner_queries_21f0_2760_115 import (
    WALKER, LengthError, Obj, build_message, caller_out_copy, frame,
    gate, limit_check, pick_handler, set_bit, twin_query, uleb128,
    zero_out_record,
)


def _obj(**over):
    kw = dict(chain_head=[WALKER] * 12, limit8=10, limit10=1,
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
    mask, changed = set_bit(0, 4)
    assert (mask, changed) == (0x10, 1)
    mask, changed = set_bit(mask, 4)
    assert (mask, changed) == (0x10, 0)
    mask, changed = set_bit(mask, 5)
    assert (mask, changed) == (0x30, 1)


def test_limit_check_direction():
    assert limit_check(_obj(limit8=10, slot20=lambda: 11)) == 1
    assert limit_check(_obj(limit8=10, slot20=lambda: 10)) == 0
    assert limit_check(_obj(limit8=10, slot20=lambda: 9)) == 0


def test_gate_skips_when_limit_exceeded():
    obj = _obj(limit8=10, slot20=lambda: 11, limit10=1)
    assert gate(obj, 5) is False
    assert obj.counter30 == 0


def test_gate_flag_masks_per_tag():
    for tag, mask in ((3, 0x02), (4, 0x01), (5, 0x04), (6, 0x08),
                      (13, 0x10)):
        assert gate(_obj(flags18=mask, limit10=1), tag) is False
        assert gate(_obj(flags18=0, limit10=1), tag) is True
    # A flag bit for another tag does not block this tag.
    assert gate(_obj(flags18=0x08, limit10=1), 5) is True
    assert gate(_obj(flags18=0x04, limit10=1), 6) is True


def test_gate_tags_without_mask_skip_flag_check():
    # Tags 7..12 (and out-of-range tags) go straight to the
    # counter path even with every flag bit set.
    assert gate(_obj(flags18=0xFFFFFFFF, limit10=1), 7) is True
    assert gate(_obj(flags18=0xFFFFFFFF, limit10=1), 12) is True
    assert gate(_obj(flags18=0xFFFFFFFF, limit10=1), 2) is True
    assert gate(_obj(flags18=0xFFFFFFFF, limit10=1), 14) is True


def test_gate_throttle_cadence():
    obj = _obj(limit10=3)
    assert gate(obj, 5) is False
    assert obj.counter30 == 1
    assert gate(obj, 5) is False
    assert obj.counter30 == 2
    assert gate(obj, 5) is True
    assert obj.counter30 == 0
    assert gate(obj, 5) is False
    assert obj.counter30 == 1


def test_gate_throttle_limit_one_builds_every_time():
    obj = _obj(limit10=1)
    assert gate(obj, 5) is True
    assert gate(obj, 5) is True
    assert obj.counter30 == 0


def test_walk_first_mismatch_and_twelfth_link():
    assert pick_handler([0x1111] + [WALKER] * 11) == 0
    assert pick_handler([WALKER, WALKER, 0x2222] + [WALKER] * 9) == 2
    assert pick_handler([WALKER] * 10 + [0x3333, WALKER]) == 10
    assert pick_handler([WALKER] * 12) == 11
    try:
        pick_handler([WALKER] * 11)
    except ValueError:
        pass
    else:
        raise AssertionError("walk with 11 links must fail")


def test_message_layout_all_pairs():
    msg = build_message(0xAABBCCDD, (b"AB", 2), (b"CDE", 3),
                        (b"FGHI", 4))
    assert msg[:8] == struct.pack("<Q", 0x30 | 0x40 | 0x80)
    assert msg[8:12] == struct.pack("<I", 0xAABBCCDD)
    assert msg[12:] == (uleb128(2) + b"AB" + uleb128(3) + b"CDE"
                        + uleb128(4) + b"FGHI")


def test_message_optional_pairs_and_mask_bits():
    only_a = build_message(7, (b"X", 1))
    assert only_a[:8] == struct.pack("<Q", 0x30)
    assert only_a[12:] == uleb128(1) + b"X"
    with_b = build_message(7, (b"X", 1), (b"YZ", 2))
    assert with_b[:8] == struct.pack("<Q", 0x30 | 0x40)
    assert with_b[12:] == uleb128(1) + b"X" + uleb128(2) + b"YZ"
    with_c = build_message(7, (b"X", 1), None, (b"Q", 1))
    assert with_c[:8] == struct.pack("<Q", 0x30 | 0x80)
    assert with_c[12:] == uleb128(1) + b"X" + uleb128(1) + b"Q"
    # A zero-length pair is absent, exactly as the binary's
    # nonzero-length test decides.
    empty_b = build_message(7, (b"X", 1), (b"", 0))
    assert empty_b == only_a


def test_message_length_guard():
    from tools.twin_inner_queries_21f0_2760_115 import (
        MAX_STRING, check_append_room)
    # Exactly at the boundary: remaining capacity equals the
    # needed length, so the binary's `<=` guard throws.
    try:
        check_append_room(MAX_STRING - 8, 8)
    except LengthError as err:
        assert str(err) == "basic_string::append"
    else:
        raise AssertionError("boundary append must raise")
    check_append_room(MAX_STRING - 9, 8)
    check_append_room(0, 8)
    # A pair length beyond its supplied data is a bad input,
    # not a length error.
    try:
        build_message(0, (b"x" * 10, 0x3FFFFFFFFFFFFFFF))
    except ValueError:
        pass
    else:
        raise AssertionError("oversize pair must raise")


def test_frame_layout():
    framed = frame(0x1122334455667788, 5, b"MSG")
    assert framed == (struct.pack("<Q", 0x1122334455667788)
                      + b"\x05" + struct.pack("<I", 3) + b"MSG")


def test_twins_differ_only_in_tag_byte():
    seen = []

    def handler(index):
        seen.append(index)
        return 0x99

    def deliver(out, target, framed):
        out.update({"u32": 1, "u16": 2, "qword": 3})

    out5, framed5 = twin_query(_obj(), 5, 0x1234, (b"A", 1),
                               handler=handler, deliver=deliver)
    out6, framed6 = twin_query(_obj(), 6, 0x1234, (b"A", 1),
                               handler=handler, deliver=deliver)
    assert seen == [11, 11]
    assert out5 == out6 == {"u32": 1, "u16": 2, "qword": 3}
    assert len(framed5) == len(framed6)
    diffs = [i for i, (a, b) in enumerate(zip(framed5, framed6))
             if a != b]
    assert diffs == [8]
    assert framed5[8] == 5 and framed6[8] == 6


def test_zero_out_path_skips_everything():
    calls = []

    def handler(index):
        calls.append(index)
        return 0

    def deliver(out, target, framed):
        calls.append("deliver")

    out, framed = twin_query(_obj(flags18=0x04), 5, 0,
                             (b"A", 1), handler=handler,
                             deliver=deliver)
    assert out == {"u32": 0, "u16": 0, "qword": 0}
    assert framed is None
    assert calls == []


def test_end_to_end_first_mismatch_handler():
    seen = {}

    def handler(index):
        seen["index"] = index
        return 0xDEADBEEFCAFEBABE

    def deliver(out, target, framed):
        seen["target"] = target
        seen["frame"] = framed
        out.update({"u32": 0x11111111, "u16": 0x2222,
                    "qword": 0x3333333333333333})

    links = [WALKER, WALKER, 0x7777] + [WALKER] * 9
    obj = _obj(chain_head=links, limit10=1)
    out, framed = twin_query(obj, 6, 0xAABBCCDD, (b"AB", 2),
                             (b"C", 1), (b"DEFG", 4),
                             handler=handler, deliver=deliver)
    assert seen["index"] == 2
    assert seen["target"] == "target"
    message = build_message(0xAABBCCDD, (b"AB", 2), (b"C", 1),
                            (b"DEFG", 4))
    assert framed == frame(0xDEADBEEFCAFEBABE, 6, message)
    assert seen["frame"] == framed
    assert out == {"u32": 0x11111111, "u16": 0x2222,
                   "qword": 0x3333333333333333}
    assert caller_out_copy(out) == (0x11111111, 0x2222)


def test_zero_out_record_shape():
    assert zero_out_record() == {"u32": 0, "u16": 0, "qword": 0}
    assert caller_out_copy(zero_out_record()) == (0, 0)


if __name__ == "__main__":
    passed = 0
    for name in sorted(dir()):
        if name.startswith("test_"):
            globals()[name]()
            passed += 1
    print("model tests passed: %d" % passed)
