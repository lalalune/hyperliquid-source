"""Model tests for the node #115 tag-3 and tag-4 inner queries
(RE-001-tag3-tag4-queries-1af0-1e40-115).

Run directly (pytest is not installed on this VM):
    python3 tests/test_tag3_tag4_queries_1af0_1e40_115.py
or through the packet's verify.py, which imports every test_*
function here and runs it. Expectations are target-grounded: the
ULEB128 width boundaries, the flag-bit setter's changed flag, the
gate's three skip conditions and throttle cadence, the chain
walk's first-mismatch / thirteenth-link rule (one link deeper
than the tag-5/tag-6 twins), the exact tag-3 and tag-4 message
and frame byte layouts, the two queries differing in tag byte
and payload, and the zero-out path.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.tag3_tag4_queries_1af0_1e40_115 import (
    WALKER, LengthError, Obj, build_message_tag3,
    build_message_tag4, frame, gate, limit_check, pick_handler,
    set_bit, tag3_query, tag4_query, uleb128, zero_out_record,
)


def _obj(**over):
    kw = dict(chain_head=[WALKER] * 13, limit8=10, limit10=1,
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
    mask, changed = set_bit(0, 1)
    assert (mask, changed) == (0x02, 1)
    mask, changed = set_bit(mask, 1)
    assert (mask, changed) == (0x02, 0)
    mask, changed = set_bit(mask, 2)
    assert (mask, changed) == (0x06, 1)
    mask, changed = set_bit(mask, 3)
    assert (mask, changed) == (0x0E, 1)


def test_limit_check_direction():
    assert limit_check(_obj(limit8=10, slot20=lambda: 11)) == 1
    assert limit_check(_obj(limit8=10, slot20=lambda: 10)) == 0
    assert limit_check(_obj(limit8=10, slot20=lambda: 9)) == 0


def test_gate_skips_when_limit_exceeded():
    obj = _obj(limit8=10, slot20=lambda: 11, limit10=1)
    assert gate(obj, 3) is False
    assert gate(obj, 4) is False
    assert obj.counter30 == 0


def test_gate_flag_masks_per_tag():
    # Tag 3 selects mask 0x02, tag 4 selects mask 0x01 (the
    # gate's jump table at 0x97c5f4).
    assert gate(_obj(flags18=0x02, limit10=1), 3) is False
    assert gate(_obj(flags18=0x01, limit10=1), 3) is True
    assert gate(_obj(flags18=0x01, limit10=1), 4) is False
    assert gate(_obj(flags18=0x02, limit10=1), 4) is True
    for tag, mask in ((5, 0x04), (6, 0x08), (13, 0x10)):
        assert gate(_obj(flags18=mask, limit10=1), tag) is False
        assert gate(_obj(flags18=0, limit10=1), tag) is True


def test_gate_throttle_cadence():
    obj = _obj(limit10=3)
    assert gate(obj, 3) is False
    assert obj.counter30 == 1
    assert gate(obj, 3) is False
    assert obj.counter30 == 2
    assert gate(obj, 3) is True
    assert obj.counter30 == 0
    assert gate(obj, 4) is False
    assert obj.counter30 == 1


def test_walk_first_mismatch_and_thirteenth_link():
    assert pick_handler([0x1111] + [WALKER] * 12) == 0
    assert pick_handler([WALKER, WALKER, 0x2222] + [WALKER] * 10) == 2
    assert pick_handler([WALKER] * 11 + [0x3333, WALKER]) == 11
    assert pick_handler([WALKER] * 13) == 12
    # The walk needs thirteen reachable links: twelve is not
    # enough for these queries (the twins need twelve).
    try:
        pick_handler([WALKER] * 12)
    except ValueError:
        pass
    else:
        raise AssertionError("walk with 12 links must fail")


def test_tag3_message_layout():
    msg = build_message_tag3((b"HELLO", 5))
    assert msg[:8] == struct.pack("<Q", 0x02)
    assert msg[8:] == uleb128(5) + b"HELLO"
    # A 128-byte payload crosses the one-byte varint boundary.
    big = build_message_tag3((b"x" * 300, 300))
    assert big[:8] == struct.pack("<Q", 0x02)
    assert big[8:10] == uleb128(300)
    assert big[10:] == b"x" * 300
    # A zero-length pair still appends the varint zero byte and
    # no data: the binary appends unconditionally.
    assert build_message_tag3((b"", 0)) == struct.pack("<Q", 0x02) + b"\x00"


def test_tag4_message_layout():
    msg = build_message_tag4(0xAABBCCDD, (b"HELLO", 5))
    assert msg[:8] == struct.pack("<Q", 0x0C)
    assert msg[8:12] == struct.pack("<I", 0xAABBCCDD)
    assert msg[12:] == uleb128(5) + b"HELLO"
    big = build_message_tag4(0, (b"y" * 200, 200))
    assert big[:8] == struct.pack("<Q", 0x0C)
    assert big[8:12] == struct.pack("<I", 0)
    assert big[12:14] == uleb128(200)
    assert big[14:] == b"y" * 200
    assert build_message_tag4(7, (b"", 0)) == (
        struct.pack("<Q", 0x0C) + struct.pack("<I", 7) + b"\x00")


def test_message_length_guard():
    from tools.tag3_tag4_queries_1af0_1e40_115 import (
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
    try:
        build_message_tag3((b"x" * 10, 0x3FFFFFFFFFFFFFFF))
    except ValueError:
        pass
    else:
        raise AssertionError("oversize pair must raise")


def test_frame_layout():
    framed = frame(0x1122334455667788, 3, b"MSG")
    assert framed == (struct.pack("<Q", 0x1122334455667788)
                      + b"\x03" + struct.pack("<I", 3) + b"MSG")
    framed4 = frame(0x1122334455667788, 4, b"MSG")
    assert framed4[8] == 4
    assert framed4[:8] == framed[:8] and framed4[9:] == framed[9:]


def test_queries_differ_in_tag_and_payload():
    seen = []

    def handler(index):
        seen.append(index)
        return 0x99

    def deliver(out, target, framed):
        out.update({"u32": 1, "u16": 2, "qword": 3})

    out3, framed3 = tag3_query(_obj(), (b"A", 1),
                               handler=handler, deliver=deliver)
    out4, framed4 = tag4_query(_obj(), lambda: 0x1234, (b"A", 1),
                               handler=handler, deliver=deliver)
    assert seen == [12, 12]
    assert out3 == out4 == {"u32": 1, "u16": 2, "qword": 3}
    assert framed3[8] == 3 and framed4[8] == 4
    assert framed3[9:13] == struct.pack(
        "<I", len(build_message_tag3((b"A", 1))))
    assert framed4[9:13] == struct.pack(
        "<I", len(build_message_tag4(0x1234, (b"A", 1))))
    # Same handler return and tag-3's shorter message.
    assert framed3[:8] == framed4[:8]
    assert len(framed4) - len(framed3) == 4


def test_zero_out_path_skips_everything():
    calls = []

    def handler(index):
        calls.append(index)
        return 0

    def deliver(out, target, framed):
        calls.append("deliver")

    out, framed = tag3_query(_obj(flags18=0x02), (b"A", 1),
                             handler=handler, deliver=deliver)
    assert out == {"u32": 0, "u16": 0, "qword": 0}
    assert framed is None
    out, framed = tag4_query(_obj(flags18=0x01), lambda: 0,
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

    links = [WALKER, WALKER, 0x7777] + [WALKER] * 10
    obj = _obj(chain_head=links, limit10=1)
    out, framed = tag3_query(obj, (b"AB", 2),
                             handler=handler, deliver=deliver)
    assert seen["index"] == 2
    assert seen["target"] == "target"
    message = build_message_tag3((b"AB", 2))
    assert framed == frame(0xDEADBEEFCAFEBABE, 3, message)
    assert seen["frame"] == framed
    assert out == {"u32": 0x11111111, "u16": 0x2222,
                   "qword": 0x3333333333333333}

    seen.clear()
    obj = _obj(chain_head=links, limit10=1)
    out, framed = tag4_query(obj, lambda: 0xAABBCCDD, (b"C", 1),
                             handler=handler, deliver=deliver)
    assert seen["index"] == 2
    message = build_message_tag4(0xAABBCCDD, (b"C", 1))
    assert framed == frame(0xDEADBEEFCAFEBABE, 4, message)
    assert out == {"u32": 0x11111111, "u16": 0x2222,
                   "qword": 0x3333333333333333}


def test_zero_out_record_shape():
    assert zero_out_record() == {"u32": 0, "u16": 0, "qword": 0}


if __name__ == "__main__":
    passed = 0
    for name in sorted(dir()):
        if name.startswith("test_"):
            globals()[name]()
            passed += 1
    print("model tests passed: %d" % passed)
