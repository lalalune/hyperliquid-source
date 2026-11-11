"""Tests for the node #115 chain-dispatch notifier model
(tools/chain_dispatch_notifier_1bca30_115.py).

Every expectation is target-grounded: the varint vectors follow the
0x61bd410 branches, the walk selections follow the comparison chains
in 0x61bca30 and 0x5d4d490, and the message/frame bytes follow the
append sequences in 0x61bca30 and 0x61b1260.  Run without pytest:
python3 -c "import importlib.util; ..." or via the packet verify.py.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.chain_dispatch_notifier_1bca30_115 import (
    EXPECTED_SLOT, LengthError_, append_checked, build_frame,
    build_message, caller_once, dispatch, uleb128_encode,
    walk_chain, walk_expected)

OTHER = 0x61B1260
THIRD = 0x5D527A0


def test_uleb128_single_byte():
    assert uleb128_encode(0) == b"\x00"
    assert uleb128_encode(0x7F) == b"\x7f"


def test_uleb128_two_bytes():
    assert uleb128_encode(0x80) == b"\x80\x01"
    assert uleb128_encode(0x3FFF) == b"\xff\x7f"


def test_uleb128_three_bytes():
    assert uleb128_encode(0x4000) == b"\x80\x80\x01"
    assert uleb128_encode(0x1FFFFF) == b"\xff\xff\x7f"


def test_uleb128_four_bytes():
    assert uleb128_encode(0x200000) == b"\x80\x80\x80\x01"
    assert uleb128_encode(0xFFFFFFF) == b"\xff\xff\xff\x7f"


def test_uleb128_five_bytes():
    assert uleb128_encode(0x10000000) == b"\x80\x80\x80\x80\x01"
    assert uleb128_encode(0xFFFFFFFF) == b"\xff\xff\xff\xff\x0f"
    try:
        uleb128_encode(0x100000000)
    except ValueError:
        pass
    else:
        raise AssertionError("u32 overflow accepted")


def test_walk_chain_homogeneous_selects_fifth():
    slots = [EXPECTED_SLOT] * 5
    assert walk_chain(slots) == 4


def test_walk_chain_mismatch_at_head():
    assert walk_chain([OTHER] + [EXPECTED_SLOT] * 4) == 0


def test_walk_chain_mismatch_at_each_link():
    base = [EXPECTED_SLOT] * 5
    for k in (1, 2, 3):
        slots = list(base)
        slots[k] = THIRD
        assert walk_chain(slots) == k


def test_walk_chain_short_chain_rejected():
    try:
        walk_chain([EXPECTED_SLOT] * 4)
    except ValueError:
        pass
    else:
        raise AssertionError("short chain accepted")


def test_walk_expected_homogeneous_selects_ninth():
    assert walk_expected([EXPECTED_SLOT] * 9) == 8


def test_walk_expected_mismatch_positions():
    for k in (0, 1, 4, 7):
        slots = [EXPECTED_SLOT] * 9
        slots[k] = OTHER
        assert walk_expected(slots) == k


def test_build_message_bytes():
    assert build_message(b"AB") == (
        b"\x02AB\x08\x00\x00\x00\x01\x00\x00\x00")
    assert build_message(b"") == b"\x00\x08\x00\x00\x00\x01\x00\x00\x00"
    tag = b"x" * 0x80
    assert build_message(tag)[:2] == b"\x80\x01"
    assert build_message(tag)[2:2 + 0x80] == tag


def test_build_frame_bytes():
    message = build_message(b"AB")
    frame = build_frame(0x1122334455667788, 1, message)
    assert frame[:8] == (0x1122334455667788).to_bytes(8, "little")
    assert frame[8] == 1
    assert frame[9:13] == len(message).to_bytes(4, "little")
    assert frame[13:] == message


def test_length_guard_boundary():
    assert append_checked(0x3FFFFFFFFFFFFFFB, 4) == 0x3FFFFFFFFFFFFFFF
    try:
        append_checked(0x3FFFFFFFFFFFFFFC, 4)
    except LengthError_:
        pass
    else:
        raise AssertionError("length guard did not fire")


def test_dispatch_end_to_end():
    slots = [EXPECTED_SLOT] * 5
    trace = dispatch(slots, b"AB", 0x1122334455667788, "owner", "target")
    kinds = [t[0] for t in trace]
    assert kinds == ["select", "message", "frame", "deliver",
                     "free", "free", "return"]
    assert trace[0] == ("select", 4, EXPECTED_SLOT)
    assert trace[3][1] == "owner" and trace[3][2] == "target"
    assert trace[3][3]["data"] == trace[2][1]
    assert trace[6] == ("return", "owner")


def test_caller_skips_notify_when_slot_present():
    trace = caller_once(True, [EXPECTED_SLOT] * 5, b"AB", 1,
                        "owner", "target")
    assert trace[0] == ("header_write", "owner", (11, 0, 0))
    assert all(t[0] != "select" for t in trace)


def test_caller_builds_then_notifies_when_slot_null():
    trace = caller_once(False, [EXPECTED_SLOT] * 5, b"AB", 1,
                        "owner", "target")
    assert trace[0] == ("construct_subobject", 0x30)
    assert trace[2] == ("flag_byte", 1)
    assert any(t[0] == "select" for t in trace)
    assert trace[-1] == ("call_60d52f0",)
