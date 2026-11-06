"""Tests for the node #115 arena snapshot refresh model (0x5f07200).

Run under pytest when available, or plain python3 (the __main__
runner below) — pytest is not installed on the author's VM.
"""

import os
import random
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from arena_snapshot_refresh_5f07200_115 import (  # noqa: E402
    COPIES,
    MEMBER_COUNTER,
    MEMBER_FIELD_940,
    MEMBER_REMAINING,
    OBJECT_MIN_SIZE,
    SNAP_COUNTER,
    SNAP_FIELD_960,
    SNAP_REMAINING,
    snapshot_refresh,
)


def _obj(size=OBJECT_MIN_SIZE, fill=0):
    return bytearray(bytes([fill]) * size)


def _set(obj, offset, value):
    struct.pack_into("<Q", obj, offset, value)


def _get(obj, offset):
    return struct.unpack_from("<Q", obj, offset)[0]


def test_copies_match_window_offsets():
    # The (source, destination) pairs and their order are the window.
    assert COPIES == (
        (MEMBER_REMAINING, SNAP_REMAINING),
        (MEMBER_FIELD_940, SNAP_FIELD_960),
        (MEMBER_COUNTER, SNAP_COUNTER),
    )
    assert (MEMBER_REMAINING, MEMBER_FIELD_940, MEMBER_COUNTER) == (
        0x930, 0x940, 0x918)
    assert (SNAP_REMAINING, SNAP_FIELD_960, SNAP_COUNTER) == (
        0x958, 0x960, 0x968)


def test_three_copies_land():
    obj = _obj()
    _set(obj, MEMBER_REMAINING, 0x1122334455667788)
    _set(obj, MEMBER_FIELD_940, 0xAABBCCDDEEFF0011)
    _set(obj, MEMBER_COUNTER, 0x0123456789ABCDEF)
    # Stale destination values are overwritten, not merged.
    _set(obj, SNAP_REMAINING, 0xFF)
    _set(obj, SNAP_FIELD_960, 0xFF)
    _set(obj, SNAP_COUNTER, 0xFF)
    assert snapshot_refresh(obj) is None
    assert _get(obj, SNAP_REMAINING) == 0x1122334455667788
    assert _get(obj, SNAP_FIELD_960) == 0xAABBCCDDEEFF0011
    assert _get(obj, SNAP_COUNTER) == 0x0123456789ABCDEF


def test_sources_and_other_bytes_untouched():
    rng = random.Random(0x5F07200)
    obj = bytearray(rng.randbytes(OBJECT_MIN_SIZE))
    before = bytes(obj)
    snapshot_refresh(obj)
    changed = {i for i in range(OBJECT_MIN_SIZE) if obj[i] != before[i]}
    allowed = set()
    for _, dst in COPIES:
        allowed.update(range(dst, dst + 8))
    assert changed <= allowed
    for src, _ in COPIES:
        assert _get(obj, src) == struct.unpack_from("<Q", before, src)[0]


def test_zero_and_full_width_values():
    obj = _obj(fill=0xEE)
    _set(obj, MEMBER_REMAINING, 0)
    _set(obj, MEMBER_FIELD_940, 0xFFFFFFFFFFFFFFFF)
    _set(obj, MEMBER_COUNTER, 0x8000000000000000)
    snapshot_refresh(obj)
    assert _get(obj, SNAP_REMAINING) == 0
    assert _get(obj, SNAP_FIELD_960) == 0xFFFFFFFFFFFFFFFF
    assert _get(obj, SNAP_COUNTER) == 0x8000000000000000


def test_second_run_is_noop():
    rng = random.Random(115)
    obj = bytearray(rng.randbytes(OBJECT_MIN_SIZE))
    snapshot_refresh(obj)
    once = bytes(obj)
    snapshot_refresh(obj)
    assert bytes(obj) == once


def test_larger_object_tail_untouched():
    obj = _obj(size=OBJECT_MIN_SIZE + 0x100, fill=0x5A)
    _set(obj, MEMBER_REMAINING, 7)
    _set(obj, MEMBER_FIELD_940, 8)
    _set(obj, MEMBER_COUNTER, 9)
    snapshot_refresh(obj)
    assert _get(obj, SNAP_REMAINING) == 7
    assert _get(obj, SNAP_FIELD_960) == 8
    assert _get(obj, SNAP_COUNTER) == 9
    assert all(b == 0x5A for b in obj[OBJECT_MIN_SIZE:])


def _run_all():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL", name, repr(exc))
        else:
            print("PASS", name)
    print("%d passed, %d failed" % (len(tests) - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
