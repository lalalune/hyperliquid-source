"""Tests for the node #115 guard release model (0x5f0b5e0).

Run under pytest when available, or plain python3 (the __main__
runner below) — pytest is not installed on the author's VM.
"""

import os
import random
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from guard_release_5f0b5e0_115 import (  # noqa: E402
    DEVICE_OFFSET,
    OWNS_OFFSET,
    SLOT_SIZE,
    THROW_CODE,
    SystemErrorThrow,
    guard_release,
)

MEM_SIZE = 0x100


def _slot(device=0, owns=0, fill=0):
    slot = bytearray([fill] * SLOT_SIZE)
    struct.pack_into("<Q", slot, DEVICE_OFFSET, device)
    slot[OWNS_OFFSET] = owns
    return slot


def _mem(fill=0):
    return bytearray([fill] * MEM_SIZE)


def test_layout_constants():
    assert SLOT_SIZE == 16
    assert DEVICE_OFFSET == 0x00
    assert OWNS_OFFSET == 0x08
    assert THROW_CODE == 1


def test_release_clears_lock_byte_and_owns():
    mem = _mem(fill=0xEE)
    mem[0x40] = 1
    slot = _slot(device=0x40, owns=1, fill=0xA5)
    before = bytes(slot)
    assert guard_release(slot, mem) is None
    assert mem[0x40] == 0
    assert slot[OWNS_OFFSET] == 0
    # The device pointer field and the padding are not written.
    assert bytes(slot[:OWNS_OFFSET]) == before[:OWNS_OFFSET]
    assert bytes(slot[OWNS_OFFSET + 1:]) == before[OWNS_OFFSET + 1:]
    # No other memory byte changes.
    assert all(b == 0xEE for i, b in enumerate(mem) if i != 0x40)


def test_not_owning_throws_and_touches_nothing():
    mem = _mem(fill=0x77)
    mem[0x40] = 1
    slot = _slot(device=0x40, owns=0, fill=0x3C)
    slot_before, mem_before = bytes(slot), bytes(mem)
    try:
        guard_release(slot, mem)
    except SystemErrorThrow as exc:
        assert exc.code == 1
    else:
        raise AssertionError("expected SystemErrorThrow")
    assert bytes(slot) == slot_before
    assert bytes(mem) == mem_before


def test_null_device_keeps_owns_and_writes_nothing():
    mem = _mem(fill=0x99)
    slot = _slot(device=0, owns=1, fill=0x5A)
    slot_before, mem_before = bytes(slot), bytes(mem)
    assert guard_release(slot, mem) is None
    # The owns byte is NOT cleared on the null-device arm.
    assert slot[OWNS_OFFSET] == 1
    assert bytes(slot) == slot_before
    assert bytes(mem) == mem_before


def test_any_nonzero_owns_releases():
    for owns in (0x02, 0x7F, 0x80, 0xFF):
        mem = _mem()
        mem[0x10] = 1
        slot = _slot(device=0x10, owns=owns)
        guard_release(slot, mem)
        assert mem[0x10] == 0
        assert slot[OWNS_OFFSET] == 0


def test_lock_byte_already_zero_still_drops_owns():
    mem = _mem()
    assert mem[0x20] == 0
    slot = _slot(device=0x20, owns=1)
    guard_release(slot, mem)
    assert mem[0x20] == 0
    assert slot[OWNS_OFFSET] == 0


def test_second_release_throws():
    mem = _mem()
    mem[0x30] = 1
    slot = _slot(device=0x30, owns=1)
    guard_release(slot, mem)
    try:
        guard_release(slot, mem)
    except SystemErrorThrow as exc:
        assert exc.code == THROW_CODE
    else:
        raise AssertionError("second release must throw")


def test_randomised_states_match_arm_table():
    rng = random.Random(0x5F0B5E0)
    for _ in range(300):
        device = rng.choice([0, 0x08, 0x40, MEM_SIZE - 1])
        owns = rng.choice([0, 1, 0x42, 0xFF])
        slot = bytearray(rng.randbytes(SLOT_SIZE))
        struct.pack_into("<Q", slot, DEVICE_OFFSET, device)
        slot[OWNS_OFFSET] = owns
        mem = bytearray(rng.randbytes(MEM_SIZE))
        slot_before, mem_before = bytes(slot), bytes(mem)
        if owns == 0:
            try:
                guard_release(slot, mem)
            except SystemErrorThrow as exc:
                assert exc.code == 1
            else:
                raise AssertionError("expected throw")
            assert bytes(slot) == slot_before
            assert bytes(mem) == mem_before
        elif device == 0:
            guard_release(slot, mem)
            assert bytes(slot) == slot_before
            assert bytes(mem) == mem_before
        else:
            guard_release(slot, mem)
            assert mem[device] == 0
            assert slot[OWNS_OFFSET] == 0
            assert bytes(slot[:OWNS_OFFSET]) == slot_before[:OWNS_OFFSET]
            assert bytes(slot[OWNS_OFFSET + 1:]) == \
                slot_before[OWNS_OFFSET + 1:]
            for i in range(MEM_SIZE):
                if i != device:
                    assert mem[i] == mem_before[i]


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
