"""Tests for the node #115 arena allocate model (window 0x605d930).

Run under pytest when available, or plain python3 (the __main__
runner below) — pytest is not installed on the author's VM.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from arena_allocate_605d930_115 import (  # noqa: E402
    MASK64,
    Arena,
    arena_allocate,
)


class Slow:
    """Records the tail-jump contract and returns a sentinel."""

    def __init__(self, result=0x5E17DE1):
        self.result = result
        self.calls = []

    def __call__(self, size, third):
        self.calls.append((size, third))
        return self.result


def test_fast_partial_carve():
    a = Arena(end=0x5000, remaining=0x800)
    slow = Slow()
    out = arena_allocate(a, 0x100, slow)
    assert out == 0x4F00  # returns the post-decrement end field
    assert a.end == 0x4F00
    assert a.remaining == 0x700
    assert slow.calls == []


def test_fast_exact_fit():
    a = Arena(end=0x5000, remaining=0x800)
    out = arena_allocate(a, 0x800, Slow())
    assert out == 0x4800
    assert a.end == 0x4800
    assert a.remaining == 0


def test_fast_zero_size_zero_remaining():
    # 0 >= 0 takes the fast path: nothing changes, end returned.
    a = Arena(end=0x5000, remaining=0)
    slow = Slow()
    assert arena_allocate(a, 0, slow) == 0x5000
    assert (a.end, a.remaining) == (0x5000, 0)
    assert slow.calls == []


def test_fast_zero_size_with_remaining():
    a = Arena(end=0x5000, remaining=0x800)
    assert arena_allocate(a, 0, Slow()) == 0x5000
    assert (a.end, a.remaining) == (0x5000, 0x800)


def test_slow_when_short_by_one():
    a = Arena(end=0x5000, remaining=0x800)
    slow = Slow()
    out = arena_allocate(a, 0x801, slow)
    assert out == slow.result  # slow return passes through
    assert slow.calls == [(0x801, 0)]  # rdx forced to 0
    assert (a.end, a.remaining) == (0x5000, 0x800)  # untouched


def test_slow_on_empty():
    a = Arena(end=0x5000, remaining=0)
    slow = Slow()
    arena_allocate(a, 1, slow)
    assert slow.calls == [(1, 0)]
    assert (a.end, a.remaining) == (0x5000, 0)


def test_end_wraps_when_state_inconsistent():
    # remaining >= size is the only guard: an end field smaller
    # than the size wraps in 64-bit arithmetic, literally.
    a = Arena(end=8, remaining=100)
    out = arena_allocate(a, 16, Slow())
    assert a.remaining == 84
    assert a.end == (8 - 16) & MASK64
    assert out == a.end


def test_max_values():
    a = Arena(end=MASK64, remaining=MASK64)
    out = arena_allocate(a, MASK64, Slow())
    assert out == 0
    assert (a.end, a.remaining) == (0, 0)


def test_huge_size_goes_slow():
    a = Arena(end=0x5000, remaining=0x800)
    slow = Slow()
    arena_allocate(a, MASK64, slow)
    assert slow.calls == [(MASK64, 0)]
    assert (a.end, a.remaining) == (0x5000, 0x800)


def test_return_is_stored_end_on_fast_path():
    for end, remaining, size in (
        (0x1000, 0x1000, 0x1000),
        (0xDEADBEEF, 0x1234, 0x1234),
        (0, 5, 5),
        (7, 7, 0),
    ):
        a = Arena(end=end, remaining=remaining)
        out = arena_allocate(a, size, Slow())
        assert out == a.end == (end - size) & MASK64
        assert a.remaining == remaining - size


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print("PASS", fn.__name__)
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL", fn.__name__, exc)
    print("%d passed, %d failed" % (len(fns) - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
