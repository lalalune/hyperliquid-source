"""Tests for the node #115 allocation boundary model (0x5963650).

Target-grounded expectations: the size guard (product overflow
and the 2^63 - alignment limit, with the +0x10 word left
unwritten on that path), the zero-size fresh result, the plain
vs aligned dispatch (alignment < 0x11 and <= size, or trailing
zeros == 0), the four callee argument tuples, and the two result
shapes for a non-null and a null allocator return. Run from the
repository root:

    python3 tests/test_alloc_boundary_63650_115.py
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from alloc_boundary_63650_115 import (ALIGNED_ALLOC, ALIGNED_REALLOC,
                                      PLAIN_ALLOC, PLAIN_REALLOC,
                                      alloc_boundary)

CHECKS = []
POISON = bytes([0xAA] * 24)
NEW_PTR = 0x30000000
OLD_PTR = 0x20000000


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def words(result):
    return struct.unpack_from("<QQQ", result, 0)


def run(old_size, old_ptr, count, align, width, alloc_result):
    def allocate(kind, args):
        return alloc_result
    return alloc_boundary(old_size, old_ptr, count, align, width,
                          allocate, initial=POISON)


def main():
    # 1. Plain fresh allocation: count 3 x width 0x40, align 8.
    result, calls = run(0, OLD_PTR, 3, 8, 0x40, NEW_PTR)
    check("fresh plain call", calls == [(PLAIN_ALLOC, (0xC0,))])
    check("fresh plain result", words(result) == (0, NEW_PTR, 0xC0))

    # 2. Null return: tag 1, +0x08 = alignment, +0x10 = size.
    result, calls = run(0, OLD_PTR, 3, 8, 0x40, 0)
    check("fresh null result", words(result) == (1, 8, 0xC0))

    # 3. Zero-size fresh request: no call, (0, alignment, 0).
    result, calls = run(0, OLD_PTR, 0, 8, 0x40, NEW_PTR)
    check("zero fresh no call", calls == [])
    check("zero fresh result", words(result) == (0, 8, 0))
    result, calls = run(0, OLD_PTR, 5, 0x1000, 0, NEW_PTR)
    check("zero-width fresh result", words(result) == (0, 0x1000, 0))

    # 4. Guard: product overflow (2^32 x 2^32 = 2^64). +0x10 word
    # keeps its poison: the guard path never writes it, and no
    # allocator is called.
    result, calls = run(0, OLD_PTR, 1 << 32, 8, 1 << 32, NEW_PTR)
    check("overflow no call", calls == [])
    check("overflow result", words(result)[:2] == (1, 0))
    check("overflow leaves +0x10",
          result[16:24] == POISON[16:24])

    # 5. Guard limit is exactly 2^63 - alignment: at the limit
    # the request proceeds; one byte above it fails.
    result, calls = run(0, OLD_PTR, (1 << 61) - 2, 8, 4, NEW_PTR)
    check("at-limit proceeds", calls == [(PLAIN_ALLOC, ((1 << 63) - 8,))]
          and words(result) == (0, NEW_PTR, (1 << 63) - 8))
    result, calls = run(0, OLD_PTR, (1 << 61) - 1, 8, 4, NEW_PTR)
    check("above-limit fails", calls == []
          and words(result)[:2] == (1, 0))

    # 6. Alignment above 2^63 wraps the limit upward: 2^63 - 2^63
    # = 0 rejects any positive size, while align 2^64 - 1 gives
    # limit 2^63 + 1.
    result, calls = run(0, OLD_PTR, 1, 1 << 63, 1, NEW_PTR)
    check("align 2^63 rejects size 1", calls == [])
    result, calls = run(0, OLD_PTR, 1, (1 << 64) - 1, 1, NEW_PTR)
    check("align max: wrapped limit admits, odd align plain",
          calls == [(PLAIN_ALLOC, (1,))]
          and words(result) == (0, NEW_PTR, 1))

    # 7. Dispatch: trailing zeros of 0x20 = 5, and 0x20 is not
    # below 0x11, so the aligned form is chosen.
    result, calls = run(0, OLD_PTR, 0x100, 0x20, 0x100, NEW_PTR)
    check("aligned fresh", calls == [(ALIGNED_ALLOC, (0x10000, 5))])
    # Alignment equal to the size still takes the plain form when
    # below 0x11; one above the size takes the aligned form.
    result, calls = run(0, OLD_PTR, 1, 0x10, 0x10, NEW_PTR)
    check("align == size plain", calls == [(PLAIN_ALLOC, (0x10,))])
    result, calls = run(0, OLD_PTR, 1, 0x10, 0x8, NEW_PTR)
    check("align > size aligned", calls == [(ALIGNED_ALLOC, (0x8, 4))])
    # Alignment 1 with a zero product goes plain via tz == 0 in
    # the reallocation family (no zero-size shortcut there).
    result, calls = run(7, OLD_PTR, 0, 1, 8, NEW_PTR)
    check("realloc zero plain", calls == [(PLAIN_REALLOC, (OLD_PTR, 0))])
    # Non-power-of-two alignment 0x18: trailing zeros 3.
    result, calls = run(0, OLD_PTR, 1, 0x18, 0x10, NEW_PTR)
    check("align 0x18 aligned", calls == [(ALIGNED_ALLOC, (0x10, 3))])
    # Alignment 0 is accepted by the plain test (0 <= any size).
    result, calls = run(0, OLD_PTR, 2, 0, 8, NEW_PTR)
    check("align 0 plain", calls == [(PLAIN_ALLOC, (0x10,))])

    # 8. Reallocation family: old size non-zero only switches the
    # callee; its value is never used beyond zero/non-zero. The
    # old pointer is passed verbatim, even when null.
    result, calls = run(1, OLD_PTR, 3, 8, 0x40, NEW_PTR)
    check("realloc plain", calls == [(PLAIN_REALLOC, (OLD_PTR, 0xC0))])
    result, calls = run(999, OLD_PTR, 3, 8, 0x40, NEW_PTR)
    check("realloc old size value unused",
          calls == [(PLAIN_REALLOC, (OLD_PTR, 0xC0))])
    result, calls = run(7, 0, 3, 8, 0x40, NEW_PTR)
    check("realloc null old pointer verbatim",
          calls == [(PLAIN_REALLOC, (0, 0xC0))])
    result, calls = run(7, OLD_PTR, 1, 0x20, 0x100, NEW_PTR)
    check("realloc aligned",
          calls == [(ALIGNED_REALLOC, (OLD_PTR, 0x100, 5))])
    result, calls = run(7, OLD_PTR, 3, 8, 0x40, 0)
    check("realloc null result", words(result) == (1, 8, 0xC0))

    # 9. The product is count x width in either caller's order:
    # width in rcx vs r9 is the caller's choice; the boundary
    # multiplies rcx by r9 (count=rcx here by construction).
    result, calls = run(0, OLD_PTR, 0x40, 8, 3, NEW_PTR)
    check("product symmetric", calls == [(PLAIN_ALLOC, (0xC0,))])

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
