"""Tests for the node #115 refcount increment model
(tools/refcount_increment_12a00_115.py, RE-001 work item
RE-001-refcount-increment-12a00-115). Each check counts; the run
prints "<n> checks pass" on success.

Expectations are target-grounded, read from the whole-function
excerpt in the packet: the body is a single `addl $0x1,
0x40(%rdi)`, so the dword at +0x40 increments by exactly one and
wraps modulo 2**32 -- including the 0xffffffff -> 0 wrap that a
saturating or trapping model would get wrong, and the
0x7fffffff -> 0x80000000 step that a signed model would get
wrong.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from refcount_increment_12a00_115 import refcount_increment

CHECKS = [0]


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


def expect_raises(fn, label):
    try:
        fn()
    except (ValueError, TypeError):
        CHECKS[0] += 1
    else:
        raise AssertionError(label)


def main():
    # Ordinary steps.
    check(refcount_increment(0) == 1, "0 increments to 1")
    check(refcount_increment(1) == 2, "1 increments to 2")
    check(refcount_increment(2) == 3, "2 increments to 3")
    check(refcount_increment(41) == 42, "41 increments to 42")

    # The fresh-object case from the prepare call site: the
    # copy-on-write swap leaves the count the move helper copied,
    # and this routine raises it by exactly one -- never by more.
    check(refcount_increment(1) - 1 == 1,
          "prepare-case step is exactly one")

    # Signed-boundary step: no sign interpretation, no trap.
    check(refcount_increment(0x7FFFFFFF) == 0x80000000,
          "0x7fffffff increments to 0x80000000")
    check(refcount_increment(0x80000000) == 0x80000001,
          "0x80000000 increments to 0x80000001")

    # Wrap: addl wraps modulo 2**32; it neither saturates nor
    # traps, so the maximum count wraps to zero. (The release at
    # 0x5f13ea0 treats a decremented-to-zero count as the destroy
    # signal; what a wrapped-to-zero count would mean to a later
    # release is a caller question, not claimed here.)
    check(refcount_increment(0xFFFFFFFE) == 0xFFFFFFFF,
          "0xfffffffe increments to 0xffffffff")
    check(refcount_increment(0xFFFFFFFF) == 0,
          "0xffffffff wraps to 0")

    # Every result stays an unsigned 32-bit value.
    for value in (0, 1, 0x12345678, 0xFFFFFFFE, 0xFFFFFFFF):
        result = refcount_increment(value)
        check(0 <= result <= 0xFFFFFFFF,
              "result for %#x stays in uint32 range" % value)

    # Input guards (model safety, not binary claims).
    expect_raises(lambda: refcount_increment(-1),
                  "negative count raises")
    expect_raises(lambda: refcount_increment(2 ** 32),
                  "count above uint32 raises")
    expect_raises(lambda: refcount_increment(True),
                  "bool count raises")
    expect_raises(lambda: refcount_increment(1.5),
                  "non-integer count raises")
    expect_raises(lambda: refcount_increment(None),
                  "null count raises")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
