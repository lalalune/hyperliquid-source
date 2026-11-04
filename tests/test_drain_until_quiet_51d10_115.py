"""Tests for the node #115 drain-until-quiet model
(tools/drain_until_quiet_51d10_115.py, RE-001 work item
RE-001-drain-until-quiet-51d10-115). Each check counts; the run
prints "<n> checks pass" on success.

Expectations are target-grounded: the loop returns at once when
both pending fields are already zero; it calls the worker with
the object field at +0xa10 once per pending iteration; each
iteration reads the +0x1430 qword first and reads the +0x143c
dword only when that qword is zero; and it returns only after
an iteration that reads a zero qword and then a zero dword --
all read from the whole-function excerpt in the packet. What the
worker does and what the fields denote are not claimed, so the
worker here is a test double that clears the fields.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from drain_until_quiet_51d10_115 import (
    CALLEE_ARG_OFFSET,
    DrainObject,
    drain_until_quiet,
)

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
    check(CALLEE_ARG_OFFSET == 0xA10, "worker argument is object +0xa10")

    # Already quiet: zero calls, one qword read, one dword read.
    trace = drain_until_quiet(DrainObject(0, 0), lambda arg: None)
    check(trace.calls == 0, "already quiet makes no worker call")
    check(trace.qword_reads == 1, "already quiet reads the qword once")
    check(trace.dword_reads == 1, "already quiet reads the dword once")

    # Qword-only pending, cleared on the first call.
    obj = DrainObject(5, 0)

    def clear_qword(arg):
        assert arg == 0xA10
        obj.pending_qword = 0

    trace = drain_until_quiet(obj, clear_qword)
    check(trace.calls == 1, "qword pending calls the worker once")
    check(trace.qword_reads == 2, "qword cleared after one call: 2 reads")
    check(trace.dword_reads == 1, "dword read only on the quiet iteration")

    # Dword-only pending, cleared on the second call.
    obj = DrainObject(0, 3)
    calls = [0]

    def clear_dword_second(arg):
        calls[0] += 1
        if calls[0] == 2:
            obj.pending_dword = 0

    trace = drain_until_quiet(obj, clear_dword_second)
    check(trace.calls == 2, "dword pending calls until cleared")
    check(trace.qword_reads == 3, "qword read once per iteration")
    check(trace.dword_reads == 3, "dword read once per iteration here")

    # Check order: a non-zero qword suppresses the dword read.
    # The worker leaves the qword non-zero for two calls, then
    # clears both fields on the third call.
    obj = DrainObject(9, 7)
    calls = [0]

    def clear_both_third(arg):
        calls[0] += 1
        if calls[0] == 3:
            obj.pending_qword = 0
            obj.pending_dword = 0

    trace = drain_until_quiet(obj, clear_both_third)
    check(trace.calls == 3, "qword-gated loop calls three times")
    check(trace.qword_reads == 4, "qword read once per iteration")
    check(trace.dword_reads == 1,
          "dword read only on the final quiet iteration, "
          "never while the qword was non-zero")

    # Qword precedence: both pending, worker clears the qword
    # first, then the dword -- two calls, not one.
    obj = DrainObject(1, 1)
    calls = [0]

    def clear_in_order(arg):
        calls[0] += 1
        if calls[0] == 1:
            obj.pending_qword = 0
        else:
            obj.pending_dword = 0

    trace = drain_until_quiet(obj, clear_in_order)
    check(trace.calls == 2, "clearing qword first still needs a dword call")
    check(trace.qword_reads == 3, "three iterations to quiet")
    check(trace.dword_reads == 2, "dword read on the last two iterations")

    # The worker always receives the same +0xa10 argument.
    seen = []
    obj = DrainObject(2, 0)

    def record_and_clear(arg):
        seen.append(arg)
        obj.pending_qword = 0

    drain_until_quiet(obj, record_and_clear)
    check(seen == [0xA10], "worker argument is always object +0xa10")

    # Large pending values are plain integers, not booleans.
    obj = DrainObject(2 ** 64 - 1, 2 ** 32 - 1)

    def clear_all(arg):
        obj.pending_qword = 0
        obj.pending_dword = 0

    trace = drain_until_quiet(obj, clear_all)
    check(trace.calls == 1, "max pending values still drain in one call")

    # Input guards (model safety, not binary claims).
    expect_raises(lambda: drain_until_quiet(None, lambda a: None),
                  "null object raises")
    expect_raises(lambda: drain_until_quiet(DrainObject(0, 0), None),
                  "non-callable worker raises")
    expect_raises(lambda: DrainObject(-1, 0), "negative qword raises")
    expect_raises(lambda: DrainObject(0, -1), "negative dword raises")
    expect_raises(lambda: DrainObject(2 ** 64, 0), "qword overflow raises")
    expect_raises(lambda: DrainObject(0, 2 ** 32), "dword overflow raises")
    expect_raises(lambda: DrainObject(True, 0), "bool qword raises")
    expect_raises(lambda: DrainObject(0, True), "bool dword raises")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
