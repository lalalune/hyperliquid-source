"""Tests for tools/shared_handle_copy_115.py, the model of node #115
routine 0x5d50400. The oracle is the routine's own selection and
count rules: selector null or flag 0 copies slot A, flag non-zero
copies slot B, a non-null copied control count rises by exactly 1,
and the destination's previous pair is never released by the copy.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from shared_handle_copy_115 import (  # noqa: E402
    ControlBlock, Holder, Selector, copy_active_handle)

CHECKS = [0]


def check(condition, label):
    CHECKS[0] += 1
    if not condition:
        raise AssertionError(label)


def expect_raises(kind, fn, label):
    CHECKS[0] += 1
    try:
        fn()
    except kind:
        return
    except Exception as exc:  # noqa: BLE001 - any other error is a failure
        raise AssertionError("%s: wrong exception %r" % (label, exc))
    raise AssertionError("%s: no exception" % label)


def main():
    # Selector null -> slot A, lock form at the captured global byte 0.
    ctrl_a, ctrl_b = ControlBlock(3), ControlBlock(7)
    holder = Holder(("ptr-a", ctrl_a), None, ("ptr-b", ctrl_b))
    ptr, ctrl, form = copy_active_handle(holder, global_byte=0)
    check(ptr == "ptr-a" and ctrl is ctrl_a, "null selector copies slot A")
    check(form == "lock", "global byte 0 selects the lock form")
    check(ctrl_a.count == 4, "slot A count rises by exactly 1")
    check(ctrl_b.count == 7, "slot B count untouched when A is copied")

    # Selector flag 0 -> slot A.
    ctrl_a, ctrl_b = ControlBlock(0), ControlBlock(0)
    holder = Holder(("ptr-a", ctrl_a), Selector(0), ("ptr-b", ctrl_b))
    ptr, ctrl, form = copy_active_handle(holder)
    check(ptr == "ptr-a" and ctrl is ctrl_a, "flag 0 copies slot A")
    check(ctrl_a.count == 1 and ctrl_b.count == 0, "flag 0 counts only A")

    # Selector flag non-zero (1 and 255) -> slot B.
    for flag in (1, 255):
        ctrl_a, ctrl_b = ControlBlock(5), ControlBlock(9)
        holder = Holder(("ptr-a", ctrl_a), Selector(flag), ("ptr-b", ctrl_b))
        ptr, ctrl, form = copy_active_handle(holder)
        check(ptr == "ptr-b" and ctrl is ctrl_b,
              "flag %d copies slot B" % flag)
        check(ctrl_b.count == 10 and ctrl_a.count == 5,
              "flag %d counts only B" % flag)

    # Global byte non-zero -> plain form, count still rises by 1.
    ctrl_a = ControlBlock(2)
    holder = Holder(("ptr-a", ctrl_a), None, ("ptr-b", None))
    ptr, ctrl, form = copy_active_handle(holder, global_byte=1)
    check(form == "plain", "global byte non-zero selects the plain form")
    check(ctrl_a.count == 3, "plain form still increments by 1")

    # Copied control null -> pair copied, nothing incremented, no form.
    holder = Holder(("ptr-a", None), Selector(9), ("ptr-b", None))
    ptr, ctrl, form = copy_active_handle(holder)
    check(ptr == "ptr-b" and ctrl is None and form is None,
          "null control copies the pair with no increment")

    # The routine tests only the control pointer: a null managed
    # pointer with a live control still increments that control.
    ctrl_b = ControlBlock(4)
    holder = Holder(("ptr-a", None), Selector(1), (None, ctrl_b))
    ptr, ctrl, form = copy_active_handle(holder)
    check(ptr is None and ctrl_b.count == 5,
          "null pointer with live control still increments")

    # Each copy bumps again: the destination's previous pair is not
    # released by the copy, it is simply overwritten by the caller.
    ctrl_a = ControlBlock(0)
    holder = Holder(("ptr-a", ctrl_a), None, ("ptr-b", None))
    copy_active_handle(holder)
    copy_active_handle(holder)
    check(ctrl_a.count == 2, "two copies increment twice, no release")

    # Model guards (not binary claims): out-of-range flag and global
    # byte values are rejected instead of silently wrapped.
    expect_raises(ValueError, lambda: Selector(256), "flag above a byte")
    expect_raises(ValueError, lambda: Selector(-1), "negative flag")
    expect_raises(ValueError,
                  lambda: copy_active_handle(holder, global_byte=256),
                  "global byte above a byte")
    expect_raises(TypeError,
                  lambda: copy_active_handle(holder, global_byte="x"),
                  "non-integer global byte")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
