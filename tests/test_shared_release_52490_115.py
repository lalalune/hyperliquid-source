"""Tests for the node #115 shared release model (0x5a52490).

Target-grounded expectations: the state-2 early return that
touches nothing; the first callee running before any release
step with its result discarded; the lock-dec on the +0x08
refcount with the destructor chosen by the +0x00 byte only when
the count reaches 0; the +0x30/+0x38 callback tail call through
[table + 0x18]; and the three LSDA landing pads (pair-release
redo for a first-callee raise, callback-only for a destructor
raise, the 'panic in a destructor during cleanup' shim for a
raise inside cleanup). Run from the repository root:

    python3 tests/test_shared_release_52490_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from shared_release_52490_115 import (
    CALLBACK_DATA_OFFSET, CALLBACK_ENTRY_OFFSET, CALLBACK_TABLE_OFFSET,
    DESTRUCTOR_NONZERO, DESTRUCTOR_ZERO, FIRST_CALLEE, PAIR_HELPER,
    PANIC_MESSAGE, PANIC_SHIM, REFCOUNT_POINTER_OFFSET, RELEASED_STATE,
    ROUTINE, ROUTINE_FDE, ROUTINE_SIZE, STATE_OFFSET, UNWIND_RESUME,
    Cell, CleanupPanic, release)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def kinds(events):
    return [event[0] for event in events]


def main():
    # Pinned constants.
    check("routine address", ROUTINE == 0x5A52490)
    check("routine fde", ROUTINE_FDE == (0x5A52490, 0x5A52518))
    check("routine size", ROUTINE_SIZE == 136)
    check("state offset", STATE_OFFSET == 0x00)
    check("refcount offset", REFCOUNT_POINTER_OFFSET == 0x08)
    check("callback table offset", CALLBACK_TABLE_OFFSET == 0x30)
    check("callback data offset", CALLBACK_DATA_OFFSET == 0x38)
    check("callback entry offset", CALLBACK_ENTRY_OFFSET == 0x18)
    check("released state", RELEASED_STATE == 2)
    check("panic message",
          PANIC_MESSAGE == "panic in a destructor during cleanup"
          and len(PANIC_MESSAGE) == 0x24)

    # State 2: immediate return, nothing else is touched even
    # with a live refcount and a present callback table.
    cell = Cell(state=2, refcount=7, callback_table=0x1000,
                callback_data=0x55)
    events = []
    check("state 2 returns noop", release(cell, events) == "noop")
    check("state 2 emits only the noop event", kinds(events) == ["noop"])
    check("state 2 leaves the refcount", cell.refcount == 7)

    # The first callee runs first, before the decrement.
    cell = Cell(state=1, refcount=3)
    events = []
    check("plain release returns", release(cell, events) == "returned")
    check("first callee is the first event",
          events[0] == ("first-callee", FIRST_CALLEE, "cell"))
    check("decrement follows", events[1] == ("dec", 2))
    check("no destructor above zero",
          "destructor" not in kinds(events))
    check("no callback without a table",
          "callback-tail" not in kinds(events))

    # Decrement to exactly 0 calls the destructor chosen by the
    # selector byte, with the +0x08 field as its argument.
    cell = Cell(state=0, refcount=1)
    events = []
    release(cell, events)
    check("zero selector picks the zero destructor",
          ("destructor", DESTRUCTOR_ZERO, "cell+0x8") in events)
    cell = Cell(state=1, refcount=1)
    events = []
    release(cell, events)
    check("nonzero selector picks the nonzero destructor",
          ("destructor", DESTRUCTOR_NONZERO, "cell+0x8") in events)
    cell = Cell(state=3, refcount=1)
    events = []
    release(cell, events)
    check("selector 3 picks the nonzero destructor",
          ("destructor", DESTRUCTOR_NONZERO, "cell+0x8") in events)
    cell = Cell(state=0x100, refcount=1)
    events = []
    release(cell, events)
    check("selector is the low byte of the state dword",
          ("destructor", DESTRUCTOR_ZERO, "cell+0x8") in events)

    # Callback: tail-called through [table + 0x18] with the
    # +0x38 data value in rdi, after the pair release.
    cell = Cell(state=1, refcount=2, callback_table=0x9000,
                callback_data=0x1234)
    events = []
    check("callback release tail-calls",
          release(cell, events) == "tail-called")
    check("callback is the last event",
          events[-1] == ("callback-tail", 0x9000 + 0x18, 0x1234))
    check("pair release precedes the callback",
          kinds(events) == ["first-callee", "dec", "callback-tail"])

    # First callee raises: pad 0x5a524ef redoes the pair release
    # through the standalone helper, calls the callback, resumes.
    cell = Cell(state=1, refcount=1, callback_table=0x9000,
                callback_data=0x77)
    events = []
    try:
        release(cell, events, fail="first")
        check("first-callee raise propagates", False)
    except RuntimeError:
        pass
    check("cleanup runs the pair helper",
          ("pair-helper", PAIR_HELPER) in events)
    check("cleanup decrements exactly once",
          kinds(events).count("dec") == 1)
    check("cleanup calls the destructor on zero",
          ("destructor", DESTRUCTOR_NONZERO, "cell+0x8") in events)
    check("cleanup calls (not tail-calls) the callback",
          ("callback-call", 0x9000 + 0x18, 0x77) in events
          and "callback-tail" not in kinds(events))
    check("cleanup ends in resume",
          events[-1] == ("resume", UNWIND_RESUME))

    # Destructor raises: pad 0x5a524ea runs only the callback
    # step; the pair release is not redone.
    cell = Cell(state=0, refcount=1, callback_table=0x9000,
                callback_data=0x99)
    events = []
    try:
        release(cell, events, fail="destructor")
        check("destructor raise propagates", False)
    except RuntimeError:
        pass
    check("destructor pad skips the pair helper",
          "pair-helper" not in kinds(events))
    check("destructor pad decrements exactly once",
          kinds(events).count("dec") == 1)
    check("destructor pad calls the callback",
          ("callback-call", 0x9000 + 0x18, 0x99) in events)
    check("destructor pad ends in resume",
          events[-1] == ("resume", UNWIND_RESUME))

    # A raise inside cleanup (here the redone destructor, and
    # separately the cleanup callback) goes to the shim at
    # 0x5a52512 instead of resuming.
    cell = Cell(state=1, refcount=1)
    events = []
    try:
        release(cell, events, fail={"first", "destructor"})
        check("cleanup destructor raise panics", False)
    except CleanupPanic:
        pass
    check("cleanup panic names the shim",
          ("cleanup-panic", PANIC_SHIM, PANIC_MESSAGE) in events)
    check("cleanup panic never resumes",
          "resume" not in kinds(events))
    cell = Cell(state=1, refcount=1, callback_table=0x9000)
    events = []
    try:
        release(cell, events, fail={"destructor", "callback"})
        check("cleanup callback raise panics", False)
    except CleanupPanic:
        pass
    check("cleanup callback panic names the shim",
          ("cleanup-panic", PANIC_SHIM, PANIC_MESSAGE) in events)

    # Corruption control: a null +0x08 pointer on a live cell is
    # refused by the model (the binary faults on the lock dec).
    cell = Cell(state=1, refcount=None)
    events = []
    try:
        release(cell, events)
        check("null refcount pointer refused", False)
    except ValueError:
        pass
    check("null refcount still ran the first callee first",
          kinds(events) == ["first-callee"])

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
