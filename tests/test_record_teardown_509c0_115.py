"""Tests for the node #115 record teardown model
(tools/record_teardown_509c0_115.py, RE-001 work item
RE-001-record-teardown-509c0-115). Each check counts; the run prints
"<n> checks pass" on success.

Expectations are target-grounded: the flag-gated condition-variable
destroy, the +0x80-before-+0x70 delete order, the null-pointer skips,
and the no-write/no-record-free properties are read from the
whole-function excerpt in the packet.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from record_teardown_509c0_115 import Record, teardown_record

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
    # Flag zero, both buffers null: nothing happens.
    check(teardown_record(Record("a")) == [],
          "fresh record frees nothing")
    # Initializer-shaped record: flag byte 0 (word 0x100 low byte),
    # both pointers 0 -> same empty result.
    check(teardown_record(Record("init", flag=0)) == [],
          "initializer-shaped record frees nothing")

    # Flag nonzero alone: only the condition variable is destroyed.
    check(teardown_record(Record("b", flag=1)) ==
          [("condition_variable", "destroy")],
          "flag 1 destroys only the condition variable")
    check(teardown_record(Record("c", flag=255)) ==
          [("condition_variable", "destroy")],
          "any nonzero flag byte destroys the condition variable")

    # Buffers without the flag: deletes only, +0x80 before +0x70.
    check(teardown_record(Record("d", buffer_80="x", buffer_70="y")) ==
          [("delete_array", 0x80, "x"), ("delete_array", 0x70, "y")],
          "+0x80 freed before +0x70")
    check(teardown_record(Record("e", buffer_80="x")) ==
          [("delete_array", 0x80, "x")],
          "+0x80 alone, +0x70 null skipped")
    check(teardown_record(Record("f", buffer_70="y")) ==
          [("delete_array", 0x70, "y")],
          "+0x70 alone, +0x80 null skipped")

    # Full order: condition variable first, then +0x80, then +0x70.
    check(teardown_record(Record("g", flag=1, buffer_80="x",
                                 buffer_70="y")) ==
          [("condition_variable", "destroy"),
           ("delete_array", 0x80, "x"), ("delete_array", 0x70, "y")],
          "full order: cv, +0x80, +0x70")

    # The routine writes no record slot and never frees the record:
    # the object is unchanged after teardown.
    rec = Record("h", flag=1, buffer_80="x", buffer_70="y")
    teardown_record(rec)
    check(rec.flag == 1 and rec.buffer_80 == "x" and
          rec.buffer_70 == "y", "record slots unchanged by teardown")

    # Input guards (model safety, not binary claims).
    expect_raises(lambda: teardown_record(None), "null record raises")
    expect_raises(lambda: Record("i", flag=256), "flag above a byte raises")
    expect_raises(lambda: Record("j", flag=-1), "negative flag raises")
    expect_raises(lambda: Record("k", buffer_80=123),
                  "non-string buffer token raises")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
