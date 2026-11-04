"""Tests for the node #115 object release model
(tools/object_release_51c70_115.py, RE-001 work item
RE-001-object-release-51c70-115). Each check counts; the run prints
"<n> checks pass" on success.

Expectations are target-grounded: the +0x20 member released first,
the vector elements in order with null slots skipped, the buffer
delete with the capacity-minus-begin byte size only when begin is
non-null, and the +0x00 head released last via a tail jump -- all
read from the whole-function excerpt in the packet.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from object_release_51c70_115 import ReleaseObject, release_object

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
    # Empty object: nothing happens, no buffer delete, no head release.
    check(release_object(ReleaseObject("empty")) == [],
          "empty object releases nothing")

    # Single member alone, before anything else.
    check(release_object(ReleaseObject("s", single="solo")) ==
          [("release", 0x20, "solo")],
          "single member released alone")

    # Head alone: the tail-jump release is the only event.
    check(release_object(ReleaseObject("h", head="top")) ==
          [("release_tail", 0x00, "top")],
          "head alone released via tail jump")

    # Vector alone: elements in order, null slot skipped, then the
    # buffer delete with capacity (4 slots) * 8 = 32 bytes.
    check(release_object(ReleaseObject(
        "v", elements=["a", None, "b"], buffer="buf",
        capacity_slots=4)) ==
        [("release", 0x08, "a"), ("release", 0x08, "b"),
         ("delete_buffer", "buf", 32)],
        "vector order, null skipped, buffer delete 32 bytes")

    # Buffer with capacity but no elements: the delete still runs
    # (begin non-null), with size capacity * 8.
    check(release_object(ReleaseObject(
        "e", buffer="buf", capacity_slots=2)) ==
        [("delete_buffer", "buf", 16)],
        "empty vector still deletes its buffer, 16 bytes")

    # Buffer with zero capacity and no elements: delete with size 0.
    check(release_object(ReleaseObject(
        "z", buffer="buf", capacity_slots=0)) ==
        [("delete_buffer", "buf", 0)],
        "zero-capacity buffer deletes with size 0")

    # Full order: single, vector elements, buffer delete, head tail.
    check(release_object(ReleaseObject(
        "full", head="top", single="solo",
        elements=["a", None, "b"], buffer="buf",
        capacity_slots=3)) ==
        [("release", 0x20, "solo"), ("release", 0x08, "a"),
         ("release", 0x08, "b"), ("delete_buffer", "buf", 24),
         ("release_tail", 0x00, "top")],
        "full order: single, vector, buffer, head tail")

    # All-null vector slots: no releases, but the buffer delete runs.
    check(release_object(ReleaseObject(
        "n", elements=[None, None], buffer="buf",
        capacity_slots=2)) ==
        [("delete_buffer", "buf", 16)],
        "all-null slots: no releases, buffer still deleted")

    # The routine writes no object slot: the object is unchanged.
    obj = ReleaseObject("u", head="top", single="solo",
                        elements=["a", "b"], buffer="buf",
                        capacity_slots=2)
    release_object(obj)
    check(obj.head == "top" and obj.single == "solo" and
          obj.elements == ["a", "b"] and obj.buffer == "buf" and
          obj.capacity_slots == 2, "object slots unchanged by release")

    # Repeated release gives the same event list (model is pure).
    twice = ReleaseObject("t", head="top", single="solo",
                          elements=["a"], buffer="buf", capacity_slots=1)
    check(release_object(twice) == release_object(twice),
          "release is repeatable in the model")

    # Input guards (model safety, not binary claims).
    expect_raises(lambda: release_object(None), "null object raises")
    expect_raises(lambda: ReleaseObject("g", head=123),
                  "non-string head token raises")
    expect_raises(lambda: ReleaseObject("g", single=123),
                  "non-string single token raises")
    expect_raises(lambda: ReleaseObject("g", elements=["a", 5]),
                  "non-string element token raises")
    expect_raises(lambda: ReleaseObject("g", elements=["a", "b"],
                                        buffer="buf", capacity_slots=1),
                  "length above capacity raises")
    expect_raises(lambda: ReleaseObject("g", elements=["a"]),
                  "elements without a buffer raise")
    expect_raises(lambda: ReleaseObject("g", capacity_slots=1),
                  "capacity without a buffer raises")
    expect_raises(lambda: ReleaseObject("g", capacity_slots=-1),
                  "negative capacity raises")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
