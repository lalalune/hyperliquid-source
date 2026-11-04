#!/usr/bin/env python3
"""Tests for tools/take_record_4e420_115.py.

Every expectation is grounded in the 0x5d4e420..0x5d4e59c
disassembly in research/work-items/RE-001-take-record-4e420-115/main.txt
and the 0x5d49b10..0x5d49b79 helper body in helper.txt.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.take_record_4e420_115 import (
    REPORT_LEVEL,
    REPORT_MESSAGE,
    REPORT_PATH,
    ModelError,
    Record,
    Source,
    move_assign,
    run,
)


def harness(slot):
    calls = []
    source = Source(slot=slot, guard="G")

    def acquire(guard):
        calls.append(("acquire", guard))

    def release(guard):
        calls.append(("release", guard))

    def fill(temp, slot_object):
        calls.append(("fill", slot_object))
        temp.value = 0x12345678
        temp.flags = 0xABCD
        temp.pointer = "data"

    def destroy(slot_object):
        calls.append(("destroy", slot_object))

    def delete_object(slot_object, size):
        calls.append(("delete_object", slot_object, size))

    def report(temp, level, message, path):
        calls.append(("report", level, message, path))
        temp.value = 7
        temp.flags = 3
        temp.pointer = "err"

    def delete_array(pointer):
        calls.append(("delete_array", pointer))

    return source, calls, (acquire, release, fill, destroy,
                           delete_object, report, delete_array)


def test_normal_take():
    slot = object()
    source, calls, hooks = harness(slot)
    out = Record()
    assert run(out, source, *hooks) is out
    assert (out.value, out.flags, out.pointer) == (0x12345678, 0xABCD, "data")
    assert source.slot is None
    assert calls == [("acquire", "G"), ("fill", slot), ("destroy", slot),
                     ("delete_object", slot, 0x38), ("release", "G")]
    print("ok: normal take moves fields, clears slot, destroys, deletes 0x38")


def test_prefilled_out_pointer_dropped_without_delete():
    slot = object()
    source, calls, hooks = harness(slot)
    out = Record(value=9, flags=9, pointer="old")
    run(out, source, *hooks)
    assert (out.value, out.flags, out.pointer) == (0x12345678, 0xABCD, "data")
    assert not [c for c in calls if c[0] == "delete_array"]
    print("ok: pre-filled out pointer is dropped by the init, never deleted")


def test_empty_slot_report_path():
    source, calls, hooks = harness(None)
    out = Record()
    run(out, source, *hooks)
    assert (out.value, out.flags, out.pointer) == (7, 3, "err")
    assert source.slot is None
    assert calls == [("acquire", "G"),
                     ("report", REPORT_LEVEL, REPORT_MESSAGE, REPORT_PATH),
                     ("release", "G")]
    assert REPORT_MESSAGE == "No trace file to close"
    assert len(REPORT_MESSAGE) == 22
    assert REPORT_PATH.endswith("futures-channel/src/oneshot.rs")
    print("ok: empty slot reports, move-assigns, releases, no destroy/delete")


def test_empty_slot_leaves_no_delete():
    source, calls, hooks = harness(None)
    out = Record()
    run(out, source, *hooks)
    assert not [c for c in calls if c[0] in ("delete_array", "delete_object",
                                             "destroy")]
    print("ok: report path deletes nothing (temp pointer already moved)")


def test_move_assign_helper():
    calls = []
    dest = Record(value=1, flags=1, pointer="old-dest")
    src = Record(value=2, flags=2, pointer="new")
    move_assign(dest, src, lambda p: calls.append(p))
    assert (dest.value, dest.flags, dest.pointer) == (2, 2, "new")
    assert (src.value, src.flags, src.pointer) == (0, 0, None)
    assert calls == ["old-dest"]
    same = Record(value=5, flags=5, pointer="self")
    move_assign(same, same, lambda p: calls.append(p))
    assert (same.value, same.flags, same.pointer) == (5, 5, "self")
    assert calls == ["old-dest"]
    print("ok: helper copies six bytes, moves pointer, deletes old, self no-op")


def test_null_inputs_raise():
    source, _calls, hooks = harness(object())
    try:
        run(None, source, *hooks)
    except ModelError:
        pass
    else:
        raise AssertionError("null out must raise")
    try:
        run(Record(), None, *hooks)
    except ModelError:
        pass
    else:
        raise AssertionError("null source must raise")
    print("ok: null inputs raise")


def main():
    test_normal_take()
    test_prefilled_out_pointer_dropped_without_delete()
    test_empty_slot_report_path()
    test_empty_slot_leaves_no_delete()
    test_move_assign_helper()
    test_null_inputs_raise()
    print("ALL MODEL TESTS PASSED")


if __name__ == "__main__":
    main()
