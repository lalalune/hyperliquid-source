"""Tests for the node #115 record-reset model
(tools/record_reset_51d80_115.py, RE-001 work item
RE-001-record-reset-51d80-115). Each check counts; the run
prints "<n> checks pass" on success.

Expectations are target-grounded: the record gate byte at +0x00
returns before the object flag is read; a non-zero object flag
at +0x333 returns without build or emit; the proceed path runs
build, then emit with (2, object+0x360, "[%s:755] Ignoring
error %s", "db/db_impl/db_impl.cc", temp pointer), then the
SSO temp disposal, then the record reset (dword at +0x00, word
at +0x04, qword at +0x08), then delete[] of the saved +0x08
pointer only when it was non-null -- all read from the
whole-function excerpt in the packet. What the build and emit
callees do with their arguments is not claimed, so both are
test doubles here.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from record_reset_51d80_115 import (
    EMIT_LEVEL,
    FILE_STRING,
    FORMAT_STRING,
    TempString,
    record_reset,
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


def make_obj(flag):
    return {"flag_0x333": flag, "field_0x360": "object-field"}


def make_record(gate, ptr):
    return {"byte_0x00": gate, "ptr_0x08": ptr}


def run(obj, record, temp):
    calls = []
    events = []

    def build(slot, rec):
        calls.append(("build", slot, rec is record))
        return temp

    def emit(level, field, fmt, file, ptr):
        calls.append(("emit", level, field, fmt, file, ptr))

    result = record_reset(obj, record, build, emit, events)
    return result, calls, events


def main():
    check(EMIT_LEVEL == 2, "emit level is 2")
    check(FORMAT_STRING == "[%s:755] Ignoring error %s",
          "emit format string pinned")
    check(FILE_STRING == "db/db_impl/db_impl.cc",
          "emit file string pinned")

    # Record gate zero: early return, flag never read, no calls.
    result, calls, events = run(make_obj(1), make_record(0, "old"),
                                TempString("heap", 5, False))
    check(result == "returned", "gate-zero path returns")
    check(calls == [], "gate-zero path makes no build/emit call")
    check(events == ["early-return: record gate byte zero"],
          "gate-zero path reads nothing else")

    # Flag non-zero: early return after the flag read only.
    result, calls, events = run(make_obj(0xFF), make_record(1, "old"),
                                TempString("heap", 5, False))
    check(calls == [], "flag-set path makes no build/emit call")
    check(events == ["read object flag 0x333",
                     "early-return: object flag non-zero"],
          "flag-set path stops after the flag read")

    # Full heap path: order, emit arguments, cap+1 size, reset.
    record = make_record(1, "old-ptr")
    result, calls, events = run(make_obj(0), record,
                                TempString("heap-ptr", 41, False))
    check(result == "returned", "full path returns")
    check(calls[0][0] == "build" and calls[0][2],
          "build called first with the record")
    check(calls[1] == ("emit", 2, "object+0x360",
                       "[%s:755] Ignoring error %s",
                       "db/db_impl/db_impl.cc", "heap-ptr"),
          "emit called with the pinned five arguments")
    check(events == [
        "read object flag 0x333",
        "build called",
        "emit called",
        "delete temp pointer size 42",
        "record zeroed (+0x00 dword, +0x04 word, +0x08 qword)",
        "delete[] saved +0x08 pointer",
    ], "full heap path event order pinned")
    check(record == {"byte_0x00": 0, "word_0x04": 0, "ptr_0x08": 0},
          "record reset writes exactly the three zeroed slots")

    # Inline temp: no free; null saved pointer: no delete[].
    record = make_record(1, None)
    _r, _c, events = run(make_obj(0), record,
                         TempString("temp+0x10", 15, True))
    check("temp inline: no free" in events, "inline temp frees nothing")
    check(events[-1] == "saved +0x08 pointer null: no delete[]",
          "null saved pointer skips delete[]")
    check(record["ptr_0x08"] == 0, "null-pointer record still zeroed")

    # Cap-0 heap temp deletes with size 1 (cap + 1).
    record = make_record(0x80, "old")
    _r, _c, events = run(make_obj(0), record, TempString("h", 0, False))
    check("delete temp pointer size 1" in events,
          "cap-0 temp deletes size 1")

    # Any non-zero gate byte proceeds.
    for gate in (1, 2, 0xFF):
        record = make_record(gate, None)
        _r, calls, _e = run(make_obj(0), record,
                            TempString("t", 0, True))
        check(calls[0][0] == "build",
              "gate byte %d proceeds to build" % gate)

    # Null object or record raises (binary dereferences unconditionally).
    expect_raises(lambda: run(None, make_record(1, None),
                              TempString("t", 0, True)),
                  "null object raises")
    expect_raises(lambda: run(make_obj(0), None,
                              TempString("t", 0, True)),
                  "null record raises")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
