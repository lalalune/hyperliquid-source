"""Tests for the node #115 statistics-emit model (0x5d52020).

Target-grounded expectations: the null gate, the produce
argument order, the exact emit argument list, the SSO disposal
rule, and the input guards. Run from the repository root:

    python3 tests/test_stats_emit_52020_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stats_emit_52020_115 import (EMIT_LEVEL, FILE_STRING,
                                  FORMAT_STRING, TempString, stats_emit)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def run(obj, produce, emit):
    events = []
    result = stats_emit(obj, produce, emit, events)
    return result, events


def main():
    calls = []

    def produce(slot, field):
        calls.append(("produce", slot, field))
        return TempString("heap-ptr", 7, False)

    def emit(level, field_addr, fmt, file, temp_ptr):
        calls.append(("emit", level, field_addr, fmt, file, temp_ptr))

    # 1. Null +0x548 slot: nothing else happens.
    result, events = run({"ptr_0x548": None, "field_0x360": "sink"},
                         produce, emit)
    check("null slot returns", result == "returned")
    check("null slot events", events == ["early-return: +0x548 slot null"])
    check("null slot makes no calls", calls == [])

    # 2. Heap temp: produce, emit, delete with capacity + 1.
    calls.clear()
    result, events = run({"ptr_0x548": "field-obj", "field_0x360": "sink"},
                         produce, emit)
    check("heap path returns", result == "returned")
    check("heap path events",
          events == ["produce called (vtable slot 0xe8)", "emit called",
                     "delete temp pointer size 8"])
    check("produce argument order",
          calls[0] == ("produce", "temp-slot", "field-obj"))
    check("emit argument list",
          calls[1] == ("emit", 1, "object+0x360",
                       "[%s:774] STATISTICS:\n %s",
                       "db/db_impl/db_impl.cc", "heap-ptr"))
    check("emit level constant", EMIT_LEVEL == 1)
    check("emit format constant",
          FORMAT_STRING == "[%s:774] STATISTICS:\n %s")
    check("emit file constant", FILE_STRING == "db/db_impl/db_impl.cc")

    # 3. Inline temp: produce and emit, no delete.
    def produce_inline(slot, field):
        calls.append(("produce-inline", slot, field))
        return TempString("temp+0x10", 99, True)

    calls.clear()
    result, events = run({"ptr_0x548": "field-obj", "field_0x360": "sink"},
                         produce_inline, emit)
    check("inline path events",
          events == ["produce called (vtable slot 0xe8)", "emit called",
                     "temp inline: no free"])
    check("inline capacity ignored",
          all("size 100" not in e for e in events))

    # 4. Heap temp with capacity 0: delete size is 1, not 0.
    def produce_cap0(slot, field):
        return TempString("heap-ptr", 0, False)

    _r, events = run({"ptr_0x548": "field-obj", "field_0x360": "sink"},
                     produce_cap0, emit)
    check("cap-0 delete size 1", events[-1] == "delete temp pointer size 1")

    # 5. Input guards: null object raises, before any call.
    calls.clear()
    try:
        stats_emit(None, produce, emit, [])
        check("null object raises", False)
    except ValueError:
        check("null object raises", True)
    check("null object makes no calls", calls == [])

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
