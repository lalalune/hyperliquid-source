"""Tests for the node #115 refresh model (0x5d50a70).

Target-grounded expectations: the +0x700 enter/exit calls,
the +0x1938 counter fast/slow paths and single increment,
the two temp initializations, the flag-gated second build
and merge, the +0x1930 pointer refresh with the vtable
disposal rule (delete size 0x10 on the relocated global,
otherwise a vtable call), the teardown order, the virtual
finish calls, and the input guards. Run from the repository
root:

    python3 tests/test_refresh_50a70_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from refresh_50a70_115 import (BUILD_CALLEE, COUNTER_OFFSET,
                               DELETE_SIZE, ENTER_CALLEE,
                               EXIT_CALLEE, FIELD_1100, FIELD_D40,
                               FIELD_F50, FLAG_OFFSET,
                               GLOBAL_ADDRESS, GLOBAL_VALUE,
                               LOCK_OFFSET, MERGE_CALLEE,
                               PTR_OFFSET, REFRESH_CALLEE,
                               TEMP_INIT_08, TEMP_INIT_50,
                               TEMP_INIT_60,
                               TEMP_UNINITIALIZED, TEARDOWN_CALLEE,
                               VTABLE_SLOT_FINISH,
                               VTABLE_SLOT_PRODUCE, Dest, Source,
                               dispose_pointer, init_temp, refresh)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


class Hooks:
    """Records every observable step; vtable1 returns a
    preset value per pointer."""

    def __init__(self, vtable_map=None, refresh_result="new",
                 produce_result=None, counter_hook=None):
        self.events = []
        self.vtable_map = vtable_map or {}
        self.refresh_result = refresh_result
        self.produce_result = produce_result
        self.counter_hook = counter_hook

    def enter(self, lock):
        self.events.append(("enter", ENTER_CALLEE, lock))

    def exit(self, lock):
        self.events.append(("exit", EXIT_CALLEE, lock))

    def build(self, field, temp, lock):
        self.events.append(("build", BUILD_CALLEE, field))
        if self.counter_hook is not None:
            self.counter_hook()

    def merge(self, field, temp):
        self.events.append(("merge", MERGE_CALLEE, field))

    def refresh(self, field):
        self.events.append(("refresh", REFRESH_CALLEE, field))
        return self.refresh_result

    def teardown(self, temp):
        self.events.append(("teardown", TEARDOWN_CALLEE,
                            temp.fields[0x50]))

    def virtual300(self, dest, source, zero):
        self.events.append(("virtual300", VTABLE_SLOT_FINISH, zero))

    def virtual318(self, source):
        self.events.append(("virtual318", VTABLE_SLOT_PRODUCE))
        return self.produce_result

    def vtable1(self, ptr):
        return self.vtable_map.get(ptr, GLOBAL_VALUE)

    def delete(self, ptr, size):
        self.events.append(("delete", ptr, size))

    def delete_array(self, ptr):
        self.events.append(("delete_array", ptr))

    def call_vtable1(self, ptr, value):
        self.events.append(("call_vtable1", ptr, value))


def kinds(events):
    return [event[0] for event in events]


def main():
    check("enter callee", ENTER_CALLEE == 0x606CA40)
    check("exit callee", EXIT_CALLEE == 0x60D52F0)
    check("lock offset", LOCK_OFFSET == 0x700)
    check("build callee", BUILD_CALLEE == 0x5FCBF90)
    check("merge callee", MERGE_CALLEE == 0x5FCBDA0)
    check("refresh callee", REFRESH_CALLEE == 0x5FC9520)
    check("teardown callee", TEARDOWN_CALLEE == 0x5D509C0)
    check("finish slot", VTABLE_SLOT_FINISH == 0x300)
    check("produce slot", VTABLE_SLOT_PRODUCE == 0x318)
    check("counter offset", COUNTER_OFFSET == 0x1938)
    check("flag offset", FLAG_OFFSET == 0x17B0)
    check("pointer offset", PTR_OFFSET == 0x1930)
    check("field d40", FIELD_D40 == 0xD40)
    check("field f50", FIELD_F50 == 0xF50)
    check("field 1100", FIELD_1100 == 0x1100)
    check("global address", GLOBAL_ADDRESS == 0x64ED2D8)
    check("global relocated value", GLOBAL_VALUE == 0x5D486C0)
    check("delete size", DELETE_SIZE == 0x10)

    temp = init_temp()
    check("temp +0x08", temp.fields[0x08] == TEMP_INIT_08)
    check("temp +0x50", temp.fields[0x50] == TEMP_INIT_50)
    check("temp +0x60", temp.fields[0x60] == TEMP_INIT_60)
    check("temp flag byte zero", temp.flag_byte() == 0)
    check("temp +0x00 zero", temp.fields[0x00] == 0)
    check("temp +0xf0 zero", temp.fields[0xF0] == 0)
    check("temp gap uninitialized",
          TEMP_UNINITIALIZED == (0x88, 0xEF)
          and all(slot not in temp.fields
                  for slot in (0x88, 0xC0, 0xE8)))

    # 1. Fast path: counter non-zero, no refresh sequence,
    # exit before the virtual finish, byte0 zero skips produce.
    hooks = Hooks()
    dest = Dest(byte0=0)
    source = Source(counter=5, flag=0, ptr_field="old")
    result = refresh(dest, source, hooks)
    check("fast path returns dest", result is dest)
    check("fast path counter +1", source.counter == 6)
    check("fast path pointer untouched", source.ptr_field == "old")
    check("fast path event order",
          kinds(hooks.events) == ["enter", "exit", "virtual300"])
    check("fast path exit before finish",
          kinds(hooks.events).index("exit")
          < kinds(hooks.events).index("virtual300"))

    # 2. Fast path with byte0 set and a produce pointer:
    # virtual318 runs, then delete[] of its +0x08 pointer.
    hooks = Hooks(produce_result="heap")
    dest = Dest(byte0=1)
    source = Source(counter=2, flag=1)
    refresh(dest, source, hooks)
    check("fast path produce runs",
          "virtual318" in kinds(hooks.events))
    check("fast path delete[] after produce",
          hooks.events[-1] == ("delete_array", "heap"))

    # 3. Fast path with byte0 set but a null produce pointer:
    # no delete[].
    hooks = Hooks(produce_result=None)
    refresh(Dest(byte0=1), Source(counter=1, flag=0), hooks)
    check("fast path null produce skips delete[]",
          "delete_array" not in kinds(hooks.events))

    # 4. Slow path, flag zero: one build, pointer refresh,
    # old pointer deleted with size 0x10 on the global,
    # merge temp1 only, teardowns temp2 then temp1.
    hooks = Hooks(vtable_map={"old": GLOBAL_VALUE})
    dest = Dest(byte0=0)
    source = Source(counter=0, flag=0, ptr_field="old")
    refresh(dest, source, hooks)
    check("slow path counter +1", source.counter == 1)
    check("slow path pointer replaced", source.ptr_field == "new")
    check("slow path event order",
          kinds(hooks.events) == ["enter", "build", "refresh",
                                  "delete", "merge", "teardown",
                                  "teardown", "exit", "virtual300"])
    check("slow path one build", kinds(hooks.events).count("build") == 1)
    check("slow path delete size", ("delete", "old", 0x10)
          in hooks.events)
    check("slow path merge is d40",
          [e for e in hooks.events if e[0] == "merge"][0][2] == "d40")

    # 5. Slow path, flag set: second build and merge, same
    # teardown order, merge f50 before merge d40.
    hooks = Hooks(vtable_map={"old": GLOBAL_VALUE})
    source = Source(counter=0, flag=1, ptr_field="old")
    refresh(Dest(byte0=0), source, hooks)
    check("flag path two builds", kinds(hooks.events).count("build") == 2)
    merges = [e[2] for e in hooks.events if e[0] == "merge"]
    check("flag path merge order", merges == ["f50", "d40"])
    check("flag path counter +1", source.counter == 1)

    # 6. Slow path, old pointer with a different vtable slot:
    # the slot is called instead of a sized delete.
    hooks = Hooks(vtable_map={"old": 0x6000000})
    refresh(Dest(byte0=0),
            Source(counter=0, flag=0, ptr_field="old"), hooks)
    check("non-global vtable called",
          ("call_vtable1", "old", 0x6000000) in hooks.events)
    check("non-global vtable no delete",
          not any(e[0] == "delete" for e in hooks.events))

    # 7. Slow path, null old pointer: no disposal events.
    hooks = Hooks()
    refresh(Dest(byte0=0),
            Source(counter=0, flag=0, ptr_field=None), hooks)
    check("null old skips disposal",
          not any(e[0] in ("delete", "call_vtable1")
                  for e in hooks.events))

    # 8. A build hook that changes the counter: the refresh
    # branch is skipped literally, the increment still runs
    # exactly once, merges still run.
    holder = {}

    def bump():
        holder["source"].counter = 9

    hooks = Hooks(counter_hook=bump)
    source = Source(counter=0, flag=0, ptr_field="old")
    holder["source"] = source
    refresh(Dest(byte0=0), source, hooks)
    check("counter hook skips refresh",
          "refresh" not in kinds(hooks.events))
    check("counter hook increment once", source.counter == 10)
    check("counter hook pointer untouched",
          source.ptr_field == "old")

    # 9. Guards.
    try:
        refresh(None, Source(), Hooks())
        check("null dest raises", False)
    except ValueError:
        check("null dest raises", True)
    try:
        refresh(Dest(), None, Hooks())
        check("null source raises", False)
    except ValueError:
        check("null source raises", True)

    # 10. dispose_pointer directly: null is silent.
    hooks = Hooks()
    dispose_pointer(None, hooks)
    check("dispose null silent", hooks.events == [])

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
