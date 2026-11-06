"""Tests for the node #115 timestamp-guard model (0x5d58810).

Target-grounded expectations: the resolve rule (direct object
vs default-getter vs custom slot), the +0x28 gate, the exact
message assembly, the status builder's ": " join rule, and the
input guards. Run from the repository root:

    python3 tests/test_timestamp_guard_8810_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from timestamp_guard_8810_115 import (
    CODE_INVALID_ARGUMENT, CODE_OK, DEFAULT_GETTER, PREFIX, SUFFIX,
    Status, build_status, timestamp_guard)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def obj_with(field, calls):
    def describe(o):
        calls.append("describe")
        return {"field_0x28": field}
    return describe


def name_fn(text, calls):
    def name(o):
        calls.append("name")
        return text
    return name


def run(factory, obj, describe, name):
    events = []
    result = timestamp_guard(factory, obj, describe, name, events)
    return result, events


def main():
    # 1. OK path: +0x28 null, no message, name never called.
    calls = []
    result, events = run(None, "obj", obj_with(None, calls),
                         name_fn("db", calls))
    check("ok status", result == Status(CODE_OK, 0, None))
    check("ok code is 0", result.code == 0)
    check("ok message is None", result.msg is None)
    check("ok events",
          events == ["describe called (vtable slot 0x28)",
                     "gate: +0x28 null, OK status"])
    check("ok path never calls name", calls == ["describe"])

    # 2. Error path: exact message assembly.
    calls = []
    result, events = run(None, "obj", obj_with("marker", calls),
                         name_fn("default", calls))
    check("error status",
          result == Status(CODE_INVALID_ARGUMENT, 0,
                           "cannot call this method on column family "
                           "default that enables timestamp"))
    check("error code is 4", result.code == 4)
    check("error events",
          events == ["describe called (vtable slot 0x28)",
                     "gate: +0x28 non-null, building message",
                     "name called (vtable slot 0x10)",
                     "message assembled"])
    check("error path calls describe then name",
          calls == ["describe", "name"])

    # 3. Resolve via the default getter when obj is null.
    calls = []
    factory = {"slot_0x3e8": "default", "field_0x740": "resolved-obj"}
    result, events = run(factory, None, obj_with("marker", calls),
                         name_fn("cf", calls))
    check("default resolve reaches error path",
          result.msg == PREFIX + "cf" + SUFFIX)
    check("default resolve event first",
          events[0] == "resolve: default getter *(factory+0x740)")
    check("default getter constant", DEFAULT_GETTER == 0x5D48510)

    # 4. Resolve via a custom slot when obj is null.
    seen = []
    def custom_slot(f):
        seen.append(f)
        return "custom-obj"
    factory = {"slot_0x3e8": custom_slot, "field_0x740": "ignored"}
    result, events = run(factory, None, obj_with(None, []),
                         name_fn("x", []))
    check("custom slot resolves", result == Status(CODE_OK, 0, None))
    check("custom slot called with factory", seen == [factory])
    check("custom resolve event first",
          events[0] == "resolve: vtable slot 0x3e8 called")

    # 5. Direct object: the factory is never read.
    result, events = run(None, "obj", obj_with(None, []),
                         name_fn("x", []))
    check("direct object ignores null factory",
          result == Status(CODE_OK, 0, None))
    check("direct object events start with describe",
          events[0] == "describe called (vtable slot 0x28)")

    # 6. Null object and null factory raises before any call.
    calls = []
    try:
        timestamp_guard(None, None, obj_with("m", calls),
                        name_fn("x", calls), [])
        check("null factory raises", False)
    except ValueError:
        check("null factory raises", True)
    check("null factory makes no calls", calls == [])

    # 7. Resolve returning null raises.
    factory = {"slot_0x3e8": "default", "field_0x740": None}
    try:
        timestamp_guard(factory, None, obj_with("m", []),
                        name_fn("x", []), [])
        check("null resolved object raises", False)
    except ValueError:
        check("null resolved object raises", True)

    # 8. Null describe result raises.
    try:
        timestamp_guard(None, "obj", lambda o: None,
                        name_fn("x", []), [])
        check("null describe raises", False)
    except ValueError:
        check("null describe raises", True)

    # 9. Empty name: prefix and suffix sit adjacent.
    result, _ = run(None, "obj", obj_with("m", []), name_fn("", []))
    check("empty name message", result.msg == PREFIX + SUFFIX)
    check("prefix constant",
          PREFIX == "cannot call this method on column family ")
    check("suffix constant", SUFFIX == " that enables timestamp")

    # 10. Long name passes through unchanged.
    long_name = "c" * 300
    result, _ = run(None, "obj", obj_with("m", []),
                    name_fn(long_name, []))
    check("long name message", result.msg == PREFIX + long_name + SUFFIX)

    # 11. Builder ": " join rule with a non-empty second view.
    check("builder joins non-empty second view",
          build_status("first", "second") ==
          Status(CODE_INVALID_ARGUMENT, 0, "first: second"))
    check("builder skips empty second view",
          build_status("first", "") ==
          Status(CODE_INVALID_ARGUMENT, 0, "first"))

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
