"""Tests for the node #115 three-stage fallback lookup model
(0x5d52b60).

Target-grounded expectations: the callee argument order, the
callee-first priority, the array entry selected by the same
index, the default fallback, and the input guards. Run from
the repository root:

    python3 tests/test_fallback_lookup_52b60_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from fallback_lookup_52b60_115 import (
    ARRAY_FIELD_OFFSET, CALLEE, DEFAULT_FIELD_OFFSET, fallback_lookup)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def main():
    calls = []

    def callee_hit(query, index):
        calls.append(("callee", query, index))
        return "callee-result"

    def callee_miss(query, index):
        calls.append(("callee", query, index))
        return None

    # 1. Callee hit: returned at once, array/default never read.
    # The array is None here on purpose: a read would raise.
    calls.clear()
    result = fallback_lookup(
        {"array_0xd10": None, "default_0xd08": "default"},
        "query", 2, callee_hit)
    check("callee hit returns callee result", result == "callee-result")
    check("callee argument order",
          calls == [("callee", "query", 2)])
    check("callee address constant", CALLEE == 0x5D8CE30)

    # 2. Callee miss, array hit: the entry at the same index.
    calls.clear()
    result = fallback_lookup(
        {"array_0xd10": ["a0", "a1", "a2"], "default_0xd08": "default"},
        "query", 2, callee_miss)
    check("array hit returns entry at index", result == "a2")
    check("array path still calls callee first",
          calls == [("callee", "query", 2)])
    check("array field offset", ARRAY_FIELD_OFFSET == 0xD10)

    # 3. Callee miss, array entry null: the default slot.
    result = fallback_lookup(
        {"array_0xd10": [None, "a1"], "default_0xd08": "default"},
        "query", 0, callee_miss)
    check("array miss falls back to default", result == "default")

    # 4. All three miss: the default slot itself is null.
    result = fallback_lookup(
        {"array_0xd10": [None], "default_0xd08": None},
        "query", 0, callee_miss)
    check("null default returns null", result is None)
    check("default field offset", DEFAULT_FIELD_OFFSET == 0xD08)

    # 5. Index 0 and the last entry both resolve by position.
    result = fallback_lookup(
        {"array_0xd10": ["first", "second"], "default_0xd08": "default"},
        "query", 0, callee_miss)
    check("index 0 selects first entry", result == "first")
    result = fallback_lookup(
        {"array_0xd10": ["first", "second"], "default_0xd08": "default"},
        "query", 1, callee_miss)
    check("index 1 selects second entry", result == "second")

    # 6. Input guards: null object raises before any call, and a
    # null array pointer on the miss path raises too.
    calls.clear()
    try:
        fallback_lookup(None, "query", 0, callee_miss)
        check("null object raises", False)
    except ValueError:
        check("null object raises", True)
    check("null object makes no calls", calls == [])
    try:
        fallback_lookup({"array_0xd10": None, "default_0xd08": "d"},
                        "query", 0, callee_miss)
        check("null array raises", False)
    except ValueError:
        check("null array raises", True)

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
