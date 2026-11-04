"""Tests for the node #115 visited-element teardown model at 0x5d516f0.

Run from the repository root:
    python3 tests/test_element_teardown_115.py
Prints "<n> checks passed" on success, else raises.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from element_teardown_115 import (  # noqa: E402
    MASK64, destroy_list, destroy_loop_vector, destroy_plain_vector,
    destroy_string, element_teardown)

CHECKS = [0]


def check(condition, label):
    if not condition:
        raise AssertionError("failed check: %s" % label)
    CHECKS[0] += 1


def string(ptr, cap, cap_addr):
    return {"ptr": ptr, "cap": cap, "cap_addr": cap_addr}


def full_object():
    # Distinct pointers per field so the delete order is unambiguous.
    return {
        "string_0x160": string(0x100000, 0x1F, 0x900000),
        "string_0x138": string(0x110000, 0x10, 0x900010),
        "vector_0x110": {"begin": 0x120000, "cap": 0x120080},
        "vector_0xf8": {"begin": 0, "cap": 0x130000},
        "vector_0xe0": {
            "begin": 0x200000, "end": 0x2000B0, "cap": 0x200100,
            "elements": [
                {"string_0x38": string(0x210000, 0x07, 0x910000),
                 "string_0x18": string(0x920000, 0x00, 0x920000)},
                {"string_0x38": string(0x930000, 0x00, 0x930000),
                 "string_0x18": string(0x220000, 0x03, 0x940000)},
            ],
        },
        "vector_0xc8": {
            "begin": 0x300000, "end": 0x300130, "cap": 0x300200,
            "elements": [
                {"string_0x100": string(0x310000, 0x00, 0x950000),
                 "string_0xe0": string(0x960000, 0x00, 0x960000),
                 "string_0x50": string(0x320000, 0x01, 0x970000),
                 "string_0x30": string(0x980000, 0x00, 0x980000)},
            ],
        },
        "list_0xa8": {
            "head": 0x400000,
            "nodes": {
                0x400000: {"next": 0x400030, "field18": 0xDEAD},
                0x400030: {"next": 0, "field18": 0xBEEF},
            },
        },
        "vector_0x80": {
            "begin": 0x500000, "end": 0x500028, "cap": 0x500040,
            "elements": [
                {"string_0x08": string(0x510000, 0x09, 0x990000)},
            ],
        },
        "string_0x28": string(0x9A0000, 0x00, 0x9A0000),
        "string_0x08": string(0x600000, 0x00, 0x9B0000),
    }


def main():
    check(destroy_string(string(0x200000, 0x1F, 0x300000)) == (0x200000, 0x20),
          "heap string deletes ptr with cap + 1")
    check(destroy_string(string(0x300000, 0x1F, 0x300000)) is None,
          "inline string makes no delete call")
    check(destroy_plain_vector({"begin": 0, "cap": 0x130000}) is None,
          "zero-begin plain vector makes no delete call")
    check(destroy_plain_vector({"begin": 0x400000, "cap": 0x400100})
          == (0x400000, 0x100), "plain vector deletes cap minus begin")
    check(destroy_plain_vector({"begin": 0x400100, "cap": 0x400000})
          == (0x400100, (0x400000 - 0x400100) & MASK64),
          "plain vector size wraps modulo 2**64")

    empty_loop, _ = destroy_loop_vector(
        {"begin": 0x600000, "end": 0x600000, "cap": 0x600040,
         "elements": []}, 0x28, ("string_0x08",))
    check(empty_loop == [(0x600000, 0x40)],
          "empty loop vector still deletes its array")
    zero_loop, _ = destroy_loop_vector(
        {"begin": 0, "end": 0, "cap": 0, "elements": []}, 0x28,
        ("string_0x08",))
    check(zero_loop == [], "zero loop vector deletes nothing")
    for bad in ({"begin": 0x600000, "end": 0x600010, "cap": 0x600040,
                 "elements": []},
                {"begin": 0x600028, "end": 0x600000, "cap": 0x600040,
                 "elements": []},
                {"begin": 0x600000, "end": 0x600028, "cap": 0x600040,
                 "elements": []},
                {"begin": 0, "end": 0x600028, "cap": 0x600040,
                 "elements": [{"string_0x08": string(1, 0, 2)}]}):
        try:
            destroy_loop_vector(bad, 0x28, ("string_0x08",))
        except ValueError:
            CHECKS[0] += 1
        else:
            raise AssertionError("bad loop vector did not raise: %r" % (bad,))

    list_deletes, list_calls = destroy_list(full_object()["list_0xa8"])
    check(list_calls == [0xDEAD, 0xBEEF],
          "list calls the callee per node in chain order")
    check(list_deletes == [(0x400000, 0x30), (0x400030, 0x30)],
          "list deletes each node with size 0x30")
    check(destroy_list({"head": 0, "nodes": {}}) == ([], []),
          "empty list deletes nothing and calls nothing")
    try:
        destroy_list({"head": 0x400000, "nodes": {
            0x400000: {"next": 0x400000, "field18": 1}}})
    except ValueError:
        CHECKS[0] += 1
    else:
        raise AssertionError("cyclic list did not raise")
    try:
        destroy_list({"head": 0x400000, "nodes": {}})
    except ValueError:
        CHECKS[0] += 1
    else:
        raise AssertionError("dangling list head did not raise")

    result = element_teardown(full_object())
    expected_deletes = [
        (0x100000, 0x20), (0x110000, 0x11), (0x120000, 0x80),
        (0x210000, 0x08), (0x220000, 0x04), (0x200000, 0x100),
        (0x310000, 0x01), (0x320000, 0x02), (0x300000, 0x200),
        (0x400000, 0x30), (0x400030, 0x30),
        (0x510000, 0x0A), (0x500000, 0x40),
        (0x600000, 0x01),
    ]
    check(result["deletes"] == expected_deletes,
          "full teardown deletes in descending-offset code order")
    check(result["external_calls"] == [0xDEAD, 0xBEEF],
          "full teardown passes list fields to the callee in order")
    try:
        broken = full_object()
        del broken["string_0x160"]
        element_teardown(broken)
    except ValueError:
        CHECKS[0] += 1
    else:
        raise AssertionError("missing field did not raise")
    print("%d checks passed" % CHECKS[0])


if __name__ == "__main__":
    main()
