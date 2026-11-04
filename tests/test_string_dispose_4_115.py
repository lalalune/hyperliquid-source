"""Tests for tools/string_dispose_4_115.py, the model of node #115
routine 0x5d506b0. The oracle is the routine's own disposal rule:
four fields in walk order, inline strings freed never,
heap strings freed with size capacity + 1, nothing else touched.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from string_dispose_4_115 import (  # noqa: E402
    FIELD_OFFSETS, Record, StringField, dispose_record_strings)

CHECKS = [0]


def check(condition, label):
    CHECKS[0] += 1
    if not condition:
        raise AssertionError(label)


def expect_raises(kind, fn, label):
    CHECKS[0] += 1
    try:
        fn()
    except kind:
        return
    except Exception as exc:  # noqa: BLE001 - any other error is a failure
        raise AssertionError("%s: wrong exception %r" % (label, exc))
    raise AssertionError("%s: no exception" % label)


def make_record(inline_flags, capacities=None):
    fields = {}
    for i, offset in enumerate(FIELD_OFFSETS):
        cap = 0 if capacities is None else capacities[i]
        fields[offset] = StringField("ptr-%#x" % offset, cap,
                                     inline_flags[i])
    return Record(fields)


def main():
    check(FIELD_OFFSETS == (0xF8, 0xD8, 0x48, 0x28),
          "field walk order matches the routine")
    check(len(FIELD_OFFSETS) == 4, "four string fields")

    # All inline: nothing freed.
    freed = dispose_record_strings(make_record([True] * 4))
    check(freed == [], "all-inline record frees nothing")

    # All heap with distinct capacities: freed in walk order, cap + 1.
    caps = [0, 15, 100, 4096]
    freed = dispose_record_strings(make_record([False] * 4, caps))
    expected = [("ptr-%#x" % off, cap + 1)
                for off, cap in zip(FIELD_OFFSETS, caps)]
    check(freed == expected, "all-heap freed in order with cap + 1 sizes")

    # Mixed: only heap fields freed, order preserved, inline skipped.
    flags = [False, True, False, True]
    caps = [10, 0, 20, 0]
    freed = dispose_record_strings(make_record(flags, caps))
    expected = [("ptr-%#x" % off, cap + 1) for off, cap, flag
                in zip(FIELD_OFFSETS, caps, flags) if not flag]
    check(freed == expected, "mixed record frees only heap fields")

    # Capacity 0 heap string still frees size 1 (cap + 1, not 0).
    freed = dispose_record_strings(make_record([False] + [True] * 3,
                                               [0] + [0] * 3))
    check(freed == [("ptr-0xf8", 1)], "cap 0 frees size 1")

    # The routine does not modify the record's slots.
    record = make_record([False] * 4, [7] * 4)
    dispose_record_strings(record)
    check(all(f.capacity == 7 and f.pointer == "ptr-%#x" % off
              for off, f in record.fields.items()),
          "slots unchanged after disposal")

    # First and last fields in walk order are 0xf8 and 0x28: the
    # last field is freed by tail jump, same observable effect.
    freed = dispose_record_strings(make_record([True] * 3 + [False],
                                               [0] * 3 + [5]))
    check(freed == [("ptr-0x28", 6)],
          "last field (tail-jump delete) frees cap + 1 too")

    # Model guards (not binary claims).
    expect_raises(ValueError, lambda: Record({}),
                  "record missing fields rejected")
    expect_raises(ValueError, lambda: StringField("p", -1, False),
                  "negative capacity rejected")
    expect_raises(TypeError, lambda: StringField("p", "x", False),
                  "non-integer capacity rejected")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
