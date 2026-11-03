"""Tests for tools/guarded_convert_52c80_115.py.

The expectations are pinned to routine 0x5d52c80 in the
digest-verified node #115 binary: acquire with the +0x9c8
member, two-branch element selection, the 16-byte converter
at 0x5f03b40, release with the same member, and the
low-byte-replaced return value (sete writes only %al).

Address-chain convention in these tests: memory[A - 0x18] is
the element pointer P, memory[P] is the target Q, and the
predicate reads memory[Q + 0x58].
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from guarded_convert_52c80_115 import guarded_convert, predicate_value


def make_owner(first, second, end, mutex="mutex-token"):
    return {
        "mutex_0x9c8": mutex,
        "slot_0xb50": first,
        "slot_0xb58": second,
        "slot_0xb68": end,
    }


def test_first_branch_predicate_set():
    # A != [owner +0xb58]: P = memory[A - 0x18] = 0x8000;
    # Q = memory[0x8000] = 0x1000AB (low byte 0xAB); field at
    # Q +0x58 is zero, so the flag is 1 and only the low byte
    # of Q's low 32 bits changes: 0x1000AB -> 0x100001.
    memory = {0x1000 - 0x18: 0x8000, 0x8000: 0x1000AB, 0x1000AB + 0x58: 0}
    events = []
    result = guarded_convert(make_owner(0x1000, 0x2000, 0x3000), memory, events)
    assert result == 0x100001, hex(result)
    assert events == [
        ("acquire", "mutex-token"),
        ("convert", 0x8000, 0x1000AB),
        ("release", "mutex-token"),
    ]


def test_first_branch_predicate_clear_keeps_upper_bytes():
    # Field nonzero: flag 0, so the low byte becomes 0 while
    # Q's other low-32 bytes survive (no eax clearing).
    memory = {0x2000 - 0x18: 0x8100, 0x8100: 0x7F00C3, 0x7F00C3 + 0x58: 5}
    result = guarded_convert(make_owner(0x2000, 0x2001, 0x3000), memory)
    assert result == 0x7F0000, hex(result)


def test_equal_branch_uses_end_slot_chain():
    # A == [owner +0xb58]: P = memory[memory[E - 8] + 0x200
    # - 0x18] = 0x9000; Q = memory[0x9000] = 0x600077; field
    # at Q +0x58 is zero, so the result is 0x600001.
    memory = {
        0x4000 - 8: 0x5000,
        0x5000 + 0x200 - 0x18: 0x9000,
        0x9000: 0x600077,
        0x600077 + 0x58: 0,
    }
    events = []
    result = guarded_convert(make_owner(0x4000, 0x4000, 0x4000), memory, events)
    assert result == 0x600001, hex(result)
    assert events[1] == ("convert", 0x9000, 0x600077)


def test_predicate_value_direct():
    memory = {0x9000: 0x123456, 0x123456 + 0x58: 0}
    value, target = predicate_value(memory, 0x9000)
    assert target == 0x123456
    assert value == 0x123401, hex(value)
    memory[0x123456 + 0x58] = 1
    value, _ = predicate_value(memory, 0x9000)
    assert value == 0x123400, hex(value)


def test_null_owner_raises():
    try:
        guarded_convert(None, {})
    except ValueError:
        return
    raise AssertionError("null owner must raise")


def test_unmapped_selection_raises():
    try:
        guarded_convert(make_owner(0x1000, 0x2000, 0x3000), {})
    except ValueError:
        return
    raise AssertionError("unmapped element slot must raise")


def test_release_is_last_even_when_flag_clear():
    memory = {0x1000 - 0x18: 0x42, 0x42: 0x5000, 0x5000 + 0x58: 9}
    events = []
    guarded_convert(make_owner(0x1000, 0x2000, 0x3000), memory, events)
    assert events[-1] == ("release", "mutex-token")
    assert events[0] == ("acquire", "mutex-token")


if __name__ == "__main__":
    tests = [
        test_first_branch_predicate_set,
        test_first_branch_predicate_clear_keeps_upper_bytes,
        test_equal_branch_uses_end_slot_chain,
        test_predicate_value_direct,
        test_null_owner_raises,
        test_unmapped_selection_raises,
        test_release_is_last_even_when_flag_clear,
    ]
    for test in tests:
        test()
        print("PASS %s" % test.__name__)
    print("%d checks passed" % len(tests))
