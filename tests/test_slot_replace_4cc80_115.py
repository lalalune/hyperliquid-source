"""Tests for the node #115 slot replace model (0x5d4cc80).

Target-grounded expectations: the null-slot report path
with its exact stack block, the flag-selected node shape
and insert callee, the slot store before the old release,
the release-then-notify order, the owner returned
unchanged, and the input guards. Run from the repository
root:

    python3 tests/test_slot_replace_4cc80_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from slot_replace_4cc80_115 import (
    FIELD_ADDR, FLAG_OFFSET, INSERT_CALLEE_FLAG_NONZERO,
    INSERT_CALLEE_FLAG_ZERO, NODE_SIZE, OPERATOR_NEW,
    REPORT_BLOCK, REPORT_CALLEE, REPORT_MESSAGE, REPORT_REGS,
    VTABLE_FLAG_NONZERO, VTABLE_FLAG_ZERO, Key, Node,
    RecordingHooks, slot_replace)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def test_constants():
    check("node size", NODE_SIZE == 0x70)
    check("flag offset", FLAG_OFFSET == 0x4C9)
    check("flag-zero vtable", VTABLE_FLAG_ZERO == 0x64D2C38)
    check("flag-nonzero vtable", VTABLE_FLAG_NONZERO == 0x64D2CA0)
    check("flag-zero insert callee", INSERT_CALLEE_FLAG_ZERO == 0x606C680)
    check("flag-nonzero insert callee",
          INSERT_CALLEE_FLAG_NONZERO == 0x606EF50)
    check("report callee", REPORT_CALLEE == 0x61CF670)
    check("operator new", OPERATOR_NEW == 0x63F0DD0)
    check("report block", REPORT_BLOCK == (0x960EE0, 0x20, 0x4376FD, 0))
    check("report message length", len(REPORT_MESSAGE) == 0x20)
    check("report regs", REPORT_REGS == {"esi": 4, "edx": 0, "r9": 0})


def test_null_slot_reports_and_returns_owner():
    hooks = RecordingHooks()
    owner = object()
    result = slot_replace(owner, Key(0), "a", "b", None, hooks)
    check("null slot returns the owner", result is owner)
    check("null slot only reports, nothing else",
          hooks.events == [("report", REPORT_BLOCK, REPORT_REGS)])


def common_fields(node, key, a, b):
    check("vtable slot", node.fields[0x00] in
          (VTABLE_FLAG_ZERO, VTABLE_FLAG_NONZERO))
    check("+0x10 carries rdx", node.fields[0x10] == a)
    check("+0x18 carries rcx", node.fields[0x18] == b)
    check("+0x28 zeroed", node.fields[0x28] == 0)
    check("+0x30 zeroed", node.fields[0x30] == 0)
    check("+0x38 points at +0x28",
          node.fields[0x38] == (FIELD_ADDR, 0x28))
    check("+0x40 points at +0x28",
          node.fields[0x40] == (FIELD_ADDR, 0x28))
    check("+0x48 zeroed", node.fields[0x48] == 0)
    check("+0x50 zeroed", node.fields[0x50] == 0)
    check("+0x54 word zeroed", node.fields[0x54] == 0)
    check("+0x58 zeroed", node.fields[0x58] == 0)
    check("+0x60 set to 1", node.fields[0x60] == 1)
    check("+0x68 carries the key", node.fields[0x68] is key)
    check("+0x20 never written", 0x20 not in node.fields)


def test_flag_zero_path_empty_slot():
    hooks = RecordingHooks()
    owner = object()
    key = Key(0)
    slot = [None]
    result = slot_replace(owner, key, "a", "b", slot, hooks)
    node = slot[0]
    check("flag-zero path returns the owner", result is owner)
    check("flag-zero vtable used", node.fields[0x00] == VTABLE_FLAG_ZERO)
    check("flag-zero path leaves +0x08 untouched",
          0x08 not in node.fields)
    common_fields(node, key, "a", "b")
    kinds = [e[0] for e in hooks.events]
    check("flag-zero event order",
          kinds == ["alloc", "insert_a", "notify"])
    check("alloc size is 0x70", hooks.events[0] == ("alloc", 0x70))
    check("insert_a takes node, rdx, rcx",
          hooks.events[1] == ("insert_a", node, "a", "b"))
    check("notify takes owner and node",
          hooks.events[2] == ("notify", owner, node))


def test_flag_nonzero_path_with_old_node():
    hooks = RecordingHooks()
    owner = object()
    key = Key(7)
    old = Node()
    slot = [old]
    result = slot_replace(owner, key, "a", "b", slot, hooks)
    node = slot[0]
    check("flag-nonzero path returns the owner", result is owner)
    check("flag-nonzero vtable used",
          node.fields[0x00] == VTABLE_FLAG_NONZERO)
    check("flag-nonzero path zeroes +0x08", node.fields[0x08] == 0)
    common_fields(node, key, "a", "b")
    kinds = [e[0] for e in hooks.events]
    check("flag-nonzero event order with old node",
          kinds == ["alloc", "insert_b", "release", "notify"])
    check("insert_b takes node, rdx, rcx",
          hooks.events[1] == ("insert_b", node, "a", "b"))
    check("old node released", hooks.events[2] == ("release", old))
    check("notify after release",
          hooks.events[3] == ("notify", owner, node))
    check("slot holds the new node", slot[0] is node)


def test_flag_is_zero_vs_nonzero_only():
    for flag in (1, 0x40, 0xFF):
        hooks = RecordingHooks()
        slot = [None]
        slot_replace(object(), Key(flag), "a", "b", slot, hooks)
        kinds = [e[0] for e in hooks.events]
        check("any nonzero flag takes the nonzero path",
              kinds == ["alloc", "insert_b", "notify"])
        check("any nonzero flag zeroes +0x08",
              slot[0].fields[0x08] == 0)


def test_guards():
    hooks = RecordingHooks()
    try:
        slot_replace(object(), None, "a", "b", [None], hooks)
        check("null key raises", False)
    except ValueError:
        check("null key raises", True)
    check("null key raises before any event", hooks.events == [])
    hooks = RecordingHooks()
    owner = object()
    result = slot_replace(owner, Key(0), "a", "b", [None], hooks)
    check("owner is never dereferenced, only returned and notified",
          result is owner)


def main():
    test_constants()
    test_null_slot_reports_and_returns_owner()
    test_flag_zero_path_empty_slot()
    test_flag_nonzero_path_with_old_node()
    test_flag_is_zero_vs_nonzero_only()
    test_guards()
    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
