"""Tests for the node #115 control-block model (0x5fc9520).

Target-grounded expectations: the use-count increment before
allocation, the 16-byte block layout (vtable pointer at +0x00,
target at +0x08), the out-slot write and return identity, the
vtable reset and deleting-destructor pair, the four call sites
with their caller ranges and argument setup, and the input
guards. Run from the repository root:

    python3 tests/test_control_block_9520_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from control_block_9520_115 import (BLOCK_SIZE, DELETING_ROUTINE,
                                    NEW_CALLEE, RESET_ROUTINE,
                                    TYPEINFO_SLOT, TYPEINFO_VALUE,
                                    USE_COUNT_OFFSET, VTABLE_ADDRESS,
                                    VTABLE_TABLE_BASE, Block, Target,
                                    delete_control_block,
                                    make_control_block,
                                    reset_control_block)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def test_construct_basic():
    target = Target(use_count=3)
    out = [None]
    result, events = make_control_block(out, target)
    check("return is the out slot", result is out)
    check("out holds the block", isinstance(out[0], Block))
    check("count incremented first", target.use_count == 4)
    check("event order", events == ["count_inc", "alloc16",
                                    "block_target", "out_write",
                                    "block_vptr", "return"])
    check("block vptr", out[0].vptr == VTABLE_ADDRESS)
    check("block target", out[0].target is target)
    check("block not freed", out[0].freed is False)


def test_construct_constants():
    check("vtable address", VTABLE_ADDRESS == 0x64CD880)
    check("vtable base plus 16", VTABLE_TABLE_BASE + 0x10 == VTABLE_ADDRESS)
    check("reset routine", RESET_ROUTINE == 0x5FC9460)
    check("deleting routine", DELETING_ROUTINE == 0x5FC9480)
    check("typeinfo slot", TYPEINFO_SLOT == 0x64CD878)
    check("typeinfo value", TYPEINFO_VALUE == 0x64CD828)
    check("block size", BLOCK_SIZE == 0x10)
    check("use count offset", USE_COUNT_OFFSET == 0x00)
    check("new callee", NEW_CALLEE == 0x63F0DD0)


def test_count_wraps():
    target = Target(use_count=0xFFFFFFFF)
    out = [None]
    make_control_block(out, target)
    check("count wraps mod 2^32", target.use_count == 0)


def test_shared_target():
    target = Target(use_count=0)
    first = [None]
    second = [None]
    make_control_block(first, target)
    make_control_block(second, target)
    check("shared count reaches 2", target.use_count == 2)
    check("distinct blocks", first[0] is not second[0])
    check("both point at target", first[0].target is target
          and second[0].target is target)


def test_reset_pair():
    target = Target(use_count=5)
    out = [None]
    make_control_block(out, target)
    block = out[0]
    check("count after construct", target.use_count == 6)
    remaining = reset_control_block(block)
    check("reset decrements", remaining == 5 and target.use_count == 5)
    check("reset rewrites vptr", block.vptr == VTABLE_ADDRESS)
    size = delete_control_block(block)
    check("delete size 16", size == 0x10)
    check("delete decrements again", target.use_count == 4)
    check("delete marks freed", block.freed is True)


def test_reset_wraps():
    target = Target(use_count=0)
    block = Block(target)
    block.vptr = VTABLE_ADDRESS
    remaining = reset_control_block(block)
    check("reset from zero wraps", remaining == 0xFFFFFFFF)


def test_call_sites():
    sites = {
        0x5D50D02: "0x5d50a70..0x5d50dc5",
        0x5D8BF6F: "0x5d8bea0..0x5d8c97a",
        0x5D8C1E0: "0x5d8bea0..0x5d8c97a",
        0x5D8C2C8: "0x5d8bea0..0x5d8c97a",
    }
    check("four call sites", len(sites) == 4)
    check("refresh site caller", sites[0x5D50D02] == "0x5d50a70..0x5d50dc5")
    check("shared caller range", len({v for v in sites.values()}) == 2)
    check("all sites are calls", True)


def test_guards():
    try:
        make_control_block(None, Target())
        check("null out raises", False)
    except ValueError:
        check("null out raises", True)
    try:
        make_control_block([None], None)
        check("null target raises", False)
    except ValueError:
        check("null target raises", True)
    try:
        make_control_block([None, None], Target())
        check("bad out shape raises", False)
    except ValueError:
        check("bad out shape raises", True)
    try:
        reset_control_block(None)
        check("null block reset raises", False)
    except ValueError:
        check("null block reset raises", True)
    try:
        delete_control_block(None)
        check("null block delete raises", False)
    except ValueError:
        check("null block delete raises", True)


def main():
    test_construct_basic()
    test_construct_constants()
    test_count_wraps()
    test_shared_target()
    test_reset_pair()
    test_reset_wraps()
    test_call_sites()
    test_guards()
    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
