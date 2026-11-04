#!/usr/bin/env python3
"""Tests for tools/chain_reset_dispatch_4dc00_115.py.

Every expectation is grounded in the 0x5d4dc00..0x5d4dd50
disassembly in research/work-items/RE-001-chain-reset-dispatch-4dc00-115/main.txt.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.chain_reset_dispatch_4dc00_115 import (
    ChainNode,
    ChainString,
    FourthStruct,
    LookupResult,
    ModelError,
    ProduceResult,
    run,
)


def harness(lookup_result):
    calls = []

    def lookup(third):
        return lookup_result

    def dispose(field18):
        calls.append(("dispose-callee", field18))

    def produce(second):
        return ProduceResult("target-8d8")

    def acquire(arg):
        calls.append(("acquire-callee", arg))

    def dispatch(target, lookup_value, third, fourth):
        calls.append(("dispatch-callee", target, lookup_value, third, fourth))
        return 42

    def release(arg):
        calls.append(("release-callee", arg))

    return calls, lookup, dispose, produce, acquire, dispatch, release


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    print("ok: %s" % name)


def test_empty_chain_flag_zero():
    calls, lookup, dispose, produce, acquire, dispatch, release = harness(
        LookupResult(0, 7))
    fourth = FourthStruct(None)
    value, trace = run(0x1000, "second", "third", fourth,
                       lookup, dispose, produce, acquire, dispatch, release)
    check("empty chain returns dispatch value", value == 42)
    check("empty chain reset field10", fourth.field10 == 0)
    check("empty chain reset field18", fourth.field18 == "struct+0x08")
    check("empty chain reset field20", fourth.field20 == "struct+0x08")
    check("empty chain reset field28", fourth.field28 == 0)
    kinds = [entry[0] for entry in trace]
    check("empty chain trace order",
          kinds == ["lookup", "reset", "produce", "acquire", "dispatch", "release"])
    check("acquire argument is base + 0x700",
          ("acquire", 0x1700) in trace and ("release", 0x1700) in trace)
    dispatch_entry = [e for e in trace if e[0] == "dispatch"][0]
    check("dispatch argument list",
          dispatch_entry[1] == "target-8d8"
          and dispatch_entry[3] == "third"
          and dispatch_entry[4] is fourth)


def test_chain_teardown_order_and_sso():
    heap40 = ChainString("ptr40", 10, inline=False)
    inline20 = ChainString("ptr20", 3, inline=True)
    node2 = ChainNode(None, "f18-b", ChainString("p", 0, inline=True),
                      ChainString("q", 0, inline=True))
    node1 = ChainNode(node2, "f18-a", heap40, inline20)
    calls, lookup, dispose, produce, acquire, dispatch, release = harness(
        LookupResult(5, 1))
    fourth = FourthStruct(node1)
    value, trace = run(0x2000, "second", "third", fourth,
                       lookup, dispose, produce, acquire, dispatch, release)
    check("flag-nonzero returns dispatch value", value == 42)
    kinds = [entry[0] for entry in trace]
    check("flag-nonzero has no acquire or release",
          "acquire" not in kinds and "release" not in kinds)
    check("chain teardown order",
          kinds == ["lookup", "dispose", "delete", "delete-node",
                    "dispose", "delete-node", "reset", "produce", "dispatch"])
    check("heap string deletes with capacity + 1",
          ("delete", "ptr40", 11) in trace)
    check("inline string frees nothing",
          not any(e[0] == "delete" and e[1] == "ptr20" for e in trace))
    check("node deleted with size 0x60",
          ("delete-node", node1, 0x60) in trace
          and ("delete-node", node2, 0x60) in trace)
    check("next captured before deletion: node2 still visited",
          ("dispose", "f18-b") in trace)


def test_second_string_heap_and_both_strings():
    node = ChainNode(None, "f", ChainString("a", 4, inline=False),
                     ChainString("b", 9, inline=False))
    _calls, lookup, dispose, produce, acquire, dispatch, release = harness(
        LookupResult(0, 2))
    fourth = FourthStruct(node)
    _value, trace = run(0x1000, "second", "third", fourth,
                        lookup, dispose, produce, acquire, dispatch, release)
    deletes = [e for e in trace if e[0] == "delete"]
    check("both strings disposed, +0x40 string first",
          deletes == [("delete", "a", 5), ("delete", "b", 10)])


def test_null_lookup_returns_zero_after_effects():
    _calls, lookup, dispose, produce, acquire, dispatch, release = harness(None)
    node = ChainNode(None, "f", ChainString("a", 0, inline=True),
                     ChainString("b", 0, inline=True))
    fourth = FourthStruct(node)
    value, trace = run(0x1000, "second", "third", fourth,
                       lookup, dispose, produce, acquire, dispatch, release)
    check("null lookup returns 0", value == 0)
    kinds = [entry[0] for entry in trace]
    check("null lookup still tears down, resets and produces",
          kinds == ["lookup", "dispose", "delete-node", "reset", "produce"])
    check("null lookup never dispatches", "dispatch" not in kinds)


def test_zero_field28_returns_zero():
    _calls, lookup, dispose, produce, acquire, dispatch, release = harness(
        LookupResult(0, 0))
    fourth = FourthStruct(None)
    value, trace = run(0x1000, "second", "third", fourth,
                       lookup, dispose, produce, acquire, dispatch, release)
    check("zero +0x28 returns 0", value == 0)
    check("zero +0x28 never dispatches",
          "dispatch" not in [e[0] for e in trace])


def test_flag_zero_vs_nonzero_first_byte_only():
    for first_byte, want_acquire in ((0, True), (1, False), (255, False)):
        _calls, lookup, dispose, produce, acquire, dispatch, release = harness(
            LookupResult(first_byte, 3))
        fourth = FourthStruct(None)
        value, trace = run(0x1000, "second", "third", fourth,
                           lookup, dispose, produce, acquire, dispatch, release)
        kinds = [e[0] for e in trace]
        check("first byte %d acquire presence" % first_byte,
              ("acquire" in kinds) == want_acquire)
        check("first byte %d returns dispatch value" % first_byte, value == 42)


def test_null_inputs_raise():
    _calls, lookup, dispose, produce, acquire, dispatch, release = harness(
        LookupResult(0, 1))
    try:
        run(0x1000, None, "third", FourthStruct(None),
            lookup, dispose, produce, acquire, dispatch, release)
    except ModelError:
        pass
    else:
        raise AssertionError("null second object must raise")
    try:
        run(0x1000, "second", "third", None,
            lookup, dispose, produce, acquire, dispatch, release)
    except ModelError:
        pass
    else:
        raise AssertionError("null fourth struct must raise")
    print("ok: null inputs raise")


def main():
    test_empty_chain_flag_zero()
    test_chain_teardown_order_and_sso()
    test_second_string_heap_and_both_strings()
    test_null_lookup_returns_zero_after_effects()
    test_zero_field28_returns_zero()
    test_flag_zero_vs_nonzero_first_byte_only()
    test_null_inputs_raise()
    print("ALL MODEL TESTS PASSED")


if __name__ == "__main__":
    main()
