"""Tests for the node #115 object destructor model (0x5d5e5d0).

Run from the repository root:
    python3 tests/test_destructor_5d5e5d0_115.py
Prints "checks pass" on success, else raises.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from destructor_5d5e5d0_115 import (  # noqa: E402
    Node, StringField, destroy_object)

CHECKS = []


def check(name, actual, expected):
    CHECKS.append(name)
    if actual != expected:
        raise AssertionError("%s: %r != %r" % (name, actual, expected))


def heap(cap):
    return StringField("heap", cap)


def inline():
    return StringField("inline")


ALL_STRINGS = (0x3B8, 0x398, 0x368, 0x2B8, 0x298, 0x278, 0x258,
               0x238, 0x218, 0x1F8, 0x1D8, 0x1B8, 0x198, 0x178,
               0x158, 0x40, 0x20, 0x00)


def obj(t318=None, t2e8=None, strings=None):
    base = {offset: inline() for offset in ALL_STRINGS}
    if strings:
        base.update(strings)
    return {"trees": {0x318: t318, 0x2E8: t2e8}, "strings": base}


def expect_raises(name, fn):
    CHECKS.append(name)
    try:
        fn()
    except ValueError:
        return
    raise AssertionError("%s: no ValueError raised" % name)


def main():
    # Empty object: null trees, inline strings -> no deletes.
    check("empty", destroy_object(obj()), [])

    # Single node, heap strings: child (none), B, A, node, in that order.
    node = Node("n", str_a=heap(10), str_b=heap(20))
    check("single-node", destroy_object(obj(t318=node)),
          [("delete-string-B", "n", 21),
           ("delete-string-A", "n", 11),
           ("delete-node", "n", 0x60)])

    # Inline strings free nothing; the node itself is still deleted.
    check("inline-strings", destroy_object(obj(t318=Node("n"))),
          [("delete-node", "n", 0x60)])

    # Worked tree: head A with child chain C -> D (D having child E)
    # and sibling B. Order: C, E, D, A, B (each: B, A, node).
    e = Node("E")
    d = Node("D", child=e)
    c = Node("C", nxt=d)
    b = Node("B")
    a = Node("A", child=c, nxt=b)
    check("worked-tree", destroy_object(obj(t318=a)),
          [("delete-node", "C", 0x60),
           ("delete-node", "E", 0x60),
           ("delete-node", "D", 0x60),
           ("delete-node", "A", 0x60),
           ("delete-node", "B", 0x60)])

    # Second tree is destroyed only after the first tree, in full.
    check("two-trees-order", destroy_object(obj(t318=Node("first"),
                                                t2e8=Node("second"))),
          [("delete-node", "first", 0x60),
           ("delete-node", "second", 0x60)])

    # Null first tree still destroys the second tree.
    check("null-first-tree", destroy_object(obj(t2e8=Node("only"))),
          [("delete-node", "only", 0x60)])

    # The three leading strings come before both trees, in the
    # binary's order (+0x3b8, +0x398, +0x368), heap only, cap + 1.
    check("leading-strings-first", destroy_object(obj(
        t318=Node("n"), strings={0x3B8: heap(0), 0x368: heap(5)})),
        [("delete-string", "0x3b8", 1),
         ("delete-string", "0x368", 6),
         ("delete-node", "n", 0x60)])

    # Trailing strings are disposed in descending offset order,
    # after the trees. The last field (+0x00) is the tail-jump
    # delete in the binary; the effect is identical.
    check("trailing-strings-descending", destroy_object(obj(strings={
        0x2B8: heap(0), 0x1F8: heap(5), 0x00: heap(15)})),
        [("delete-string", "0x2b8", 1),
         ("delete-string", "0x1f8", 6),
         ("delete-string", "0x0", 16)])

    # Full order: leading strings, trees, trailing strings.
    check("full-order", destroy_object(obj(
        t318=Node("n"), strings={0x398: heap(1), 0x40: heap(2)})),
        [("delete-string", "0x398", 2),
         ("delete-node", "n", 0x60),
         ("delete-string", "0x40", 3)])

    # Heap node strings use capacity + 1, not the string length.
    check("heap-size-cap-plus-one", destroy_object(obj(t318=Node(
        "n", str_a=heap(0), str_b=heap(0xFFFFFFFF)))),
        [("delete-string-B", "n", 0x100000000),
         ("delete-string-A", "n", 1),
         ("delete-node", "n", 0x60)])

    # The object itself is never deleted and the input is not mutated.
    before = obj(t318=Node("n"), strings={0x3B8: heap(1)})
    result = destroy_object(before)
    check("no-object-delete", [d for d in result if d[1] == "obj"], [])
    check("input-unchanged", (before["trees"][0x318].label,
                              before["strings"][0x3B8].capacity), ("n", 1))

    # Guards: cycles, dangling references, missing fields.
    cyclic = Node("x")
    cyclic.next = cyclic
    expect_raises("sibling-cycle",
                  lambda: destroy_object(obj(t318=cyclic)))
    child_cycle = Node("p")
    child_cycle.child = child_cycle
    expect_raises("child-cycle",
                  lambda: destroy_object(obj(t318=child_cycle)))
    shared = Node("s")
    expect_raises("shared-node-twice",
                  lambda: destroy_object(obj(t318=Node("a", nxt=shared),
                                            t2e8=shared)))
    expect_raises("dangling-child",
                  lambda: destroy_object(obj(t318=Node("a", child="nope"))))
    expect_raises("missing-tree",
                  lambda: destroy_object({"trees": {0x318: None},
                                          "strings": {}}))
    bad_strings = {offset: inline() for offset in ALL_STRINGS[:-1]}
    expect_raises("missing-string",
                  lambda: destroy_object({"trees": {0x318: None, 0x2E8: None},
                                          "strings": bad_strings}))
    expect_raises("bad-string-type",
                  lambda: destroy_object(obj(strings={0x3B8: "heap"})))

    print("checks pass (%d checks)" % len(CHECKS))


if __name__ == '__main__':
    main()
