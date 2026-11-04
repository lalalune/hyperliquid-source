"""Tests for the node #115 two-tree destructor model (0x5d50170).

Run from the repository root:
    python3 tests/test_two_tree_destructor_115.py
Prints "checks pass" on success, else raises.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from two_tree_destructor_115 import (  # noqa: E402
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


def obj(t288=None, t258=None, strings=None):
    base = {offset: inline() for offset in
            (0x228, 0x208, 0x1E8, 0x1C8, 0x1A8, 0x188,
             0x168, 0x148, 0x128, 0x108, 0xE8, 0xC8)}
    if strings:
        base.update(strings)
    return {"trees": {0x288: t288, 0x258: t258}, "strings": base}


def expect_raises(name, fn):
    CHECKS.append(name)
    try:
        fn()
    except ValueError:
        return
    raise AssertionError("%s: no ValueError raised" % name)


# Empty object: null trees, inline strings -> no deletes.
check("empty", destroy_object(obj()), [])

# Single node, heap strings: child (none), B, A, node, in that order.
node = Node("n", str_a=heap(10), str_b=heap(20))
check("single-node", destroy_object(obj(t288=node)),
      [("delete-string-B", "n", 21),
       ("delete-string-A", "n", 11),
       ("delete-node", "n", 0x60)])

# Inline strings free nothing; the node itself is still deleted.
check("inline-strings", destroy_object(obj(t288=Node("n"))),
      [("delete-node", "n", 0x60)])

# Worked tree: head A with child chain C -> D (D having child E)
# and sibling B. Order: C, E, D, A, B (each: B, A, node).
e = Node("E")
d = Node("D", child=e)
c = Node("C", nxt=d)
b = Node("B")
a = Node("A", child=c, nxt=b)
check("worked-tree", destroy_object(obj(t288=a)),
      [("delete-node", "C", 0x60),
       ("delete-node", "E", 0x60),
       ("delete-node", "D", 0x60),
       ("delete-node", "A", 0x60),
       ("delete-node", "B", 0x60)])

# Second tree is destroyed only after the first tree, in full.
check("two-trees-order", destroy_object(obj(t288=Node("first"),
                                            t258=Node("second"))),
      [("delete-node", "first", 0x60),
       ("delete-node", "second", 0x60)])

# Null first tree still destroys the second tree.
check("null-first-tree", destroy_object(obj(t258=Node("only"))),
      [("delete-node", "only", 0x60)])

# String fields are disposed in descending offset order, heap
# only, with size capacity + 1. The last field (+0xc8) is the
# tail-jump delete in the binary; the effect is identical.
check("strings-descending", destroy_object(obj(strings={
    0x228: heap(0), 0x1E8: heap(5), 0xC8: heap(15)})),
    [("delete-string", "0x228", 1),
     ("delete-string", "0x1e8", 6),
     ("delete-string", "0xc8", 16)])

# Heap node strings use capacity + 1, not the string length.
check("heap-size-cap-plus-one", destroy_object(obj(t288=Node(
    "n", str_a=heap(0), str_b=heap(0xFFFFFFFF)))),
    [("delete-string-B", "n", 0x100000000),
     ("delete-string-A", "n", 1),
     ("delete-node", "n", 0x60)])

# Trees come before all string fields, whatever the strings hold.
check("trees-before-strings", destroy_object(obj(
    t288=Node("n"), strings={0x228: heap(3)})),
    [("delete-node", "n", 0x60),
     ("delete-string", "0x228", 4)])

# The object itself is never deleted and the input is not mutated.
before = obj(t288=Node("n"), strings={0x228: heap(1)})
result = destroy_object(before)
check("no-object-delete", [d for d in result if d[1] == "obj"], [])
check("input-unchanged", (before["trees"][0x288].label,
                          before["strings"][0x228].capacity), ("n", 1))

# Guards: cycles, dangling references, missing fields.
cyclic = Node("x")
cyclic.next = cyclic
expect_raises("sibling-cycle",
              lambda: destroy_object(obj(t288=cyclic)))
child_cycle = Node("p")
child_cycle.child = child_cycle
expect_raises("child-cycle",
              lambda: destroy_object(obj(t288=child_cycle)))
shared = Node("s")
expect_raises("shared-node-twice",
              lambda: destroy_object(obj(t288=Node("a", nxt=shared),
                                        t258=shared)))
expect_raises("dangling-child",
              lambda: destroy_object(obj(t288=Node("a", child="nope"))))
expect_raises("missing-tree",
              lambda: destroy_object({"trees": {0x288: None},
                                      "strings": {}}))
bad_strings = {offset: inline() for offset in
               (0x228, 0x208, 0x1E8, 0x1C8, 0x1A8, 0x188,
                0x168, 0x148, 0x128, 0x108, 0xE8)}
expect_raises("missing-string",
              lambda: destroy_object({"trees": {0x288: None, 0x258: None},
                                      "strings": bad_strings}))
expect_raises("bad-string-type",
              lambda: destroy_object(obj(strings={0x228: "heap"})))

print("checks pass (%d checks)" % len(CHECKS))
