"""Model tests for the node #115 object destructor at 0x5d55110.

Run from the repository root:
    python3 tests/test_destructor_5d55110_115.py
Prints "checks pass" with the count on success, else raises.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from destructor_5d55110_115 import Node, StringField, destroy_object

CHECKS = [0]


def check(condition, label):
    CHECKS[0] += 1
    if not condition:
        raise AssertionError("check failed: %s" % label)


def inline_strings():
    return {off: StringField("inline") for off in
            (0x290, 0x270, 0x250, 0x230, 0x210, 0x1F0, 0x1D0, 0x1B0,
             0x190, 0x170, 0x150, 0x130, 0x40, 0x20, 0x00)}


def obj(teardown=None, inline=None, strings=None):
    return {"teardown_list": teardown, "inline_list": inline,
            "strings": strings if strings is not None else inline_strings()}


def expect_raises(fn, label):
    CHECKS[0] += 1
    try:
        fn()
    except ValueError:
        return
    raise AssertionError("check failed (no raise): %s" % label)


def main():
    # Empty object: nothing happens, and the object is not deleted.
    check(destroy_object(obj()) == [], "empty object destroys nothing")
    # Single node in the teardown list, heap strings: B, A, node.
    node = Node("T", str_a=StringField("heap", 3), str_b=StringField("heap", 0))
    check(destroy_object(obj(teardown=node)) ==
          [("delete-string-B", "T", 1), ("delete-string-A", "T", 4),
           ("delete-node", "T", 0x60)],
          "teardown list single node order and cap+1 sizes")
    # Single node in the inline list: same per-node sequence.
    node = Node("I", str_a=StringField("heap", 15), str_b=StringField("inline"))
    check(destroy_object(obj(inline=node)) ==
          [("delete-string-A", "I", 16), ("delete-node", "I", 0x60)],
          "inline list single node")
    # Teardown list runs before the inline list.
    check(destroy_object(obj(teardown=Node("T"), inline=Node("I"))) ==
          [("delete-node", "T", 0x60), ("delete-node", "I", 0x60)],
          "teardown list before inline list")
    # Worked tree in the inline list: head A, child chain C -> D
    # (D having child E), sibling B -> C, E, D, A, B.
    e = Node("E")
    d = Node("D", child=e)
    c = Node("C", nxt=d)
    b = Node("B")
    a = Node("A", child=c, nxt=b)
    check([row[1] for row in destroy_object(obj(inline=a))
           if row[0] == "delete-node"] == ["C", "E", "D", "A", "B"],
          "worked tree order")
    # Strings descend, cap + 1, last field included, no object delete.
    strings = inline_strings()
    strings[0x290] = StringField("heap", 5)
    strings[0x130] = StringField("heap", 0)
    strings[0x00] = StringField("heap", 15)
    check(destroy_object(obj(strings=strings)) ==
          [("delete-string", "0x290", 6), ("delete-string", "0x130", 1),
           ("delete-string", "0x0", 16)],
          "strings descending with cap+1, last field via tail jump")
    # Full order: teardown list, inline list, then strings.
    strings = inline_strings()
    strings[0x270] = StringField("heap", 2)
    out = destroy_object(obj(teardown=Node("T"), inline=Node("I"),
                             strings=strings))
    check(out == [("delete-node", "T", 0x60), ("delete-node", "I", 0x60),
                  ("delete-string", "0x270", 3)],
          "full order teardown, inline, strings")
    # Inline strings free nothing; heap node strings in a tree do.
    deep = Node("P", child=Node("K", str_b=StringField("heap", 7)))
    check(destroy_object(obj(teardown=deep)) ==
          [("delete-string-B", "K", 8), ("delete-node", "K", 0x60),
           ("delete-node", "P", 0x60)],
          "child subtree before parent")
    # Input is not mutated: a second run gives the same result.
    first = destroy_object(obj(teardown=Node("T"), inline=Node("I")))
    second = destroy_object(obj(teardown=Node("T"), inline=Node("I")))
    check(first == second, "repeat run agrees")
    # Guards.
    cyc = Node("C")
    cyc.next = cyc
    expect_raises(lambda: destroy_object(obj(inline=cyc)), "cycle guard")
    expect_raises(lambda: destroy_object(obj(inline="nope")), "dangling guard")
    bad = obj()
    del bad["strings"][0x20]
    expect_raises(lambda: destroy_object(bad), "missing field guard")
    expect_raises(lambda: destroy_object({"teardown_list": None}),
                  "missing keys guard")
    print("checks pass: %d" % CHECKS[0])


if __name__ == "__main__":
    main()
