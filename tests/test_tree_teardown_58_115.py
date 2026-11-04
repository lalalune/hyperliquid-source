"""Model tests for the node #115 0x58-byte tree teardown 0x5d4d250."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tree_teardown_58_115 import Node58, destroy

CHECKS = []


def check(name, condition):
    CHECKS.append((name, bool(condition)))
    if not condition:
        raise AssertionError("failed: %s" % name)


def main():
    # Null head destroys nothing.
    check("null head", destroy(None) == [])

    # Single node, no child, no nested: one delete, size 0x58.
    check("single node",
          destroy(Node58("a")) == [("delete", "a", 0x58)])

    # Single node with a nested tree: nested torn down first.
    check("nested before delete",
          destroy(Node58("a", nested=object())) ==
          [("nested", "a"), ("delete", "a", 0x58)])

    # Sibling chain in order, no children.
    a = Node58("a", next=Node58("b", next=Node58("c")))
    check("sibling order",
          destroy(a) == [("delete", "a", 0x58),
                         ("delete", "b", 0x58),
                         ("delete", "c", 0x58)])

    # Child chain before the parent, then the parent's sibling.
    # Tree: a -> child b -> child d; a's sibling c.
    d = Node58("d")
    b = Node58("b", child=d)
    c = Node58("c")
    a = Node58("a", child=b, next=c)
    check("child before parent, sibling last",
          destroy(a) == [("delete", "d", 0x58),
                         ("delete", "b", 0x58),
                         ("delete", "a", 0x58),
                         ("delete", "c", 0x58)])

    # Worked tree mixing children, siblings and nested trees.
    # Root r has child chain x -> y; x has child z; y has a
    # nested tree; r has sibling s with a child t.
    z = Node58("z")
    x = Node58("x", child=z, next=Node58("y", nested=object()))
    t = Node58("t")
    s = Node58("s", child=t)
    r = Node58("r", child=x, next=s)
    check("worked tree order",
          destroy(r) == [("delete", "z", 0x58),
                         ("delete", "x", 0x58),
                         ("nested", "y"),
                         ("delete", "y", 0x58),
                         ("delete", "r", 0x58),
                         ("delete", "t", 0x58),
                         ("delete", "s", 0x58)])

    # Deep child chain (10 levels) exercises the same order the
    # binary reaches through its self-recursion past the six
    # unrolled levels: deepest first, then back up the chain.
    head = None
    for i in range(10):
        head = Node58("n%d" % i, child=head)
    events = destroy(head)
    check("deep chain order",
          events == [("delete", "n%d" % i, 0x58)
                     for i in range(10)])

    # Deep sibling chain with a child on every node.
    head = None
    for i in range(8):
        head = Node58("s%d" % i, child=Node58("c%d" % i),
                      next=head)
    events = destroy(head)
    want = []
    for i in reversed(range(8)):
        want.append(("delete", "c%d" % i, 0x58))
        want.append(("delete", "s%d" % i, 0x58))
    check("sibling-with-child order", events == want)

    # Every node deleted exactly once in a mixed tree.
    events = destroy(r)
    names = [e[1] for e in events if e[0] == "delete"]
    check("exact once", sorted(names) == ["r", "s", "t", "x", "y", "z"])

    # Cycle guard: a child pointing back at an ancestor raises
    # instead of looping (binary behavior on cycles not claimed).
    loop = Node58("loop")
    loop.child = loop
    try:
        destroy(loop)
        check("cycle raises", False)
    except ValueError:
        check("cycle raises", True)

    # Sibling cycle raises too.
    s1 = Node58("s1")
    s2 = Node58("s2", next=s1)
    s1.next = s2
    try:
        destroy(s1)
        check("sibling cycle raises", False)
    except ValueError:
        check("sibling cycle raises", True)

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
