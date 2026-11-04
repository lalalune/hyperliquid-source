"""Tests for the node #115 0x48-byte tree teardown model
(tools/tree_teardown_48str_115.py, RE-001 work item
RE-001-tree-teardown-48str-115). Each check counts; the run prints
"<n> checks pass" on success.

Expectations are target-grounded: the per-node sequence (string
dispose, then node delete 0x48, successor loaded before the deletes)
and the post-order (children before parent, siblings in chain order)
are read from the whole-function excerpt in the packet; the 10-level
case exercises the recursion the binary uses past its six unrolled
levels.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tree_teardown_48str_115 import Node, StringField, destroy_chain, node_order

CHECKS = [0]


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


def heap(data, cap):
    return StringField(data, inline=False, capacity=cap)


def expect_raises(fn, label):
    try:
        fn()
    except ValueError:
        CHECKS[0] += 1
    else:
        raise AssertionError(label)


def main():
    # Null head destroys nothing.
    check(destroy_chain(None) == [], "null head destroys nothing")

    # Single inline node: no heap delete, node delete 0x48.
    check(destroy_chain(Node("a")) ==
          [("string", "a", None), ("node", "a", 0x48)],
          "single inline node")

    # Single heap node: delete size is capacity + 1.
    check(destroy_chain(Node("a", string=heap(b"hello", 15))) ==
          [("string", "a", 16), ("node", "a", 0x48)],
          "heap delete size is cap + 1")

    # Heap string with spare capacity still frees cap + 1.
    check(destroy_chain(Node("a", string=heap(b"hi", 31)))[0] ==
          ("string", "a", 32), "spare capacity frees cap + 1")

    # Sibling chain order.
    head = Node("a", next_=Node("b", next_=Node("c")))
    check(node_order(head) == ["a", "b", "c"], "sibling chain order")

    # Child before parent.
    head = Node("a", child=Node("b", next_=Node("c")))
    check(node_order(head) == ["b", "c", "a"], "child before parent")

    # Worked mixed tree:
    #   a
    #  / \
    # b   c
    # |   |
    # d   e
    # plus a's sibling f, whose child is g.
    tree = Node("a",
                child=Node("b", child=Node("d"),
                           next_=Node("c", child=Node("e"))),
                next_=Node("f", child=Node("g")))
    check(node_order(tree) == ["d", "b", "e", "c", "a", "g", "f"],
          "worked mixed tree order")
    events = destroy_chain(tree)
    for i in range(0, len(events), 2):
        check(events[i][0] == "string" and events[i + 1][0] == "node"
              and events[i][1] == events[i + 1][1]
              and events[i + 1][2] == 0x48,
              "string event precedes its node event")

    # Ten-level child chain: deepest first, then back up.
    head = Node("n0")
    cursor = head
    for i in range(1, 10):
        child = Node("n%d" % i)
        cursor.child = child
        cursor = child
    check(node_order(head) == ["n%d" % i for i in range(9, -1, -1)],
          "ten-level chain order")

    # A shared subtree under two parents is not a well-formed tree;
    # the model must refuse the second visit, not double-delete.
    inner = Node("x", child=Node("y"))
    shared = Node("a", child=inner, next_=Node("b", child=inner))
    expect_raises(lambda: destroy_chain(shared), "shared subtree rejected")

    # Sibling cycle back to a chain head.
    a = Node("a")
    b = Node("b")
    a.child = b
    b.next = a
    expect_raises(lambda: destroy_chain(a), "sibling cycle rejected")

    # Self sibling cycle.
    a = Node("a")
    a.next = a
    expect_raises(lambda: destroy_chain(a), "self-cycle rejected")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
