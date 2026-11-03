"""Tests for the node #115 0x48-byte tree teardown with a per-node
destroy hook model (tools/tree_teardown_hook_115.py, RE-001 work item
RE-001-tree-teardown-hook-115). Each check counts; the run prints
"<n> checks pass" on success.

Expectations are target-grounded: the per-node sequence (hook call
when the +0x38 slot is non-null, then node delete 0x48, successor
loaded before both) and the post-order (children before parent,
siblings in chain order) are read from the whole-function excerpt in
the packet; the 12-level case exercises the recursion the binary
uses past its eight unrolled child links. The hook's internals are
not claimed: tests record only that it is invoked, when, and with
exactly (member, member, 3).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tree_teardown_hook_115 import Node, destroy_chain, node_order

CHECKS = [0]


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


def expect_raises(fn, label):
    try:
        fn()
    except ValueError:
        CHECKS[0] += 1
    else:
        raise AssertionError(label)


def main():
    # Null head destroys nothing and calls no hook.
    check(destroy_chain(None) == [], "null head destroys nothing")

    # Single node with a null hook slot: only the node delete.
    check(destroy_chain(Node("a")) == [("node", "a", 0x48)],
          "single null-hook node")

    # Single node with a hook: the hook runs first, with exactly
    # (member, member, 3), then the node delete 0x48.
    calls = []

    def hook(*args):
        calls.append(args)

    node = Node("a", hook=hook)
    check(destroy_chain(node) ==
          [("hook", "a", 3), ("node", "a", 0x48)],
          "single hook node order")
    check(len(calls) == 1 and calls[0][0] is node
          and calls[0][1] is node and calls[0][2] == 3,
          "hook arguments are (member, member, 3)")

    # A null hook slot never calls, even among hooked siblings.
    calls = []
    head = Node("a", hook=hook, next_=Node("b", next_=Node("c", hook=hook)))
    events = destroy_chain(head)
    check(events == [("hook", "a", 3), ("node", "a", 0x48),
                     ("node", "b", 0x48),
                     ("hook", "c", 3), ("node", "c", 0x48)],
          "null hook skipped among siblings")
    check([c for c in calls] and len(calls) == 2,
          "only hooked siblings called")

    # Sibling chain order.
    head = Node("a", next_=Node("b", next_=Node("c")))
    check(node_order(head) == ["a", "b", "c"], "sibling chain order")

    # Child before parent, and a child's hook runs before the
    # parent's hook.
    calls = []
    head = Node("a", hook=hook, child=Node("b", hook=hook,
                                          next_=Node("c", hook=hook)))
    events = destroy_chain(head)
    check(node_order(head) == ["b", "c", "a"], "child before parent")
    check([name for kind, name, _ in events if kind == "hook"] ==
          ["b", "c", "a"], "child hooks before parent hook")

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
    for name in ("d", "b", "e", "c", "a", "g", "f"):
        check(("node", name, 0x48) in events, "node delete 0x48: " + name)

    # Mixed hooked/unhooked tree: hook events precede their own node
    # events and follow post-order.
    calls = []
    tree = Node("a", hook=hook,
                child=Node("b", child=Node("d", hook=hook),
                           next_=Node("c")),
                next_=Node("f", hook=hook, child=Node("g", hook=hook)))
    events = destroy_chain(tree)
    check([name for kind, name, _ in events if kind == "hook"] ==
          ["d", "a", "g", "f"], "mixed tree hook order")
    for i, event in enumerate(events):
        if event[0] == "hook":
            check(events[i + 1] == ("node", event[1], 0x48),
                  "hook precedes its node delete")

    # Twelve-level child chain: deepest first, then back up. This
    # passes the eight unrolled links, so it exercises the
    # self-recursion path.
    head = Node("n0")
    cursor = head
    for i in range(1, 12):
        child = Node("n%d" % i)
        cursor.child = child
        cursor = child
    check(node_order(head) == ["n%d" % i for i in range(11, -1, -1)],
          "twelve-level chain order")

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
