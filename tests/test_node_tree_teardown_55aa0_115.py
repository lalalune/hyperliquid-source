"""Tests for tools/node_tree_teardown_55aa0_115.py (node #115, 0x5d55aa0).

pytest is not installed on this VM; the packet verify.py invokes every
test_* function here directly, so each test is self-contained.
Events are ("release", payload) and ("free", node, 0x38), in the
routine's post-order: a node's +0x18 subtree first, then the node,
then its +0x10 chain.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from node_tree_teardown_55aa0_115 import NODE_SIZE, Node, destroy


def _run(root):
    events = []
    destroy(root, events.append)
    return events


def test_null_root_emits_nothing():
    assert _run(None) == []


def test_single_node_releases_then_frees():
    node = Node(payload="p")
    assert _run(node) == [("release", "p"), ("free", node, NODE_SIZE)]
    assert NODE_SIZE == 0x38


def test_single_node_null_payload_still_frees():
    node = Node(payload=None)
    assert _run(node) == [("free", node, NODE_SIZE)]


def test_next_chain_in_order():
    a = Node(payload="a")
    b = Node(payload="b")
    c = Node(payload=None)
    a.next = b
    b.next = c
    assert _run(a) == [("release", "a"), ("free", a, NODE_SIZE),
                       ("release", "b"), ("free", b, NODE_SIZE),
                       ("free", c, NODE_SIZE)]


def test_down_chain_deepest_first():
    leaf = Node(payload="leaf")
    mid = Node(payload="mid", down=leaf)
    root = Node(payload="root", down=mid)
    assert _run(root) == [("release", "leaf"), ("free", leaf, NODE_SIZE),
                          ("release", "mid"), ("free", mid, NODE_SIZE),
                          ("release", "root"), ("free", root, NODE_SIZE)]


def test_full_tree_post_order():
    a1 = Node(payload="a1")
    a2 = Node(payload="a2")
    a = Node(payload="a", down=a1)
    a1.next = a2
    s = Node(payload="s")
    root = Node(payload="r", down=a)
    root.next = s
    assert _run(root) == [("release", "a1"), ("free", a1, NODE_SIZE),
                          ("release", "a2"), ("free", a2, NODE_SIZE),
                          ("release", "a"), ("free", a, NODE_SIZE),
                          ("release", "r"), ("free", root, NODE_SIZE),
                          ("release", "s"), ("free", s, NODE_SIZE)]


def test_release_precedes_free_for_every_node():
    n1 = Node(payload="x", down=Node(payload="y"))
    events = _run(n1)
    for i, event in enumerate(events):
        if event[0] == "release":
            node = n1.down if event[1] == "y" else n1
            assert ("free", node, NODE_SIZE) in events[i + 1:]


def test_deep_down_chain():
    nodes = [Node(payload=str(i)) for i in range(10)]
    for upper, lower in zip(nodes, nodes[1:]):
        upper.down = lower
    events = _run(nodes[0])
    assert [e[1] for e in events if e[0] == "release"] == \
        [str(i) for i in reversed(range(10))]
    assert len(events) == 20
