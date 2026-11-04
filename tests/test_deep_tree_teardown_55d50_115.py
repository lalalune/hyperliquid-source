"""Tests for tools/deep_tree_teardown_55d50_115.py (RE-001, node #115).

Run without pytest (not installed on this VM) by importing the module
and calling every test_* function; verify.py does exactly that.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from deep_tree_teardown_55d50_115 import Node, Ref, dispose_node, teardown


def _names(events):
    return [e[1] for e in events if e[0] == "delete_node"]


def test_null_root_is_noop():
    events = []
    teardown(None, events)
    assert events == []


def test_single_node_sso_null_ref():
    node = Node("R")
    events = []
    teardown(node, events)
    assert events == [("delete_node", "R", 0x50)]
    assert node.disposed is True


def test_single_node_heap_string_and_ref():
    ref = Ref("P", owners=1)
    node = Node("R", ref=ref, heap_string=True, capacity=15)
    events = []
    teardown(node, events)
    assert events == [("release", "P"), ("destroy", "P"),
                      ("delete_string", 16), ("delete_node", "R", 0x50)]
    assert ref.destroyed is True


def test_ref_survives_when_owners_remain():
    ref = Ref("P", owners=2)
    node = Node("R", ref=ref)
    events = []
    teardown(node, events)
    assert ref.owners == 1 and ref.destroyed is False
    assert ("destroy", "P") not in events


def test_post_order_tree():
    # R down A; A down C, A next B; B down D.
    c = Node("C")
    d = Node("D")
    b = Node("B", down=d)
    a = Node("A", down=c, next=b)
    r = Node("R", down=a)
    events = []
    teardown(r, events)
    assert _names(events) == ["C", "A", "D", "B", "R"]


def test_sibling_chain_in_order():
    s2 = Node("S2")
    s1 = Node("S1", next=s2)
    r = Node("R", next=s1)
    events = []
    teardown(r, events)
    assert _names(events) == ["R", "S1", "S2"]


def test_deep_chain_beyond_eight_level_unroll():
    # A 12-deep down chain: the binary unrolls 8 levels then recurses,
    # so disposal must still be deepest-first for the whole chain.
    head = Node("N0")
    cur = head
    for i in range(1, 12):
        nxt = Node(f"N{i}")
        cur.down = nxt
        cur = nxt
    events = []
    teardown(head, events)
    assert _names(events) == [f"N{i}" for i in range(11, -1, -1)]


def test_dispose_node_event_order():
    ref = Ref("P", owners=1)
    node = Node("R", ref=ref, heap_string=True, capacity=0)
    events = []
    dispose_node(node, events)
    assert events == [("release", "P"), ("destroy", "P"),
                      ("delete_string", 1), ("delete_node", "R", 0x50)]
