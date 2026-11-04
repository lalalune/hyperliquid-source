"""Tests for tools/node_tree_60_115.py (node #115 0x60-byte trees)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from node_tree_60_115 import (  # noqa: E402
    Node, construct_string, copy_tree, teardown)

CHECKS = []


def check(name, condition):
    CHECKS.append((name, bool(condition)))
    if not condition:
        raise AssertionError("FAILED: %s" % name)


def main():
    # String construct: SSO threshold and heap path.
    buf, size, inline, cap = construct_string(b"")
    check("empty string inline, size 0", (buf, size, inline, cap) == (b"", 0, True, None))
    buf, size, inline, cap = construct_string(b"x")
    check("1-byte string inline", (buf, size, inline) == (b"x", 1, True))
    buf, size, inline, cap = construct_string(b"0123456789abcde")
    check("15-byte string inline", (size, inline) == (15, True))
    buf, size, inline, cap = construct_string(b"0123456789abcdef")
    check("16-byte string heap, cap == len", (size, inline, cap) == (16, False, 16))
    buf, size, inline, cap = construct_string(b"hello world, this is long")
    check("long string round-trips bytes", buf == b"hello world, this is long" and size == 25)
    try:
        construct_string("not bytes")
        check("non-bytes input raises", False)
    except ValueError:
        check("non-bytes input raises", True)

    # Teardown: null head frees nothing.
    check("null teardown frees nothing", teardown(None) == [])

    # Teardown: single node, both strings heap.
    node = Node("A", tag=7, s20=b"0123456789abcdef", s40=b"0123456789abcdefg")
    freed = teardown(node)
    check("single-node teardown order B string, A string, node",
          freed == [("string", "A", "B", 18), ("string", "A", "A", 17),
                    ("node", "A", 0x60)])

    # Teardown: single node, both strings inline frees only the node.
    node = Node("A", s20=b"short", s40=b"tiny")
    check("inline strings free nothing but the node",
          teardown(node) == [("node", "A", 0x60)])

    # Teardown: worked tree A(child C -> D, D child E; sibling B).
    e = Node("E", s20=b"e" * 20, s40=b"e" * 5)
    d = Node("D", child=e, s20=b"d" * 3, s40=b"d" * 30)
    c = Node("C", next_node=d, s20=b"c" * 16, s40=b"c" * 2)
    b = Node("B", s20=b"b" * 1, s40=b"b" * 40)
    a = Node("A", child=c, next_node=b, s20=b"a" * 7, s40=b"a" * 8)
    freed = teardown(a)
    names = [(kind, name) for kind, name, *_rest in freed]
    check("worked tree teardown order C,E,D,A,B",
          names == [("string", "C"), ("node", "C"),
                    ("string", "E"), ("node", "E"),
                    ("string", "D"), ("node", "D"),
                    ("node", "A"),
                    ("string", "B"), ("node", "B")])
    check("worked tree heap sizes use cap+1",
          ("string", "C", "A", 17) in freed and ("string", "D", "B", 31) in freed)

    # Teardown: cycle raises instead of recursing forever.
    cyc = Node("X")
    cyc.next = cyc
    try:
        teardown(cyc)
        check("cyclic teardown raises", False)
    except ValueError:
        check("cyclic teardown raises", True)
    try:
        teardown(Node("Y", child=Node("Z", child=None)))
        check("acyclic deep teardown ok", True)
    except ValueError:
        check("acyclic deep teardown ok", False)

    # Copy: single node fields, link rule, string normalization.
    src = Node("A", tag=0x12345678, s20=b"0123456789abcdef",
               s40=b"short")
    made, order = copy_tree(src, "LINK")
    check("copy head link is incoming link", made.link == "LINK")
    check("copy tag copied", made.tag == 0x12345678)
    check("copy strings byte-equal", made.s20 == src.s20 and made.s40 == src.s40)
    check("copy string normalization is length-based",
          construct_string(made.s20)[2] is False and
          construct_string(made.s40)[2] is True)
    check("single copy allocation order", order == ["A'"])
    check("single copy has no next/child", made.next is None and made.child is None)

    # Copy: worked tree structure, links, allocation order.
    e = Node("E", s20=b"e", s40=b"e")
    d = Node("D", child=e, s20=b"d", s40=b"d")
    c = Node("C", next_node=d, s20=b"c", s40=b"c")
    b = Node("B", s20=b"b", s40=b"b")
    a = Node("A", child=c, next_node=b, s20=b"a", s40=b"a")
    made, order = copy_tree(a, "ROOT")
    check("worked copy allocation order head, child subtree, sibling",
          order == ["A'", "C'", "D'", "E'", "B'"])
    check("head child is C copy", made.child.name == "C'")
    check("C copy next is D copy", made.child.next.name == "D'")
    check("D copy child is E copy", made.child.next.child.name == "E'")
    check("head next is B copy", made.next.name == "B'")
    check("head copy link is incoming", made.link == "ROOT")
    check("child copy link is head copy", made.child.link is made)
    check("sibling copy link is previous copy", made.next.link is made)
    check("sibling child copy link is sibling copy",
          made.child.next.child.link is made.child.next)
    check("source untouched by copy",
          a.child.name == "C" and a.next.name == "B" and
          a.child.next.child.name == "E")

    # Copy: null source and cyclic source raise.
    try:
        copy_tree(None, "X")
        check("null copy source raises", False)
    except ValueError:
        check("null copy source raises", True)
    cyc = Node("X")
    cyc.child = cyc
    try:
        copy_tree(cyc, "X")
        check("cyclic copy raises", False)
    except ValueError:
        check("cyclic copy raises", True)

    # Round trip: teardown of a copy frees exactly the copy's blocks.
    src = Node("A", child=Node("C", next_node=Node("D")),
               next_node=Node("B"), s20=b"0123456789abcdef", s40=b"z")
    made, _order = copy_tree(src, "R")
    freed = teardown(made)
    freed_nodes = [name for kind, name, *_r in freed if kind == "node"]
    check("round trip frees copy nodes in teardown order",
          freed_nodes == ["C'", "D'", "A'", "B'"])
    check("round trip frees copy heap strings",
          ("string", "A'", "A", 17) in freed)

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
