"""Model tests for the node #115 0x48-byte tree assign (0x5d4e140).

Run from the repository root:
    python3 tests/test_tree_assign_48_115.py
Prints "<n> checks pass" on success, else raises.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from tree_assign_48_115 import (HEADER, Container, Node, _pop, _teardown,
                                assign, rebuilder)

CHECKS = [0]


def check(condition, label):
    CHECKS[0] += 1
    if not condition:
        raise AssertionError(label)


def shape(node, label, tag, s, extra40, link, next_label, child_label):
    check(node.label == label, "label %s" % label)
    check(node.tag == tag, "tag %s" % label)
    check(node.s == s, "string %s" % label)
    check(node.extra40 == extra40, "extra40 %s" % label)
    check(node.link is link, "link %s" % label)
    check((node.next.label if node.next else None) == next_label,
          "next %s" % label)
    check((node.child.label if node.child else None) == child_label,
          "child %s" % label)


def src_tree():
    """Root R, child chain A -> B, A child E; count 4."""
    e = Node("E", tag=5, s="e", extra40=50)
    b = Node("B", tag=2, s="bb", extra40=20)
    a = Node("A", tag=1, s="a", extra40=10, next_=b, child=e)
    r = Node("R", tag=0, s="root", extra40=0, child=a)
    return Container(root=r, slot18=r, slot20=e, count=4)


def test_empty_into_empty():
    events = []
    dst = Container()
    assign(dst, Container(), events)
    check(dst.root is None, "empty dst root")
    check(dst.slot18 is HEADER and dst.slot20 is HEADER, "empty slots")
    check(dst.count == 0, "empty count")
    check(events == [], "empty events")


def test_fresh_build():
    events = []
    dst = Container()
    assign(dst, src_tree(), events)
    root = dst.root
    check([e for e in events] == [("alloc", "fresh0", 0x48),
                                  ("alloc", "fresh1", 0x48),
                                  ("alloc", "fresh2", 0x48),
                                  ("alloc", "fresh3", 0x48)],
          "fresh alloc order root, child, grandchild, sibling")
    shape(root, "fresh0", 0, "root", 0, HEADER, None, "fresh1")
    shape(root.child, "fresh1", 1, "a", 10, root, "fresh3", "fresh2")
    shape(root.child.child, "fresh2", 5, "e", 50, root.child, None, None)
    shape(root.child.next, "fresh3", 2, "bb", 20, root.child, None, None)
    check(dst.slot18 is root, "slot18 root has no next")
    check(dst.slot20 is root.child.child, "slot20 deepest child")
    check(dst.count == 4, "count copied")


def test_empty_src_destroys_old():
    # Old tree: root R, child chain A -> B -> C (worked teardown order).
    c = Node("C", tag=3, s="c", extra40=30)
    b = Node("B", tag=2, s="bb", extra40=20, next_=c)
    a = Node("A", tag=1, s="a", extra40=10, next_=b)
    r = Node("R", tag=0, s="root", extra40=0, child=a)
    a.link = r
    b.link = a
    c.link = b
    dst = Container(root=r, slot18=r, slot20=a, count=4)
    events = []
    assign(dst, Container(), events)
    check(dst.root is None and dst.count == 0, "dst emptied")
    check(events == [("delete", "A", 0x48), ("delete", "B", 0x48),
                     ("delete", "C", 0x48), ("delete", "R", 0x48)],
          "teardown order child chain then root")


def test_heap_dispose_sizes():
    # Heap strings (length > 15) free length + 1; inline free nothing.
    old = Node("O", tag=0, s="x" * 20, extra40=0)
    dst = Container(root=old, slot18=old, slot20=old, count=1)
    events = []
    assign(dst, Container(), events)
    check(events == [("dispose", "O", 21), ("delete", "O", 0x48)],
          "heap dispose size is length + 1")


def test_reuse_and_orphan():
    # Old: root R, first child chain A -> B -> C. Src: single node S.
    # Pop takes B (simple case clears A.next); leftover destroys A
    # and R; C is orphaned: never reused, never deleted.
    c = Node("C", tag=3, s="c", extra40=30)
    b = Node("B", tag=2, s="bb", extra40=20, next_=c)
    a = Node("A", tag=1, s="a", extra40=10, next_=b)
    r = Node("R", tag=0, s="root", extra40=0, child=a)
    a.link = r
    b.link = a
    c.link = b
    dst = Container(root=r, slot18=r, slot20=a, count=4)
    src = Container(root=Node("S", tag=9, s="solo", extra40=99),
                    slot18=HEADER, slot20=HEADER, count=1)
    events = []
    assign(dst, src, events)
    check(dst.root is b, "B reused as new root")
    shape(b, "B", 9, "solo", 99, HEADER, None, None)
    check(dst.slot18 is b and dst.slot20 is b, "slots for single node")
    check(dst.count == 1, "count")
    check(events == [("delete", "A", 0x48), ("delete", "R", 0x48)],
          "leftover deletes A and R only; C orphaned, B reused")
    check(all(e[1] != "C" for e in events), "C never disposed or deleted")
    check(dst.root.child is None, "new root has no child, so C is unreachable")


def test_no_orphan_two_siblings():
    # Old: root R, first child chain A -> B. Src: single node.
    # Pop takes B; leftover destroys A and R; nothing orphaned.
    b = Node("B", tag=2, s="bb", extra40=20)
    a = Node("A", tag=1, s="a", extra40=10, next_=b)
    r = Node("R", tag=0, s="root", extra40=0, child=a)
    a.link = r
    b.link = a
    dst = Container(root=r, slot18=r, slot20=a, count=3)
    src = Container(root=Node("S", tag=9, s="solo", extra40=99), count=1)
    events = []
    assign(dst, src, events)
    check(dst.root is b, "B reused")
    check(events == [("delete", "A", 0x48), ("delete", "R", 0x48)],
          "no orphan: every old node reused or deleted")


def test_splice_reuses_root():
    # Old: root R, only child X (X is the +0x20 slot, no successor).
    # First pop splices: R.child cleared, pool[1] becomes R. A
    # two-node source then reuses X as root and R as its sibling.
    x = Node("X", tag=7, s="x", extra40=70)
    r = Node("R", tag=0, s="root", extra40=0, child=x)
    x.link = r
    dst = Container(root=r, slot18=r, slot20=x, count=2)
    s2 = Node("S2", tag=2, s="two", extra40=2)
    s1 = Node("S1", tag=1, s="one", extra40=1, next_=s2)
    src = Container(root=s1, count=2)
    events = []
    assign(dst, src, events)
    check(dst.root is x, "X reused as root")
    shape(x, "X", 1, "one", 1, HEADER, "R", None)
    shape(r, "R", 2, "two", 2, x, None, None)
    check(dst.slot18 is r, "slot18 last via next")
    check(dst.slot20 is x, "slot20 root has no child")
    check(events == [], "splice case: no old node deleted")


def test_pop_branches():
    # Simple case: head's link has no child equal to head.
    a = Node("A", s="a")
    b = Node("B", s="b", link=a)
    pool = [a, b]
    check(_pop(pool) is b, "simple pop takes head")
    check(pool[1] is a, "simple pop pool head becomes the link")
    check(a.next is None, "simple pop clears link next")
    # Splice walk-down: head X, link P with P.child == X, P.next Q,
    # Q.child Q1, Q1.next Z -> pool[1] ends at Z, P.child cleared.
    z = Node("Z", s="z")
    q1 = Node("Q1", s="q1", next_=z)
    q = Node("Q", s="q", child=q1)
    p = Node("P", s="p", child=None, next_=q)
    x = Node("X", s="x", link=p)
    p.child = x
    pool = [p, x]
    check(_pop(pool) is x, "splice pop takes head")
    check(pool[1] is z, "splice walk-down ends at deepest next")
    check(p.child is None, "splice clears child")
    # Empty pool and nxt-None case.
    check(_pop([None, None]) is None, "empty pool")
    lone = Node("L", s="l")
    pool = [lone, lone]
    check(_pop(pool) is lone, "nxt-None pop takes head")
    check(pool[0] is None, "nxt-None clears pool[0]")


def test_self_assign_and_cycles():
    dst = src_tree()
    events = []
    assign(dst, dst, events)
    check(events == [], "self-assign no effect")
    check(dst.root.tag == 0 and dst.count == 4, "self-assign unchanged")
    cyc = Node("C", s="c")
    cyc.next = cyc
    try:
        _teardown(cyc, [], set())
        check(False, "cyclic teardown must raise")
    except ValueError:
        check(True, "cyclic teardown raises")


def test_random_chained_assigns():
    import random
    rng = random.Random(48)

    seq = [0]

    def rand_tree(depth, prefix):
        seq[0] += 1
        node = Node("n%d" % seq[0],
                    tag=rng.randint(0, 9),
                    s="s" * rng.randint(0, 20),
                    extra40=rng.randint(0, 99))
        if depth > 0 and rng.random() < 0.6:
            node.child = rand_tree(depth - 1, prefix + "c")
        if rng.random() < 0.5:
            node.next = rand_tree(0, prefix + "n")
        return node

    def collect(node, out):
        while node is not None:
            out.append((node.s, node.tag, node.extra40))
            collect(node.child, out)
            node = node.next

    def collect_ids(node, out):
        while node is not None:
            out.append(id(node))
            collect_ids(node.child, out)
            node = node.next

    dst = Container()
    for i in range(60):
        src_root = rand_tree(2, "t%d" % i)
        want = []
        collect(src_root, want)
        src = Container(root=src_root, count=len(want))
        before_ids = []
        collect_ids(dst.root, before_ids)
        # The destination tree stays a proper tree (no node
        # reachable twice), so the leftover teardown, which
        # visits each node once (its seen-set raises otherwise),
        # can never free the same node twice in one assign.
        # Fresh labels repeat across assigns by design (the
        # counter resets per assign), so label uniqueness is
        # not the right check here; object identity is.
        check(len(before_ids) == len(set(before_ids)),
              "chained assign %d old tree is proper" % i)
        events = []
        assign(dst, src, events)
        got = []
        collect(dst.root, got)
        check(got == want, "chained assign %d shape" % i)
        check(dst.count == len(want), "chained assign %d count" % i)
        after_ids = []
        collect_ids(dst.root, after_ids)
        check(len(after_ids) == len(set(after_ids)),
              "chained assign %d new tree is proper" % i)


def main():
    test_empty_into_empty()
    test_fresh_build()
    test_empty_src_destroys_old()
    test_heap_dispose_sizes()
    test_reuse_and_orphan()
    test_no_orphan_two_siblings()
    test_splice_reuses_root()
    test_pop_branches()
    test_self_assign_and_cycles()
    test_random_chained_assigns()
    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
