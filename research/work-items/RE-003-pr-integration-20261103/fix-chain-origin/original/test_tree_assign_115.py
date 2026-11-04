"""Tests for tools/tree_assign_115.py (node #115 tree assign).

The model is validated against target-grounded expectations: a rebuilt
tree must match the source tree exactly (tags, strings, shape), every
old destination node must be reused or destroyed exactly once, and
destroy events must reference old nodes only.
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tree_assign_115 import Container, Node, assign, HEADER

_checks = []


def check(name, cond):
    _checks.append((name, bool(cond)))
    if not cond:
        print("FAIL:", name)


def shape(node):
    """(tag, stra, strb, child-shape, next-shape) for a whole chain."""
    if node is None:
        return None
    return (node.tag, node.stra, node.strb, shape(node.child),
            shape(node.next))


def collect(node, out):
    while node is not None:
        out.append(node)
        collect(node.child, out)
        node = node.next


def all_nodes(container):
    out = []
    collect(container.root, out)
    return out


def link_tree(root, head_link=HEADER):
    """Set link fields per the binary convention: a chain head's
    link is the given head_link (HEADER for a tree root, the
    parent for a child chain), a later sibling's link is its
    previous sibling."""
    prev = None
    cur = root
    while cur is not None:
        cur.link = prev if prev is not None else head_link
        if cur.child is not None:
            link_tree(cur.child, cur)
        prev = cur
        cur = cur.next


def make_tree(spec, prefix):
    """Build a sibling chain from nested tuples
    (tag, stra, strb, [children...], next...)."""
    head = None
    prev = None
    for i, item in enumerate(spec):
        tag, stra, strb, children = item
        node = Node("%s%d" % (prefix, i), tag=tag, stra=stra, strb=strb)
        node.child = make_tree(children, "%s%dc" % (prefix, i)) \
            if children else None
        if prev is not None:
            prev.next = node
        else:
            head = node
        prev = node
    if head is not None:
        link_tree(head)
    return head


def deepest_child(root):
    node = root
    while node.child is not None:
        node = node.child
    return node


def container_of(root, count):
    if root is None:
        return Container()
    last10 = root
    while last10.next is not None:
        last10 = last10.next
    return Container(root, last10, deepest_child(root), count)


def build_container(spec, prefix, count):
    root = make_tree(spec, prefix)
    return container_of(root, count)


# A source tree: root with two children (one with its own child),
# a root sibling, and a long heap string plus a short inline one.
SRC = [(1, "alpha", "a" * 20, [
    (2, "beta", "b", [
        (3, "gamma", "c" * 17, []),
    ]),
    (4, "delta", "d", []),
]), (5, "epsilon", "e" * 16, [])]
OLD = [(9, "old-root-long-string-here", "o", [
    (8, "old-child", "p" * 30, []),
]), (7, "old-sib", "q", [])]

src = build_container(SRC, "s", 5)
dst = build_container(OLD, "o", 3)
old_labels = {n.label for n in all_nodes(dst)}
events = []
assign(dst, src, events)
check("copy shape matches source", shape(dst.root) == shape(src.root))
check("count copied", dst.count == 5)
check("slot18 is last +0x10 node",
      dst.slot18 is not None and dst.slot18.tag == 5)
check("slot20 is deepest first child",
      dst.slot20 is not None and dst.slot20.tag == 3)
reused = {n.label for n in all_nodes(dst)}
destroyed = [e[1] for e in events if e[0] == "delete"]
check("reused and destroyed are disjoint, each at most once",
      not (set(destroyed) & (reused & old_labels)) and
      len(destroyed) == len(set(destroyed)))
check("destroy events reference old nodes only",
      set(destroyed) <= old_labels)
check("3-node old tree + 5-node source allocates exactly 2",
      len([e for e in events if e[0] == "alloc"]) == 2)

# Worked orphan case (the binary's own cut, see the model docstring):
# old root with three children; the pool entry is the middle child,
# so the third child hangs off the taken node's +0x10 chain and is
# orphaned: neither reused nor destroyed.
ORPHAN_OLD = [(1, "r", "r", [
    (2, "c0", "c", []),
    (3, "c1", "c", []),
    (4, "c2", "c", []),
])]
ORPHAN_SRC = [(9, "only", "o", [])]
dst_o = build_container(ORPHAN_OLD, "w", 4)
old_o = {n.label for n in all_nodes(dst_o)}
ev_o = []
assign(dst_o, build_container(ORPHAN_SRC, "n", 1), ev_o)
reused_o = {n.label for n in all_nodes(dst_o)}
destroyed_o = {e[1] for e in ev_o if e[0] == "delete"}
check("orphan case: later sibling of the pool entry is orphaned",
      old_o - reused_o - destroyed_o == {"w0c2"})
check("orphan case: no double destroy",
      len([e for e in ev_o if e[0] == "delete"]) == len(destroyed_o))
check("orphan case: shape still matches source",
      shape(dst_o.root) == shape(build_container(ORPHAN_SRC, "n", 1).root))

# Old tree at least as large as the source, entry with no later
# sibling: exact-once reuse/destroy holds.
dst_b = build_container(SRC, "s", 5)
old_b = {n.label for n in all_nodes(dst_b)}
ev_b = []
assign(dst_b, build_container(OLD, "o", 3), ev_b)
reused_b = {n.label for n in all_nodes(dst_b)}
destroyed_b = [e[1] for e in ev_b if e[0] == "delete"]
check("no-orphan case: exact-once reuse/destroy",
      (reused_b & old_b) | set(destroyed_b) == old_b and
      not ((reused_b & old_b) & set(destroyed_b)) and
      len(destroyed_b) == len(set(destroyed_b)))
check("no-orphan case: no fresh alloc",
      not [e for e in ev_b if e[0] == "alloc"])

# Empty destination, nonempty source: everything allocates.
dst2 = Container()
events2 = []
assign(dst2, build_container(SRC, "s", 5), events2)
check("empty dst allocates whole tree",
      shape(dst2.root) == shape(src.root) and
      len([e for e in events2 if e[0] == "alloc"]) == 5 and
      not [e for e in events2 if e[0] == "delete"])

# Empty source into a nonempty destination: whole old tree destroyed.
dst3 = build_container(OLD, "o", 3)
events3 = []
assign(dst3, Container(), events3)
check("empty src destroys old tree",
      dst3.root is None and dst3.slot18 == HEADER and
      dst3.slot20 == HEADER and dst3.count == 0 and
      sorted(e[1] for e in events3 if e[0] == "delete") ==
      sorted({"o0", "o0c0", "o1"}))

# Self-assign is a no-op.
dst4 = build_container(OLD, "o", 3)
before = shape(dst4.root)
events4 = []
assign(dst4, dst4, events4)
check("self-assign is a no-op",
      events4 == [] and shape(dst4.root) == before)

# Heap strings dispose with length + 1; inline strings dispose nothing.
dst5 = build_container(
    [(1, "x" * 16, "y" * 5, [])], "h", 1)
events5 = []
assign(dst5, Container(), events5)
check("heap dispose size is length + 1, inline disposes nothing",
      ("dispose", "h0", "A", 17) in events5 and
      not [e for e in events5 if e[0] == "dispose" and e[2] == "B"])

# Random fuzz: chained assigns keep exact-once reuse/destroy.
rng = random.Random(115)


def random_spec(depth, budget, prefix):
    if budget <= 0 or depth <= 0:
        return []
    chain = []
    n = rng.randint(1, 3)
    for _ in range(n):
        if budget <= 0:
            break
        budget -= 1
        stra = "s" * rng.randint(0, 20)
        strb = "t" * rng.randint(0, 20)
        children = random_spec(depth - 1, budget // 2, prefix) \
            if rng.random() < 0.6 else []
        chain.append((rng.randint(0, 99), stra, strb, children))
    return chain


for trial in range(60):
    old = build_container(random_spec(3, 8, "o"), "o", 0)
    new = build_container(random_spec(3, 8, "s"), "s", 0)
    old_labels = {n.label for n in all_nodes(old)}
    expected = shape(new.root)
    ev = []
    assign(old, new, ev)
    got_reused = {n.label for n in all_nodes(old)}
    got_destroyed = [e[1] for e in ev if e[0] == "delete"]
    check("fuzz %d: shape" % trial, shape(old.root) == expected)
    check("fuzz %d: disjoint, no double destroy" % trial,
          not ((got_reused & old_labels) & set(got_destroyed)) and
          len(got_destroyed) == len(set(got_destroyed)))
    check("fuzz %d: destroys old nodes only" % trial,
          set(got_destroyed) <= old_labels)
    check("fuzz %d: count" % trial, old.count == new.count)

failed = [name for name, ok in _checks if not ok]
print("%d checks pass" % (len(_checks) - len(failed)))
if failed:
    print("FAILED:", failed)
    raise SystemExit(1)
