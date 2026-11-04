"""Tests for the node #115 tree find at 0x5d4ec40.

Builds binary search trees ordered by the routine's own string
comparison (node key at +0x20/+0x28, left at +0x10, right at
+0x18) and checks the model against target-grounded expectations:
exact hits, misses that must return the sentinel (not the
lower_bound successor), prefix keys, the empty key, the empty
tree, and corruption guards.

Address plan: the header lives at 0x1000, so the sentinel is
0x1008; node ids start at 0x2000 and never collide with it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tree_find_115 import Node, Tree, string_compare, tree_find


def build(keys, header=0x1000):
    """Build a BST over keys (bytes) with node ids from 0x2000 up."""
    tree = Tree(header=header)
    root = None

    def fresh_id():
        return 0x2000 + 8 * len(tree.nodes)

    def insert(node_id, key):
        node = tree.nodes[node_id]
        cmp = string_compare(key, len(key), node.key, len(node.key))
        if cmp < 0:
            if node.left is None:
                new = fresh_id()
                tree.add(new, Node(key))
                node.left = new
            else:
                insert(node.left, key)
        else:
            if node.right is None:
                new = fresh_id()
                tree.add(new, Node(key))
                node.right = new
            else:
                insert(node.right, key)

    for key in keys:
        if root is None:
            root = fresh_id()
            tree.add(root, Node(key))
        else:
            insert(root, key)
    tree.root = root
    return tree


def node_id_for(tree, key):
    return next(i for i, n in tree.nodes.items() if n.key == key)


def check(name, got, want):
    assert got == want, "%s: got %#x want %#x" % (name, got, want)


def main():
    count = 0
    # Empty tree: root null returns the sentinel at once.
    tree = Tree(header=0x2000)
    check("empty tree", tree_find(tree, b"a"), 0x2008)
    count += 1

    # Single node: hit and miss, with header and node distinct.
    tree = build([b"mango"])
    check("single hit", tree_find(tree, b"mango"),
          node_id_for(tree, b"mango"))
    check("single miss below", tree_find(tree, b"apple"), tree.sentinel)
    check("single miss above", tree_find(tree, b"zebra"), tree.sentinel)
    count += 3

    # Balanced tree: every key hits, every gap misses with the
    # sentinel, never the successor (this is find, not lower_bound).
    keys = [b"fig", b"apple", b"mango", b"banana", b"grape",
            b"lemon", b"peach"]
    tree = build(keys)
    for key in keys:
        node = tree_find(tree, key)
        assert tree.nodes[node].key == key, "hit wrong node for %r" % key
        count += 1
    for gap in [b"apricot", b"cherry", b"kiwi", b"melon", b"plum",
                b"aardvark", b"zucchini"]:
        check("gap %r" % gap, tree_find(tree, gap), tree.sentinel)
        count += 1

    # Prefix keys: a key that extends a node key, and a node key
    # that extends the search key, are both misses.
    tree = build([b"app", b"banana", b"band"])
    check("key extends node", tree_find(tree, b"apple"), tree.sentinel)
    check("node extends key", tree_find(tree, b"ban"), tree.sentinel)
    check("prefix hit", tree_find(tree, b"band"),
          node_id_for(tree, b"band"))
    count += 3

    # Empty key: only an empty-key node matches.
    tree = build([b"", b"a", b"b"])
    check("empty key hit", tree.nodes[tree_find(tree, b"")].key, b"")
    tree = build([b"a", b"b"])
    check("empty key miss", tree_find(tree, b""), tree.sentinel)
    count += 2

    # Deep walk: keys inserted in sorted order (a degenerate chain
    # through right children) still find every key.
    tree = build([bytes([97 + i]) for i in range(20)])
    for i in range(20):
        node = tree_find(tree, bytes([97 + i]))
        assert tree.nodes[node].key == bytes([97 + i])
        count += 1
    check("degenerate miss", tree_find(tree, b"{"), tree.sentinel)
    count += 1

    # Corruption guards: dangling child and cyclic walk raise
    # instead of returning a bogus node.
    tree = Tree(header=0x7000)
    tree.add(0x8000, Node(b"m", left=0x9999))
    tree.root = 0x8000
    try:
        tree_find(tree, b"a")
        raise AssertionError("dangling child did not raise")
    except ValueError:
        count += 1
    tree = Tree(header=0x7000)
    tree.add(0x8000, Node(b"m", left=0x8000))
    tree.root = 0x8000
    try:
        tree_find(tree, b"a")
        raise AssertionError("cyclic walk did not raise")
    except ValueError:
        count += 1

    # Saturated comparison: prefix ties with huge length gaps
    # saturate instead of overflowing int32.
    assert string_compare(b"a", 0x80000001, b"a", 1) == 1
    assert string_compare(b"a", 1, b"a", 0x80000002) == -1
    assert string_compare(b"a", 0x80000000, b"a", 1) == 0x7fffffff
    assert string_compare(b"b", 3, b"a", 3) == 1
    assert string_compare(b"a", 3, b"b", 3) == -1
    count += 4

    print("%d checks pass" % count)


if __name__ == "__main__":
    main()
