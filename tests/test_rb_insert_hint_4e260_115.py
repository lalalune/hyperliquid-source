"""Tests for the node #115 RB insert-position models 0x5d4e260 /
0x5d49910 (RE-001).

Trees are built by hand (root, children, parent links, count) so
the tests exercise the search models, not a builder. Keys are
single bytes, as the binary reads them from node offset +0x20.
"""
import unittest

from tools.rb_insert_hint_4e260_115 import (
    Node,
    Tree,
    decrement,
    get_insert_hint_unique_pos,
    get_insert_unique_pos,
    increment,
)


def link(parent, child, side):
    setattr(parent, side, child)
    if child is not None:
        child.parent = parent


def build(spec):
    """Build a tree from (key, left_spec, right_spec) nested tuples."""
    tree = Tree()

    def make(node_spec):
        if node_spec is None:
            return None
        key, left, right = node_spec
        node = Node(key)
        link(node, make(left), "left")
        link(node, make(right), "right")
        return node

    tree.root = make(spec)
    if tree.root is not None:
        tree.root.parent = None

    def count(node):
        if node is None:
            return 0
        return 1 + count(node.left) + count(node.right)

    tree.count = count(tree.root)
    return tree


def find(tree, key):
    node = tree.root
    while node is not None:
        if key == node.key:
            return node
        node = node.left if key < node.key else node.right
    return None


# Tree: root 20, left 10 (left 5, right 15), right 30 (left 25).
SPEC = (20, (10, (5, None, None), (15, None, None)),
        (30, (25, None, None), None))


class TestUnhinted(unittest.TestCase):
    def test_empty_tree(self):
        tree = Tree()
        first, second = get_insert_unique_pos(tree, 7)
        self.assertIsNone(first)
        self.assertIs(tree.header, second)

    def test_existing_key_is_duplicate_marker(self):
        tree = build(SPEC)
        for key in (5, 10, 15, 20, 25, 30):
            first, second = get_insert_unique_pos(tree, key)
            self.assertIs(find(tree, key), first)
            self.assertIsNone(second)

    def test_below_leftmost(self):
        tree = build(SPEC)
        first, second = get_insert_unique_pos(tree, 1)
        self.assertIsNone(first)
        self.assertIs(find(tree, 5), second)

    def test_between_nodes_inserts_as_child(self):
        tree = build(SPEC)
        # 12: descent runs 20 -> 10 -> 15, then left to null with
        # predecessor 10 < 12 -> child of 15.
        first, second = get_insert_unique_pos(tree, 12)
        self.assertIsNone(first)
        self.assertIs(find(tree, 15), second)
        # 27: descent runs 20 -> 30 -> 25, then right to null with
        # 25 < 27 -> child of 25.
        first, second = get_insert_unique_pos(tree, 27)
        self.assertIsNone(first)
        self.assertIs(find(tree, 25), second)

    def test_above_rightmost(self):
        tree = build(SPEC)
        first, second = get_insert_unique_pos(tree, 99)
        self.assertIsNone(first)
        self.assertIs(find(tree, 30), second)

    def test_successor_predecessor_walks(self):
        tree = build(SPEC)
        self.assertIs(find(tree, 15), increment(find(tree, 10)))
        self.assertIs(find(tree, 20), increment(find(tree, 15)))
        self.assertIs(find(tree, 10), decrement(find(tree, 15)))
        self.assertIs(find(tree, 25), decrement(find(tree, 30)))


class TestHinted(unittest.TestCase):
    def test_end_hint_above_max(self):
        tree = build(SPEC)
        first, second = get_insert_hint_unique_pos(tree, tree.header, 99)
        self.assertIsNone(first)
        self.assertIs(find(tree, 30), second)

    def test_end_hint_below_max_falls_back(self):
        tree = build(SPEC)
        first, second = get_insert_hint_unique_pos(tree, tree.header, 12)
        self.assertIsNone(first)
        self.assertIs(find(tree, 15), second)

    def test_empty_tree_end_hint(self):
        tree = Tree()
        first, second = get_insert_hint_unique_pos(tree, tree.header, 7)
        self.assertIsNone(first)
        self.assertIs(tree.header, second)

    def test_hint_equal_key_is_duplicate(self):
        tree = build(SPEC)
        hint = find(tree, 20)
        first, second = get_insert_hint_unique_pos(tree, hint, 20)
        self.assertIs(hint, first)
        self.assertIsNone(second)

    def test_hint_leftmost_with_smaller_key(self):
        tree = build(SPEC)
        hint = find(tree, 5)
        first, second = get_insert_hint_unique_pos(tree, hint, 1)
        self.assertIs(hint, first)
        self.assertIs(hint, second)

    def test_hint_backward_bracket_with_free_child(self):
        tree = build(SPEC)
        # Hint 15, key 12: predecessor 10 < 12 and 10's right child
        # is 15 (occupied) -> doubled hint pair.
        hint = find(tree, 15)
        first, second = get_insert_hint_unique_pos(tree, hint, 12)
        self.assertIs(hint, first)
        self.assertIs(hint, second)

    def test_hint_backward_bracket_empty_right_slot(self):
        tree = build(SPEC)
        # Hint 25, key 22: predecessor 20 < 22 and 20's right child
        # is 30 (occupied) -> doubled hint pair; use hint 30/key 27
        # fallback instead: predecessor 25 >= 27 is false, 25 < 27,
        # and 25's right is None -> (None, 25).
        hint = find(tree, 30)
        first, second = get_insert_hint_unique_pos(tree, hint, 27)
        self.assertIsNone(first)
        self.assertIs(find(tree, 25), second)

    def test_hint_backward_falls_back(self):
        tree = build(SPEC)
        # Hint 30, key 12: predecessor 25 >= 12 -> full search,
        # which lands on 15 as above.
        hint = find(tree, 30)
        first, second = get_insert_hint_unique_pos(tree, hint, 12)
        self.assertIsNone(first)
        self.assertIs(find(tree, 15), second)

    def test_hint_forward_bracket(self):
        tree = build(SPEC)
        # Hint 10, key 12: successor 15 > 12 and 10's right child
        # is 15 (occupied) -> doubled successor pair.
        hint = find(tree, 10)
        first, second = get_insert_hint_unique_pos(tree, hint, 12)
        succ = find(tree, 15)
        self.assertIs(succ, first)
        self.assertIs(succ, second)

    def test_hint_forward_empty_right_slot(self):
        tree = build(SPEC)
        # Hint 25, key 27: successor 30 > 27 and 25's right is None
        # -> (None, 25).
        hint = find(tree, 25)
        first, second = get_insert_hint_unique_pos(tree, hint, 27)
        self.assertIsNone(first)
        self.assertIs(hint, second)

    def test_hint_forward_falls_back(self):
        tree = build(SPEC)
        # Hint 10, key 27: successor 15 <= 27 -> full search,
        # which lands on 25 as above.
        hint = find(tree, 10)
        first, second = get_insert_hint_unique_pos(tree, hint, 27)
        self.assertIsNone(first)
        self.assertIs(find(tree, 25), second)

    def test_hint_rightmost_with_larger_key(self):
        tree = build(SPEC)
        hint = find(tree, 30)
        first, second = get_insert_hint_unique_pos(tree, hint, 99)
        self.assertIsNone(first)
        self.assertIs(hint, second)

    def test_null_guards(self):
        with self.assertRaises(ValueError):
            Node(256)
        with self.assertRaises(ValueError):
            Node(-1)


if __name__ == "__main__":
    unittest.main()
