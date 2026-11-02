"""Model of node #94 tree insert-hint unique position 0x514c8f0 (RE-001 work item).

The function takes a tree container, a hint node (or the header node for
end) and a signed int32 key, and returns the (first, second) pair the
two insert consumers at 0x514ca70 and 0x514cb40 feed to
_Rb_tree_insert_and_rebalance:

* (node, None) on an exact hit -- the consumers free their fresh node
  and return the existing node;
* otherwise an insertion position: (0-ish, parent) as (None, parent)
  when the empty child link belongs to the parent, or (node, node)
  when the new node becomes a child of that node itself.

Container layout (offsets from the container object, as read from the
bytes):

    +0x10  root pointer (None when the tree is empty)
    +0x18  leftmost node (the header node itself when empty)
    +0x20  rightmost node (the header node itself when empty)
    +0x28  node count

Node layout:

    +0x08  parent pointer
    +0x10  left child
    +0x18  right child
    +0x20  signed int32 key

The model transliterates the bytes exactly, including the
less-or-equal arms of the full walk (on a valid tree they coincide
with equality, because the walk only ends going right at a node whose
key is at most the sought key, and only steps to a predecessor whose
key is at most the sought key).  See
research/work-items/RE-001-tree-insert-hint-94 for the observations /
inferences / unknowns split.
"""


class Header:
    """The container header node; also the end sentinel (container + 0x8)."""


class Node:
    def __init__(self, key, left=None, right=None, parent=None):
        self.key = key
        self.left = left
        self.right = right
        self.parent = parent


class Tree:
    """A tree container.  Extremes and count are derived from the root."""

    def __init__(self, root=None):
        self.header = Header()
        self.root = root
        if root is not None:
            root.parent = self.header

    @property
    def leftmost(self):
        if self.root is None:
            return self.header
        node = self.root
        while node.left is not None:
            node = node.left
        return node

    @property
    def rightmost(self):
        if self.root is None:
            return self.header
        node = self.root
        while node.right is not None:
            node = node.right
        return node

    @property
    def count(self):
        return len(inorder(self.root))


def inorder(node):
    if node is None:
        return []
    return inorder(node.left) + [node] + inorder(node.right)


def build(spec):
    """Build a tree from a nested (key, left, right) spec."""
    if spec is None:
        return None
    key, left, right = spec
    node = Node(key)
    node.left = build(left)
    if node.left is not None:
        node.left.parent = node
    node.right = build(right)
    if node.right is not None:
        node.right.parent = node
    return node


def find(tree, key):
    for node in inorder(tree.root):
        if node.key == key:
            return node
    return None


def decrement(tree, node):
    """In-order predecessor of a real node (the 0x56604b0 PLT callee)."""
    if node is tree.header:
        raise ValueError("decrement is never called on the header here")
    if node.left is not None:
        node = node.left
        while node.right is not None:
            node = node.right
        return node
    parent = node.parent
    while parent is not tree.header and node is parent.left:
        node = parent
        parent = parent.parent
    return parent


def increment(tree, node):
    """In-order successor of a real node (the 0x5660560 PLT callee)."""
    if node is tree.header:
        raise ValueError("increment is never called on the header here")
    if node.right is not None:
        node = node.right
        while node.left is not None:
            node = node.left
        return node
    parent = node.parent
    while parent is not tree.header and node is parent.right:
        node = parent
        parent = parent.parent
    return parent


def get_insert_unique_pos(tree, key):
    """The twin full search (0x514b220) this function falls back to.

    Returns (first, second): (node, None) on a hit, (None, neighbour)
    on a miss, (None, header) on an empty tree.
    """
    node = tree.root
    if node is None:
        return (None, tree.header)
    last = None
    went_left = False
    while node is not None:
        last = node
        if key < node.key:
            went_left = True
            node = node.left
        else:
            went_left = False
            node = node.right
    if not went_left:
        # Bytes: (last, 0) when sought <= last key, else (0, last).
        if key <= last.key:
            return (last, None)
        return (None, last)
    # Walk ended going left: sought < last key.
    if last is tree.leftmost:
        return (None, last)
    pred = decrement(tree, last)
    # Bytes: (pred, 0) when sought <= pred key, else (0, last).
    if key <= pred.key:
        return (pred, None)
    return (None, last)


def get_insert_hint_unique_pos(tree, hint, key):
    """The 0x514c8f0 routine.  hint may be tree.header (end)."""
    if hint is tree.header:
        if tree.root is not None and key > tree.rightmost.key:
            return (None, tree.rightmost)
        return get_insert_unique_pos(tree, key)
    if key < hint.key:
        if hint is tree.leftmost:
            return (hint, hint)
        pred = decrement(tree, hint)
        if pred.key >= key:
            return get_insert_unique_pos(tree, key)
        if pred.right is not None:
            return (hint, hint)
        return (None, pred)
    if key == hint.key:
        return (hint, None)
    # key > hint.key
    if hint is tree.rightmost:
        return (None, hint)
    succ = increment(tree, hint)
    if succ.key <= key:
        return get_insert_unique_pos(tree, key)
    if hint.right is not None:
        return (succ, succ)
    return (None, hint)


def consumer_decision(tree, hint, key):
    """What the two insert consumers do with the returned pair.

    Returns ("hit", existing_node) when the returned second is None
    (the fresh node is freed), else ("insert", insert_left) where
    insert_left follows the consumers' rule: 1 when the returned first
    is non-null, else 1 when the returned second is the header, else
    (sought key < returned second's key).
    """
    first, second = get_insert_hint_unique_pos(tree, hint, key)
    if second is None:
        return ("hit", first)
    if first is not None:
        return ("insert", True)
    if second is tree.header:
        return ("insert", True)
    return ("insert", key < second.key)
