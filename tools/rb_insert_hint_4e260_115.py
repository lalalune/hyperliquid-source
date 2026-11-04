"""Model of node #115 RB-tree unique-insert position search,
0x5d4e260 (hinted) with its unhinted fallback 0x5d49910 (RE-001).

The routines operate on a libstdc++-layout red-black tree whose key
is a single byte stored at node offset +0x20 (the first payload
byte after the 32-byte node base: color +0x00, parent +0x08, left
+0x10, right +0x18). The tree object holds its header node at
+0x08, so the header's parent slot (tree +0x10) is the root, its
left slot (tree +0x18) is the leftmost node, its right slot
(tree +0x20) is the rightmost node, and the node count lives at
tree +0x28. The header node itself stands in for the end iterator.

Pinned return convention (see
research/work-items/RE-001-rb-insert-hint-4e260-115/):

- (node, None): the key is already present; node is the existing
  node. The binary's only observed consumer tests the second slot
  for null and takes its duplicate path in exactly this case.
- (None, parent): the key is absent; insert it as a child of
  parent (left child when the key is below parent, right child
  when above -- the descent that produced the parent decides).
- (node, node): returned only by the hinted routine when the hint
  already brackets the key tightly (hint == leftmost with a smaller
  key, or the predecessor/successor sits in the hint's own child
  slot). The pair is reproduced exactly; how a caller consumes a
  doubled pair is not pinned by this packet, and the model does
  not guess at it.

The increment/decrement steps are the libstdc++ in-order
successor/predecessor walks the binary calls through the PLT
(_ZSt18_Rb_tree_increment / _ZSt18_Rb_tree_decrement); their
bodies are not in these excerpts, only their call sites and the
branch outcomes that depend on them. The model implements the
standard walks and never calls them on the header sentinel, just
as the binary never does on the paths that reach them.
"""

HEADER = "header"


class Node:
    """One tree node: a u8 key plus BST links."""

    def __init__(self, key):
        if not 0 <= key <= 0xFF:
            raise ValueError("key must be a single byte")
        self.key = key
        self.parent = None
        self.left = None
        self.right = None

    def __repr__(self):
        return f"Node({self.key})"


class Tree:
    """A tree object with a header sentinel standing in for end."""

    def __init__(self):
        # The header is a distinct object, never a real node.
        self.header = Node(0)
        self.header.is_header = True
        self.root = None
        self.count = 0

    @property
    def leftmost(self):
        node = self.root
        if node is None:
            return self.header
        while node.left is not None:
            node = node.left
        return node

    @property
    def rightmost(self):
        node = self.root
        if node is None:
            return self.header
        while node.right is not None:
            node = node.right
        return node


def increment(node):
    """In-order successor of a real node (never the header here)."""
    if node.right is not None:
        node = node.right
        while node.left is not None:
            node = node.left
        return node
    parent = node.parent
    while parent is not None and node is parent.right:
        node = parent
        parent = parent.parent
    if parent is None:
        raise ValueError("successor of the rightmost node is end")
    return parent


def decrement(node):
    """In-order predecessor of a real node (never the header here)."""
    if node.left is not None:
        node = node.left
        while node.right is not None:
            node = node.right
        return node
    parent = node.parent
    while parent is not None and node is parent.left:
        node = parent
        parent = parent.parent
    if parent is None:
        raise ValueError("predecessor of the leftmost node is end")
    return parent


def get_insert_unique_pos(tree, key):
    """Unhinted search 0x5d49910: the plain tree descent."""
    x = tree.root
    y = tree.header
    comp = True  # went-left on the last step; True before any step
    while x is not None:
        y = x
        comp = key < x.key
        x = x.left if comp else x.right
    if comp:
        if y is tree.leftmost:
            return (None, y)
        j = decrement(y)
    else:
        j = y
    if j.key < key:
        return (None, y)
    return (j, None)


def get_insert_hint_unique_pos(tree, hint, key):
    """Hinted search 0x5d4e260; hint is a node or tree.header (end)."""
    if hint is tree.header:
        if tree.count > 0 and tree.rightmost.key < key:
            return (None, tree.rightmost)
        # The hinted routine inlines this same descent here; the
        # model delegates to the unhinted routine, which the binary
        # also reaches by tail jump on the other fallback paths.
        return get_insert_unique_pos(tree, key)
    if key < hint.key:
        if hint is tree.leftmost:
            return (hint, hint)
        before = decrement(hint)
        if before.key < key:
            if before.right is None:
                return (None, before)
            return (hint, hint)
        return get_insert_unique_pos(tree, key)
    if hint.key < key:
        if hint is tree.rightmost:
            return (None, tree.rightmost)
        after = increment(hint)
        if key < after.key:
            if hint.right is None:
                return (None, hint)
            return (after, after)
        return get_insert_unique_pos(tree, key)
    return (hint, None)
