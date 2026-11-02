"""Model of node #94 tree copy-assign 0x514c780 (RE-001 work item).

The function copies one ordered tree container into another.  Container
layout (offsets from the container object, as read from the bytes):

    +0x10  root pointer (None when the tree is empty)
    +0x18  leftmost node (the container header itself when empty)
    +0x20  rightmost node (the container header itself when empty)
    +0x28  node count, copied from the source container

Node layout (48 bytes, 0x30), matching research/work-items/RE-001-tree-deep-copy-94:

    +0x00  int32 value word, copied verbatim (any colour reading is
           not claimed)
    +0x08  parent pointer
    +0x10  left child
    +0x18  right child
    +0x20  payload, 16 bytes copied verbatim (key bytes at +0x20 and
           the value bytes at +0x28, matching the map::at value address
           of node + 0x28 pinned by earlier RE-001 binds)

Behaviour pinned by 0x514c780, its deep-copy callee 0x514b7e0 and its
erase callee 0x514b690 (see research/work-items/RE-001-tree-copy-assign-94):

* Self-assign (dest is src) returns immediately; nothing is copied,
  allocated or destroyed.
* Otherwise the source tree is deep-copied: every source node yields one
  destination node with the same int32 value word, the same 16 payload bytes
  and the same left/right shape.  Nodes are sourced from the destination's
  old nodes when any remain (reuse) and freshly allocated (0x30 bytes via
  operator new, as in 0x514b7e0) once the old nodes run out.
* After the copy the destination header is reset from the new tree: root
  is the new root, leftmost is the left spine's end, rightmost is the
  right spine's end, and the count is the source count.  An empty source
  leaves an empty destination (root None, both extremes the header).
* Old destination nodes that were not reused are destroyed by the erase
  loop (right subtree first, then the node itself, walking the left
  spine), which is 0x514b690 inlined in the caller.

The exact pop sequence of 0x514b7e0's node pool is transliterated in
tools/foundation_tree_deep_copy.py (research/work-items/RE-001-tree-deep-copy-94)
and is NOT re-pinned here: the pool is seeded by this function as
([rsp] = old root, [rsp+0x8] = old rightmost's left child when non-null
else old rightmost, or 0 when the destination is empty), and this model
abstracts it as a list, pinning only the order-independent observables
(shape, payloads, header fields and the allocation / reuse / destruction
counts).  See the packet README for the observations / inferences /
unknowns split.
"""

from __future__ import annotations

NODE_SIZE = 0x30
HEADER = "header"  # sentinel for "the container header itself"


class Node:
    """One tree node.  ``left`` / ``right`` / ``parent`` are Nodes or None."""

    def __init__(self, value=0, payload=b"\x00" * 16):
        if len(payload) != 16:
            raise ValueError("payload must be exactly 16 bytes")
        self.value = value & 0xFFFFFFFF
        self.payload = bytes(payload)
        self.left = None
        self.right = None
        self.parent = None

    def __repr__(self):  # pragma: no cover - debugging aid
        return "Node(value=%d, payload=%r)" % (self.value, self.payload)


class Stats:
    """Outcome counts for one copy-assign."""

    def __init__(self, allocations=0, reuses=0, destructions=0):
        self.allocations = allocations
        self.reuses = reuses
        self.destructions = destructions

    def __repr__(self):  # pragma: no cover - debugging aid
        return "Stats(allocations=%d, reuses=%d, destructions=%d)" % (
            self.allocations,
            self.reuses,
            self.destructions,
        )


class Container:
    """A tree container with the header layout above."""

    def __init__(self, root=None):
        self.root = root
        self.leftmost = HEADER
        self.rightmost = HEADER
        self.count = 0
        self.refresh_header()

    def refresh_header(self):
        """Recompute the extremes and count from the current root."""
        if self.root is None:
            self.leftmost = HEADER
            self.rightmost = HEADER
            self.count = 0
            return
        node = self.root
        while node.left is not None:
            node = node.left
        self.leftmost = node
        node = self.root
        while node.right is not None:
            node = node.right
        self.rightmost = node
        self.count = len(list(inorder(self.root)))


def inorder(node):
    """Yield the nodes of a tree in left / node / right order."""
    if node is None:
        return
    yield from inorder(node.left)
    yield node
    yield from inorder(node.right)


def leftmost(node):
    """End of the left spine, or None for an empty tree."""
    while node is not None and node.left is not None:
        node = node.left
    return node


def rightmost(node):
    """End of the right spine, or None for an empty tree."""
    while node is not None and node.right is not None:
        node = node.right
    return node


def erase_count(node):
    """Number of nodes the erase loop (0x514b690) destroys in a subtree."""
    if node is None:
        return 0
    return 1 + erase_count(node.left) + erase_count(node.right)


def _copy_tree(src_node, pool, stats, parent=None):
    """Deep-copy one subtree, sourcing nodes from ``pool`` (a list).

    ``pool.pop(0)`` models a reuse; an empty pool models a fresh
    0x30-byte operator-new allocation in 0x514b7e0.  The copy recurses
    into the right subtree before the left subtree, matching the callee's
    instruction order (right recursion at 0x514b854, left at 0x514b8d0).
    """
    if src_node is None:
        return None
    if pool:
        node = pool.pop(0)
        stats.reuses += 1
    else:
        node = Node()
        stats.allocations += 1
    node.value = src_node.value
    node.payload = src_node.payload
    node.parent = parent
    node.left = None
    node.right = None
    node.right = _copy_tree(src_node.right, pool, stats, parent=node)
    node.left = _copy_tree(src_node.left, pool, stats, parent=node)
    return node


def copy_assign(dest, src, reuse_pool=None):
    """Assign ``src`` into ``dest``; return the outcome :class:`Stats`.

    ``reuse_pool`` optionally supplies the destination's old nodes in
    reuse order; when omitted, the destination's own nodes (in inorder)
    are the pool.  The pool order is deliberately a parameter because
    the binary's exact pop order is an open unknown (see module docstring).
    """
    if dest is src:
        return Stats()
    stats = Stats()
    if reuse_pool is None:
        pool = list(inorder(dest.root))
    else:
        pool = list(reuse_pool)
    new_root = _copy_tree(src.root, pool, stats)
    stats.destructions = len(pool)
    dest.root = new_root
    if new_root is None:
        dest.leftmost = HEADER
        dest.rightmost = HEADER
        dest.count = 0
    else:
        dest.leftmost = leftmost(new_root)
        dest.rightmost = rightmost(new_root)
        dest.count = len(list(inorder(new_root)))
    return stats
