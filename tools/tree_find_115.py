"""Python model of the node #115 tree find at 0x5d4ec40.

The routine takes a tree header pointer (as an integer id in this
model), a key pointer and a key length, and returns the address of
the node whose key string equals the search key, or the header
sentinel (header + 0x08) when no such node exists.

Node layout, as read by the routine (other fields are never read):
  +0x10  left child (node id, or None)
  +0x18  right child (node id, or None)
  +0x20  key string pointer (modelled as the key bytes)
  +0x28  key string length

Header layout, as read by the routine:
  +0x08  sentinel value returned when nothing is found
  +0x10  root node id (or None)

The walk is a lower_bound walk with an equality recheck, transcribed
literally from the disassembly (see the work-item README for the
site-by-site trace):

  * Compare the current node key against the search key as strings:
    memcmp over the shorter length, then the signed length
    difference, saturated to the int32 range (a difference at or
    above 2**31 counts as positive; at or below -2**31 - 1 counts
    as negative).
  * Node key < search key: step to the right child (+0x18).
  * Node key >= search key: record the node as the candidate, then
    step to the left child (+0x10).
  * At a null child, recheck the candidate: return it only when
    comparing the search key against the candidate key gives a
    result >= 0 (same saturated string comparison, opposite
    orientation); otherwise return the sentinel. Combined with
    the walk invariant that every recorded candidate satisfies
    node key >= search key, the net result is exact equality:
    the returned node is returned only when its key equals the
    search key.

The model raises on a null child that is not a recorded link, on a
missing node id, and on a cyclic walk (bounded by the node count),
because the binary dereferences unchecked there and no live tree
goes there.
"""

INT32_MAX = 0x7FFFFFFF
INT32_MIN = -0x80000000


def string_compare(left, left_len, right, right_len):
    """Saturated string comparison, as the routine computes it.

    Compares the first min(left_len, right_len) bytes; on a prefix
    tie returns the signed length difference, saturated to int32:
    a difference >= 2**31 is positive, a difference <= -2**31 - 1
    is negative. The byte arguments are the stored strings; the
    length arguments are the stored lengths.
    """
    n = min(left_len, right_len)
    head = left[:n]
    other = right[:n]
    if head != other:
        return -1 if head < other else 1
    diff = left_len - right_len
    if diff >= 0x80000000:
        return 1
    if diff <= -0x80000001:
        return -1
    return diff


class Node:
    """One tree node: key bytes plus left/right child ids."""

    def __init__(self, key, left=None, right=None):
        self.key = bytes(key)
        self.left = left
        self.right = right


class Tree:
    """Header plus nodes, addressed by integer ids.

    The sentinel is header + 0x08; node ids are the model
    addresses. The header itself is never a node.
    """

    def __init__(self, header, root=None):
        self.header = header
        self.sentinel = header + 0x08
        self.root = root
        self.nodes = {}

    def add(self, node_id, node):
        self.nodes[node_id] = node


def tree_find(tree, key):
    """Return the node id whose key equals key, else the sentinel."""
    key = bytes(key)
    sentinel = tree.sentinel
    candidate = sentinel
    node_id = tree.root
    if node_id is None:
        return sentinel
    seen = set()
    while True:
        if node_id in seen:
            raise ValueError("cyclic walk at %#x" % node_id)
        seen.add(node_id)
        node = tree.nodes.get(node_id)
        if node is None:
            raise ValueError("dangling node %#x" % node_id)
        cmp = string_compare(node.key, len(node.key), key, len(key))
        if cmp < 0:
            node_id = node.right
            if node_id is None:
                break
        else:
            candidate = node_id
            node_id = node.left
            if node_id is None:
                break
    if candidate == sentinel:
        return sentinel
    cand = tree.nodes[candidate]
    check = string_compare(key, len(key), cand.key, len(cand.key))
    if check < 0:
        return sentinel
    return candidate
