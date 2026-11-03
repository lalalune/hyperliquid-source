"""Model of the node #115 0x58-byte tree teardown at 0x5d4d250.

The routine destroys a whole sibling chain of 0x58-byte nodes.
Each node carries three fields this routine reads:

* ``next`` -- the +0x10 successor in the same sibling chain,
* ``child`` -- the +0x18 first child (head of the child chain),
* ``nested`` -- the +0x38 pointer to a 0x48-byte tree root, torn
  down by the 0x5d4cba0 teardown (open PR #2453's component,
  referenced here, not re-claimed), or None.

Fields the routine never reads (+0x00, +0x08, +0x40..+0x57)
carry no semantics in this model.

Observable order, per node, in chain order: destroy the node's
whole child chain first, then tear down its nested tree, then
delete the node itself with size 0x58. The binary unrolls the
first six child-chain levels inline and recurses (site
0x5d4d2e8) for deeper levels; the observable order is the same
post-order either way, so the model is a plain recursion. A null
head destroys nothing. The binary has no cycle guard; the model
raises on a revisited node instead of looping, and cyclic
behavior is not claimed.
"""

_NODE_SIZE = 0x58


class Node58:
    """One 0x58-byte tree node in the model."""

    def __init__(self, name, child=None, next=None, nested=None):
        self.name = name
        self.child = child
        self.next = next
        self.nested = nested


def destroy(head, events=None):
    """Destroy the sibling chain starting at ``head``.

    Appends (``"nested"``, name) when a node's nested tree is
    torn down and (``"delete"``, name, 0x58) when a node is
    deleted, in the binary's observable order. Returns the
    event list. Raises ValueError on a revisited node.
    """
    if events is None:
        events = []
    seen = set()
    _destroy_chain(head, events, seen)
    return events


def _destroy_chain(head, events, seen):
    node = head
    while node is not None:
        if id(node) in seen:
            raise ValueError("cycle: node %r revisited" % (node.name,))
        seen.add(id(node))
        _destroy_chain(node.child, events, seen)
        if node.nested is not None:
            events.append(("nested", node.name))
        events.append(("delete", node.name, _NODE_SIZE))
        node = node.next
