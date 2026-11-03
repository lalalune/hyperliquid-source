"""Model of node #115 routine 0x5d4d890: teardown of a sibling chain
of 0x48-byte tree nodes, each carrying one string field.

Node layout (offsets the routine actually reads; everything else is
recorded as never read, not modelled):
  +0x10  next sibling (or 0)
  +0x18  first child (or 0)
  +0x28  string pointer
  +0x38  string capacity-or-inline slot: the string is inline exactly
         when its pointer equals the address of its own +0x38 slot;
         a heap string is freed as delete(pointer, capacity + 1).
The routine never reads +0x00, +0x08, +0x20 or the string size slot
(+0x30); the model therefore does not use them either.

Net behaviour (the binary unrolls the first six child-chain levels
inline and recurses for deeper levels; the observable order is
identical either way): a null head destroys nothing. Otherwise, for
each node in the +0x10 chain in order: destroy that node's whole
+0x18 child chain first, then dispose the node's string, then delete
the node with size 0x48, and advance to the +0x10 successor that was
loaded before the deletes. Net order is post-order: children before
their parent, siblings in chain order, each node exactly once on a
well-formed tree.

The model raises on a cyclic structure, where the binary would loop
forever; that guard is a model safety property, not a binary claim.
"""

_DELETED_SIZE = 0x48


class StringField:
    """One string triple as the routine sees it.

    ``data`` is the string bytes. ``inline`` selects the inline case
    (pointer equals the node's own +0x38 slot address). ``capacity``
    is meaningful only for heap strings and is the value the binary
    reads from +0x38 when freeing.
    """

    def __init__(self, data=b"", inline=True, capacity=None):
        self.data = bytes(data)
        if inline:
            self.inline = True
            self.capacity = None
        else:
            if capacity is None or capacity < len(self.data):
                raise ValueError("heap string needs capacity >= length")
            self.inline = False
            self.capacity = capacity

    def dispose_size(self):
        """Delete size for the heap case, or None for inline."""
        if self.inline:
            return None
        return self.capacity + 1


class Node:
    """One 0x48-byte tree node. ``name`` is a test label only."""

    def __init__(self, name, string=None, child=None, next_=None):
        self.name = name
        self.string = string if string is not None else StringField()
        self.child = child
        self.next = next_


def destroy_chain(head):
    """Destroy the sibling chain starting at ``head``.

    Returns a list of events in destruction order:
    ("string", node name, delete size or None) for each disposed
    string, followed by ("node", node name, 0x48) for the node
    delete itself -- the string event always precedes its node event,
    matching the binary's per-node sequence.
    """
    events = []
    seen = set()

    def destroy(node):
        while node is not None:
            if id(node) in seen:
                raise ValueError("cyclic tree: node %r revisited" % node.name)
            seen.add(id(node))
            nxt = node.next  # loaded before any delete, as in binary
            destroy(node.child)
            events.append(("string", node.name, node.string.dispose_size()))
            events.append(("node", node.name, _DELETED_SIZE))
            node = nxt

    destroy(head)
    return events


def node_order(head):
    """Just the node-delete order for a chain."""
    return [name for kind, name, _size in destroy_chain(head)
            if kind == "node"]
