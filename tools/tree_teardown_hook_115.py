"""Model of node #115 routine 0x5d4d560: teardown of a sibling chain
of 0x48-byte tree nodes, each carrying a per-node destroy hook.

Node layout (offsets the routine actually reads; everything else is
recorded as never read, not modelled):
  +0x10  next sibling (or 0)
  +0x18  first child (or 0)
  +0x28  member field: never dereferenced as data by this routine;
         only its address is passed to the hook
  +0x38  destroy-hook function pointer (or 0 for no hook): when
         non-null it is called as hook(member, member, 3), where both
         pointer arguments are the address of the node's +0x28 field
         and 3 is the constant third argument the binary passes.
The routine never reads +0x00, +0x08, +0x20, +0x30 or +0x40..+0x47;
the model therefore does not use them either.

Net behaviour (the binary unrolls the first eight child links inline
and recurses for deeper levels; the observable order is identical
either way): a null head destroys nothing. Otherwise, for each node
in the +0x10 chain in order: destroy that node's whole +0x18 child
chain first, then invoke the node's hook when its +0x38 slot is
non-null, then delete the node with size 0x48, and advance to the
+0x10 successor that was loaded before the hook call and the delete.
Net order is post-order: children before their parent, siblings in
chain order, each node exactly once on a well-formed tree, with each
hook invoked after its children are destroyed and before its own
node delete.

What the hook does internally is not modelled: in the model it is a
per-node callable, and the events record its exact invocation
arguments. The model raises on a cyclic structure, where the binary
would loop forever; that guard is a model safety property, not a
binary claim.
"""

_DELETED_SIZE = 0x48
_HOOK_THIRD_ARG = 3


class Node:
    """One 0x48-byte tree node. ``name`` is a test label only.

    ``hook`` is None for a null +0x38 slot, or a callable taking
    (member, member, 3). The model passes the node itself as the
    member token twice, standing in for the address of its +0x28
    field, which is the same value in both argument positions.
    """

    def __init__(self, name, hook=None, child=None, next_=None):
        self.name = name
        self.hook = hook
        self.child = child
        self.next = next_


def destroy_chain(head):
    """Destroy the sibling chain starting at ``head``.

    Returns a list of events in destruction order: ("hook", node
    name, third argument) for each invoked hook, followed by
    ("node", node name, 0x48) for the node delete itself -- the hook
    event always precedes its node event, matching the binary's
    per-node sequence. Nodes with a null hook slot produce no hook
    event.
    """
    events = []
    seen = set()

    def destroy(node):
        while node is not None:
            if id(node) in seen:
                raise ValueError("cyclic tree: node %r revisited" % node.name)
            seen.add(id(node))
            nxt = node.next  # loaded before hook call and delete
            destroy(node.child)
            if node.hook is not None:
                node.hook(node, node, _HOOK_THIRD_ARG)
                events.append(("hook", node.name, _HOOK_THIRD_ARG))
            events.append(("node", node.name, _DELETED_SIZE))
            node = nxt

    destroy(head)
    return events


def node_order(head):
    """Just the node-delete order for a chain."""
    return [name for kind, name, _size in destroy_chain(head)
            if kind == "node"]
