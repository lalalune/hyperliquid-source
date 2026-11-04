"""Python model of node #115's recursive list-tree teardown at 0x5d4c8d0.

RE-001 work item: research/work-items/RE-001-list-tree-teardown-115/.
The routine takes one list head in rdi and returns void. Each node
is 0x30 bytes with two pointers the routine reads: +0x10 (next
sibling) and +0x18 (child list head). Nothing else in a node is
read, and nothing is written by the routine itself: every effect
is a call to operator delete (PLT 0x63f0d80, ``_ZdlPvm``) with
``(node, 0x30)``.

Destruction order, stated literally: for a list head, walk the
+0x10 chain in order; for each node, first destroy the whole
list at its +0x18 (each element of that list in the same
post-order), then delete the node itself, then move to the
node's +0x10 successor (loaded before the delete, so the chain
survives the free). A null head returns at once with no delete.
The binary inlines this loop for the first eight child levels
and recurses into itself (site 0x5d4c961) once the +0x18 chain
runs deeper than that; the recursion is an implementation
detail of the same order, not a different rule.

A node dict must carry both ``next`` and ``child``; a missing
node, a missing field, a node revisited while it is still being
destroyed (a cycle), or a node deleted twice raises ValueError
instead of being silently modelled.
"""

MASK64 = (1 << 64) - 1


def _require(mapping, key):
    if not isinstance(mapping, dict) or key not in mapping:
        raise ValueError("missing field %r" % (key,))
    return mapping[key]


def destroy_list(head, nodes, _active=None, _deleted=None, _deletes=None):
    """Destroy the +0x10 list headed by ``head``.

    ``nodes`` maps a node address to ``{"next": ..., "child": ...}``.
    Returns the ordered list of ``(node_address, 0x30)`` deletes.
    """
    if _active is None:
        _active = set()
        _deleted = set()
        _deletes = []
    head = head & MASK64
    node_addr = head
    while node_addr != 0:
        if node_addr in _active:
            raise ValueError("list-tree cycle through %#x" % node_addr)
        if node_addr in _deleted:
            raise ValueError("list-tree revisits deleted %#x" % node_addr)
        node = _require(nodes, node_addr)
        nxt = _require(node, "next") & MASK64
        child = _require(node, "child") & MASK64
        _active.add(node_addr)
        destroy_list(child, nodes, _active, _deleted, _deletes)
        _active.discard(node_addr)
        _deletes.append((node_addr, 0x30))
        _deleted.add(node_addr)
        node_addr = nxt
    return _deletes
