"""Python model of node #115's recursive tree teardown 0x5f53f50.

Implements the semantics pinned by
research/work-items/RE-001-recursive-teardown-115: teardown(chain)
walks the +0x10 sibling chain from chain; for each node it first
tears down the chain at node +0x18, then records the operator delete
of the node itself with size 0x30. The binary unrolls the first-child
descent through eight levels before a true recursive self-call, but
the observable delete order is identical to this direct recursive
formulation, which is what the model implements.

A node is a dict with keys:

- "next": the id of the next sibling (+0x10), or None
- "child": the id of the head of the child chain (+0x18), or None

Nodes live in a mapping from id to node dict. ``teardown`` returns
the list of deleted ids in execution order. A null head deletes
nothing, matching the binary's entry null check.

Model-side guards (not binary behavior, stated explicitly): the
binary has no cycle check and would loop on a cyclic chain, and it
would fault on a dangling pointer. The model raises ValueError on a
revisited node or an unknown id so the Python model always
terminates; tests pin both guards.
"""


def teardown(head, nodes):
    """Delete the tree rooted at the chain ``head``; return delete order."""
    order = []
    seen = set()

    def walk(chain):
        node = chain
        while node is not None:
            if node in seen:
                raise ValueError("cycle: node %r visited twice" % (node,))
            if node not in nodes:
                raise ValueError("unknown node %r" % (node,))
            seen.add(node)
            entry = nodes[node]
            child = entry["child"]
            nxt = entry["next"]
            # Child and next are read before the delete, as in the binary.
            if child is not None:
                walk(child)
            order.append(node)
            node = nxt

    walk(head)
    return order
