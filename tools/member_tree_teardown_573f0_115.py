"""Python model of node #115 routine 0x5d573f0 (RE-001 member-tree teardown).

The routine takes a tree root in rdi and destroys the tree post-order:
for each node in the +0x10 sibling chain, its +0x18 subtree is destroyed
first, then the node itself, then the next sibling. Each node's teardown,
in order, is: call 0x5d35c30 with node+0x40 (call-shape only), dispose
the +0x20 string, sized-delete the node with size 0x58.

The string-disposal idiom depends on the node's level inside one
invocation frame: levels 0-4 use the manual short-form check (nothing
freed when the data pointer equals node+0x30, otherwise a sized delete
of (pointer, capacity + 1)); levels 5-8 use the _M_dispose PLT. The
self-recursion at 0x5d57489 restarts the frame, so a node at absolute
depth d uses the idiom of frame level d mod 9.

Nodes are dicts: {"next": id or None, "child": id or None,
"string": (text, heap_capacity or None)} where heap_capacity None means
the string is in short form. teardown returns the operation list; the
binary keeps no visited set, so a cyclic graph raises instead of
looping (the binary would not terminate either).
"""

MEMBER_CALL = 0x5D35C30
NODE_SIZE = 0x58
FRAME_LEVELS = 9
MANUAL_LEVELS = 5


def _idiom(depth):
    """String-disposal idiom for a node at absolute depth `depth`."""
    return "manual" if (depth % FRAME_LEVELS) < MANUAL_LEVELS else "m_dispose"


def _dispose_string(node_id, string, depth):
    text, heap_cap = string
    if _idiom(depth) == "manual":
        if heap_cap is None:
            return ("dispose_string", node_id, "manual", "short")
        return ("dispose_string", node_id, "manual", "sized", heap_cap + 1)
    return ("dispose_string", node_id, "m_dispose")


def _destroy_node(node_id, node, depth, ops):
    ops.append(("member_call", node_id, MEMBER_CALL))
    ops.append(_dispose_string(node_id, node["string"], depth))
    ops.append(("free_node", node_id, NODE_SIZE))


def _destroy_chain(head_id, nodes, depth, ops, visiting):
    """Destroy a +0x10 sibling chain at absolute depth `depth`."""
    cur = head_id
    while cur is not None:
        if cur in visiting:
            raise ValueError(f"cyclic graph at node {cur!r}")
        node = nodes[cur]
        visiting.add(cur)
        if node["child"] is not None:
            _destroy_chain(node["child"], nodes, depth + 1, ops, visiting)
        _destroy_node(cur, node, depth, ops)
        visiting.discard(cur)
        cur = node["next"]


def teardown(root_id, nodes):
    """Destroy the tree rooted at `root_id`; return the operation list."""
    ops = []
    if root_id is None:
        return ops
    _destroy_chain(root_id, nodes, 0, ops, set())
    return ops
