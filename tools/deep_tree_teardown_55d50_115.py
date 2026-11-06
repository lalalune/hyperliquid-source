"""Python model of the RE-001 deep tree teardown routine 0x5d55d50 (node #115).

Models only the established semantics from
research/work-items/RE-001-deep-tree-teardown-55d50-115/:
a 0x50-byte node whose +0x18 field is the first child, whose +0x10 field
is the next sibling, whose +0x48 field is a refcounted pointer released
through the shared helper 0x5d350c0, and whose +0x20 field is a
libstdc++ string whose heap buffer (when not stored inline) is freed
with size capacity + 1. The binary unrolls the first eight descent
levels and then calls itself for deeper levels; that unrolling is an
implementation detail and is not modelled, because the observable
disposal order is the same recursive post-order at every depth.
"""

NODE_SIZE = 0x50


class Ref:
    """A refcounted pointer target; owners counts owning references."""

    def __init__(self, name, owners=0):
        self.name = name
        self.owners = owners
        self.destroyed = False

    def __repr__(self):
        return f"Ref({self.name!r}, owners={self.owners})"


def release(ref, events):
    """Shared release helper 0x5d350c0, simplified: decrement, destroy at zero."""
    if ref is None:
        return
    ref.owners -= 1
    events.append(("release", ref.name))
    if ref.owners == 0:
        ref.destroyed = True
        events.append(("destroy", ref.name))


class Node:
    """One 0x50-byte tree node.

    down: first child (+0x18); next: next sibling (+0x10);
    ref: refcounted pointer at +0x48 (or None); heap_string: True when
    the +0x20 string's buffer is heap-allocated rather than inline;
    capacity: the string's allocated capacity when heap_string is True.
    """

    def __init__(self, name, down=None, next=None, ref=None,
                 heap_string=False, capacity=0):
        self.name = name
        self.down = down
        self.next = next
        self.ref = ref
        self.heap_string = heap_string
        self.capacity = capacity
        self.disposed = False


def dispose_node(node, events):
    """Dispose one node: release +0x48, free a heap string buffer, delete node."""
    release(node.ref, events)
    if node.heap_string:
        events.append(("delete_string", node.capacity + 1))
    events.append(("delete_node", node.name, NODE_SIZE))
    node.disposed = True


def teardown(node, events):
    """Routine 0x5d55d50: post-order teardown of a node tree.

    Children before the node, siblings in chain order, the node's own
    next sibling after the node. A null root is a no-op.
    """
    if node is None:
        return
    teardown(node.down, events)
    dispose_node(node, events)
    teardown(node.next, events)
