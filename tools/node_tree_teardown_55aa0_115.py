"""Python model of node #115 routine 0x5d55aa0 (RE-001 work item).

The routine destroys a structure of 0x38-byte nodes reachable from a
root through two links: +0x18 (down: the subtree destroyed before
the node itself) and +0x10 (next: the sibling followed after the
node itself is destroyed). Each node carries a refcounted payload
at +0x30, released through the shared helper 0x5d350c0 when
non-null and skipped when null.

The model follows the disassembly literally: a null root returns
immediately; for each node in the +0x10 chain starting at the root,
the +0x18 subtree is destroyed first, then the node's payload is
released (when non-null), then the node itself is sized-deleted
with size 0x38, then the chain moves to the next +0x10 node. The
binary unrolls the first levels of the +0x18 descent inline and
uses its single self-recursive call at 0x5d55b40 for deeper chains;
the observable event order is the post-order above regardless of
unrolling. The routine keeps no visited set, so the model assumes
the links form a tree (each node reached exactly once), as recorded
in the packet.

Arguments (System V): rdi = root node.

Per-node teardown, in order:
  release [node +0x30] through 0x5d350c0 when non-null
  sized delete of the node itself with size 0x38 via _ZdlPvm
"""

NODE_SIZE = 0x38
RELEASE_HELPER = 0x5D350C0


class Node:
    """One 0x38-byte node: down (+0x18), next (+0x10), payload (+0x30)."""

    def __init__(self, payload=None, down=None, next=None):
        self.payload = payload
        self.down = down
        self.next = next


def destroy(root, emit):
    """Destroy the structure rooted at root, emitting events in order.

    emit receives ("release", payload) for each non-null payload and
    ("free", node, 0x38) for each node, in the routine's post-order.
    A null root emits nothing.
    """
    node = root
    while node is not None:
        if node.down is not None:
            destroy(node.down, emit)
        if node.payload is not None:
            emit(("release", node.payload))
        emit(("free", node, NODE_SIZE))
        node = node.next
