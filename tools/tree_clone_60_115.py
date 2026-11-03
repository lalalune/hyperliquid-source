"""Python model of the node #115 0x60-byte two-string tree clone
at 0x5d4d050 (RE-001 work item RE-001-tree-clone-60-115).

The binary routine takes a source node pointer and a link value and
returns a fresh root node. It clones the source node and its whole
+0x10 sibling chain: one fresh 0x60-byte node per source node, both
strings rebuilt through the 0x5d4a6a0 builder (referenced from open
PR #2409, modelled here as a content copy), the tag dword copied,
and each node's child subtree cloned the same way, with the new
node as the child's link argument. The source tree is never modified
and no source node is destroyed.

Node fields modelled: tag dword (+0x00), link (+0x08), next (+0x10),
first child (+0x18), string A (+0x20 object), string B (+0x40
object). The qword at +0x58 is never read or written by the
routine and is not modelled.

Cycle and null guards: the binary recurses unchecked on a cyclic
child chain, loops forever on a cyclic sibling chain, and
dereferences a null source pointer unchecked. The model raises
ValueError in those cases instead; this is a stated guard, not a
claim about the binary's behaviour there.
"""

__all__ = ["TreeNode", "clone_tree", "node_count", "preorder_tags"]


class TreeNode:
    """One 0x60-byte two-string tree node."""

    def __init__(self, tag, link=None, string_a="", string_b=""):
        self.tag = tag
        self.link = link
        self.next = None
        self.child = None
        self.string_a = string_a
        self.string_b = string_b

    def __repr__(self):
        return "TreeNode(tag=%r, a=%r, b=%r)" % (
            self.tag, self.string_a, self.string_b)


def _clone_chain(first_src, first_link, ancestors):
    """Clone first_src and its whole +0x10 sibling chain.

    The first new node's link is first_link; each later sibling's
    link is the previous new sibling, and the previous new
    sibling's next pointer is set to it. Each node's child subtree
    is cloned the same way, with the new node as its link.
    Ancestors are the source nodes above the current chain; seeing
    one again means a cycle, which the model refuses.
    """
    head = None
    prev_new = None
    link = first_link
    src = first_src
    seen = set()
    while src is not None:
        if id(src) in seen or id(src) in ancestors:
            raise ValueError("cyclic tree structure")
        seen.add(id(src))
        new = TreeNode(src.tag, link=link,
                       string_a=src.string_a, string_b=src.string_b)
        if prev_new is not None:
            prev_new.next = new
        else:
            head = new
        if src.child is not None:
            new.child = _clone_chain(src.child, first_link=new,
                                     ancestors=ancestors | {id(src)})
        prev_new = new
        link = new
        src = src.next
    return head


def clone_tree(src, link=None):
    """Clone the tree rooted at src; link is the root's +0x08.

    The returned root heads the cloned +0x10 chain, exactly as the
    binary returns the fresh root of the cloned chain.
    """
    if src is None:
        raise ValueError("clone called on a null source node")
    return _clone_chain(src, link, frozenset())


def node_count(root):
    """Count nodes in a tree (child subtrees plus sibling chains)."""
    if root is None:
        return 0
    total = 1
    if root.child is not None:
        total += node_count(root.child)
    if root.next is not None:
        total += node_count(root.next)
    return total


def preorder_tags(root):
    """Tags in pre-order: node, child subtree, then next siblings."""
    if root is None:
        return []
    tags = [root.tag]
    if root.child is not None:
        tags.extend(preorder_tags(root.child))
    if root.next is not None:
        tags.extend(preorder_tags(root.next))
    return tags
