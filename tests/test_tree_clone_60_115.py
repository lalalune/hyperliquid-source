"""Tests for the node #115 0x60-byte tree clone model
(tools/tree_clone_60_115.py, RE-001 work item
RE-001-tree-clone-60-115). Each check counts; the run prints
"<n> checks pass" on success.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tree_clone_60_115 import (TreeNode, clone_tree, node_count,
                               preorder_tags)

CHECKS = [0]


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


def main():
    # Single node: fields, link argument, fresh identity.
    src = TreeNode(7, string_a="alpha", string_b="beta")
    out = clone_tree(src, link="owner")
    check(out is not src, "clone is a fresh node")
    check(out.tag == 7, "tag copied")
    check(out.string_a == "alpha" and out.string_b == "beta",
          "both strings copied")
    check(out.link == "owner", "root link is the link argument")
    check(out.next is None and out.child is None,
          "single node has no next or child")
    check(node_count(out) == 1, "single node count")

    # Root with one child: child link is the new parent.
    src = TreeNode(1, string_a="r", string_b="R")
    src.child = TreeNode(2, string_a="c", string_b="C")
    out = clone_tree(src)
    check(out.child is not None, "child cloned")
    check(out.child is not src.child, "child is fresh")
    check(out.child.link is out, "child link is the new parent")
    check(out.child.tag == 2, "child tag copied")
    check(out.child.string_a == "c", "child string A copied")
    check(out.next is None, "root next stays None without siblings")

    # Root with three siblings: chain order and link rules.
    root = TreeNode(10, string_a="a0", string_b="b0")
    s1 = TreeNode(11, string_a="a1", string_b="b1")
    s2 = TreeNode(12, string_a="a2", string_b="b2")
    root.next = s1
    s1.next = s2
    out = clone_tree(root)
    check(preorder_tags(out) == [10, 11, 12], "sibling order kept")
    check(out.next is not None and out.next.next is not None,
          "sibling chain cloned")
    check(out.next.link is out, "first sibling link is the root")
    check(out.next.next.link is out.next,
          "second sibling link is the previous new sibling")
    check(node_count(out) == 3, "sibling count kept")
    check(out.next.string_b == "b1", "sibling string B copied")

    # Mixed tree: child subtree with siblings, one with its own child.
    root = TreeNode(20)
    child = TreeNode(21)
    child_sib = TreeNode(22)
    grandchild = TreeNode(23)
    child.next = child_sib
    child_sib.child = grandchild
    root.child = child
    root.next = TreeNode(24)
    out = clone_tree(root)
    check(preorder_tags(out) == [20, 21, 22, 23, 24],
          "mixed tree pre-order kept")
    check(node_count(out) == 5, "mixed tree count kept")
    check(out.child.link is out, "child link is the new root")
    check(out.child.next.link is out.child,
          "child sibling link is the previous new sibling")
    check(out.child.next.child.link is out.child.next,
          "grandchild link is its new parent")
    check(out.next.link is out, "root sibling link is the root")

    # Strings: empty, one-byte, and long content all copy by value.
    src = TreeNode(30, string_a="", string_b="x" * 40)
    out = clone_tree(src)
    check(out.string_a == "" and out.string_b == "x" * 40,
          "empty and long strings copied")
    out.string_a = "changed"
    check(src.string_a == "", "no sharing with the source strings")

    # No sharing anywhere: mutating the clone leaves the source alone.
    src = TreeNode(40, string_a="s", string_b="t")
    src.child = TreeNode(41, string_a="u", string_b="v")
    out = clone_tree(src)
    out.child.string_b = "mutated"
    out.tag = 999
    check(src.child.string_b == "v", "source child string untouched")
    check(src.tag == 40, "source tag untouched")
    check(out.child is not src.child, "child nodes are distinct")

    # Guards: null source, child cycle, sibling cycle all raise.
    try:
        clone_tree(None)
    except ValueError:
        check(True, "null source raises")
    else:
        check(False, "null source raises")
    cyclic = TreeNode(50)
    cyclic.child = cyclic
    try:
        clone_tree(cyclic)
    except ValueError:
        check(True, "child cycle raises")
    else:
        check(False, "child cycle raises")
    loop = TreeNode(60)
    loop.next = loop
    try:
        clone_tree(loop)
    except ValueError:
        check(True, "sibling cycle raises")
    else:
        check(False, "sibling cycle raises")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
