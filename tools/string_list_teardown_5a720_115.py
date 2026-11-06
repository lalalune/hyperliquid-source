#!/usr/bin/env python3
"""Model of node #115 routine 0x5d5a720 (FDE 0x5d5a720..0x5d5a7e5).

String-list teardown:

1. List phase. The head pointer lives at holder+0x10. A null head
   skips the loop outright. Otherwise each 0x68-byte node runs,
   in order: (a) dispose the string at node+0x30 (capacity at
   node+0x40) under the short-form rule — a pointer equal to
   node+0x40 frees nothing, else a sized delete of (pointer,
   capacity + 1); (b) dispose the string at node+0x10 (capacity
   at node+0x20) under the same rule; (c) free the node itself
   with a sized delete of exactly 0x68. The next pointer at
   node+0x00 is loaded before any of the frees, and the loop
   follows it until null. All frees go through the _ZdlPvm PLT
   at 0x63f0d80.
2. Buffer phase (always runs, even when the list is empty). The
   buffer span (begin at holder+0x00, count at holder+0x08) is
   cleared with memset (begin, 0, count * 8) through the memset
   PLT at 0x63f0a90; holder+0x10 and holder+0x18 are zeroed;
   then, unless begin equals holder+0x30, the buffer span is
   freed with a sized delete of (begin, count * 8), tail-jumped.
   The holder itself is never freed.

Inputs are abstract: a node is {"a": string, "b": string} where
a string is {"inline": bool, "capacity": int}; begin is None
(null), "inline" (begin == holder+0x30), or "heap". A null begin
is modelled only with count 0, matching the only case the code
can reach without passing a null pointer to memset with a
nonzero size.
"""

DELETE_PLT = 0x63F0D80
MEMSET_PLT = 0x63F0A90
NODE_SIZE = 0x68


def dispose_string(string):
    """Sized-delete size for one string, or None when short-form.

    string: {"inline": bool, "capacity": int}. Short form (the
    pointer equals its own capacity slot) frees nothing.
    """
    if string["inline"]:
        return None
    return string["capacity"] + 1


def destroy_node(node):
    """Ordered ops for one 0x68-byte list node.

    node: {"a": string, "b": string}. String A (node+0x30) is
    disposed before string B (node+0x10); the node free follows.
    """
    ops = []
    size = dispose_string(node["a"])
    if size is not None:
        ops.append(("free_string", "a", size))
    size = dispose_string(node["b"])
    if size is not None:
        ops.append(("free_string", "b", size))
    ops.append(("free_node", NODE_SIZE))
    return ops


def destroy_holder(nodes, begin, count):
    """Ordered ops for one holder teardown.

    nodes: list of nodes in list order (empty when head is null).
    begin: None (null begin, count must be 0), "inline"
    (begin == holder+0x30, no buffer free) or "heap" (buffer
    freed). count: the element count at holder+0x08.
    """
    if begin is None and count != 0:
        raise ValueError("null begin with nonzero count is not modelled")
    ops = []
    for node in nodes:
        ops.extend(destroy_node(node))
    ops.append(("memset_buffer", count * 8))
    ops.append(("zero_fields", ["+0x10", "+0x18"]))
    if begin in ("heap", None):
        # A null begin still reaches the tail-jump delete with
        # size count * 8 (0 in the only modelled case).
        ops.append(("free_buffer", count * 8))
    return ops


def empty_node():
    return {"a": {"inline": True, "capacity": 0},
            "b": {"inline": True, "capacity": 0}}
