#!/usr/bin/env python3
"""Model of node #115 routine 0x5d5a940 (FDE 0x5d5a940..0x5d5a9c7).

Node-list teardown:

1. List phase. The head pointer lives at holder+0x10. A null head
   skips the loop outright. Otherwise each 0x38-byte node runs
   with no payload disposed: the next pointer at node+0x00 is
   loaded before the free, then the node itself is freed with a
   sized delete of exactly 0x38 through the _ZdlPvm PLT at
   0x63f0d80, and the loop follows the loaded next pointer until
   null. Node fields other than +0x00 are never read.
2. Buffer phase (always runs, even when the list is empty). The
   buffer span (begin at holder+0x00, count at holder+0x08) is
   cleared with memset (begin, 0, count * 8) through the memset
   PLT at 0x63f0a90; holder+0x10 and holder+0x18 are zeroed;
   then, unless begin equals holder+0x30, the buffer span is
   freed with a sized delete of (begin, count * 8), tail-jumped
   through the same _ZdlPvm PLT. The holder itself is never
   freed.

Inputs are abstract: nodes is a list with one entry per list
node (contents unused, since no payload is read); begin is None
(null), "inline" (begin == holder+0x30, no buffer free) or
"heap" (buffer freed). A null begin is modelled only with count
0, matching the only case the code can reach without passing a
null pointer to memset with a nonzero size.
"""

DELETE_PLT = 0x63F0D80
MEMSET_PLT = 0x63F0A90
NODE_SIZE = 0x38


def destroy_node():
    """Ordered ops for one 0x38-byte list node: just the node free."""
    return [("free_node", NODE_SIZE)]


def destroy_holder(nodes, begin, count):
    """Ordered ops for one holder teardown.

    nodes: list with one entry per node in list order (empty when
    head is null). begin: None (null begin, count must be 0),
    "inline" (begin == holder+0x30, no buffer free) or "heap"
    (buffer freed). count: the element count at holder+0x08.
    """
    if begin is None and count != 0:
        raise ValueError("null begin with nonzero count is not modelled")
    ops = []
    for _node in nodes:
        ops.extend(destroy_node())
    ops.append(("memset_buffer", count * 8))
    ops.append(("zero_fields", ["+0x10", "+0x18"]))
    if begin in ("heap", None):
        # A null begin still reaches the tail-jump delete with
        # size count * 8 (0 in the only modelled case).
        ops.append(("free_buffer", count * 8))
    return ops
