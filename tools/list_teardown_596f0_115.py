#!/usr/bin/env python3
"""Model of node #115 routine 0x5d596f0 (FDE 0x5d596f0..0x5d59777).

List teardown followed by a buffer clear:

1. The list head lives at holder+0x10. A null head skips the loop.
   Otherwise the loop walks the chain head to tail: the next
   pointer at node+0x00 is loaded before each free, then the node
   is freed with a sized delete of exactly 0x18 through the
   _ZdlPvm PLT at 0x63f0d80. No per-node payload is disposed.
2. Buffer phase: the count from holder+0x08 and the begin from
   holder+0x00 are loaded, and the buffer is cleared with
   memset(begin, 0, count * 8) through the memset PLT at
   0x63f0a90. The begin and count are reloaded, and the qwords
   at holder+0x10 and holder+0x18 are zeroed.
3. Exit: when the reloaded begin equals holder+0x30 the routine
   returns plainly; otherwise it tail-jumps to the sized-delete
   PLT freeing (begin, count * 8). The begin slot (+0x00) and
   the count slot (+0x08) are not cleared in either path, the
   holder itself is never freed, and no canary check is performed.

Preconditions (matching the binary's assumptions): the list is a
well-formed null-terminated chain, and the count matches the
buffer when the begin is non-inline.
"""

NODE_SIZE = 0x18


def list_teardown(holder):
    """holder: {"nodes": int (chain length),
    "count": int (buffer element count),
    "buffer_inline": bool (begin == holder+0x30)}.
    Returns the ordered op list."""
    ops = []
    for _ in range(holder["nodes"]):
        ops.append(("free_node", NODE_SIZE))
    ops.append(("memset_buffer", holder["count"] * 8))
    ops.append(("clear_list_slots",))
    if not holder["buffer_inline"]:
        ops.append(("free_buffer", holder["count"] * 8))
    return ops
