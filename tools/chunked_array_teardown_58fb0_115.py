#!/usr/bin/env python3
"""Model of node #115 routine 0x5d58fb0 (FDE 0x5d58fb0..0x5d59015).

Chunked array teardown:

1. The holder in rdi points at an inner object: inner = [holder+0x00].
   A null inner returns plainly with nothing freed.
2. Chunk phase: the holder carries chunk-pointer slots. The cursor
   starts at [holder+0x28] and runs while it is below
   [holder+0x48] + 8 (unsigned), stepping 8, so the slot at
   [holder+0x48] itself is included. Per slot, the pointer is freed
   with a sized delete of exactly 0x200 through the _ZdlPvm PLT at
   0x63f0d80, with no null test on slot pointers.
3. Exit: the routine tail-jumps to the same PLT freeing the inner
   object at ([holder+0x00], [holder+0x08] * 8). The holder itself
   is never freed, and no canary check is performed.

Preconditions (matching the binary's assumptions): the slot range is
well-formed, and chunk pointers point at 0x200-byte blocks.
"""

CHUNK_SIZE = 0x200


def chunked_array_teardown(holder):
    """holder: None (inner null), or {"inner_count": int, "slots": [...]}.
    slots lists the chunk pointers in the order the loop visits them.
    Returns the ordered op list."""
    if holder is None:
        return []
    ops = []
    for _slot in holder["slots"]:
        ops.append(("free_chunk", CHUNK_SIZE))
    ops.append(("free_inner", holder["inner_count"] * 8))
    return ops
