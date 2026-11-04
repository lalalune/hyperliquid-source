#!/usr/bin/env python3
"""Model of node #115 routine 0x5d58ed0 (FDE 0x5d58ed0..0x5d58f02).

Buffer-inner teardown:

1. The holder in rdi points at an inner object: inner = [holder+0x00].
   A null inner returns plainly with nothing freed.
2. Buffer phase: buffer = [inner+0x00]. A null buffer skips the buffer
   free. Otherwise the buffer is freed with a sized delete of
   ([inner+0x10] - buffer) bytes through the _ZdlPvm PLT at
   0x63f0d80. The qword at inner+0x08 is never read.
3. Exit: the routine tail-jumps to the same PLT freeing the inner
   object itself at a fixed size of 0x18 bytes. The holder itself
   is never freed, and no canary check is performed.

Preconditions (matching the binary's assumptions): the buffer range
is well-formed, with the capacity end at or above the buffer begin.
"""

INNER_SIZE = 0x18


def buffer_inner_teardown(holder):
    """holder: None (inner null), or {"buffer_begin": int|None,
    "buffer_cap_end": int}. buffer_begin None means a null buffer
    pointer (buffer free skipped, inner free still runs).
    Returns the ordered op list."""
    if holder is None:
        return []
    ops = []
    if holder["buffer_begin"] is not None:
        ops.append(("free_buffer",
                    holder["buffer_cap_end"] - holder["buffer_begin"]))
    ops.append(("free_inner", INNER_SIZE))
    return ops
