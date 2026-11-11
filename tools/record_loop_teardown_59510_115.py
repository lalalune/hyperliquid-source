#!/usr/bin/env python3
"""Model of node #115 routine 0x5d59510 (FDE 0x5d59510..0x5d596e5).

Record-loop teardown over a vector of 0x1d8-byte records:

1. The holder at rdi is a vector: begin at +0x00, end at +0x08,
   capacity end at +0x10. The end is loaded once at entry; when
   begin equals end the loop is skipped entirely.
2. Per record, in order, eleven string fields are disposed. Each
   field is a pointer/capacity pair; the short-form rule applies:
   a pointer equal to the record base plus the capacity offset
   frees nothing, otherwise a sized delete frees (pointer,
   capacity + 1) through the _ZdlPvm PLT at 0x63f0d80. The fields,
   as (pointer offset, capacity offset), are:
       0x1b0/0x1c0, 0x190/0x1a0, 0x170/0x180, 0x150/0x160,
       0x130/0x140, 0xd0/0xe0, 0xb0/0xc0, 0x80/0x90,
       0x60/0x70, 0x20/0x30, 0x00/0x10.
   For the last field the cursor is advanced by 0x1d8 before its
   delete call; the free order is unchanged, since the next record
   is only processed after that call.
3. Buffer exit: the begin is reloaded from holder+0x00. A null
   begin returns plainly; otherwise the routine tail-jumps to the
   sized-delete PLT freeing (begin, capacity end - begin), where
   capacity end is the qword at holder+0x10. The end slot (+0x08)
   is not reset, the begin slot is not cleared, the holder itself
   is never freed, and no canary check is performed. No call other
   than the sized-delete PLT occurs.

Preconditions (matching the binary's assumptions): the record
range is well-formed (begin/end delimit whole 0x1d8-byte records),
and the buffer range is valid when the begin is non-null.
"""

RECORD_STRIDE = 0x1D8

# (pointer offset, capacity offset), in the order the routine visits them.
FIELDS = [
    (0x1B0, 0x1C0),
    (0x190, 0x1A0),
    (0x170, 0x180),
    (0x150, 0x160),
    (0x130, 0x140),
    (0x0D0, 0x0E0),
    (0x0B0, 0x0C0),
    (0x080, 0x090),
    (0x060, 0x070),
    (0x020, 0x030),
    (0x000, 0x010),
]


def dispose_string(field):
    """field is ("short",) or ("heap", capacity). Returns the op."""
    if field[0] == "short":
        return "skip_string"
    return ("free_string", field[1] + 1)


def record_loop_teardown(holder):
    """holder: {"records": [[field per record, in FIELDS order], ...],
    "buffer_size": int | None (None = null begin, plain return)}.
    Returns the ordered op list."""
    ops = []
    for index, record in enumerate(holder["records"]):
        for field_index, field in enumerate(record):
            op = dispose_string(field)
            if isinstance(op, tuple):
                ops.append((index, field_index, op[0], op[1]))
            else:
                ops.append((index, field_index, op))
    if holder["buffer_size"] is not None:
        ops.append(("free_buffer", holder["buffer_size"]))
    return ops
