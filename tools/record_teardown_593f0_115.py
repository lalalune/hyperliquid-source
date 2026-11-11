#!/usr/bin/env python3
"""Model of node #115 routine 0x5d593f0 (FDE 0x5d593f0..0x5d594dd).

Record teardown: for each 0x130-byte record in the holder range
[holder+0x00, holder+0x08), dispose four pointer/capacity fields in
order (+0x100, +0xe0, +0x50, +0x30) with the short-form rule, then
free the holder buffer (begin, [holder+0x10] - begin) via a tail
jump to the sized-delete PLT, or return plainly when the buffer
is null.

Each field is a pointer at +0x00 and a capacity at +0x10 relative
to the field base (so the short-form address is field base + 0x10):
a pointer equal to that address frees nothing, otherwise the sized
delete frees (pointer, capacity + 1). The routine writes nothing to
the holder or the records: no field is reset, the +0x08 end is not
reset, and the holder itself is never freed. It performs no canary
check and makes no call other than the sized-delete PLT.

Preconditions (matching the binary's assumptions): the record range
is valid, or the buffer is null with an empty range. A null buffer
with a non-empty range is not modelled (the binary would dereference
the null begin).
"""

FIELD_OFFSETS = (0x100, 0xE0, 0x50, 0x30)
STRIDE = 0x130


def dispose_field(field):
    """field is ("short",) or ("heap", capacity). Returns the op."""
    if field[0] == "short":
        return "skip_short_field"
    return ("free_field", field[1] + 1)


def record_teardown(holder):
    """holder: {"elements": [[field x 4] per record],
    "buffer": None|size}.
    Returns the ordered op list."""
    elements = holder["elements"]
    if holder["buffer"] is None:
        if elements:
            raise ValueError("null buffer with a non-empty range")
        return ["return_null_buffer"]
    ops = []
    for index, element in enumerate(elements):
        if len(element) != 4:
            raise ValueError("each record holds exactly four fields")
        for field_index, field in enumerate(element):
            op = dispose_field(field)
            if isinstance(op, tuple):
                ops.append((index, field_index, op[0], op[1]))
            else:
                ops.append((index, field_index, op))
    ops.append(("free_buffer", holder["buffer"]))
    return ops
