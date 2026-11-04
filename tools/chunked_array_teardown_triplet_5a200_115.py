#!/usr/bin/env python3
"""Model of node #115 routines 0x5d5a200, 0x5d5a270, 0x5d5a2e0
(FDEs 0x5d5a200..0x5d5a265, 0x5d5a270..0x5d5a2d5,
0x5d5a2e0..0x5d5a345).

Chunked array teardown triplet:

1. The holder in rdi points at an inner object: inner = [holder+0x00].
   A null inner returns plainly with nothing freed.
2. Chunk phase: the holder carries chunk-pointer slots. The cursor
   starts at [holder+0x28] and runs while it is below
   [holder+0x48] + 8 (unsigned), stepping 8, so the slot at
   [holder+0x48] itself is included. Per slot, the pointer is freed
   with a sized delete of exactly chunk_size through the _ZdlPvm PLT
   at 0x63f0d80, with no null test on slot pointers.
3. Exit: the routine tail-jumps to the same PLT freeing the inner
   object at ([holder+0x00], [holder+0x08] * 8). The holder itself
   is never freed, and no canary check is performed.

0x5d5a200 and 0x5d5a2e0 use chunk size 0x200; 0x5d5a270 uses 0x1f8.
The shared owners call the three in the fixed order 0x5d5a2e0,
0x5d5a270, 0x5d5a200.

Preconditions (matching the binary's assumptions): the slot range is
well-formed, and chunk pointers point at chunk_size-byte blocks.
"""

ROUTINES = {
    0x5D5A200: 0x200,
    0x5D5A270: 0x1F8,
    0x5D5A2E0: 0x200,
}

OWNER_SEQUENCE = [0x5D5A2E0, 0x5D5A270, 0x5D5A200]


def visited_slot_count(slot_start_index, slot_bound_index):
    """Slots visited when the cursor runs from slot_start_index while
    below slot_bound_index + 1 (the bound slot itself is included)."""
    return max(0, slot_bound_index - slot_start_index + 1)


def chunked_array_teardown(holder, chunk_size):
    """holder: None (inner null), or {"inner_count": int, "slots": [...]}.
    slots lists the chunk pointers in the order the loop visits them.
    Returns the ordered op list."""
    if holder is None:
        return []
    ops = []
    for _slot in holder["slots"]:
        ops.append(("free_chunk", chunk_size))
    ops.append(("free_inner", holder["inner_count"] * 8))
    return ops


def owner_sequence_teardown(holders):
    """holders: {routine_address: holder} for the three routines, in
    any order. Returns the ops of the fixed owner sequence
    0x5d5a2e0, 0x5d5a270, 0x5d5a200."""
    ops = []
    for routine in OWNER_SEQUENCE:
        ops.extend(chunked_array_teardown(holders[routine],
                                           ROUTINES[routine]))
    return ops
