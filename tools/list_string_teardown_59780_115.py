#!/usr/bin/env python3
"""Model of node #115 routine 0x5d59780 (FDE 0x5d59780..0x5d59825).

List teardown with a per-node string dispose, then a buffer clear:

1. Drain the linked list whose head is at holder+0x10. Each node is
   0x38 bytes: the next pointer at +0x00 is loaded before the node
   is disposed, and the string at +0x08 (pointer) / +0x18 (capacity)
   follows the short-form rule: a pointer equal to node+0x18 frees
   nothing, otherwise the sized delete frees (pointer, capacity + 1).
   The node itself is then freed with size 0x38. Nodes are freed
   head to tail; a null head skips the loop entirely.
2. Clear the buffer: memset(holder+0x00, 0, count * 8) where count is
   the qword at holder+0x08, then zero holder+0x10 (the drained list
   head) and holder+0x18.
3. Buffer exit: when the buffer begin equals holder+0x30 the routine
   returns plainly; otherwise it tail-jumps to the sized-delete PLT
   freeing (begin, count * 8). The begin (+0x00) and count (+0x08)
   slots are not cleared, the holder itself is never freed, and no
   canary check is performed. No call other than the sized-delete
   PLT and the memset PLT occurs.

Preconditions (matching the binary's assumptions): the list is
well-formed and terminates, and the buffer range is valid for
count * 8 bytes when the begin is not holder+0x30.
"""

NODE_SIZE = 0x38


def dispose_string(field):
    """field is ("short",) or ("heap", capacity). Returns the op."""
    if field[0] == "short":
        return "skip_string"
    return ("free_string", field[1] + 1)


def list_string_teardown(holder):
    """holder: {"nodes": [string field per node, head to tail],
    "buffer": "heap" | "inline", "count": int}.
    Returns the ordered op list."""
    ops = []
    for index, field in enumerate(holder["nodes"]):
        op = dispose_string(field)
        if isinstance(op, tuple):
            ops.append((index, op[0], op[1]))
        else:
            ops.append((index, op))
        ops.append((index, "free_node", NODE_SIZE))
    size = holder["count"] * 8
    ops.append(("memset_buffer", size))
    ops.append(("zero_slots", (0x10, 0x18)))
    if holder["buffer"] == "inline":
        ops.append("return_inline_buffer")
    else:
        ops.append(("free_buffer", size))
    return ops
