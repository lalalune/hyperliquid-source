#!/usr/bin/env python3
"""Model of node #115 routine 0x5d58f10 (FDE 0x5d58f10..0x5d58fab).

Nested array teardown that frees its own inner holder:

1. The holder in rdi points at an inner object: inner = [holder].
   A null inner returns plainly with nothing freed.
2. Array phase: the inner object holds a vector-like triple of
   8-byte pointers (begin +0x00, end +0x08, capacity end +0x10).
   The loop walks [begin, end): each element is a pointer to a
   0x20-byte struct. A null element pointer is skipped. Otherwise
   the string at element+0x00 is disposed first when its pointer
   differs from element+0x10: sized delete (pointer, capacity + 1)
   where capacity lives at element+0x10, through the _ZdlPvm PLT
   at 0x63f0d80. The element struct itself is then freed with a
   sized delete of exactly 0x20 through the same PLT.
3. Buffer phase: begin is reloaded from inner+0x00. When it is
   non-null the array buffer is freed with a sized delete of
   (capacity end - begin) bytes, capacity end read from
   inner+0x10. A null begin skips this free.
4. Exit: the inner object itself is freed with a sized delete of
   exactly 0x18 via a tail jump to the same PLT. The outer holder
   in rdi is never freed, and no canary check is performed.

Preconditions (matching the binary's assumptions): the array
range is well-formed, element pointers are either null or point
at 0x20-byte structs, and the capacity end is at or past begin.
"""

ELEMENT_SIZE = 0x20
INNER_SIZE = 0x18


def nested_array_teardown(holder):
    """holder: None, or {"elements": [...], "begin_nonnull": bool,
    "buffer_bytes": int}. Each element is None or
    {"string_alloc": bool, "capacity": int} where string_alloc
    means the string pointer differs from element+0x10.
    Returns the ordered op list."""
    if holder is None:
        return []
    ops = []
    for element in holder["elements"]:
        if element is None:
            continue
        if element["string_alloc"]:
            ops.append(("free_string", element["capacity"] + 1))
        ops.append(("free_element", ELEMENT_SIZE))
    if holder["begin_nonnull"]:
        ops.append(("free_buffer", holder["buffer_bytes"]))
    ops.append(("free_inner", INNER_SIZE))
    return ops
