"""Model of node #115 routine 0x5d5aff0: teardown of a holder that
owns a linked list of 0x10-byte plain nodes plus a qword buffer.

Holder layout as the routine uses it: buffer begin at +0x00,
buffer slot count at +0x08, list head at +0x10. The routine
never reads holder bytes at +0x18 except to zero them, and never
touches +0x20..+0x30 except to compare the buffer begin against
the holder+0x30 address, so those fields carry no claimed role
beyond what is stated here.

List phase: the head at +0x10 is followed through each node's
+0x00 next pointer, and every node is freed with a sized delete
of exactly 0x10 bytes; a null head skips the phase, and no node
payload is read. Buffer phase (always runs, even when the list
phase skipped): the buffer is zeroed with memset(begin, 0,
count * 8), the fields at +0x10 and +0x18 are zeroed, and then,
unless the begin pointer equals the holder+0x30 address (the
holder's own inline storage, which is not freed), the buffer is
freed with a tail-jump sized delete of count * 8 bytes. The
holder itself is never freed. The routine pushes rbp and rbx,
reserves 8 bytes of stack, and performs no canary check.

Representation: a holder is a dict with "nodes" (list, in walk
order; each entry is a placeholder because no payload is read),
"begin" (int address or None), "count" (int slot count) and
"inline" (bool: True when begin equals the holder+0x30 address).
``destroy`` returns the ordered event list: ("free", 16) per
node, ("zero", count * 8) for the memset, and ("free_span",
count * 8) for the buffer free when the buffer is not inline.
A null begin paired with a nonzero count raises ValueError,
mirroring that the routine would zero through a null base.
"""

NODE_SIZE = 0x10


def destroy(holder, events=None):
    """Return the ordered teardown events for ``holder``."""
    if events is None:
        events = []
    if holder["begin"] is None and holder["count"] != 0:
        raise ValueError("null buffer begin with nonzero count")
    for _node in holder["nodes"]:
        events.append(("free", NODE_SIZE))
    events.append(("zero", holder["count"] * 8))
    if not holder["inline"]:
        events.append(("free_span", holder["count"] * 8))
    return events
