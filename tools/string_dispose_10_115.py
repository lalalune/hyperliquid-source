"""Model of node #115 routine 0x5d507d0: dispose the ten heap
strings of one record.

The routine walks ten string fields, in this order (base offsets
from the record pointer in rdi):

    0x190, 0x170, 0x150, 0x130, 0xd0, 0xb0, 0x80, 0x60, 0x20, 0x00

Each field is one 32-byte string: pointer at +0x00, size at +0x08
(never read by this routine), capacity-or-inline-buffer at +0x10.
For each field the routine compares the pointer with the address
of its own +0x10 slot: equal means the string is inline (SSO) and
nothing is freed; different means the string is heap-allocated and
the routine frees it with delete(pointer, capacity + 1), where the
capacity is read from the +0x10 slot. The last field (+0x00) is
freed by a tail jump to the same delete entry point instead of a
call; the observable effect is identical.

The routine frees only those ten fields. It does not free the
record itself, does not touch any other field (including the
+0x08 size slots and every byte outside the ten fields), and it
does not write anything: after it returns, the freed heap buffers
are gone but the record's pointer/capacity slots are left as they
were. What the record and its strings denote is not claimed.

The model is deliberately data-only: pointers are opaque tokens,
capacities are integers, and a freed buffer is recorded as a
(pointer, size) pair in disposal order. It raises on malformed
model inputs (a negative capacity, a non-integer capacity) as a
model safety property, not a binary claim.
"""

# Disposal order, exactly as the routine walks the fields.
FIELD_OFFSETS = (0x190, 0x170, 0x150, 0x130, 0xD0, 0xB0, 0x80, 0x60,
                 0x20, 0x00)


class StringField:
    """One 32-byte string field: pointer token, capacity, inline flag.

    inline=True means the pointer equals the address of the field's
    own +0x10 slot, so the routine frees nothing for this field.
    inline=False means a heap string: the routine frees
    (pointer, capacity + 1).
    """

    def __init__(self, pointer, capacity, inline):
        if not isinstance(capacity, int) or isinstance(capacity, bool):
            raise TypeError("capacity must be an integer")
        if capacity < 0:
            raise ValueError("capacity must not be negative")
        self.pointer = pointer
        self.capacity = capacity
        self.inline = inline


class Record:
    """The record: a mapping from field offset to StringField.

    Fields outside FIELD_OFFSETS are never read by the routine and
    need not be present.
    """

    def __init__(self, fields):
        for offset in FIELD_OFFSETS:
            if offset not in fields:
                raise ValueError("missing string field %#x" % offset)
        self.fields = fields


def dispose_record_strings(record):
    """Dispose the record's ten strings, in the routine's order.

    Returns the list of (pointer, freed_size) pairs for the heap
    strings, in disposal order. Inline strings contribute nothing.
    The record's own slots are left unchanged, exactly as the
    routine leaves them.
    """
    freed = []
    for offset in FIELD_OFFSETS:
        field = record.fields[offset]
        if field.inline:
            continue
        freed.append((field.pointer, field.capacity + 1))
    return freed
