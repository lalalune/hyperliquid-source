"""Model of node #115 routine 0x5d51010: tear down one composite
object in seven phases.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes one argument, an object pointer in rdi, and
returns nothing. In instruction order:

1. Member: if the pointer at object +0x210 is non-null, call
   the destroy routine 0x5d8d820 with it, then operator delete
   it with size 0x290. The +0x210 slot itself is never
   written.
2. First array, backwards: the count at +0x68 is walked down
   to zero (the count slot is written back on every iteration
   and ends at 0). Each element is 0x30 bytes at the buffer
   pointed to by +0x1f0; each element holds one string with
   its pointer at +0x00, its size at +0x08 (never read), and
   its capacity-or-inline-buffer at +0x10. A pointer equal to
   the element's own +0x10 slot address is inline (SSO) and
   frees nothing; otherwise the pointer is deleted with size
   capacity + 1.
3. Second array, forwards: elements are 0x30 bytes from the
   begin pointer at +0x1f8 to the end pointer at +0x200,
   with the same string layout and the same SSO rule. After
   the walk, +0x200 is reset to +0x1f8.
4. Post-reset re-walk: the binary then re-walks from +0x1f8
   to +0x200, but +0x200 was just reset to +0x1f8 and +0x1f8
   is not written in between, so the walk's entry condition
   is already satisfied and it deletes nothing on any entry
   path. The re-walk instructions (including the delete at
   0x5d51108) are present in the range but execute zero
   iterations; the model records this as a vacuous step, not
   as a second deletion pass.
5. Second-array buffer: if the +0x1f8 buffer pointer is
   non-null, delete it with size +0x208 minus +0x1f8 (the
   capacity-end slot minus the begin slot, in bytes).
6. Head count: if the qword at +0x00 is non-zero, zero it.
   Nothing is freed here.
7. Pointer vector: if +0x58 differs from +0x50, reset +0x58
   to +0x50 first; then, if +0x50 is non-null, tail-jump to
   operator delete with size +0x60 minus +0x50. A null begin
   with a non-null end still resets the end and returns
   without deleting.

The routine never frees the object itself, never writes the
+0x210, +0x1f8, +0x208, +0x50 or +0x60 slots, and never
writes any element string slot. The destroy callee 0x5d8d820
is opaque here: only its argument and its position before
the member delete are pinned.
"""

DESTROY_CALLEE = 0x5D8D820
MEMBER_DELETE_SIZE = 0x290
ELEMENT_STRIDE = 0x30
DELETE_CALLEE = 0x63F0D80


class StringField:
    """One 32-byte string field: pointer, capacity, inline flag.

    ``inline`` means the pointer equals the field's own +0x10
    slot address, so the binary frees nothing for it. For a
    heap string, ``pointer`` is an opaque identity and
    ``capacity`` is the value at +0x10; the delete size is
    capacity + 1. The size at +0x08 is never read by the
    binary and is not modelled."""

    def __init__(self, pointer, capacity, inline=False):
        self.pointer = pointer
        self.capacity = capacity
        self.inline = inline


class CompositeObject:
    """The object torn down by 0x5d51010, as plain fields."""

    def __init__(self, member=None, first=None, second=None,
                 second_buffer_size=None, head_count=0,
                 ptr_begin=None, ptr_end=None, ptr_cap_size=None):
        self.member = member
        self.first = list(first) if first is not None else []
        self.first_count = len(self.first)
        self.second = list(second) if second is not None else []
        # second_buffer_size is +0x208 minus +0x1f8 in bytes;
        # None stands for a null +0x1f8 buffer pointer.
        self.second_buffer_size = second_buffer_size
        self.second_end_reset = False
        self.head_count = head_count
        # ptr_begin/ptr_end are opaque buffer identities (None
        # for a null pointer); ptr_cap_size is +0x60 minus
        # +0x50 in bytes, used only when ptr_begin is not None.
        self.ptr_begin = ptr_begin
        self.ptr_end = ptr_end
        self.ptr_cap_size = ptr_cap_size


def teardown_composite(obj):
    """Run the seven phases on obj and return the event list.

    Events are ("destroy", member), ("delete", identity, size),
    ("tail_delete", identity, size), ("zero", field),
    ("reset", field) and ("rewalk_vacuous",) tuples, in binary
    order. A null object
    raises, matching the binary reading +0x210 immediately
    with no null check; a nonzero first count with no first
    buffer, or a second buffer size without a second buffer,
    likewise raises instead of inventing a layout."""
    if obj is None:
        raise ValueError("null object")
    events = []
    # Phase 1: member.
    if obj.member is not None:
        events.append(("destroy", obj.member))
        events.append(("delete", obj.member, MEMBER_DELETE_SIZE))
    # Phase 2: first array, backwards, count written to zero.
    if obj.first_count != len(obj.first):
        raise ValueError("first count does not match first array")
    for field in reversed(obj.first):
        if not field.inline:
            events.append(("delete", field.pointer, field.capacity + 1))
    obj.first_count = 0
    # Phase 3: second array, forwards, then reset end to begin.
    for field in obj.second:
        if not field.inline:
            events.append(("delete", field.pointer, field.capacity + 1))
    obj.second_end_reset = True
    # Phase 4: post-reset re-walk, vacuous by construction.
    events.append(("rewalk_vacuous",))
    # Phase 5: second-array buffer.
    if obj.second_buffer_size is not None:
        events.append(("delete", "second_buffer", obj.second_buffer_size))
    # Phase 6: head count.
    if obj.head_count != 0:
        obj.head_count = 0
        events.append(("zero", "head_count"))
    # Phase 7: pointer vector; end reset precedes the null check.
    if obj.ptr_end != obj.ptr_begin:
        obj.ptr_end = obj.ptr_begin
        events.append(("reset", "ptr_end"))
    if obj.ptr_begin is not None:
        events.append(("tail_delete", obj.ptr_begin, obj.ptr_cap_size))
    return events
