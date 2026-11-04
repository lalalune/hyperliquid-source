"""Model of node #115 routine 0x5d519d0: a destructor chain for
one composite object.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes one argument, an object pointer in rdi, and
returns nothing (it leaves through a tail jump, so control
returns directly to its caller through the teardown). In
instruction order:

1. Composite destructor: call 0x5d50de0 with the object
   pointer. That routine was mapped separately; here only
   its call and its position first are pinned.
2. Pointer vector, in index order: the total element count
   is the qword at +0x218 plus (the qword at +0x270 minus
   the qword at +0x268) divided by 8. Index i reads the
   i-th qword of the first chunk (the array pointed to by
   the qword at +0x260) while i <= 7, and the (i - 8)-th
   qword of the second chunk (the array starting at the
   qword at +0x268) once i >= 8. Each non-null element
   pointer is destroyed by calling 0x5f10d40 with it, then
   deleted with operator delete and size 0xd20. Null
   elements are skipped. The index rule is literal: the
   switch to the second chunk happens at index 8
   regardless of the +0x218 count, so when the second
   chunk is non-empty but the +0x218 count is not 8, the
   walk visits first-chunk slots for every index below 8
   and second-chunk slots only from index 8 on, which can
   leave second-chunk elements unvisited or walk past the
   second chunk (the model raises on the latter).
3. Post-loop field handling, in order: if the +0x218
   qword is non-zero, zero it; if the +0x270 end differs
   from the +0x268 begin, reset +0x270 to +0x268; if the
   +0x268 begin pointer is non-null, delete that buffer
   with operator delete and size +0x278 minus +0x268.
   The end reset precedes the null check, so a null begin
   with a non-null end still resets the end and returns
   without deleting (in a well-formed vector the loop
   count keeps that shape from arising with a live second
   chunk; the model keeps the two steps separate).
4. Teardown tail jump: with the object pointer restored
   in rdi, tail-jump to the composite teardown 0x5d51010.

The routine never frees the object itself, never writes
the +0x260, +0x268 or +0x278 slots, and never writes any
element slot. The destroy callee 0x5f10d40 and the
destructor callee 0x5d50de0 are opaque here: only their
arguments and positions are pinned.
"""

DESTRUCTOR_CALLEE = 0x5D50DE0
DESTROY_CALLEE = 0x5F10D40
ELEMENT_DELETE_SIZE = 0xD20
TEARDOWN_CALLEE = 0x5D51010
DELETE_CALLEE = 0x63F0D80
FIRST_CHUNK_LIMIT = 8


class CompositeObject:
    """The object destroyed by 0x5d519d0, as plain fields."""

    def __init__(self, first_chunk=None, first_count=0,
                 second_chunk=None, second_begin=None,
                 second_end=None, second_cap_size=None):
        # first_chunk: identities of the qwords in the array
        # pointed to by +0x260, in order; first_count is the
        # +0x218 qword. second_chunk: identities of the
        # qwords in the second chunk (begin +0x268), in
        # order; second_begin/second_end are opaque buffer
        # identities (None for a null pointer);
        # second_cap_size is +0x278 minus +0x268 in bytes,
        # used only when second_begin is not None.
        self.first_chunk = list(first_chunk) if first_chunk is not None else []
        self.first_count = first_count
        self.second_chunk = list(second_chunk) if second_chunk is not None else []
        self.second_begin = second_begin
        self.second_end = second_end
        self.second_cap_size = second_cap_size


def destroy_chain(obj):
    """Run the four phases on obj and return the event list.

    Events are ("destructor_call",), ("destroy", identity),
    ("delete", identity, size), ("zero", field),
    ("reset", field) and ("tail",) tuples, in binary order.
    A null object raises, matching the binary calling
    0x5d50de0 with rdi immediately and with no null check;
    a negative first count, or an index walk that runs past
    a modelled chunk, likewise raises instead of inventing
    a layout."""
    if obj is None:
        raise ValueError("null object")
    if obj.first_count < 0:
        raise ValueError("negative first count")
    events = []
    # Phase 1: composite destructor.
    events.append(("destructor_call",))
    # Phase 2: pointer vector, index order, chunk rule literal.
    total = obj.first_count + len(obj.second_chunk)
    for index in range(total):
        if index < FIRST_CHUNK_LIMIT:
            if index >= len(obj.first_chunk):
                raise ValueError("first-chunk walk past the chunk")
            element = obj.first_chunk[index]
        else:
            second_index = index - FIRST_CHUNK_LIMIT
            if second_index >= len(obj.second_chunk):
                raise ValueError("second-chunk walk past the chunk")
            element = obj.second_chunk[second_index]
        if element is None:
            continue
        events.append(("destroy", element))
        events.append(("delete", element, ELEMENT_DELETE_SIZE))
    # Phase 3: field handling, in binary order.
    if obj.first_count != 0:
        obj.first_count = 0
        events.append(("zero", "first_count"))
    if obj.second_end != obj.second_begin:
        obj.second_end = obj.second_begin
        events.append(("reset", "second_end"))
    if obj.second_begin is not None:
        events.append(("delete", "second_buffer", obj.second_cap_size))
    # Phase 4: teardown tail jump.
    events.append(("tail",))
    return events
