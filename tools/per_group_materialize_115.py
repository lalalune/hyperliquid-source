"""Node #115 per-group materialize step (0x5f6a630) with its factory leaf.

RE-001 work item. This is a complete behavior, not a lone-window
fragment: the step takes one group entry (a byte range of 8-byte
element pointers) plus an allocator owner, allocates one 80-byte
output record per element, initializes every record with a fixed
pattern, and then fills each record end to end from its source
element: the element's first five qwords, the element pointer, a
freshly concatenated copy of the element's two byte segments, and
the segment lengths and pointers. The pipeline group pass
(0x5f801f0, pinned by the earlier RE-001 pipeline item and
referenced here, not re-claimed) calls this step once per group;
its other known call site is 0x5da98b8, recorded site-only.

Native layout (all offsets from the disassembly of work/hl-node-115.bin,
bound to provenance/artifacts.json digest a6e2897c...5301):

  materialize(out, group, owner, allocator):
    span = group.end - group.begin       (64-bit wrapping difference)
    count = span >> 3                    (arithmetic shift of the
                                          signed difference)
    out.count = count
    buffer = allocator(owner, count * 80 mod 2**64, 0, 0)
    if span (unsigned) > 0xcccccccccccccc8:
        throw bad_array_new_length       (after the allocator call)
    out.buffer = buffer
    for i in 0..count-1:                 (skipped when count == 0)
        slot = buffer + 80 * i
        slot = init_pattern()            (see below; one factory
                                          call per slot, see
                                          factory_value)
    if span == 0: return
    i = 0
    loop:                                (do-while: runs at least
                                          once when span != 0, so a
                                          1..7-byte span still
                                          materializes exactly one
                                          element)
        elt = group.elements[i]
        seg1 = elt.seg1; seg2 = elt.seg2
        concat = allocator(owner, len(seg1) + len(seg2) mod 2**64,
                           previous element pointer or 0, 0)
        concat[0:len(seg1)] = seg1       (memcpy)
        concat[len(seg1):] = seg2        (memcpy)
        slot = buffer + 80 * i
        slot.f00 = elt.f00; slot.f08 = elt.f08; slot.f10 = elt.f10
        slot.f18 = elt.f18; slot.f20 = elt.f20
        slot.f28 = elt pointer; slot.f30 = concat pointer
        slot.f38 = len(seg1)
        slot.f40 = concat pointer + len(seg1)
        slot.f48 = len(seg2)
        i += 1
    while i < count                      (unsigned compare)

  init_pattern() per slot (80 bytes, ten qwords):
    +0x00 = 0
    +0x08 = factory_value(0, 0) = 0      (see factory_value)
    +0x10 = 0
    +0x18 = 0x00FFFFFFFFFFFFFF
    +0x20 = 0
    +0x28 = 0
    +0x30 = 0x4376FD                     (literal constant; what it
                                          points to is not claimed)
    +0x38 = 0
    +0x40 = 0x4376FD
    +0x48 = 0
  Every init field is overwritten by the fill phase when count > 0,
  so the init pattern is observable only in the call log (one
  factory call per slot), never in a finished slot.

  factory_value(a, b):                   (the 15-byte leaf 0x5f54680)
    return (a | (b << 62)) mod 2**64
  Called here with (0, 0) only, so the stored value is always 0;
  the leaf's general form is recorded because it is the whole
  function, not because this call site varies it.

The allocator is a virtual method (offset 0x18 of the owner's table)
and stays an oracle: the model passes it (size, rdx, rcx) exactly as
the native code does -- rdx is 0 on the first call of each phase
and the previous element pointer on later fill calls, rcx is 0 --
and takes the returned opaque buffer token. Whether the allocator
reads the trailing arguments is its own business and is not pinned.
memcpy is the libc routine; the model copies the segment bytes.

Assumptions recorded explicitly:
  * The caller supplies at least as many elements as the fill phase
    reads; a shorter list would read out of bounds natively and is
    rejected by the model.
  * Segment byte strings are the bytes the native code would copy;
    a segment pointer that is null with a nonzero length would
    fault natively and is rejected by the model.
  * The group entry's third qword (+0x10) is never read by this
    function and is not an input of the model.
  * The output record's fields past +0x08 are not written by this
    function and are not part of the model.
  * No return value is claimed: the known callers continue without
    reading rax after the call.
  * A negative byte span always trips the span limit (its unsigned
    value is at least 2**63, above the limit), so the length throw
    fires before any loop and a negative count never reaches the
    init loop.
"""

MASK64 = (1 << 64) - 1

# Native bad_array_new_length trip point for the element byte span.
SPAN_LIMIT = 0xcccccccccccccc8

# Literal constants stored by the per-slot initialization.
INIT_TAG = 0x4376FD
INIT_MASK56 = 0x00FFFFFFFFFFFFFF


class BadArrayNewLength(Exception):
    """Native __cxa_throw_bad_array_new_length for an overlong span."""


def u64(value):
    return value & MASK64


def factory_value(a, b):
    """The 0x5f54680 leaf: (a | (b << 62)) mod 2**64."""
    return u64(a | (u64(b) << 62))


def init_pattern():
    """One initialized 80-byte slot, as ten qwords by offset."""
    return {
        0x00: 0,
        0x08: factory_value(0, 0),
        0x10: 0,
        0x18: INIT_MASK56,
        0x20: 0,
        0x28: 0,
        0x30: INIT_TAG,
        0x38: 0,
        0x40: INIT_TAG,
        0x48: 0,
    }


def materialize(out, group, allocator):
    """Run the per-group materialize step.

    out: dict receiving "count" and "buffer".
    group: dict with "byte_span" (the signed 64-bit end-begin
        difference) and "elements" (source elements in order).
        Each element is a dict with qwords "f00", "f08", "f10",
        "f18", "f20" and byte strings "seg1", "seg2".
    allocator: callable(size, rdx, rcx) returning an opaque buffer
        token. The model also accepts a size-only callable, which
        is wrapped.

    Returns a dict with the output record, the finished slots, the
    init slots (overwritten by the fill phase when count > 0), the
    concatenation buffers, and the call log.
    """
    if allocator is None:
        raise ValueError("allocator oracle is required")

    def alloc(size, rdx, rcx):
        return allocator(size, rdx, rcx)

    byte_span = group["byte_span"]
    elements = group["elements"]
    span_u = u64(byte_span)
    count = byte_span >> 3  # arithmetic shift of the signed difference
    out["count"] = count
    calls = {"allocator": [], "factory": 0, "memcpy": []}

    buffer = alloc(u64(count * 80), 0, 0)
    calls["allocator"].append((u64(count * 80), 0, 0))
    if span_u > SPAN_LIMIT:
        raise BadArrayNewLength(
            "element byte span %#x exceeds %#x" % (span_u, SPAN_LIMIT))
    out["buffer"] = buffer

    init_slots = []
    for _ in range(count) if count > 0 else []:
        calls["factory"] += 1
        init_slots.append(init_pattern())

    slots = []
    concats = []
    if span_u == 0:
        return {"out": out, "slots": slots, "init_slots": init_slots,
                "concats": concats, "calls": calls}
    iterations = max(count, 1)
    if len(elements) < iterations:
        raise ValueError(
            "group supplies %d elements, fill phase reads %d"
            % (len(elements), iterations))
    previous = 0
    for index in range(iterations):
        elt = elements[index]
        seg1 = elt["seg1"]
        seg2 = elt["seg2"]
        size = u64(len(seg1) + len(seg2))
        concat = alloc(size, previous, 0)
        calls["allocator"].append((size, previous, 0))
        calls["memcpy"].append((concat, "seg1", len(seg1)))
        calls["memcpy"].append((concat, "seg2", len(seg2)))
        concats.append(seg1 + seg2)
        slot = {
            0x00: elt["f00"],
            0x08: elt["f08"],
            0x10: elt["f10"],
            0x18: elt["f18"],
            0x20: elt["f20"],
            0x28: ("element", index),
            0x30: ("buffer", concat),
            0x38: len(seg1),
            0x40: ("buffer_offset", concat, len(seg1)),
            0x48: len(seg2),
        }
        slots.append(slot)
        previous = ("element", index)
    return {"out": out, "slots": slots, "init_slots": init_slots,
            "concats": concats, "calls": calls}
