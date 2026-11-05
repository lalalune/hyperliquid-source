"""Model of the node #115 tagged-value destructor 0x57aa810 (RE-001).

The routine is the drop glue for the 32-byte tagged value whose
widening conversion is pinned by the sibling packet at 0x57ae540:
callers build or widen a value and eventually hand it here. Its own
FDE is 0x57aa810..0x57aa9cd (445 bytes); it is reached by direct
calls only (see the packet census).

Pinned layout (see research/work-items/
RE-001-tagged-value-drop-aa810-115/): the value is 32 bytes.

- +0x00: tag byte. Tags 0..0x14 select through the 21-entry jump
  table at 0x9317a4; any tag byte >= 0x15 takes the table's default
  arm. The routine reads no other byte of the value for the
  no-payload tags.
- +0x08: word A. Meaning by arm: the capacity (in elements) of a
  buffer triple, or the child pointer of the two box arms.
- +0x10: word B. The buffer pointer of a buffer triple.
- +0x18: word C. The length (in elements) of a buffer triple.

Pinned behaviour, reproduced exactly (the model returns the ordered
list of effects; addresses are the integers stored in the fields):

- No-payload arms (tags 0..11, 13, 15, 16, 18): no effect at all.
  The routine returns without reading +0x08/+0x10/+0x18 and without
  any call.
- Byte-buffer arms (tags 12, 14): if A == 0, no effect. Otherwise
  one sized deallocation, dealloc(B, A): the size is A unshifted,
  so A is a capacity in 1-byte elements and C is never read.
- Box arms (tags 17, 19): a recursive drop of the child at A (the
  same routine, same rules), then dealloc(A, 0x20) unconditionally.
  The two tags have identical bodies (tag 17's body jumps to the
  shared tail of tag 19's).
- Value-vector arm (tag 20): drop each of the C elements at
  B + 0x20*i, in increasing address order, with the *twin*
  destructor 0x5b20680 (a second, self-recursive instantiation of
  this same 21-tag decision table); then, if A != 0,
  dealloc(B, A << 5). The elements are not dropped by this routine
  itself: the recursion asymmetry is in the bytes.
- Pair-vector arm (every tag >= 0x15, the jump table's default):
  for each of the C pairs at B + 0x40*i, in increasing address
  order, drop the pair's first half (B + 0x40*i) and then its
  second half (B + 0x40*i + 0x20), both with the twin destructor;
  then, if A != 0, dealloc(B, A << 6).

Every deallocation goes through GOT slot 0x64df4a0, an
R_X86_64_RELATIVE relocation with addend 0x635de30 (the binary's
sized-deallocation entry), always with the third argument 0. The
routine writes nothing: no store in its body touches the value,
the buffers, or any other memory.

Unwind behaviour is pinned structurally in the packet (LSDA): a
raise out of an element or pair drop continues the same arm's
cleanup over the not-yet-dropped remainder, deallocates the
buffer through the same slot as a call, and resumes unwinding
with _Unwind_Resume; a raise out of a box arm's recursion frees
the 32-byte box first. A raise inside such a cleanup call itself
routes to the panic-in-a-destructor shim (slot 0x64df4c0, addend
0x1680cab, message "panic in a destructor during cleanup").

The twin destructor's body, the pair glue 0x5b0ad70 (which drops a
pair by two twin calls), the deallocation entry's body and the
widening conversion's body are cited, not modelled here.
"""

VALUE_SIZE = 0x20
ELEMENT_SIZE = 0x20
PAIR_SIZE = 0x40

NO_PAYLOAD_TAGS = frozenset(
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 16, 18))
BYTE_BUFFER_TAGS = frozenset((12, 14))
BOX_TAGS = frozenset((17, 19))
VECTOR_TAG = 20
FIRST_PAIR_TAG = 0x15


class Value:
    """A 32-byte tagged value, as the four words the drop reads."""

    __slots__ = ("tag", "a", "b", "c")

    def __init__(self, tag, a=0, b=0, c=0):
        self.tag = tag & 0xFF
        self.a = a
        self.b = b
        self.c = c

    def __repr__(self):
        return (f"Value(tag={self.tag}, a={self.a:#x}, "
                f"b={self.b:#x}, c={self.c:#x})")


def drop(value, heap):
    """Return the ordered effects of dropping ``value``.

    ``heap`` resolves a pointer to the Value stored there; it is
    consulted only by the box arms, for the child at field A.
    Effects are ("twin", address) for an element drop by the twin
    destructor 0x5b20680, ("self", address) for a recursive entry
    into this routine, and ("dealloc", pointer, size) for a sized
    deallocation through slot 0x64df4a0 with third argument 0.
    """
    effects = []
    tag = value.tag
    if tag >= FIRST_PAIR_TAG:
        base = value.b
        for i in range(value.c):
            effects.append(("twin", base + PAIR_SIZE * i))
            effects.append(("twin", base + PAIR_SIZE * i + ELEMENT_SIZE))
        if value.a != 0:
            effects.append(("dealloc", value.b, value.a << 6))
    elif tag in NO_PAYLOAD_TAGS:
        pass
    elif tag in BYTE_BUFFER_TAGS:
        if value.a != 0:
            effects.append(("dealloc", value.b, value.a))
    elif tag in BOX_TAGS:
        child = heap(value.a)
        effects.append(("self", value.a))
        effects.extend(drop(child, heap))
        effects.append(("dealloc", value.a, VALUE_SIZE))
    elif tag == VECTOR_TAG:
        base = value.b
        for i in range(value.c):
            effects.append(("twin", base + ELEMENT_SIZE * i))
        if value.a != 0:
            effects.append(("dealloc", value.b, value.a << 5))
    return effects
