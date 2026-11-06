"""Model of node #115 routine 0x593da30: a power-of-ten
divisibility gate over a table-selected element.

The routine takes an out pointer in rdi, an unsigned 64-bit
value in rsi, an unsigned 64-bit index in rdx and a context
pointer in rcx, and answers one question: is the value exactly
divisible by the power of ten that the selected table record's
class byte prescribes? The decision, in order, read from the
whole-function excerpt in the packet:

  1. If index >= the entry count at ctx +0x10, leave through
     the noreturn slot call at 0x64df620 (RELATIVE-resolved to
     0x1680cbf) with rdi = index, rsi = count and rdx = the
     static at 0x6476678. Nothing is written.
  2. Read the element E, the u64 at the index lane of the array
     at ctx +0x08 (32-byte stride; only the first 8 bytes of a
     lane are read). If E >= the bound at ctx +0x28, leave
     through the noreturn slot call at 0x64df830
     (RELATIVE-resolved to 0x1680c10) with rdi = the static at
     0x64768d8. Nothing is written.
  3. Read the class byte T at record E of the table at
     ctx +0x20: offset E * 0x158 + 0x48 (only that one byte of
     the 0x158-byte record is read). If T >= 9, write the tag
     word 0x6a at (out) and return; the payload qword at
     (out) +8 is not written.
  4. If T is in 0..8, the divisor is 10^(8 - T). The routine
     builds it with a multiply ladder (x10 for bit 0 of 8 - T,
     x100 for bit 1, x10000 for bit 2, x10^8 for the T == 0
     remainder arm) and tests value mod divisor with a 32-bit
     div when (value | divisor) fits in 32 bits, else a 64-bit
     div; both compute the exact quotient and remainder. If the
     remainder is 0, write the tag word 0x1a2 at (out) and the
     quotient at (out) +8. Otherwise write 0x6a at (out) and
     leave (out) +8 untouched.

On both return paths rax = rdi. The routine writes nothing
besides the tag word and, on the divisible path, the payload
qword -- in particular never the out bytes +0x02..+0x08 or any
byte past +0x10. It has no direct calls and no tail jumps; the
two slot calls above are its only transfers out, and both are
on failed checks.

The two noreturn exits are modelled as the IndexPanic and
BoundPanic exceptions below: the model raises instead of
writing, which is the observable difference the callers see.
What the callees behind the slots do is not modelled.
"""

import struct
from collections import namedtuple

COUNT_OFFSET = 0x10
ARRAY_OFFSET = 0x08
BOUND_OFFSET = 0x28
RECORDS_OFFSET = 0x20

ELEMENT_STRIDE = 32
RECORD_STRIDE = 0x158
CLASS_BYTE_OFFSET = 0x48

TAG_DIVISIBLE = 0x1A2
TAG_NOT_DIVISIBLE = 0x6A

U64_MAX = 2 ** 64 - 1

GateOutcome = namedtuple("GateOutcome", ["tag", "quotient"])


class IndexPanic(Exception):
    """Model of the index-check exit (slot 0x64df620).

    Carries the argument registers the routine sets on that
    path: index, count, and the static address 0x6476678."""


class BoundPanic(Exception):
    """Model of the bound-check exit (slot 0x64df830).

    The routine sets only rdi on that path, to the static
    address 0x64768d8."""


def _check_u64(value, label):
    if not isinstance(value, int) or isinstance(value, bool) \
            or not 0 <= value <= U64_MAX:
        raise ValueError("%s must be an unsigned 64-bit integer" % label)


class GateContext:
    """The context as the routine sees it.

    ``count`` is the u64 at ctx +0x10. ``elements`` is the
    array at ctx +0x08 reduced to the only lane content the
    routine reads: elements[i] is the u64 at array + i * 32.
    ``bound`` is the u64 at ctx +0x28. ``record_area`` is the
    byte string of the record table at ctx +0x20; the class
    byte for element E is read at E * 0x158 + 0x48, and no
    other byte of the table is read.
    """

    def __init__(self, count, elements, bound, record_area):
        _check_u64(count, "count")
        _check_u64(bound, "bound")
        if not isinstance(elements, (list, tuple)):
            raise TypeError("elements must be a list or tuple of u64")
        for element in elements:
            _check_u64(element, "element")
        if not isinstance(record_area, (bytes, bytearray)):
            raise TypeError("record_area must be bytes")
        self.count = count
        self.elements = list(elements)
        self.bound = bound
        self.record_area = bytes(record_area)


def divisor_for(class_byte):
    """The divisor the class byte prescribes, or None.

    T in 0..8 selects 10^(8 - T); T >= 9 selects no divisor and
    the routine takes the immediate 0x6a path.
    """
    _check_u64(class_byte, "class byte")
    if class_byte > 255:
        raise ValueError("class byte must be a single byte 0..255")
    if class_byte >= 9:
        return None
    return 10 ** (8 - class_byte)


def pow10_divisibility_gate(out, value, index, context):
    """Run the gate and write the result into ``out``.

    ``out`` is a bytearray of at least 16 bytes acting as the
    out slot: the tag word is written at out +0 and, on the
    divisible path only, the quotient at out +8; no other byte
    is touched. Returns a GateOutcome(tag, quotient) with
    quotient None on the 0x6a paths. Raises IndexPanic when
    index >= context.count and BoundPanic when the selected
    element is >= context.bound; on both raises nothing is
    written to ``out``.
    """
    if not isinstance(out, bytearray):
        raise TypeError("out must be a bytearray")
    if len(out) < 16:
        raise ValueError("out must hold at least 16 bytes")
    _check_u64(value, "value")
    _check_u64(index, "index")
    if not isinstance(context, GateContext):
        raise TypeError("context must be a GateContext")
    if index >= context.count:
        raise IndexPanic(
            "index %#x >= count %#x (static 0x6476678)"
            % (index, context.count))
    element = context.elements[index]
    if element >= context.bound:
        raise BoundPanic(
            "element %#x >= bound %#x (static 0x64768d8)"
            % (element, context.bound))
    offset = element * RECORD_STRIDE + CLASS_BYTE_OFFSET
    if offset >= len(context.record_area):
        # The binary reads the byte from live memory; a short
        # record_area is a model limit, not a binary claim.
        raise ValueError("record_area too short for element %#x" % element)
    class_byte = context.record_area[offset]
    divisor = divisor_for(class_byte)
    if divisor is not None and value % divisor == 0:
        quotient = value // divisor
        struct.pack_into("<Q", out, 8, quotient)
        struct.pack_into("<H", out, 0, TAG_DIVISIBLE)
        return GateOutcome(TAG_DIVISIBLE, quotient)
    struct.pack_into("<H", out, 0, TAG_NOT_DIVISIBLE)
    return GateOutcome(TAG_NOT_DIVISIBLE, None)
