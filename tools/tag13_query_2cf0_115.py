"""Python model of the node #115 tag-13 inner query pinned by
RE-001-tag13-query-2cf0-115.

Routines (node #115, work/hl-node-115.bin):
  * tag-13 inner query      0x61b2cf0..0x61b3596
  * count-mismatch helper   0x61cf670..0x61cf767
  * mismatch cleanup        0x61cf650..0x61cf666
  * shared cleanup fragment 0x61b2ca8..0x61b2ce2
  * throttle gate           0x61b1930..0x61b19e7
  * limit check             0x61b1910..0x61b192b
  * flag-bit setter         0x61b18b0..0x61b18c8
  * frame-and-deliver       0x61b1a10..0x61b1ac6
  * ULEB128 encoder         0x61bd410..0x61bd4e9
  * frame builder           0x61b1260..0x61b13a3

The tag-13 query is the fifth caller of the throttle gate pinned
in the open PR #3001 and #3004 packets: same gate, same
handler-chain walk shape, same framing and delivery, but the
largest of the family (2694 bytes) and the only one with a
count-mismatch prologue and a record loop. It takes two parallel
ranges -- a range of 16-byte {data pointer, length} records and
a range of 8-byte elements -- whose counts must agree; on a
mismatch it returns an error record (code 2) holding the message
"the CFs size and keys size does not match!" instead of building.
On the build path it walks nine handler links (tenth link's slot
when all nine match), then builds mask8 (bits 8, 9, 10) ||
LE32(count) || ULEB128(len(S2)) || S2 || ULEB128(len(S3)) || S3,
where S2 concatenates one LE32 per element (each from virtual
slot +0x18 on the element) and S3 concatenates one
ULEB128(len) || data per record. Virtual targets (slot +0x20,
slot +0x10, the handler slot +0x98, each element's slot +0x18)
are injected as callables so the behavior is testable without
the target's vtables.
"""

import struct

WALKER = 0x5D4D490
TAG_MASK = {3: 0x02, 4: 0x01, 5: 0x04, 6: 0x08, 13: 0x10}
MAX_STRING = 0x3FFFFFFFFFFFFFFF
LENGTH_ERROR = "basic_string::append"
MISMATCH_MESSAGE = b"the CFs size and keys size does not match!"
MISMATCH_CODE = 2


class LengthError(Exception):
    """Raised where the binary throws __throw_length_error."""


def uleb128(value):
    """The 0x61bd410 encoder: 1 byte to 0x7f, 2 to 0x3fff,
    3 to 0x1fffff, 4 to 0xfffffff, 5 above."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def set_bit(mask, bit):
    """The 0x61b18b0 flag-bit setter: returns (new mask, changed),
    where changed is 1 exactly when the bit was clear before."""
    new = mask | (1 << bit)
    return new, 1 if new != mask else 0


def check_append_room(size, needed):
    """The length guard every append in the query and the frame
    builder applies: remaining capacity must exceed the needed
    length, else __throw_length_error("basic_string::append")."""
    if MAX_STRING - size <= needed:
        raise LengthError(LENGTH_ERROR)


def join_mismatch_message(first, second):
    """The 0x61cf670 count-mismatch helper: returns first, or
    first + ": " + second when the second string is non-empty.
    The tag-13 query passes an empty second string, so the
    result is the first string alone."""
    if second:
        return first + b": " + second
    return first


class Obj:
    """The obj the query takes in rsi: chain head at +0x00, limit
    at +0x08, throttle limit at +0x10, flag bits at +0x18,
    delivery target at +0x28, throttle counter at +0x30. The
    target's slot +0x20 is injected as `slot20`."""

    def __init__(self, chain_head, limit8, limit10, flags18,
                 target, slot20):
        self.chain_head = chain_head
        self.limit8 = limit8
        self.limit10 = limit10
        self.flags18 = flags18
        self.target = target
        self.counter30 = 0
        self.slot20 = slot20


def limit_check(obj):
    """The 0x61b1910 limit check: 1 exactly when the limit at
    obj+0x08 is below the target slot +0x20 return (unsigned)."""
    return 1 if obj.limit8 < obj.slot20() else 0


def gate(obj, tag):
    """The 0x61b1930 throttle gate. Returns True exactly when the
    message must be built, False when the query must be skipped
    (and the out record zeroed). The gate mutates the throttle
    counter at obj+0x30 on the counter path. Tag 13 selects flag
    mask 0x10 through the jump table at 0x97c5f4."""
    if limit_check(obj):
        return False
    mask = TAG_MASK.get(tag)
    if mask is not None and obj.flags18 & mask:
        return False
    obj.counter30 += 1
    if obj.counter30 < obj.limit10:
        return False
    obj.counter30 = 0
    return True


def pick_handler(links):
    """The chain walk of the tag-13 query: links are the vtable
    slot +0x98 values of the ten links reachable via +0x20 from
    *(obj). Returns the index of the first link whose slot
    differs from the walker, or 9 when all nine comparisons pass
    (the tenth link's slot is then called unconditionally). Three
    links shallower than the tag-3/tag-4 queries, whose walk
    compares twelve links and calls the thirteenth."""
    if len(links) < 10:
        raise ValueError("the walk needs ten reachable links")
    for i in range(9):
        if links[i] != WALKER:
            return i
    return 9


def build_s2(elements):
    """The tag-13 query's first per-element string: one LE32 per
    element, each the u32 returned by virtual slot +0x18 on the
    element. `elements` is a list of zero-argument callables."""
    out = bytearray()
    for slot18 in elements:
        value = slot18()
        check_append_room(len(out), 4)
        out += struct.pack("<I", value & 0xFFFFFFFF)
    return bytes(out)


def build_s3(records):
    """The tag-13 query's second per-record string: one
    ULEB128(len) || data per 16-byte {data, length} record. The
    length is encoded from its low 32 bits while the full length
    is appended; each pair is appended unconditionally, even for
    a zero length."""
    out = bytearray()
    for data, length in records:
        if length > len(data):
            raise ValueError("record length exceeds supplied data")
        encoded = uleb128(length & 0xFFFFFFFF)
        check_append_room(len(out), len(encoded))
        out += encoded
        check_append_room(len(out), length)
        out += data[:length]
    return bytes(out)


def build_message_tag13(records, elements):
    """The tag-13 query's message: mask8 || LE32(count) ||
    ULEB128(len(S2)) || S2 || ULEB128(len(S3)) || S3. The mask
    has bits 8, 9 and 10 (0x700); count is the number of records
    (equal to the number of elements on this path); the two
    lengths are encoded from their low 32 bits."""
    if len(records) != len(elements):
        raise ValueError("record and element counts differ")
    mask = 0
    for bit in (8, 9, 10):
        mask, _ = set_bit(mask, bit)
    s2 = build_s2(elements)
    s3 = build_s3(records)
    out = bytearray()
    check_append_room(len(out), 8)
    out += struct.pack("<Q", mask)
    check_append_room(len(out), 4)
    out += struct.pack("<I", len(records) & 0xFFFFFFFF)
    encoded_s2 = uleb128(len(s2) & 0xFFFFFFFF)
    check_append_room(len(out), len(encoded_s2))
    out += encoded_s2
    check_append_room(len(out), len(s2))
    out += s2
    encoded_s3 = uleb128(len(s3) & 0xFFFFFFFF)
    check_append_room(len(out), len(encoded_s3))
    out += encoded_s3
    check_append_room(len(out), len(s3))
    out += s3
    return bytes(out)


def frame(handler_return, tag, message):
    """The 0x61b1260 frame builder: raw8(return) || byte(tag) ||
    LE32(len(message)) || message."""
    out = bytearray()
    check_append_room(len(out), 8)
    out += struct.pack("<Q", handler_return & 0xFFFFFFFFFFFFFFFF)
    check_append_room(len(out), 1)
    out.append(tag & 0xFF)
    check_append_room(len(out), 4)
    out += struct.pack("<I", len(message))
    check_append_room(len(out), len(message))
    out += message
    return bytes(out)


def zero_out_record():
    """The out record the query writes on the gate-true path:
    u32 0 at +0x00, u16 0 at +0x04, qword 0 at +0x08."""
    return {"u32": 0, "u16": 0, "qword": 0}


def error_out_record():
    """The out record the query writes on the count-mismatch
    path: u32 2 at +0x00, u16 0 at +0x04, and at +0x08 a pointer
    to a heap buffer holding MISMATCH_MESSAGE (modelled here as
    the message bytes themselves). Bytes 6..7 of the record are
    never written on this path."""
    return {"u32": MISMATCH_CODE, "u16": 0, "qword": MISMATCH_MESSAGE}


def tag13_query(obj, records, elements, handler=None, deliver=None):
    """The tag-13 inner query end to end. `records` is a list of
    (data bytes, length) pairs (the 16-byte-record range);
    `elements` is a list of zero-argument callables standing in
    for the virtual slot +0x18 call on each element of the
    qword range; `handler(link_index)` stands in for the
    chain-walk slot call and returns the handler's qword;
    `deliver(out, target, frame_bytes)` stands in for the
    target's virtual slot +0x10 and fills the out record.
    Returns (out record dict, frame bytes or None)."""
    if len(records) != len(elements):
        message = join_mismatch_message(MISMATCH_MESSAGE, b"")
        out = error_out_record()
        assert out["qword"] == message
        return out, None
    out = zero_out_record()
    if not gate(obj, 13):
        return out, None
    index = pick_handler(obj.chain_head)
    value = handler(index)
    message = build_message_tag13(records, elements)
    framed = frame(value, 13, message)
    deliver(out, obj.target, framed)
    return out, framed
