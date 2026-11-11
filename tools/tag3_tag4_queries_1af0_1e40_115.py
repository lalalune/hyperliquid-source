"""Python model of the node #115 tag-3 and tag-4 inner queries pinned
by RE-001-tag3-tag4-queries-1af0-1e40-115.

Routines (node #115, work/hl-node-115.bin):
  * tag-3 inner query       0x61b1af0..0x61b1e18
  * tag-4 inner query       0x61b1e40..0x61b21ca
  * throttle gate           0x61b1930..0x61b19e7
  * limit check             0x61b1910..0x61b192b
  * flag-bit setter         0x61b18b0..0x61b18c8
  * frame-and-deliver       0x61b1a10..0x61b1ac6
  * ULEB128 encoder         0x61bd410..0x61bd4e9
  * frame builder           0x61b1260..0x61b13a3

The two queries are siblings of the tag-5/tag-6 twins pinned in the
open PR #3001 packet: same throttle gate, same handler-chain walk,
same message framing and delivery, but different tags (3 and 4),
a one-link-deeper walk (twelve comparisons, thirteenth link), and
different payloads. Tag 3 builds mask8 || ULEB128(len) || data
from one {data, length} pair read at +0x40/+0x48 of its third
argument. Tag 4 builds mask8 || LE32(slot +0x18 on its third
argument) || ULEB128(len) || data from the {data, length} pair its
fourth argument points at. Virtual targets (slot +0x20, slot
+0x10, the handler slot +0x98, tag 4's slot +0x18) are injected as
callables so the behavior is testable without the target's
vtables.
"""

import struct

WALKER = 0x5D4D490
TAG_MASK = {3: 0x02, 4: 0x01, 5: 0x04, 6: 0x08, 13: 0x10}
MAX_STRING = 0x3FFFFFFFFFFFFFFF
LENGTH_ERROR = "basic_string::append"


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
    """The length guard every append in the queries and the frame
    builder applies: remaining capacity must exceed the needed
    length, else __throw_length_error("basic_string::append")."""
    if MAX_STRING - size <= needed:
        raise LengthError(LENGTH_ERROR)


class Obj:
    """The obj the queries take in rsi: chain head at +0x00, limit
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
    counter at obj+0x30 on the counter path."""
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
    """The chain walk of the tag-3/tag-4 queries: links are the
    vtable slot +0x98 values of the thirteen links reachable via
    +0x20 from *(obj). Returns the index of the first link whose
    slot differs from the walker, or 12 when all twelve
    comparisons pass (the thirteenth link's slot is then called
    unconditionally). One link deeper than the tag-5/tag-6 twins,
    whose walk compares eleven links and calls the twelfth."""
    if len(links) < 13:
        raise ValueError("the walk needs thirteen reachable links")
    for i in range(12):
        if links[i] != WALKER:
            return i
    return 12


def build_message_tag3(pair):
    """The tag-3 query's message: mask8 || ULEB128(len) || data.
    The pair is (data bytes, length), read by the binary from
    +0x40/+0x48 of its third argument. The mask has bit 1 only
    (0x02); the length and the bytes are appended unconditionally,
    even for a zero length (which appends a single 0x00 varint
    byte and no data)."""
    data, length = pair
    if length > len(data):
        raise ValueError("pair length exceeds supplied data")
    mask, _ = set_bit(0, 1)
    out = bytearray()
    check_append_room(len(out), 8)
    out += struct.pack("<Q", mask)
    encoded = uleb128(length & 0xFFFFFFFF)
    check_append_room(len(out), len(encoded))
    out += encoded
    check_append_room(len(out), length)
    out += data[:length]
    return bytes(out)


def build_message_tag4(slot18_value, pair):
    """The tag-4 query's message: mask8 || LE32(slot +0x18
    result) || ULEB128(len) || data. The pair is (data bytes,
    length), read by the binary from +0x00/+0x08 of its fourth
    argument; slot18_value is the u32 the binary obtains by
    calling virtual slot +0x18 on its third argument. The mask
    has bits 2 and 3 (0x0c); the length and the bytes are
    appended unconditionally, even for a zero length."""
    data, length = pair
    if length > len(data):
        raise ValueError("pair length exceeds supplied data")
    mask = 0
    mask, _ = set_bit(mask, 2)
    mask, _ = set_bit(mask, 3)
    out = bytearray()
    check_append_room(len(out), 8)
    out += struct.pack("<Q", mask)
    check_append_room(len(out), 4)
    out += struct.pack("<I", slot18_value & 0xFFFFFFFF)
    encoded = uleb128(length & 0xFFFFFFFF)
    check_append_room(len(out), len(encoded))
    out += encoded
    check_append_room(len(out), length)
    out += data[:length]
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
    """The out record the queries write on the gate-true path:
    u32 0 at +0x00, u16 0 at +0x04, qword 0 at +0x08."""
    return {"u32": 0, "u16": 0, "qword": 0}


def tag3_query(obj, pair, handler=None, deliver=None):
    """The tag-3 inner query end to end. `handler(link_index)`
    stands in for the chain-walk slot call and returns the
    handler's qword; `deliver(out, target, frame_bytes)` stands
    in for the target's virtual slot +0x10 and fills the out
    record. Returns (out record dict, frame bytes or None)."""
    out = zero_out_record()
    if not gate(obj, 3):
        return out, None
    index = pick_handler(obj.chain_head)
    value = handler(index)
    message = build_message_tag3(pair)
    framed = frame(value, 3, message)
    deliver(out, obj.target, framed)
    return out, framed


def tag4_query(obj, slot18, pair, handler=None, deliver=None):
    """The tag-4 inner query end to end. `slot18()` stands in
    for the virtual slot +0x18 call on the third argument and
    returns its u32; `handler(link_index)` and `deliver(out,
    target, frame_bytes)` are as in tag3_query. Returns (out
    record dict, frame bytes or None)."""
    out = zero_out_record()
    if not gate(obj, 4):
        return out, None
    index = pick_handler(obj.chain_head)
    value = handler(index)
    message = build_message_tag4(slot18(), pair)
    framed = frame(value, 4, message)
    deliver(out, obj.target, framed)
    return out, framed
