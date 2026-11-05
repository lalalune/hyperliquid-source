"""Python model of the node #115 twin inner queries pinned by
RE-001-twin-inner-queries-21f0-2760-115.

Routines (node #115, work/hl-node-115.bin):
  * twin inner query, tag 5  0x61b21f0..0x61b2738
  * twin inner query, tag 6  0x61b2760..0x61b2ca8
  * throttle gate           0x61b1930..0x61b19e7
  * limit check             0x61b1910..0x61b192b
  * flag-bit setter         0x61b18b0..0x61b18c8
  * frame-and-deliver       0x61b1a10..0x61b1ac6
  * ULEB128 encoder         0x61bd410..0x61bd4e9
  * frame builder           0x61b1260..0x61b13a3

The twins are one routine compiled twice: the tag byte (0x5 or
0x6) is the only semantic difference. The gate decides whether a
message is built; the chain walk picks a handler; the message is
mask || LE32(u32) || length-prefixed pairs; the frame is the
handler return || tag || LE32(message length) || message, delivered
by the target's virtual slot +0x10. Virtual targets (slot +0x20,
slot +0x10, the handler slot +0x98) are injected as callables so
the behavior is testable without the target's vtables.
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
    """The length guard every append in the twins and the frame
    builder applies: remaining capacity must exceed the needed
    length, else __throw_length_error("basic_string::append")."""
    if MAX_STRING - size <= needed:
        raise LengthError(LENGTH_ERROR)


class Obj:
    """The obj the twins take in rsi: chain head at +0x00, limit
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
    """The chain walk: links are the vtable slot +0x98 values of
    the twelve links reachable via +0x20 from *(obj). Returns the
    index of the first link whose slot differs from the walker,
    or 11 when all eleven comparisons pass (the twelfth link's
    slot is then called unconditionally)."""
    if len(links) < 12:
        raise ValueError("the walk needs twelve reachable links")
    for i in range(11):
        if links[i] != WALKER:
            return i
    return 11


def build_message(u32, pair_a, pair_b=None, pair_c=None):
    """The twins' message: mask8 || LE32(u32) || ULEB128(lenA) ||
    A || [ULEB128(lenB) || B] || [ULEB128(lenC) || C]. Each pair
    is (data bytes, length); a pair is present exactly when its
    length is nonzero. The mask has bits 4 and 5 always set, bit
    6 exactly when pair B is present, bit 7 exactly when pair C
    is present."""
    mask = 0
    mask, _ = set_bit(mask, 4)
    mask, _ = set_bit(mask, 5)
    if pair_b is not None and pair_b[1] != 0:
        mask, _ = set_bit(mask, 6)
    if pair_c is not None and pair_c[1] != 0:
        mask, _ = set_bit(mask, 7)
    out = bytearray()
    check_append_room(len(out), 8)
    out += struct.pack("<Q", mask)
    check_append_room(len(out), 4)
    out += struct.pack("<I", u32 & 0xFFFFFFFF)
    for pair in (pair_a, pair_b, pair_c):
        if pair is None or pair[1] == 0:
            continue
        data, length = pair
        if length > len(data):
            raise ValueError("pair length exceeds supplied data")
        encoded = uleb128(length)
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
    """The out record the twins write on the gate-true path:
    u32 0 at +0x00, u16 0 at +0x04, qword 0 at +0x08."""
    return {"u32": 0, "u16": 0, "qword": 0}


def caller_out_copy(twin_out):
    """What the callers (0x5d55451 / 0x5d555b1) copy from the
    twin's out record into their own out: the u32 at +0x00 and
    the u16 at +0x04."""
    return (twin_out["u32"], twin_out["u16"])


def twin_query(obj, tag, u32, pair_a, pair_b=None, pair_c=None,
               handler=None, deliver=None):
    """One twin inner query end to end. `handler(link_index)`
    stands in for the chain-walk slot call and returns the
    handler's qword; `deliver(out, target, frame_bytes)` stands
    in for the target's virtual slot +0x10 and fills the out
    record. Returns (out record dict, frame bytes or None)."""
    out = zero_out_record()
    if not gate(obj, tag):
        return out, None
    index = pick_handler(obj.chain_head)
    value = handler(index)
    message = build_message(u32, pair_a, pair_b, pair_c)
    framed = frame(value, tag, message)
    deliver(out, obj.target, framed)
    return out, framed
