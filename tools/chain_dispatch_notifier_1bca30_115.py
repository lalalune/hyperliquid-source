"""Model of node #115 routine 0x61bca30 (FDE 0x61bca30..0x61bcd5a)
and its expected-slot walker 0x5d4d490, ULEB128 encoder 0x61bd410 and
frame builder 0x61b1260.

The routine resolves a handler from a +0x20 chain, builds a message
from a runtime tag string, frames the handler's return value, and
delivers the frame through a virtual call.  Everything here is pinned
to the disassembly in
research/work-items/RE-001-chain-dispatch-notifier-1bca30-115/;
see that packet's README.md for the field map and the per-branch
derivation.  The model records an observable-effect trace instead of
touching real memory: handler selection, message bytes, frame bytes,
the delivery record and the frees are trace entries, in the order
the routine produces them.

Chain layout (subobject at rsi):
  +0x00  chain head pointer (links continue at link +0x20)
  +0x28  delivery-target object (vtable slot +0x10 is the deliver call)
Each link's handler is its vtable slot +0x98.  The global at
0x64ecf80 holds 0x5d4d490 after relocation (RELATIVE, addend
0x5d4d490); that is the expected slot value for the head link.

0x61bca30 walk rule (four comparisons, fifth link unconditional):
  slot(head) vs *(0x64ecf80); then slot(link k) vs slot(link k-1)
  for k = 1, 2, 3; the first mismatch selects that link; if all four
  comparisons pass, link 4 is selected.  The selected link's slot
  function is called with (link, rsi, rbx = &message); its return
  value is saved and framed.

0x5d4d490 walk rule (eight comparisons, ninth link unconditional):
  starts at *(rdi + 0x20); slot(link k) vs the previous slot for
  k = 1..8, the first comparison against *(0x64ecf80); the first
  mismatch tail-jumps to that link's slot; if all eight pass, the
  ninth link's slot is tail-jumped to.  No stack frame, no return.

Message (string at rsp+0x68):
  ULEB128(len(tag)) || tag bytes || LE32(8) || LE32(1)
  where tag is the BSS std::string at 0x6508800 (data +0x00,
  size +0x08); its bytes are not retained in the file, so callers
  supply the tag.  Each append requires its length to be at most
  0x3fffffffffffffff - size, else __throw_length_error.

Frame (0x61b1260, value block at rsp+0x50):
  raw 8 bytes of the return value || one flag byte (1) ||
  LE32(len(message)) || message bytes
  The flag byte is the value block's +0x08 byte, set to 1 by the
  routine; the message string fields are the block's +0x18/+0x20.

Delivery: virtual call slot +0x10 on the object at *(rsi + 0x28)
with (rdi = owner, rsi = that object, rdx = &{data, size} view of
the framed string).  The target is virtual and not pinned to one
address, so the model records the delivery as data.

Caller (FDE 0x61bcde0..0x61bcee4, sole call site 0x61bcebd):
  when *(rbx + 0x60) is non-null it writes the header (11, 0, 0)
  into the owner and skips the notify; when null it allocates a
  0x30-byte subobject, builds it with 0x61bc290, stores it at
  *(rbx + 0x60) with byte *(rbx + 0x68) = 1, then calls 0x61bca30
  exactly once and afterwards calls 0x60d52f0 on (rsi + 0x20).
"""

MAX_STRING = 0x3FFFFFFFFFFFFFFF
EXPECTED_SLOT = 0x5D4D490
TAG_GLOBAL = 0x6508800
EXPECTED_GLOBAL = 0x64ECF80


class LengthError_(ValueError):
    """__throw_length_error (PLT 0x63f0de0)."""


def append_checked(size, add):
    """Mirror one length guard: the append is allowed exactly when
    add <= 0x3fffffffffffffff - size, else the length error fires."""
    if add > MAX_STRING - size:
        raise LengthError_("basic_string::append")
    return size + add


def uleb128_encode(value):
    """0x61bd410: ULEB128 of a u32 into the output, returns the bytes.
    1 byte to 0x7f, 2 to 0x3fff, 3 to 0x1fffff, 4 to 0xfffffff,
    5 above; the fifth byte holds value >> 28."""
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("uleb128 input is a u32 (esi)")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_message(tag):
    """0x61bca30 message phase: varint(len(tag)) || tag ||
    LE32(8) || LE32(1), with a length guard before each append."""
    size = 0
    parts = []
    encoded = uleb128_encode(len(tag))
    size = append_checked(size, len(encoded))
    parts.append(encoded)
    size = append_checked(size, len(tag))
    parts.append(tag)
    size = append_checked(size, 4)
    parts.append((8).to_bytes(4, "little"))
    size = append_checked(size, 4)
    parts.append((1).to_bytes(4, "little"))
    return b"".join(parts)


def build_frame(value, flag, message):
    """0x61b1260: raw 8 bytes of value || one flag byte ||
    LE32(len(message)) || message, with a length guard before
    each append."""
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("frame value is one qword")
    if not 0 <= flag <= 0xFF:
        raise ValueError("frame flag is one byte")
    size = 0
    parts = []
    raw = value.to_bytes(8, "little")
    size = append_checked(size, 8)
    parts.append(raw)
    size = append_checked(size, 1)
    parts.append(bytes([flag]))
    size = append_checked(size, 4)
    parts.append(len(message).to_bytes(4, "little"))
    size = append_checked(size, len(message))
    parts.append(message)
    return b"".join(parts)


def walk_chain(slots, expected=EXPECTED_SLOT):
    """0x61bca30 selection: index of the link whose slot function
    is called.  slots[0] is the head link; at least five links are
    required (the routine never checks for a null link)."""
    if len(slots) < 5:
        raise ValueError("chain needs at least five links")
    if slots[0] != expected:
        return 0
    for k in (1, 2, 3):
        if slots[k] != slots[k - 1]:
            return k
    return 4


def walk_expected(slots, expected=EXPECTED_SLOT):
    """0x5d4d490 selection: slots[0] is the first link after the
    head; eight pairwise comparisons, ninth link unconditional."""
    if len(slots) < 9:
        raise ValueError("walker needs at least nine links")
    if slots[0] != expected:
        return 0
    for k in range(1, 8):
        if slots[k] != slots[k - 1]:
            return k
    return 8


def dispatch(chain_slots, tag, value, owner, target, flag=1,
             expected=EXPECTED_SLOT):
    """End-to-end trace of one 0x61bca30 call: select the handler
    link, build the message, frame the handler's return value, and
    record the delivery.  The slot-0x98 handler itself is virtual,
    so its return value is supplied as `value`."""
    trace = []
    selected = walk_chain(chain_slots, expected)
    trace.append(("select", selected, chain_slots[selected]))
    message = build_message(tag)
    trace.append(("message", message))
    frame = build_frame(value, flag, message)
    trace.append(("frame", frame))
    trace.append(("deliver", owner, target,
                  {"data": frame, "size": len(frame)}))
    trace.append(("free", "message"))
    trace.append(("free", "frame"))
    trace.append(("return", owner))
    return trace


def caller_once(slot_present, chain_slots, tag, value, owner, target):
    """One call of the sole caller (FDE 0x61bcde0..0x61bcee4):
    with the slot present it writes the header and skips the
    notify; with the slot null it builds the subobject and then
    runs the dispatch above."""
    if slot_present:
        return [("header_write", owner, (11, 0, 0)),
                ("call_60d52f0",), ("return", owner)]
    trace = [("construct_subobject", 0x30),
             ("store_slot",), ("flag_byte", 1)]
    trace.extend(dispatch(chain_slots, tag, value, owner, target))
    trace.append(("call_60d52f0",))
    return trace
