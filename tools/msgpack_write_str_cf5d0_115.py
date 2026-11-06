"""Model of node #115 MessagePack string writer 0x57cf5d0
(RE-001).

The routine appends one byte string to the node's shared byte
buffer in MessagePack str format: a header whose form is chosen
by the string length, then the payload bytes verbatim. Its own
FDE is 0x57cf5d0..0x57cf85a (650 bytes); it is reached by 903
direct calls in 440 caller FDEs and by nothing else (no tail
jumps, no stored pointers, no relocations naming it).

Pinned layout and contract (see
research/work-items/RE-001-msgpack-write-str-cf5d0-115/):

- rdi points at the buffer descriptor: +0x00 capacity in bytes,
  +0x08 data pointer, +0x10 current length. The descriptor is the
  same triple the buffer growth routine 0x5963a10 serves. This
  routine reads all three fields and stores the running length
  at +0x10 after every step; it never stores capacity or the
  data pointer itself (only the growth routine does).
- rsi = payload bytes pointer. rdx = payload length in bytes:
  the header decision reads only its low 32 bits (the compares
  are on %ebx/%ebp), while the payload capacity check and the
  memcpy count use the full 64-bit value in %rbx.
- The header, by the 32-bit length L:
    L < 0x20:      one byte, 0xa0 | L            (fixstr)
    L < 0x100:     0xd9, then L as one byte      (str 8)
    L < 0x10000:   0xda, then L big-endian u16   (str 16)
    otherwise:     0xdb, then L big-endian u32   (str 32)
- Append protocol: before every store of n bytes (n is 1, 2 or
  4 for the header pieces, the full string length for the
  payload) the routine compares the remaining capacity
  (capacity - length) with n; when remaining < n it calls the
  growth routine 0x5963a10 with (descriptor, current length,
  additional = n, rcx = 1, r8 = 1), reloads the data pointer
  and length, and stores without re-checking. The payload is a
  single memcpy through GOT slot 0x64df508
  (memcpy@GLIBC_2.14), skipped entirely when the length is 0.
- The single exit stores the constant pair rax = 2, rdx = 0
  and returns. There is no error path and no landing pad in the
  body: the FDE sits under CIE 0 (augmentation "zR") with
  augmentation length 0, so the routine has no LSDA.

The growth routine's body is cited, not pinned, by this packet
(it is the subject of the RE-001 buffer growth packet); the
model takes growth as an injected callable that receives
(length, additional) and must leave the buffer with capacity
>= length + additional, exactly what the routine assumes.
"""

ROUTINE = 0x57CF5D0
GROWTH_ROUTINE = 0x5963A10
MEMCPY_SLOT = 0x64DF508

RETURN_PAIR = (2, 0)


def header_bytes(length):
    """The MessagePack str header for a length, byte for byte.

    The decision reads only the low 32 bits of the length (the
    disassembly compares %ebx/%ebp), so the argument is masked
    first; the tiers and the big-endian length stores are the
    pinned table.
    """
    len32 = length & 0xFFFFFFFF
    if len32 < 0x20:
        return bytes([0xA0 | len32])
    if len32 < 0x100:
        return bytes([0xD9, len32])
    if len32 < 0x10000:
        return b"\xda" + len32.to_bytes(2, "big")
    return b"\xdb" + len32.to_bytes(4, "big")


class Buffer:
    """The buffer descriptor as this routine sees it.

    capacity (+0x00) and length (+0x10) are counts of bytes;
    data stands in for the allocation behind the +0x08 pointer
    and is always exactly capacity bytes long. grow_requests
    records every (length, additional) pair handed to the
    growth callable, in order.
    """

    def __init__(self, capacity=0, contents=b""):
        assert len(contents) <= capacity
        self.capacity = capacity
        self.data = bytearray(capacity)
        self.data[:len(contents)] = contents
        self.length = len(contents)
        self.grow_requests = []

    def bytes(self):
        return bytes(self.data[:self.length])


def pinned_growth(buf):
    """A growth callable with the 0x5963a10 policy for element
    size 1, as pinned by the buffer growth packet: new capacity
    is max(2 * capacity, length + additional, 8). Returns a
    callable taking (length, additional)."""

    def grow(length, additional):
        new_capacity = max(2 * buf.capacity, length + additional, 8)
        new_data = bytearray(new_capacity)
        new_data[:buf.length] = buf.data[:buf.length]
        buf.data = new_data
        buf.capacity = new_capacity

    return grow


def write_str(buf, payload, grow):
    """Append payload to buf in MessagePack str format.

    grow(length, additional) is the growth step: it is invoked
    exactly when a store of additional bytes would not fit, with
    the current length, and must leave capacity >= length +
    additional. Returns the routine's constant pair (2, 0).
    The payload length drives the header through its low 32
    bits and the payload step at full width, as pinned.
    """
    full_length = len(payload)
    header = header_bytes(full_length)

    def ensure(n):
        if buf.capacity - buf.length < n:
            buf.grow_requests.append((buf.length, n))
            grow(buf.length, n)

    def store(chunk):
        ensure(len(chunk))
        start = buf.length
        buf.data[start:start + len(chunk)] = chunk
        buf.length += len(chunk)

    # Header: the first byte is stored alone; the length bytes
    # of the str 8 / str 16 / str 32 forms follow as one store
    # of 1, 2 or 4 bytes, matching the body's store boundaries
    # (and therefore its growth-request boundaries).
    store(header[:1])
    if len(header) > 1:
        store(header[1:])
    # Payload: one capacity decision for the whole string, then
    # a single memcpy; a zero-length payload skips both.
    if full_length:
        ensure(full_length)
        start = buf.length
        buf.data[start:start + full_length] = payload
        buf.length += full_length
    return RETURN_PAIR
