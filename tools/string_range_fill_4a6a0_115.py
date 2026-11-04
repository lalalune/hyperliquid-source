"""Model of node #115 string range-fill, 0x5d4a6a0..0x5d4a743 (RE-001).

The routine fills a libstdc++-layout string object from a byte range
(rdi = destination object, rsi = begin, rdx = end, exclusive; the
length is end - begin). The object layout pinned by the disassembly
is: +0x00 data pointer, +0x08 size, +0x10 capacity. The routine
itself reads the destination's +0x00 pointer as the writable buffer;
callers observed in the census set that pointer to the object's own
inline buffer (destination + 0x10) before calling, i.e. a fresh
small-string object.

Pinned algorithm (see research/work-items/RE-001-string-range-fill-4a6a0-115/):

1. Length at most 15: copy the range into the buffer the +0x00
   pointer already names. A one-byte range takes a single-byte copy
   (0x5d4a6d7); any other length takes memcpy (0x5d4a729), and the
   empty range copies nothing. The +0x10 capacity field is not
   touched on this path, and no allocation or free runs.
2. Length at least 16: call the string _M_create PLT stub with the
   length as the capacity variable and old capacity 0, store the
   returned pointer to +0x00 and the (updated) capacity to +0x10,
   then memcpy the range into the new buffer. The exact capacity
   _M_create chooses is not pinned by this routine's excerpt, only
   that it is at least the length; the model records capacity as
   at least the length and tests assert only that bound.
3. Common tail: store the length to +0x08 and a NUL byte at
   buffer + length, then return the destination pointer. The
   routine never frees a previous buffer: on the long path a
   previous heap pointer in +0x00 is simply replaced.
4. Stack-canary check, then return.

The model requires the short-path precondition the callers
establish: the +0x00 pointer must name a buffer of at least
length + 1 bytes (the fresh inline buffer satisfies this for
lengths up to 15). The model raises ValueError when a short copy
would overflow the supplied buffer, as a model-only guard, not a
binary claim (the binary copies with no check).
"""

SSO_LIMIT = 15


class StringObject:
    """A libstdc++-layout string object as the routine sees it."""

    def __init__(self, buffer=None, size=0, capacity=SSO_LIMIT,
                 inline=True):
        # Fresh objects: buffer is the 16-byte inline area and the
        # data pointer names it. ``buffer`` is a bytearray whose
        # length is the writable area; ``inline`` tracks whether
        # the data pointer names that inline area (True) or a heap
        # allocation (False).
        self.buffer = bytearray(16) if buffer is None else bytearray(buffer)
        self.size = size
        self.capacity = capacity
        self.inline = inline
        self.abandoned_heap_buffer = False

    @property
    def data(self):
        return bytes(self.buffer[:self.size])

    @property
    def terminator(self):
        return self.buffer[self.size] if self.size < len(self.buffer) else None


def fresh_string():
    """A fresh string object as the census callers prepare it."""
    return StringObject()


def string_range_fill(dest, source):
    """Fill ``dest`` from ``source`` bytes, exactly as 0x5d4a6a0 does.

    Returns the destination object. ``source`` may contain NUL
    bytes; the copy is by length, not by terminator.
    """
    if not isinstance(source, (bytes, bytearray)):
        raise TypeError("source must be bytes")
    length = len(source)
    if length <= SSO_LIMIT:
        if length + 1 > len(dest.buffer):
            raise ValueError("short copy would overflow the buffer")
        # Length 1 takes the single-byte path, every other short
        # length takes memcpy; both copy exactly ``length`` bytes.
        dest.buffer[:length] = source
        dest.buffer[length] = 0
        # Capacity untouched on the short path.
    else:
        # _M_create path: the previous +0x00 pointer is replaced
        # without a free. Only a previous heap buffer is thereby
        # abandoned; a fresh inline buffer simply stops being the
        # data pointer, as in a normal SSO-to-heap transition.
        if not dest.inline:
            dest.abandoned_heap_buffer = True
        dest.buffer = bytearray(source) + bytearray(1)
        dest.capacity = length  # lower bound only; _M_create may round up
        dest.inline = False
    dest.size = length
    return dest
