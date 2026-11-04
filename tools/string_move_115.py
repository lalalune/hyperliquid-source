"""Model of the node #115 string move helper at 0x5d49a10.

A string object is three fields: a pointer, a size, and a
capacity-or-inline slot. The object is inline (short-string
optimization) exactly when its pointer equals its own inline
buffer address; otherwise the pointer names a heap buffer whose
usable length is capacity + 1 (the extra byte holds the NUL).

move_assign(dst, src) implements the helper exactly as traced
from the disassembly:

* Heap source: the destination takes over the source's heap
  buffer, size, and capacity. The source is left empty: it takes
  the destination's old heap buffer when the destination was
  heap-allocated (that buffer keeps its bytes except byte 0,
  which is set to NUL, and its capacity), and it becomes an
  empty inline string (its own inline buffer, byte 0 NUL) when
  the destination was inline or had a null pointer. The
  destination's old inline bytes are simply abandoned.
* Inline source: the destination keeps its own buffer and
  capacity; the source's bytes are copied into it (a one-byte
  source takes the single-byte fast path, an empty source
  writes only the NUL), the destination size becomes the
  source size, and a NUL is written just past the copied
  bytes. The source is left empty: size 0, byte 0 NUL, pointer
  and capacity unchanged.
* Self move (dst is src): the string is emptied -- size 0 and
  byte 0 NUL, pointer and capacity unchanged -- except that a
  null pointer becomes the inline buffer address first. This
  is what the code does; it is not smoothed over.

The helper returns nothing. Guards raise where the binary
would dereference unchecked memory (a null destination
pointer on the inline-source copy path, or a destination
buffer too small for the copied bytes); live strings never
hit those paths, because a heap buffer always holds at
least 16 bytes and an inline source holds at most 15.
"""

INLINE_CAPACITY = 15


class HeapBuffer:
    """A heap string buffer of capacity + 1 bytes (extra: NUL)."""

    def __init__(self, data=b"", capacity=None):
        if capacity is None:
            capacity = max(INLINE_CAPACITY, len(data))
        self.capacity = capacity
        self.data = bytearray(capacity + 1)
        self.data[:len(data)] = data
        self.data[len(data)] = 0

    def content(self):
        return bytes(self.data)


class StringObj:
    """A modeled string object: pointer, size, capacity/inline."""

    def __init__(self, data=b"", heap=False, capacity=None,
                 null_pointer=False):
        self.inline_buf = bytearray(16)
        if null_pointer:
            self.ptr = None
            self.buf = None
            self.size = len(data)
            self.capacity = capacity
            return
        if heap or len(data) > INLINE_CAPACITY:
            self.buf = HeapBuffer(data, capacity)
            self.ptr = self.buf
            self.capacity = self.buf.capacity
        else:
            self.buf = None
            self.ptr = "inline"
            self.capacity = None
            self.inline_buf[:len(data)] = data
            self.inline_buf[len(data)] = 0
        self.size = len(data)

    @property
    def is_inline(self):
        return self.ptr == "inline"

    def buffer(self):
        """The bytearray the pointer currently names."""
        if self.ptr is None:
            return None
        if self.ptr == "inline":
            return self.inline_buf
        return self.ptr.data

    def content(self):
        """The string's bytes as the binary would expose them."""
        buf = self.buffer()
        if buf is None:
            return b""
        return bytes(buf[:self.size])


def move_assign(dst, src):
    """Move src into dst, following 0x5d49a10 branch for branch."""
    if dst is src:
        if dst.ptr is None:
            dst.ptr = "inline"
        buf = dst.buffer()
        dst.size = 0
        buf[0] = 0
        return None
    src_heap = src.ptr is not None and src.ptr != "inline"
    if src_heap:
        old_ptr = dst.ptr
        old_cap = dst.capacity
        old_buf = dst.buffer()
        new_buf = src.ptr
        new_size = src.size
        new_cap = src.capacity
        dst.ptr = new_buf
        dst.size = new_size
        dst.capacity = new_cap
        if old_ptr is None or old_ptr == "inline":
            src.ptr = "inline"
            src.capacity = None
            src.size = 0
            src.inline_buf[0] = 0
        else:
            src.ptr = old_ptr
            src.capacity = old_cap
            src.size = 0
            old_buf[0] = 0
        return None
    # Inline source: copy into the destination's own buffer.
    dst_buf = dst.buffer()
    if dst_buf is None:
        raise ValueError("null destination pointer on copy path")
    if src.size > len(dst_buf) - 1:
        raise ValueError("destination buffer too small for copy")
    dst_buf[:src.size] = src.inline_buf[:src.size]
    dst.size = src.size
    dst_buf[dst.size] = 0
    src.size = 0
    src.inline_buf[0] = 0
    return None
