"""Tests for tools/string_move_115.py (node #115 string move helper).

The model is validated against target-grounded expectations: a
heap source is taken over by buffer exchange, an inline source
is copied into the destination's own buffer, the source is
always left empty, and a self move empties the string.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from string_move_115 import HeapBuffer, StringObj, move_assign

_checks = []


def check(name, cond):
    _checks.append((name, bool(cond)))
    if not cond:
        print("FAIL:", name)


def heap(data, capacity=None):
    return StringObj(data, heap=True, capacity=capacity)


def inline(data):
    return StringObj(data)


# Heap source into a heap destination: buffer exchange.
dst = heap(b"old-destination-data", capacity=32)
src = heap(b"hello", capacity=20)
old_dst_buf = dst.ptr
old_src_buf = src.ptr
move_assign(dst, src)
check("heap->heap dst takes src content", dst.content() == b"hello")
check("heap->heap dst takes src buffer", dst.ptr is old_src_buf)
check("heap->heap dst takes src capacity", dst.capacity == 20)
check("heap->heap src takes old dst buffer", src.ptr is old_dst_buf)
check("heap->heap src takes old dst capacity", src.capacity == 32)
check("heap->heap src emptied", src.size == 0 and src.content() == b"")
check("heap->heap src old buffer NUL at 0",
      old_dst_buf.data[0] == 0)
check("heap->heap src old buffer keeps tail",
      bytes(old_dst_buf.data[1:4]) == b"ld-")

# Heap source into an inline destination: src becomes inline-empty.
dst = inline(b"tiny")
src = heap(b"a much longer heap string", capacity=40)
old_src_buf = src.ptr
move_assign(dst, src)
check("heap->inline dst takes src content",
      dst.content() == b"a much longer heap string")
check("heap->inline dst takes src buffer", dst.ptr is old_src_buf)
check("heap->inline src is inline", src.is_inline)
check("heap->inline src emptied", src.size == 0)
check("heap->inline src inline NUL at 0", src.inline_buf[0] == 0)

# Inline source into a heap destination: copy, dst keeps its buffer.
dst = heap(b"previous heap contents here", capacity=32)
src = inline(b"copy-me")
old_dst_buf = dst.ptr
move_assign(dst, src)
check("inline->heap dst content copied", dst.content() == b"copy-me")
check("inline->heap dst keeps buffer", dst.ptr is old_dst_buf)
check("inline->heap dst keeps capacity", dst.capacity == 32)
check("inline->heap src emptied", src.size == 0)
check("inline->heap src inline NUL at 0", src.inline_buf[0] == 0)

# Inline source into an inline destination: copy.
dst = inline(b"old")
src = inline(b"new-value")
move_assign(dst, src)
check("inline->inline dst content", dst.content() == b"new-value")
check("inline->inline dst stays inline", dst.is_inline)
check("inline->inline src emptied", src.size == 0)

# Empty inline source: destination size 0 with a NUL, source emptied.
dst = heap(b"nonempty", capacity=32)
src = inline(b"")
move_assign(dst, src)
check("empty src dst size 0", dst.size == 0 and dst.content() == b"")
check("empty src dst NUL at 0", dst.buffer()[0] == 0)
check("empty src src emptied", src.size == 0)

# One-byte inline source: the single-byte fast path, same effect.
dst = inline(b"zzzz")
src = inline(b"q")
move_assign(dst, src)
check("one-byte dst content", dst.content() == b"q")
check("one-byte dst NUL past byte", dst.buffer()[1] == 0)
check("one-byte src emptied", src.size == 0)

# Maximum inline source (15 bytes) into an inline destination.
dst = inline(b"")
src = inline(b"123456789012345")
move_assign(dst, src)
check("15-byte dst content", dst.content() == b"123456789012345")
check("15-byte dst NUL at 15", dst.buffer()[15] == 0)
check("15-byte src emptied", src.size == 0)

# Self move empties, for both heap and inline strings.
obj = heap(b"self heap", capacity=24)
buf = obj.ptr
move_assign(obj, obj)
check("self heap emptied", obj.size == 0 and obj.content() == b"")
check("self heap keeps buffer", obj.ptr is buf)
check("self heap keeps capacity", obj.capacity == 24)
check("self heap NUL at 0", buf.data[0] == 0)
obj = inline(b"self inline")
move_assign(obj, obj)
check("self inline emptied", obj.size == 0 and obj.content() == b"")
check("self inline stays inline", obj.is_inline)
check("self inline NUL at 0", obj.inline_buf[0] == 0)

# Null-pointer destination with a heap source: src goes inline-empty.
dst = StringObj(b"", null_pointer=True)
src = heap(b"takeover", capacity=20)
old_src_buf = src.ptr
move_assign(dst, src)
check("null dst takes src buffer", dst.ptr is old_src_buf)
check("null dst content", dst.content() == b"takeover")
check("null dst src inline-empty",
      src.is_inline and src.size == 0)

# Guards: paths the binary leaves unchecked raise instead of
# silently producing a wrong model.
try:
    move_assign(StringObj(b"", null_pointer=True), inline(b"x"))
    check("null dst copy path raises", False)
except ValueError:
    check("null dst copy path raises", True)
try:
    small = StringObj(b"", heap=True, capacity=16)
    small.ptr.data = bytearray(4)
    move_assign(small, inline(b"123456789012345"))
    check("undersized dst copy raises", False)
except ValueError:
    check("undersized dst copy raises", True)

# HeapBuffer helper sanity: capacity + 1 bytes, NUL terminated.
buf = HeapBuffer(b"abc", capacity=10)
check("heap buffer length", len(buf.data) == 11)
check("heap buffer NUL", buf.data[3] == 0)


def main():
    failed = [name for name, ok in _checks if not ok]
    print("%d checks, %d failed" % (len(_checks), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
