"""Model of node #115 routine 0x5963650: the shared allocation
boundary behind the buffer-growth family.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes six arguments and reports through a 24-byte
result struct instead of a return value:

  rdi = out (result struct), rsi = old size as the caller counts
  it (read ONLY for zero/non-zero), rdx = old data pointer,
  rcx = element count, r8 = alignment, r9 = element width.

End to end, in order:

1. Size guard. P = count * width (full 128-bit product considered:
   the byte size is the low 64 bits, and a product above 2^64 - 1
   is an overflow). The request fails at once when the product
   overflows OR P > 2^63 - alignment (unsigned; the limit itself
   wraps modulo 2^64, so an alignment above 2^63 raises the
   limit). Failure here writes tag 1 at out+0x00 and 0 at
   out+0x08, and leaves out+0x10 UNWRITTEN; no allocator is
   called.
2. Zero-size fresh request (old size == 0 and P == 0): no call;
   the result is tag 0, out+0x08 = alignment, out+0x10 = 0.
3. Dispatch. tz = trailing zero count of the alignment (the
   binary uses tzcnt; alignment 0 never reaches it because the
   plain test below accepts it first). The PLAIN form is chosen
   when (alignment < 0x11 and alignment <= P) or tz == 0 (which
   is exactly alignment == 1); otherwise the ALIGNED form, which
   receives tz as its extra argument.
   - old size != 0 (reallocation): plain calls the entry behind
     GOT slot 0x64df588 (0x635a7a0) with (old pointer, P); aligned
     calls the entry behind GOT slot 0x64df580 (0x635a790) with
     (old pointer, P, tz).
   - old size == 0 (fresh): plain calls the entry behind GOT
     slot 0x64df480 (0x6355830) with (P); aligned calls the entry
     behind GOT slot 0x64df590 (0x63577f0) with (P, tz).
4. Result publication. A non-null allocator return R gives
   tag 0, out+0x08 = R, out+0x10 = P. A null return gives tag 1,
   out+0x08 = alignment, out+0x10 = P. Callers compare the dword
   at out+0x00 against 1; on failure they hand (out+0x08,
   out+0x10) to the shared failure entry, so the failure pair is
   (0, unwritten) after the guard, (alignment, P) after a null
   return.

The routine writes nothing else: the result struct is its only
memory footprint besides its own stack frame. rax at the return
is a leftover store offset (8 after the guard failure, 0x10 on
every other exit), not a result channel.

NOT modelled: the four allocator callees' internals (cited by
slot and entry address only), and what count/width/alignment
denote for any particular caller beyond the product rule above.
"""

import struct

M64 = (1 << 64) - 1
GUARD_BASE = 0x8000000000000000

PLAIN_ALLOC = "alloc"                    # slot 0x64df480 -> 0x6355830
ALIGNED_ALLOC = "alloc_aligned"          # slot 0x64df590 -> 0x63577f0
PLAIN_REALLOC = "realloc"                # slot 0x64df588 -> 0x635a7a0
ALIGNED_REALLOC = "realloc_aligned"      # slot 0x64df580 -> 0x635a790

def _tzcnt(value):
    """Trailing zero count as the binary's tzcnt computes it;
    only called with values the plain test already rejected, but
    defined for 0 as well (64)."""
    if value == 0:
        return 64
    count = 0
    while value & 1 == 0:
        count += 1
        value >>= 1
    return count


def alloc_boundary(old_size, old_ptr, count, align, width, allocate,
                   initial=None):
    """Run the pinned behaviour.

    old_size, old_ptr, count, align, width: the five argument
    words after the result pointer (ints, taken modulo 2^64).
    allocate: callable(kind, args) -> int, standing in for the
    four GOT-slot callees; kind is one of PLAIN_ALLOC,
    ALIGNED_ALLOC, PLAIN_REALLOC, ALIGNED_REALLOC and args is the
    exact argument tuple the binary passes. A return of 0 models
    the allocator's null result.
    initial: optional 24 bytes the result struct starts with
    (default: all zero). Bytes the routine does not write are
    preserved, which is how the guard path's untouched +0x10 is
    observable.

    Returns (result_bytes, calls): the final 24-byte struct and
    the list of (kind, args) allocator calls made, in order.
    """
    old_size &= M64
    old_ptr &= M64
    count &= M64
    align &= M64
    width &= M64
    out = bytearray(initial if initial is not None else bytes(24))
    if len(out) != 24:
        raise ValueError("result struct is 24 bytes")
    calls = []

    full = count * width
    overflow = full > M64
    p = full & M64
    limit = (GUARD_BASE - align) & M64
    if overflow or p > limit:
        struct.pack_into("<Q", out, 0, 1)
        struct.pack_into("<Q", out, 8, 0)
        return bytes(out), calls

    if old_size == 0 and p == 0:
        struct.pack_into("<Q", out, 0, 0)
        struct.pack_into("<Q", out, 8, align)
        struct.pack_into("<Q", out, 16, 0)
        return bytes(out), calls

    tz = _tzcnt(align)
    plain = (align < 0x11 and align <= p) or tz == 0
    if old_size != 0:
        if plain:
            kind, args = PLAIN_REALLOC, (old_ptr, p)
        else:
            kind, args = ALIGNED_REALLOC, (old_ptr, p, tz)
    else:
        if plain:
            kind, args = PLAIN_ALLOC, (p,)
        else:
            kind, args = ALIGNED_ALLOC, (p, tz)
    calls.append((kind, args))
    result = allocate(kind, args) & M64
    if result != 0:
        struct.pack_into("<Q", out, 0, 0)
        struct.pack_into("<Q", out, 8, result)
        struct.pack_into("<Q", out, 16, p)
    else:
        struct.pack_into("<Q", out, 0, 1)
        struct.pack_into("<Q", out, 8, align)
        struct.pack_into("<Q", out, 16, p)
    return bytes(out), calls
