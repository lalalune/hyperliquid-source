"""Python model of node #115 hash-bucket projection (0x5f099b0).

One whole function from the digest-verified node #115 work binary
(work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):
given a host object holding a table span and a key slice, it returns
the address of the table entry the key hashes to.

Window, in order:

1. Span: rbx = (host + 0xc48) - (host + 0xc40), arithmetic-shifted
   right by 3, so rbx is the span counted in 8-byte units.
2. Scale: rbx = rbx * 0x6db6db6db6db6db7 (mod 2**64). That
   constant is the modular inverse of 7 modulo 2**64
   (0x6db6db6db6db6db7 * 7 mod 2**64 == 1), so when the span is a
   whole number of 56-byte entries, the scaled value is exactly the
   entry count: a span of 56 * k bytes gives k. The window performs
   no divisibility check; for any other span the scaled value is
   whatever the low 64 bits of the product give, and the caller is
   responsible for passing a whole-entry span.
3. Hash: the key slice (pointer at record + 0x00, length at
   record + 0x08) is hashed by callee 0x61c38a0 (cited by contract
   only -- callers pass a hash function in).
4. Bucket: the window multiplies the 64-bit hash by the scaled
   count with a 32-bit-limb widening multiply and keeps the high
   64 bits, i.e. bucket = (hash * scaled_count) >> 64. When the
   scaled count is the entry count k, bucket is in [0, k).
5. Result: rax = (host + 0xc40) + 56 * bucket, computed as
   base + (bucket * 7) * 8. The function returns that entry address;
   it writes nothing and has no failure path.

The hash callee's body is not modelled: it is an input to this
model, exactly as the window treats it as a black-box call.
"""

MASK64 = (1 << 64) - 1
MAGIC = 0x6DB6DB6DB6DB6DB7
ENTRY_BYTES = 56
QWORDS_PER_ENTRY = 7


def _signed64(value):
    value &= MASK64
    return value - (1 << 64) if value >= (1 << 63) else value


def scaled_count(span_bytes):
    """The window's scaled count for a table span in bytes.

    Mirrors the sub / sar / imul sequence: the span is a signed
    64-bit difference, shifted arithmetically by 3, then multiplied
    by MAGIC with only the low 64 bits kept.
    """
    units = _signed64(span_bytes) >> 3
    return (units * MAGIC) & MASK64


def limb_high_product(hash_value, scaled):
    """The window's widening multiply, transcribed limb by limb.

    Computes (hash_value * scaled) >> 64 using only 32-bit limbs,
    following the window's instruction sequence (low/high halves
    crossed and carried the same way). Used by the tests to prove
    the transcription equals the closed form.
    """
    h_lo = hash_value & 0xFFFFFFFF
    h_hi = (hash_value >> 32) & 0xFFFFFFFF
    m_lo = scaled & 0xFFFFFFFF
    m_hi = (scaled >> 32) & 0xFFFFFFFF
    rsi = (h_lo * m_lo) & MASK64
    rdx = (m_hi * h_lo) & MASK64
    rcx = (h_hi * m_lo) & MASK64
    rax = (m_hi * h_hi) & MASK64
    rsi >>= 32
    edi = rdx & 0xFFFFFFFF
    rdx >>= 32
    rsi = (rsi + edi) & MASK64
    rcx = (rcx + rsi) & MASK64
    rax = (rax + rdx) & MASK64
    rcx >>= 32
    rax = (rax + rcx) & MASK64
    return rax


def bucket_index(hash_value, span_bytes):
    """Bucket for a hash value over a table span in bytes."""
    return limb_high_product(hash_value & MASK64, scaled_count(span_bytes))


def entry_address(base, hash_value, span_bytes):
    """Entry address for a table base, hash value and span."""
    return base + ENTRY_BYTES * bucket_index(hash_value, span_bytes)


def project(host_base, host_end, key, hash_fn):
    """Full window behaviour for a host table span and a key.

    host_base is the value of the host + 0xc40 field, host_end the
    value of the host + 0xc48 field, key the key bytes, and
    hash_fn the hash callee (key bytes -> unsigned 64-bit value).
    Returns the entry address the window returns.
    """
    span = _signed64(host_end - host_base)
    return entry_address(host_base, hash_fn(key), span)
