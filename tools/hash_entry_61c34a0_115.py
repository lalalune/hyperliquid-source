"""Model of the node #115 hash entry at 0x61c34a0 (rocksdb::Hash).

Three merged packets cite this 133-byte body by contract only
(RE-001-hash-find-insert-115 lists "the hash callee 0x61c34a0's
body" first among its unknowns; RE-014-batch-lookup-115 and
RE-014-memtable-iterator-seek-gate-115 record its size and two of
its seeds), and the RE-002 vendor census registers the identity
rocksdb::Hash(const char*, size_t, uint32_t). This module models
the body (0x61c34a0..0x61c3525, FDE at .eh_frame offset 0x376dcc,
no LSDA) exactly as written. All arithmetic is 32-bit, mod 2^32,
with the single multiplier M = 0xc6a4a793:

- h = (uint32(length) * M) ^ seed. The entry imul reads %esi,
  the low 32 bits of the 64-bit length argument; the end-pointer
  arithmetic below uses the full length.
- For each little-endian 4-byte word w of the input, in order:
  h += w; t = h * M; h = t ^ (t >> 16).
- The tail (length mod 4 bytes at data + 4 * (length // 4)) is
  folded in only when the remainder is nonzero, and the tail
  bytes are SIGN-extended (the body uses movsbl):
  remainder 3: h += sign_extend8(tail[2]) << 16, then as for 2;
  remainder 2: h += sign_extend8(tail[1]) << 8, then as for 1;
  remainder 1: h += sign_extend8(tail[0]);
  then the final mix runs once: t = h * M; result = t ^ (t >> 24).
- When the remainder is 0 there is NO final mix: the accumulator
  is returned as it stands (so length 0 returns the seed itself,
  and a multiple-of-4 length returns the last word step's h).

The result is the 32-bit value in %eax, zero-extended into %rax
(the citing packets record a 32-bit "hash32" result). The body
contains no call instruction, reads nothing outside
[data, data+length), and writes no memory at all.
"""

MASK32 = 0xFFFFFFFF
MULT = 0xC6A4A793


def _s8(byte):
    return byte - 0x100 if byte >= 0x80 else byte


def hash_entry(data, seed):
    """Hash `data` with the 32-bit `seed` at 0x61c34a0."""
    length = len(data)
    seed &= MASK32
    h = (((length & MASK32) * MULT) & MASK32) ^ seed
    words = length // 4
    for i in range(words):
        w = int.from_bytes(data[4 * i:4 * i + 4], "little")
        h = (h + w) & MASK32
        t = (h * MULT) & MASK32
        h = t ^ (t >> 16)
    rem = length - 4 * words
    if rem == 0:
        return h
    tail = data[4 * words:]
    if rem == 3:
        h = (h + (_s8(tail[2]) << 16)) & MASK32
    if rem >= 2:
        h = (h + (_s8(tail[1]) << 8)) & MASK32
    h = (h + _s8(tail[0])) & MASK32
    t = (h * MULT) & MASK32
    return t ^ (t >> 24)
