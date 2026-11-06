"""Model of node #115 routine 0x61c27f0: the hash
merge-accumulators body.

The routine (FDE 0x61c27f0..0x61c2888, 152 bytes) is the
merge callee the hash-long with-seed packet
(RE-001-hash-long-seed-61c2cb0-115, PR #3510) left by
contract only: that packet pinned that the with-seed body
0x61c2cb0 calls it once, at 0x61c31fc, with the accumulator
array, the custom secret + 11 bytes and
length * PRIME64_1, and returns its rax -- but not what it
computes. The RE-002 vendor census registers this body as
librocksdb-sys 0.11.0+8.1.1 `XXPH3_mergeAccs`; that
identity is cited, not re-asserted -- this model pins the
body's own instructions.

Signature: merge(acc=rdi, secret=rsi, start=rdx) -> rax.

  * rdi points to eight accumulator qwords (64 bytes).
    The body reads all eight, in order, and writes none.
  * rsi points to the secret window: the body reads
    exactly the 64 bytes at the handed pointer (qwords at
    byte offsets 0, 8, ..., 56) and nothing beyond them.
    Both callers hand a pointer 11 bytes into a 192-byte
    secret (the default secret at 0x97df00 from the
    seedless body, the caller's customised secret from
    the with-seed body); the +11 offset is the callers'
    choice, this body simply reads at the pointer given.
  * rdx is the start value both callers set to
    length * PRIME64_1 (mod 2^64).

The whole body is straight-line: no branches, no calls,
no reads or writes outside the two 64-byte windows and
one balanced push %r12 / pop %r12 pair (r12 is never
written; the pair has no observable effect beyond the
transient stack slot). What it computes, in its own
instruction order, with all arithmetic mod 2^64:

  1. Four lane-pair folds. For pair i = 0..3, with
     a = acc[2*i] XOR secret64[16*i] and
     b = acc[2*i+1] XOR secret64[16*i + 8], the pair
     contributes fold(a, b) = lo64(a * b) XOR hi64(a * b)
     (one 128-bit mul per pair; the first pair is loaded
     and multiplied before the second pair's loads, the
     rest follow in order).
  2. The sum. The four fold terms and the start value
     are added together. (In instruction order the start
     value is added third -- after the second fold term,
     before the third -- but addition mod 2^64 commutes,
     so the total is start + fold0 + fold1 + fold2 +
     fold3.)
  3. The avalanche. The sum x is returned as
     avalanche(x): x XOR (x >> 37), times
     0x165667b19e3779f9 (mod 2^64), then XOR (x >> 32).

Callers (the census finds exactly two direct call sites
in the whole binary, no tail jumps, no stored qword and
no RELATIVE addend naming this body):

  * 0x61c2c8e, inside the seedless hash-long body
    0x61c2890 (FDE 0x61c2890..0x61c2cad): rdi = that
    body's accumulator array (its frame base), rsi =
    0x97df0b (the default secret + 11), rdx = its length
    * PRIME64_1, set up at 0x61c2c76..0x61c2c8b.
  * 0x61c31fc, inside the with-seed hash-long body
    0x61c2cb0 (FDE 0x61c2cb0..0x61c3221): rdi = that
    body's accumulator array (frame +0x00), rsi = its
    custom secret + 11 (frame +0x4b), rdx = its length
    * PRIME64_1, set up at 0x61c31e6..0x61c31f8.

Both callers are themselves reached only from the parent
hash dispatch 0x61c3530 (108 direct call sites, pinned by
RE-001-hash-callee-61c3530-115, PR #3486), so the runtime
reachability of this body runs through them.
"""

MASK64 = 0xFFFFFFFFFFFFFFFF
PRIME64_1 = 0x9E3779B185EBCA87
PRIME64_2 = 0x165667B19E3779F9

ROUTINE = 0x61C27F0
CALL_SITES = (0x61C2C8E, 0x61C31FC)

ACC_BYTES = 64
SECRET_BYTES = 64


def _fold64(a, b):
    """lo64(a * b) XOR hi64(a * b), the one mul per lane
    pair."""
    product = a * b
    return ((product & MASK64) ^ (product >> 64)) & MASK64


def avalanche(x):
    """The closing avalanche: xor-shift 37, multiply by
    PRIME64_2, xor-shift 32 (all mod 2^64)."""
    x &= MASK64
    x ^= x >> 37
    x = (x * PRIME64_2) & MASK64
    x ^= x >> 32
    return x


def merge_accs(acc, secret, start):
    """Run the merge body 0x61c27f0 against model values.

    `acc` is a sequence of the eight accumulator qwords;
    `secret` is a bytes-like object of which exactly the
    first 64 bytes are read (the window at the handed
    pointer); `start` is the rdx value (both callers pass
    length * PRIME64_1). Returns the body's rax: the
    avalanche of start plus the four lane-pair folds.
    """
    if len(acc) != 8:
        raise ValueError("merge body reads exactly 8 accumulators")
    if len(secret) < SECRET_BYTES:
        raise ValueError("merge body reads exactly 64 secret bytes")
    result = start & MASK64
    for i in range(4):
        lo = int.from_bytes(secret[16 * i:16 * i + 8], "little")
        hi = int.from_bytes(secret[16 * i + 8:16 * i + 16], "little")
        result = (result + _fold64((acc[2 * i] & MASK64) ^ lo,
                                   (acc[2 * i + 1] & MASK64) ^ hi)) & MASK64
    return avalanche(result)
