"""Python model of node #115 hash callee (0x61c3530).

RE-001 work item RE-001-hash-callee-61c3530-115. The model follows
the window's observed behavior, not a source spelling: the exact
source name of the function is inference; the mechanics below are
the window's.

Observed arguments
------------------
data (rdi): pointer to the input bytes; read but never written.
length (rsi): the input length in bytes.
seed (rdx): a 64-bit seed folded into every lane constant.
Returns (rax): the 64-bit hash.

Behavior (one function, end to end)
-----------------------------------
All arithmetic is modulo 2**64. rd64/rd32 are little-endian loads.
fold(x, y) is the 128-bit multiply fold (x*y low) ^ (x*y high).
Every lane is a pair ((K1 + seed) ^ rd64(first), (K2 - seed) ^
rd64(second)) whose contribution is fold(x, y). The final mix is
final_mix(x): y = x ^ (x >> 37); y = y * P3; y ^ (y >> 32), with
P3 = 0x165667b19e3779f9.

- length 0: fold(C_A + seed, P2). The data pointer is never
  dereferenced on this arm.
- length 1..3: v = data[0] | data[length >> 1] << 8 |
  data[length - 1] << 16 | length << 24 (a 32-bit value);
  return final_mix((v ^ (seed + 0x396cfeb8)) * P1).
- length 4..8: w = rd32(data) | rd32(data + length - 4) << 32;
  w ^= C_A + seed; u = w ^ (w >> 51); u = u * 0x9e3779b1 + length;
  u ^= u >> 47; return final_mix(u * P2).
- length 9..16: A = (C_A + seed) ^ rd64(data),
  B = (C_B - seed) ^ rd64(data + length - 8);
  return final_mix(A + length + B + fold(A, B)).
- length 17..128: acc = P1 * length, plus one 32-byte block sum
  per length band, plus the final two-lane sum:
    band 97..128 adds block D (lanes at data+48 and data+length-64),
    band 65..128 adds block A (lanes at data+32 and data+length-48),
    band 33..128 adds block B (lanes at data+16 and data+length-32),
    every band adds the final lanes (data+0 and data+length-16).
  Each block sum is fold(pair1) + fold(pair2); the result is
  final_mix(acc + fold(final pair1) + fold(final pair2)).
- length 129..240: the window tail-jumps to 0x61c3230 with the
  same (data, length, seed) registers; length 241 and above
  tail-jumps to 0x61c2cb0. Those two bodies are cited by contract
  only in the packet, so this model raises DelegatedHash for them
  instead of inventing semantics.

Constants: P1/P2/P3 are 0x9e3779b185ebca87 / 0xc2b2ae3d27d4eb4f /
0x165667b19e3779f9 (three of the four xxHash64 primes, which are
also the first three entries of the wyhash family's default
secret); C_A/C_B and the eight block-lane constants are pinned as
observed in the window (see the packet records.json).
"""

MASK64 = (1 << 64) - 1

P1 = 0x9E3779B185EBCA87
P2 = 0xC2B2AE3D27D4EB4F
P3 = 0x165667B19E3779F9

C_A = 0xBE4BA423396CFEB8
C_B = 0x1CAD21F72C81017C

# Block lane constants: (first-lane K1, second-lane K2) per pair.
BLOCK_D_PAIRS = (
    (0x3F349CE33F76FAA8, 0x1D4F0BC7C7BBDCF9),
    (0x3159B4CD4BE0518A, 0x647378D9C97E9FC8),
)
BLOCK_A_PAIRS = (
    (0xCB00C391BB52283C, 0xA32E531B8B65D088),
    (0x4EF90DA297486471, 0xD8ACDEA946EF1938),
)
BLOCK_B_PAIRS = (
    (0x78E5C0CC4EE679CB, 0x2172FFCC7DD05A82),
    (0x8E2443F7744608B8, 0x4C263A81E69035E0),
)
FINAL_PAIR2 = (0xDB979083E96DD4DE, 0x1F67B3B7A4A44072)

DELEGATE_MID = 0x61C3230   # lengths 129..240
DELEGATE_LONG = 0x61C2CB0  # lengths 241+


class DelegatedHash(Exception):
    """Raised for lengths the window hands off by tail jump."""

    def __init__(self, length, target):
        super().__init__(
            "length %d delegates to 0x%x" % (length, target))
        self.length = length
        self.target = target


def _rd64(data, off):
    return int.from_bytes(data[off:off + 8], "little")


def _rd32(data, off):
    return int.from_bytes(data[off:off + 4], "little")


def _fold(x, y):
    p = (x & MASK64) * (y & MASK64)
    return (p & MASK64) ^ (p >> 64)


def _pair(data, off_first, off_second, k1, k2, seed):
    x = ((k1 + seed) & MASK64) ^ _rd64(data, off_first)
    y = ((k2 - seed) & MASK64) ^ _rd64(data, off_second)
    return _fold(x, y)


def _final_mix(x):
    y = (x & MASK64) ^ ((x & MASK64) >> 37)
    y = (y * P3) & MASK64
    return y ^ (y >> 32)


def delegate_target(length):
    """The tail-jump target for a length, or None if in-window."""
    if 129 <= length <= 240:
        return DELEGATE_MID
    if length > 240:
        return DELEGATE_LONG
    return None


def hash_callee(data, seed):
    """The 0x61c3530 hash of `data` (bytes) under `seed`.

    Defined for lengths 0..128 (the window's own paths). For
    length 129 and above raises DelegatedHash carrying the
    tail-jump target the window uses.
    """
    data = bytes(data)
    seed &= MASK64
    n = len(data)
    target = delegate_target(n)
    if target is not None:
        raise DelegatedHash(n, target)
    if n == 0:
        return _fold((C_A + seed) & MASK64, P2)
    if n <= 3:
        v = (data[0] | (data[n >> 1] << 8) | (data[n - 1] << 16)
             | (n << 24))
        u = ((v ^ ((seed + 0x396CFEB8) & MASK64)) * P1) & MASK64
        return _final_mix(u)
    if n <= 8:
        w = _rd32(data, 0) | (_rd32(data, n - 4) << 32)
        w ^= (C_A + seed) & MASK64
        u = w ^ (w >> 51)
        u = (u * 0x9E3779B1 + n) & MASK64
        u ^= u >> 47
        return _final_mix((u * P2) & MASK64)
    if n <= 16:
        a = ((C_A + seed) & MASK64) ^ _rd64(data, 0)
        b = ((C_B - seed) & MASK64) ^ _rd64(data, n - 8)
        t = (a + n + b + _fold(a, b)) & MASK64
        return _final_mix(t)
    acc = (P1 * n) & MASK64
    if n > 96:
        (k1, k2), (k3, k4) = BLOCK_D_PAIRS
        acc = (acc + _pair(data, 48, 56, k1, k2, seed)
               + _pair(data, n - 64, n - 56, k3, k4, seed)) & MASK64
    if n > 64:
        (k1, k2), (k3, k4) = BLOCK_A_PAIRS
        acc = (acc + _pair(data, 32, 40, k1, k2, seed)
               + _pair(data, n - 48, n - 40, k3, k4, seed)) & MASK64
    if n > 32:
        (k1, k2), (k3, k4) = BLOCK_B_PAIRS
        acc = (acc + _pair(data, 16, 24, k1, k2, seed)
               + _pair(data, n - 32, n - 24, k3, k4, seed)) & MASK64
    total = (acc + _pair(data, 0, 8, C_A, C_B, seed)
             + _pair(data, n - 16, n - 8, FINAL_PAIR2[0],
                     FINAL_PAIR2[1], seed)) & MASK64
    return _final_mix(total)
