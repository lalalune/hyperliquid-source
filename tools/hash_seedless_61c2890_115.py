"""Model of the node #115 seedless hash-long body at 0x61c2890.

The with-seed hash-long body at 0x61c2cb0 (packet
RE-001-hash-long-seed-61c2cb0-115, PR #3510) tests its seed on
entry: with seed == 0 it verifies its stack canary, restores the
stack and tail-jumps here with the argument registers untouched,
so this body is the seedless half of the 241+ length arm. The
length-dispatching sibling entry at 0x61c38a0 jumps here directly
for lengths above 0xf0. This module models the body
(0x61c2890..0x61c2cad, 1053 bytes) exactly as written. Its
signature is hash(data=rdi, length=rsi) -> rax: the third
argument register is never read.

All arithmetic is mod 2^64. The body keeps eight accumulators in
a stack array (the array the closing merge call receives):

- init (baked-in constant vectors, the prime ladder):
  acc = [PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3,
         PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1]
- one accumulate step over a 64-byte stripe whose secret window
  starts at secret offset `soff`, per qword lane i of the stripe:
      x = data[i] ^ SECRET[soff + i]
      acc[i] += data[i] + lo32(x) * hi32(x)
  (the added data term is the raw data qword and the product is
  of the xored value's two halves; both are as the SSE2 sequence
  in the bytes computes them, and the packet differential pins
  the reading against the native bytes)
- full blocks of 1024 bytes: 16 stripes, the secret window
  sliding +8 per stripe (offsets 8*k + 16*j per pair j), then a
  scramble of every accumulator:
      acc[i] = (acc[i] ^ (acc[i] >> 47) ^ SECRET[128 + i]) *
               PRIME32_1
  (the scramble key window is the secret's last 64 bytes)
- remainder stripes after the last full block:
  count = (length >> 6) & 0xf, secret window again sliding +8
  per stripe from offset 0
- the final partial stripe, only when length & 63 != 0: one
  accumulate step over data[length-64 .. length] with the
  secret window at offset 121
- the result is the merge routine at 0x61c27f0 called once with
  (acc array, SECRET + 11, length * PRIME64_1): per pair i,
  fold(acc[2i] ^ rd64(SECRET, 11 + 16*i),
       acc[2i+1] ^ rd64(SECRET, 11 + 16*i + 8))
  with fold(x, y) = lo(x*y) ^ hi(x*y) is summed with the start
  value and avalanched (y = x ^ (x >> 37); y *= PRIME_MIX;
  y ^ (y >> 32)). The merge body itself is pinned by its own
  packet (PR #3533); it is modelled here so this module is
  self-contained, and the differential runs the real merge
  bytes, so the end-to-end result is pinned either way.

SECRET is the 192-byte table the binary holds at VA 0x97df00 in
.rodata, the same table the rest of the hash family cites; the
scramble keys and the final stripe's window are its entries at
the offsets named above, baked into the body as .rodata
constant vectors and verified entry by entry against the table.

The body writes only its own 0x58-byte stack frame (the
accumulator array plus the stack-canary slot it verifies before
returning), reads the input but never writes it, and preserves
the callee-saved registers. Lengths below 241 never reach it —
both entries gate on length >= 241 — and this model documents
that contract range.
"""

MASK = (1 << 64) - 1
PRIME32_1 = 0x9E3779B1
PRIME64_1 = 0x9E3779B185EBCA87
PRIME_MIX = 0x165667B19E3779F9

INIT = [
    0x00000000C2B2AE3D,  # PRIME32_3
    0x9E3779B185EBCA87,  # PRIME64_1
    0xC2B2AE3D27D4EB4F,  # PRIME64_2
    0x165667B19E3779F9,  # PRIME64_3
    0x85EBCA77C2B2AE63,  # PRIME64_4
    0x0000000085EBCA77,  # PRIME32_2
    0x27D4EB2F165667C5,  # PRIME64_5
    0x000000009E3779B1,  # PRIME32_1
]

SECRET = bytes.fromhex(
    "b8fe6c3923a44bbe7c01812cf721ad1cded46de9839097db7240a4a4"
    "b7b3671fcb79e64eccc0e578825ad07dccff7221b8084674f743248e"
    "e03590e6813a264c3c2852bb91c300cb88d0658b1b532ea371644897"
    "a20df94e3819ef46a9deacd8a8fa763fe39c343ff9dcbbc7c70b4f1d"
    "8a51e04bcdb45931c89f7ec9d9787364eac5ac8334d3ebc3c581a0ff"
    "fa1363eb170ddd51b7f0da49d316552629d4689e2b16be587d47a1f"
    "c8ff8b8d17ad031ce45cb3a8f95160428afd7fbcabb4b407e"
)


def _rd64(buf, off):
    return int.from_bytes(buf[off:off + 8], "little")


def _accumulate(acc, data, doff, soff):
    for j in range(4):
        for l in range(2):
            i = 2 * j + l
            d = _rd64(data, doff + 16 * j + 8 * l)
            x = d ^ _rd64(SECRET, soff + 16 * j + 8 * l)
            acc[i] = (acc[i] + d + (x & 0xFFFFFFFF) * (x >> 32)) & MASK


def _scramble(acc):
    for i in range(8):
        a = acc[i] ^ (acc[i] >> 47) ^ _rd64(SECRET, 128 + i * 8)
        acc[i] = (a * PRIME32_1) & MASK


def _avalanche(x):
    x &= MASK
    x ^= x >> 37
    x = (x * PRIME_MIX) & MASK
    x ^= x >> 32
    return x & MASK


def _merge(acc, start):
    total = start & MASK
    for i in range(4):
        x = acc[2 * i] ^ _rd64(SECRET, 11 + 16 * i)
        y = acc[2 * i + 1] ^ _rd64(SECRET, 11 + 16 * i + 8)
        p = x * y
        total = (total + ((p & MASK) ^ (p >> 64))) & MASK
    return _avalanche(total)


def final_acc(data):
    """The accumulator array after all stripes, before the merge."""
    n = len(data)
    acc = INIT[:]
    nb = n >> 10
    for b in range(nb):
        for k in range(16):
            _accumulate(acc, data, b * 1024 + 64 * k, 8 * k)
        _scramble(acc)
    rem = (n >> 6) & 0xF
    for k in range(rem):
        _accumulate(acc, data, nb * 1024 + 64 * k, 8 * k)
    if n & 0x3F:
        _accumulate(acc, data, n - 64, 121)
    return acc


def hash_seedless(data):
    """Hash `data` (contract: len >= 241) with the body at 0x61c2890."""
    return _merge(final_acc(data), (len(data) * PRIME64_1) & MASK)
