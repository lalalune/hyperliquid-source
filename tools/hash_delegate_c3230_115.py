"""Model of the node #115 hash delegate at 0x61c3230.

The parent hash callee at 0x61c3530 (packet
RE-001-hash-callee-61c3530-115, PR #3486) handles input lengths
0..128 itself and tail-jumps here for lengths 129..240, with the
argument registers already in place: rdi = data, rsi = len,
rdx = seed. This module models the delegate body
(0x61c3230..0x61c3491, 609 bytes) exactly as written:

- acc = len * PRIME64_1
- eight opening stripes: for i in 0..7,
  acc += mix16(data + 16*i, SECRET + 16*i, seed)
- acc = avalanche(acc)
- middle stripes, only when len > 143: with nbRounds = len >> 4,
  for k in 0..nbRounds-9,
  acc += mix16(data + 128 + 16*k, SECRET + 3 + 16*k, seed)
  (the loop reads the secret at offset 3 + 16*k, not 128 + 16*k;
  the +3 offset is in the bytes, at 0x61c33f8 the loop's secret
  pointer starts at 0x97df0b and reads [ptr-8] / [ptr])
- final pair: acc += mix16(data + len - 16, SECRET + 119, seed)
- result = avalanche(acc)

mix16(data_off, secret_off, seed) is the family's shared lane pair:
x = (rd64(secret, secret_off) + seed) ^ rd64(data, data_off),
y = (rd64(secret, secret_off + 8) - seed) ^ rd64(data, data_off + 8),
and the contribution is fold(x, y) = lo(x*y) ^ hi(x*y) of the
128-bit product, all arithmetic mod 2^64.

avalanche(x): y = x ^ (x >> 37); y *= 0x165667b19e3779f9;
result = y ^ (y >> 32).

SECRET is the 192-byte table the binary holds at VA 0x97df00 in
.rodata (the same table the parent's opening stripes bake in as
immediates; the first sixteen pairs of constants in this body are
that table read back). The delegate reads it from memory only in
the middle loop; the opening stripes and the final pair use
immediates equal to table entries at the offsets named above.

The body contains no call instruction and writes nothing but its
own stack frame; every read stays inside [data, data+len) plus the
secret table, for lengths in the contract range 129..240. Outside
that range the parent never delegates here and this model does not
claim the behaviour (the opening stripes read data[0..128)
unconditionally).
"""

MASK = (1 << 64) - 1
PRIME64_1 = 0x9E3779B185EBCA87
PRIME_MIX = 0x165667B19E3779F9

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


def _fold(x, y):
    p = (x & MASK) * (y & MASK)
    return ((p & MASK) ^ (p >> 64)) & MASK


def _mix16(data, data_off, secret_off, seed):
    x = ((_rd64(SECRET, secret_off) + seed) & MASK) ^ _rd64(data, data_off)
    y = ((_rd64(SECRET, secret_off + 8) - seed) & MASK) ^ _rd64(
        data, data_off + 8)
    return _fold(x, y)


def _avalanche(x):
    x &= MASK
    x ^= x >> 37
    x = (x * PRIME_MIX) & MASK
    x ^= x >> 32
    return x & MASK


def hash_delegate(data, seed):
    """Hash `data` (129..240 bytes) with the delegate at 0x61c3230."""
    length = len(data)
    seed &= MASK
    acc = (length * PRIME64_1) & MASK
    for i in range(8):
        acc = (acc + _mix16(data, 16 * i, 16 * i, seed)) & MASK
    acc = _avalanche(acc)
    if length > 0x8F:
        nb_rounds = length >> 4
        for k in range(nb_rounds - 8):
            acc = (acc + _mix16(data, 128 + 16 * k, 3 + 16 * k,
                                seed)) & MASK
    acc = (acc + _mix16(data, length - 16, 119, seed)) & MASK
    return _avalanche(acc)
