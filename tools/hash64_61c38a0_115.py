"""Model of the node #115 hash body at 0x61c38a0.

This is the hash callee the merged packet
RE-001-hash-bucket-projection-115 cited by contract only: its
projection at 0x5f099b0 calls here (site 0x5f099e7) with
rdi = key pointer, rsi = key length, and uses the 64-bit result
to pick a table bucket. The RE-002 vendor census registers this
window as librocksdb-sys 0.11.0+8.1.1 `rocksdb::Hash64(const
char*, size_t)` (window id node115-vendor-61c38a0); this module
pins the body's own semantics, transcribed instruction by
instruction from 0x61c38a0..0x61c3bb9 (793 bytes), and neither
needs nor re-claims that identity.

Signature: (data rdi, len rsi) -> rax. There is no seed
register: every lane constant is baked in as an immediate, and
each immediate is a qword of the family's 192-byte secret table
at VA 0x97df00 (verified entry by entry; the offsets used are
listed per arm below). The body is not a leaf at the top level:
for lengths above 128 it leaves by tail jump and never returns
here, so this model covers lengths 0..128 exactly and exposes
the two delegation exits separately (delegation_target).

Length arms (dispatch order in the bytes: cmp 0x10, cmp 8,
cmp 0x80, then the stripe gates 0x20 / 0x40 / 0x60):

- len == 0: returns the constant 0x5342c3010fe1dd04, loaded
  before the zero test at 0x61c3aa6; no byte is read.
- len 1..3: combined = data[0] | data[len >> 1] << 8 |
  data[len - 1] << 16 | len << 24 (32-bit); result =
  avalanche((combined ^ 0x396cfeb8) * PRIME64_1), where
  0x396cfeb8 is the low 32 bits of secret qword 0.
- len 4..8: input = rd32(data) | rd32(data + len - 4) << 32;
  h = input ^ SECRET[0]; h ^= h >> 51; h *= 0x9e3779b1 (the
  32-bit prime zero-extended, a full 64-bit imul); h += len;
  h ^= h >> 47; result = avalanche(h * PRIME64_2).
- len 9..16: lo = SECRET[0] ^ rd64(data), hi = SECRET[8] ^
  rd64(data + len - 8); result = avalanche(lo + len + hi +
  fold(lo, hi)).
- len 17..128: acc = len * PRIME64_1, plus lane-pair folds.
  Every length in this band adds the first pair (data + 0,
  secret 0) and the last pair (data + len - 16, secret 16).
  Longer lengths add stripe pairs in execution order, each
  pair read at a fixed or end-relative data offset with the
  secret offset in parentheses:
    len >= 33: (data + 16, secret 32), (data + len - 32,
      secret 48)
    len >= 65: (data + 32, secret 64), (data + len - 48,
      secret 80)
    len >= 97: (data + 48, secret 96), (data + len - 64,
      secret 112)
  result = avalanche(acc + all folds).

fold(x, y) = lo(x*y) ^ hi(x*y) of the 128-bit product.
avalanche(x): y = x ^ (x >> 37); y *= 0x165667b19e3779f9;
result = y ^ (y >> 32). All arithmetic mod 2^64.

Delegation (by contract only, not modelled here):
- len 129..240: at 0x61c3a95 edx is zeroed and the body tail-
  jumps at 0x61c3a97 to the delegate at 0x61c3230 (packet
  RE-001-hash-delegate-c3230-115, PR #3489), which takes
  (data, len, seed) — so this entry always passes seed 0.
- len >= 241: at 0x61c3b50 the body tail-jumps to the seedless
  long body at 0x61c2890 (cited by contract in packet
  RE-001-hash-long-seed-61c2cb0-115, PR #3510), with (data,
  len) unchanged.

Side effects: none. The body writes nothing; its only stack
traffic is the push/pop of r15, r14, r12 on the 17..128 arms
(all restored before ret); callee-saved registers are
preserved. Every read stays inside [data, data+len): the
arm read windows are [0,8k) union [len-8k, len) sized by the
band, and the empty input reads nothing.
"""

MASK = (1 << 64) - 1
MASK32 = (1 << 32) - 1
PRIME64_1 = 0x9E3779B185EBCA87
PRIME64_2 = 0xC2B2AE3D27D4EB4F
PRIME64_3 = 0x165667B19E3779F9
PRIME32_1 = 0x9E3779B1

LEN0_RESULT = 0x5342C3010FE1DD04

# The 192-byte secret table at VA 0x97df00 in .rodata (the same
# table the sibling hash bodies cite). Only the qwords this
# body bakes in as immediates are used, at the offsets the
# instructions name; the full table is kept so the test can
# pin the correspondence.
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


def _rd32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little")


def _sq(off):
    return _rd64(SECRET, off)


def _fold(x, y):
    p = (x & MASK) * (y & MASK)
    return ((p & MASK) ^ (p >> 64)) & MASK


def _pair(data, data_off, sec_first, sec_second=None):
    if sec_second is None:
        sec_second = sec_first + 8
    x = _sq(sec_first) ^ _rd64(data, data_off)
    y = _sq(sec_second) ^ _rd64(data, data_off + 8)
    return _fold(x, y)


def _avalanche(x):
    x &= MASK
    x ^= x >> 37
    x = (x * PRIME64_3) & MASK
    x ^= x >> 32
    return x & MASK


def delegation_target(length):
    """The tail-jump exit for lengths this body does not finish.

    Returns (target, seed_register) for len >= 129, else None.
    seed_register is the rdx value at the jump: the 129..240
    exit zeroes it; the 241+ exit never writes rdx in this
    body, so it forwards whatever the caller held (the model
    reports None for "untouched").
    """
    if length > 0xF0:
        return (0x61C2890, None)
    if length > 0x80:
        return (0x61C3230, 0)
    return None


def hash64(data):
    """Hash `data` (0..128 bytes) with the body at 0x61c38a0."""
    n = len(data)
    if n > 0x80:
        raise ValueError(
            "lengths >= 129 leave by tail jump; see delegation_target")
    if n == 0:
        return LEN0_RESULT
    if n <= 3:
        combined = (data[0] | (data[n >> 1] << 8)
                    | (data[n - 1] << 16) | (n << 24)) & MASK32
        # the xor immediate at 0x61c3ae6 is 0x396cfeb8, the low
        # 32 bits of secret qword 0
        keyed = combined ^ 0x396CFEB8
        return _avalanche((keyed * PRIME64_1) & MASK)
    if n <= 8:
        inp = _rd32(data, 0) | (_rd32(data, n - 4) << 32)
        h = inp ^ _sq(0)
        h ^= h >> 51
        h = (h * PRIME32_1) & MASK
        h = (h + n) & MASK
        h ^= h >> 47
        return _avalanche((h * PRIME64_2) & MASK)
    if n <= 16:
        lo = _sq(0) ^ _rd64(data, 0)
        hi = _sq(8) ^ _rd64(data, n - 8)
        acc = (lo + n + hi + _fold(lo, hi)) & MASK
        return _avalanche(acc)
    acc = (n * PRIME64_1) & MASK
    if n >= 97:
        acc = (acc + _pair(data, 48, 96)
               + _pair(data, n - 64, 112)) & MASK
    if n >= 65:
        acc = (acc + _pair(data, 32, 64)
               + _pair(data, n - 48, 80)) & MASK
    if n >= 33:
        acc = (acc + _pair(data, 16, 32)
               + _pair(data, n - 32, 48)) & MASK
    acc = (acc + _pair(data, 0, 0)
           + _pair(data, n - 16, 16)) & MASK
    return _avalanche(acc)
