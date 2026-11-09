#!/usr/bin/env python3
"""Node #115 `rocksdb::GetUniqueIdFromTableProperties`.

Reconstructs one vendored RocksDB function from the node #115 binary
(artifact SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* `rocksdb::GetUniqueIdFromTableProperties` at 0x61b0490..0x61b0631
  (417 bytes, census node115-vendor-61b0490, body SHA-256
  00698ef733869baa717ad1d89956504088b731feb827238875df41cee3d540d4):
  derives the 16-byte external unique id of an SST file from its
  `TableProperties`. The function reads three fields of the struct
  (RocksDB 8.1.1 layout, verified against the upstream header:
  `orig_file_number` at offset 0, `db_id` at 0xc8, `db_session_id`
  at 0xe8) and calls `GetSstInternalUniqueId(db_id, db_session_id,
  orig_file_number, write_third_word=false, lenient=false)`
  (0x61b04de). When that call returns a non-OK Status, the out
  string is cleared to "" (0x61b04eb: size 0, buffer kept) and the
  Status is returned as-is. On success it calls
  `InternalUniqueIdToExternal(id, flag=false)` (0x61b0525) and
  `EncodeUniqueIdBytes(id, flag=false)` (0x61b0534) and move-assigns
  the resulting 16-byte string into the out string; the OK Status
  is returned. The third UniqueId word is never written by the
  GetSst call (write_third_word clear) and is passed through
  untouched by the external conversion (flag clear), and the
  16-byte encoder reads only the first two words, so the unwritten
  third word cannot affect the output. The only in-binary caller
  is `rocksdb::TableProperties::ToString` (0x61aa011, census
  0x61a8530..0x61aaa8b), which checks the returned Status byte.

The census `source_body_sha256`
(d5faca9cef62ea92b6180a53a1b98823de3c33b975c60cde08a33795b0dfeda6) is
reproduced exactly by hashing the body with the seven relocation
fields zeroed (six kind-4 `E8` rel32 fields at offsets 79, 150,
165, 279, 351, 401 and one kind-2 `E9` rel32 field at offset 413),
so `raw_equal` false is fully explained: the linked body differs
from the source body only in the call displacements. The FDE
range 0x61b0490..0x61b0631 matches the census range exactly.

The callee transliterations below are adapted from the open PRs
that reconstruct them standalone (same author): `GetSstInternalUniqueId`
+ `DecodeSessionId` from open PR #5834, `InternalUniqueIdToExternal`
+ `EncodeUniqueIdBytes` + `BijectiveHash2x64` and its seed-0 adapter
from open PR #5831, the `Hash2x64` wrappers from open PR #5723, and
the 128-bit one-shot transliteration from open PR #5578; the
one-shots' standalone reconstruction is #5578, and lengths above
128 delegate to the len_129to240 helper (open PR #5595) and the
hashLong helpers (open PR #5598), which are out of scope here: this
tool covers hashed inputs of length 0..128 only, which covers every
realistic db_id (a UUID string) and db_session_id (13..24
characters) and every in-binary call site.

No binary is executed by this tool; the models below are checked
against each other and against the binary's bytes.
"""

import argparse
import hashlib
import json
import random
import struct
from pathlib import Path

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
MASK62 = (1 << 62) - 1
MASK64 = M64
MASK32 = M32

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
CENSUS_PATH = (
    "research/work-items/RE-002-node115-vendor-census/census.json"
)

# Status codes (rocksdb/status.h): kOk = 0, kNotSupported = 3.
STATUS_OK = 0
STATUS_NOT_SUPPORTED = 3

DECODE_ERRORS = {
    "empty": "Missing db_session_id",
    "short": "Too short db_session_id",
    "long": "Too long db_session_id",
    "digit": "Bad digit in db_session_id",
}
GET_SST_ERRORS = {
    "db_id": "Missing db_id",
    "file_number": "Missing or bad file number",
    "session": "Missing db_session_id",
}

PRIME64_1 = 0x9E3779B185EBCA87
PRIME64_2 = 0xC2B2AE3D27D4EB4F
PRIME64_3 = 0x165667919E3779F9
PRIME64_4 = 0x85EBCA77C2B2AE63
PRIME_MX1 = 0xC2B2AE3D27D4EB4F
PRIME_MX2 = 0x165667B19E3779F9
PRIME_MX2B = 0x9FB21C651E98DF25

# Published xxHash default secret (192 bytes, xxh3.h kSecret). The binary
# slice at file offset 0x97ec80 is byte-compared against this constant.
KSECRET = bytes.fromhex(
    "b8fe6c3923a44bbe7c01812cf721ad1c"
    "ded46de9839097db7240a4a4b7b3671f"
    "cb79e64eccc0e578825ad07dccff7221"
    "b8084674f743248ee03590e6813a264c"
    "3c2852bb91c300cb88d0658b1b532ea3"
    "71644897a20df94e3819ef46a9deacd8"
    "a8fa763fe39c343ff9dcbbc7c70b4f1d"
    "8a51e04bcdb45931c89f7ec9d9787364"
    "eac5ac8334d3ebc3c581a0fffa1363eb"
    "170ddd51b7f0da49d316552629d4689e"
    "2b16be587d47a1fc8ff8b8d17ad031ce"
    "45cb3a8f95160428afd7fbcabb4b407e"
)

# Additive salts in InternalUniqueIdToExternal (movabs immediates at
# 0x61b0268 and 0x61b027d).
SALT_W0 = 0x590EB907C873E891
SALT_W1 = 0xF1598607FB45CBD8

# (name, start, end, target_body_sha256) of every function this packet
# binds, in FDE order. GetUniqueIdFromTableProperties is the claim;
# the rest are callee context, reconstructed standalone in the open
# PRs cited in the module docstring. The BijectiveHash2x64 adapter
# has no census record (below the 32-byte minimum); its body hash
# below is the hash of the FDE bytes in this binary.
FUNCTIONS = [
    ("DecodeSessionId", 0x61AF500, 0x61AFFAF,
     "73426de07243605a472e661f6b4a59094c4a8094cf5dc5b54cf2bfa970761cb9"),
    ("GetSstInternalUniqueId", 0x61AFFE0, 0x61B0260,
     "1b64d1af98c276016dc33017c08fd35534868998668d2a72e123ddaa0d0db1be"),
    ("InternalUniqueIdToExternal", 0x61B0260, 0x61B02F3,
     "9a1ae61f46968c646f4819250736e6139b911e675e7b9488a987d54a299533de"),
    ("EncodeUniqueIdBytes", 0x61B0300, 0x61B0381,
     "520abebd6899cd3cb64cac38e28f69dcfbb0a0cde30ccfbd0f79b5454c372044"),
    ("GetUniqueIdFromTableProperties", 0x61B0490, 0x61B0631,
     "00698ef733869baa717ad1d89956504088b731feb827238875df41cee3d540d4"),
    ("Hash2x64", 0x61C3DB0, 0x61C3DD3,
     "cdf83f118dae4ddaabf19ff5fef1f5c12469608c9664d39a3b95b0389165ce3f"),
    ("Hash2x64_withSeed", 0x61C3DE0, 0x61C3E03,
     "77d46c5d98d167a3da48e8471c2ded2361ced5e47565abbdc0c11628ab785b7b"),
    ("BijectiveHash2x64", 0x61C3E10, 0x61C3F55,
     "d586664de83493cc5a48eefd3bcef95b10a3ab433b32699334c68671b8cb0864"),
    ("BijectiveHash2x64_adapter", 0x61C3F60, 0x61C3F71,
     "8eb9df37604f72f0b72b1b1af72232ed0875460ff8deafd4f46fd93ca8e3dc55"),
]
KSECRET_VA = 0x97EC80
# --- Binary helpers (adapted from open PR #5834). ---

def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]

def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]

def _bswap64(x):
    return struct.unpack("<Q", struct.pack(">Q", x))[0]

def _bswap32(x):
    return struct.unpack("<I", struct.pack(">I", x & M32))[0]

def _rotl32(x, r):
    return ((x << r) | (x >> (32 - r))) & M32

def _swap32(x):
    return _bswap32(x)

def _mul128_fold64(a, b):
    p = a * b
    return (p & M64) ^ (p >> 64)

def _xxh3_avalanche(h):
    h &= M64
    h ^= h >> 37
    h = (h * PRIME64_3) & M64
    h ^= h >> 32
    return h

def _rrmxmx(h):
    h &= M64
    h ^= h >> 33
    h = (h * PRIME_MX1) & M64
    h ^= h >> 29
    h = (h * PRIME_MX2) & M64
    h ^= h >> 32
    return h

def _xorshift(h, r):
    return (h ^ (h >> r)) & M64


# --- XXH3 128-bit one-shots (callee context, adapted from open PR #5578).
#
# ROCKSDB_XXH3_128bits (0x61deab0) and _withSeed (0x61defa0), lengths
# 0..128 with the default 192-byte secret. The transliteration follows
# the disassembly op order; the independent reference below is written
# from the published xxh3.h formulas.

# --- XXH3 128-bit one-shots (callee context, adapted from open PR #5578 via #5834). ---

def _mix16b(data, data_off, secret, sec_off, seed):
    lo = _u64(data, data_off) ^ ((_u64(secret, sec_off) + seed) & M64)
    hi = _u64(data, data_off + 8) ^ ((_u64(secret, sec_off + 8) - seed) & M64)
    return _mul128_fold64(lo, hi)

def _xxh3_128(data, seed, secret=KSECRET):
    """ROCKSDB_XXH3_128bits / _withSeed for len <= 128 (seed 0 / seed)."""
    n = len(data)
    seed &= M64
    if n > 128:
        raise ValueError(
            "len > 128 out of scope (delegates to len_129to240 / hashLong)")
    if n == 0:
        return (_rrmxmx(seed ^ (_u64(secret, 64) ^ _u64(secret, 72))),
                _rrmxmx(seed ^ (_u64(secret, 80) ^ _u64(secret, 88))))
    if n <= 3:
        combinedl = (data[n - 1] | (data[0] << 16) | (n << 8)
                     | (data[n >> 1] << 24))
        combinedh = _rotl32(_bswap32(combinedl), 13)
        bitflipl = ((_u32(secret, 0) ^ _u32(secret, 4)) + seed) & M64
        bitfliph = ((_u32(secret, 8) ^ _u32(secret, 12)) - seed) & M64
        return (_rrmxmx(combinedl ^ bitflipl),
                _rrmxmx(combinedh ^ bitfliph))
    if n <= 8:
        seed_t = (seed ^ (_swap32(seed) << 32)) & M64
        input64 = (_u32(data, 0) + (_u32(data, n - 4) << 32)) & M64
        bitflip = ((_u64(secret, 16) ^ _u64(secret, 24)) + seed_t) & M64
        keyed = input64 ^ bitflip
        p = keyed * (PRIME64_1 + (n << 2))
        lo, hi = p & M64, p >> 64
        hi = (hi + ((lo << 1) & M64)) & M64
        lo = (lo ^ (hi >> 3)) & M64
        lo = _xorshift(lo, 35)
        lo = (lo * PRIME_MX2B) & M64
        lo = _xorshift(lo, 28)
        hi = _xxh3_avalanche(hi)
        return (lo, hi)
    if n <= 16:
        bitflipl = ((_u64(secret, 32) ^ _u64(secret, 40)) - seed) & M64
        bitfliph = ((_u64(secret, 48) ^ _u64(secret, 56)) + seed) & M64
        input_lo = _u64(data, 0)
        input_hi = _u64(data, n - 8)
        acc = (input_lo ^ input_hi ^ bitflipl) & M64
        p = acc * PRIME64_1
        lo1, hi1 = p & M64, p >> 64
        c_hi = input_hi ^ bitfliph
        c = (((c_hi & M32) * 0x85EBCA76 + c_hi + hi1) & M64)
        low2 = ((lo1 + (((n - 1) << 54) & M64)) & M64) ^ _bswap64(c)
        p2 = low2 * PRIME64_2
        lo2, hi2 = p2 & M64, p2 >> 64
        d = (c * PRIME64_2 + hi2) & M64
        return (_xxh3_avalanche(lo2), _xxh3_avalanche(d))
    # len 17..128: two mix16B accumulators, largest window inward.
    acc = (n * PRIME64_1) & M64
    acc2 = 0
    if n > 96:
        fold_a = _mix16b(data, 48, secret, 96, seed)
        acc = (((_u64(data, n - 56) + _u64(data, n - 64)) & M64)
               ^ ((fold_a + acc) & M64))
        fold_b = _mix16b(data, n - 64, secret, 112, seed)
        acc2 = ((fold_b + acc2) & M64
                ^ ((_u64(data, 56) + _u64(data, 48)) & M64))
    if n > 64:
        fold_a = _mix16b(data, 32, secret, 64, seed)
        acc = (((_u64(data, n - 40) + _u64(data, n - 48)) & M64)
               ^ ((fold_a + acc) & M64))
        fold_b = _mix16b(data, n - 48, secret, 80, seed)
        acc2 = ((fold_b + acc2) & M64
                ^ ((_u64(data, 40) + _u64(data, 32)) & M64))
    if n > 32:
        fold_a = _mix16b(data, 16, secret, 32, seed)
        acc = (((_u64(data, n - 24) + _u64(data, n - 32)) & M64)
               ^ ((fold_a + acc) & M64))
        fold_b = _mix16b(data, n - 32, secret, 48, seed)
        acc2 = ((fold_b + acc2) & M64
                ^ ((_u64(data, 24) + _u64(data, 16)) & M64))
    fold_first = _mix16b(data, 0, secret, 0, seed)
    fold_last = _mix16b(data, n - 16, secret, 16, seed)
    a = ((fold_first + acc) & M64) ^ ((_u64(data, n - 8) + _u64(data, n - 16)) & M64)
    b = ((fold_last + acc2) & M64) ^ ((_u64(data, 8) + _u64(data, 0)) & M64)
    low = _xxh3_avalanche((a + b) & M64)
    y = (a * PRIME64_1 + b * PRIME64_4 + ((n - seed) & M64) * PRIME64_2) & M64
    high = (-_xxh3_avalanche(y)) & M64
    return (low, high)

def xxh3_128bits(data):
    """ROCKSDB_XXH3_128bits(data, len), len <= 128. Returns (low64, high64)."""
    return _xxh3_128(data, 0)

def xxh3_128bits_with_seed(data, seed):
    """ROCKSDB_XXH3_128bits_withSeed(data, len, seed), len <= 128."""
    return _xxh3_128(data, seed)

def _ref_mix16b(data, off, secret, sec_off, seed):
    lo = _u64(data, off) ^ ((_u64(secret, sec_off) + seed) & M64)
    hi = _u64(data, off + 8) ^ ((_u64(secret, sec_off + 8) - seed) & M64)
    return _mul128_fold64(lo, hi)

def _ref_len_17to128_128b(data, secret, seed):
    n = len(data)
    acc = (n * PRIME64_1) & M64
    acc2 = 0
    for (a_off, a_sec, b_off, b_sec, guard) in (
            (48, 96, n - 64, 112, 96),
            (32, 64, n - 48, 80, 64),
            (16, 32, n - 32, 48, 32)):
        if n <= guard:
            continue
        acc = (((_u64(data, b_off + 8) + _u64(data, b_off)) & M64)
               ^ ((_ref_mix16b(data, a_off, secret, a_sec, seed) + acc) & M64))
        acc2 = ((_ref_mix16b(data, b_off, secret, b_sec, seed) + acc2) & M64
                ^ ((_u64(data, a_off + 8) + _u64(data, a_off)) & M64))
    first = _ref_mix16b(data, 0, secret, 0, seed)
    last = _ref_mix16b(data, n - 16, secret, 16, seed)
    a = ((first + acc) & M64) ^ ((_u64(data, n - 8) + _u64(data, n - 16)) & M64)
    b = ((last + acc2) & M64) ^ ((_u64(data, 8) + _u64(data, 0)) & M64)
    low = _xxh3_avalanche((a + b) & M64)
    high = (-_xxh3_avalanche(
        (a * PRIME64_1 + b * PRIME64_4 + ((n - seed) & M64) * PRIME64_2) & M64)) & M64
    return (low, high)

def _ref_len_0to128(data, secret, seed):
    """Independent reference for the 128-bit one-shots, from xxh3.h."""
    n = len(data)
    seed &= M64
    if n == 0:
        return (_rrmxmx(seed ^ (_u64(secret, 64) ^ _u64(secret, 72))),
                _rrmxmx(seed ^ (_u64(secret, 80) ^ _u64(secret, 88))))
    if n <= 3:
        combinedl = (data[n - 1] | (data[0] << 16) | (n << 8)
                     | (data[n >> 1] << 24))
        combinedh = _rotl32(_bswap32(combinedl), 13)
        bitflipl = ((_u32(secret, 0) ^ _u32(secret, 4)) + seed) & M64
        bitfliph = ((_u32(secret, 8) ^ _u32(secret, 12)) - seed) & M64
        return (_rrmxmx(combinedl ^ bitflipl),
                _rrmxmx(combinedh ^ bitfliph))
    if n <= 8:
        seed2 = (seed ^ (_swap32(seed) << 32)) & M64
        input64 = (_u32(data, 0) + (_u32(data, n - 4) << 32)) & M64
        bitflip = ((_u64(secret, 16) ^ _u64(secret, 24)) + seed2) & M64
        keyed = input64 ^ bitflip
        p = keyed * (PRIME64_1 + (n << 2))
        lo, hi = p & M64, p >> 64
        hi = (hi + ((lo << 1) & M64)) & M64
        lo = (lo ^ (hi >> 3)) & M64
        lo = _xorshift(lo, 35)
        lo = (lo * PRIME_MX2B) & M64
        lo = _xorshift(lo, 28)
        hi = _xxh3_avalanche(hi)
        return (lo, hi)
    if n <= 16:
        bitflipl = ((_u64(secret, 32) ^ _u64(secret, 40)) - seed) & M64
        bitfliph = ((_u64(secret, 48) ^ _u64(secret, 56)) + seed) & M64
        input_lo = _u64(data, 0)
        input_hi = _u64(data, n - 8)
        acc = (input_lo ^ input_hi ^ bitflipl) & M64
        p = acc * PRIME64_1
        lo1, hi1 = p & M64, p >> 64
        c_hi = input_hi ^ bitfliph
        c = (((c_hi & M32) * 0x85EBCA76 + c_hi + hi1) & M64)
        low2 = ((lo1 + (((n - 1) << 54) & M64)) & M64) ^ _bswap64(c)
        p2 = low2 * PRIME64_2
        lo2, hi2 = p2 & M64, p2 >> 64
        d = (c * PRIME64_2 + hi2) & M64
        return (_xxh3_avalanche(lo2), _xxh3_avalanche(d))
    return _ref_len_17to128_128b(data, secret, seed)

def ref_128bits(data):
    return _ref_len_0to128(data, KSECRET, 0)

def ref_128bits_with_seed(data, seed):
    return _ref_len_0to128(data, KSECRET, seed)

# --- DecodeSessionId: transliteration of 0x61af500..0x61affaf. ---
#
# The body is a fully unrolled base-36 accumulation. Length gates
# first (0 / <= 12 / > 24), then the first len-12 characters fold
# into rax (the high part) and the last 12 characters fold into rsi
# (the low part); each character is digit / upper / lower with the
# same three-way value mapping, and any other byte jumps to the
# "Bad digit" error. The final block (0x61afd89) stores
# *out1 = high >> 2 and *out2 = ((high & 3) << 62) | (low & mask62).
# Accumulation cannot overflow: each part holds at most 12 base-36
# digits, so both parts stay below 36**12 < 2**63.

# --- DecodeSessionId: transliteration of 0x61af500..0x61affaf (open PR #5834). ---

def _digit_value(byte):
    """Base-36 digit value, or None for a non-digit byte."""
    if 0x30 <= byte <= 0x39:  # '0'..'9'
        return byte - 0x30
    if 0x41 <= byte <= 0x5A:  # 'A'..'Z'
        return byte - 0x37
    if 0x61 <= byte <= 0x7A:  # 'a'..'z'
        return byte - 0x57
    return None

def decode_session_id(data):
    """Transliteration of rocksdb::DecodeSessionId at 0x61af500.

    Returns (ok, session_id, session_id2, error_message). On error
    the two words are None and the message is the .rodata text the
    binary builds; the Status code is always 3 (kNotSupported).
    """
    n = len(data)
    if n == 0:
        return False, None, None, DECODE_ERRORS["empty"]
    if n <= 12:
        return False, None, None, DECODE_ERRORS["short"]
    if n > 24:
        return False, None, None, DECODE_ERRORS["long"]
    # High part: the first n-12 characters, folded left to right.
    high = 0
    for i in range(n - 12):
        d = _digit_value(data[i])
        if d is None:
            return False, None, None, DECODE_ERRORS["digit"]
        high = high * 36 + d
    # Low part: the last 12 characters, folded left to right.
    low = 0
    for i in range(n - 12, n):
        d = _digit_value(data[i])
        if d is None:
            return False, None, None, DECODE_ERRORS["digit"]
        low = low * 36 + d
    session_id = high >> 2
    session_id2 = (((high & 3) << 62) | (low & MASK62)) & M64
    return True, session_id, session_id2, ""

def decode_session_id_model(data):
    """Independent model of DecodeSessionId.

    Same contract, written from the split formula: the whole string
    is one base-36 number N, the high part is N // 36**12 and the
    low part is N % 36**12. The charset is validated first so the
    int(s, 36) conversion cannot accept anything the binary would
    reject (Python's int() would also take signs and whitespace).
    """
    n = len(data)
    if n == 0:
        return False, None, None, DECODE_ERRORS["empty"]
    if n <= 12:
        return False, None, None, DECODE_ERRORS["short"]
    if n > 24:
        return False, None, None, DECODE_ERRORS["long"]
    for byte in data:
        if _digit_value(byte) is None:
            return False, None, None, DECODE_ERRORS["digit"]
    whole = int(data.decode("ascii"), 36)
    high, low = divmod(whole, 36 ** 12)
    session_id = high >> 2
    session_id2 = (((high & 3) << 62) | (low & MASK62)) & M64
    return True, session_id, session_id2, ""


# --- Hash2x64 wrappers: 0x61c3db0 (unseeded) and 0x61c3de0 (seeded). ---
#
# Each wrapper is one E8 call to the 128-bit one-shot (0x61deab0 /
# 0x61defa0, open PR #5578) and then stores high64 through the first
# out-pointer and low64 through the second. The wrappers return
# (out1, out2) = (high64, low64).

# --- Hash2x64 wrappers: 0x61c3db0 (unseeded) and 0x61c3de0 (seeded) (open PR #5723 via #5834). ---

def hash2x64(data, seed=None):
    """rocksdb::Hash2x64(data, len[, seed], &out1, &out2).

    Returns (out1, out2) = (high64, low64) of the 128-bit one-shot.
    Unseeded runs with seed 0. Lengths above 128 are out of scope
    (the one-shot delegates to the len_129to240 / hashLong helpers).
    """
    if seed is None:
        low, high = xxh3_128bits(data)
    else:
        low, high = xxh3_128bits_with_seed(data, seed & M64)
    return high, low

def hash2x64_model(data, seed=None):
    """Independent model of the Hash2x64 wrappers."""
    if seed is None:
        low, high = ref_128bits(data)
    else:
        low, high = ref_128bits_with_seed(data, seed & M64)
    return high, low


# --- GetSstInternalUniqueId: transliteration of 0x61affe0..0x61b0260. ---
#
# Register map (sret Status* in rdi, then the census parameters):
#   rbx = sret Status* (returned in rax), r12 = db_id string&,
#   rsi = db_session_id string& (saved as rdx after 0x61afff5),
#   rbp = file_number (rcx), r13 = out UniqueIdPtr (r8),
#   r14 = write_third_word (r9), stack bool at rsp+0xa0 = lenient.
#
# Strict path (lenient clear, 0x61b0014 fall-through): db_id empty
# -> "Missing db_id"; file_number == 0 -> "Missing or bad file
# number"; db_session_id empty -> "Missing db_session_id"; then
# DecodeSessionId, whose error Status is copied to *rbx and
# returned (0x61b0067..0x61b008a). Lenient path (0x61b0100): no
# validation, DecodeSessionId straight away; on failure the session
# string is hashed with the unseeded Hash2x64 wrapper (0x61b01c1)
# and a zero low word is replaced by (high | 1) (0x61b01c6..0x61b01db),
# and the failed Status's message is freed, not propagated
# (0x61b013f..0x61b0149). Shared tail (0x61b014e..): out[0] =
# session_id2; Hash2x64(db_id, seed=session_id) seeded wrapper
# (0x61b016d); out[1] = file_number ^ high64; out[2] = low64 only
# when write_third_word is set (0x61b017b..0x61b0185); an OK Status
# is written to *rbx and rbx returned.

# --- GetSstInternalUniqueId: transliteration of 0x61affe0..0x61b0260 (open PR #5834). ---

def get_sst_internal_unique_id(db_id, db_session_id, file_number,
                               write_third_word=False, lenient=False):
    """Transliteration of rocksdb::GetSstInternalUniqueId at 0x61affe0.

    Returns a dict: status_code (0 OK / 3 kNotSupported),
    status_message ("" on success), out0, out1, out2. out2 is None
    when write_third_word is clear: the binary does not write the
    third word in that case. out0/out1 are None on error: the binary
    returns before writing anything to the out buffer.
    """
    file_number &= M64
    if not lenient:
        if len(db_id) == 0:
            return {"status_code": STATUS_NOT_SUPPORTED,
                    "status_message": GET_SST_ERRORS["db_id"],
                    "out0": None, "out1": None, "out2": None}
        if file_number == 0:
            return {"status_code": STATUS_NOT_SUPPORTED,
                    "status_message": GET_SST_ERRORS["file_number"],
                    "out0": None, "out1": None, "out2": None}
        if len(db_session_id) == 0:
            return {"status_code": STATUS_NOT_SUPPORTED,
                    "status_message": GET_SST_ERRORS["session"],
                    "out0": None, "out1": None, "out2": None}
        ok, s1, s2, msg = decode_session_id(db_session_id)
        if not ok:
            return {"status_code": STATUS_NOT_SUPPORTED,
                    "status_message": msg,
                    "out0": None, "out1": None, "out2": None}
    else:
        ok, s1, s2, msg = decode_session_id(db_session_id)
        if not ok:
            high, low = hash2x64(db_session_id)
            s1, s2 = high, low
            if s2 == 0:
                s2 = (s1 | 1) & M64
    out0 = s2
    high, low = hash2x64(db_id, seed=s1)
    out1 = (file_number ^ high) & M64
    out2 = low if write_third_word else None
    return {"status_code": STATUS_OK, "status_message": "",
            "out0": out0, "out1": out1, "out2": out2}

def get_sst_internal_unique_id_model(db_id, db_session_id, file_number,
                                    write_third_word=False,
                                    lenient=False):
    """Independent model of GetSstInternalUniqueId.

    Same branch structure, written against the model helpers so a
    misread of one register flow shows up as a mismatch.
    """
    file_number &= M64
    if not lenient:
        if len(db_id) == 0:
            return {"status_code": STATUS_NOT_SUPPORTED,
                    "status_message": GET_SST_ERRORS["db_id"],
                    "out0": None, "out1": None, "out2": None}
        if file_number == 0:
            return {"status_code": STATUS_NOT_SUPPORTED,
                    "status_message": GET_SST_ERRORS["file_number"],
                    "out0": None, "out1": None, "out2": None}
        if len(db_session_id) == 0:
            return {"status_code": STATUS_NOT_SUPPORTED,
                    "status_message": GET_SST_ERRORS["session"],
                    "out0": None, "out1": None, "out2": None}
        ok, s1, s2, msg = decode_session_id_model(db_session_id)
        if not ok:
            return {"status_code": STATUS_NOT_SUPPORTED,
                    "status_message": msg,
                    "out0": None, "out1": None, "out2": None}
    else:
        ok, s1, s2, msg = decode_session_id_model(db_session_id)
        if not ok:
            high, low = hash2x64_model(db_session_id)
            s1, s2 = high, low
            if s2 == 0:
                s2 = (s1 | 1) & M64
    out0 = s2
    high, low = hash2x64_model(db_id, seed=s1)
    out1 = (file_number ^ high) & M64
    out2 = low if write_third_word else None
    return {"status_code": STATUS_OK, "status_message": "",
            "out0": out0, "out1": out1, "out2": out2}


# --- Binary grounding. ---

# --- BijectiveHash2x64 + UniqueId conversion/encoding (open PR #5831). ---

def _avalanche(x):
    """XXH3 avalanche: (x * 0x165667919e3779f9) ^ (>> 32)."""
    y = (x * 0x165667919E3779F9) & MASK64
    return y ^ (y >> 32)

def bijective_hash2x64(a, b, c):
    """Transliteration of rocksdb::BijectiveHash2x64 at 0x61c3e10.

    Returns (out1, out2). Follows the disassembly instruction by
    instruction; see the packet README for the register-level walk.
    """
    # s = (b^a) ^ (0x59973f0033362349 - c)   (0x61c3e14..0x61c3e31)
    s = ((b ^ a) ^ ((0x59973F0033362349 - c) & MASK64)) & MASK64
    lo = s & MASK32
    hi = s >> 32
    # Four 32x32 products (0x61c3e34..0x61c3e52).
    p1 = (lo * 0x9E3779B1) & MASK64
    p2 = (lo * 0x85EBCA87) & MASK64
    p3 = (hi * 0x85EBCA87) & MASK64
    p4 = (hi * 0x9E3779B1) & MASK64
    # Packed word (0x61c3e56..0x61c3e85): ((mid & 0xffffffff) << 32) |
    # (p2 & 0xffffffff), plus the 0x03c0000000000000 round constant.
    rdx_mid = (p3 + (p2 >> 32) + (p1 & MASK32)) & MASK64
    x0 = (((rdx_mid & MASK32) << 32) | (p2 & MASK32)) & MASK64
    x0 = (x0 + 0x03C0000000000000) & MASK64
    # Second mix (0x61c3e88..0x61c3ead): v = (0xc202797692d63d58 + c) ^ a.
    v = (((0xC202797692D63D58 + c) & MASK64) ^ a) & MASK64
    y0 = (
        (v & MASK32) * 0x85EBCA76
        + p4
        + v
        + (p1 >> 32)
        + (rdx_mid >> 32)
    ) & MASK64
    # x1 = x0 ^ bswap(y0)   (0x61c3eb0..0x61c3eb6)
    x1 = x0 ^ _bswap64(y0)
    m_lo = x1 & MASK32
    m_hi = x1 >> 32
    # Four more 32x32 products (0x61c3eb9..0x61c3ecb).
    q1 = (m_lo * 0x27D4EB4F) & MASK64
    q2 = (m_lo * 0xC2B2AE3D) & MASK64
    q3 = (m_hi * 0x27D4EB4F) & MASK64
    q4 = (m_hi * 0xC2B2AE3D) & MASK64
    # m, y1, r (0x61c3ed2..0x61c3f22).
    m = (q3 + (q1 >> 32) + (q2 & MASK32)) & MASK64
    y1 = (((m & MASK32) << 32) | (q1 & MASK32)) & MASK64
    r = (0xC2B2AE3D27D4EB4F * y0 + q4 + (q2 >> 32) + (m >> 32)) & MASK64
    # out2 = avalanche(y1 ^ ((m & 0xffffffff) >> 5))   (0x61c3f11..0x61c3f36)
    out2 = _avalanche(y1 ^ ((m & MASK32) >> 5))
    # out1 = avalanche(r ^ (r >> 37))   (0x61c3f39..0x61c3f51)
    out1 = _avalanche(r ^ (r >> 37))
    return out1, out2

def bijective_hash2x64_model(a, b, c):
    """Independently structured model of BijectiveHash2x64.

    Same arithmetic as the transliteration, written as named stages
    with explicit 32-bit splits and a shared avalanche helper, so a
    misread of one register flow shows up as a mismatch.
    """
    M = MASK64

    def mul32(x, k):
        return (x * k) & M

    def split32(x):
        return x & MASK32, x >> 32

    s = (a ^ b ^ ((0x59973F0033362349 - c) & M)) & M
    slo, shi = split32(s)
    lo_golden = mul32(slo, 0x9E3779B1)
    lo_prime = mul32(slo, 0x85EBCA87)
    hi_prime = mul32(shi, 0x85EBCA87)
    hi_golden = mul32(shi, 0x9E3779B1)
    mid = (hi_prime + (lo_prime >> 32) + (lo_golden & MASK32)) & M
    packed = (((mid & MASK32) << 32) | (lo_prime & MASK32)) & M
    packed = (packed + 0x03C0000000000000) & M
    v = ((0xC202797692D63D58 + c) & M) ^ a
    y0 = (
        mul32(v & MASK32, 0x85EBCA76)
        + hi_golden
        + v
        + (lo_golden >> 32)
        + (mid >> 32)
    ) & M
    mixed = packed ^ _bswap64(y0)
    xlo, xhi = split32(mixed)
    lo_s = mul32(xlo, 0x27D4EB4F)
    lo_c = mul32(xlo, 0xC2B2AE3D)
    hi_s = mul32(xhi, 0x27D4EB4F)
    hi_c = mul32(xhi, 0xC2B2AE3D)
    m = (hi_s + (lo_s >> 32) + (lo_c & MASK32)) & M
    y1 = (((m & MASK32) << 32) | (lo_s & MASK32)) & M
    r = (0xC2B2AE3D27D4EB4F * y0 + hi_c + (lo_c >> 32) + (m >> 32)) & M
    out2 = _avalanche(y1 ^ ((m & MASK32) >> 5))
    out1 = _avalanche(r ^ (r >> 37))
    return out1, out2

def to_external(w0, w1, w2, flag):
    """Transliteration of InternalUniqueIdToExternal at 0x61b0260.

    Transforms the 24-byte id in place; returns (w0', w1', w2').
    flag False leaves the third word untouched.
    """
    a = (w1 + SALT_W1) & MASK64
    b = (w0 + SALT_W0) & MASK64
    out1, out2 = bijective_hash2x64(a, b, 0)
    nw0, nw1 = out2, out1
    nw2 = (w2 + out1 + out2) & MASK64 if flag else w2
    return nw0, nw1, nw2

def to_external_model(w0, w1, w2, flag):
    """Independent model of InternalUniqueIdToExternal (same staging)."""
    a = (w1 + SALT_W1) & MASK64
    b = (w0 + SALT_W0) & MASK64
    out1, out2 = bijective_hash2x64_model(a, b, 0)
    nw0, nw1 = out2, out1
    nw2 = (w2 + out1 + out2) & MASK64 if flag else w2
    return nw0, nw1, nw2

def encode_unique_id_bytes(w0, w1, w2, flag):
    """Transliteration of EncodeUniqueIdBytes at 0x61b0300.

    24 little-endian bytes (w0, w1, w2) when flag is set, else
    16 bytes (w0, w1).
    """
    if flag:
        return struct.pack("<QQQ", w0, w1, w2)
    return struct.pack("<QQ", w0, w1)

# --- Binary grounding (adapted from open PR #5834). ---

def _read_binary(binary_path):
    blob = Path(binary_path).read_bytes()
    if hashlib.sha256(blob).hexdigest() != ARTIFACT_SHA256:
        raise ValueError("binary digest mismatch: %s" % binary_path)
    return blob

def verify_binary(binary_path):
    """Hash the bound bodies and byte-compare the default secret."""
    blob = _read_binary(binary_path)
    for name, start, end, target in FUNCTIONS:
        body = blob[start - 0x1000:end - 0x1000]
        got = hashlib.sha256(body).hexdigest()
        if got != target:
            raise ValueError("%s body hash mismatch: %s" % (name, got))
    secret = blob[KSECRET_VA:KSECRET_VA + 192]
    if secret != KSECRET:
        raise ValueError("default secret table mismatch at 0x%x" % KSECRET_VA)
    return True

def census_targets():
    """Map start address -> census target_body_sha256."""
    root = Path(__file__).resolve().parents[1]
    census = json.loads((root / CENSUS_PATH).read_text())
    return {r["start"]: r["target_body_sha256"] for r in census["records"]}


# --- Deterministic cases (2,400). ---

BASE36 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# --- GetUniqueIdFromTableProperties: transliteration of 0x61b0490..0x61b0631. ---
#
# Register map (sret Status* in rdi, then the census parameters):
#   rbx = sret Status* (returned in rax), rsi = TableProperties&,
#   rdx = out string* (saved as rbp), r12 = rsp (UniqueIdPtr slot),
#   r9 = write_third_word = 0 (xor r9d at 0x61b049a),
#   stack push $0x0 = lenient = 0 (0x61b04d9).
#
# The call (0x61b04de) passes db_id = props+0xc8 (rsi after
# `add $0xc8,%rsi`), db_session_id = props+0xe8 (rdx),
# file_number = *props = props.orig_file_number (rcx, loaded at
# 0x61b04b7 as `mov -0xc8(%rsi),%rcx`), out = rsp (r8), and the two
# flags clear. On a non-OK Status (`cmpb $0x0,(%rbx)` at 0x61b04e3)
# the out string is cleared to "" (0x61b04eb..0x61b04f7: size 0, NUL
# at ptr[0], buffer kept) and the Status is returned as-is. On
# success (0x61b0520): InternalUniqueIdToExternal(id, flag=0),
# EncodeUniqueIdBytes(string at rsp+0x10, id, flag=0), then the
# 16-byte string is move-assigned into *out (0x61b0539..0x61b061e:
# std::string move-assign with SSO handling, old buffer freed via
# operator delete when replaced, memcpy for the long form), and the
# OK Status is returned.

def get_unique_id_from_table_properties(db_id, db_session_id,
                                       orig_file_number):
    """Transliteration of rocksdb::GetUniqueIdFromTableProperties at 0x61b0490.

    Returns a dict: status_code (0 OK / 3 kNotSupported),
    status_message ("" on success), out (the 16-byte external id on
    success, b"" on error: the binary clears *out and returns the
    Status from GetSstInternalUniqueId).
    """
    sst = get_sst_internal_unique_id(
        db_id, db_session_id, orig_file_number,
        write_third_word=False, lenient=False)
    if sst["status_code"] != STATUS_OK:
        return {"status_code": sst["status_code"],
                "status_message": sst["status_message"], "out": b""}
    # The third word is never written by GetSstInternalUniqueId
    # (write_third_word clear) and InternalUniqueIdToExternal with
    # flag clear passes it through untouched; EncodeUniqueIdBytes
    # with flag clear reads only the first two words, so the
    # unwritten third word cannot affect the output (0 is used here
    # as its placeholder).
    ext0, ext1, _ext2 = to_external(sst["out0"], sst["out1"], 0, False)
    out = encode_unique_id_bytes(ext0, ext1, 0, False)
    return {"status_code": STATUS_OK, "status_message": "", "out": out}


def get_unique_id_from_table_properties_model(db_id, db_session_id,
                                             orig_file_number):
    """Independent model of GetUniqueIdFromTableProperties.

    Same branch structure, written against the model helpers so a
    misread of one register flow shows up as a mismatch.
    """
    sst = get_sst_internal_unique_id_model(
        db_id, db_session_id, orig_file_number,
        write_third_word=False, lenient=False)
    if sst["status_code"] != STATUS_OK:
        return {"status_code": sst["status_code"],
                "status_message": sst["status_message"], "out": b""}
    ext0, ext1, _ext2 = to_external_model(
        sst["out0"], sst["out1"], 0, False)
    out = encode_unique_id_bytes(ext0, ext1, 0, False)
    return {"status_code": STATUS_OK, "status_message": "", "out": out}


# --- Deterministic cases (2,400). ---

BASE36 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _rng():
    return random.Random(0x61B0490)


def _rand_base36(rng, length):
    return bytes(rng.choice(BASE36) for _ in range(length))


def _rand_bytes(rng, length):
    return bytes(rng.randrange(256) for _ in range(length))


def _rand_db_id(rng, style):
    if style == 0:  # UUID-like, the realistic db_id form.
        hexpart = "%08x-%04x-%04x-%04x-%012x" % (
            rng.getrandbits(32), rng.getrandbits(16),
            rng.getrandbits(16), rng.getrandbits(16),
            rng.getrandbits(48))
        return hexpart.encode()
    if style == 1:
        return _rand_base36(rng, rng.choice([1, 8, 16, 36, 64, 128]))
    if style == 2:
        return _rand_bytes(rng, rng.choice([1, 16, 36, 100, 128]))
    return b""


def generate_cases():
    """2,400 deterministic cases across the two case kinds.

    table_properties: 1,800 end-to-end cases over (db_id,
    db_session_id, orig_file_number), covering valid UUID-like ids
    and valid sessions (the success path), every error gate
    (empty db_id, file number 0, empty session, short/long/bad
    sessions), boundary file numbers and long ids/sessions.
    external_encode: 600 cases over (w0, w1) pinning the
    to_external + encode composition with flag clear.
    """
    rng = _rng()
    cases = []

    # --- table_properties: 1,800 cases. ---
    file_numbers = [0, 1, 2, 7, 123456, 2**32 - 1, 2**32,
                    2**63 - 1, 2**63, 2**64 - 1]
    for i in range(1800):
        style = i % 8
        if style == 0:
            db_id = _rand_db_id(rng, 0)
            session = _rand_base36(rng, rng.choice([13, 14, 20, 24]))
            file_number = file_numbers[i % len(file_numbers)] or 1
        elif style == 1:
            db_id = b""
            session = _rand_base36(rng, 20)
            file_number = file_numbers[i % len(file_numbers)]
        elif style == 2:
            db_id = _rand_db_id(rng, 0)
            session = _rand_base36(rng, 20)
            file_number = 0
        elif style == 3:
            db_id = _rand_db_id(rng, 0)
            session = b""
            file_number = file_numbers[i % len(file_numbers)] or 1
        elif style == 4:
            db_id = _rand_db_id(rng, rng.choice([1, 2]))
            session = _rand_base36(rng, rng.choice([0, 1, 5, 12]))
            file_number = file_numbers[i % len(file_numbers)]
        elif style == 5:
            db_id = _rand_db_id(rng, 0)
            session = _rand_base36(rng, rng.choice([25, 26, 30, 40]))
            file_number = file_numbers[i % len(file_numbers)] or 1
        elif style == 6:
            db_id = _rand_db_id(rng, 0)
            session = bytearray(_rand_base36(rng, 20))
            session[rng.randrange(20)] = rng.choice(b"-_ .!@#")
            session = bytes(session)
            file_number = file_numbers[i % len(file_numbers)] or 1
        else:
            db_id = _rand_db_id(rng, rng.choice([0, 1, 2]))
            session = _rand_base36(
                rng, rng.choice([13, 16, 24, 0, 12, 25]))
            file_number = rng.getrandbits(64)
        got = get_unique_id_from_table_properties(
            db_id, session, file_number)
        cases.append({
            "kind": "table_properties", "index": i,
            "db_id_hex": db_id.hex(),
            "session_hex": session.hex(),
            "file_number_hex": "%016x" % file_number,
            "status_code": got["status_code"],
            "status_message": got["status_message"],
            "out_hex": got["out"].hex(),
        })

    # --- external_encode: 600 cases. ---
    boundary = [
        0, 1, 2, 0xFFFFFFFF, 0x100000000, 0xFFFFFFFFFFFFFFFF,
        0x8000000000000000, 0x590EB907C873E891, 0xF1598607FB45CBD8,
        0x59973F0033362349, 0xC202797692D63D58,
    ]
    for i in range(600):
        if i < len(boundary) * 2:
            w0 = boundary[i % len(boundary)]
            w1 = boundary[(i * 5) % len(boundary)]
        else:
            w0 = rng.getrandbits(64)
            w1 = rng.getrandbits(64)
        e0, e1, _e2 = to_external(w0, w1, 0, False)
        out = encode_unique_id_bytes(e0, e1, 0, False)
        cases.append({
            "kind": "external_encode", "index": i,
            "w0_hex": "%016x" % w0,
            "w1_hex": "%016x" % w1,
            "status_code": STATUS_OK,
            "status_message": "",
            "out_hex": out.hex(),
        })
    return cases


def verify(binary_path):
    """Ground the binary, then re-run all cases against the models."""
    verify_binary(binary_path)
    cases = generate_cases()
    mismatches = 0
    for case in cases:
        if case["kind"] == "table_properties":
            got = get_unique_id_from_table_properties(
                bytes.fromhex(case["db_id_hex"]),
                bytes.fromhex(case["session_hex"]),
                int(case["file_number_hex"], 16))
            want = get_unique_id_from_table_properties_model(
                bytes.fromhex(case["db_id_hex"]),
                bytes.fromhex(case["session_hex"]),
                int(case["file_number_hex"], 16))
            good = (got == want
                    and got["status_code"] == case["status_code"]
                    and got["status_message"] == case["status_message"]
                    and got["out"].hex() == case["out_hex"])
        else:
            e0, e1, _e2 = to_external(
                int(case["w0_hex"], 16), int(case["w1_hex"], 16),
                0, False)
            m0, m1, _m2 = to_external_model(
                int(case["w0_hex"], 16), int(case["w1_hex"], 16),
                0, False)
            out = encode_unique_id_bytes(e0, e1, 0, False)
            good = ((e0, e1) == (m0, m1)
                    and out.hex() == case["out_hex"])
        if not good:
            mismatches += 1
    checks = {
        "128bits(b'')": xxh3_128bits(b""),
        "128bits(b'a')": xxh3_128bits(b"a"),
        "128bits(b'abc')": xxh3_128bits(b"abc"),
        "table_properties": get_unique_id_from_table_properties(
            b"123e4567-e89b-12d3-a456-426614174000",
            b"0123456789ABCDEF0123", 123456),
    }
    published = {"128bits(b'')": (0x6001C324468D497F, 0x99AA06D3014798D8)}
    for key, want in published.items():
        if checks[key] != want:
            raise ValueError("published anchor mismatch: %s = %s"
                             % (key, checks[key]))
    print("%d cases agree (%d mismatches)" % (len(cases), mismatches))
    for key, value in checks.items():
        print("  %s = %s" % (key, value))
    return mismatches


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--binary", default="work/hl-node-115.bin")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.verify:
        raise SystemExit(1 if verify(args.binary) else 0)
    if args.out is not None:
        verify_binary(args.binary)
        cases = generate_cases()
        mismatches = 0
        for case in cases:
            if case["kind"] == "table_properties":
                want = get_unique_id_from_table_properties_model(
                    bytes.fromhex(case["db_id_hex"]),
                    bytes.fromhex(case["session_hex"]),
                    int(case["file_number_hex"], 16))
                good = (want["status_code"] == case["status_code"]
                        and want["status_message"]
                        == case["status_message"]
                        and want["out"].hex() == case["out_hex"])
            else:
                m0, m1, _m2 = to_external_model(
                    int(case["w0_hex"], 16), int(case["w1_hex"], 16),
                    0, False)
                out = encode_unique_id_bytes(m0, m1, 0, False)
                good = out.hex() == case["out_hex"]
            if not good:
                mismatches += 1
        fixed = get_unique_id_from_table_properties(
            b"123e4567-e89b-12d3-a456-426614174000",
            b"0123456789ABCDEF0123", 123456)
        result = {
            "artifact": "node115",
            "artifact_sha256": ARTIFACT_SHA256,
            "functions": [
                {"name": name, "start": "0x%x" % s, "end": "0x%x" % e,
                 "body_sha256": t,
                 "scope": "db_id/session inputs of length 0..128"}
                for name, s, e, t in FUNCTIONS
            ],
            "cases": {
                "table_properties": 1800,
                "external_encode": 600,
                "total": len(cases),
            },
            "total_cases": len(cases),
            "mismatches": mismatches,
            "check_values": {
                "128bits(b'')": ["%016x" % v for v in xxh3_128bits(b"")],
                "128bits(b'a')": ["%016x" % v for v in xxh3_128bits(b"a")],
                "128bits(b'abc')":
                    ["%016x" % v for v in xxh3_128bits(b"abc")],
                "table_properties(fixed)": {
                    "status_code": fixed["status_code"],
                    "status_message": fixed["status_message"],
                    "out_hex": fixed["out"].hex(),
                },
            },
        }
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "result.json").write_text(json.dumps(result, indent=1) + "\n")
        print("wrote %s (%d cases, %d mismatches)"
              % (args.out / "result.json", len(cases), mismatches))
        raise SystemExit(1 if mismatches else 0)
    parser.print_help()
    raise SystemExit(2)


if __name__ == "__main__":
    main()
