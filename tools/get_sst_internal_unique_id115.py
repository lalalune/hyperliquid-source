#!/usr/bin/env python3
"""Node #115 `rocksdb::GetSstInternalUniqueId` + `DecodeSessionId`.

Reconstructs two vendored RocksDB functions from the node #115 binary
(artifact SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* `rocksdb::GetSstInternalUniqueId` at 0x61affe0..0x61b0260
  (640 bytes, census node115-vendor-61affe0, body SHA-256
  1b64d1af98c276016dc33017c08fd35534868998668d2a72e123ddaa0d0db1be):
  derives a 24-byte internal UniqueId for an SST file from the DB id,
  the DB session id and the file number. Strict mode validates the
  inputs and propagates `DecodeSessionId` errors; lenient mode skips
  validation and falls back to hashing the session string when the
  decode fails (the degraded functionality the upstream header
  documents for non-standard session ids). The result words are
  (session_id2, file_number ^ Hash2x64(db_id, seed=session_id).high,
  Hash2x64(db_id, seed=session_id).low), where the third word is
  written only when the write_third_word flag is set.
* `rocksdb::DecodeSessionId` at 0x61af500..0x61affaf
  (2735 bytes, census node115-vendor-61af500, body SHA-256
  73426de07243605a472e661f6b4a59094c4a8094cf5dc5b54cf2bfa970761cb9):
  parses a base-36 DB session id string of 13..24 characters into
  two u64s. The string splits into a high part (the first len-12
  characters) and a low part (the last 12 characters); with
  high = base36(s[:len-12]) and low = base36(s[len-12:]),
  session_id = high >> 2 and
  session_id2 = ((high & 3) << 62) | (low & 0x3fffffffffffffff).
  Length 0 / <= 12 / > 24 and non-base-36 digits are errors with
  Status code 3 (kNotSupported) and the messages
  "Missing db_session_id" / "Too short db_session_id" /
  "Too long db_session_id" / "Bad digit in db_session_id"
  (21 / 23 / 22 / 26 bytes at .rodata 0x43430e / 0x435387 /
  0x44b53f / 0x43333e).

Both functions return Status through the hidden sret pointer the
Itanium ABI uses for the non-trivially-destructible Status class;
the model below returns (status_code, status_message, ...) tuples
instead. The error code is 3 (kNotSupported) everywhere the binary
builds an error Status: the Status ctor is called with code 3
(`mov $0x3,%esi` at 0x61b00c9 / 0x61af5fe / 0x61af63b), and the
upstream header documents DecodeSessionId as returning NotSupported
"because non-standard session IDs should be allowed with degraded
functionality".

The function takes two boolean flags beyond the five parameters the
census symbol demangles to
(`(const string&, const string&, unsigned long, UniqueIdPtr, bool)`):
the sixth register argument (r9) gates the third output word and
the seventh argument (a bool on the stack) selects the lenient
path. All seven in-binary call sites pass the first flag clear; the
lenient flag is set only at the two read paths
(`BlockBasedTable::Open` 0x6120bc5 and the `OffsetableCacheKey`
constructor 0x5daf6e8) and clear at the five write/ingest paths
(see callers.tsv). No source names are claimed for the flags.

The Hash2x64 callees are the thin wrappers reconstructed in open
PR #5723 (`rocksdb::Hash2x64` unseeded at 0x61c3db0, 35 bytes, body
cdf83f11...; seeded at 0x61c3de0, 35 bytes, body 77d46c5d...), each
delegating to a 128-bit one-shot (0x61deab0 / 0x61defa0, open
PR #5578) and storing high64 through the first out-pointer and
low64 through the second. The 128-bit one-shot transliteration
below is adapted from the #5578 tool (same author) so the wrappers
execute end-to-end; the one-shots' standalone reconstruction is
#5578, and lengths above 128 delegate to the len_129to240 helper
at 0x61d80a0 (open PR #5595) and the hashLong helpers at
0x61d8a60 / 0x61d9bc0 (open PR #5598), which are out of scope here:
this tool covers hashed inputs of length 0..128 only, which covers
every realistic db_id (a UUID string) and db_session_id (13..24
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

# (name, start, end, target_body_sha256) of every function this packet
# binds, in FDE order. The two Hash2x64 wrappers are direct callees
# (context); GetSstInternalUniqueId and DecodeSessionId are the claim.
FUNCTIONS = [
    ("DecodeSessionId", 0x61AF500, 0x61AFFAF,
     "73426de07243605a472e661f6b4a59094c4a8094cf5dc5b54cf2bfa970761cb9"),
    ("GetSstInternalUniqueId", 0x61AFFE0, 0x61B0260,
     "1b64d1af98c276016dc33017c08fd35534868998668d2a72e123ddaa0d0db1be"),
    ("Hash2x64", 0x61C3DB0, 0x61C3DD3,
     "cdf83f118dae4ddaabf19ff5fef1f5c12469608c9664d39a3b95b0389165ce3f"),
    ("Hash2x64_withSeed", 0x61C3DE0, 0x61C3E03,
     "77d46c5d98d167a3da48e8471c2ded2361ced5e47565abbdc0c11628ab785b7b"),
]
KSECRET_VA = 0x97EC80


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


def _rng():
    return random.Random(0x61AFFE0)


def _rand_base36(rng, length):
    return bytes(rng.choice(BASE36) for _ in range(length))


def _rand_bytes(rng, length):
    return bytes(rng.randrange(256) for _ in range(length))


def generate_cases():
    """2,400 deterministic cases across the three case kinds.

    decode_session: 600 cases covering every length 0..25, valid
    strings (mixed case, digits only, letters only), bad digits,
    and case-equivalence pairs. hash2x64: 600 cases over lengths
    0..128, seeded and unseeded, boundary and random data.
    get_sst: 1,200 end-to-end cases over realistic and boundary
    inputs in both strict and lenient mode, both flag values.
    """
    rng = _rng()
    cases = []

    # --- decode_session: 600 cases. ---
    for i in range(600):
        if i < 26:
            length = i  # every length 0..25 once
        elif i < 126:
            length = 13 + (i % 12)  # valid lengths 13..24
        else:
            length = rng.choice([0, 1, 5, 12, 13, 14, 23, 24, 25,
                                 26, 30, 40])
        style = i % 6
        if style == 0:
            data = _rand_base36(rng, length)
        elif style == 1:
            data = bytes(rng.choice(b"0123456789") for _ in range(length))
        elif style == 2:
            data = bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz")
                         for _ in range(length))
        elif style == 3:
            data = bytes(rng.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                         for _ in range(length))
        elif style == 4 and length > 0:
            data = bytearray(_rand_base36(rng, length))
            data[rng.randrange(length)] = rng.choice(b"-_ .!@#")
            data = bytes(data)
        else:
            data = _rand_bytes(rng, length)
        ok, s1, s2, msg = decode_session_id(data)
        cases.append({
            "kind": "decode_session", "index": i,
            "session_hex": data.hex(),
            "status_code": STATUS_OK if ok else STATUS_NOT_SUPPORTED,
            "status_message": msg,
            "out0_hex": ("%016x" % s1) if ok else "",
            "out1_hex": ("%016x" % s2) if ok else "",
        })

    # --- hash2x64: 600 cases. ---
    seeds = [0, 1, 2, PRIME64_1, 0xFFFFFFFFFFFFFFFF,
             0x123456789ABCDEF0, 0x8000000000000000, 42]
    for _ in range(4):
        seeds.append(rng.getrandbits(64))
    for i in range(600):
        length = i % 129
        if i < 60:
            if length == 0:
                data = b""
            elif i % 4 == 0:
                data = bytes(length)
            elif i % 4 == 1:
                data = b"\xff" * length
            elif i % 4 == 2:
                data = bytes((j * 7 + 3) & 0xFF for j in range(length))
            else:
                data = _rand_bytes(rng, length)
        else:
            data = _rand_bytes(rng, length)
        if i % 2 == 0:
            high, low = hash2x64(data)
            cases.append({
                "kind": "hash2x64", "index": i,
                "data_hex": data.hex(), "seed_hex": "",
                "out0_hex": "%016x" % low, "out1_hex": "%016x" % high,
            })
        else:
            seed = seeds[(i // 2) % len(seeds)]
            high, low = hash2x64(data, seed=seed)
            cases.append({
                "kind": "hash2x64", "index": i,
                "data_hex": data.hex(), "seed_hex": "%016x" % seed,
                "out0_hex": "%016x" % low, "out1_hex": "%016x" % high,
            })

    # --- get_sst: 1,200 end-to-end cases. ---
    uuid_like = b"0192a3f4-5b6c-7d8e-9f01-23456789abcd"
    for i in range(1200):
        style = i % 8
        if style == 0:
            db_id = uuid_like
        elif style == 1:
            db_id = _rand_base36(rng, rng.choice([1, 8, 16, 36, 64, 128]))
        elif style == 2:
            db_id = _rand_bytes(rng, i % 129)
        elif style == 3:
            db_id = b""
        elif style == 4:
            db_id = bytes(rng.choice(b"0123456789abcdef-")
                          for _ in range(rng.choice([36, 32, 40])))
        else:
            db_id = _rand_bytes(rng, rng.choice([0, 1, 17, 36, 100, 128]))
        sstyle = i % 6
        if sstyle == 0:
            session = _rand_base36(rng, rng.choice([13, 16, 20, 24]))
        elif sstyle == 1:
            session = _rand_base36(rng, 13 + (i % 12))
        elif sstyle == 2:
            session = _rand_bytes(rng, rng.choice([0, 1, 12, 13, 24, 25]))
        elif sstyle == 3:
            session = bytearray(_rand_base36(rng, 16))
            session[rng.randrange(16)] = ord("-")
            session = bytes(session)
        elif sstyle == 4:
            session = b""
        else:
            session = _rand_base36(rng, rng.choice([13, 24]))
        if i % 11 == 0:
            file_number = 0
        elif i % 11 == 1:
            file_number = 1
        elif i % 11 == 2:
            file_number = 0xFFFFFFFFFFFFFFFF
        else:
            file_number = rng.getrandbits(64)
        write_third_word = bool(i % 2)
        lenient = bool((i // 2) % 2)
        got = get_sst_internal_unique_id(
            db_id, session, file_number, write_third_word, lenient)
        cases.append({
            "kind": "get_sst", "index": i,
            "db_id_hex": db_id.hex(), "session_hex": session.hex(),
            "file_number_hex": "%016x" % file_number,
            "write_third_word": int(write_third_word),
            "lenient": int(lenient),
            "status_code": got["status_code"],
            "status_message": got["status_message"],
            "out0_hex": ("%016x" % got["out0"]) if got["out0"] is not None else "",
            "out1_hex": ("%016x" % got["out1"]) if got["out1"] is not None else "",
            "out2_hex": ("%016x" % got["out2"]) if got["out2"] is not None else "",
        })
    return cases


def verify(binary_path):
    """Ground the binary, then re-run all cases against the models."""
    verify_binary(binary_path)
    cases = generate_cases()
    mismatches = 0
    for case in cases:
        if case["kind"] == "decode_session":
            data = bytes.fromhex(case["session_hex"])
            ok, s1, s2, msg = decode_session_id(data)
            mok, ms1, ms2, mmsg = decode_session_id_model(data)
            good = ((ok, s1, s2, msg) == (mok, ms1, ms2, mmsg)
                    and (STATUS_OK if ok else STATUS_NOT_SUPPORTED)
                    == case["status_code"]
                    and msg == case["status_message"])
        elif case["kind"] == "hash2x64":
            data = bytes.fromhex(case["data_hex"])
            if case["seed_hex"]:
                seed = int(case["seed_hex"], 16)
                got = hash2x64(data, seed=seed)
                ref = hash2x64_model(data, seed=seed)
            else:
                got = hash2x64(data)
                ref = hash2x64_model(data)
            good = (got == ref
                    and ("%016x" % got[1]) == case["out0_hex"]
                    and ("%016x" % got[0]) == case["out1_hex"])
        else:
            db_id = bytes.fromhex(case["db_id_hex"])
            session = bytes.fromhex(case["session_hex"])
            file_number = int(case["file_number_hex"], 16)
            got = get_sst_internal_unique_id(
                db_id, session, file_number,
                bool(case["write_third_word"]), bool(case["lenient"]))
            want = get_sst_internal_unique_id_model(
                db_id, session, file_number,
                bool(case["write_third_word"]), bool(case["lenient"]))
            good = (got == want
                    and got["status_code"] == case["status_code"]
                    and got["status_message"] == case["status_message"])
        if not good:
            mismatches += 1
    checks = {
        "128bits(b'')": xxh3_128bits(b""),
        "128bits(b'a')": xxh3_128bits(b"a"),
        "128bits(b'abc')": xxh3_128bits(b"abc"),
        "128bits(b'123456789')": xxh3_128bits(b"123456789"),
        "decode(b'0' * 13)": decode_session_id(b"0" * 13),
        "decode(b'ZZZZZZZZZZZZZ')": decode_session_id(b"ZZZZZZZZZZZZZ"),
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
    parser.add_argument("--binary", default="artifacts/node/115/hl-node")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.verify:
        raise SystemExit(1 if verify(args.binary) else 0)
    if args.out is not None:
        verify_binary(args.binary)
        cases = generate_cases()
        mismatches = 0
        for case in cases:
            if case["kind"] == "decode_session":
                data = bytes.fromhex(case["session_hex"])
                ok, s1, s2, msg = decode_session_id_model(data)
                good = ((STATUS_OK if ok else STATUS_NOT_SUPPORTED)
                        == case["status_code"] and msg == case["status_message"])
            elif case["kind"] == "hash2x64":
                data = bytes.fromhex(case["data_hex"])
                if case["seed_hex"]:
                    ref = hash2x64_model(data, seed=int(case["seed_hex"], 16))
                else:
                    ref = hash2x64_model(data)
                good = (("%016x" % ref[1]) == case["out0_hex"]
                        and ("%016x" % ref[0]) == case["out1_hex"])
            else:
                want = get_sst_internal_unique_id_model(
                    bytes.fromhex(case["db_id_hex"]),
                    bytes.fromhex(case["session_hex"]),
                    int(case["file_number_hex"], 16),
                    bool(case["write_third_word"]), bool(case["lenient"]))
                good = (want["status_code"] == case["status_code"]
                        and want["status_message"] == case["status_message"])
            if not good:
                mismatches += 1
        result = {
            "artifact": "node115",
            "artifact_sha256": ARTIFACT_SHA256,
            "functions": [
                {"name": name, "start": "0x%x" % s, "end": "0x%x" % e,
                 "body_sha256": t, "scope": "hashed inputs of length 0..128"}
                for name, s, e, t in FUNCTIONS
            ],
            "cases": {
                "decode_session": 600,
                "hash2x64": 600,
                "get_sst": 1200,
                "total": len(cases),
            },
            "total_cases": len(cases),
            "mismatches": mismatches,
            "check_values": {
                "128bits(b'')": ["%016x" % v for v in xxh3_128bits(b"")],
                "128bits(b'a')": ["%016x" % v for v in xxh3_128bits(b"a")],
                "128bits(b'abc')": ["%016x" % v for v in xxh3_128bits(b"abc")],
                "decode(b'0' * 13)": list(decode_session_id(b"0" * 13)),
                "decode(b'ZZZZZZZZZZZZZ')": list(
                    decode_session_id(b"ZZZZZZZZZZZZZ")),
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
