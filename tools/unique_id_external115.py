#!/usr/bin/env python3
"""Node #115 `rocksdb` UniqueId external conversion + byte encode/decode.

Reconstructs three vendored RocksDB functions from the node #115 binary
(artifact SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* `rocksdb::InternalUniqueIdToExternal` at 0x61b0260..0x61b02f3
  (147 bytes, census node115-vendor-61b0260, body SHA-256
  9a1ae61f46968c646f4819250736e6139b911e675e7b9488a987d54a299533de):
  transforms a 24-byte UniqueId (three little-endian u64 words) in
  place. With (w0, w1, w2) as the input words and
  (out1, out2) = BijectiveHash2x64(w1 + 0xf1598607fb45cbd8,
  w0 + 0x590eb907c873e891, c = 0), the result is (out2, out1, w2),
  except that when the flag is set the third word becomes
  w2 + out1 + out2. The two additive constants are immediates in the
  body; no source for them beyond the bytes is claimed.
* `rocksdb::EncodeUniqueIdBytes` at 0x61b0300..0x61b0381 (129 bytes,
  census node115-vendor-61b0300, body SHA-256
  520abebd6899cd3cb64cac38e28f69dcfbb0a0cde30ccfbd0f79b5454c372044):
  serializes the id to a std::string of 24 bytes (w0, w1, w2,
  little-endian) when the flag is set, else 16 bytes (w0, w1).
* `rocksdb::DecodeUniqueIdBytes` at 0x61b0390..0x61b045f (207 bytes,
  census node115-vendor-61b0390, body SHA-256
  8522807e5003634305476eb6c50f6b987a2e80f4f2326d68f77fa2bc83e97054):
  the inverse. It requires the string to be exactly 24 bytes when
  the flag is set, else exactly 16 bytes; on a length mismatch it
  returns Status InvalidArgument with the message
  "Not a valid unique_id" (21 bytes at .rodata 0x434324) and leaves
  the output id untouched. On success it writes w0, w1 (and w2 when
  the flag is set) and returns an OK Status.

The flag is the same one in all three functions: set selects the
24-byte / third-word form, clear selects the 16-byte form. The only
in-binary caller that uses both the conversion and the encoder,
`GetUniqueIdFromTableProperties` at 0x61b0490, passes 0 for both
(0x61b0525, 0x61b0534), so the 16-byte form is the live one there;
no claim is made about what the flag is called in the source.

The transform depends on the callee `rocksdb::BijectiveHash2x64` at
0x61c3e10 (325 bytes, census node115-vendor-61c3e10, body SHA-256
d586664de83493cc5a48eefd3bcef95b10a3ab433b32699334c68671b8cb0864,
raw_equal true) reached through its seed-0 adapter at 0x61c3f60
(17 bytes, no census record: below the 32-byte minimum), which
sets c = 0 and forwards (out1, out2) through rcx/r8. The adapter
is a 4-instruction tail jump; the transliteration below is derived
from the callee's own disassembly so the transform executes
end-to-end, and is cross-checked in the tests against an
independently structured model. The callee's standalone
reconstruction is open PR #5720; this packet claims only the three
UniqueId functions above.

No binary is executed by this tool; the models below are checked
against each other and against the binary's bytes.
"""

import hashlib
import json
import struct
from pathlib import Path

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
CENSUS_PATH = (
    "research/work-items/RE-002-node115-vendor-census/census.json"
)

# Additive salts in InternalUniqueIdToExternal (movabs immediates at
# 0x61b0268 and 0x61b027d).
SALT_W0 = 0x590EB907C873E891
SALT_W1 = 0xF1598607FB45CBD8

DECODE_ERROR_MESSAGE = "Not a valid unique_id"


def _bswap64(x):
    return int.from_bytes((x & MASK64).to_bytes(8, "little"), "big")


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


def decode_unique_id_bytes(data, flag):
    """Transliteration of DecodeUniqueIdBytes at 0x61b0390.

    Returns (ok, (w0, w1, w2_or_None), message). On a length
    mismatch ok is False, the words are None, and the message is the
    InvalidArgument text the binary builds ("Not a valid unique_id").
    On success w2 is None when flag is clear: the binary does not
    write the third word in the 16-byte form.
    """
    expected = 24 if flag else 16
    if len(data) != expected:
        return False, None, DECODE_ERROR_MESSAGE
    if flag:
        w0, w1, w2 = struct.unpack("<QQQ", data)
    else:
        w0, w1 = struct.unpack("<QQ", data)
        w2 = None
    return True, (w0, w1, w2), ""


# (start, end) of every function this packet binds, in FDE order.
FUNCTIONS = (
    (0x61B0260, 0x61B02F3),
    (0x61B0300, 0x61B0381),
    (0x61B0390, 0x61B045F),
    (0x61C3E10, 0x61C3F55),
    (0x61C3F60, 0x61C3F71),
)


def census_targets():
    """Map start address -> census target_body_sha256."""
    root = Path(__file__).resolve().parents[1]
    census = json.loads((root / CENSUS_PATH).read_text())
    return {r["start"]: r["target_body_sha256"] for r in census["records"]}


def verify_binary(binary_path):
    """Map start address -> SHA-256 of the FDE body in the binary.

    .text file offset is VA - 0x1000 in work/hl-node-115.bin.
    """
    binary = Path(binary_path).read_bytes()
    out = {}
    for start, end in FUNCTIONS:
        body = binary[start - 0x1000 : end - 0x1000]
        out[start] = hashlib.sha256(body).hexdigest()
    return out
