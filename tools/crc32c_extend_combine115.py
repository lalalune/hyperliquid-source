#!/usr/bin/env python3
"""Node #115 `rocksdb::crc32c` slow-path reconstruction.

Reconstructs two vendored RocksDB functions from the node #115 binary
(artifact SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* `rocksdb::crc32c::ExtendImpl<Slow_CRC32>` at 0x61c21d0..0x61c23b9
  (489 bytes, census node115-vendor-61c21d0, body SHA-256
  84b07761adc5476aeaa34ab231b330bd77f0b1fca654c2b6772f752d38d704a8):
  the table-driven CRC-32C (Castagnoli, reflected poly 0x82f63b78) extend.
  Byte-at-a-time prologue to a 16-byte boundary, slicing-by-4 main loop
  (16 bytes, then 8 bytes per round), byte-at-a-time tail. The four
  256-entry tables live in .rodata at 0x97cee0 (T3), 0x97d2e0 (T2),
  0x97d6e0 (T1), 0x97dae0 (T0); T0 is the standard CRC-32C base table
  and T_k is T0 advanced by k zero bytes (verified for all 256 entries).
* `rocksdb::crc32c::Crc32cCombine` at 0x61c2600..0x61c26c9 (201 bytes,
  census node115-vendor-61c2600, body SHA-256
  09b69c91e274c5adf31eb408cf6a7fc004f4db177f34b61dc053cff1b8b4480c):
  combine(crc1, crc2, len2) == crc2 ^ advance_raw(crc1, 8*len2), where
  advance_raw is the reflected one-bit CRC step. The binary implements
  the advance with a 32-entry .rodata table at 0x97cde0 (entry[0] is the
  polynomial; the inner loop multiplies the state by x^(32*2^p) for each
  set bit p of len2>>2) plus a slow path for len2 % 4 != 0 that advances
  by the remainder through the public Extend entry.

The public `crc32c::Extend` entry is the 16-byte stub at 0x61c25f0, which
jumps through the BSS function pointer at 0x6508908. The only writer of
that slot in .text is the init function at 0x61c26d0..0x61c26e3, which
stores the address of ExtendImpl (0x61c21d0); the fast CRC-32C path is
unavailable on this binary (IsFastCrc32Supported at 0x61c2400 returns
"Not supported on x86", reconstructed in an earlier packet), so the slow
path is the live Extend. Which initializer calls 0x61c26d0 is not
established (no direct E8 caller; not in .init_array) and is recorded
as an unknown in the packet.

Degenerate case, verified against the disassembly and both models:
Crc32cCombine(crc1, crc2, 0) returns crc1 ^ crc2 -- there is no len2==0
early return. The three in-binary call sites always pass crc2 equal to
Extend(0, buf, len2), which is 0 when len2==0, so the result is correct
there; a caller passing an arbitrary crc2 with len2==0 would get
crc1^crc2 instead of crc1.

All arithmetic is over GF(2) with the reflected Castagnoli polynomial.
No binary is executed; the models below are checked against each other
and against the published CRC-32C check value.
"""

import hashlib
import json
import struct
from pathlib import Path

POLY = 0x82F63B78
MASK32 = 0xFFFFFFFF

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
CENSUS_PATH = (
    "research/work-items/RE-002-node115-vendor-census/census.json"
)

# .rodata tables (verified against work/hl-node-115.bin; SHA-256 in the packet).
TABLE_VAS = {
    "t3": 0x97CEE0,
    "t2": 0x97D2E0,
    "t1": 0x97D6E0,
    "t0": 0x97DAE0,
}
COMBINE_TABLE_VA = 0x97CDE0

# The 32-entry combine table, extracted from .rodata at 0x97cde0.
# Entry 0 is the polynomial; entry[i] is the polynomial for x^(32*2^i).
# The packet stores the raw bytes (crc32c_combine_table115.bin, SHA-256
# 972d7728fced25b6a41f9631128f65353fb9328c7db55b469b3559f1e196afea).
COMBINE_TABLE = (
    0x82F63B78, 0x6EA2D55C, 0x18B8EA18, 0x510AC59A, 0xB82BE955, 0xB8FDB1E7,
    0x88E56F72, 0x74C360A4, 0xE4172B16, 0x0D65762A, 0x35D73A62, 0x28461564,
    0xBF455269, 0xE2EA32DC, 0xFE7740E6, 0xF946610B, 0x3C204F8F, 0x538586E3,
    0x59726915, 0x734D5309, 0xBC1AC763, 0x7D0722CC, 0xD289CABE, 0xE94CA9BC,
    0x05B74F3F, 0xA51E1F42, 0x40000000, 0x20000000, 0x08000000, 0x00800000,
    0x00008000, 0x82F63B78,
)


def _step(state):
    """One reflected CRC-32C bit step (advance the raw state by one bit)."""
    return (state >> 1) ^ (POLY if state & 1 else 0)


def advance_raw(state, n_bits):
    """Advance the raw (pre/post-inversion-free) CRC state by n_bits."""
    for _ in range(n_bits):
        state = _step(state)
    return state & MASK32


def _apply_operator(op, value):
    """Apply a GF(2)-linear advance operator (32 basis images) to a state."""
    out = 0
    j = 0
    while value:
        if value & 1:
            out ^= op[j]
        value >>= 1
        j += 1
    return out & MASK32


_OP_POWERS = None


def _advance_operators():
    """Advance-by-2^k-bits operators for k = 0..63, built by squaring."""
    global _OP_POWERS
    if _OP_POWERS is not None:
        return _OP_POWERS
    op1 = tuple(_step(1 << j) for j in range(32))
    ops = [op1]
    for _ in range(63):
        prev = ops[-1]
        ops.append(tuple(_apply_operator(prev, prev[j]) for j in range(32)))
    _OP_POWERS = ops
    return ops


def advance_raw_fast(state, n_bits):
    """Advance the raw CRC state by n_bits, via operator squaring.

    Exactly equal to advance_raw (checked in the tests); only faster, so
    large advances (e.g. 32*2^31 bits) stay computable.
    """
    ops = _advance_operators()
    k = 0
    while n_bits:
        if n_bits & 1:
            state = _apply_operator(ops[k], state)
        n_bits >>= 1
        k += 1
    return state & MASK32


def base_table():
    """The standard CRC-32C base table T0, generated from the polynomial."""
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = _step(crc)
        table.append(crc)
    return table


def slice_tables():
    """T0..T3: T_k is T0 advanced by k zero bytes (verified vs .rodata)."""
    t0 = base_table()
    tables = [t0]
    for k in (1, 2, 3):
        tables.append([advance_raw(v, 8 * k) for v in t0])
    return tables  # [T0, T1, T2, T3]


_T0, _T1, _T2, _T3 = slice_tables()


def _slice4(word):
    """One slicing-by-4 round: tables over the four bytes of word."""
    return (
        _T3[word & 0xFF]
        ^ _T2[(word >> 8) & 0xFF]
        ^ _T1[(word >> 16) & 0xFF]
        ^ _T0[(word >> 24) & 0xFF]
    )


def extend(crc, data, data_addr=0x1000):
    """Transliteration of ExtendImpl<Slow_CRC32> at 0x61c21d0.

    ``data_addr`` is the address the buffer would sit at; only its
    alignment matters (the prologue runs byte-at-a-time up to the next
    16-byte boundary). The observable result is alignment-independent.
    """
    state = (~crc) & MASK32
    n = len(data)
    i = 0
    # Prologue: byte-at-a-time until the pointer is 16-byte aligned,
    # or the end is reached (0x61c21d0..0x61c221d).
    align_up = (data_addr + 15) & ~15
    if data_addr + n >= align_up and data_addr != align_up:
        while i < n and (data_addr + i) != align_up:
            state = _T0[(state ^ data[i]) & 0xFF] ^ (state >> 8)
            state &= MASK32
            i += 1
    # Main loop: 16 bytes per round (0x61c2250..0x61c22f9).
    while n - i > 15:
        w0, w1, w2, w3 = struct.unpack_from("<4I", data, i)
        x = _slice4(state ^ w0) ^ w1
        x = _slice4(x) ^ w2
        x = _slice4(x) ^ w3
        state = _slice4(x)
        i += 16
    # Middle loop: 8 bytes per round (0x61c2328..0x61c2385).
    while n - i > 7:
        w0, w1 = struct.unpack_from("<2I", data, i)
        x = _slice4(state ^ w0) ^ w1
        state = _slice4(x)
        i += 8
    # Tail: byte-at-a-time (0x61c2398..0x61c23b3).
    while i < n:
        state = _T0[(state ^ data[i]) & 0xFF] ^ (state >> 8)
        state &= MASK32
        i += 1
    return (~state) & MASK32


def extend_bitref(crc, data):
    """Independent reference: bit-by-bit CRC-32C with pre/post inversion."""
    state = (~crc) & MASK32
    for byte in data:
        state ^= byte
        for _ in range(8):
            state = _step(state)
    return (~state) & MASK32


def _combine_inner(state, table_value):
    """One 32-iteration matrix step of Crc32cCombine (0x61c2660..0x61c2687).

    Returns (new_state, advanced_state): new_state is state multiplied by
    x^(32*2^p) for the table entry, advanced_state is state advanced by
    32 bits. The two agree with advance_raw(state, 32*2^p) and
    advance_raw(state, 32) respectively (checked in the tests).
    """
    eax = state
    acc = 0
    value = table_value
    for _ in range(32):
        old = eax
        top = (value >> 31) & 1
        value = (value * 2) & MASK32
        eax = _step(old)
        if top:
            acc ^= old
    return acc & MASK32, eax


def combine_translit(crc1, crc2, len2):
    """Transliteration of Crc32cCombine at 0x61c2600."""
    acc = crc1
    if len2 & 3:
        # Slow path (0x61c26ae..0x61c26bf): ~Extend(~crc1, zeros, len2&3).
        acc = (~extend((~crc1) & MASK32, bytes(len2 & 3))) & MASK32
    remaining = len2 >> 2
    index = 0
    while remaining:
        tz = (remaining & -remaining).bit_length() - 1
        remaining >>= tz
        index += tz
        acc, _ = _combine_inner(acc, COMBINE_TABLE[index])
        index += 1
        remaining >>= 1
    return (crc2 ^ acc) & MASK32


def combine(crc1, crc2, len2):
    """Independent model: crc2 ^ advance_raw(crc1, 8*len2).

    Computed with advance_raw_fast, which is exactly advance_raw by
    operator squaring (checked against the one-bit-step advance in the
    tests); the naive loop is infeasible for large len2.
    """
    return (crc2 ^ advance_raw_fast(crc1, 8 * len2)) & MASK32


def census_targets():
    """Body SHA-256 targets for the two functions from the vendor census."""
    root = Path(__file__).resolve().parents[1]
    census = json.loads((root / CENSUS_PATH).read_text())
    out = {}
    for record in census["records"]:
        if record["start"] in (0x61C21D0, 0x61C2600):
            out[record["start"]] = record["target_body_sha256"]
    return out


def verify_binary(binary_path):
    """Check the two FDE bodies hash to the census targets."""
    binary = Path(binary_path).read_bytes()
    # .text file offset is VA - 0x1000 (second LOAD segment).
    results = {}
    for start, end in ((0x61C21D0, 0x61C23B9), (0x61C2600, 0x61C26C9)):
        body = binary[start - 0x1000 : end - 0x1000]
        results[start] = hashlib.sha256(body).hexdigest()
    return results
