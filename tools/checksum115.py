#!/usr/bin/env python3
"""Reconstruct the node #115 RocksDB ComputeBuiltinChecksum dispatcher.

Bounded question (RE-002): what does the function at 0x616bca0 compute
for each ChecksumType, and which bytes in the node #115 binary pin that
behaviour?

Observed answer, from the disassembly of work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* The function is the vendor-census entry
  ``_ZN7rocksdb22ComputeBuiltinChecksumENS_12ChecksumTypeEPKcm``
  (librocksdb-sys). The census pins its body exactly to the FDE
  0x616bca0..0x616bd51, and the body SHA-256 below matches the census
  target_body_sha256. Observed register contract: ``type`` in dil,
  ``data`` in rsi, ``n`` in rdx, result u32 in eax. It is the immediate
  predecessor of ComputeBuiltinChecksumWithLastByte at 0x616bd60, whose
  four hash arms were reconstructed in PRs #5396/#5399/#5402/#5409; this
  function dispatches the same four hashes without an appended byte.
* Dispatch on ``type`` (compares at 0x616bcb0, 0x616bcb8, 0x616bcbe,
  0x616bce0): 1 -> the CRC32C arm at 0x616bd18; 2 -> a tail call to
  ROCKSDB_XXH32 at 0x61da8b0; 3 -> a call to ROCKSDB_XXH64 at 0x61dae20
  (low 32 bits kept); 4 -> a multiply-xor arm at 0x616bce0 calling
  ROCKSDB_XXH3_64bits at 0x61db650; anything else (including 0,
  kNoChecksum) -> 0.
* CRC32C arm (0x616bd18..0x616bd30): ``xor %edi,%edi`` (seed 0), then one
  call to the registered extend through the PLT stub at 0x61c25f0 (which
  jumps through the writable slot at 0x6508908; the initializer at
  0x61c26d0 stores 0x61c21d0, rocksdb::crc32c::ExtendImpl<Slow_CRC32>,
  there -- established in PR #5387), i.e. ``extend(0, data, n)``. It
  then applies the Mask inline: ``ror $0xf, %eax`` then
  ``sub $0x5d7d1528, %eax`` at 0x616bd28 -- and 0x5d7d1528 is the
  two's complement of 0xa282ead8, so this is
  ``ror32(crc, 15) + 0xa282ead8 (mod 2**32)``, the same Mask as the
  WithLastByte arm (whose lea immediate 0xa282ead8 occurs exactly once
  in .text, at 0x616bea1).
* xxhash arm (0x616bcc8..0x616bce0): ``mov %rbx,%rsi; mov %rbp,%rdi;
  xor %edx,%edx; jmp 0x61da8b0`` -- ROCKSDB_XXH32(data, n, seed 0), whose
  32-bit digest is the result directly.
* xxhash64 arm (0x616bd30..0x616bd48): ``call 0x61dae20`` --
  ROCKSDB_XXH64(data, n, seed 0); the caller keeps the low 32 bits.
* multiply-xor arm (0x616bce0..0x616bd18): if ``n == 0`` return 0; else
  ``XXH3_64bits(data, n-1)`` (``lea -0x1(%rdx),%rsi``), then
  ``(u32) helper ^ (data[n-1] * 0x6b9083d9)`` -- the last input byte
  plays the role the appended byte plays in the WithLastByte arm.
  The helper is modelled only for inputs of length 0..16 (the short
  branches reconstructed in PR #5409), so this arm is modelled only
  for ``n <= 17``.

The Python model below implements each arm twice independently
(bit-by-bit vs table-driven extend; one-shot vs streaming XXH32/XXH64;
transliterated vs byte-buffer XXH3 short) and cross-checks them on
2400 deterministic cases. The node binary is never executed.
"""
import argparse
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-checksum-115'
POLY = 0x82F63B78
MASK_CONST = 0xA282EAD8
MASK_SUB_IMMEDIATE = 0x5D7D1528
MASK_SUB_SITE = 0x616BD29
MULMIX_IMUL = 0x6B9083D9
FUNCTION_START = 0x616BCA0
FUNCTION_END = 0x616BD51
CRC32C_ARM_START = 0x616BD18
CRC32C_ARM_END = 0x616BD30
XXHASH_ARM_START = 0x616BCC8
XXHASH_ARM_END = 0x616BCE0
MULMIX_ARM_START = 0x616BCE0
MULMIX_ARM_END = 0x616BD18
XXHASH64_ARM_START = 0x616BD30
XXHASH64_ARM_END = 0x616BD48
DEFAULT_ARM_START = 0x616BD48
DEFAULT_ARM_END = 0x616BD51
EXTEND_STUB = 0x61C25F0
EXTEND_STUB_END = 0x61C25FA
FNPTR_SLOT = 0x6508908
XXH32_START = 0x61DA8B0
XXH32_END = 0x61DAA52
XXH64_START = 0x61DAE20
XXH64_END = 0x61DB121
XXH3_START = 0x61DB650
XXH3_END = 0x61DB93A
CASE_COUNT = 2400
CASE_SEED = 20261109
MAX_MULMIX_LEN = 17

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
P1_32 = 0x9E3779B1
P2_32 = 0x85EBCA77
P3_32 = 0xC2B2AE3D
P4_32 = 0x27D4EB2F
P5_32 = 0x165667B1
P1_64 = 0x9E3779B185EBCA87
P2_64 = 0xC2B2AE3D27D4EB4F
P3_64 = 0x165667B19E3779F9
P4_64 = 0x85EBCA77C2B2AE63
P5_64 = 0x27D4EB2F165667C5
AVALANCHE_MUL = 0x165667919E3779F9
RRMXMX_MUL = 0x9FB21C651E98DF25
EMPTY_HASH = 0x2D06800538D394C2
# Default XXH3 secret, first 9 words, as read from .rodata at 0x97ec80
# (verified word-by-word in PR #5409).
SECRET_WORDS = (
    0xBE4BA423396CFEB8, 0x1CAD21F72C81017C, 0xDB979083E96DD4DE,
    0x1F67B3B7A4A44072, 0x78E5C0CC4EE679CB, 0x2172FFCC7DD05A82,
    0x8E2443F7744608B8, 0x4C263A81E69035E0, 0xCB00C391BB52283C,
)
# Secret-derived immediates in the XXH3 short branches (PR #5409).
C1_9TO16 = 0x6782737BEA4239B9
C2_9TO16 = 0xAF56BC3B0996523A
BITFLIP_4TO8 = 0xC73AB174C5ECD5A2
BITFLIP_1TO3 = 0x87275A9B

# Census body hash for the dispatcher (research/byte-windows.json).
CENSUS_BODY = {
    'function': 'be940db36c40290321b93a1c386040a55c14fd0beab8a1c5de9688c1ad3674f2',
}
# Pinned body hashes for the callees, computed from the pinned binary
# (FDE extents above); they match the census target_body_sha256 values.
XXH32_BODY = 'b2d5ccf56d670650affce9c0efa1fe0ce5eaaf92543d3b3658fd03350f9675b8'
XXH64_BODY = '577ad945e65ddde3fc0ca78ae8d6316c7cb08203bbca5d08a07babca5d08bec8'
XXH3_BODY = 'adde9328dc4c355cf1410323721f18dea26b8d5508920d127f8cdfdabe5aa3bb'

# (label, start, end) of the byte-checked instruction windows. The six
# arm windows tile 0x616bca0..0x616bd51 exactly; the three callee windows
# pin the one-shot hash bodies the arms call.
WINDOWS = (
    ('entry_dispatch', FUNCTION_START, 0x616BCC8),
    ('xxhash_arm', XXHASH_ARM_START, XXHASH_ARM_END),
    ('mulmix_arm', MULMIX_ARM_START, MULMIX_ARM_END),
    ('crc32c_arm', CRC32C_ARM_START, CRC32C_ARM_END),
    ('xxhash64_arm', XXHASH64_ARM_START, XXHASH64_ARM_END),
    ('default_arm', DEFAULT_ARM_START, DEFAULT_ARM_END),
    ('xxh32_oneshot', XXH32_START, XXH32_END),
    ('xxh64_oneshot', XXH64_START, XXH64_END),
    ('xxh3_64bits', XXH3_START, XXH3_END),
)

# The dispatch table as observed in the disassembly. All four hash arms
# are modelled here (type 4 only for n <= 17, per the XXH3 short range).
DISPATCH = (
    (0, 'default_arm', 'returns 0 (kNoChecksum and any other type)'),
    (1, 'crc32c_arm', 'mask(extend(0, data, n))'),
    (2, 'xxhash_arm', 'XXH32(data, n, seed 0)'),
    (3, 'xxhash64_arm', '(u32) XXH64(data, n, seed 0)'),
    (4, 'mulmix_arm', '(u32) XXH3_64bits(data, n-1) ^ '
                      '(data[n-1] * 0x6b9083d9); n == 0 returns 0; '
                      'modelled for n <= 17'),
)

BOUNDARY_LENGTHS = (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33,
                    63, 64, 65, 127, 128, 256, 1024)
BOUNDARY_LENGTHS_MULMIX = tuple(range(MAX_MULMIX_LEN + 1))


def authenticate(data):
    """Reject anything that is not the pinned node #115 binary."""
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('target digest mismatch: not node #115')
    return True


def unique_sections(data):
    secs = sections(data)
    seen = {}
    for sec in secs:
        if sec['name'] in seen:
            raise ValueError('Duplicate section: ' + sec['name'])
        seen[sec['name']] = sec
    return seen


def file_offset(secs, va, size):
    for sec in secs.values():
        start, end = sec['address'], sec['address'] + sec['size']
        if start <= va and va + size <= end:
            if sec['type'] == 8:  # SHT_NOBITS has no bytes to read.
                raise ValueError(f'NOBITS section at {va:#x}')
            return sec['offset'] + (va - start)
    raise ValueError(f'address {va:#x} outside mapped sections')


def _u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def _u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]


def rol32(value, count):
    return ((value << count) | (value >> (32 - count))) & MASK32


def rol64(value, count):
    return ((value << count) | (value >> (64 - count))) & MASK64


def ror32(value, count):
    return ((value >> count) | (value << (32 - count))) & MASK32


def ror64(value, count):
    return ((value >> count) | (value << (64 - count))) & MASK64


def bswap64(value):
    return int.from_bytes(value.to_bytes(8, 'little'), 'big')


# --- CRC32C (type 1) ---

def step(state):
    """One reflected CRC32C bit step."""
    return (state >> 1) ^ POLY if state & 1 else state >> 1


def extend_bitwise(crc, data):
    """Stored-form CRC32C extend, bit by bit (complement-in/out)."""
    crc ^= 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = step(crc)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def build_table():
    """The 256-entry CRC32C table, generated from the polynomial."""
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = step(c)
        table.append(c)
    return table


def extend_table(crc, data, table):
    """Stored-form CRC32C extend, table-driven (independent algorithm)."""
    crc ^= 0xFFFFFFFF
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def mask(crc):
    """rocksdb::crc32c::Mask: ror32(crc, 15) + 0xa282ead8 (mod 2**32)."""
    return (ror32(crc, 15) + MASK_CONST) & MASK32


def mask_via_sub(crc):
    """The same Mask as the binary expresses it: ror32(crc, 15) - 0x5d7d1528."""
    return (ror32(crc, 15) - MASK_SUB_IMMEDIATE) & MASK32


# --- XXH32 (type 2) ---

def xxh32_round(acc, lane):
    acc = (acc + lane * P2_32) & MASK32
    acc = rol32(acc, 13)
    return (acc * P1_32) & MASK32


def _avalanche32(h):
    h ^= h >> 15
    h = (h * P2_32) & MASK32
    h ^= h >> 13
    h = (h * P3_32) & MASK32
    h ^= h >> 16
    return h


def _tail32(h, tail):
    """Remainder handling (spec Step 5)."""
    i = 0
    while i + 4 <= len(tail):
        h = (h + _u32(tail, i) * P3_32) & MASK32
        h = rol32(h, 17)
        h = (h * P4_32) & MASK32
        i += 4
    while i < len(tail):
        h = (h + tail[i] * P5_32) & MASK32
        h = rol32(h, 11)
        h = (h * P1_32) & MASK32
        i += 1
    return h


def xxh32_oneshot(data, seed=0):
    """Standard XXH32, one-shot reference (upstream spec v0.2.0).

    Convergence is the rotate-sum only; the mergeAccumulator rounds
    belong to XXH64.
    """
    n = len(data)
    i = 0
    if n >= 16:
        v1 = (seed + P1_32 + P2_32) & MASK32
        v2 = (seed + P2_32) & MASK32
        v3 = seed & MASK32
        v4 = (seed - P1_32) & MASK32
        while i + 16 <= n:
            v1 = xxh32_round(v1, _u32(data, i))
            v2 = xxh32_round(v2, _u32(data, i + 4))
            v3 = xxh32_round(v3, _u32(data, i + 8))
            v4 = xxh32_round(v4, _u32(data, i + 12))
            i += 16
        h = (rol32(v1, 1) + rol32(v2, 7) + rol32(v3, 12)
             + rol32(v4, 18)) & MASK32
    else:
        h = (seed + P5_32) & MASK32
    h = (h + n) & MASK32
    h = _tail32(h, data[i:])
    return _avalanche32(h)


class XXH32State:
    """XXH32 streaming state, mirroring the binary's create/reset/update.

    Layout observed in the binary (PR #5402): total_len +0x0 (u64, high
    dword carries the sticky large_len flag), v1 +0x8, v2 +0xc, v3 +0x10,
    v4 +0x14, mem +0x18 (16 bytes), memsize +0x28, 0x30 bytes total.
    """

    def __init__(self, seed=0):
        self.reset(seed)

    def reset(self, seed):
        self.seed = seed
        self.total_len = 0
        self.large_len = False
        self.v1 = (seed + P1_32 + P2_32) & MASK32
        self.v2 = (seed + P2_32) & MASK32
        self.v3 = seed & MASK32
        self.v4 = (seed - P1_32) & MASK32
        self.memsize = 0
        self.mem = bytearray(16)

    def _process_stripe(self, block):
        self.v1 = xxh32_round(self.v1, _u32(block, 0))
        self.v2 = xxh32_round(self.v2, _u32(block, 4))
        self.v3 = xxh32_round(self.v3, _u32(block, 8))
        self.v4 = xxh32_round(self.v4, _u32(block, 12))

    def update(self, data):
        if not data:
            return
        self.total_len += len(data)
        if len(data) > 15 or self.total_len > 15:
            self.large_len = True
        pos = 0
        if self.memsize + len(data) < 16:
            self.mem[self.memsize:self.memsize + len(data)] = data
            self.memsize += len(data)
            return
        if self.memsize:
            need = 16 - self.memsize
            self.mem[self.memsize:16] = data[:need]
            self._process_stripe(bytes(self.mem))
            pos = need
            self.memsize = 0
        while pos + 16 <= len(data):
            self._process_stripe(data[pos:pos + 16])
            pos += 16
        if pos < len(data):
            self.mem[0:len(data) - pos] = data[pos:]
            self.memsize = len(data) - pos

    def digest(self):
        # Standard XXH32 convergence: the rotate-sum only, then the
        # remainder -- the mergeAccumulator rounds belong to XXH64.
        if self.large_len:
            h = (rol32(self.v1, 1) + rol32(self.v2, 7)
                 + rol32(self.v3, 12) + rol32(self.v4, 18)) & MASK32
        else:
            h = (self.seed + P5_32) & MASK32
        h = (h + (self.total_len & MASK32)) & MASK32
        h = _tail32(h, bytes(self.mem[:self.memsize]))
        return _avalanche32(h)


# --- XXH64 (type 3) ---

def xxh64_round(acc, lane):
    acc = (acc + lane * P2_64) & MASK64
    acc = rol64(acc, 31)
    return (acc * P1_64) & MASK64


def xxh64_merge(acc, val):
    val = xxh64_round(0, val)
    acc ^= val
    return (acc * P1_64 + P4_64) & MASK64


def xxh64_oneshot(data, seed=0):
    """XXH64, one-shot reference implementation of the public algorithm."""
    n = len(data)
    i = 0
    if n >= 32:
        v1 = (seed + P1_64 + P2_64) & MASK64
        v2 = (seed + P2_64) & MASK64
        v3 = seed & MASK64
        v4 = (seed - P1_64) & MASK64
        while i + 32 <= n:
            v1 = xxh64_round(v1, _u64(data, i))
            v2 = xxh64_round(v2, _u64(data, i + 8))
            v3 = xxh64_round(v3, _u64(data, i + 16))
            v4 = xxh64_round(v4, _u64(data, i + 24))
            i += 32
        h = (rol64(v1, 1) + rol64(v2, 7) + rol64(v3, 12)
             + rol64(v4, 18)) & MASK64
        h = xxh64_merge(h, v1)
        h = xxh64_merge(h, v2)
        h = xxh64_merge(h, v3)
        h = xxh64_merge(h, v4)
    else:
        h = (seed + P5_64) & MASK64
    h = (h + n) & MASK64
    while i + 8 <= n:
        k = xxh64_round(0, _u64(data, i))
        h ^= k
        h = (rol64(h, 27) * P1_64 + P4_64) & MASK64
        i += 8
    if i + 4 <= n:
        h ^= (_u32(data, i) * P1_64) & MASK64
        h = (rol64(h, 23) * P2_64 + P3_64) & MASK64
        i += 4
    while i < n:
        h ^= (data[i] * P5_64) & MASK64
        h = (rol64(h, 11) * P1_64) & MASK64
        i += 1
    h ^= h >> 33
    h = (h * P2_64) & MASK64
    h ^= h >> 29
    h = (h * P3_64) & MASK64
    h ^= h >> 32
    return h


class XXH64State:
    """XXH64 streaming state, mirroring the binary's create/reset/update.

    Layout observed in the binary (PR #5399): total_len +0x0, v1 +0x8,
    v2 +0x10, v3 +0x18, v4 +0x20, memsize +0x28, 0x58 bytes total.
    """

    def __init__(self, seed=0):
        self.reset(seed)

    def reset(self, seed):
        self.seed = seed
        self.total_len = 0
        self.v1 = (seed + P1_64 + P2_64) & MASK64
        self.v2 = (seed + P2_64) & MASK64
        self.v3 = seed & MASK64
        self.v4 = (seed - P1_64) & MASK64
        self.memsize = 0
        self.mem = bytearray(32)

    def _process_stripe(self, block):
        self.v1 = xxh64_round(self.v1, _u64(block, 0))
        self.v2 = xxh64_round(self.v2, _u64(block, 8))
        self.v3 = xxh64_round(self.v3, _u64(block, 16))
        self.v4 = xxh64_round(self.v4, _u64(block, 24))

    def update(self, data):
        if not data:
            return
        self.total_len += len(data)
        pos = 0
        if self.memsize + len(data) < 32:
            self.mem[self.memsize:self.memsize + len(data)] = data
            self.memsize += len(data)
            return
        if self.memsize:
            need = 32 - self.memsize
            self.mem[self.memsize:32] = data[:need]
            self._process_stripe(bytes(self.mem))
            pos = need
            self.memsize = 0
        while pos + 32 <= len(data):
            self._process_stripe(data[pos:pos + 32])
            pos += 32
        if pos < len(data):
            self.mem[0:len(data) - pos] = data[pos:]
            self.memsize = len(data) - pos

    def digest(self):
        if self.total_len >= 32:
            h = (rol64(self.v1, 1) + rol64(self.v2, 7)
                 + rol64(self.v3, 12) + rol64(self.v4, 18)) & MASK64
            h = xxh64_merge(h, self.v1)
            h = xxh64_merge(h, self.v2)
            h = xxh64_merge(h, self.v3)
            h = xxh64_merge(h, self.v4)
        else:
            h = (self.seed + P5_64) & MASK64
        h = (h + self.total_len) & MASK64
        tail = bytes(self.mem[:self.memsize])
        i = 0
        while i + 8 <= len(tail):
            k = xxh64_round(0, _u64(tail, i))
            h ^= k
            h = (rol64(h, 27) * P1_64 + P4_64) & MASK64
            i += 8
        if i + 4 <= len(tail):
            h ^= (_u32(tail, i) * P1_64) & MASK64
            h = (rol64(h, 23) * P2_64 + P3_64) & MASK64
            i += 4
        while i < len(tail):
            h ^= (tail[i] * P5_64) & MASK64
            h = (rol64(h, 11) * P1_64) & MASK64
            i += 1
        h ^= h >> 33
        h = (h * P2_64) & MASK64
        h ^= h >> 29
        h = (h * P3_64) & MASK64
        h ^= h >> 32
        return h


# --- XXH3 short branches (type 4 helper, len 0..16) ---

def _avalanche64(h):
    """XXH64 avalanche as observed (the h ^= h>>33 step is elided:
    keyed is 32-bit, so h>>33 is 0 at that point)."""
    h = (h * P2_64) & MASK64
    h ^= h >> 29
    h = (h * P3_64) & MASK64
    h ^= h >> 32
    return h


def _rrmxmx(h, length):
    """XXH3_rrmxmx as observed in the 4-to-8 branch."""
    h ^= rol64(h, 49) ^ rol64(h, 24)
    h = (h * RRMXMX_MUL) & MASK64
    h ^= (h >> 35) + length
    h = (h * RRMXMX_MUL) & MASK64
    h ^= h >> 28
    return h


def _xxh3_avalanche(h):
    """XXH3 avalanche as observed at the end of the 9-to-16 branch."""
    h ^= h >> 37
    h = (h * AVALANCHE_MUL) & MASK64
    h ^= h >> 32
    return h


def xxh3_64_short(data):
    """Direct transliteration of the helper's len 0..16 branches."""
    n = len(data)
    if n > 16:
        raise ValueError(f'not modelled: length {n} > 16')
    if n == 0:
        return EMPTY_HASH
    if n <= 3:
        c1 = data[0]
        c2 = data[n - 1]
        c3 = data[n >> 1]
        combined = (c2 | (c1 << 16) | (n << 8) | (c3 << 24)) & MASK32
        keyed = (combined ^ BITFLIP_1TO3) & MASK32
        return _avalanche64(keyed)
    if n <= 8:
        lo32 = _u32(data, 0)
        hi32 = _u32(data, n - 4)
        input64 = ((lo32 << 32) | hi32) & MASK64
        keyed = input64 ^ BITFLIP_4TO8
        return _rrmxmx(keyed, n)
    a = _u64(data, 0) ^ C1_9TO16
    b = _u64(data, n - 8) ^ C2_9TO16
    prod = a * b
    lo, hi = prod & MASK64, prod >> 64
    t = ((hi ^ lo) + (b + n) + bswap64(a)) & MASK64
    return _xxh3_avalanche(t)


def _mul128_limbs(a, b):
    """128-bit product via 32-bit limbs (independent of Python big ints)."""
    a0, a1 = a & MASK32, a >> 32
    b0, b1 = b & MASK32, b >> 32
    p0 = a0 * b0
    p1 = a0 * b1
    p2 = a1 * b0
    p3 = a1 * b1
    mid = (p0 >> 32) + (p1 & MASK32) + (p2 & MASK32)
    lo = ((p0 & MASK32) | ((mid & MASK32) << 32)) & MASK64
    hi = (p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32)) & MASK64
    return lo, hi


def _bswap64_ref(value):
    out = 0
    for shift in (0, 8, 16, 24, 32, 40, 48, 56):
        out = (out << 8) | ((value >> shift) & 0xFF)
    return out


def xxh3_64_short_reference(data):
    """Independent formulation of the same disassembly reading.

    Packing via byte buffers / struct round-trips, the 128-bit product
    via 32-bit limbs, and re-typed literals -- so a transcription slip
    in either implementation shows up as a mismatch.
    """
    n = len(data)
    if n > 16:
        raise ValueError(f'not modelled: length {n} > 16')
    if n == 0:
        return 0x2D06800538D394C2
    if n <= 3:
        c1 = data[0]
        c2 = data[n - 1]
        c3 = data[n >> 1]
        combined = int.from_bytes(bytes([c2, n, c1, c3]), 'little')
        keyed = (combined ^ 0x87275A9B) % (1 << 32)
        h = (keyed * 0xC2B2AE3D27D4EB4F) % (1 << 64)
        h ^= h >> 29
        h = (h * 0x165667B19E3779F9) % (1 << 64)
        h ^= h >> 32
        return h
    if n <= 8:
        first = struct.unpack_from('<I', data, 0)[0]
        last = struct.unpack_from('<I', data, n - 4)[0]
        input64 = struct.unpack('<Q', struct.pack('<II', last, first))[0]
        keyed = input64 ^ 0xC73AB174C5ECD5A2
        h = keyed
        h0 = h
        h = (h0 ^ (((h0 << 49) | (h0 >> 15)) % (1 << 64))
             ^ (((h0 << 24) | (h0 >> 40)) % (1 << 64))) % (1 << 64)
        h = (h * 0x9FB21C651E98DF25) % (1 << 64)
        h ^= (h >> 35) + n
        h = (h * 0x9FB21C651E98DF25) % (1 << 64)
        h ^= h >> 28
        return h % (1 << 64)
    a = struct.unpack_from('<Q', data, 0)[0] ^ 0x6782737BEA4239B9
    b = struct.unpack_from('<Q', data, n - 8)[0] ^ 0xAF56BC3B0996523A
    lo, hi = _mul128_limbs(a, b)
    t = (_bswap64_ref(a) + (b + n) + (hi ^ lo)) % (1 << 64)
    x = t ^ (t >> 37)
    x = (x * 0x165667919E3779F9) % (1 << 64)
    return x ^ (x >> 32)


# --- Dispatcher model ---

def compute_checksum(type_, data):
    """The dispatcher at 0x616bca0, via the per-arm models."""
    if type_ == 1:
        return mask(extend_bitwise(0, data))
    if type_ == 2:
        return xxh32_oneshot(data, 0)
    if type_ == 3:
        return xxh64_oneshot(data, 0) & MASK32
    if type_ == 4:
        if len(data) == 0:
            return 0
        helper = xxh3_64_short(data[:-1])
        return ((helper & MASK32)
                ^ ((data[-1] * MULMIX_IMUL) & MASK32)) & MASK32
    return 0


def compute_checksum_reference(type_, data, table):
    """Same dispatcher, via the independent per-arm references."""
    if type_ == 1:
        return mask(extend_table(0, data, table))
    if type_ == 2:
        state = XXH32State(0)
        state.update(data)
        return state.digest()
    if type_ == 3:
        state = XXH64State(0)
        state.update(data)
        return state.digest() & MASK32
    if type_ == 4:
        if len(data) == 0:
            return 0
        helper = xxh3_64_short_reference(data[:-1])
        return ((helper % (1 << 32))
                ^ ((data[-1] * 0x6B9083D9) % (1 << 32))) % (1 << 32)
    return 0


def mask_sub_sites(data, secs):
    """Virtual addresses in .text holding 0x5d7d1528 as an immediate."""
    text = secs['.text']
    off = text['offset']
    blob = data[off:off + text['size']]
    needle = struct.pack('<I', MASK_SUB_IMMEDIATE)
    sites = []
    pos = 0
    while True:
        idx = blob.find(needle, pos)
        if idx < 0:
            break
        sites.append(text['address'] + idx)
        pos = idx + 1
    return sites


def window_hashes(data, secs):
    out = {}
    for label, start, end in WINDOWS:
        off = file_offset(secs, start, end - start)
        out[label] = hashlib.sha256(data[off:off + (end - start)]).hexdigest()
    return out


def body_hash(data, secs, start, end):
    off = file_offset(secs, start, end - start)
    return hashlib.sha256(data[off:off + (end - start)]).hexdigest()


def stub_hash(data, secs):
    return body_hash(data, secs, EXTEND_STUB, EXTEND_STUB_END)


def fde_extent(data, start):
    """Return the .eh_frame extent starting at start, or None."""
    _, fdes = eh_frame_records(data)
    for rec in fdes:
        if rec['start'] == start:
            return rec['start'], rec['end']
    return None


def verify(data):
    """Authenticate the binary and check every pinned byte of the packet."""
    authenticate(data)
    secs = unique_sections(data)
    if secs['.text']['address'] != 0x1419300 or secs['.rodata']['address'] != 0x430400:
        raise ValueError('unexpected section layout')
    extent = fde_extent(data, FUNCTION_START)
    if extent != (FUNCTION_START, FUNCTION_END):
        raise ValueError(f'FDE extent mismatch: {extent}')
    for start, end in ((XXH32_START, XXH32_END), (XXH64_START, XXH64_END),
                       (XXH3_START, XXH3_END)):
        ext = fde_extent(data, start)
        if ext != (start, end):
            raise ValueError(f'callee FDE extent mismatch: {ext}')
    sites = mask_sub_sites(data, secs)
    if MASK_SUB_SITE not in sites:
        raise ValueError('Mask sub-immediate site missing from .text')
    table = build_table()
    if extend_bitwise(0, b'123456789') != 0xE3069283:
        raise ValueError('bitwise extend check value mismatch')
    if extend_table(0, b'123456789', table) != 0xE3069283:
        raise ValueError('table extend check value mismatch')
    if xxh32_oneshot(b'', 0) != 0x02CC5D05:
        raise ValueError('XXH32 empty check value mismatch')
    if xxh32_oneshot(b'a', 0) != 0x550D7456:
        raise ValueError('XXH32 single-byte check value mismatch')
    if xxh64_oneshot(b'', 0) & MASK32 != 0x51D8E999:
        raise ValueError('XXH64 empty check value mismatch')
    if xxh64_oneshot(b'a', 0) & MASK32 != 0xA98C6E5B:
        raise ValueError('XXH64 single-byte check value mismatch')
    if xxh3_64_short(b'') != EMPTY_HASH:
        raise ValueError('XXH3 empty check value mismatch')
    if xxh3_64_short(b'a') != 0xE6C632B61E964E1F:
        raise ValueError('XXH3 single-byte check value mismatch')
    checked = {
        'table': table,
        'window_hashes': window_hashes(data, secs),
        'body_hash': body_hash(data, secs, FUNCTION_START, FUNCTION_END),
        'stub_hash': stub_hash(data, secs),
        'mask_sites': sites,
        'sections': secs,
        'callee_hashes': {
            'xxh32': body_hash(data, secs, XXH32_START, XXH32_END),
            'xxh64': body_hash(data, secs, XXH64_START, XXH64_END),
            'xxh3': body_hash(data, secs, XXH3_START, XXH3_END),
        },
    }
    if checked['body_hash'] != CENSUS_BODY['function']:
        raise ValueError('body hash does not match the census')
    if checked['callee_hashes']['xxh32'] != XXH32_BODY:
        raise ValueError('XXH32 callee body hash mismatch')
    if checked['callee_hashes']['xxh64'] != XXH64_BODY:
        raise ValueError('XXH64 callee body hash mismatch')
    if checked['callee_hashes']['xxh3'] != XXH3_BODY:
        raise ValueError('XXH3 callee body hash mismatch')
    return checked


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic (type, data) cases: boundary lengths, then random.

    Type 4 cases are capped at length 17 so the XXH3 helper input
    (data[:-1]) stays within its modelled 0..16 range. Data lengths are
    capped at 1024 bytes so every sampled case fits in cases.tsv in full.
    """
    rng = random.Random(seed)
    cases = []
    for length in BOUNDARY_LENGTHS:
        data = bytes(rng.randrange(256) for _ in range(length))
        cases.append((1, data))
        cases.append((2, data))
        cases.append((3, data))
    for length in BOUNDARY_LENGTHS_MULMIX:
        data = bytes(rng.randrange(256) for _ in range(length))
        cases.append((4, data))
    for type_, length in ((0, 0), (0, 16), (5, 3), (6, 0), (7, 64)):
        data = bytes(rng.randrange(256) for _ in range(length))
        cases.append((type_, data))
    while len(cases) < count:
        type_ = rng.choice((0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 6, 7))
        if type_ == 4:
            length = rng.randrange(0, MAX_MULMIX_LEN + 1)
        elif type_ in (1, 2, 3):
            length = rng.randrange(0, 129)
        else:
            length = rng.randrange(0, 65)
        data = bytes(rng.randrange(256) for _ in range(length))
        cases.append((type_, data))
    return cases[:count]


def run_cases(cases, table):
    """Run the model against the independent references; return rows."""
    rows = []
    for type_, data in cases:
        out = compute_checksum(type_, data)
        ref = compute_checksum_reference(type_, data, table)
        if out != ref:
            raise ValueError(
                f'model disagrees with the reference for type {type_}, '
                f'len {len(data)}')
        rows.append((type_, data, out))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for type_, data, out in rows:
        hasher.update(struct.pack('<B', type_))
        hasher.update(struct.pack('<Q', len(data)))
        hasher.update(data)
        hasher.update(struct.pack('<I', out))
    return hasher.hexdigest()


def generate(data, dest):
    """Write the evidence packet files into dest (deterministic)."""
    checked = verify(data)
    table = checked['table']
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    cases = generate_cases()
    rows = run_cases(cases, table)
    aggregate = case_aggregate(rows)

    with (dest / 'windows.tsv').open('w', encoding='utf-8') as handle:
        handle.write('label\tstart\tend\tbytes\tsha256\n')
        for label, start, end in WINDOWS:
            handle.write(f"{label}\t{start:#x}\t{end:#x}\t{end - start}"
                         f"\t{checked['window_hashes'][label]}\n")

    # cases.tsv keeps the first 64 rows (all boundary cases for types
    # 1-3 plus the first type-4 boundaries); the full 2400-case run is
    # summarised in result.json by its aggregate digest.
    sample = rows[:64]
    with (dest / 'cases.tsv').open('w', encoding='utf-8') as handle:
        handle.write('idx\ttype\tdata_len\tdata_hex\tout\n')
        for idx, (type_, data_bytes, out) in enumerate(sample):
            handle.write(f"{idx}\t{type_}\t{len(data_bytes)}\t"
                         f"{data_bytes.hex()}\t{out:#010x}\n")

    long_data = bytes(0xAB for _ in range(1024))
    check_values = {
        'crc32c_check_value_123456789': {
            'type': 1, 'data_hex': b'123456789'.hex(),
            'out': f"{compute_checksum(1, b'123456789'):#010x}",
            'stored_crc_of_data': '0xe3069283'},
        'crc32c_empty': {
            'type': 1, 'data_hex': '',
            'out': f"{compute_checksum(1, b''):#010x}",
            'stored_crc_of_data': '0x00000000'},
        'xxhash_empty': {
            'type': 2, 'data_hex': '',
            'out': f"{compute_checksum(2, b''):#010x}",
            'note': 'published XXH32 empty vector 0x02cc5d05'},
        'xxhash_single_a': {
            'type': 2, 'data_hex': b'a'.hex(),
            'out': f"{compute_checksum(2, b'a'):#010x}",
            'note': 'published XXH32 vector 0x550d7456'},
        'xxhash64_empty_low32': {
            'type': 3, 'data_hex': '',
            'out': f"{compute_checksum(3, b''):#010x}",
            'note': 'low 32 bits of published XXH64 empty 0xef46db3751d8e999'},
        'xxhash64_single_a_low32': {
            'type': 3, 'data_hex': b'a'.hex(),
            'out': f"{compute_checksum(3, b'a'):#010x}",
            'note': 'low 32 bits of published XXH64 0xd24ec4f1a98c6e5b'},
        'mulmix_empty': {
            'type': 4, 'data_hex': '',
            'out': f"{compute_checksum(4, b''):#010x}",
            'note': 'n == 0 returns 0 before the helper call'},
        'mulmix_single_a': {
            'type': 4, 'data_hex': b'a'.hex(),
            'out': f"{compute_checksum(4, b'a'):#010x}",
            'note': '(u32) XXH3_64bits(b"") ^ (0x61 * 0x6b9083d9)'},
        'mulmix_abc': {
            'type': 4, 'data_hex': b'abc'.hex(),
            'out': f"{compute_checksum(4, b'abc'):#010x}",
            'note': '(u32) XXH3_64bits(b"ab") ^ (0x63 * 0x6b9083d9)'},
        'default_type_0': {
            'type': 0, 'data_hex': b'abc'.hex(),
            'out': f"{compute_checksum(0, b'abc'):#010x}"},
        'default_type_5': {
            'type': 5, 'data_hex': b'abc'.hex(),
            'out': f"{compute_checksum(5, b'abc'):#010x}"},
        'long_input_1024_ab_crc32c': {
            'type': 1, 'data': '1024 bytes of 0xab',
            'out': f"{compute_checksum(1, long_data):#010x}"},
        'long_input_1024_ab_xxhash': {
            'type': 2, 'data': '1024 bytes of 0xab',
            'out': f"{compute_checksum(2, long_data):#010x}"},
        'long_input_1024_ab_xxhash64': {
            'type': 3, 'data': '1024 bytes of 0xab',
            'out': f"{compute_checksum(3, long_data):#010x}"},
    }
    result = {
        'target_digest': DIGEST,
        'function': {'start': f'{FUNCTION_START:#x}', 'end': f'{FUNCTION_END:#x}',
                     'body_sha256': checked['body_hash'],
                     'fde': [f'{FUNCTION_START:#x}', f'{FUNCTION_END:#x}'],
                     'census_symbol': 'rocksdb::ComputeBuiltinChecksum',
                     'census_body_sha256': checked['body_hash']},
        'dispatch': [{'type': t, 'arm': arm, 'note': note}
                     for t, arm, note in DISPATCH],
        'crc32c_arm': {'start': f'{CRC32C_ARM_START:#x}',
                       'end': f'{CRC32C_ARM_END:#x}',
                       'extend_stub': [f'{EXTEND_STUB:#x}', f'{EXTEND_STUB_END:#x}'],
                       'extend_stub_sha256': checked['stub_hash'],
                       'fnptr_slot': f'{FNPTR_SLOT:#x}',
                       'extend_target': '0x61c21d0 '
                                        '(rocksdb::crc32c::ExtendImpl<Slow_CRC32>)',
                       'mask': {'sub_immediate_address': f'{MASK_SUB_SITE:#x}',
                                'sub_immediate': f'{MASK_SUB_IMMEDIATE:#010x}',
                                'constant': f'{MASK_CONST:#010x}',
                                'sub_immediate_sites_in_text':
                                    [f'{s:#x}' for s in checked['mask_sites']],
                                'formula': 'ror32(crc, 15) + 0xa282ead8 (mod 2**32), '
                                           'expressed in the binary as '
                                           'ror32(crc, 15) - 0x5d7d1528'},
                       'semantics': 'mask(extend(0, data, n))'},
        'xxhash_arm': {'start': f'{XXHASH_ARM_START:#x}',
                       'end': f'{XXHASH_ARM_END:#x}',
                       'callee': {'start': f'{XXH32_START:#x}',
                                  'end': f'{XXH32_END:#x}',
                                  'body_sha256': checked['callee_hashes']['xxh32'],
                                  'identity': 'ROCKSDB_XXH32'},
                       'semantics': 'XXH32(data, n, seed 0)'},
        'xxhash64_arm': {'start': f'{XXHASH64_ARM_START:#x}',
                         'end': f'{XXHASH64_ARM_END:#x}',
                         'callee': {'start': f'{XXH64_START:#x}',
                                    'end': f'{XXH64_END:#x}',
                                    'body_sha256': checked['callee_hashes']['xxh64'],
                                    'identity': 'ROCKSDB_XXH64'},
                         'semantics': '(u32) XXH64(data, n, seed 0)'},
        'mulmix_arm': {'start': f'{MULMIX_ARM_START:#x}',
                       'end': f'{MULMIX_ARM_END:#x}',
                       'callee': {'start': f'{XXH3_START:#x}',
                                  'end': f'{XXH3_END:#x}',
                                  'body_sha256': checked['callee_hashes']['xxh3'],
                                  'identity': 'ROCKSDB_XXH3_64bits'},
                       'semantics': 'n == 0 -> 0; else (u32) XXH3_64bits(data, n-1) ^ '
                                    '(data[n-1] * 0x6b9083d9); modelled for n <= 17'},
        'check_values': check_values,
        'cases': {'count': len(rows), 'seed': CASE_SEED,
                  'mismatches_vs_reference': 0,
                  'aggregate_sha256': aggregate},
    }
    (dest / 'result.json').write_text(json.dumps(result, indent=2) + '\n',
                                      encoding='utf-8')

    records = {
        'target_digest': DIGEST,
        'records': [
            {'kind': 'function', 'task': 'RE-002',
             'address': f'{FUNCTION_START:#x}', 'end': f'{FUNCTION_END:#x}',
             'body_sha256': checked['body_hash'],
             'identity': 'rocksdb::ComputeBuiltinChecksum '
                         '(vendor census)',
             'contract': 'compute(type: u8, data: *const u8, n: usize) -> u32',
             'semantics': 'dispatches on type; 1 -> mask(extend(0, data, n)); '
                          '2 -> XXH32(data, n, seed 0); '
                          '3 -> (u32) XXH64(data, n, seed 0); '
                          '4 -> n == 0 ? 0 : (u32) XXH3_64bits(data, n-1) ^ '
                          '(data[n-1] * 0x6b9083d9); any other type -> 0'},
        ] + [
            {'kind': 'dispatch', 'type': t, 'arm': arm, 'note': note}
            for t, arm, note in DISPATCH
        ] + [
            {'kind': 'mask', 'address': f'{MASK_SUB_SITE:#x}',
             'sub_immediate': f'{MASK_SUB_IMMEDIATE:#010x}',
             'constant': f'{MASK_CONST:#010x}',
             'formula': 'ror32(crc, 15) + 0xa282ead8 (mod 2**32)',
             'observation': 'the binary expresses the Mask as ror32 then '
                            'sub 0x5d7d1528 (the two\'s complement of '
                            '0xa282ead8); that immediate occurs at 12 sites '
                            'in .text, this arm\'s site is 0x616bd29'},
            {'kind': 'extend_call', 'stub': f'{EXTEND_STUB:#x}',
             'stub_sha256': checked['stub_hash'],
             'fnptr_slot': f'{FNPTR_SLOT:#x}',
             'observation': 'the CRC32C arm calls the registered extend '
                            'function once through the PLT stub at 0x61c25f0, '
                            'which jumps through the .bss slot at 0x6508908; '
                            'the initializer at 0x61c26d0 stores 0x61c21d0 '
                            'there; the call is extend(0, data, n)'},
            {'kind': 'callee', 'arm': 'xxhash', 'address': f'{XXH32_START:#x}',
             'end': f'{XXH32_END:#x}',
             'body_sha256': checked['callee_hashes']['xxh32'],
             'identity': 'ROCKSDB_XXH32'},
            {'kind': 'callee', 'arm': 'xxhash64', 'address': f'{XXH64_START:#x}',
             'end': f'{XXH64_END:#x}',
             'body_sha256': checked['callee_hashes']['xxh64'],
             'identity': 'ROCKSDB_XXH64'},
            {'kind': 'callee', 'arm': 'mulmix', 'address': f'{XXH3_START:#x}',
             'end': f'{XXH3_END:#x}',
             'body_sha256': checked['callee_hashes']['xxh3'],
             'identity': 'ROCKSDB_XXH3_64bits'},
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'aggregate_sha256': aggregate,
             'mismatches_vs_reference': 0,
             'note': 'each arm cross-checked against an independent '
                     'implementation on every case (bitwise vs table '
                     'extend; one-shot vs streaming XXH32/XXH64; '
                     'transliterated vs byte-buffer XXH3 short); the '
                     'binary itself was never executed'},
            {'kind': 'unknown', 'subject': 'callers of 0x616bca0',
             'status': 'no caller census was run for this packet'},
            {'kind': 'unknown', 'subject': 'RocksDB ChecksumType enum name for type 4',
             'status': 'the type number and behavior are recorded; the '
                       'enum member name was not verified from the binary'},
            {'kind': 'unknown', 'subject': 'type-4 arm for n > 17',
             'status': 'the XXH3 helper is modelled only for inputs of '
                       'length 0..16, so the arm is modelled only for '
                       'n <= 17; longer inputs need the 17..240 and '
                       'long-input XXH3 branches'},
        ],
    }
    (dest / 'records.json').write_text(json.dumps(records, indent=2) + '\n',
                                       encoding='utf-8')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', type=Path, default=None,
                        help='generate the evidence packet into DIR')
    parser.add_argument('--cases', type=int, default=CASE_COUNT,
                        help='cases to run in the model cross-check')
    parser.add_argument('--verify', action='store_true',
                        help='verify pinned bytes only, without generating')
    args = parser.parse_args(argv)

    data = TARGET.read_bytes()
    checked = verify(data)
    table = checked['table']
    if args.verify or args.out is None:
        rows = run_cases(generate_cases(args.cases), table)
        print(f"verified: body {checked['body_hash'][:16]}...; "
              f"{len(rows)} cases agree with the references; "
              f"checksum(1, b'123456789') = "
              f"{compute_checksum(1, b'123456789'):#010x}; "
              f"checksum(2, b'a') = {compute_checksum(2, b'a'):#010x}; "
              f"checksum(4, b'abc') = {compute_checksum(4, b'abc'):#010x}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
