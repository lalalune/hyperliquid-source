#!/usr/bin/env python3
"""Reconstruct the node #115 RocksDB ComputeBuiltinChecksumWithLastByte multiply-xor arm.

Bounded question (RE-002): what does the function at 0x616bd60 compute for
ChecksumType 4, for short inputs, and which bytes in the node #115 binary
pin that behaviour?

Observed answer, from the disassembly of work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* The function is the vendor-census entry
  ``_ZN7rocksdb34ComputeBuiltinChecksumWithLastByteENS_12ChecksumTypeEPKcmc``
  (librocksdb-sys). The census pins its body exactly to the FDE
  0x616bd60..0x616beac, and the body SHA-256 below matches the census
  target_body_sha256. Observed register contract: ``type`` in dil,
  ``data`` in rsi, ``n`` in rdx, ``last_byte`` in cl, result u32 in eax.
* Dispatch on ``type`` (compares at 0x616bd76, 0x616bd82, 0x616bd8c,
  0x616bde8): 1 -> CRC32C arm (reconstructed in PR #5396); 2 -> the
  xxhash arm (reconstructed in PR #5402); 3 -> the xxhash64 arm
  (reconstructed in PR #5399); 4 -> the multiply-xor arm at 0x616bdee,
  modelled here; anything else (including 0, kNoChecksum) -> 0.
* Multiply-xor arm (0x616bdee..0x616be11): it calls the 64-bit helper at
  0x61db650 with (data, n), then returns
  ``(u32)helper(data, n) ^ ((u32)last_byte * 0x6b9083d9)`` -- the
  ``imul $0x6b9083d9`` is at 0x616be02 and the 32-bit xor at 0x616be08,
  so only the low 32 bits of the helper result survive.
* The helper at 0x61db650 (FDE 0x61db650..0x61db93a, body SHA-256 below)
  is the XXH3-family 64-bit hash with the default secret and seed 0:
  its short branches use the default XXH3 secret words (verified
  against the secret table at 0x97ec80 in .rodata), the XXH3 primes,
  the rrmxmx finaliser and the XXH3 avalanche; the empty input returns
  0x2d06800538d394c2, the published XXH3_64bits(b"") check value.
  Only inputs of length 0..16 are modelled here: the 1-to-3, 4-to-8
  and 9-to-16 branches. The 17-to-128, 129-to-240 and over-240
  branches (shared tails at 0x61d7dc0 and 0x61d8510) are recorded as
  observed-but-not-modelled.
* Short-input formulas, transliterated instruction by instruction
  (see README.md for the per-address walk):

  - len 0: return 0x2d06800538d394c2.
  - len 1..3 (0x61db8d4..0x61db939): combined = data[len-1]
    | data[0]<<16 | len<<8 | data[len>>1]<<24; keyed =
    (combined ^ 0x87275a9b) where 0x87275a9b is secret[0..4) ^
    secret[4..8); then the XXH64 avalanche without its first
    ``h ^= h>>33`` step (elided: keyed is 32-bit, so h>>33 is 0):
    h *= PRIME64_2, h ^= h>>29, h *= PRIME64_3, h ^= h>>32.
  - len 4..8 (0x61db860..0x61db8bd): input64 = first u32 << 32 |
    last u32; keyed = input64 ^ 0xc73ab174c5ecd5a2 where that
    constant is secret[8..16) ^ secret[16..24); then rrmxmx:
    h ^= rol(h,49) ^ rol(h,24); h *= 0x9fb21c651e98df25;
    h ^= (h>>35) + len; h *= 0x9fb21c651e98df25; h ^= h>>28.
  - len 9..16 (0x61db664..0x61db6b8): A = read64(input) ^
    0x6782737bea4239b9 (secret[24..32) ^ secret[32..40)), B =
    read64(input+len-8) ^ 0xaf56bc3b0996523a (secret[40..48) ^
    secret[48..56)); t = (hi(A*B) ^ lo(A*B)) + (B + len) +
    bswap64(A); then the XXH3 avalanche: t ^= t>>37,
    t *= 0x165667919e3779f9, t ^= t>>32.

  The byte packing in the 1-to-3 and 4-to-8 branches is exactly the
  public XXH3_64bits packing, verified line by line against the
  public implementation (Ruby prism xxh3.c, a faithful port of
  upstream xxHash: XXH3_64_1to3 builds combined as
  input[len-1] | len<<8 | input[0]<<16 | input[len>>1]<<24;
  XXH3_64_4to8 builds combined as read32(input+len-4) |
  read32(input)<<32; XXH3_64_9to16 returns
  avalanche(len + bswap64(lo) + hi + mul128_fold64(lo, hi)) with
  lo = (secret+24 ^ secret+32) ^ read64(input) and hi =
  (secret+40 ^ secret+48) ^ read64(input+len-8)). The empty-input
  value is the published XXH3_64bits(b"") check value, and the
  model reproduces the published XXH3_64bits(b"a") value
  0xe6c632b61e964e1f. The model is still grounded in the disassembly
  first; the public implementation is used only as a cross-check.

The Python model below implements the short-input helper twice
independently -- once as a direct transliteration of the instruction
sequence, once as a structurally different formulation (byte-buffer
packing, struct round-trips, limb multiplication) -- and
cross-checks them on 2400 deterministic cases of length 0..16.
The node binary is never executed.
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
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-xxh3-last-byte-115'
FUNCTION_START = 0x616BD60
FUNCTION_END = 0x616BEAC
MULMIX_ARM_START = 0x616BDEE
MULMIX_ARM_END = 0x616BE11
HELPER_START = 0x61DB650
HELPER_END = 0x61DB93A
LEN_9TO16_START = 0x61DB664
LEN_9TO16_END = 0x61DB6B9
LEN_4TO8_START = 0x61DB860
LEN_4TO8_END = 0x61DB8BE
LEN_1TO3_START = 0x61DB8D4
LEN_1TO3_END = 0x61DB93A
SECRET_ADDR = 0x97EC80
CASE_COUNT = 2400
CASE_SEED = 20261109
MAX_MODEL_LEN = 16

MASK64 = 0xFFFFFFFFFFFFFFFF
MASK32 = 0xFFFFFFFF
P1_64 = 0x9E3779B185EBCA87
P2_64 = 0xC2B2AE3D27D4EB4F
P3_64 = 0x165667B19E3779F9
AVALANCHE_MUL = 0x165667919E3779F9
RRMXMX_MUL = 0x9FB21C651E98DF25
MULMIX_IMUL = 0x6B9083D9
EMPTY_HASH = 0x2D06800538D394C2
# Default XXH3 secret, first 9 words, as read from .rodata at 0x97ec80.
SECRET_WORDS = (
    0xBE4BA423396CFEB8, 0x1CAD21F72C81017C, 0xDB979083E96DD4DE,
    0x1F67B3B7A4A44072, 0x78E5C0CC4EE679CB, 0x2172FFCC7DD05A82,
    0x8E2443F7744608B8, 0x4C263A81E69035E0, 0xCB00C391BB52283C,
)
# Secret-derived immediates in the short branches.
C1_9TO16 = 0x6782737BEA4239B9
C2_9TO16 = 0xAF56BC3B0996523A
BITFLIP_4TO8 = 0xC73AB174C5ECD5A2
BITFLIP_1TO3 = 0x87275A9B

# Census body hash for the dispatcher. The helper has no census record
# (checked: no 0x61db650 entry in
# research/work-items/RE-002-node115-vendor-census/census.json).
CENSUS_BODY = {
    'function': '5680596a85a5810082875d361be174363d5b2b435a5c2494bc72543840138972',
}

# Pinned body hashes, computed from the pinned binary (FDE extents above).
HELPER_BODY = 'adde9328dc4c355cf1410323721f18dea26b8d5508920d127f8cdfdabe5aa3bb'
ARM_BODY = '3ffd29f510ec5ac717311872c4bce129b14ed4d1b6503b8ac601028ef421213d'

# (label, start, end) of the byte-checked instruction windows.
WINDOWS = (
    ('entry_dispatch', 0x616BD60, 0x616BD96),
    ('mulmix_arm', MULMIX_ARM_START, MULMIX_ARM_END),
    ('xxh3_entry', HELPER_START, LEN_9TO16_START),
    ('xxh3_len_9to16', LEN_9TO16_START, LEN_9TO16_END),
    ('xxh3_len_4to8', LEN_4TO8_START, LEN_4TO8_END),
    ('xxh3_len_1to3', LEN_1TO3_START, LEN_1TO3_END),
    ('xxh3_helper', HELPER_START, HELPER_END),
)

# The dispatch table as observed in the disassembly. Only type 4 is
# modelled; the other arms are observations, not claims about the
# hash functions they call.
DISPATCH = (
    (0, 'default_arm', 'returns 0 (kNoChecksum and any other type)'),
    (1, 'crc32c_arm', 'mask(extend(extend(0, data), last_byte)); '
                      'reconstructed in PR #5396'),
    (2, 'xxhash_arm', 'XXH32(data || last_byte, seed 0); '
                      'reconstructed in PR #5402'),
    (3, 'xxhash64_arm', '(u32) XXH64(data || last_byte, seed 0); '
                        'reconstructed in PR #5399'),
    (4, 'mulmix_arm', '(u32) XXH3_64bits(data, n) ^ '
                      '(last_byte * 0x6b9083d9); modelled here for '
                      'n <= 16'),
)

BOUNDARY_LENGTHS = tuple(range(MAX_MODEL_LEN + 1))


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


def rol64(value, count):
    return ((value << count) | (value >> (64 - count))) & MASK64


def ror64(value, count):
    return ((value >> count) | (value << (64 - count))) & MASK64


def bswap64(value):
    return int.from_bytes(value.to_bytes(8, 'little'), 'big')


def _u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def _u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]


def _avalanche64_full(h):
    """Full XXH64 avalanche (with the h ^= h>>33 step)."""
    h ^= h >> 33
    h = (h * P2_64) & MASK64
    h ^= h >> 29
    h = (h * P3_64) & MASK64
    h ^= h >> 32
    return h


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
    if n > MAX_MODEL_LEN:
        raise ValueError(f'not modelled: length {n} > {MAX_MODEL_LEN}')
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
    if n > MAX_MODEL_LEN:
        raise ValueError(f'not modelled: length {n} > {MAX_MODEL_LEN}')
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


def checksum_mulmix_arm(data, last_byte):
    """The type-4 arm for short inputs, via the transliterated helper."""
    helper = xxh3_64_short(data)
    return ((helper & MASK32) ^ ((last_byte * MULMIX_IMUL) & MASK32)) & MASK32


def checksum_mulmix_arm_reference(data, last_byte):
    """Same arm, computed with the independent reference helper."""
    helper = xxh3_64_short_reference(data)
    return ((helper % (1 << 32))
            ^ ((last_byte * 0x6B9083D9) % (1 << 32))) % (1 << 32)


def body_hash(data, secs, start, end):
    off = file_offset(secs, start, end - start)
    return hashlib.sha256(data[off:off + (end - start)]).hexdigest()


def window_hashes(data, secs):
    out = {}
    for label, start, end in WINDOWS:
        out[label] = body_hash(data, secs, start, end)
    return out


def fde_extent(data, start):
    """Return the .eh_frame extent starting at start, or None."""
    _, fdes = eh_frame_records(data)
    for rec in fdes:
        if rec['start'] == start:
            return rec['start'], rec['end']
    return None


def immediate_sites(data, secs):
    """Occurrences of each short-branch immediate in the helper bytes."""
    off = file_offset(secs, HELPER_START, HELPER_END - HELPER_START)
    blob = data[off:off + (HELPER_END - HELPER_START)]
    needles = {
        'bitflip_1to3': struct.pack('<I', BITFLIP_1TO3),
        'empty_hash': struct.pack('<Q', EMPTY_HASH),
        'bitflip_4to8': struct.pack('<Q', BITFLIP_4TO8),
        'rrmxmx_mul': struct.pack('<Q', RRMXMX_MUL),
        'c1_9to16': struct.pack('<Q', C1_9TO16),
        'c2_9to16': struct.pack('<Q', C2_9TO16),
        'avalanche_mul': struct.pack('<Q', AVALANCHE_MUL),
        'prime64_2': struct.pack('<Q', P2_64),
        'prime64_3': struct.pack('<Q', P3_64),
    }
    out = {}
    for name, needle in needles.items():
        sites = []
        pos = 0
        while True:
            idx = blob.find(needle, pos)
            if idx < 0:
                break
            sites.append(f'{HELPER_START + idx:#x}')
            pos = idx + 1
        out[name] = sites
    return out


def secret_words(data, secs):
    off = file_offset(secs, SECRET_ADDR, 8 * len(SECRET_WORDS))
    return struct.unpack_from(f'<{len(SECRET_WORDS)}Q', data, off)


def verify(data):
    """Authenticate the binary and check every pinned byte of the packet."""
    authenticate(data)
    secs = unique_sections(data)
    if secs['.text']['address'] != 0x1419300 or secs['.rodata']['address'] != 0x430400:
        raise ValueError('unexpected section layout')
    extent = fde_extent(data, FUNCTION_START)
    if extent != (FUNCTION_START, FUNCTION_END):
        raise ValueError(f'FDE extent mismatch (dispatcher): {extent}')
    helper_extent = fde_extent(data, HELPER_START)
    if helper_extent != (HELPER_START, HELPER_END):
        raise ValueError(f'FDE extent mismatch (helper): {helper_extent}')
    hashes = {
        'function': body_hash(data, secs, FUNCTION_START, FUNCTION_END),
        'helper': body_hash(data, secs, HELPER_START, HELPER_END),
        'arm': body_hash(data, secs, MULMIX_ARM_START, MULMIX_ARM_END),
    }
    if hashes['function'] != CENSUS_BODY['function']:
        raise ValueError('dispatcher body hash mismatch vs census: '
                         + hashes['function'])
    if hashes['helper'] != HELPER_BODY:
        raise ValueError(f"helper body hash mismatch: {hashes['helper']}")
    if hashes['arm'] != ARM_BODY:
        raise ValueError(f"arm body hash mismatch: {hashes['arm']}")
    sites = immediate_sites(data, secs)
    for name, found in sites.items():
        if not found:
            raise ValueError(f'{name} immediate not found in helper bytes')
    words = secret_words(data, secs)
    if tuple(words) != SECRET_WORDS:
        raise ValueError(f'secret table mismatch at {SECRET_ADDR:#x}: {words}')
    if (words[3] ^ words[4]) != C1_9TO16:
        raise ValueError('C1 derivation mismatch')
    if (words[5] ^ words[6]) != C2_9TO16:
        raise ValueError('C2 derivation mismatch')
    if (words[1] ^ words[2]) != BITFLIP_4TO8:
        raise ValueError('4-to-8 bitflip derivation mismatch')
    if ((words[0] & MASK32) ^ (words[0] >> 32)) != BITFLIP_1TO3:
        raise ValueError('1-to-3 bitflip derivation mismatch')
    # The empty-input constant is the constant-folded XXH3_64_empty:
    # avalanche_XXH64(secret[56..64) ^ secret[64..72)).
    if _avalanche64_full(words[7] ^ words[8]) != EMPTY_HASH:
        raise ValueError('empty-input derivation mismatch')
    # Anchors: the empty input returns the published XXH3_64bits(b"")
    # value in both implementations, and the two implementations agree
    # on every boundary length.
    if xxh3_64_short(b'') != EMPTY_HASH:
        raise ValueError('empty-input check value mismatch')
    if xxh3_64_short_reference(b'') != EMPTY_HASH:
        raise ValueError('empty-input check value mismatch (reference)')
    if xxh3_64_short(b'a') != 0xE6C632B61E964E1F:
        raise ValueError('len-1 check value mismatch vs published '
                         'XXH3_64bits(b"a")')
    for length in BOUNDARY_LENGTHS:
        payload = bytes((length * 7 + i) & 0xFF for i in range(length))
        if xxh3_64_short(payload) != xxh3_64_short_reference(payload):
            raise ValueError(f'model/reference mismatch at length {length}')
    return {'body_hashes': hashes, 'window_hashes': window_hashes(data, secs),
            'immediate_sites': sites, 'sections': secs,
            'secret_words': [f'{w:#018x}' for w in words]}


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic (data, last_byte) cases, all of length 0..16."""
    rng = random.Random(seed)
    cases = []
    for length in BOUNDARY_LENGTHS:
        cases.append((bytes(rng.randrange(256) for _ in range(length)),
                      rng.randrange(256)))
    while len(cases) < count:
        length = rng.randrange(0, MAX_MODEL_LEN + 1)
        cases.append((bytes(rng.randrange(256) for _ in range(length)),
                      rng.randrange(256)))
    return cases[:count]


def run_cases(cases):
    """Run the transliterated model against the independent reference."""
    rows = []
    for payload, last_byte in cases:
        out = checksum_mulmix_arm(payload, last_byte)
        ref = checksum_mulmix_arm_reference(payload, last_byte)
        if out != ref:
            raise ValueError('model disagrees with the reference helper')
        rows.append((payload, last_byte, out))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for payload, last_byte, out in rows:
        hasher.update(hashlib.sha256(payload).digest())
        hasher.update(struct.pack('<B', last_byte))
        hasher.update(struct.pack('<I', out))
    return hasher.hexdigest()


def generate(data, dest):
    """Write the evidence packet files into dest (deterministic)."""
    checked = verify(data)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    cases = generate_cases()
    rows = run_cases(cases)
    aggregate = case_aggregate(rows)

    with (dest / 'windows.tsv').open('w', encoding='utf-8') as handle:
        handle.write('label\tstart\tend\tbytes\tsha256\n')
        for label, start, end in WINDOWS:
            handle.write(f"{label}\t{start:#x}\t{end:#x}\t{end - start}"
                         f"\t{checked['window_hashes'][label]}\n")

    # cases.tsv keeps every boundary-length case plus the first generated
    # rows (63 rows total); the full 2400-case run is summarised in
    # result.json by its aggregate digest.
    sample = rows[:len(BOUNDARY_LENGTHS)] + rows[len(BOUNDARY_LENGTHS):
                                                 len(BOUNDARY_LENGTHS) + 46]
    with (dest / 'cases.tsv').open('w', encoding='utf-8') as handle:
        handle.write('idx\tlen\tdata_sha256\tlast_byte\tarm_out\n')
        for idx, (case_payload, last_byte, out) in enumerate(sample):
            handle.write(f"{idx}\t{len(case_payload)}"
                         f"\t{hashlib.sha256(case_payload).hexdigest()}"
                         f"\t{last_byte:#04x}\t{out:#010x}\n")

    result = {
        'target_digest': DIGEST,
        'function': {'start': f'{FUNCTION_START:#x}', 'end': f'{FUNCTION_END:#x}',
                     'body_sha256': checked['body_hashes']['function'],
                     'fde': [f'{FUNCTION_START:#x}', f'{FUNCTION_END:#x}'],
                     'census_symbol': 'rocksdb::ComputeBuiltinChecksumWithLastByte',
                     'census_body_sha256': CENSUS_BODY['function']},
        'dispatch': [
            {'type': t, 'arm': arm, 'note': note}
            for t, arm, note in DISPATCH
        ],
        'mulmix_arm': {
            'start': f'{MULMIX_ARM_START:#x}', 'end': f'{MULMIX_ARM_END:#x}',
            'body_sha256': checked['body_hashes']['arm'],
            'helper': [f'{HELPER_START:#x}', f'{HELPER_END:#x}'],
            'helper_body_sha256': checked['body_hashes']['helper'],
            'fde': [f'{HELPER_START:#x}', f'{HELPER_END:#x}'],
            'modelled_lengths': f'0..{MAX_MODEL_LEN}',
            'semantics': '(u32) xxh3_64_short(data) ^ '
                         '(last_byte * 0x6b9083d9)',
            'secret_table': f'{SECRET_ADDR:#x}',
            'secret_words': checked['secret_words'],
        },
        'immediates': {
            'bitflip_1to3': f'{BITFLIP_1TO3:#010x}',
            'bitflip_4to8': f'{BITFLIP_4TO8:#018x}',
            'c1_9to16': f'{C1_9TO16:#018x}',
            'c2_9to16': f'{C2_9TO16:#018x}',
            'prime64_2': f'{P2_64:#018x}',
            'prime64_3': f'{P3_64:#018x}',
            'avalanche_mul': f'{AVALANCHE_MUL:#018x}',
            'rrmxmx_mul': f'{RRMXMX_MUL:#018x}',
            'mulmix_imul': f'{MULMIX_IMUL:#010x}',
            'empty_hash': f'{EMPTY_HASH:#018x}',
        },
        'immediate_sites': checked['immediate_sites'],
        'check_value': {
            'helper_empty': f"0x{xxh3_64_short(b''):016x}",
            'expected_helper_empty': '0x2d06800538d394c2',
            'helper_a': f"{xxh3_64_short(b'a'):#018x}",
            'expected_helper_a': '0xe6c632b61e964e1f',
            'helper_abc': f"{xxh3_64_short(b'abc'):#018x}",
            'helper_16byte': f"{xxh3_64_short(bytes(range(16))):#018x}",
            'arm_empty_0x00': f"{checksum_mulmix_arm(b'', 0):#010x}",
            'arm_a_0x00': f"{checksum_mulmix_arm(b'a', 0):#010x}",
            'arm_abc_0xff': f"{checksum_mulmix_arm(b'abc', 0xff):#010x}",
            'arm_16byte_0x00': f"{checksum_mulmix_arm(bytes(range(16)), 0):#010x}",
        },
        'cases': {'count': len(rows), 'seed': CASE_SEED,
                  'max_length': MAX_MODEL_LEN,
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
             'body_sha256': checked['body_hashes']['function'],
             'identity': 'rocksdb::ComputeBuiltinChecksumWithLastByte '
                         '(vendor census)',
             'contract': 'compute(type: u8, data: *const u8, n: usize, '
                         'last_byte: u8) -> u32',
             'semantics': 'dispatches on type; type 4 returns '
                          '(u32) XXH3_64bits(data, n) ^ '
                          '(last_byte * 0x6b9083d9); any other type '
                          'returns 0 except types 1, 2, 3, which take '
                          'their own hash arms'},
        ] + [
            {'kind': 'dispatch', 'type': t, 'arm': arm, 'note': note}
            for t, arm, note in DISPATCH
        ] + [
            {'kind': 'arm', 'type': 4, 'start': f'{MULMIX_ARM_START:#x}',
             'end': f'{MULMIX_ARM_END:#x}',
             'body_sha256': checked['body_hashes']['arm'],
             'semantics': '(u32) helper(data, n) ^ '
                          '(last_byte * 0x6b9083d9)',
             'observation': 'calls the helper at 0x61db650 with '
                            '(data, n) (call at 0x616bdf4); loads the '
                            'last byte (movzbl at 0x616bdf9); '
                            'imul $0x6b9083d9 at 0x616be02; 32-bit xor '
                            'with the helper result at 0x616be08; only '
                            'the low 32 bits of the helper result '
                            'survive'},
            {'kind': 'callee', 'name': 'ROCKSDB_XXH3_64bits',
             'start': f'{HELPER_START:#x}', 'end': f'{HELPER_END:#x}',
             'body_sha256': checked['body_hashes']['helper'],
             'observation': 'XXH3-family 64-bit hash, default secret '
                            '(table at 0x97ec80 in .rodata), seed 0; '
                            'the short branches match public XXH3_64bits '
                            'line by line (verified against the Ruby '
                            'prism xxh3.c port of upstream xxHash: '
                            '1-to-3, 4-to-8 and 9-to-16 formulas); len 0 '
                            'returns 0x2d06800538d394c2 (the published '
                            'XXH3_64bits empty-input value, also derived '
                            'here as avalanche_XXH64(secret[56..64) ^ '
                            'secret[64..72))); len 1 returns '
                            '0xe6c632b61e964e1f (the published '
                            'XXH3_64bits(b"a") value); len 1..3 uses the '
                            'XXH64 avalanche (h *= PRIME64_2, h ^= h>>29, '
                            'h *= PRIME64_3, h ^= h>>32); len 4..8 uses '
                            'rrmxmx; len 9..16 uses a 128-bit product '
                            'fold plus the XXH3 avalanche; no census '
                            'record'},
            {'kind': 'secret', 'address': f'{SECRET_ADDR:#x}',
             'words': checked['secret_words'],
             'observation': 'default XXH3 secret, read from .rodata; '
                            'the short-branch immediates are XORs of '
                            'its words: C1 = secret[24..32) ^ '
                            'secret[32..40), C2 = secret[40..48) ^ '
                            'secret[48..56), 4-to-8 bitflip = '
                            'secret[8..16) ^ secret[16..24), 1-to-3 '
                            'bitflip = secret[0..4) ^ secret[4..8)'},
        ] + [
            {'kind': 'immediate', 'name': name,
             'sites': checked['immediate_sites'][name]}
            for name in ('bitflip_1to3', 'empty_hash', 'bitflip_4to8',
                         'rrmxmx_mul', 'c1_9to16', 'c2_9to16',
                         'avalanche_mul', 'prime64_2', 'prime64_3')
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'max_length': MAX_MODEL_LEN,
             'aggregate_sha256': aggregate, 'mismatches_vs_reference': 0,
             'note': 'transliterated model cross-checked against an '
                     'independent reference formulation on every case; '
                     'the binary itself was never executed'},
            {'kind': 'unknown', 'subject': 'helper branches for len >= 17',
             'status': 'len 17..128, 129..240 and over-240 branches '
                       '(shared tails at 0x61d7dc0 and 0x61d8510) are '
                       'observed but not modelled; the arm is only '
                       'pinned for inputs of length 0..16'},
            {'kind': 'unknown', 'subject': 'callers of 0x616bd60',
             'status': 'no caller census was run for this packet'},
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
    if args.verify or args.out is None:
        rows = run_cases(generate_cases(args.cases))
        print(f"verified: helper {checked['body_hashes']['helper'][:16]}...; "
              f"{len(rows)} cases agree with the reference; "
              f"arm(b'abc', 0xff) = "
              f"{checksum_mulmix_arm(b'abc', 0xff):#010x}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
