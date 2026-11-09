#!/usr/bin/env python3
"""Reconstruct the node #115 RocksDB streaming XXH32 API.

Bounded question (RE-002): what do the five streaming helpers at
0x61daa60..0x61dae18 compute -- createState, freeState, reset, update,
digest -- and which bytes in the node #115 binary pin that behaviour?

Observed answer, from the disassembly of work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* The family is the public XXH32 streaming API. Three members are
  vendor-census entries (librocksdb-sys 0.11.0+8.1.1): ``ROCKSDB_XXH32_reset``
  (id node115-vendor-61daa90, body 62156180...), ``ROCKSDB_XXH32_update``
  (id node115-vendor-61daac0, body c9368927...), ``ROCKSDB_XXH32_digest``
  (id node115-vendor-61dacf0, body f4ced493...); each census body hash
  matches the FDE body hashed from the binary. ``createState`` and
  ``freeState`` have no census records; their bodies are pinned by FDE
  extent and disassembly only.
* ``createState`` (0x61daa60..0x61daa6e) is a tail call to
  ``malloc(0x30)``; it does not initialise the state. ``freeState``
  (0x61daa70..0x61daa84) calls ``free`` and returns 0.
* ``reset`` (0x61daa90..0x61daabb) zeroes the whole 0x30-byte state
  (three ``movups`` stores) and seeds the lanes ``v1 = seed+P1+P2``,
  ``v2 = seed+P2``, ``v3 = seed``, ``v4 = seed-P1``; the seed constants
  arrive as one 16-byte ``.rodata`` vector at 0x451ae0
  (``P1+P2`` 0x24234428, ``P2`` 0x85ebca77, ``0``, ``-P1`` 0x61c8864f),
  added to the broadcast seed with a single ``paddd`` at 0x61daaae --
  the same lane seeding the public XXH32 one-shot uses.
* State layout (0x30 bytes allocated, 44-byte struct): ``total_len``
  +0x00 (u32), ``large_len`` +0x04 (u32, 0/1), ``v1`` +0x08, ``v2``
  +0x0c, ``v3`` +0x10, ``v4`` +0x14, ``mem`` +0x18 (16 bytes),
  ``memsize`` +0x28 (u32). The four bytes at +0x2c..+0x2f are padding
  zeroed by reset and never read. ``total_len`` is a wrapping u32.
* ``update`` (0x61daac0..0x61dace6) returns 0 in every path. A null
  data pointer returns 0 with the state untouched
  (``test %rsi,%rsi; je 0x61dacc0`` -- the length is not even read).
  Otherwise ``total_len += n`` (u32) and ``large_len`` is set when
  ``n > 15`` or the new ``total_len > 15``; when ``memsize + n <= 15``
  the input is buffered in ``mem`` via ``memcpy`` and ``memsize``
  grows. When the buffer fills, the 16-byte ``mem`` block is processed
  with one round per lane (vectorised: ``mem`` lanes times ``P2``
  from the ``.rodata`` vector at 0x452c60, added to the lanes, ``rol``
  13, times ``P1`` via the shift-add chain at 0x61dac29..0x61dac7e)
  and ``memsize`` is cleared; full 16-byte stripes are then processed
  in place (``round(acc, k) = rol(acc + k*P2, 13) * P1`` per lane, the
  scalar loop at 0x61dab29..0x61daba0); the remainder (under 16 bytes)
  is buffered and ``memsize`` is set to its length. The invariant
  after every update is ``memsize == total_len % 16`` and ``mem``
  holds the last ``memsize`` input bytes.
* ``digest`` (0x61dacf0..0x61dae18) reads the tail from ``mem`` with
  ``remaining = memsize``. When ``large_len`` is set it merges the
  lanes (``h = rol(v1,1) + rol(v2,7) + rol(v3,12) + rol(v4,18)``) and
  adds ``total_len``; otherwise ``h = v3 + total_len + P5`` (``v3``
  is the seed). The tail runs at most three 4-byte rounds
  (``h += read32 * P3; h = rol(h,17) * P4``) with the binary's
  unrolled countdown checks, then at most three 1-byte rounds
  (``h += byte * P5; h = rol(h,11) * P1``), then the avalanche
  (``h ^= h>>15; h *= P2; h ^= h>>13; h *= P3; h ^= h>>16``).
  The 4-byte and 1-byte tails are the same shapes as the one-shot
  function at 0x61da8b0 (reconstructed in RE-014-checksum-selector2-115).

The Python model below is a step-by-step transliteration of the
disassembly (buffering branches, stripe loop, merge, unrolled tails).
It is cross-checked against an independent clean-room implementation
of the public XXH32 specification (the one-shot reference over the
concatenated input) on 2400 deterministic cases, each fed in a
different chunking. The node binary is never executed.
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

TARGET = ROOT / 'work' / 'hl-node-115.bin'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-xxh32-streaming-115'
CASE_COUNT = 2400
CASE_SEED = 20261109

MASK32 = 0xFFFFFFFF
P1 = 0x9E3779B1
P2 = 0x85EBCA77
P3 = 0xC2B2AE3D
P4 = 0x27D4EB2F
P5 = 0x165667B1
STATE_SIZE = 0x30
# State offsets, observed in reset/update/digest.
OFF_TOTAL_LEN = 0x00
OFF_LARGE_LEN = 0x04
OFF_V1 = 0x08
OFF_V2 = 0x0C
OFF_V3 = 0x10
OFF_V4 = 0x14
OFF_MEM = 0x18
OFF_MEMSIZE = 0x28

# (name, start, end, census id or None, census symbol or None, body hash)
FUNCTIONS = (
    ('createState', 0x61DAA60, 0x61DAA6E, None, None,
     '308f2076440391812825325f24d327c32527672b15d8a9a730fe94232d429aa8'),
    ('freeState', 0x61DAA70, 0x61DAA84, None, None,
     '630a5e3c790921ea2ebb0214f1d6b96e1a494793443717c8c12c9c26fa551770'),
    ('reset', 0x61DAA90, 0x61DAABB, 'node115-vendor-61daa90',
     'ROCKSDB_XXH32_reset',
     '621561804b9507796c857c877e6915fd5dd213c6181a6115532ab4b3147351a4'),
    ('update', 0x61DAAC0, 0x61DACE6, 'node115-vendor-61daac0',
     'ROCKSDB_XXH32_update',
     'c9368927c229a3d3840e5fa5489e6b1aba1d178d81cb43d03d7119aacd49eae2'),
    ('digest', 0x61DACF0, 0x61DAE18, 'node115-vendor-61dacf0',
     'ROCKSDB_XXH32_digest',
     'f4ced493734fa7a8319db45be0a35b23343a679d37fbbf8bc5cc125b5b6353c5'),
)
# (label, start, end) of the byte-checked instruction windows. The
# windows tile the five functions exactly; the last window pins the
# six streaming calls in the xxhash32 arm of ComputeBuiltinChecksum
# WithLastByte (0x616bd60, reconstructed in PR #5399).
WINDOWS = (
    ('create_state', 0x61DAA60, 0x61DAA6E),
    ('free_state', 0x61DAA70, 0x61DAA84),
    ('reset_zero', 0x61DAA90, 0x61DAAA9),
    ('reset_seeds', 0x61DAAA9, 0x61DAABB),
    ('update_entry', 0x61DAAC0, 0x61DAB14),
    ('update_stripes', 0x61DAB14, 0x61DABC8),
    ('update_fill', 0x61DABC8, 0x61DAC98),
    ('update_tail', 0x61DAC98, 0x61DACC0),
    ('update_null', 0x61DACC0, 0x61DACC8),
    ('update_small', 0x61DACC8, 0x61DACE6),
    ('digest_entry', 0x61DACF0, 0x61DAD2A),
    ('digest_tail4', 0x61DAD2A, 0x61DAD90),
    ('digest_tail1', 0x61DAD90, 0x61DADDF),
    ('digest_avalanche', 0x61DADDF, 0x61DAE08),
    ('digest_short', 0x61DAE08, 0x61DAE18),
    ('arm_xxh32_calls', 0x616BD96, 0x616BDDA),
)
# (label, address, expected 16-byte little-endian word tuple) of the
# .rodata constant vectors the streaming code reads.
RODATA_VECTORS = (
    ('reset_seeds', 0x451AE0,
     ((P1 + P2) & MASK32, P2, 0, (-P1) & MASK32)),
    ('update_p2', 0x452C60, (P2, P2, P2, P2)),
)
# (label, site, immediate offset inside the instruction, value) of the
# 32-bit prime immediates in update/digest (imul $imm and the lea
# displacement that carries P5 in the digest short path).
PRIME_SITES = (
    ('P2', 0x61DAB40, 2, P2),
    ('P1', 0x61DAB4F, 2, P1),
    ('P3', 0x61DAD34, 2, P3),
    ('P4', 0x61DAD43, 2, P4),
    ('P5', 0x61DAD98, 2, P5),
    ('P1', 0x61DADA3, 2, P1),
    ('P2', 0x61DADE6, 2, P2),
    ('P3', 0x61DADF3, 2, P3),
    ('P5', 0x61DAE08, 3, P5),
)
# The six streaming calls in the xxhash32 arm at 0x616bd60.
ARM_CALLS = (
    ('createState', 0x616BD96, 0x61DAA60),
    ('reset', 0x616BDA3, 0x61DAA90),
    ('update', 0x616BDB1, 0x61DAAC0),
    ('update', 0x616BDC3, 0x61DAAC0),
    ('digest', 0x616BDCB, 0x61DACF0),
    ('freeState', 0x616BDD5, 0x61DAA70),
)
ARM_FUNCTION = 'rocksdb::ComputeBuiltinChecksumWithLastByte'
ARM_ADDRESS = 0x616BD60

BOUNDARY_LENGTHS = (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 24, 25,
                    31, 32, 33, 39, 40, 47, 48, 55, 56, 63, 64, 65,
                    71, 72, 95, 96, 127, 128, 129, 256, 1024)
BOUNDARY_SEEDS = (0, 1, 0x9E3779B1, 0x01234567)
CHUNK_STYLES = ('whole', 'halves', 'thirds', 'bytes', 'at16', 'random')


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


def rol32(value, count):
    return ((value << count) | (value >> (32 - count))) & MASK32


def _avalanche(h):
    h ^= h >> 15
    h = (h * P2) & MASK32
    h ^= h >> 13
    h = (h * P3) & MASK32
    h ^= h >> 16
    return h


def _round(acc, lane):
    return (rol32((acc + lane * P2) & MASK32, 13) * P1) & MASK32


def xxh32_reference(data, seed=0):
    """Clean-room XXH32 one-shot from the public specification."""
    n = len(data)
    i = 0
    if n >= 16:
        v1 = (seed + P1 + P2) & MASK32
        v2 = (seed + P2) & MASK32
        v3 = seed & MASK32
        v4 = (seed - P1) & MASK32
        while i + 16 <= n:
            v1 = _round(v1, _u32(data, i))
            v2 = _round(v2, _u32(data, i + 4))
            v3 = _round(v3, _u32(data, i + 8))
            v4 = _round(v4, _u32(data, i + 12))
            i += 16
        h = (rol32(v1, 1) + rol32(v2, 7) + rol32(v3, 12)
             + rol32(v4, 18) + n) & MASK32
    else:
        h = (seed + P5 + n) & MASK32
    while i + 4 <= n:
        h = (rol32((h + _u32(data, i) * P3) & MASK32, 17) * P4) & MASK32
        i += 4
    while i < n:
        h = (rol32((h + data[i] * P5) & MASK32, 11) * P1) & MASK32
        i += 1
    return _avalanche(h)


class XXH32StreamingState:
    """Transliteration of the node #115 streaming XXH32 state machine.

    ``create()`` models the malloc(0x30) tail call: the fields are
    uninitialised until ``reset()`` runs, exactly as in the binary,
    where createState does not initialise the state. ``update(None)``
    is the null-input rule (returns 0, state untouched).
    """

    def __init__(self):
        self.allocated = True
        self.freed = False
        self.initialised = False
        self.total_len = None
        self.large_len = None
        self.v1 = self.v2 = self.v3 = self.v4 = None
        self.mem = None
        self.memsize = None

    @classmethod
    def create(cls):
        """createState: malloc(0x30); no initialisation, returns state."""
        return cls()

    def _check_live(self):
        if self.freed:
            raise ValueError('use after freeState')
        if not self.initialised:
            raise ValueError('update/digest before reset (uninitialised '
                             'malloc memory: contract-undefined)')

    def reset(self, seed):
        """reset(state, seed): zero the state, seed the lanes; returns 0."""
        if self.freed:
            raise ValueError('reset after freeState')
        # 0x61daa9e..0x61daaa9: three movups stores zero the whole
        # 0x30-byte state (the 44-byte struct plus 4 padding bytes).
        self.total_len = 0
        self.large_len = 0
        self.mem = bytearray(16)
        self.memsize = 0
        # 0x61daaa9..0x61daab6: v3 = seed; v1 = seed+P1+P2;
        # v2 = seed+P2; v4 = seed-P1 (the .rodata vector at 0x451ae0).
        self.v1 = (seed + P1 + P2) & MASK32
        self.v2 = (seed + P2) & MASK32
        self.v3 = seed & MASK32
        self.v4 = (seed - P1) & MASK32
        self.initialised = True
        return 0

    def _round_block(self, block):
        """One 16-byte stripe: one round per lane (0x61dab29..0x61daba0,
        and the vectorised fill path at 0x61dabdd..0x61dac82)."""
        self.v1 = _round(self.v1, _u32(block, 0))
        self.v2 = _round(self.v2, _u32(block, 4))
        self.v3 = _round(self.v3, _u32(block, 8))
        self.v4 = _round(self.v4, _u32(block, 12))

    def update(self, data):
        """update(state, data, n): feed bytes; returns 0 in every path."""
        self._check_live()
        if data is None:
            # 0x61daac4..0x61daac7: test data; je -> return 0, the state
            # (including total_len) is untouched.
            return 0
        data = bytes(data)
        n = len(data)
        # 0x61daae4..0x61dab00: total_len += n (u32 wrap); large_len is
        # set when n > 15 or the new total_len > 15.
        new_total = (self.total_len + n) & MASK32
        if n > 15 or new_total > 15:
            self.large_len = 1
        self.total_len = new_total
        # 0x61dab03..0x61dab0e: memsize + n <= 15 -> buffer only.
        if self.memsize + n <= 15:
            self.mem[self.memsize:self.memsize + n] = data
            self.memsize += n
            return 0
        # 0x61dabc8..0x61dac82: the buffer is non-empty, so fill it to
        # 16 bytes, process that block, clear memsize, advance input.
        if self.memsize != 0:
            fill = 16 - self.memsize
            self.mem[self.memsize:16] = data[:fill]
            self._round_block(bytes(self.mem))
            self.memsize = 0
            data = data[fill:]
        # 0x61dab1c..0x61daba0: full 16-byte stripes in place.
        while len(data) >= 16:
            self._round_block(data[:16])
            data = data[16:]
        # 0x61dac98..0x61dacaa: buffer the remainder, memsize = its length.
        self.mem[0:len(data)] = data
        self.memsize = len(data)
        return 0

    def digest(self):
        """digest(state): merge, tail over mem, avalanche; returns u32."""
        self._check_live()
        n = self.total_len
        if self.large_len:
            # 0x61dad07..0x61dad28: h = rol(v1,1)+rol(v2,7)+rol(v3,12)
            # +rol(v4,18), then + total_len.
            h = (rol32(self.v1, 1) + rol32(self.v2, 7)
                 + rol32(self.v3, 12) + rol32(self.v4, 18) + n) & MASK32
        else:
            # 0x61dae08..0x61dae13: h = v3 + total_len + P5 (v3 is the seed).
            h = (self.v3 + n + P5) & MASK32
        # The tail reads mem[0..memsize]; memsize == n % 16 by the update
        # invariant, so mem holds exactly the remaining bytes.
        rem = self.memsize
        i = 0
        # 0x61dad2a..0x61dad90: at most three 4-byte rounds, unrolled with
        # the binary's countdown checks (rem & 12, then rem-4 > 3, then
        # the second counter > 3).
        while rem - i >= 4:
            h = (rol32((h + _u32(self.mem, i) * P3) & MASK32, 17)
                 * P4) & MASK32
            i += 4
        # 0x61dad90..0x61daddf: 1-byte rounds, unrolled three times.
        while i < rem:
            h = (rol32((h + self.mem[i] * P5) & MASK32, 11) * P1) & MASK32
            i += 1
        # 0x61daddf..0x61dae00: avalanche.
        return _avalanche(h)

    def free(self):
        """freeState: free(state); returns 0."""
        if self.freed:
            raise ValueError('double freeState')
        self.freed = True
        return 0


def window_hashes(data, secs):
    out = {}
    for label, start, end in WINDOWS:
        off = file_offset(secs, start, end - start)
        out[label] = hashlib.sha256(data[off:off + (end - start)]).hexdigest()
    return out


def body_hash(data, secs, start, end):
    off = file_offset(secs, start, end - start)
    return hashlib.sha256(data[off:off + (end - start)]).hexdigest()


def fde_extent(data, start):
    """Return the .eh_frame extent starting at start, or None."""
    _, fdes = eh_frame_records(data)
    for rec in fdes:
        if rec['start'] == start:
            return rec['start'], rec['end']
    return None


def _imm32(data, secs, va, off):
    """The 4-byte little-endian immediate at va+off."""
    base = file_offset(secs, va, off + 4)
    return struct.unpack_from('<I', data, base + off)[0]


def _rodata_words(data, secs, va):
    """The four little-endian u32 words at a .rodata address."""
    base = file_offset(secs, va, 16)
    return tuple(struct.unpack_from('<I', data, base + 4 * i)[0]
                 for i in range(4))


def _call_target(data, secs, va):
    """The E8 call target at va (5-byte relative call)."""
    off = file_offset(secs, va, 5)
    if data[off] != 0xE8:
        raise ValueError(f'not a call at {va:#x}')
    rel = struct.unpack_from('<i', data, off + 1)[0]
    return va + 5 + rel


def verify(data):
    """Authenticate the binary and check every pinned byte of the packet."""
    authenticate(data)
    secs = unique_sections(data)
    if secs['.text']['address'] != 0x1419300 or secs['.rodata']['address'] != 0x430400:
        raise ValueError('unexpected section layout')
    bodies = {}
    for name, start, end, census_id, _symbol, census_body in FUNCTIONS:
        extent = fde_extent(data, start)
        if extent != (start, end):
            raise ValueError(f'FDE extent mismatch for {name}: {extent}')
        bodies[name] = body_hash(data, secs, start, end)
        if census_body is not None and bodies[name] != census_body:
            raise ValueError(f'body hash does not match the census for '
                             f'{name}')
        if census_id is not None and census_body is None:
            raise ValueError(f'census id without body for {name}')
    for label, va, want in RODATA_VECTORS:
        got = _rodata_words(data, secs, va)
        if got != want:
            raise ValueError(f'rodata vector mismatch for {label} at '
                             f'{va:#x}: {[hex(w) for w in got]}')
    for _name, site, off, value in PRIME_SITES:
        got = _imm32(data, secs, site, off)
        if got != value:
            raise ValueError(f'immediate mismatch at {site:#x}: '
                             f'{got:#x} != {value:#x}')
    # P1+P2 and -P1 are the seed constants, not P1/P2 themselves.
    if RODATA_VECTORS[0][2][0] != (P1 + P2) & MASK32:
        raise ValueError('P1+P2 seed constant is wrong')
    if RODATA_VECTORS[0][2][3] != (-P1) & MASK32:
        raise ValueError('-P1 seed constant is wrong')
    for name, site, target in ARM_CALLS:
        if _call_target(data, secs, site) != target:
            raise ValueError(f'arm call site {site:#x} does not target '
                             f'{target:#x} ({name})')
    # Published XXH32 vectors anchor the model and the reference; the
    # remaining values were confirmed against the system libxxhash
    # 0.8.2 oracle before this packet was written.
    for data_bytes, seed, want in (
            (b'', 0, 0x02CC5D05),
            (b'a', 0, 0x550D7456),
            (b'abc', 0, 0x32D153FF),
            (b'123456789', 0, 0x937BAD67)):
        state = XXH32StreamingState.create()
        state.reset(seed)
        state.update(data_bytes)
        if state.digest() != want:
            raise ValueError(f'streaming check value mismatch for '
                             f'{data_bytes!r}')
        if xxh32_reference(data_bytes, seed) != want:
            raise ValueError(f'reference check value mismatch for '
                             f'{data_bytes!r}')
    checked = {
        'window_hashes': window_hashes(data, secs),
        'body_hashes': bodies,
        'sections': secs,
    }
    return checked


def _split_lengths(rng, length, style):
    """Chunk lengths for one case under the given style (deterministic)."""
    if length == 0:
        return ()
    if style == 'whole':
        return (length,)
    if style == 'halves':
        cut = length // 2
        return (cut, length - cut)
    if style == 'thirds':
        a = length // 3
        b = 2 * length // 3
        return (a, b - a, length - b)
    if style == 'bytes':
        return tuple(1 for _ in range(length))
    if style == 'at16':
        cuts = [c for c in (16, 32) if 0 < c < length]
        out, prev = [], 0
        for cut in cuts:
            out.append(cut - prev)
            prev = cut
        out.append(length - prev)
        return tuple(out)
    # 'random': 0..8 random split points (a 1-byte input has none).
    if length <= 1:
        return (length,)
    points = sorted(rng.randrange(1, length) for _ in range(rng.randrange(9)))
    out, prev = [], 0
    for point in points:
        out.append(point - prev)
        prev = point
    out.append(length - prev)
    return tuple(out)


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic (seed, data, chunking) cases.

    Boundary lengths hit every stripe/tail boundary under four seeds,
    then patterned and sequential data, then random lengths up to 1024
    with random seeds and random chunkings (whole, halves, thirds,
    byte-by-byte, splits at 16/32, random splits).
    """
    rng = random.Random(seed)
    cases = []
    for idx, length in enumerate(BOUNDARY_LENGTHS):
        for s in BOUNDARY_SEEDS:
            data = bytes(rng.randrange(256) for _ in range(length))
            style = CHUNK_STYLES[idx % len(CHUNK_STYLES)]
            cases.append((s, data, _split_lengths(rng, length, style)))
    for pattern in (b'\x00', b'\xab', b'\xff'):
        for length in (0, 1, 15, 16, 17, 31, 32, 33, 64, 1024):
            cases.append((0, pattern * length,
                          _split_lengths(rng, length, 'halves')))
    for length in (0, 1, 15, 16, 17, 32, 33, 64, 128, 1024):
        cases.append((0, bytes((i & 0xFF) for i in range(length)),
                      _split_lengths(rng, length, 'at16')))
    while len(cases) < count:
        s = rng.getrandbits(32)
        length = rng.choice((rng.randrange(0, 17), rng.randrange(0, 65),
                             rng.randrange(0, 1025)))
        data = bytes(rng.randrange(256) for _ in range(length))
        style = rng.choice(CHUNK_STYLES)
        cases.append((s, data, _split_lengths(rng, length, style)))
    return cases[:count]


def run_cases(cases):
    """Run the streaming model against the one-shot reference; return rows."""
    rows = []
    for seed, data, splits in cases:
        state = XXH32StreamingState.create()
        state.reset(seed)
        pos = 0
        for size in splits:
            if state.update(data[pos:pos + size]) != 0:
                raise ValueError('update did not return 0')
            pos += size
        if pos != len(data):
            raise ValueError('chunking does not cover the input')
        if state.memsize != len(data) % 16:
            raise ValueError('memsize invariant broken')
        if state.total_len != len(data):
            raise ValueError('total_len invariant broken')
        out = state.digest()
        ref = xxh32_reference(data, seed)
        if out != ref:
            raise ValueError(
                f'streaming model disagrees with the one-shot reference '
                f'for seed {seed:#x}, len {len(data)}, splits {splits}')
        if state.free() != 0:
            raise ValueError('freeState did not return 0')
        rows.append((seed, data, splits, out))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for seed, data, splits, out in rows:
        hasher.update(struct.pack('<I', seed))
        hasher.update(struct.pack('<Q', len(data)))
        hasher.update(data)
        hasher.update(struct.pack('<Q', len(splits)))
        for size in splits:
            hasher.update(struct.pack('<Q', size))
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

    # cases.tsv keeps the first 64 rows (all boundary cases for the
    # first seeds); the full 2400-case run is summarised in result.json
    # by its aggregate digest.
    sample = rows[:64]
    with (dest / 'cases.tsv').open('w', encoding='utf-8') as handle:
        handle.write('idx\tseed\tdata_len\tdata_hex\tchunks\tout\n')
        for idx, (seed, data_bytes, splits, out) in enumerate(sample):
            handle.write(f"{idx}\t{seed:#010x}\t{len(data_bytes)}\t"
                         f"{data_bytes.hex()}\t"
                         f"{','.join(str(s) for s in splits)}\t"
                         f"{out:#010x}\n")

    def stream_value(data_bytes, seed, splits):
        state = XXH32StreamingState.create()
        state.reset(seed)
        pos = 0
        for size in splits:
            state.update(data_bytes[pos:pos + size])
            pos += size
        return state.digest()

    long_data = bytes(0xAB for _ in range(1024))
    check_values = {
        'xxh32_empty': {
            'data_hex': '', 'seed': '0x0',
            'out': f"{stream_value(b'', 0, ()):#010x}",
            'note': 'published XXH32 empty vector 0x02cc5d05'},
        'xxh32_single_a': {
            'data_hex': b'a'.hex(), 'seed': '0x0',
            'out': f"{stream_value(b'a', 0, (1,)):#010x}",
            'note': 'published XXH32 vector 0x550d7456'},
        'xxh32_abc': {
            'data_hex': b'abc'.hex(), 'seed': '0x0',
            'out': f"{stream_value(b'abc', 0, (3,)):#010x}",
            'note': 'published XXH32 vector 0x32d153ff'},
        'xxh32_123456789': {
            'data_hex': b'123456789'.hex(), 'seed': '0x0',
            'out': f"{stream_value(b'123456789', 0, (9,)):#010x}",
            'note': 'computed by model and reference (both agree); '
                    'confirmed against the system libxxhash oracle'},
        'xxh32_32_sequential': {
            'data': 'bytes 0..31', 'seed': '0x0',
            'out': f"{stream_value(bytes(range(32)), 0, (32,)):#010x}",
            'note': 'two full stripes, no tail'},
        'xxh32_33_sequential_halves': {
            'data': 'bytes 0..32', 'seed': '0x0',
            'out': f"{stream_value(bytes(range(33)), 0, (16, 17)):#010x}",
            'note': 'two stripes plus a 1-byte tail, fed in halves'},
        'xxh32_64_sequential_seed1_bytes': {
            'data': 'bytes 0..63', 'seed': '0x1',
            'out': f"{stream_value(bytes(range(64)), 1, tuple([1] * 64)):#010x}",
            'note': 'four stripes, nonzero seed, fed byte-by-byte'},
        'xxh32_1024_ab_thirds': {
            'data': '1024 bytes of 0xab', 'seed': '0x0',
            'out': f"{stream_value(long_data, 0, (341, 341, 342)):#010x}",
            'note': 'fed in thirds'},
        'xxh32_empty_seed1': {
            'data_hex': '', 'seed': '0x1',
            'out': f"{stream_value(b'', 1, ()):#010x}",
            'note': 'empty input under a nonzero seed'},
    }
    result = {
        'target_digest': DIGEST,
        'functions': [
            {'name': name, 'start': f'{start:#x}', 'end': f'{end:#x}',
             'body_sha256': checked['body_hashes'][name],
             'fde': [f'{start:#x}', f'{end:#x}'],
             'census_id': census_id, 'census_symbol': symbol,
             'census_body_sha256': census_body}
            for name, start, end, census_id, symbol, census_body
            in FUNCTIONS
        ],
        'contract': {
            'createState': 'createState() -> *mut XXH32_state_t (malloc 0x30, uninitialised)',
            'reset': 'reset(state: *mut XXH32_state_t, seed: u32) -> 0',
            'update': 'update(state: *mut XXH32_state_t, data: *const u8, n: usize) -> 0',
            'digest': 'digest(state: *const XXH32_state_t) -> u32',
            'freeState': 'freeState(state: *mut XXH32_state_t) -> 0',
        },
        'state_layout': {
            'size': f'{STATE_SIZE:#x}',
            'total_len': f'{OFF_TOTAL_LEN:#x}',
            'large_len': f'{OFF_LARGE_LEN:#x}',
            'v1': f'{OFF_V1:#x}', 'v2': f'{OFF_V2:#x}',
            'v3': f'{OFF_V3:#x}', 'v4': f'{OFF_V4:#x}',
            'mem': f'{OFF_MEM:#x}', 'memsize': f'{OFF_MEMSIZE:#x}',
            'invariant': 'after every update, memsize == total_len % 16 '
                         'and mem holds the last memsize input bytes',
        },
        'rodata_vectors': {f'{label}@{va:#x}': {'words': [f'{w:#010x}' for w in words]}
                           for label, va, words in RODATA_VECTORS},
        'primes': {f'{name}@{site:#x}': {'value': f'{value:#010x}'}
                   for name, site, _off, value in PRIME_SITES},
        'null_update': {
            'test_site': '0x61daac4',
            'target': '0x61dacc0',
            'semantics': 'update(state, NULL, n) returns 0 with the state '
                         'untouched (total_len unchanged); a zero length '
                         'with a non-null pointer routes through the '
                         'small-copy path with a zero-length memcpy and is '
                         'observably the same no-op',
        },
        'caller': {
            'function': ARM_FUNCTION,
            'address': f'{ARM_ADDRESS:#x}',
            'calls': [{'name': name, 'site': f'{site:#x}',
                       'target': f'{target:#x}'}
                      for name, site, target in ARM_CALLS],
            'note': 'the type-2 (xxhash32) arm of '
                    'ComputeBuiltinChecksumWithLastByte creates a state, '
                    'resets it with seed 0, updates with the input then '
                    'with the single last byte, digests, keeps the low 32 '
                    'bits, and frees the state (reconstructed in PR #5399)',
        },
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
             'name': name, 'address': f'{start:#x}', 'end': f'{end:#x}',
             'body_sha256': checked['body_hashes'][name],
             'identity': (f'{symbol} (librocksdb-sys 0.11.0+8.1.1, vendor '
                          f'census id {census_id})' if census_id else
                          f'{name} (no vendor-census record; pinned by FDE '
                          f'extent and disassembly only)'),
             'contract': result['contract'][name],
             'semantics': {
                 'createState': 'malloc(0x30) tail call; the returned state '
                                'is uninitialised until reset runs',
                 'freeState': 'free(state); returns 0',
                 'reset': 'zero the whole 0x30-byte state, then v1 = '
                          'seed+P1+P2, v2 = seed+P2, v3 = seed, '
                          'v4 = seed-P1; returns 0',
                 'update': 'buffer sub-16-byte remainders in mem, process '
                           'full 16-byte stripes with one round per lane, '
                           'keep memsize == total_len % 16; returns 0',
                 'digest': 'merge the lanes (or seed+P5+total_len when '
                           'large_len is clear), run the 4/1-byte tail over '
                           'mem, avalanche; returns the u32 hash',
             }[name]}
            for name, start, end, census_id, symbol, _body in FUNCTIONS
        ] + [
            {'kind': 'rodata_vector', 'label': label,
             'address': f'{va:#x}',
             'words': [f'{w:#010x}' for w in words],
             'observation': f'the {label} constant vector at {va:#x} '
                            f'holds these four little-endian u32 words'}
            for label, va, words in RODATA_VECTORS
        ] + [
            {'kind': 'prime', 'prime': name, 'address': f'{site:#x}',
             'value': f'{value:#010x}',
             'observation': f'the {name} prime appears as a 32-bit '
                            f'immediate at {site:#x}'}
            for name, site, _off, value in PRIME_SITES
        ] + [
            {'kind': 'state_layout',
             'observation': 'total_len +0x00 (u32, wrapping), large_len '
                            '+0x04 (u32, 0/1), v1 +0x08, v2 +0x0c, v3 +0x10, '
                            'v4 +0x14, mem +0x18 (16 bytes), memsize +0x28 '
                            '(u32); after every update memsize == total_len '
                            '% 16 and mem holds the last memsize input bytes; '
                            'the four bytes at +0x2c..+0x2f are padding, '
                            'zeroed by reset and never read'},
            {'kind': 'merge',
             'observation': 'h = rol(v1,1) + rol(v2,7) + rol(v3,12) + '
                            'rol(v4,18), then + total_len; the short path '
                            '(large_len clear) instead starts from '
                            'h = v3 + total_len + P5'},
            {'kind': 'null_update', 'address': '0x61daac4',
             'target': '0x61dacc0',
             'observation': 'test data; je returns 0 with the state '
                            'untouched when the data pointer is null'},
        ] + [
            {'kind': 'caller', 'address': f'{site:#x}',
             'observation': f'the xxhash32 arm of {ARM_FUNCTION} '
                            f'({ARM_ADDRESS:#x}) calls {name} here '
                            f'(reconstructed in PR #5399)'}
            for name, site, _target in ARM_CALLS
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'aggregate_sha256': aggregate,
             'mismatches_vs_reference': 0,
             'note': 'streaming model (disassembly transliteration) '
                     'cross-checked against an independent clean-room '
                     'XXH32 one-shot reference over the concatenated input '
                     'on every case, under varied chunkings; the binary '
                     'itself was never executed'},
            {'kind': 'unknown', 'subject': 'createState/freeState census',
             'status': 'no vendor-census records for 0x61daa60 or '
                       '0x61daa70; pinned by FDE extent and disassembly only'},
            {'kind': 'unknown', 'subject': 'update/digest before reset',
             'status': 'the binary would read uninitialised malloc memory; '
                       'the public API contract requires reset first, so '
                       'that path is not modelled'},
            {'kind': 'unknown', 'subject': 'callers of the streaming API',
             'status': 'only the ComputeBuiltinChecksumWithLastByte '
                       'xxhash32 arm call sites are recorded; no full '
                       'caller census was run for this packet'},
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
        state = XXH32StreamingState.create()
        state.reset(0)
        state.update(b'abc')
        print(f"verified: bodies "
              f"{checked['body_hashes']['reset'][:16]}.../"
              f"{checked['body_hashes']['update'][:16]}.../"
              f"{checked['body_hashes']['digest'][:16]}...; "
              f"{len(rows)} cases agree with the reference; "
              f"stream(b'abc', 0) = {state.digest():#010x}; "
              f"stream(b'123456789', 0) = "
              f"{xxh32_reference(b'123456789', 0):#010x}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
