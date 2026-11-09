#!/usr/bin/env python3
"""Reconstruct the node #115 RocksDB streaming XXH64 API.

Bounded question (RE-002): what do the five streaming helpers at
0x61db130..0x61db649 compute -- createState, reset, update, digest,
freeState -- and which bytes in the node #115 binary pin that behaviour?

Observed answer, from the disassembly of work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* The family is the public XXH64 streaming API. Three members are
  vendor-census entries (librocksdb-sys 0.11.0+8.1.1): ``ROCKSDB_XXH64_reset``
  (id node115-vendor-61db160, body 55640a2f...), ``ROCKSDB_XXH64_update``
  (id node115-vendor-61db1d0, body bde58491...), ``ROCKSDB_XXH64_digest``
  (id node115-vendor-61db3e0, body bab7d213...); each census body hash
  matches the FDE body hashed from the binary. ``createState`` and
  ``freeState`` have no census records; their bodies are pinned by FDE
  extent and disassembly only.
* ``createState`` (0x61db130..0x61db13e) is a tail call to
  ``malloc(0x58)``; it does not initialise the state. ``freeState``
  (0x61db140..0x61db154) calls ``free`` and returns 0.
* ``reset`` (0x61db160..0x61db1c9) zeroes the whole 0x58-byte state
  (``total_len`` store plus a ``rep stos`` over the rest) and seeds the
  lanes ``v1 = seed+P1+P2``, ``v2 = seed+P2``, ``v3 = seed``,
  ``v4 = seed-P1``; the three seed constants appear as movabs
  immediates (``P1+P2`` 0x60ea27eeadc0b5d6 at 0x61db193, ``P2`` at
  0x61db1a4, ``-P1`` 0x61c8864e7a143579 at 0x61db1b5).
* State layout (0x58 bytes): ``total_len`` +0x00 (u64), ``v1`` +0x08,
  ``v2`` +0x10, ``v3`` +0x18, ``v4`` +0x20, ``mem`` +0x28 (32 bytes),
  ``memsize`` +0x48 (u32). The trailing 12 bytes (+0x4c..+0x58) are
  zeroed by reset and never read or written by update/digest in the
  observed code; their purpose is recorded as unknown.
* ``update`` (0x61db1d0..0x61db3de) returns 0 in every path. A null
  data pointer returns 0 with the state untouched
  (``test %rsi,%rsi; je 0x61db3b8``). Otherwise ``total_len += n``;
  when ``memsize + n <= 31`` the input is buffered in ``mem`` and
  ``memsize`` grows. When the buffer fills, the 32-byte ``mem`` block
  is processed with one round per lane and ``memsize`` is cleared;
  full 32-byte stripes are then processed in place
  (``round(acc, k) = rol(acc + k*P2, 31) * P1`` per lane, ``P2`` at
  0x61db238 and ``P1`` at 0x61db242; the fourth lane multiplies before
  adding, which is the same arithmetic); the remainder (under 32
  bytes) is buffered and ``memsize`` is set to its length. The
  invariant after every update is ``memsize == total_len % 32`` and
  ``mem`` holds the last ``memsize`` input bytes.
* ``digest`` (0x61db3e0..0x61db649) reads the tail from ``mem`` with
  ``remaining = total_len & 31``. When ``total_len >= 32`` it merges
  the lanes (``h = rol(v1,1) + rol(v2,7) + rol(v3,12) + rol(v4,18)``,
  then one mergeRound per lane, ``h ^= round(0, v); h = h*P1 + P4``,
  with ``+ total_len`` folded into the last mergeRound's ``+ P4``);
  otherwise ``h = v3 + total_len + P5`` (``v3`` is the seed). The tail
  is the same 8/4/1-byte sequence as the one-shot function at
  0x61dae20 (reconstructed in PR #5429), followed by the 64-bit
  avalanche. The 8-byte tail uses the binary's countdown checks
  (``rem & 0x18``, then ``rem-8 > 7``, then ``rem-16 > 7``).

The Python model below is a step-by-step transliteration of the
disassembly (buffering branches, stripe loop, merge with the folded
``+ n``, unrolled tails). It is cross-checked against an independent
clean-room implementation of the public XXH64 specification (the
one-shot reference over the concatenated input) on 2400 deterministic
cases, each fed in a different chunking. The node binary is never
executed.
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
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-xxh64-streaming-115'
CASE_COUNT = 2400
CASE_SEED = 20261109

MASK64 = 0xFFFFFFFFFFFFFFFF
P1 = 0x9E3779B185EBCA87
P2 = 0xC2B2AE3D27D4EB4F
P3 = 0x165667B19E3779F9
P4 = 0x85EBCA77C2B2AE63
P5 = 0x27D4EB2F165667C5
STATE_SIZE = 0x58
# State offsets, observed in reset/update/digest.
OFF_TOTAL_LEN = 0x00
OFF_V1 = 0x08
OFF_V2 = 0x10
OFF_V3 = 0x18
OFF_V4 = 0x20
OFF_MEM = 0x28
OFF_MEMSIZE = 0x48

# (name, start, end, census id or None, census symbol or None, body hash)
FUNCTIONS = (
    ('createState', 0x61DB130, 0x61DB13E, None, None,
     'b0d76579e9e2feb60c2263ceaff242d69aa681f6deccb834d1ea89bcfc9b83d5'),
    ('freeState', 0x61DB140, 0x61DB154, None, None,
     '7d72966cb6b17f2fc99570c89cb360c349dcb13ee4d2d197dddd4b53ff1b160f'),
    ('reset', 0x61DB160, 0x61DB1C9, 'node115-vendor-61db160',
     'ROCKSDB_XXH64_reset',
     '55640a2f386af102afa902c1695c2c609cab93621b3eeac7e6871a0108232025'),
    ('update', 0x61DB1D0, 0x61DB3DE, 'node115-vendor-61db1d0',
     'ROCKSDB_XXH64_update',
     'bde58491e6f3fa0a1febf1f0635c2d6b49399cf2d9c6ada9c7fc2a458cbc8de5'),
    ('digest', 0x61DB3E0, 0x61DB649, 'node115-vendor-61db3e0',
     'ROCKSDB_XXH64_digest',
     'bab7d213c94b5599f51e62102067dbed9cf676a9223a3a3f51ed949426a9edb4'),
)
# (label, start, end) of the byte-checked instruction windows. The
# windows tile the five functions exactly; the last window pins the
# six streaming calls in the xxhash64 arm of ComputeBuiltinChecksum
# WithLastByte (0x616bd60, reconstructed in PR #5399).
WINDOWS = (
    ('create_state', 0x61DB130, 0x61DB13E),
    ('free_state', 0x61DB140, 0x61DB154),
    ('reset_zero', 0x61DB160, 0x61DB18F),
    ('reset_seeds', 0x61DB18F, 0x61DB1C9),
    ('update_entry', 0x61DB1D0, 0x61DB20B),
    ('update_stripes', 0x61DB20B, 0x61DB2E8),
    ('update_fill', 0x61DB2E8, 0x61DB390),
    ('update_trailing', 0x61DB390, 0x61DB3B8),
    ('update_empty', 0x61DB3B8, 0x61DB3C0),
    ('update_small', 0x61DB3C0, 0x61DB3DE),
    ('digest_entry', 0x61DB3E0, 0x61DB3F8),
    ('digest_merge', 0x61DB3F8, 0x61DB4A8),
    ('digest_tail8', 0x61DB4A8, 0x61DB54F),
    ('digest_tail4', 0x61DB54F, 0x61DB58F),
    ('digest_tail1', 0x61DB58F, 0x61DB5EC),
    ('digest_avalanche', 0x61DB5EC, 0x61DB630),
    ('digest_short', 0x61DB630, 0x61DB649),
    ('arm_xxh64_calls', 0x616BE28, 0x616BE6C),
)
# movabs sites for the primes and the seed constants.
PRIME_SITES = (
    ('P1+P2', 0x61DB193, 0x60EA27EEADC0B5D6),
    ('P2', 0x61DB1A4, P2),
    ('-P1', 0x61DB1B5, 0x61C8864E7A143579),
    ('P2', 0x61DB238, P2),
    ('P1', 0x61DB242, P1),
    ('P2', 0x61DB400, P2),
    ('P1', 0x61DB44A, P1),
    ('P4', 0x61DB463, P4),
    ('P3', 0x61DB582, P3),
    ('P5', 0x61DB594, P5),
)
# The six streaming calls in the xxhash64 arm at 0x616bd60.
ARM_CALLS = (
    ('createState', 0x616BE28, 0x61DB130),
    ('reset', 0x616BE35, 0x61DB160),
    ('update', 0x616BE43, 0x61DB1D0),
    ('update', 0x616BE55, 0x61DB1D0),
    ('digest', 0x616BE5D, 0x61DB3E0),
    ('freeState', 0x616BE67, 0x61DB140),
)
ARM_FUNCTION = 'rocksdb::ComputeBuiltinChecksumWithLastByte'
ARM_ADDRESS = 0x616BD60

BOUNDARY_LENGTHS = (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 24, 25,
                    31, 32, 33, 39, 40, 47, 48, 55, 56, 63, 64, 65,
                    71, 72, 95, 96, 127, 128, 129, 256, 1024)
BOUNDARY_SEEDS = (0, 1, 0x9E3779B185EBCA87, 0x0123456789ABCDEF)
CHUNK_STYLES = ('whole', 'halves', 'thirds', 'bytes', 'at32', 'random')


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


def rol64(value, count):
    return ((value << count) | (value >> (64 - count))) & MASK64


def _avalanche(h):
    h ^= h >> 33
    h = (h * P2) & MASK64
    h ^= h >> 29
    h = (h * P3) & MASK64
    h ^= h >> 32
    return h


def _round(acc, lane):
    return (rol64((acc + lane * P2) & MASK64, 31) * P1) & MASK64


def _merge(acc, val):
    acc ^= _round(0, val)
    return (acc * P1 + P4) & MASK64


def xxh64_reference(data, seed=0):
    """Clean-room XXH64 one-shot from the public specification."""
    n = len(data)
    i = 0
    if n >= 32:
        v1 = (seed + P1 + P2) & MASK64
        v2 = (seed + P2) & MASK64
        v3 = seed & MASK64
        v4 = (seed - P1) & MASK64
        while i + 32 <= n:
            v1 = _round(v1, _u64(data, i))
            v2 = _round(v2, _u64(data, i + 8))
            v3 = _round(v3, _u64(data, i + 16))
            v4 = _round(v4, _u64(data, i + 24))
            i += 32
        h = (rol64(v1, 1) + rol64(v2, 7) + rol64(v3, 12)
             + rol64(v4, 18)) & MASK64
        h = _merge(h, v1)
        h = _merge(h, v2)
        h = _merge(h, v3)
        h = _merge(h, v4)
        h = (h + n) & MASK64
    else:
        h = (seed + P5 + n) & MASK64
    while i + 8 <= n:
        h ^= _round(0, _u64(data, i))
        h = (rol64(h, 27) * P1 + P4) & MASK64
        i += 8
    if i + 4 <= n:
        h ^= (_u32(data, i) * P1) & MASK64
        h = (rol64(h, 23) * P2 + P3) & MASK64
        i += 4
    while i < n:
        h ^= (data[i] * P5) & MASK64
        h = (rol64(h, 11) * P1) & MASK64
        i += 1
    return _avalanche(h)


class XXH64StreamingState:
    """Transliteration of the node #115 streaming XXH64 state machine.

    ``create()`` models the malloc(0x58) tail call: the fields are
    uninitialised until ``reset()`` runs, exactly as in the binary,
    where createState does not initialise the state. ``update(None)``
    is the null-input rule (returns 0, state untouched).
    """

    def __init__(self):
        self.allocated = True
        self.freed = False
        self.initialised = False
        self.total_len = None
        self.v1 = self.v2 = self.v3 = self.v4 = None
        self.mem = None
        self.memsize = None

    @classmethod
    def create(cls):
        """createState: malloc(0x58); no initialisation, returns state."""
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
        # 0x61db164..0x61db18c: total_len = 0, then rep stos zeroes the
        # rest of the 0x58-byte state (mem and the trailing bytes too).
        self.total_len = 0
        self.mem = bytearray(32)
        self.memsize = 0
        # 0x61db18f..0x61db1c8: v3 = seed; v1 = seed+P1+P2;
        # v2 = seed+P2; v4 = seed-P1.
        self.v1 = (seed + P1 + P2) & MASK64
        self.v2 = (seed + P2) & MASK64
        self.v3 = seed & MASK64
        self.v4 = (seed - P1) & MASK64
        self.initialised = True
        return 0

    def _round_block(self, block):
        """One 32-byte stripe: one round per lane (0x61db250..0x61db2be).

        The fourth lane multiplies before adding (``imul 0x40(%rbx),
        %rax`` at 0x61db35b), which is the same arithmetic as the
        other three lanes.
        """
        self.v1 = _round(self.v1, _u64(block, 0))
        self.v2 = _round(self.v2, _u64(block, 8))
        self.v3 = _round(self.v3, _u64(block, 16))
        self.v4 = _round(self.v4, _u64(block, 24))

    def update(self, data):
        """update(state, data, n): feed bytes; returns 0 in every path."""
        self._check_live()
        if data is None:
            # 0x61db1d4..0x61db1d7: test data; je -> return 0, the state
            # (including total_len) is untouched.
            return 0
        data = bytes(data)
        n = len(data)
        if n == 0:
            # The binary routes a zero length through the small-copy
            # path with a zero-length memcpy; observably a no-op.
            return 0
        # 0x61db1f4: total_len += n.
        self.total_len = (self.total_len + n) & MASK64
        # 0x61db1f7..0x61db205: memsize + n <= 31 -> buffer only.
        if self.memsize + n <= 31:
            self.mem[self.memsize:self.memsize + n] = data
            self.memsize += n
            return 0
        # 0x61db2e8..0x61db378: the buffer is non-empty, so fill it to
        # 32 bytes, process that block, clear memsize, advance input.
        if self.memsize != 0:
            fill = 32 - self.memsize
            self.mem[self.memsize:32] = data[:fill]
            self._round_block(bytes(self.mem))
            self.memsize = 0
            data = data[fill:]
        # 0x61db221..0x61db2c7: full 32-byte stripes in place.
        while len(data) >= 32:
            self._round_block(data[:32])
            data = data[32:]
        # 0x61db390..0x61db3a2: buffer the remainder, memsize = its length.
        self.mem[0:len(data)] = data
        self.memsize = len(data)
        return 0

    def digest(self):
        """digest(state): merge, tail over mem, avalanche; returns u64."""
        self._check_live()
        n = self.total_len
        if n >= 32:
            # 0x61db3f8..0x61db4a1: h = rol(v1,1)+rol(v2,7)+rol(v3,12)
            # +rol(v4,18), one mergeRound per lane; +n is folded into
            # the last mergeRound as +P4+n (add %rbp,%r8 at 0x61db497
            # sets r11 = P4 + total_len).
            h = (rol64(self.v1, 1) + rol64(self.v2, 7)
                 + rol64(self.v3, 12) + rol64(self.v4, 18)) & MASK64
            h = _merge(h, self.v1)
            h = _merge(h, self.v2)
            h = _merge(h, self.v3)
            h = ((h ^ _round(0, self.v4)) * P1 + P4 + n) & MASK64
        else:
            # 0x61db630..0x61db644: h = v3 + n + P5 (v3 is the seed).
            h = (self.v3 + n + P5) & MASK64
        # The tail reads mem[0..n&31]; memsize == n % 32 by the update
        # invariant, so mem holds exactly the remaining bytes.
        rem = n & 31
        i = 0
        # 0x61db4a8..0x61db54f: 8-byte tail with the binary's countdown
        # checks (rem & 0x18, then rem-8 > 7, then rem-16 > 7).
        if rem & 0x18:
            r = rem - 8
            h = self._tail8(h, i)
            i += 8
            if r > 7:
                h = self._tail8(h, i)
                i += 8
                if rem - 16 > 7:
                    h = self._tail8(h, i)
                    i += 8
        # 0x61db54f..0x61db58f: at most one 4-byte round.
        if (rem & 7) > 3:
            h ^= (_u32(self.mem, i) * P1) & MASK64
            h = (rol64(h, 23) * P2 + P3) & MASK64
            i += 4
        # 0x61db58f..0x61db5ec: 1-byte rounds, unrolled three times.
        while i < rem:
            h ^= (self.mem[i] * P5) & MASK64
            h = (rol64(h, 11) * P1) & MASK64
            i += 1
        # 0x61db5ec..0x61db626: avalanche.
        return _avalanche(h)

    def _tail8(self, h, i):
        """One 8-byte tail round: h ^= round(0, k); h = rol(h,27)*P1+P4."""
        h ^= _round(0, _u64(self.mem, i))
        return (rol64(h, 27) * P1 + P4) & MASK64

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


def _movabs_immediate(data, secs, va):
    """The 8-byte little-endian immediate after a movabs at va."""
    off = file_offset(secs, va, 10)
    return struct.unpack_from('<Q', data, off + 2)[0]


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
    for _name, site, value in PRIME_SITES:
        got = _movabs_immediate(data, secs, site)
        if got != value:
            raise ValueError(f'immediate mismatch at {site:#x}: '
                             f'{got:#x} != {value:#x}')
    # P1+P2 and -P1 are the seed constants, not P1/P2 themselves.
    if PRIME_SITES[0][2] != (P1 + P2) & MASK64:
        raise ValueError('P1+P2 seed constant is wrong')
    if PRIME_SITES[2][2] != (-P1) & MASK64:
        raise ValueError('-P1 seed constant is wrong')
    for name, site, target in ARM_CALLS:
        if _call_target(data, secs, site) != target:
            raise ValueError(f'arm call site {site:#x} does not target '
                             f'{target:#x} ({name})')
    # Published XXH64 vectors anchor the model and the reference.
    for data_bytes, seed, want in (
            (b'', 0, 0xEF46DB3751D8E999),
            (b'a', 0, 0xD24EC4F1A98C6E5B),
            (b'abc', 0, 0x44BC2CF5AD770999),
            (b'123456789', 0, 0x8CB841DB40E6AE83)):
        state = XXH64StreamingState.create()
        state.reset(seed)
        state.update(data_bytes)
        if state.digest() != want:
            raise ValueError(f'streaming check value mismatch for '
                             f'{data_bytes!r}')
        if xxh64_reference(data_bytes, seed) != want:
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
    if style == 'at32':
        cuts = [c for c in (32, 64) if 0 < c < length]
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
    byte-by-byte, splits at 32/64, random splits).
    """
    rng = random.Random(seed)
    cases = []
    for idx, length in enumerate(BOUNDARY_LENGTHS):
        for s in BOUNDARY_SEEDS:
            data = bytes(rng.randrange(256) for _ in range(length))
            style = CHUNK_STYLES[idx % len(CHUNK_STYLES)]
            cases.append((s, data, _split_lengths(rng, length, style)))
    for pattern in (b'\x00', b'\xab', b'\xff'):
        for length in (0, 1, 31, 32, 33, 63, 64, 65, 128, 1024):
            cases.append((0, pattern * length,
                          _split_lengths(rng, length, 'halves')))
    for length in (0, 1, 31, 32, 33, 64, 65, 128, 1024):
        cases.append((0, bytes((i & 0xFF) for i in range(length)),
                      _split_lengths(rng, length, 'at32')))
    while len(cases) < count:
        s = rng.getrandbits(64)
        length = rng.choice((rng.randrange(0, 33), rng.randrange(0, 129),
                             rng.randrange(0, 1025)))
        data = bytes(rng.randrange(256) for _ in range(length))
        style = rng.choice(CHUNK_STYLES)
        cases.append((s, data, _split_lengths(rng, length, style)))
    return cases[:count]


def run_cases(cases):
    """Run the streaming model against the one-shot reference; return rows."""
    rows = []
    for seed, data, splits in cases:
        state = XXH64StreamingState.create()
        state.reset(seed)
        pos = 0
        for size in splits:
            if state.update(data[pos:pos + size]) != 0:
                raise ValueError('update did not return 0')
            pos += size
        if pos != len(data):
            raise ValueError('chunking does not cover the input')
        if state.memsize != len(data) % 32:
            raise ValueError('memsize invariant broken')
        if state.total_len != len(data):
            raise ValueError('total_len invariant broken')
        out = state.digest()
        ref = xxh64_reference(data, seed)
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
        hasher.update(struct.pack('<Q', seed))
        hasher.update(struct.pack('<Q', len(data)))
        hasher.update(data)
        hasher.update(struct.pack('<Q', len(splits)))
        for size in splits:
            hasher.update(struct.pack('<Q', size))
        hasher.update(struct.pack('<Q', out))
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
            handle.write(f"{idx}\t{seed:#018x}\t{len(data_bytes)}\t"
                         f"{data_bytes.hex()}\t"
                         f"{','.join(str(s) for s in splits)}\t"
                         f"{out:#018x}\n")

    def stream_value(data_bytes, seed, splits):
        state = XXH64StreamingState.create()
        state.reset(seed)
        pos = 0
        for size in splits:
            state.update(data_bytes[pos:pos + size])
            pos += size
        return state.digest()

    long_data = bytes(0xAB for _ in range(1024))
    check_values = {
        'xxh64_empty': {
            'data_hex': '', 'seed': '0x0',
            'out': f"{stream_value(b'', 0, ()):#018x}",
            'note': 'published XXH64 empty vector 0xef46db3751d8e999'},
        'xxh64_single_a': {
            'data_hex': b'a'.hex(), 'seed': '0x0',
            'out': f"{stream_value(b'a', 0, (1,)):#018x}",
            'note': 'published XXH64 vector 0xd24ec4f1a98c6e5b'},
        'xxh64_abc': {
            'data_hex': b'abc'.hex(), 'seed': '0x0',
            'out': f"{stream_value(b'abc', 0, (3,)):#018x}",
            'note': 'published XXH64 vector 0x44bc2cf5ad770999'},
        'xxh64_123456789': {
            'data_hex': b'123456789'.hex(), 'seed': '0x0',
            'out': f"{stream_value(b'123456789', 0, (9,)):#018x}",
            'note': 'computed by model and reference (both agree)'},
        'xxh64_32_sequential': {
            'data': 'bytes 0..31', 'seed': '0x0',
            'out': f"{stream_value(bytes(range(32)), 0, (32,)):#018x}",
            'note': 'one full stripe, no tail'},
        'xxh64_33_sequential_halves': {
            'data': 'bytes 0..32', 'seed': '0x0',
            'out': f"{stream_value(bytes(range(33)), 0, (16, 17)):#018x}",
            'note': 'one stripe plus a 1-byte tail, fed in halves'},
        'xxh64_64_sequential_seed1_bytes': {
            'data': 'bytes 0..63', 'seed': '0x1',
            'out': f"{stream_value(bytes(range(64)), 1, tuple([1] * 64)):#018x}",
            'note': 'two stripes, nonzero seed, fed byte-by-byte'},
        'xxh64_1024_ab_thirds': {
            'data': '1024 bytes of 0xab', 'seed': '0x0',
            'out': f"{stream_value(long_data, 0, (341, 341, 342)):#018x}",
            'note': 'fed in thirds'},
        'xxh64_empty_seed1': {
            'data_hex': '', 'seed': '0x1',
            'out': f"{stream_value(b'', 1, ()):#018x}",
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
            'createState': 'createState() -> *mut XXH64_state_t (malloc 0x58, uninitialised)',
            'reset': 'reset(state: *mut XXH64_state_t, seed: u64) -> 0',
            'update': 'update(state: *mut XXH64_state_t, data: *const u8, n: usize) -> 0',
            'digest': 'digest(state: *const XXH64_state_t) -> u64',
            'freeState': 'freeState(state: *mut XXH64_state_t) -> 0',
        },
        'state_layout': {
            'size': f'{STATE_SIZE:#x}',
            'total_len': f'{OFF_TOTAL_LEN:#x}',
            'v1': f'{OFF_V1:#x}', 'v2': f'{OFF_V2:#x}',
            'v3': f'{OFF_V3:#x}', 'v4': f'{OFF_V4:#x}',
            'mem': f'{OFF_MEM:#x}', 'memsize': f'{OFF_MEMSIZE:#x}',
            'invariant': 'after every update, memsize == total_len % 32 '
                         'and mem holds the last memsize input bytes',
        },
        'primes': {f'{name}@{site:#x}': {'value': f'{value:#018x}'}
                   for name, site, value in PRIME_SITES},
        'null_update': {
            'test_site': '0x61db1d4',
            'target': '0x61db3b8',
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
            'note': 'the type-3 (xxhash64) arm of '
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
                 'createState': 'malloc(0x58) tail call; the returned state '
                                'is uninitialised until reset runs',
                 'freeState': 'free(state); returns 0',
                 'reset': 'zero the whole 0x58-byte state, then v1 = '
                          'seed+P1+P2, v2 = seed+P2, v3 = seed, '
                          'v4 = seed-P1; returns 0',
                 'update': 'buffer sub-32-byte remainders in mem, process '
                           'full 32-byte stripes with one round per lane, '
                           'keep memsize == total_len % 32; returns 0',
                 'digest': 'merge the lanes (or seed+P5+total_len when '
                           'total_len < 32), run the 8/4/1-byte tail over '
                           'mem, avalanche; returns the u64 hash',
             }[name]}
            for name, start, end, census_id, symbol, _body in FUNCTIONS
        ] + [
            {'kind': 'prime', 'prime': name, 'address': f'{site:#x}',
             'value': f'{value:#018x}',
             'observation': f'the {name} prime appears as a movabs '
                            f'immediate at {site:#x}'}
            for name, site, value in PRIME_SITES
        ] + [
            {'kind': 'state_layout',
             'observation': 'total_len +0x00, v1 +0x08, v2 +0x10, v3 +0x18, '
                            'v4 +0x20, mem +0x28 (32 bytes), memsize +0x48 '
                            '(u32); after every update memsize == total_len '
                            '% 32 and mem holds the last memsize input bytes'},
            {'kind': 'merge',
             'observation': 'h = rol(v1,1) + rol(v2,7) + rol(v3,12) + '
                            'rol(v4,18), then one mergeRound per lane '
                            '(h ^= round(0, v); h = h*P1 + P4); the + '
                            'total_len term is folded into the last '
                            'mergeRound as + P4 + total_len (add %rbp,%r8 '
                            'at 0x61db497); the short path (total_len < 32) '
                            'instead starts from h = v3 + total_len + P5'},
            {'kind': 'null_update', 'address': '0x61db1d4',
             'target': '0x61db3b8',
             'observation': 'test data; je returns 0 with the state '
                            'untouched when the data pointer is null'},
        ] + [
            {'kind': 'caller', 'address': f'{site:#x}',
             'observation': f'the xxhash64 arm of {ARM_FUNCTION} '
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
                     'XXH64 one-shot reference over the concatenated input '
                     'on every case, under varied chunkings; the binary '
                     'itself was never executed'},
            {'kind': 'unknown', 'subject': 'trailing state bytes +0x4c..+0x58',
             'status': 'zeroed by reset, never read or written by '
                       'update/digest in the observed code; purpose not '
                       'claimed'},
            {'kind': 'unknown', 'subject': 'createState/freeState census',
             'status': 'no vendor-census records for 0x61db130 or '
                       '0x61db140; pinned by FDE extent and disassembly only'},
            {'kind': 'unknown', 'subject': 'update/digest before reset',
             'status': 'the binary would read uninitialised malloc memory; '
                       'the public API contract requires reset first, so '
                       'that path is not modelled'},
            {'kind': 'unknown', 'subject': 'callers of the streaming API',
             'status': 'only the ComputeBuiltinChecksumWithLastByte '
                       'xxhash64 arm call sites are recorded; no full '
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
        state = XXH64StreamingState.create()
        state.reset(0)
        state.update(b'abc')
        print(f"verified: bodies "
              f"{checked['body_hashes']['reset'][:16]}.../"
              f"{checked['body_hashes']['update'][:16]}.../"
              f"{checked['body_hashes']['digest'][:16]}...; "
              f"{len(rows)} cases agree with the reference; "
              f"stream(b'abc', 0) = {state.digest():#018x}; "
              f"stream(b'123456789', 0) = "
              f"{xxh64_reference(b'123456789', 0):#018x}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
