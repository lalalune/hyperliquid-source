#!/usr/bin/env python3
"""Reconstruct the node #115 RocksDB one-shot XXH64 function.

Bounded question (RE-002): what does the function at 0x61dae20 compute
for an input buffer and a seed, and which bytes in the node #115 binary
pin that behaviour?

Observed answer, from the disassembly of work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* The function is the vendor-census entry ``ROCKSDB_XXH64``
  (librocksdb-sys 0.11.0+8.1.1, census id node115-vendor-61dae20). The
  census pins its body exactly to the FDE 0x61dae20..0x61db121, and the
  body SHA-256 below matches the census target_body_sha256. Observed
  register contract: ``data`` in rdi, ``n`` in rsi, ``seed`` in rdx,
  result u64 in rax. It is the type-3 callee of
  ``rocksdb::ComputeBuiltinChecksum`` at 0x616bca0 (call at 0x616bd38,
  reconstructed in PR #5413), which keeps the low 32 bits.
* It is the public XXH64 one-shot hash: four 64-bit lanes seeded from
  the seed, 32-byte stripes with round ``rol(acc + k*P2, 31) * P1``,
  mergeRounds, 8/4/1-byte tails, and the 64-bit avalanche. The five
  primes appear as movabs immediates at the pinned sites below.
* Compiler detail: the mergeRounds do not recompute ``round(0, v)``
  directly. The stripe loop leaves the pre-multiply lane value
  ``rol(v_prev + k*P2, 31)`` in a scratch register, and the merge
  multiplies it by ``P1*P2 mod 2**64`` (0xdef35b010f796ca9, movabs at
  0x61daf0f) before the rol-31/*P1 steps, because
  ``pre * P1 * P2 == (pre * P1) * P2 == v * P2``. The ``+ n`` term is
  folded into the last mergeRound's ``+ P4`` (``add %rbp,%r8`` at
  0x61daf8d, where r8 holds P4).
* Null input: ``test %rdi,%rdi; je 0x61db0de`` at 0x61dae39/0x61dae3c
  jumps straight to the avalanche with ``h = seed + P5 + n`` and no
  buffer load, so a null pointer still yields the seeded empty-input
  avalanche even for a nonzero length. The model covers the non-null
  path; the null rule is recorded separately (``xxh64_null``).

The Python model below is a step-by-step transliteration of the
disassembly (unrolled tails, the P1*P2 merge reduction, the folded
``+ n``). It is cross-checked against an independent clean-room
implementation of the public XXH64 specification (while loops, plain
mergeRound helper) and against a streaming state machine fed in
chunks, on 2400 deterministic cases. The node binary is never executed.
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
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-xxh64-oneshot-115'
FUNCTION_START = 0x61DAE20
FUNCTION_END = 0x61DB121
CENSUS_ID = 'node115-vendor-61dae20'
CENSUS_SYMBOL = 'ROCKSDB_XXH64'
CENSUS_BODY = '577ad945e65ddde3fc0ca78ae8d6316c7cb08203bbca5d08a07babca5d08bec8'
CASE_COUNT = 2400
CASE_SEED = 20261109

MASK64 = 0xFFFFFFFFFFFFFFFF
P1 = 0x9E3779B185EBCA87
P2 = 0xC2B2AE3D27D4EB4F
P3 = 0x165667B19E3779F9
P4 = 0x85EBCA77C2B2AE63
P5 = 0x27D4EB2F165667C5
# P1 * P2 mod 2**64, the strength-reduced constant at 0x61daf0f.
P1_TIMES_P2 = 0xDEF35B010F796CA9
# movabs sites for the five primes and the P1*P2 constant.
PRIME_SITES = (
    ('P5', 0x61DAE24, P5),
    ('P2', 0x61DAE67, P2),
    ('P1', 0x61DAE82, P1),
    ('P4', 0x61DAF59, P4),
    ('P3', 0x61DB074, P3),
)
P1P2_SITE = 0x61DAF0F
NULL_BRANCH_JE = 0x61DAE3C
AVALANCHE_START = 0x61DB0DE
# The type-3 arm of ComputeBuiltinChecksum calls this function here.
DISPATCHER_CALL_SITE = 0x616BD38
DISPATCHER_CALL_START = 0x616BD30
DISPATCHER_CALL_END = 0x616BD48

# (label, start, end) of the byte-checked instruction windows. The
# seven function windows tile 0x61dae20..0x61db121 exactly; the last
# window pins the dispatcher call site that reaches this function.
WINDOWS = (
    ('entry', 0x61DAE20, 0x61DAE55),
    ('lane_init_and_stripes', 0x61DAE55, 0x61DAEF0),
    ('merge', 0x61DAEF0, 0x61DAF9A),
    ('tail8', 0x61DAF9A, 0x61DB041),
    ('tail4', 0x61DB041, 0x61DB081),
    ('tail1', 0x61DB081, 0x61DB0DE),
    ('avalanche', 0x61DB0DE, 0x61DB121),
    ('dispatcher_xxh64_call', DISPATCHER_CALL_START, DISPATCHER_CALL_END),
)

BOUNDARY_LENGTHS = (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 24, 25,
                    31, 32, 33, 39, 40, 47, 48, 55, 56, 63, 64, 65,
                    71, 72, 95, 96, 127, 128, 129, 256, 1024)
BOUNDARY_SEEDS = (0, 1, 0x9E3779B185EBCA87, 0x0123456789ABCDEF)


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


def xxh64_null(seed, length):
    """The null-input rule: no buffer load, h = seed + P5 + n, avalanche."""
    return _avalanche((seed + P5 + length) & MASK64)


def _round_from_pre(pre):
    """round(0, v) as the binary computes it: pre * P1*P2, rol 31, * P1.

    ``pre`` is the stripe loop's pre-multiply lane value
    ``rol(v_prev + k*P2, 31)``; ``v = pre * P1``, so
    ``pre * P1 * P2 == v * P2`` and this equals ``round(0, v)``.
    """
    return (rol64((pre * P1_TIMES_P2) & MASK64, 31) * P1) & MASK64


def _tail8(h, data, i):
    """One 8-byte tail round: h ^= round(0, k); h = rol(h, 27)*P1 + P4."""
    h ^= (rol64((_u64(data, i) * P2) & MASK64, 31) * P1) & MASK64
    return (rol64(h, 27) * P1 + P4) & MASK64


def xxh64_model(data, seed=0):
    """Transliteration of the disassembly at 0x61dae20..0x61db121.

    Stripe loop, merge with the P1*P2 reduction, unrolled 8-byte tail
    with the binary's countdown checks, single 4-byte round, unrolled
    1-byte rounds, avalanche. ``data`` must be non-null (see
    ``xxh64_null`` for the null-pointer rule).
    """
    n = len(data)
    i = 0
    # 0x61dae24..0x61dae48: rax = P5 + seed + n (kept for the short path).
    h = (seed + P5 + n) & MASK64
    if n >= 32:
        # 0x61dae55..0x61dae8c: v1 = seed+P1+P2, v2 = seed+P2,
        # v3 = seed, v4 = seed-P1.
        v1 = (seed + P1 + P2) & MASK64
        v2 = (seed + P2) & MASK64
        v3 = seed & MASK64
        v4 = (seed - P1) & MASK64
        # 0x61dae90..0x61daeee: 32-byte stripes; the loop keeps both the
        # pre-multiply value (r8/rsi/rcx/rdx) and the lane (r10/r12/r11/r14).
        while i + 32 <= n:
            pre1 = rol64((v1 + _u64(data, i) * P2) & MASK64, 31)
            pre2 = rol64((v2 + _u64(data, i + 8) * P2) & MASK64, 31)
            pre3 = rol64((v3 + _u64(data, i + 16) * P2) & MASK64, 31)
            pre4 = rol64((v4 + _u64(data, i + 24) * P2) & MASK64, 31)
            v1 = (pre1 * P1) & MASK64
            v2 = (pre2 * P1) & MASK64
            v3 = (pre3 * P1) & MASK64
            v4 = (pre4 * P1) & MASK64
            i += 32
        # 0x61daf0c..0x61daf97: h = rol(v1,1)+rol(v2,7)+rol(v3,12)
        # +rol(v4,18), then one mergeRound per lane; the +n term is
        # folded into the last mergeRound's +P4 (0x61daf8d add %rbp,%r8).
        h = (rol64(v1, 1) + rol64(v2, 7) + rol64(v3, 12)
             + rol64(v4, 18)) & MASK64
        h = ((h ^ _round_from_pre(pre1)) * P1 + P4) & MASK64
        h = ((h ^ _round_from_pre(pre2)) * P1 + P4) & MASK64
        h = ((h ^ _round_from_pre(pre3)) * P1 + P4) & MASK64
        h = ((h ^ _round_from_pre(pre4)) * P1 + P4 + n) & MASK64
    # 0x61daf9a..0x61db032: 8-byte tail. The binary tests len & 0x18
    # (== (n & 31) & 0x18), then processes up to three rounds with the
    # countdown checks r8 = rem-8 and rcx = rem-16.
    rem = n & 31
    if rem & 0x18:
        r8 = rem - 8
        h = _tail8(h, data, i)
        i += 8
        if r8 > 7:
            h = _tail8(h, data, i)
            i += 8
            if rem - 16 > 7:
                h = _tail8(h, data, i)
                i += 8
    # 0x61db041..0x61db081: at most one 4-byte round (n - i < 8 here).
    if n - i >= 4:
        h ^= (_u32(data, i) * P1) & MASK64
        h = (rol64(h, 23) * P2 + P3) & MASK64
        i += 4
    # 0x61db081..0x61db0de: 1-byte rounds, unrolled three times in the
    # binary (cmp $1/$2, je) -- at most three remain (n - i < 4).
    while i < n:
        h ^= (data[i] * P5) & MASK64
        h = (rol64(h, 11) * P1) & MASK64
        i += 1
    # 0x61db0de..0x61db120: avalanche.
    return _avalanche(h)


def _round(acc, lane):
    return (rol64((acc + lane * P2) & MASK64, 31) * P1) & MASK64


def _merge(acc, val):
    acc ^= _round(0, val)
    return (acc * P1 + P4) & MASK64


def xxh64_reference(data, seed=0):
    """Clean-room XXH64 from the public specification (while loops)."""
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
    return _xxh64_reference_tail(data, seed, n, i, h)


def _xxh64_reference_tail(data, seed, n, i, h):
    while i + 8 <= n:
        k = _round(0, _u64(data, i))
        h ^= k
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


class XXH64Stream:
    """Streaming XXH64: feed arbitrary chunks, digest at the end.

    Independent third path: buffers the sub-32-byte remainder and runs
    the one-shot reference over (lanes + buffered tail) at digest time.
    Mirrors the public streaming API shape (reset/update/digest).
    """

    def __init__(self, seed=0):
        self.reset(seed)

    def reset(self, seed):
        self.seed = seed
        self.total = 0
        self.buf = bytearray()
        self.v1 = (seed + P1 + P2) & MASK64
        self.v2 = (seed + P2) & MASK64
        self.v3 = seed & MASK64
        self.v4 = (seed - P1) & MASK64
        self.lanes_started = False

    def update(self, data):
        data = bytes(data)
        self.total += len(data)
        self.buf += data
        while len(self.buf) >= 32:
            block = bytes(self.buf[:32])
            del self.buf[:32]
            self.lanes_started = True
            self.v1 = _round(self.v1, _u64(block, 0))
            self.v2 = _round(self.v2, _u64(block, 8))
            self.v3 = _round(self.v3, _u64(block, 16))
            self.v4 = _round(self.v4, _u64(block, 24))

    def digest(self):
        n = self.total
        tail = bytes(self.buf)
        if self.lanes_started:
            h = (rol64(self.v1, 1) + rol64(self.v2, 7)
                 + rol64(self.v3, 12) + rol64(self.v4, 18)) & MASK64
            h = _merge(h, self.v1)
            h = _merge(h, self.v2)
            h = _merge(h, self.v3)
            h = _merge(h, self.v4)
            h = (h + n) & MASK64
        else:
            h = (self.seed + P5 + n) & MASK64
        i = 0
        while i + 8 <= len(tail):
            k = _round(0, _u64(tail, i))
            h ^= k
            h = (rol64(h, 27) * P1 + P4) & MASK64
            i += 8
        if i + 4 <= len(tail):
            h ^= (_u32(tail, i) * P1) & MASK64
            h = (rol64(h, 23) * P2 + P3) & MASK64
            i += 4
        while i < len(tail):
            h ^= (tail[i] * P5) & MASK64
            h = (rol64(h, 11) * P1) & MASK64
            i += 1
        return _avalanche(h)


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


def verify(data):
    """Authenticate the binary and check every pinned byte of the packet."""
    authenticate(data)
    secs = unique_sections(data)
    if secs['.text']['address'] != 0x1419300 or secs['.rodata']['address'] != 0x430400:
        raise ValueError('unexpected section layout')
    extent = fde_extent(data, FUNCTION_START)
    if extent != (FUNCTION_START, FUNCTION_END):
        raise ValueError(f'FDE extent mismatch: {extent}')
    for name, site, value in PRIME_SITES:
        got = _movabs_immediate(data, secs, site)
        if got != value:
            raise ValueError(f'{name} immediate mismatch at {site:#x}: '
                             f'{got:#x} != {value:#x}')
    if _movabs_immediate(data, secs, P1P2_SITE) != P1_TIMES_P2:
        raise ValueError('P1*P2 constant mismatch at '
                         f'{P1P2_SITE:#x}')
    if P1_TIMES_P2 != (P1 * P2) & MASK64:
        raise ValueError('P1*P2 constant does not equal P1*P2 mod 2**64')
    # Published XXH64 vectors anchor the model and the reference.
    if xxh64_model(b'', 0) != 0xEF46DB3751D8E999:
        raise ValueError('XXH64 empty check value mismatch')
    if xxh64_model(b'a', 0) != 0xD24EC4F1A98C6E5B:
        raise ValueError('XXH64 single-byte check value mismatch')
    if xxh64_model(b'abc', 0) != 0x44BC2CF5AD770999:
        raise ValueError('XXH64 abc check value mismatch')
    if xxh64_reference(b'', 0) != 0xEF46DB3751D8E999:
        raise ValueError('XXH64 reference empty check value mismatch')
    if xxh64_reference(b'abc', 0) != 0x44BC2CF5AD770999:
        raise ValueError('XXH64 reference abc check value mismatch')
    if xxh64_null(0, 0) != 0xEF46DB3751D8E999:
        raise ValueError('null-input empty check value mismatch')
    checked = {
        'window_hashes': window_hashes(data, secs),
        'body_hash': body_hash(data, secs, FUNCTION_START, FUNCTION_END),
        'sections': secs,
    }
    if checked['body_hash'] != CENSUS_BODY:
        raise ValueError('body hash does not match the census')
    return checked


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic (seed, data) cases: boundary lengths, then random.

    Boundary lengths hit every stripe/tail boundary (0, 1..9, 15..17,
    24/25, 31/32/33, 39/40, 47/48, 55/56, 63/64/65, 71/72, 95/96,
    127/128/129, 256, 1024) under four seeds, then random lengths up
    to 1024 with random 64-bit seeds and patterned data mixed in.
    """
    rng = random.Random(seed)
    cases = []
    for length in BOUNDARY_LENGTHS:
        for s in BOUNDARY_SEEDS:
            data = bytes(rng.randrange(256) for _ in range(length))
            cases.append((s, data))
    for pattern in (b'\x00', b'\xab', b'\xff'):
        for length in (0, 1, 31, 32, 33, 63, 64, 65, 128, 1024):
            cases.append((0, pattern * length))
    for length in (0, 1, 31, 32, 33, 64, 65, 128, 1024):
        cases.append((0, bytes((i & 0xFF) for i in range(length))))
    while len(cases) < count:
        s = rng.getrandbits(64)
        length = rng.choice((rng.randrange(0, 33), rng.randrange(0, 129),
                             rng.randrange(0, 1025)))
        data = bytes(rng.randrange(256) for _ in range(length))
        cases.append((s, data))
    return cases[:count]


def run_cases(cases):
    """Run the model against the references; return rows."""
    rows = []
    for seed, data in cases:
        out = xxh64_model(data, seed)
        ref = xxh64_reference(data, seed)
        if out != ref:
            raise ValueError(
                f'model disagrees with the reference for seed {seed:#x}, '
                f'len {len(data)}')
        stream = XXH64Stream(seed)
        # Feed in two uneven chunks to exercise the buffering path.
        cut = len(data) // 2
        stream.update(data[:cut])
        stream.update(data[cut:])
        if stream.digest() != out:
            raise ValueError(
                f'model disagrees with streaming for seed {seed:#x}, '
                f'len {len(data)}')
        rows.append((seed, data, out))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for seed, data, out in rows:
        hasher.update(struct.pack('<Q', seed))
        hasher.update(struct.pack('<Q', len(data)))
        hasher.update(data)
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
        handle.write('idx\tseed\tdata_len\tdata_hex\tout\n')
        for idx, (seed, data_bytes, out) in enumerate(sample):
            handle.write(f"{idx}\t{seed:#018x}\t{len(data_bytes)}\t"
                         f"{data_bytes.hex()}\t{out:#018x}\n")

    long_data = bytes(0xAB for _ in range(1024))
    check_values = {
        'xxh64_empty': {
            'data_hex': '', 'seed': '0x0',
            'out': f"{xxh64_model(b'', 0):#018x}",
            'note': 'published XXH64 empty vector 0xef46db3751d8e999'},
        'xxh64_single_a': {
            'data_hex': b'a'.hex(), 'seed': '0x0',
            'out': f"{xxh64_model(b'a', 0):#018x}",
            'note': 'published XXH64 vector 0xd24ec4f1a98c6e5b'},
        'xxh64_abc': {
            'data_hex': b'abc'.hex(), 'seed': '0x0',
            'out': f"{xxh64_model(b'abc', 0):#018x}",
            'note': 'published XXH64 vector 0x44bc2cf5ad770999'},
        'xxh64_123456789': {
            'data_hex': b'123456789'.hex(), 'seed': '0x0',
            'out': f"{xxh64_model(b'123456789', 0):#018x}",
            'note': 'computed by model and reference (both agree)'},
        'xxh64_32_sequential': {
            'data': 'bytes 0..31', 'seed': '0x0',
            'out': f"{xxh64_model(bytes(range(32)), 0):#018x}",
            'note': 'one full stripe, no tail'},
        'xxh64_33_sequential': {
            'data': 'bytes 0..32', 'seed': '0x0',
            'out': f"{xxh64_model(bytes(range(33)), 0):#018x}",
            'note': 'one stripe plus a 1-byte tail'},
        'xxh64_64_sequential_seed1': {
            'data': 'bytes 0..63', 'seed': '0x1',
            'out': f"{xxh64_model(bytes(range(64)), 1):#018x}",
            'note': 'two stripes, nonzero seed'},
        'xxh64_1024_ab': {
            'data': '1024 bytes of 0xab', 'seed': '0x0',
            'out': f"{xxh64_model(long_data, 0):#018x}"},
        'xxh64_empty_seed1': {
            'data_hex': '', 'seed': '0x1',
            'out': f"{xxh64_model(b'', 1):#018x}",
            'note': 'empty input under a nonzero seed'},
        'xxh64_null_seed0_len9': {
            'data': 'null pointer, length 9', 'seed': '0x0',
            'out': f"{xxh64_null(0, 9):#018x}",
            'note': 'null branch: avalanche(seed + P5 + 9), no buffer load'},
    }
    result = {
        'target_digest': DIGEST,
        'function': {'start': f'{FUNCTION_START:#x}',
                     'end': f'{FUNCTION_END:#x}',
                     'body_sha256': checked['body_hash'],
                     'fde': [f'{FUNCTION_START:#x}', f'{FUNCTION_END:#x}'],
                     'census_id': CENSUS_ID,
                     'census_symbol': CENSUS_SYMBOL,
                     'census_body_sha256': CENSUS_BODY},
        'contract': 'xxh64(data: *const u8, n: usize, seed: u64) -> u64',
        'primes': {name: {'site': f'{site:#x}', 'value': f'{value:#018x}'}
                   for name, site, value in PRIME_SITES},
        'strength_reduction': {
            'site': f'{P1P2_SITE:#x}',
            'constant': f'{P1_TIMES_P2:#018x}',
            'formula': 'P1 * P2 mod 2**64; round(0, v) is computed as '
                       'rol(pre * P1*P2, 31) * P1 where pre is the stripe '
                       'loop pre-multiply lane value'},
        'null_branch': {
            'je_site': f'{NULL_BRANCH_JE:#x}',
            'avalanche_start': f'{AVALANCHE_START:#x}',
            'semantics': 'null data jumps to the avalanche with '
                         'h = seed + P5 + n; no buffer load'},
        'caller': {
            'function': 'rocksdb::ComputeBuiltinChecksum',
            'address': '0x616bca0',
            'call_site': f'{DISPATCHER_CALL_SITE:#x}',
            'note': 'the type-3 arm calls 0x61dae20 and keeps the low '
                    '32 bits (reconstructed in PR #5413)'},
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
             'identity': 'ROCKSDB_XXH64 (librocksdb-sys 0.11.0+8.1.1, '
                         'vendor census id node115-vendor-61dae20)',
             'contract': 'xxh64(data: *const u8, n: usize, seed: u64) -> u64',
             'semantics': 'public XXH64 one-shot: four seeded lanes, '
                          '32-byte stripes (round rol(acc + k*P2, 31) * P1), '
                          'mergeRounds, 8/4/1-byte tails, 64-bit avalanche'},
        ] + [
            {'kind': 'prime', 'prime': name, 'address': f'{site:#x}',
             'value': f'{value:#018x}',
             'observation': f'the {name} prime appears as a movabs '
                            f'immediate at {site:#x}'}
            for name, site, value in PRIME_SITES
        ] + [
            {'kind': 'strength_reduction',
             'address': f'{P1P2_SITE:#x}',
             'constant': f'{P1_TIMES_P2:#018x}',
             'observation': 'the merge multiplies the stripe loop '
                            'pre-multiply lane value by P1*P2 mod 2**64 '
                            'before rol-31/*P1, because pre * P1 * P2 == '
                            'v * P2; this computes round(0, v) without '
                            'recomputing v * P2'},
            {'kind': 'null_branch', 'address': f'{NULL_BRANCH_JE:#x}',
             'target': f'{AVALANCHE_START:#x}',
             'observation': 'je at 0x61dae3c jumps to the avalanche when '
                            'data is null; h = seed + P5 + n with no buffer '
                            'load, so a null pointer yields the seeded '
                            'empty-input avalanche even for nonzero n'},
            {'kind': 'merge', 'observation': 'h = rol(v1,1) + rol(v2,7) + '
             'rol(v3,12) + rol(v4,18), then one mergeRound per lane '
             '(h ^= round(0, v); h = h*P1 + P4); the + n term is folded '
             'into the last mergeRound as + P4 + n (add %rbp,%r8 at '
             '0x61daf8d); the short path (n < 32) instead starts from '
             'h = seed + P5 + n'},
            {'kind': 'caller', 'address': f'{DISPATCHER_CALL_SITE:#x}',
             'observation': 'the type-3 arm of '
                            'rocksdb::ComputeBuiltinChecksum (0x616bca0) '
                            'calls 0x61dae20 here and keeps the low 32 bits '
                            '(reconstructed in PR #5413)'},
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'aggregate_sha256': aggregate,
             'mismatches_vs_reference': 0,
             'note': 'model (disassembly transliteration) cross-checked '
                     'against an independent clean-room XXH64 and a '
                     'streaming state machine on every case; the binary '
                     'itself was never executed'},
            {'kind': 'unknown', 'subject': 'callers of 0x61dae20',
             'status': 'only the ComputeBuiltinChecksum type-3 call site '
                       'is recorded; no full caller census was run for '
                       'this packet'},
            {'kind': 'unknown', 'subject': 'streaming XXH64 API',
             'status': 'createState/reset/update/digest/freeState at '
                       '0x61db130..0x61db3e0 are separate functions, '
                       'modelled only as callees in PR #5399; they are not '
                       'reconstructed here'},
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
        print(f"verified: body {checked['body_hash'][:16]}...; "
              f"{len(rows)} cases agree with the references; "
              f"xxh64(b'', 0) = {xxh64_model(b'', 0):#018x}; "
              f"xxh64(b'abc', 0) = {xxh64_model(b'abc', 0):#018x}; "
              f"xxh64(b'123456789', 0) = "
              f"{xxh64_model(b'123456789', 0):#018x}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
