#!/usr/bin/env python3
"""Reconstruct the node #115 RocksDB ComputeBuiltinChecksumWithLastByte xxhash arm.

Bounded question (RE-002): what does the function at 0x616bd60 compute for
ChecksumType 2 (kxxHash), and which bytes in the node #115 binary pin that
behaviour?

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
  xxhash arm at 0x616bd96, modelled here; 3 -> the xxhash64 arm
  (reconstructed in PR #5399); 4 -> a multiply-xor arm
  (``ROCKSDB_XXH3_64bits(data, n)`` then ``imul $0x6b9083d9`` xor
  last byte); anything else (including 0, kNoChecksum) -> 0. Only the
  xxhash arm is modelled here; the type-4 arm is recorded as
  observed-but-not-modelled.
* xxhash arm (0x616bd96..0x616bde5): it runs the ROCKSDB_XXH32
  streaming API with seed 0 over the input and then the last byte:
  createState at 0x61daa60 (``malloc(0x30)``), reset at 0x61daa90,
  update at 0x61daac0 called twice (first ``(data, n)``, then
  ``(&last_byte, 1)``), digest at 0x61dacf0, freeState at 0x61daa70
  (``free`` wrapper). The digest result is 32-bit and the arm returns
  it directly (``mov %eax,%ebx`` at 0x616bdd3).
* The reset (0x61daa90) zeroes the 0x30-byte state and initialises the
  four accumulators from the seed with one vector add: the 16-byte
  constant at 0x451ae0 is ``[P1+P2, P2, 0, -P1]`` (0x24234428,
  0x85ebca77, 0x00000000, 0x61c8864f), broadcast-added to the seed, so
  v1 = seed + PRIME32_1 + PRIME32_2, v2 = seed + PRIME32_2, v3 = seed,
  v4 = seed - PRIME32_1. Observed state offsets: total_len +0x0
  (u64; its high dword at +0x4 carries the sticky large_len flag),
  v1 +0x8, v2 +0xc, v3 +0x10, v4 +0x14, mem +0x18 (16 bytes),
  memsize +0x28. No separate seed field is stored: the digest reads
  v3 (+0x10) where the public algorithm reads the seed, and
  v3 == seed by construction.
* The update (0x61daac0) processes 16-byte stripes with the XXH32
  round (``imul $0x85ebca77`` = *P2, ``add`` the accumulator,
  ``rol $0xd``, ``imul $0x9e3779b1`` = *P1), with a vectorised
  (SSE) round for a buffered stripe and a memcpy tail for the
  remaining bytes. The large_len flag is set (``or`` into +0x4)
  whenever the input chunk or the new total_len exceeds 15.
* The digest (0x61dacf0) matches the public XXH32 algorithm exactly:
  for total_len >= 16 it computes the accumulator convergence
  (``rol`` v1 by 1, v2 by 7, v3 by 12, v4 by 18, plus total_len)
  and then the remainder handling. Per the upstream xxHash spec
  (v0.2.0, "XXH32 Algorithm Description", Step 3), XXH32
  convergence is exactly that rotate-sum -- the
  ``mergeAccumulator`` rounds (``h ^= round(0, v); h = h * P1 + P4``)
  belong to XXH64 only ("accumulator convergence is more complex
  than 32-bit variant" for XXH64). The remainder handling and
  avalanche also match the public algorithm: 4-byte chunks
  (``*P3``, ``rol`` 17, ``*P4``), single bytes (``*P5``, ``rol`` 11,
  ``*P1``), then the avalanche (``shr`` 15, ``*P2``, ``shr`` 13,
  ``*P3``, ``shr`` 16). For total_len < 16 the digest is
  ``h = seed + P5 + total_len``, as specified. The public check
  vectors XXH32(b"", 0) = 0x02cc5d05, XXH32(b"a", 0) = 0x550d7456
  and XXH32(b"abc", 0) = 0x32d153ff anchor the model, and the
  16-byte input 0x0123456789abcdef gives 0xc2c45b69 under the spec
  steps.
* So the arm computes ``XXH32(data || last_byte, seed 0)``.

CORRECTION NOTE: the first submitted revision of this packet
claimed the digest deviates from public XXH32 by omitting merge
rounds. Slopbot flagged that claim as mistaken (low_quality,
uncertain), and re-checking the upstream xxHash spec confirmed it
was wrong: XXH32 has no merge rounds. The claim, the separate
"public" reference implementation that encoded it, and the tests
that encoded it were removed in the correction; the streaming
model itself was already standard XXH32 and is unchanged.

The Python model below implements standard XXH32 twice
independently -- once as a streaming state machine mirroring the
binary's create/reset/update/digest call sequence, once as the
one-shot reference -- and cross-checks them on 2400 deterministic
cases. The node binary is never executed.
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
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-xxh32-last-byte-115'
FUNCTION_START = 0x616BD60
FUNCTION_END = 0x616BEAC
XXH32_ARM_START = 0x616BD96
XXH32_ARM_END = 0x616BDE5
CREATE_START = 0x61DAA60
CREATE_END = 0x61DAA6E
FREE_START = 0x61DAA70
FREE_END = 0x61DAA84
RESET_START = 0x61DAA90
RESET_END = 0x61DAABB
UPDATE_START = 0x61DAAC0
UPDATE_END = 0x61DACE6
DIGEST_START = 0x61DACF0
DIGEST_END = 0x61DAE18
STATE_BYTES = 0x30
CASE_COUNT = 2400
CASE_SEED = 20261109

MASK32 = 0xFFFFFFFF
P1 = 0x9E3779B1
P2 = 0x85EBCA77
P3 = 0xC2B2AE3D
P4 = 0x27D4EB2F
P5 = 0x165667B1
PRIMES = {'PRIME32_1': P1, 'PRIME32_2': P2, 'PRIME32_3': P3,
          'PRIME32_4': P4, 'PRIME32_5': P5}

# Census body hash for the function this packet binds to. The five
# callees have no census record (checked: no 0x61daa60..0x61dacf0 entry
# in research/work-items/RE-002-node115-vendor-census/census.json).
CENSUS_BODY = {
    'function': '5680596a85a5810082875d361be174363d5b2b435a5c2494bc72543840138972',
}

# Pinned body hashes for the callees, computed from the pinned binary
# (FDE extents above); no census record exists for any of them.
CREATE_BODY = '308f2076440391812825325f24d327c32527672b15d8a9a730fe94232d429aa8'
FREE_BODY = '630a5e3c790921ea2ebb0214f1d6b96e1a494793443717c8c12c9c26fa551770'
RESET_BODY = '621561804b9507796c857c877e6915fd5dd213c6181a6115532ab4b3147351a4'
UPDATE_BODY = 'c9368927c229a3d3840e5fa5489e6b1aba1d178d81cb43d03d7119aacd49eae2'
DIGEST_BODY = 'f4ced493734fa7a8319db45be0a35b23343a679d37fbbf8bc5cc125b5b6353c5'

# (label, start, end) of the byte-checked instruction windows.
WINDOWS = (
    ('entry_dispatch', 0x616BD60, 0x616BD96),
    ('xxhash_arm', 0x616BD96, 0x616BDE5),
    ('xxh32_create', 0x61DAA60, 0x61DAA6E),
    ('xxh32_free', 0x61DAA70, 0x61DAA84),
    ('xxh32_reset', 0x61DAA90, 0x61DAABB),
    ('xxh32_update', 0x61DAAC0, 0x61DACE6),
    ('xxh32_digest', 0x61DACF0, 0x61DAE18),
)

# The dispatch table as observed in the disassembly. Only type 2 is
# modelled; the other arms are observations, not claims about the
# hash functions they call.
DISPATCH = (
    (0, 'default_arm', 'returns 0 (kNoChecksum and any other type)'),
    (1, 'crc32c_arm', 'mask(extend(extend(0, data), last_byte)); '
                      'reconstructed in PR #5396'),
    (2, 'xxhash_arm', 'XXH32(data || last_byte, seed 0); '
                      'modelled here'),
    (3, 'xxhash64_arm', '(u32) XXH64(data || last_byte, seed 0); '
                        'reconstructed in PR #5399'),
    (4, 'mulmix_arm', 'ROCKSDB_XXH3_64bits(data, n) then '
                      'imul $0x6b9083d9 ^ last_byte; not modelled'),
)

BOUNDARY_LENGTHS = (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33,
                    63, 64, 65, 127, 128, 256, 1024)


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


def rol32(value, count):
    return ((value << count) | (value >> (32 - count))) & MASK32


def xxh32_round(acc, lane):
    acc = (acc + lane * P2) & MASK32
    acc = rol32(acc, 13)
    return (acc * P1) & MASK32


def _u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def _avalanche(h):
    h ^= h >> 15
    h = (h * P2) & MASK32
    h ^= h >> 13
    h = (h * P3) & MASK32
    h ^= h >> 16
    return h


def _tail(h, tail):
    """Remainder handling (spec Step 5)."""
    i = 0
    while i + 4 <= len(tail):
        h = (h + _u32(tail, i) * P3) & MASK32
        h = rol32(h, 17)
        h = (h * P4) & MASK32
        i += 4
    while i < len(tail):
        h = (h + tail[i] * P5) & MASK32
        h = rol32(h, 11)
        h = (h * P1) & MASK32
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
        v1 = (seed + P1 + P2) & MASK32
        v2 = (seed + P2) & MASK32
        v3 = seed & MASK32
        v4 = (seed - P1) & MASK32
        while i + 16 <= n:
            v1 = xxh32_round(v1, _u32(data, i))
            v2 = xxh32_round(v2, _u32(data, i + 4))
            v3 = xxh32_round(v3, _u32(data, i + 8))
            v4 = xxh32_round(v4, _u32(data, i + 12))
            i += 16
        h = (rol32(v1, 1) + rol32(v2, 7) + rol32(v3, 12)
             + rol32(v4, 18)) & MASK32
    else:
        h = (seed + P5) & MASK32
    h = (h + n) & MASK32
    h = _tail(h, data[i:])
    return _avalanche(h)


class XXH32State:
    """XXH32 streaming state, mirroring the binary's create/reset/update.

    Layout observed in the binary: total_len +0x0 (u64, high dword
    carries the sticky large_len flag), v1 +0x8, v2 +0xc, v3 +0x10,
    v4 +0x14, mem +0x18 (16 bytes), memsize +0x28, 0x30 bytes total.
    The reset stores v3 = seed, so the digest can read the seed from v3.
    """

    def __init__(self, seed=0):
        self.reset(seed)

    def reset(self, seed):
        self.seed = seed
        self.total_len = 0
        self.large_len = False
        self.v1 = (seed + P1 + P2) & MASK32
        self.v2 = (seed + P2) & MASK32
        self.v3 = seed & MASK32
        self.v4 = (seed - P1) & MASK32
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
            h = (self.seed + P5) & MASK32
        h = (h + (self.total_len & MASK32)) & MASK32
        h = _tail(h, bytes(self.mem[:self.memsize]))
        return _avalanche(h)


def checksum_xxh32_arm(data, last_byte):
    """The type-2 arm, via the streaming API exactly as the binary does.

    createState, reset(seed 0), update(data, n), update(&last_byte, 1),
    digest, freeState; the 32-bit digest is the result.
    """
    state = XXH32State(0)
    state.update(data)
    state.update(bytes((last_byte,)))
    return state.digest()


def checksum_xxh32_arm_reference(data, last_byte):
    """Same arm, computed with the independent one-shot reference."""
    return xxh32_oneshot(data + bytes((last_byte,)), 0)


def prime_sites(data, secs):
    """Occurrences of each XXH32 prime as a 32-bit immediate in update+digest."""
    out = {}
    for name, prime in PRIMES.items():
        needle = struct.pack('<I', prime)
        sites = []
        for label, start, end in (('update', UPDATE_START, UPDATE_END),
                                  ('digest', DIGEST_START, DIGEST_END)):
            off = file_offset(secs, start, end - start)
            blob = data[off:off + (end - start)]
            pos = 0
            while True:
                idx = blob.find(needle, pos)
                if idx < 0:
                    break
                sites.append(f'{start + idx:#x}')
                pos = idx + 1
        out[name] = sites
    return out


def body_hash(data, secs, start, end):
    off = file_offset(secs, start, end - start)
    return hashlib.sha256(data[off:off + (end - start)]).hexdigest()


def window_hashes(data, secs):
    out = {}
    for label, start, end in WINDOWS:
        out[label] = body_hash(data, secs, start, end)
    return out


def fde_extent(data):
    """Return the .eh_frame extent covering the function, or None."""
    _, fdes = eh_frame_records(data)
    for rec in fdes:
        if rec['start'] == FUNCTION_START:
            return rec['start'], rec['end']
    return None


def verify(data):
    """Authenticate the binary and check every pinned byte of the packet."""
    authenticate(data)
    secs = unique_sections(data)
    if secs['.text']['address'] != 0x1419300 or secs['.rodata']['address'] != 0x430400:
        raise ValueError('unexpected section layout')
    extent = fde_extent(data)
    if extent != (FUNCTION_START, FUNCTION_END):
        raise ValueError(f'FDE extent mismatch: {extent}')
    hashes = {
        'function': body_hash(data, secs, FUNCTION_START, FUNCTION_END),
        'reset': body_hash(data, secs, RESET_START, RESET_END),
        'update': body_hash(data, secs, UPDATE_START, UPDATE_END),
        'digest': body_hash(data, secs, DIGEST_START, DIGEST_END),
        'create': body_hash(data, secs, CREATE_START, CREATE_END),
        'free': body_hash(data, secs, FREE_START, FREE_END),
    }
    for key, expect in CENSUS_BODY.items():
        if hashes[key] != expect:
            raise ValueError(f'{key} body hash mismatch vs census: {hashes[key]}')
    for key, expect in (('create', CREATE_BODY), ('free', FREE_BODY),
                        ('reset', RESET_BODY), ('update', UPDATE_BODY),
                        ('digest', DIGEST_BODY)):
        if hashes[key] != expect:
            raise ValueError(f'{key} body hash mismatch: {hashes[key]}')
    sites = prime_sites(data, secs)
    for name, found in sites.items():
        if not found:
            raise ValueError(f'{name} not found as an immediate in update/digest')
    # Public check vectors anchor both implementations, including a
    # 16-byte input (convergence is the spec's rotate-sum only).
    for payload, expect in ((b'', 0x02CC5D05), (b'a', 0x550D7456),
                            (b'abc', 0x32D153FF),
                            (b'0123456789abcdef', 0xC2C45B69)):
        if xxh32_oneshot(payload, 0) != expect:
            raise ValueError('one-shot check vector mismatch')
    state = XXH32State(0)
    if state.digest() != 0x02CC5D05:
        raise ValueError('streaming check vector mismatch')
    state.update(b'a')
    if state.digest() != 0x550D7456:
        raise ValueError('streaming check vector mismatch')
    state = XXH32State(0)
    state.update(b'0123456789abcdef')
    if state.digest() != 0xC2C45B69:
        raise ValueError('streaming 16-byte check value mismatch')
    return {'body_hashes': hashes, 'window_hashes': window_hashes(data, secs),
            'prime_sites': sites, 'sections': secs}


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic (data, last_byte) cases: boundary lengths, then random."""
    rng = random.Random(seed)
    cases = []
    for length in BOUNDARY_LENGTHS:
        cases.append((bytes(rng.randrange(256) for _ in range(length)),
                      rng.randrange(256)))
    while len(cases) < count:
        length = rng.choice([rng.randrange(0, 64), rng.randrange(0, 1024),
                             rng.randrange(0, 8192)])
        cases.append((bytes(rng.randrange(256) for _ in range(length)),
                      rng.randrange(256)))
    return cases[:count]


def run_cases(cases):
    """Run the streaming model against the one-shot XXH32 reference."""
    rows = []
    for payload, last_byte in cases:
        out = checksum_xxh32_arm(payload, last_byte)
        ref = checksum_xxh32_arm_reference(payload, last_byte)
        if out != ref:
            raise ValueError('streaming model disagrees with the one-shot reference')
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
                                                 len(BOUNDARY_LENGTHS) + 41]
    with (dest / 'cases.tsv').open('w', encoding='utf-8') as handle:
        handle.write('idx\tlen\tdata_sha256\tlast_byte\tarm_out\n')
        for idx, (case_data, last_byte, out) in enumerate(sample):
            handle.write(f"{idx}\t{len(case_data)}"
                         f"\t{hashlib.sha256(case_data).hexdigest()}"
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
        'xxhash_arm': {
            'start': f'{XXH32_ARM_START:#x}', 'end': f'{XXH32_ARM_END:#x}',
            'callees': {
                'createState': [f'{CREATE_START:#x}', f'{CREATE_END:#x}'],
                'reset': [f'{RESET_START:#x}', f'{RESET_END:#x}'],
                'update': [f'{UPDATE_START:#x}', f'{UPDATE_END:#x}'],
                'digest': [f'{DIGEST_START:#x}', f'{DIGEST_END:#x}'],
                'freeState': [f'{FREE_START:#x}', f'{FREE_END:#x}'],
            },
            'callee_body_sha256': {
                'create': checked['body_hashes']['create'],
                'free': checked['body_hashes']['free'],
                'reset': checked['body_hashes']['reset'],
                'update': checked['body_hashes']['update'],
                'digest': checked['body_hashes']['digest'],
            },
            'state_bytes': STATE_BYTES,
            'seed': 0,
            'semantics': 'XXH32(data || last_byte, seed 0)',
        },
        'primes': {name: f'{value:#010x}'
                   for name, value in PRIMES.items()},
        'prime_sites': checked['prime_sites'],
        'check_value': {
            'xxh32_empty_seed0': f"{xxh32_oneshot(b'', 0):#010x}",
            'expected_xxh32_empty_seed0': '0x02cc5d05',
            'xxh32_a_seed0': f"{xxh32_oneshot(b'a', 0):#010x}",
            'expected_xxh32_a_seed0': '0x550d7456',
            'xxh32_16byte_seed0': f"{xxh32_oneshot(b'0123456789abcdef', 0):#010x}",
            'expected_xxh32_16byte_seed0': '0xc2c45b69',
            'arm_empty_0x00': f"{checksum_xxh32_arm(b'', 0):#010x}",
            'arm_123456789_0x00': f"{checksum_xxh32_arm(b'123456789', 0):#010x}",
            'arm_empty_0x61': f"{checksum_xxh32_arm(b'', 0x61):#010x}",
            'arm_16byte_0x00': f"{checksum_xxh32_arm(b'0123456789abcdef', 0):#010x}",
        },
        'cases': {'count': len(rows), 'seed': CASE_SEED,
                  'mismatches_vs_oneshot': 0, 'aggregate_sha256': aggregate},
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
             'semantics': 'dispatches on type; type 2 (kxxHash) returns '
                          'XXH32(data || last_byte, seed 0); any other type '
                          'returns 0 except types 1, 3, 4, which take their '
                          'own hash arms'},
        ] + [
            {'kind': 'dispatch', 'type': t, 'arm': arm, 'note': note}
            for t, arm, note in DISPATCH
        ] + [
            {'kind': 'arm', 'type': 2, 'start': f'{XXH32_ARM_START:#x}',
             'end': f'{XXH32_ARM_END:#x}',
             'semantics': 'XXH32(data || last_byte, seed 0)',
             'observation': 'createState (malloc 0x30) at 0x61daa60, reset '
                            '(seed 0) at 0x61daa90, update at 0x61daac0 called '
                            'twice ((data, n), then (&last_byte, 1)), digest '
                            'at 0x61dacf0, freeState at 0x61daa70; the digest '
                            'is 32-bit and the arm returns it directly '
                            '(mov %eax,%ebx at 0x616bdd3)'},
            {'kind': 'callee', 'name': 'ROCKSDB_XXH32_reset',
             'start': f'{RESET_START:#x}', 'end': f'{RESET_END:#x}',
             'body_sha256': checked['body_hashes']['reset'],
             'observation': 'zeroes the 0x30-byte state, total_len = 0, '
                            'v1 = seed + PRIME32_1 + PRIME32_2, '
                            'v2 = seed + PRIME32_2, v3 = seed, '
                            'v4 = seed - PRIME32_1 (seed vector '
                            '[P1+P2, P2, 0, -P1] at 0x451ae0)'},
            {'kind': 'callee', 'name': 'ROCKSDB_XXH32_update',
             'start': f'{UPDATE_START:#x}', 'end': f'{UPDATE_END:#x}',
             'body_sha256': checked['body_hashes']['update'],
             'observation': 'streaming update; 16-byte stripes with the '
                            'XXH32 round (imul $0x85ebca77, rol $0xd, '
                            'imul $0x9e3779b1), vectorised round for a '
                            'buffered stripe, memcpy tail; sets the '
                            'large_len flag in the high dword of total_len'},
            {'kind': 'callee', 'name': 'ROCKSDB_XXH32_digest',
             'start': f'{DIGEST_START:#x}', 'end': f'{DIGEST_END:#x}',
             'body_sha256': checked['body_hashes']['digest'],
             'observation': 'accumulator convergence is the public '
                            'rotate-sum (rol 1/7/12/18, plus total_len), '
                            'then the remainder handling: 4-byte chunks '
                            '(rol 17, *P4), single bytes (*P5, rol 11, *P1), '
                            'then the avalanche (shr 15, *P2, shr 13, *P3, '
                            'shr 16); all five primes appear as 32-bit '
                            'immediates. (Correction: an earlier revision '
                            'claimed merge rounds were omitted; per the '
                            'upstream xxHash spec v0.2.0, XXH32 convergence '
                            'is the rotate-sum only -- mergeAccumulator '
                            'rounds belong to XXH64.)'},
            {'kind': 'callee', 'name': 'XXH32_createState',
             'start': f'{CREATE_START:#x}', 'end': f'{CREATE_END:#x}',
             'body_sha256': checked['body_hashes']['create'],
             'observation': 'malloc(0x30); no census record'},
            {'kind': 'callee', 'name': 'XXH32_freeState',
             'start': f'{FREE_START:#x}', 'end': f'{FREE_END:#x}',
             'body_sha256': checked['body_hashes']['free'],
             'observation': 'free wrapper returning 0; no census record'},
        ] + [
            {'kind': 'prime', 'name': name, 'value': f'{value:#010x}',
             'sites': checked['prime_sites'][name]}
            for name, value in PRIMES.items()
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'aggregate_sha256': aggregate, 'mismatches_vs_oneshot': 0,
             'note': 'streaming model cross-checked against an independent '
                     'one-shot XXH32 reference on every case; the binary '
                     'itself was never executed'},
            {'kind': 'unknown', 'subject': 'callers of 0x616bd60',
             'status': 'no caller census was run for this packet'},
            {'kind': 'unknown', 'subject': 'semantics of the type 4 arm',
             'status': 'type 4 calls ROCKSDB_XXH3_64bits at 0x61db650 then '
                       'imul $0x6b9083d9; not reconstructed here'},
            {'kind': 'unknown', 'subject': 'XXH32 state buffer start offset',
             'status': 'mem is at +0x18 and memsize at +0x28; the update '
                       'also touches a second buffer region via the SSE '
                       'path, which was not pinned'},
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
        print(f"verified: body {checked['body_hashes']['function'][:16]}...; "
              f"{len(rows)} cases agree with the one-shot reference; "
              f"arm(b'123456789', 0x00) = "
              f"{checksum_xxh32_arm(b'123456789', 0):#010x}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
