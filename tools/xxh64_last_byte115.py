#!/usr/bin/env python3
"""Reconstruct the node #115 RocksDB ComputeBuiltinChecksumWithLastByte xxhash64 arm.

Bounded question (RE-002): what does the function at 0x616bd60 compute for
ChecksumType 3 (kxxHash64), and which bytes in the node #115 binary pin that
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
  0x616bde8): 1 -> CRC32C arm (reconstructed in PR #5396); 2 -> an xxhash
  arm calling into 0x61daa60..0x61dacf0; 3 -> the xxhash64 arm at
  0x616be28, modelled here; 4 -> a multiply-xor arm (imul $0x6b9083d9 at
  0x616be02, callee ROCKSDB_XXH3_64bits at 0x61db650); anything else
  (including 0, kNoChecksum) -> 0. Only the xxhash64 arm is modelled
  here; the type-2 and type-4 arms are recorded as observed-but-not-modelled.
* xxhash64 arm (0x616be28..0x616be80): it runs the ROCKSDB_XXH64
  streaming API with seed 0 over the input and then the last byte:
  createState at 0x61db130 (``malloc(0x58)``), reset at 0x61db160,
  update at 0x61db1d0 called twice (first ``(data, n)``, then
  ``(&last_byte, 1)``), digest at 0x61db3e0, freeState at 0x61db140
  (``free`` wrapper). The digest result is 64-bit; the arm keeps only
  its low 32 bits (``mov %eax,%ebx`` at 0x616be65).
* The reset (0x61db160) zeroes the 0x58-byte state, sets total_len to 0,
  and initialises the four accumulators from the seed: v1 = seed +
  PRIME64_1 + PRIME64_2 (the sum 0x60ea27eeadc0b5d6 is the immediate at
  0x61db193), v2 = seed + PRIME64_2, v3 = seed, v4 = seed - PRIME64_1
  (the two's complement 0x61c8864e7a143579 is the immediate at
  0x61db1b5). Observed state offsets: total_len +0x0, v1 +0x8, v2
  +0x10, v3 +0x18, v4 +0x20, memsize +0x28 (the update touches the
  buffer at +0x40/+0x48). No separate seed field is stored: the digest
  reads v3 (+0x18) where the public algorithm reads the seed, and
  v3 == seed by construction.
* The update (0x61db1d0) and digest (0x61db3e0) carry all five XXH64
  primes as 64-bit immediates (PRIME64_1 0x9e3779b185ebca87,
  PRIME64_2 0xc2b2ae3d27d4eb4f, PRIME64_3 0x165667b19e3779f9,
  PRIME64_4 0x85ebca77c2b2ae63, PRIME64_5 0x27d4eb2f165667c5), and the
  digest shows the public finalisation shape: merge prologue
  (rol v1 by 1, v2 by 7, v3 by 12, v4 by 18), merge rounds, 8-byte
  chunks (rol 27, *P1, +P4), a 4-byte chunk (rol 23, *P2, +P3),
  single bytes (*P5, rol 11, *P1), then the avalanche (shr 33, *P2,
  shr 29, *P3, shr 32).
* So the arm computes ``(u32) XXH64(data || last_byte, seed 0)``.

The Python model below implements XXH64 twice independently -- once as a
streaming state machine mirroring the binary's create/reset/update/digest
call sequence, once as the one-shot reference -- and cross-checks them
on 2400 deterministic cases. The node binary is never executed.
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
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-xxh64-last-byte-115'
FUNCTION_START = 0x616BD60
FUNCTION_END = 0x616BEAC
XXH64_ARM_START = 0x616BE28
XXH64_ARM_END = 0x616BE80
CREATE_START = 0x61DB130
CREATE_END = 0x61DB13E
FREE_START = 0x61DB140
FREE_END = 0x61DB154
RESET_START = 0x61DB160
RESET_END = 0x61DB1C9
UPDATE_START = 0x61DB1D0
UPDATE_END = 0x61DB3DE
DIGEST_START = 0x61DB3E0
DIGEST_END = 0x61DB649
STATE_BYTES = 0x58
CASE_COUNT = 2400
CASE_SEED = 20261109

MASK64 = 0xFFFFFFFFFFFFFFFF
P1 = 0x9E3779B185EBCA87
P2 = 0xC2B2AE3D27D4EB4F
P3 = 0x165667B19E3779F9
P4 = 0x85EBCA77C2B2AE63
P5 = 0x27D4EB2F165667C5
PRIMES = {'PRIME64_1': P1, 'PRIME64_2': P2, 'PRIME64_3': P3,
          'PRIME64_4': P4, 'PRIME64_5': P5}

# Census body hashes for the functions this packet binds to.
CENSUS_BODY = {
    'function': '5680596a85a5810082875d361be174363d5b2b435a5c2494bc72543840138972',
    'reset': '55640a2f386af102afa902c1695c2c609cab93621b3eeac7e6871a0108232025',
    'update': 'bde58491e6f3fa0a1febf1f0635c2d6b49399cf2d9c6ada9c7fc2a458cbc8de5',
    'digest': 'bab7d213c94b5599f51e62102067dbed9cf676a9223a3a3f51ed949426a9edb4',
}

# Pinned body hashes for the two tiny callees below the census minimum
# size (no census record exists for either).
CREATE_BODY = 'b0d76579e9e2feb60c2263ceaff242d69aa681f6deccb834d1ea89bcfc9b83d5'
FREE_BODY = '7d72966cb6b17f2fc99570c89cb360c349dcb13ee4d2d197dddd4b53ff1b160f'

# (label, start, end) of the byte-checked instruction windows.
WINDOWS = (
    ('entry_dispatch', 0x616BD60, 0x616BD96),
    ('xxhash64_arm', 0x616BE28, 0x616BE80),
    ('xxh64_create', 0x61DB130, 0x61DB13E),
    ('xxh64_free', 0x61DB140, 0x61DB154),
    ('xxh64_reset', 0x61DB160, 0x61DB1C9),
    ('xxh64_update', 0x61DB1D0, 0x61DB3DE),
    ('xxh64_digest', 0x61DB3E0, 0x61DB649),
)

# The dispatch table as observed in the disassembly. Only type 3 is
# modelled; the other arms are observations, not claims about the
# hash functions they call.
DISPATCH = (
    (0, 'default_arm', 'returns 0 (kNoChecksum and any other type)'),
    (1, 'crc32c_arm', 'mask(extend(extend(0, data), last_byte)); '
                      'reconstructed in PR #5396'),
    (2, 'xxhash_arm', 'calls into 0x61daa60..0x61dacf0; not modelled'),
    (3, 'xxhash64_arm', '(u32) XXH64(data || last_byte, seed 0); '
                        'modelled here'),
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


def rol64(value, count):
    return ((value << count) | (value >> (64 - count))) & MASK64


def xxh64_round(acc, lane):
    acc = (acc + lane * P2) & MASK64
    acc = rol64(acc, 31)
    return (acc * P1) & MASK64


def xxh64_merge(acc, val):
    val = xxh64_round(0, val)
    acc ^= val
    return (acc * P1 + P4) & MASK64


def _u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]


def _u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def xxh64_oneshot(data, seed=0):
    """XXH64, one-shot reference implementation of the public algorithm."""
    n = len(data)
    i = 0
    if n >= 32:
        v1 = (seed + P1 + P2) & MASK64
        v2 = (seed + P2) & MASK64
        v3 = seed & MASK64
        v4 = (seed - P1) & MASK64
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
        h = (seed + P5) & MASK64
    h = (h + n) & MASK64
    while i + 8 <= n:
        k = xxh64_round(0, _u64(data, i))
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
    h ^= h >> 33
    h = (h * P2) & MASK64
    h ^= h >> 29
    h = (h * P3) & MASK64
    h ^= h >> 32
    return h


class XXH64State:
    """XXH64 streaming state, mirroring the binary's create/reset/update.

    Layout observed in the binary: total_len +0x0, v1 +0x8, v2 +0x10,
    v3 +0x18, v4 +0x20, memsize +0x28, 0x58 bytes total. The reset
    stores v3 = seed, so the digest can read the seed from v3.
    """

    def __init__(self, seed=0):
        self.reset(seed)

    def reset(self, seed):
        self.seed = seed
        self.total_len = 0
        self.v1 = (seed + P1 + P2) & MASK64
        self.v2 = (seed + P2) & MASK64
        self.v3 = seed & MASK64
        self.v4 = (seed - P1) & MASK64
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
            h = (self.seed + P5) & MASK64
        h = (h + self.total_len) & MASK64
        tail = bytes(self.mem[:self.memsize])
        i = 0
        while i + 8 <= len(tail):
            k = xxh64_round(0, _u64(tail, i))
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
        h ^= h >> 33
        h = (h * P2) & MASK64
        h ^= h >> 29
        h = (h * P3) & MASK64
        h ^= h >> 32
        return h


def checksum_xxh64_arm(data, last_byte):
    """The type-3 arm, via the streaming API exactly as the binary does.

    createState, reset(seed 0), update(data, n), update(&last_byte, 1),
    digest, freeState; the 64-bit digest is truncated to its low 32 bits.
    """
    state = XXH64State(0)
    state.update(data)
    state.update(bytes((last_byte,)))
    return state.digest() & 0xFFFFFFFF


def checksum_xxh64_arm_reference(data, last_byte):
    """Same arm, computed with the independent one-shot reference."""
    return xxh64_oneshot(data + bytes((last_byte,)), 0) & 0xFFFFFFFF


def prime_sites(data, secs):
    """Occurrences of each XXH64 prime as a 64-bit immediate in update+digest."""
    out = {}
    for name, prime in PRIMES.items():
        needle = struct.pack('<Q', prime)
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
    if hashes['create'] != CREATE_BODY:
        raise ValueError(f"createState body hash mismatch: {hashes['create']}")
    if hashes['free'] != FREE_BODY:
        raise ValueError(f"freeState body hash mismatch: {hashes['free']}")
    sites = prime_sites(data, secs)
    for name, found in sites.items():
        if not found:
            raise ValueError(f'{name} not found as an immediate in update/digest')
    if xxh64_oneshot(b'', 0) != 0xEF46DB3751D8E999:
        raise ValueError('one-shot check vector mismatch')
    if XXH64State(0).digest() != 0xEF46DB3751D8E999:
        raise ValueError('streaming check vector mismatch')
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
    """Run the streaming model against the one-shot reference."""
    rows = []
    for data, last_byte in cases:
        out = checksum_xxh64_arm(data, last_byte)
        ref = checksum_xxh64_arm_reference(data, last_byte)
        if out != ref:
            raise ValueError('streaming model disagrees with the one-shot reference')
        rows.append((data, last_byte, out))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for data, last_byte, out in rows:
        hasher.update(hashlib.sha256(data).digest())
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
        'xxhash64_arm': {
            'start': f'{XXH64_ARM_START:#x}', 'end': f'{XXH64_ARM_END:#x}',
            'callees': {
                'createState': [f'{CREATE_START:#x}', f'{CREATE_END:#x}'],
                'reset': [f'{RESET_START:#x}', f'{RESET_END:#x}'],
                'update': [f'{UPDATE_START:#x}', f'{UPDATE_END:#x}'],
                'digest': [f'{DIGEST_START:#x}', f'{DIGEST_END:#x}'],
                'freeState': [f'{FREE_START:#x}', f'{FREE_END:#x}'],
            },
            'callee_body_sha256': {
                'reset': checked['body_hashes']['reset'],
                'update': checked['body_hashes']['update'],
                'digest': checked['body_hashes']['digest'],
            },
            'state_bytes': STATE_BYTES,
            'seed': 0,
            'semantics': '(u32) XXH64(data || last_byte, seed 0)',
        },
        'primes': {name: f'{value:#018x}'
                   for name, value in PRIMES.items()},
        'prime_sites': checked['prime_sites'],
        'check_value': {
            'xxh64_empty_seed0': f"{xxh64_oneshot(b'', 0):#018x}",
            'expected_xxh64_empty_seed0': '0xef46db3751d8e999',
            'arm_empty_0x00': f"{checksum_xxh64_arm(b'', 0):#010x}",
            'arm_123456789_0x00': f"{checksum_xxh64_arm(b'123456789', 0):#010x}",
            'arm_empty_0x61': f"{checksum_xxh64_arm(b'', 0x61):#010x}",
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
             'semantics': 'dispatches on type; type 3 (kxxHash64) returns '
                          '(u32) XXH64(data || last_byte, seed 0); any other '
                          'type returns 0 except types 1, 2, 4, which take '
                          'their own hash arms'},
        ] + [
            {'kind': 'dispatch', 'type': t, 'arm': arm, 'note': note}
            for t, arm, note in DISPATCH
        ] + [
            {'kind': 'arm', 'type': 3, 'start': f'{XXH64_ARM_START:#x}',
             'end': f'{XXH64_ARM_END:#x}',
             'semantics': '(u32) XXH64(data || last_byte, seed 0)',
             'observation': 'createState (malloc 0x58) at 0x61db130, reset '
                            '(seed 0) at 0x61db160, update at 0x61db1d0 called '
                            'twice ((data, n), then (&last_byte, 1)), digest '
                            'at 0x61db3e0, freeState at 0x61db140; the digest '
                            'is 64-bit and the arm keeps its low 32 bits '
                            '(mov %eax,%ebx at 0x616be65)'},
            {'kind': 'callee', 'name': 'ROCKSDB_XXH64_reset',
             'start': f'{RESET_START:#x}', 'end': f'{RESET_END:#x}',
             'body_sha256': checked['body_hashes']['reset'],
             'census_body_sha256': CENSUS_BODY['reset'],
             'observation': 'zeroes the 0x58-byte state, total_len = 0, '
                            'v1 = seed + PRIME64_1 + PRIME64_2, '
                            'v2 = seed + PRIME64_2, v3 = seed, '
                            'v4 = seed - PRIME64_1'},
            {'kind': 'callee', 'name': 'ROCKSDB_XXH64_update',
             'start': f'{UPDATE_START:#x}', 'end': f'{UPDATE_END:#x}',
             'body_sha256': checked['body_hashes']['update'],
             'census_body_sha256': CENSUS_BODY['update'],
             'observation': 'streaming update; PRIME64_1 and PRIME64_2 '
                            'appear as 64-bit immediates'},
            {'kind': 'callee', 'name': 'ROCKSDB_XXH64_digest',
             'start': f'{DIGEST_START:#x}', 'end': f'{DIGEST_END:#x}',
             'body_sha256': checked['body_hashes']['digest'],
             'census_body_sha256': CENSUS_BODY['digest'],
             'observation': 'merge prologue (rol 1/7/12/18), merge rounds, '
                            '8-byte / 4-byte / 1-byte tail handling, then the '
                            'avalanche (shr 33, *P2, shr 29, *P3, shr 32); '
                            'all five primes appear as 64-bit immediates'},
            {'kind': 'callee', 'name': 'XXH64_createState',
             'start': f'{CREATE_START:#x}', 'end': f'{CREATE_END:#x}',
             'body_sha256': checked['body_hashes']['create'],
             'observation': 'malloc(0x58); below the census minimum size, '
                            'so no census record'},
            {'kind': 'callee', 'name': 'XXH64_freeState',
             'start': f'{FREE_START:#x}', 'end': f'{FREE_END:#x}',
             'body_sha256': checked['body_hashes']['free'],
             'observation': 'free wrapper returning 0; below the census '
                            'minimum size, so no census record'},
        ] + [
            {'kind': 'prime', 'name': name, 'value': f'{value:#018x}',
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
                     'one-shot XXH64 reference on every case; the binary '
                     'itself was never executed'},
            {'kind': 'unknown', 'subject': 'callers of 0x616bd60',
             'status': 'no caller census was run for this packet'},
            {'kind': 'unknown', 'subject': 'semantics of the type 2 and 4 arms',
             'status': 'type 2 calls into 0x61daa60..0x61dacf0 (XXH32 '
                       'streaming); type 4 calls ROCKSDB_XXH3_64bits at '
                       '0x61db650 then imul $0x6b9083d9; neither was '
                       'reconstructed here'},
            {'kind': 'unknown', 'subject': 'XXH64 state buffer offsets',
             'status': 'memsize is at +0x28 and the update touches the '
                       'buffer at +0x40/+0x48; the buffer start offset was '
                       'not pinned'},
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
              f"{checksum_xxh64_arm(b'123456789', 0):#010x}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
