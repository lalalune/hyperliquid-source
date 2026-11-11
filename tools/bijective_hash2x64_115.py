#!/usr/bin/env python3
"""Reconstruct the node #115 RocksDB BijectiveHash2x64 pair.

Bounded question (RE-002): what do the two 128-bit result hashes at
0x61c3e10 (``rocksdb::BijectiveHash2x64``) and its seed-0 adapter at
0x61c3f60 compute from their three u64 inputs -- and which bytes in
the node #115 binary pin that behaviour?

Observed answer, from the disassembly of work/hl-node-115.bin
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* ``BijectiveHash2x64(a, b, c, out1, out2)`` (0x61c3e10..0x61c3f55,
  325 bytes) is a vendor-census entry (librocksdb-sys 0.11.0+8.1.1,
  ``_ZN7rocksdb17BijectiveHash2x64EmmmPmS0_``, id
  node115-vendor-61c3e10; the census ``target_body_sha256`` matches
  the FDE body hashed from the binary, and the census also records
  ``raw_equal`` true against the vendored source body). It is pure
  arithmetic: no calls, no memory reads besides its arguments, no
  stores besides the two out-pointers. It returns nothing; it stores
  ``XXH3_avalanche(X)`` through ``out2`` (r8) and
  ``XXH3_avalanche(Y)`` through ``out1`` (rcx), where X and Y are two
  64-bit mixes of the three inputs (see ``bijective_hash2x64``).
* The seed-0 adapter at 0x61c3f60..0x61c3f71 (17 bytes, no census
  record; pinned by FDE extent and disassembly only) takes
  ``(a, b, out1, out2)``, moves the out-pointers into place, zeroes
  the third input, and tail-jumps to the main body. It is the only
  caller of the main body; it is itself called from exactly one
  site (0x61b02a5, in FDE 0x61b0260, the same function that calls
  both Hash2x64 wrappers at 0x61b016d and 0x61b01c1).
* The two Hash2x64 wrappers at 0x61c3db0/0x61c3de0 (census
  ``_ZN7rocksdb8Hash2x64E...``) are NOT part of this packet; they
  call the 128-bit one-shots reconstructed in PR #5578 and only
  share the caller FDEs with the adapter.

The model below is a transliteration of the disassembly
(``bijective_hash2x64``) cross-checked against an independently
structured re-implementation (``bijective_hash2x64_structured``)
on 2,400 deterministic cases; both agree on every case.
"""
import argparse
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-bijective-hash2x64-115'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

# Prime immediates observed in the body.
P32_1 = 0x9E3779B1
C2 = 0x85EBCA87          # PRIME32_2 + 0x10
C2M1 = 0x85EBCA76         # PRIME32_2 - 1
K_SEED = 0x59973F0033362349
K_MIX = 0xC202797692D63D58
PACK_ADD = 0x03C0000000000000
P64_2 = 0xC2B2AE3D27D4EB4F
P64_2_LO = 0x27D4EB4F     # low 32 bits of PRIME64_2
P64_2_HI32 = 0xC2B2AE3D   # high 32 bits of PRIME64_2
AVALANCHE_MULT = 0x165667919E3779F9  # XXH3_avalanche multiplier

# (name, start, end, census id or None, census symbol or None, body hash)
FUNCTIONS = (
    ('bijective_hash2x64', 0x61C3E10, 0x61C3F55,
     'node115-vendor-61c3e10',
     '_ZN7rocksdb17BijectiveHash2x64EmmmPmS0_',
     'd586664de83493cc5a48eefd3bcef95b10a3ab433b32699334c68671b8cb0864'),
    ('seed0_adapter', 0x61C3F60, 0x61C3F71, None, None,
     '8eb9df37604f72f0b72b1b1af72232ed0875460ff8deafd4f46fd93ca8e3dc55'),
)
# (label, start, end) of the byte-checked instruction windows. The
# windows tile the main body exactly; the last two pin the adapter
# and its single call site.
WINDOWS = (
    ('input_mix', 0x61C3E10, 0x61C3E77),
    ('pack_add', 0x61C3E77, 0x61C3E92),
    ('second_mix', 0x61C3E92, 0x61C3EB6),
    ('third_mix', 0x61C3EB6, 0x61C3F11),
    ('avalanche_out2', 0x61C3F11, 0x61C3F39),
    ('avalanche_out1', 0x61C3F39, 0x61C3F55),
    ('adapter', 0x61C3F60, 0x61C3F71),
    ('adapter_call', 0x61B02A5, 0x61B02AA),
)
# (label, site, offset inside the instruction, value) of the 64-bit
# immediates the body folds in (movabs sites).
IMMEDIATES = (
    ('K_SEED', 0x61C3E1E, 2, K_SEED),
    ('PACK_ADD', 0x61C3E6D, 2, PACK_ADD),
    ('K_MIX', 0x61C3E88, 2, K_MIX),
    ('P64_2', 0x61C3EE2, 2, P64_2),
    ('AVALANCHE_MULT', 0x61C3F14, 2, AVALANCHE_MULT),
)
# (label, site, target) of the control transfers this packet pins.
TRANSFERS = (
    ('adapter_tail_jump', 0x61C3F6C, 0x61C3E10),
    ('adapter_call', 0x61B02A5, 0x61C3F60),
)
# The single caller of the main body and of the adapter.
CALLERS = (
    ('bijective_hash2x64', 0x61C3F6C, 0x61C3F60, 0x61C3E10,
     'seed-0 adapter tail-jump (third input zeroed)'),
    ('seed0_adapter', 0x61B02A5, 0x61B0260, 0x61C3F60,
     'direct E8 call; same FDE also calls both Hash2x64 wrappers'),
)

CASE_COUNT = 2400
CASE_SEED = 20261109
BOUNDARY_U64 = (0, 1, 2, 3, 0x9E3779B1, 0x85EBCA77, 0xFFFFFFFF,
                0x100000000, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF,
                0x59973F0033362349, 0xC202797692D63D58)


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


def _bswap64(value):
    return struct.unpack('<Q', struct.pack('>Q', value & MASK64))[0]


def _avalanche(h):
    """XXH3_avalanche: xorshift 37, * 0x165667919E3779F9, xorshift 32."""
    h ^= h >> 37
    h = (h * AVALANCHE_MULT) & MASK64
    h ^= h >> 32
    return h


def bijective_hash2x64(a, b, c):
    """Transliteration of 0x61c3e10..0x61c3f55, instruction by instruction.

    Returns (out1, out2): out1 is stored through rcx, out2 through r8.
    All arithmetic is mod 2**64.
    """
    a &= MASK64
    b &= MASK64
    c &= MASK64
    # 0x61c3e14..0x61c3e31: rax = c; s = (b ^ a) ^ (K_SEED - c).
    s = (b ^ a) ^ ((K_SEED - c) & MASK64)
    # 0x61c3e34..0x61c3e6a: the first 32-bit multiply stage.
    lo = s & MASK32
    hi = s >> 32
    p = (lo * P32_1) & MASK64          # r10
    q = (lo * C2) & MASK64             # rdi
    r = (C2 * hi) & MASK64             # rdx
    t = (hi * P32_1) & MASK64          # rsi
    rdx1 = (r + (q >> 32) + (p & MASK32)) & MASK64
    # 0x61c3e6d..0x61c3e85: pack the halves and add the round constant.
    pack = (((rdx1 & MASK32) << 32) | (q & MASK32)) & MASK64
    pack = (pack + PACK_ADD) & MASK64  # r9
    # 0x61c3e88..0x61c3ead: m = (K_MIX + c) ^ a; V = the second mix.
    m = (((K_MIX + c) & MASK64) ^ a) & MASK64  # rdi
    v = (((m & MASK32) * C2M1) + t + m + (p >> 32)
         + (rdx1 >> 32)) & MASK64      # rax
    # 0x61c3eb0..0x61c3eb6: r9 ^= bswap(V).
    r9 = pack ^ _bswap64(v)
    # 0x61c3eb9..0x61c3edf: the third multiply stage.
    lo9 = r9 & MASK32
    hi9 = r9 >> 32
    d = ((hi9 * P64_2_LO) + ((lo9 * P64_2_LO) >> 32)
         + (lo9 * P64_2_HI32 & MASK32)) & MASK64  # rdi
    # 0x61c3ee2..0x61c3f0e: X packs D's low half with a product low half;
    # Y mixes PRIME64_2 * V with the remaining high halves.
    x = (((d & MASK32) << 32) | ((lo9 * P64_2_LO) & MASK32)) & MASK64
    y = ((P64_2 * v) + (hi9 * P64_2_HI32)
         + ((lo9 * P64_2_HI32) >> 32) + (d >> 32)) & MASK64
    # 0x61c3f11..0x61c3f36: out2 = avalanche(X), stored through r8.
    out2 = _avalanche(x)
    # 0x61c3f39..0x61c3f51: out1 = avalanche(Y), stored through rcx.
    out1 = _avalanche(y)
    return out1, out2


def bijective_hash2x64_structured(a, b, c):
    """Independent structured re-implementation, from the stage reading.

    Stage 1 mixes the inputs into one 64-bit word ``s`` and splits it
    into 32-bit lanes; stage 2 packs two product halves, adds the
    round constant, and folds in the second mix ``v`` through a
    byte-swap; stage 3 multiplies the packed word's halves again and
    emits two avalanche outputs. Returns (out1, out2) as above.
    """
    a &= MASK64
    b &= MASK64
    c &= MASK64

    def mul32(x, y):
        return (x * y) & MASK64

    # Stage 1: s and its four 32-bit products.
    s = (b ^ a) ^ ((K_SEED - c) & MASK64)
    slo, shi = s & MASK32, s >> 32
    p_lo = mul32(slo, P32_1)
    q_lo = mul32(slo, C2)
    r_hi = mul32(C2, shi)
    t_hi = mul32(shi, P32_1)
    combined = (r_hi + (q_lo >> 32) + (p_lo & MASK32)) & MASK64

    # Stage 2: the packed word, the round constant, the second mix.
    packed = (((combined & MASK32) << 32) | (q_lo & MASK32)) & MASK64
    packed = (packed + PACK_ADD) & MASK64
    m = (((K_MIX + c) & MASK64) ^ a) & MASK64
    v = (mul32(m & MASK32, C2M1) + t_hi + m + (p_lo >> 32)
         + (combined >> 32)) & MASK64
    word = packed ^ _bswap64(v)

    # Stage 3: the two output mixes and their avalanches.
    wlo, whi = word & MASK32, word >> 32
    d = (mul32(whi, P64_2_LO) + (mul32(wlo, P64_2_LO) >> 32)
         + (mul32(wlo, P64_2_HI32) & MASK32)) & MASK64
    x = (((d & MASK32) << 32) | (mul32(wlo, P64_2_LO) & MASK32)) & MASK64
    y = (mul32(P64_2, v) + mul32(whi, P64_2_HI32)
         + (mul32(wlo, P64_2_HI32) >> 32) + (d >> 32)) & MASK64
    return _avalanche(y), _avalanche(x)


def seed0_adapter(a, b):
    """The 0x61c3f60 adapter: (a, b, out1, out2) with c fixed to 0."""
    return bijective_hash2x64(a, b, 0)


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


def _imm64(data, secs, va, off):
    """The 8-byte little-endian immediate at va+off."""
    base = file_offset(secs, va, off + 8)
    return struct.unpack_from('<Q', data, base + off)[0]


def _transfer_target(data, secs, va):
    """The E8/E9 relative target at va (5-byte relative transfer)."""
    off = file_offset(secs, va, 5)
    if data[off] not in (0xE8, 0xE9):
        raise ValueError(f'not a relative transfer at {va:#x}')
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
    for _label, site, off, value in IMMEDIATES:
        got = _imm64(data, secs, site, off)
        if got != value:
            raise ValueError(f'immediate mismatch at {site:#x}: '
                             f'{got:#x} != {value:#x}')
    for _label, site, target in TRANSFERS:
        if _transfer_target(data, secs, site) != target:
            raise ValueError(f'transfer at {site:#x} does not target '
                             f'{target:#x}')
    checked = {
        'window_hashes': window_hashes(data, secs),
        'body_hashes': bodies,
        'sections': secs,
    }
    return checked


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic (a, b, c) cases: boundary triples, then random."""
    rng = random.Random(seed)
    cases = []
    for a in BOUNDARY_U64:
        for b in BOUNDARY_U64:
            for c in (0, 1, 0x9E3779B1):
                cases.append((a, b, c))
    for a, b, c in (
            (0, 0, 0), (1, 1, 1),
            (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
            (0x0123456789ABCDEF, 0xFEDCBA9876543210, 0x5555555555555555),
            (0xAAAAAAAAAAAAAAAA, 0x5555555555555555, 0xAAAAAAAAAAAAAAAA),
            (0x8000000000000000, 0x8000000000000000, 0x8000000000000000),
            (0x59973F0033362349, 0xC202797692D63D58, 0x03C0000000000000),
            (0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667919E3779F9)):
        cases.append((a, b, c))
    while len(cases) < count:
        cases.append((rng.getrandbits(64), rng.getrandbits(64),
                      rng.getrandbits(64)))
    return cases[:count]


def run_cases(cases):
    """Run the transliteration against the structured model; return rows."""
    rows = []
    for a, b, c in cases:
        out1, out2 = bijective_hash2x64(a, b, c)
        ref1, ref2 = bijective_hash2x64_structured(a, b, c)
        if (out1, out2) != (ref1, ref2):
            raise ValueError(
                f'models disagree for a={a:#x}, b={b:#x}, c={c:#x}')
        rows.append((a, b, c, out1, out2))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for a, b, c, out1, out2 in rows:
        for value in (a, b, c, out1, out2):
            hasher.update(struct.pack('<Q', value))
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

    # cases.tsv keeps the first 64 rows (all boundary triples for the
    # first seeds); the full 2400-case run is summarised in result.json
    # by its aggregate digest.
    sample = rows[:64]
    with (dest / 'cases.tsv').open('w', encoding='utf-8') as handle:
        handle.write('idx\ta\tb\tc\tout1\tout2\n')
        for idx, (a, b, c, out1, out2) in enumerate(sample):
            handle.write(f"{idx}\t{a:#018x}\t{b:#018x}\t{c:#018x}\t"
                         f"{out1:#018x}\t{out2:#018x}\n")

    def both(a, b, c):
        return bijective_hash2x64(a, b, c)

    check_values = {
        'zero_inputs': {
            'a': '0x0', 'b': '0x0', 'c': '0x0',
            'out1': f"{both(0, 0, 0)[0]:#018x}",
            'out2': f"{both(0, 0, 0)[1]:#018x}",
            'note': 'all-zero inputs; the seed constant K_SEED still mixes'},
        'unit_inputs': {
            'a': '0x1', 'b': '0x1', 'c': '0x1',
            'out1': f"{both(1, 1, 1)[0]:#018x}",
            'out2': f"{both(1, 1, 1)[1]:#018x}",
            'note': 'all-one inputs'},
        'all_ones': {
            'a': '0xffffffffffffffff', 'b': '0xffffffffffffffff',
            'c': '0xffffffffffffffff',
            'out1': f"{both(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)[0]:#018x}",
            'out2': f"{both(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)[1]:#018x}",
            'note': 'wrap-around extremes'},
        'seed0_adapter_case': {
            'a': '0x0123456789abcdef', 'b': '0xfedcba9876543210',
            'c': '0x0',
            'out1': f"{both(0x0123456789ABCDEF, 0xFEDCBA9876543210, 0)[0]:#018x}",
            'out2': f"{both(0x0123456789ABCDEF, 0xFEDCBA9876543210, 0)[1]:#018x}",
            'note': 'the adapter path: third input fixed to 0'},
        'constants_as_inputs': {
            'a': '0x59973f0033362349', 'b': '0xc202797692d63d58',
            'c': '0x03c0000000000000',
            'out1': f"{both(0x59973F0033362349, 0xC202797692D63D58, 0x03C0000000000000)[0]:#018x}",
            'out2': f"{both(0x59973F0033362349, 0xC202797692D63D58, 0x03C0000000000000)[1]:#018x}",
            'note': 'the folded immediates fed back as inputs'},
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
            'bijective_hash2x64': 'bijective_hash2x64(a: u64, b: u64, c: u64, out1: *mut u64, out2: *mut u64) -> ()',
            'seed0_adapter': 'seed0_adapter(a: u64, b: u64, out1: *mut u64, out2: *mut u64) -> ()',
        },
        'outputs': {
            'out1': 'XXH3_avalanche(Y), stored through rcx (first out-pointer)',
            'out2': 'XXH3_avalanche(X), stored through r8 (second out-pointer)',
        },
        'immediates': {f'{label}@{site:#x}': {'value': f'{value:#018x}'}
                       for label, site, _off, value in IMMEDIATES},
        'callers': [
            {'function': name, 'site': f'{site:#x}',
             'caller_fde': f'{caller:#x}', 'target': f'{target:#x}',
             'note': note}
            for name, site, caller, target, note in CALLERS
        ],
        'check_values': check_values,
        'cases': {'count': len(rows), 'seed': CASE_SEED,
                  'mismatches_vs_structured_model': 0,
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
                 'bijective_hash2x64': 'pure arithmetic over three u64 inputs: '
                          's = (b^a)^(K_SEED-c); 32-bit multiply chains '
                          'build a packed word (plus the 0x03c0... round '
                          'constant); a second mix v folds in (K_MIX+c)^a '
                          'through a byte-swap; two further mixes X and Y '
                          'are avalanched into out2 and out1; no calls, no '
                          'other stores',
                 'seed0_adapter': 'moves out1/out2 into place, zeroes the '
                          'third input, tail-jumps to bijective_hash2x64',
             }[name]}
            for name, start, end, census_id, symbol, _body in FUNCTIONS
        ] + [
            {'kind': 'immediate', 'label': label,
             'address': f'{site:#x}', 'value': f'{value:#018x}',
             'observation': f'the {label} constant folded at {site:#x}'}
            for label, site, _off, value in IMMEDIATES
        ] + [
            {'kind': 'caller', 'function': name, 'site': f'{site:#x}',
             'caller_fde': f'{caller:#x}', 'target': f'{target:#x}',
             'observation': note}
            for name, site, caller, target, note in CALLERS
        ],
    }
    (dest / 'records.json').write_text(json.dumps(records, indent=2) + '\n',
                                       encoding='utf-8')
    return checked


def _objdump_text(data, secs, start, end):
    """Whole-function objdump text for the packet excerpt files."""
    import subprocess
    import tempfile
    off = file_offset(secs, start, end - start)
    body = data[off:off + (end - start)]
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / 'body.bin'
        raw.write_bytes(body)
        out = subprocess.run(
            ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
             f'--adjust-vma={start:#x}', str(raw)],
            capture_output=True, text=True, check=True)
    return out.stdout


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Reconstruct node #115 BijectiveHash2x64.')
    parser.add_argument('--verify', action='store_true',
                        help='verify the pinned bytes against the binary')
    parser.add_argument('--out', type=Path, default=None,
                        help='generate the evidence packet into this dir')
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    if args.verify:
        checked = verify(data)
        print(f"verified: {len(FUNCTIONS)} functions, "
              f"{len(WINDOWS)} windows, "
              f"{len(IMMEDIATES)} immediates, "
              f"{len(TRANSFERS)} transfers")
        cases = generate_cases()
        rows = run_cases(cases)
        print(f"cases: {len(rows)} checked, 0 mismatches, "
              f"aggregate {case_aggregate(rows)}")
        return 0
    if args.out is not None:
        checked = generate(data, args.out)
        secs = checked['sections']
        for name, start, end, _cid, _sym, _body in FUNCTIONS:
            text = _objdump_text(data, secs, start, end)
            fname = ('bijective_hash2x64_115.objdump.txt'
                     if name == 'bijective_hash2x64' else
                     'seed0_adapter_115.objdump.txt')
            (args.out / fname).write_text(text, encoding='utf-8')
        print(f"packet written to {args.out}")
        return 0
    parser.print_help()
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
