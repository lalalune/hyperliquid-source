#!/usr/bin/env python3
"""Reconstruct the node #115 RocksDB CRC32C extend step.

Bounded question (RE-002): what does the function at 0x61c21d0 compute, and
which bytes in the node #115 binary pin that behaviour?

Observed answer, from the disassembly of work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* The function is the vendor-census entry
  ``_ZN7rocksdb6crc32c10ExtendImplIXadL_ZNS0_L10Slow_CRC32EPmPPKhEEEEjjPKcm``
  (librocksdb-sys), i.e. ``rocksdb::crc32c::ExtendImpl<Slow_CRC32>`` with the
  observed register contract ``(crc: u32 in edi, buf: *const u8 in rsi,
  len: usize in rdx) -> u32 in eax``.
* It is a table-driven CRC32C (Castagnoli, reflected polynomial 0x82F63B78)
  update in the standard complement-in / complement-out form: the entry
  complements the incoming crc, the body updates the complemented value, and
  the exit complements it again. The empty input is therefore the identity.
* The body has four phases, selected by the remaining length and by the
  buffer's 16-byte alignment: a byte-at-a-time head that advances to the
  next 16-byte boundary, a slicing-by-4 loop over 16-byte blocks, a
  slicing-by-4 loop over 8-byte blocks, and a byte-at-a-time tail. All four
  phases implement the same update; only the loop structure differs.
* The four 256-entry tables live in .rodata at 0x97cee0 (T3), 0x97d2e0 (T2),
  0x97d6e0 (T1) and 0x97dae0 (T0). T0 is the plain CRC32C table generated
  from the polynomial; T1..T3 are its successive slicing derivations, and
  every table byte in the binary matches the generated values.
* The only in-binary reference to the function is the tiny initializer at
  0x61c26d0, which stores its address into the writable slot at 0x6508908.
  No direct call site exists in .text, and no in-.text reader of that slot
  was located by a rip-relative scan; the consumer of the slot is unknown,
  not claimed.

The neighbouring function at 0x61c2600 (FDE 0x61c2600..0x61c26c9) is a
separate CRC32C routine that applies the polynomial immediate 0x82F63B78
bit-by-bit over u32 words. It is recorded here as a related unknown and is
not reconstructed by this packet.

The Python model below implements the slicing-by-4 update from the tables
as read from the binary, and is cross-checked against an independent
bit-by-bit reference on 2400 deterministic cases. The model is
address-agnostic: alignment only selects which loop processes which bytes,
so it does not change the result. The node binary is never executed.
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
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-crc32c-extend-115'
POLY = 0x82F63B78
FUNCTION_START = 0x61C21D0
FUNCTION_END = 0x61C23B9
INITIALIZER_START = 0x61C26D0
INITIALIZER_END = 0x61C26E3
FNPTR_SLOT = 0x6508908
CASE_COUNT = 2400
CASE_SEED = 20261109

# (name, virtual address) of the four slicing tables in .rodata.
TABLES = (
    ('T0', 0x97DAE0),
    ('T1', 0x97D6E0),
    ('T2', 0x97D2E0),
    ('T3', 0x97CEE0),
)

# (label, start, end) of the byte-checked instruction windows.
WINDOWS = (
    ('entry_complement', 0x61C21D0, 0x61C21EF),
    ('head_byte_loop', 0x61C21EF, 0x61C221D),
    ('block16_loop', 0x61C221D, 0x61C22FF),
    ('block8_loop', 0x61C2309, 0x61C2387),
    ('tail_byte_loop', 0x61C238C, 0x61C23B9),
    ('initializer_fnptr', 0x61C26D0, 0x61C26E2),
)

BOUNDARY_LENGTHS = (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33,
                    63, 64, 65, 127, 128, 256, 1024, 4096)


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


def read_tables(data, secs):
    """Return the four slicing tables as read from the binary."""
    tables = {}
    for name, va in TABLES:
        off = file_offset(secs, va, 1024)
        tables[name] = list(struct.unpack_from('<256I', data, off))
    return tables


def generated_tables():
    """Generate T0 from the polynomial and derive T1..T3 the slicing way."""
    t0 = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ POLY if crc & 1 else crc >> 1
        t0.append(crc)
    tables = {'T0': t0}
    prev = t0
    for name in ('T1', 'T2', 'T3'):
        cur = [(v >> 8) ^ t0[v & 0xFF] for v in prev]
        tables[name] = cur
        prev = cur
    return tables


def crc32c_extend(crc, data, tables):
    """Slicing-by-4 CRC32C update, as the binary implements it.

    One 4-byte little-endian word per step: xor the word into the
    complemented crc, then fold its four bytes through T3/T2/T1/T0
    (byte 0 through T3, byte 3 through T0); remaining bytes go through
    the single-byte T0 step. The complement-in/out convention makes the
    empty input the identity.
    """
    t0, t1, t2, t3 = tables['T0'], tables['T1'], tables['T2'], tables['T3']
    crc ^= 0xFFFFFFFF
    n = len(data)
    i = 0
    while n - i >= 4:
        word = struct.unpack_from('<I', data, i)[0]
        crc ^= word
        crc = (t3[crc & 0xFF] ^ t2[(crc >> 8) & 0xFF]
               ^ t1[(crc >> 16) & 0xFF] ^ t0[(crc >> 24) & 0xFF])
        i += 4
    while i < n:
        crc = t0[(crc ^ data[i]) & 0xFF] ^ (crc >> 8)
        i += 1
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def crc32c_bitwise(crc, data):
    """Independent bit-by-bit reference for the same update."""
    crc ^= 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ POLY if crc & 1 else crc >> 1
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def table_hashes(data, secs):
    return {name: hashlib.sha256(
        data[file_offset(secs, va, 1024):file_offset(secs, va, 1024) + 1024]
    ).hexdigest() for name, va in TABLES}


def window_hashes(data, secs):
    out = {}
    for label, start, end in WINDOWS:
        off = file_offset(secs, start, end - start)
        out[label] = hashlib.sha256(data[off:off + (end - start)]).hexdigest()
    return out


def body_hash(data, secs):
    off = file_offset(secs, FUNCTION_START, FUNCTION_END - FUNCTION_START)
    return hashlib.sha256(
        data[off:off + (FUNCTION_END - FUNCTION_START)]).hexdigest()


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
    tables = read_tables(data, secs)
    if tables != generated_tables():
        raise ValueError('slicing tables do not match the generated polynomial tables')
    extent = fde_extent(data)
    if extent != (FUNCTION_START, FUNCTION_END):
        raise ValueError(f'FDE extent mismatch: {extent}')
    return {'tables': tables, 'table_hashes': table_hashes(data, secs),
            'window_hashes': window_hashes(data, secs),
            'body_hash': body_hash(data, secs), 'sections': secs}


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic (crc_in, data) cases: boundary lengths, then random."""
    rng = random.Random(seed)
    cases = []
    for length in BOUNDARY_LENGTHS:
        cases.append((rng.randrange(1 << 32),
                      bytes(rng.randrange(256) for _ in range(length))))
    while len(cases) < count:
        length = rng.choice([rng.randrange(0, 64), rng.randrange(0, 1024),
                             rng.randrange(0, 8192)])
        cases.append((rng.randrange(1 << 32),
                      bytes(rng.randrange(256) for _ in range(length))))
    return cases[:count]


def run_cases(cases, tables):
    """Run the model against the bitwise reference; return result rows."""
    rows = []
    for crc_in, data in cases:
        out = crc32c_extend(crc_in, data, tables)
        ref = crc32c_bitwise(crc_in, data)
        if out != ref:
            raise ValueError('model disagrees with the bitwise reference')
        rows.append((crc_in, data, out))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for crc_in, data, out in rows:
        hasher.update(struct.pack('<I', crc_in))
        hasher.update(hashlib.sha256(data).digest())
        hasher.update(struct.pack('<I', out))
    return hasher.hexdigest()


def generate(data, dest):
    """Write the evidence packet files into dest (deterministic)."""
    checked = verify(data)
    tables = checked['tables']
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    cases = generate_cases()
    rows = run_cases(cases, tables)
    aggregate = case_aggregate(rows)

    with (dest / 'tables.tsv').open('w', encoding='utf-8') as handle:
        handle.write('name\taddress\tfile_offset\tbytes\tsha256\n')
        secs = checked['sections']
        for name, va in TABLES:
            handle.write(f"{name}\t{va:#x}\t{file_offset(secs, va, 1024):#x}"
                         f"\t1024\t{checked['table_hashes'][name]}\n")

    with (dest / 'windows.tsv').open('w', encoding='utf-8') as handle:
        handle.write('label\tstart\tend\tbytes\tsha256\n')
        for label, start, end in WINDOWS:
            handle.write(f"{label}\t{start:#x}\t{end:#x}\t{end - start}"
                         f"\t{checked['window_hashes'][label]}\n")

    # cases.tsv keeps every boundary-length case plus the first generated
    # rows (64 rows total); the full 2400-case run is summarised in
    # result.json by its aggregate digest.
    sample = rows[:len(BOUNDARY_LENGTHS)] + rows[len(BOUNDARY_LENGTHS):
                                                 len(BOUNDARY_LENGTHS) + 41]
    with (dest / 'cases.tsv').open('w', encoding='utf-8') as handle:
        handle.write('idx\tcrc_in\tlen\tdata_sha256\tcrc_out\n')
        for idx, (crc_in, data, out) in enumerate(sample):
            handle.write(f"{idx}\t{crc_in:#010x}\t{len(data)}"
                         f"\t{hashlib.sha256(data).hexdigest()}\t{out:#010x}\n")

    result = {
        'target_digest': DIGEST,
        'function': {'start': f'{FUNCTION_START:#x}', 'end': f'{FUNCTION_END:#x}',
                     'body_sha256': checked['body_hash'],
                     'fde': [f'{FUNCTION_START:#x}', f'{FUNCTION_END:#x}']},
        'tables': {name: checked['table_hashes'][name] for name, _ in TABLES},
        'check_value': {'input': '313233343536373839', 'crc_in': '0x00000000',
                        'crc_out': f"{crc32c_extend(0, b'123456789', tables):#010x}",
                        'expected': '0xe3069283'},
        'cases': {'count': len(rows), 'seed': CASE_SEED,
                  'mismatches_vs_bitwise': 0, 'aggregate_sha256': aggregate},
        'initializer': {'start': f'{INITIALIZER_START:#x}',
                        'end': f'{INITIALIZER_END:#x}',
                        'fnptr_slot': f'{FNPTR_SLOT:#x}'},
    }
    (dest / 'result.json').write_text(json.dumps(result, indent=2) + '\n',
                                      encoding='utf-8')

    records = {
        'target_digest': DIGEST,
        'records': [
            {'kind': 'function', 'task': 'RE-002', 'address': f'{FUNCTION_START:#x}',
             'end': f'{FUNCTION_END:#x}', 'body_sha256': checked['body_hash'],
             'identity': 'rocksdb::crc32c::ExtendImpl<Slow_CRC32> (vendor census)',
             'contract': 'crc32c_extend(crc: u32, buf: *const u8, len: usize) -> u32',
             'semantics': 'table-driven CRC32C update, complement-in/out; '
                          'empty input is the identity'},
        ] + [
            {'kind': 'table', 'name': name, 'address': f'{va:#x}',
             'bytes': 1024, 'sha256': checked['table_hashes'][name],
             'derivation': 'T0 generated from polynomial 0x82F63B78; '
                           'T1..T3 successive slicing derivations'}
            for name, va in TABLES
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'registration', 'initializer': f'{INITIALIZER_START:#x}',
             'fnptr_slot': f'{FNPTR_SLOT:#x}',
             'observation': 'initializer stores the function address into '
                            'the writable slot; no direct call site in .text'},
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'aggregate_sha256': aggregate,
             'mismatches_vs_bitwise': 0,
             'note': 'model executed on deterministic cases; the binary itself '
                     'was never executed'},
            {'kind': 'unknown', 'subject': 'consumer of fnptr slot 0x6508908',
             'status': 'no in-.text reader located by rip-relative scan'},
            {'kind': 'unknown', 'subject': 'neighbour 0x61c2600 (FDE ..0x61c26c9)',
             'status': 'separate CRC32C routine using the polynomial immediate '
                       '0x82F63B78 over u32 words; not reconstructed here'},
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
    tables = checked['tables']
    if args.verify or args.out is None:
        rows = run_cases(generate_cases(args.cases), tables)
        print(f"verified: body {checked['body_hash'][:16]}...; "
              f"{len(rows)} cases agree with the bitwise reference; "
              f"check value {crc32c_extend(0, b'123456789', tables):#010x}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
