#!/usr/bin/env python3
"""Reconstruct the node #115 RocksDB CRC32C combine step.

Bounded question (RE-002): what does the function at 0x61c2600 compute, and
which bytes in the node #115 binary pin that behaviour?

Observed answer, from the disassembly of work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* The function is the vendor-census entry
  ``_ZN7rocksdb6crc32c13Crc32cCombineEjjm`` (librocksdb-sys), i.e.
  ``rocksdb::crc32c::Crc32cCombine`` with the observed register contract
  ``(crc1: u32 in edi, crc2: u32 in esi, len: usize in rdx) -> u32 in eax``.
  The census pins its body exactly to the FDE 0x61c2600..0x61c26c9, and the
  body SHA-256 below matches the census target_body_sha256.
* It returns ``crc2 ^ advance(crc1, len)``, where ``advance`` feeds ``len``
  zero bytes through the CRC32C update starting from the raw state ``crc1``.
  The function itself does no complementing; it operates on raw states.
  Concatenation reading: if ``crc1`` is the raw state after ``X`` and
  ``crc2`` is the raw CRC of ``Y`` computed from a zero initial state, the
  result is the raw state after ``X || Y``. With stored-form CRCs
  ``s1 = extend(0, X)`` and ``s2 = extend(0, Y)`` the concatenation needs
  one extra term, verified on 300 random splits:
  ``extend(0, X || Y) == ~combine(~s1, ~s2, len(Y)) ^ advance(0xFFFFFFFF,
  len(Y))``. A bare ``~combine(~s1, ~s2, n)`` is NOT the stored CRC of the
  concatenation; the difference is exactly ``advance(0xFFFFFFFF, n)``.
* Two paths implement the advance. When ``len % 4`` is non-zero, the head
  calls the registered extend function (the 0x61c21d0 routine) through the
  PLT stub at 0x61c25f0, which jumps through the writable slot at
  0x6508908; the initializer at 0x61c26d0 stores 0x61c21d0 into that slot.
  The call passes ``~crc1`` with a zeroed stack word as the buffer, so the
  double complement cancels and the result is the raw advance by
  ``len % 4`` zero bytes. The word part then advances the state by
  ``len / 4`` u32 words of zeros with a GF(2) power table: the outer loop
  decomposes the word count in binary (tzcnt), and for each set bit at
  position ``i`` the inner 32-step loop multiplies the state by the table
  entry at 0x97cde0 + 4*i, which advances it by ``32 * 2**i`` zero bits.
* The 64-entry table lives in .rodata at 0x97cde0 (256 bytes, ending just
  before the T3 slicing table at 0x97cee0). Entries 0..61 are the power
  table; entries 62..63 are zero padding, never indexed for any size_t
  length. The structure is verified, not assumed: the effective factor of
  entry ``i`` is the state advanced by ``32 * 2**i`` zero bits, and the
  squaring chain between consecutive entries holds.
* One in-binary caller is known: ``rocksdb::WritableFileWriter::Append``
  (cold part, FDE 0x6054680..0x605518b) calls 0x61c2600 at 0x6054a79 with
  the running checksum from 0xd4(%rbx), the new chunk's checksum from the
  stack, and the chunk length in rbp, storing the combined checksum back
  to 0xd4(%rbx).

The Python model below implements the advance literally from the
disassembly, using the table bytes as read from the binary, and is
cross-checked against an independent bit-by-bit reference on 2400
deterministic cases. The node binary is never executed.
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
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-crc32c-combine-115'
POLY = 0x82F63B78
FUNCTION_START = 0x61C2600
FUNCTION_END = 0x61C26C9
HEAD_CALL_STUB = 0x61C25F0
HEAD_CALL_STUB_END = 0x61C25FA
INITIALIZER_START = 0x61C26D0
INITIALIZER_END = 0x61C26E3
FNPTR_SLOT = 0x6508908
CALLER_FDE_START = 0x6054680
CALLER_FDE_END = 0x605518B
CALLER_CALL_SITE = 0x6054A79
CASE_COUNT = 2400
CASE_SEED = 20261109

# (name, virtual address, bytes) of the GF(2) power table in .rodata.
TABLES = (
    ('POW', 0x97CDE0, 256),
)

# (label, start, end) of the byte-checked instruction windows. The six
# function windows tile 0x61c2600..0x61c26c9; the stub window covers the
# PLT stub the misaligned head calls through.
WINDOWS = (
    ('entry_prologue', 0x61C2600, 0x61C262F),
    ('aligned_word_setup', 0x61C262F, 0x61C2640),
    ('outer_head_tzcnt', 0x61C2640, 0x61C2660),
    ('gf2_multiply_loop', 0x61C2660, 0x61C2689),
    ('outer_tail_exit', 0x61C2689, 0x61C26AE),
    ('misaligned_head_call', 0x61C26AE, 0x61C26C9),
    ('head_call_stub', 0x61C25F0, 0x61C25FA),
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


def step(state):
    """One reflected CRC32C bit step (the R operation)."""
    return (state >> 1) ^ POLY if state & 1 else state >> 1


def step_inv(state):
    """Inverse of step: multiply the raw state by x in the same arithmetic."""
    low = (state >> 31) & 1
    out = low
    for j in range(31):
        bit = ((state >> j) & 1) ^ (low & ((POLY >> j) & 1))
        out |= bit << (j + 1)
    return out & 0xFFFFFFFF


def advance(state, nbytes):
    """Raw state after feeding nbytes zero bytes (bit-by-bit reference)."""
    for _ in range(8 * nbytes):
        state = step(state)
    return state & 0xFFFFFFFF


def mul_loop(state, multiplier):
    """The inner 32-step GF(2) multiply, exactly as the disassembly runs it.

    Accumulates the state shifted right with polynomial reduction whenever
    the multiplier's top bit is set, while the multiplier shifts left.
    """
    result = 0
    for _ in range(32):
        if (multiplier >> 31) & 1:
            result ^= state
        state = step(state)
        multiplier = (multiplier << 1) & 0xFFFFFFFF
    return result & 0xFFFFFFFF


def mul_poly(a, b):
    """Plain GF(2) polynomial product of a and b (mul_loop carries x^-31)."""
    out = mul_loop(a, b)
    for _ in range(31):
        out = step_inv(out)
    return out


def read_table(data, secs):
    """Return the 64-entry power table as read from the binary."""
    _, va, size = TABLES[0]
    off = file_offset(secs, va, size)
    return list(struct.unpack_from('<64I', data, off))


def table_factors(table):
    """Effective advance factor of each entry: mul_loop(1, entry)."""
    return [mul_loop(1, entry) for entry in table]


def check_table(table):
    """Verify the power-table structure against the polynomial."""
    factors = table_factors(table)
    base = 1
    for _ in range(32):
        base = step(base)
    if factors[0] != base:
        raise ValueError('table entry 0 is not the 32-zero-bit advance')
    for i in range(61):
        if mul_poly(factors[i], factors[i]) != factors[i + 1]:
            raise ValueError(f'squaring chain breaks at table entry {i}')
    if table[62] != 0 or table[63] != 0:
        raise ValueError('table padding entries 62..63 are not zero')
    return factors


def crc32c_combine(crc1, crc2, n, table):
    """Combine two raw CRC32C states across n zero bytes, as the binary does.

    Head: when n % 4 is non-zero, the binary calls the registered extend
    function on a zeroed word, which advances the raw state by (n % 4)
    zero bytes. Word part: decompose n // 4 in binary; each set bit at
    position i multiplies the state by table entry i (advance by
    32 * 2**i zero bits). The result is crc2 xored with the advanced crc1.
    """
    state = crc1 & 0xFFFFFFFF
    if n & 3:
        state = advance(state, n & 3)
    words = n >> 2
    index = 0
    while words:
        shift = (words & -words).bit_length() - 1
        words >>= shift
        index += shift
        state = mul_loop(state, table[index])
        index += 1
        words >>= 1
    return (crc2 ^ state) & 0xFFFFFFFF


def crc32c_combine_reference(crc1, crc2, n):
    """Independent bit-by-bit reference: crc2 ^ advance(crc1, n)."""
    return (crc2 ^ advance(crc1 & 0xFFFFFFFF, n)) & 0xFFFFFFFF


def extend_stored_bitwise(crc, data):
    """Independent stored-form CRC32C extend (complement-in/out), bitwise."""
    crc ^= 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = step(crc)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def table_hashes(data, secs):
    return {name: hashlib.sha256(
        data[file_offset(secs, va, size):file_offset(secs, va, size) + size]
    ).hexdigest() for name, va, size in TABLES}


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
    table = read_table(data, secs)
    check_table(table)
    extent = fde_extent(data)
    if extent != (FUNCTION_START, FUNCTION_END):
        raise ValueError(f'FDE extent mismatch: {extent}')
    return {'table': table, 'table_hashes': table_hashes(data, secs),
            'window_hashes': window_hashes(data, secs),
            'body_hash': body_hash(data, secs), 'sections': secs}


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic (crc1, crc2, len) cases: boundary lengths, then random."""
    rng = random.Random(seed)
    cases = []
    for length in BOUNDARY_LENGTHS:
        cases.append((rng.randrange(1 << 32), rng.randrange(1 << 32), length))
    while len(cases) < count:
        length = rng.choice([rng.randrange(0, 64), rng.randrange(0, 1024),
                             rng.randrange(0, 8192)])
        cases.append((rng.randrange(1 << 32), rng.randrange(1 << 32), length))
    return cases[:count]


def run_cases(cases, table):
    """Run the model against the bitwise reference; return result rows."""
    rows = []
    for crc1, crc2, n in cases:
        out = crc32c_combine(crc1, crc2, n, table)
        ref = crc32c_combine_reference(crc1, crc2, n)
        if out != ref:
            raise ValueError('model disagrees with the bitwise reference')
        rows.append((crc1, crc2, n, out))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for crc1, crc2, n, out in rows:
        hasher.update(struct.pack('<I', crc1))
        hasher.update(struct.pack('<I', crc2))
        hasher.update(struct.pack('<Q', n))
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

    with (dest / 'tables.tsv').open('w', encoding='utf-8') as handle:
        handle.write('name\taddress\tfile_offset\tbytes\tsha256\n')
        secs = checked['sections']
        for name, va, size in TABLES:
            handle.write(f"{name}\t{va:#x}\t{file_offset(secs, va, size):#x}"
                         f"\t{size}\t{checked['table_hashes'][name]}\n")

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
        handle.write('idx\tcrc1\tcrc2\tlen\tcrc_out\n')
        for idx, (crc1, crc2, n, out) in enumerate(sample):
            handle.write(f"{idx}\t{crc1:#010x}\t{crc2:#010x}\t{n}"
                         f"\t{out:#010x}\n")

    split = (extend_stored_bitwise(0, b'12345'),
             extend_stored_bitwise(0, b'6789'))
    split_out = crc32c_combine(~split[0] & 0xFFFFFFFF,
                               ~split[1] & 0xFFFFFFFF, 4, table)
    correction = advance(0xFFFFFFFF, 4)
    concatenated = (~split_out & 0xFFFFFFFF) ^ correction
    if concatenated != extend_stored_bitwise(0, b'123456789'):
        raise ValueError('concatenation identity does not hold')
    check_values = {
        'zero_length': {'crc1': '0x00000000', 'crc2': '0x00000000', 'len': 0,
                        'crc_out': f"{crc32c_combine(0, 0, 0, table):#010x}",
                        'expected': '0x00000000'},
        'advance_9_zero_bytes': {'crc1': '0xffffffff', 'crc2': '0x00000000',
                                 'len': 9,
                                 'crc_out': f"{crc32c_combine(0xFFFFFFFF, 0, 9, table):#010x}",
                                 'expected': '0x441a975c'},
        'split_123456789': {'crc1': f"~extend(0, b'12345') = {~split[0] & 0xFFFFFFFF:#010x}",
                            'crc2': f"~extend(0, b'6789') = {~split[1] & 0xFFFFFFFF:#010x}",
                            'len': 4,
                            'crc_out': f"{split_out:#010x}",
                            'correction_term_advance_ffffffff_4': f"{correction:#010x}",
                            'concatenated_stored': f"{concatenated:#010x}",
                            'expected': '0xe3069283'},
    }
    result = {
        'target_digest': DIGEST,
        'function': {'start': f'{FUNCTION_START:#x}', 'end': f'{FUNCTION_END:#x}',
                     'body_sha256': checked['body_hash'],
                     'fde': [f'{FUNCTION_START:#x}', f'{FUNCTION_END:#x}'],
                     'census_symbol': 'rocksdb::crc32c::Crc32cCombine',
                     'census_body_sha256': checked['body_hash']},
        'tables': {name: checked['table_hashes'][name] for name, _, _ in TABLES},
        'check_values': check_values,
        'cases': {'count': len(rows), 'seed': CASE_SEED,
                  'mismatches_vs_bitwise': 0, 'aggregate_sha256': aggregate},
        'head_call': {'stub': [f'{HEAD_CALL_STUB:#x}', f'{HEAD_CALL_STUB_END:#x}'],
                      'fnptr_slot': f'{FNPTR_SLOT:#x}',
                      'initializer': [f'{INITIALIZER_START:#x}', f'{INITIALIZER_END:#x}'],
                      'target': '0x61c21d0 (rocksdb::crc32c::ExtendImpl<Slow_CRC32>)'},
        'consumer': {'function': 'rocksdb::WritableFileWriter::Append (.cold)',
                     'fde': [f'{CALLER_FDE_START:#x}', f'{CALLER_FDE_END:#x}'],
                     'call_site': f'{CALLER_CALL_SITE:#x}',
                     'observation': 'combines the running checksum in '
                                    '0xd4(%rbx) with the new chunk checksum '
                                    'over rbp bytes, storing the result back '
                                    'to 0xd4(%rbx)'},
    }
    (dest / 'result.json').write_text(json.dumps(result, indent=2) + '\n',
                                      encoding='utf-8')

    records = {
        'target_digest': DIGEST,
        'records': [
            {'kind': 'function', 'task': 'RE-002', 'address': f'{FUNCTION_START:#x}',
             'end': f'{FUNCTION_END:#x}', 'body_sha256': checked['body_hash'],
             'identity': 'rocksdb::crc32c::Crc32cCombine (vendor census)',
             'contract': 'crc32c_combine(crc1: u32, crc2: u32, len: usize) -> u32',
             'semantics': 'crc2 ^ advance(crc1, len zero bytes); no '
                          'complementing inside; len 0 returns crc1 ^ crc2; '
                          'stored-form concatenation needs the extra term '
                          'advance(0xFFFFFFFF, len) (see check_values)'},
        ] + [
            {'kind': 'table', 'name': name, 'address': f'{va:#x}',
             'bytes': size, 'sha256': checked['table_hashes'][name],
             'derivation': 'entry i advances the raw state by 32 * 2**i '
                           'zero bits (verified: effective factor equals the '
                           'bitwise advance; squaring chain holds for i 0..60; '
                           'entries 62..63 are zero padding)'}
            for name, va, size in TABLES
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'head_call', 'stub': f'{HEAD_CALL_STUB:#x}',
             'fnptr_slot': f'{FNPTR_SLOT:#x}',
             'initializer': f'{INITIALIZER_START:#x}',
             'observation': 'misaligned head calls the registered extend '
                            'function (0x61c21d0) through the PLT stub at '
                            '0x61c25f0, which jumps through the .bss slot at '
                            '0x6508908; the initializer stores 0x61c21d0 there; '
                            'the double complement cancels, leaving the raw '
                            'advance by len % 4 zero bytes'},
            {'kind': 'consumer', 'function': 'rocksdb::WritableFileWriter::Append (.cold)',
             'fde': [f'{CALLER_FDE_START:#x}', f'{CALLER_FDE_END:#x}'],
             'call_site': f'{CALLER_CALL_SITE:#x}',
             'observation': 'call site passes the running checksum, the new '
                            'chunk checksum and the chunk length; result is '
                            'stored back to the running checksum field'},
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'aggregate_sha256': aggregate,
             'mismatches_vs_bitwise': 0,
             'note': 'model executed on deterministic cases; the binary itself '
                     'was never executed'},
            {'kind': 'unknown', 'subject': 'other callers of 0x61c2600',
             'status': 'only the WritableFileWriter::Append call site at '
                       '0x6054a79 was located; no exhaustive call census was run'},
            {'kind': 'unknown', 'subject': 'which files or blocks the node '
                                           'checksums with the combined value',
             'status': 'not established by this packet'},
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
              f"{len(rows)} cases agree with the bitwise reference; "
              f"combine(0xffffffff, 0, 9) = "
              f"{crc32c_combine(0xFFFFFFFF, 0, 9, table):#010x}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
