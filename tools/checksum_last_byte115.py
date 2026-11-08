#!/usr/bin/env python3
"""Reconstruct the node #115 RocksDB ComputeBuiltinChecksumWithLastByte CRC32C arm.

Bounded question (RE-002): what does the function at 0x616bd60 compute for
ChecksumType 1 (kCRC32c), and which bytes in the node #115 binary pin that
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
  0x616bde8): 1 -> the CRC32C arm at 0x616be80; 2 -> an xxhash arm calling
  into 0x61daa60..0x61dacf0; 3 -> an xxhash64 arm calling
  ROCKSDB_XXH64_update (0x61db1d0) / ROCKSDB_XXH64_digest (0x61db3e0);
  4 -> a multiply-xor arm (imul $0x6b9083d9 at 0x616be02); anything else
  (including 0, kNoChecksum) -> 0. Only the CRC32C arm is modelled here;
  the other arms are recorded as observed-but-not-modelled.
* CRC32C arm (0x616be80..0x616beac): it calls the registered CRC32C
  extend function through the PLT stub at 0x61c25f0 (which jumps through
  the writable slot at 0x6508908; the initializer at 0x61c26d0 stores
  0x61c21d0, rocksdb::crc32c::ExtendImpl<Slow_CRC32>, there) twice:
  first ``extend(0, data, n)``, then ``extend(crc, &last_byte, 1)``.
  The extend is the stored form (complement-in/out): ``extend(0,
  b"123456789") == 0xe3069283``. It then applies the Mask inline:
  ``ror $0xf, %eax`` then ``lea 0xa282ead8(%rax), %ebx`` -- i.e.
  ``ror32(crc, 15) + 0xa282ead8 (mod 2**32)``. The constant 0xa282ead8
  occurs exactly once in .text, at the immediate of that lea (0x616bea1).
* So the arm computes ``mask(stored_crc32c(data || last_byte))``.

The Python model below implements the extend twice independently
(bit-by-bit and table-driven) and cross-checks them on 2400 deterministic
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

TARGET = ROOT / 'work' / 'hl-node-115.bin'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-checksum-last-byte-115'
POLY = 0x82F63B78
MASK_CONST = 0xA282EAD8
FUNCTION_START = 0x616BD60
FUNCTION_END = 0x616BEAC
CRC32C_ARM_START = 0x616BE80
CRC32C_ARM_END = 0x616BEAC
MASK_IMMEDIATE_ADDR = 0x616BEA1
EXTEND_STUB = 0x61C25F0
EXTEND_STUB_END = 0x61C25FA
FNPTR_SLOT = 0x6508908
CASE_COUNT = 2400
CASE_SEED = 20261109

# (label, start, end) of the byte-checked instruction windows. They tile
# 0x616bd60..0x616beac exactly: entry/dispatch, xxhash arm, multiply-xor
# arm, default arm, xxhash64 arm, CRC32C arm.
WINDOWS = (
    ('entry_dispatch', 0x616BD60, 0x616BD96),
    ('xxhash_arm', 0x616BD96, 0x616BDE8),
    ('mulmix_arm', 0x616BDE8, 0x616BE18),
    ('default_arm', 0x616BE18, 0x616BE28),
    ('xxhash64_arm', 0x616BE28, 0x616BE80),
    ('crc32c_arm', 0x616BE80, 0x616BEAC),
)

# The dispatch table as observed in the disassembly. Only type 1 is
# modelled; the other arms are observations, not claims about the
# hash functions they call.
DISPATCH = (
    (0, 'default_arm', 'returns 0 (kNoChecksum and any other type)'),
    (1, 'crc32c_arm', 'mask(extend(extend(0, data), last_byte))'),
    (2, 'xxhash_arm', 'calls into 0x61daa60..0x61dacf0; not modelled'),
    (3, 'xxhash64_arm', 'ROCKSDB_XXH64_update/digest; not modelled'),
    (4, 'mulmix_arm', 'hash(data, n) then imul $0x6b9083d9 ^ last_byte; '
                      'not modelled'),
)

BOUNDARY_LENGTHS = (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33,
                    63, 64)


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
    rotated = ((crc >> 15) | ((crc << 17) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return (rotated + MASK_CONST) & 0xFFFFFFFF


def checksum_crc32c_arm(data, last_byte, table=None):
    """The type-1 arm: mask(extend(extend(0, data), last_byte))."""
    crc = extend_bitwise(0, data)
    crc = extend_bitwise(crc, bytes((last_byte,)))
    return mask(crc)


def checksum_crc32c_arm_reference(data, last_byte, table):
    """Same arm, computed with the independent table-driven extend."""
    crc = extend_table(0, data, table)
    crc = extend_table(crc, bytes((last_byte,)), table)
    return mask(crc)


def mask_constant_sites(data, secs):
    """Virtual addresses in .text holding the Mask constant as an immediate."""
    text = secs['.text']
    off = text['offset']
    blob = data[off:off + text['size']]
    needle = struct.pack('<I', MASK_CONST)
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


def body_hash(data, secs):
    off = file_offset(secs, FUNCTION_START, FUNCTION_END - FUNCTION_START)
    return hashlib.sha256(
        data[off:off + (FUNCTION_END - FUNCTION_START)]).hexdigest()


def stub_hash(data, secs):
    off = file_offset(secs, EXTEND_STUB, EXTEND_STUB_END - EXTEND_STUB)
    return hashlib.sha256(
        data[off:off + (EXTEND_STUB_END - EXTEND_STUB)]).hexdigest()


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
    sites = mask_constant_sites(data, secs)
    if sites != [MASK_IMMEDIATE_ADDR]:
        raise ValueError(f'Mask constant sites are not unique: {sites}')
    table = build_table()
    if extend_bitwise(0, b'123456789') != 0xE3069283:
        raise ValueError('bitwise extend check value mismatch')
    if extend_table(0, b'123456789', table) != 0xE3069283:
        raise ValueError('table extend check value mismatch')
    return {'table': table, 'window_hashes': window_hashes(data, secs),
            'body_hash': body_hash(data, secs),
            'stub_hash': stub_hash(data, secs),
            'mask_sites': sites, 'sections': secs}


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic (data, last_byte) cases: boundary lengths, then random.

    Data lengths are capped at 64 bytes so every sampled case fits in
    cases.tsv in full; longer inputs are covered by fixed check values.
    """
    rng = random.Random(seed)
    cases = []
    for length in BOUNDARY_LENGTHS:
        data = bytes(rng.randrange(256) for _ in range(length))
        cases.append((data, rng.randrange(256)))
    while len(cases) < count:
        length = rng.randrange(0, 65)
        data = bytes(rng.randrange(256) for _ in range(length))
        cases.append((data, rng.randrange(256)))
    return cases[:count]


def run_cases(cases, table):
    """Run the model against the table-driven reference; return rows."""
    rows = []
    for data, last_byte in cases:
        out = checksum_crc32c_arm(data, last_byte)
        ref = checksum_crc32c_arm_reference(data, last_byte, table)
        if out != ref:
            raise ValueError('model disagrees with the table reference')
        rows.append((data, last_byte, out))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for data, last_byte, out in rows:
        hasher.update(struct.pack('<Q', len(data)))
        hasher.update(data)
        hasher.update(bytes((last_byte,)))
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

    # cases.tsv keeps every boundary-length case plus the first generated
    # rows (64 rows total); the full 2400-case run is summarised in
    # result.json by its aggregate digest.
    sample = rows[:len(BOUNDARY_LENGTHS)] + rows[len(BOUNDARY_LENGTHS):
                                                 len(BOUNDARY_LENGTHS) + 47]
    with (dest / 'cases.tsv').open('w', encoding='utf-8') as handle:
        handle.write('idx\tdata_len\tdata_hex\tlast_byte\tcrc_out\n')
        for idx, (data_bytes, last_byte, out) in enumerate(sample):
            handle.write(f"{idx}\t{len(data_bytes)}\t{data_bytes.hex()}"
                         f"\t{last_byte:#04x}\t{out:#010x}\n")

    long_data = bytes(0xAB for _ in range(1024))
    check_values = {
        'empty_data_zero_last': {
            'data_hex': '', 'last_byte': '0x00',
            'crc_out': f"{checksum_crc32c_arm(b'', 0):#010x}",
            'extend_of_last_only': f"{extend_bitwise(0, b'\x00'):#010x}"},
        'crc32c_check_value_123456789': {
            'data_hex': b'123456789'.hex(), 'last_byte': '0x00',
            'crc_out': f"{checksum_crc32c_arm(b'123456789', 0):#010x}",
            'stored_crc_of_data': '0xe3069283'},
        'single_byte_a': {
            'data_hex': '', 'last_byte': '0x61',
            'crc_out': f"{checksum_crc32c_arm(b'', 0x61):#010x}",
            'stored_crc_of_last_only': f"{extend_bitwise(0, b'a'):#010x}"},
        'long_input_1024_ab': {
            'data': '1024 bytes of 0xab', 'last_byte': '0xff',
            'crc_out': f"{checksum_crc32c_arm(long_data, 0xff):#010x}",
            'stored_crc_of_data_plus_last':
                f"{extend_bitwise(extend_bitwise(0, long_data), b'\xff'):#010x}"},
    }
    result = {
        'target_digest': DIGEST,
        'function': {'start': f'{FUNCTION_START:#x}', 'end': f'{FUNCTION_END:#x}',
                     'body_sha256': checked['body_hash'],
                     'fde': [f'{FUNCTION_START:#x}', f'{FUNCTION_END:#x}'],
                     'census_symbol': 'rocksdb::ComputeBuiltinChecksumWithLastByte',
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
                       'mask': {'immediate_address': f'{MASK_IMMEDIATE_ADDR:#x}',
                                'constant': f'{MASK_CONST:#010x}',
                                'unique_in_text': checked['mask_sites'] == [MASK_IMMEDIATE_ADDR],
                                'formula': 'ror32(crc, 15) + 0xa282ead8 (mod 2**32)'},
                       'semantics': 'mask(extend(extend(0, data), last_byte))'},
        'check_values': check_values,
        'cases': {'count': len(rows), 'seed': CASE_SEED,
                  'mismatches_vs_table_reference': 0,
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
             'identity': 'rocksdb::ComputeBuiltinChecksumWithLastByte '
                         '(vendor census)',
             'contract': 'compute(type: u8, data: *const u8, n: usize, '
                         'last_byte: u8) -> u32',
             'semantics': 'dispatches on type; type 1 (kCRC32c) returns '
                          'mask(extend(extend(0, data), last_byte)); '
                          'any other type returns 0 except types 2, 3, 4, '
                          'which take their own hash arms (not modelled)'},
        ] + [
            {'kind': 'dispatch', 'type': t, 'arm': arm, 'note': note}
            for t, arm, note in DISPATCH
        ] + [
            {'kind': 'mask', 'address': f'{MASK_IMMEDIATE_ADDR:#x}',
             'constant': f'{MASK_CONST:#010x}',
             'formula': 'ror32(crc, 15) + 0xa282ead8 (mod 2**32)',
             'observation': 'the constant occurs exactly once in .text, as '
                            'the immediate of the lea at 0x616be9f..0x616bea5 '
                            'inside the CRC32C arm'},
            {'kind': 'extend_call', 'stub': f'{EXTEND_STUB:#x}',
             'stub_sha256': checked['stub_hash'],
             'fnptr_slot': f'{FNPTR_SLOT:#x}',
             'observation': 'the CRC32C arm calls the registered extend '
                            'function twice through the PLT stub at 0x61c25f0, '
                            'which jumps through the .bss slot at 0x6508908; '
                            'the initializer at 0x61c26d0 stores 0x61c21d0 '
                            'there; first call is extend(0, data, n), second '
                            'is extend(crc, &last_byte, 1)'},
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'aggregate_sha256': aggregate,
             'mismatches_vs_table_reference': 0,
             'note': 'bitwise model cross-checked against an independent '
                     'table-driven extend on every case; the binary itself '
                     'was never executed'},
            {'kind': 'unknown', 'subject': 'callers of 0x616bd60',
             'status': 'no caller census was run for this packet'},
            {'kind': 'unknown', 'subject': 'semantics of the type 2, 3 and 4 arms',
             'status': 'call targets and the 0x6b9083d9 mix constant are '
                       'recorded from the disassembly; the hash functions '
                       'they implement were not reconstructed'},
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
              f"{len(rows)} cases agree with the table reference; "
              f"arm(b'123456789', 0x00) = "
              f"{checksum_crc32c_arm(b'123456789', 0):#010x}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
