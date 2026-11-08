#!/usr/bin/env python3
"""Reconstruct the node #115 FileChecksumGenCrc32c Finalize behaviour.

Bounded question (RE-002): what does the function at 0x61cd1c0 do to the
FileChecksumGenCrc32c object, and which bytes in the node #115 binary pin
that behaviour?

Observed answer, from the disassembly of work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* The function is the vendor-census entry
  ``_ZN7rocksdb21FileChecksumGenCrc32c8FinalizeEv``
  (librocksdb-sys). The census pins its body exactly to the FDE
  0x61cd1c0..0x61cd23f, and the body SHA-256 below matches the census
  target_body_sha256 (also recorded in research/byte-windows.json).
  It is vtable slot 3 of FileChecksumGenCrc32c (address point
  0x64d7970; the vtable itself was reconstructed in the merged packet
  research/work-items/RE-002-node115-rocksdb-checksum-vtable/).
* Object layout, read off the sibling methods: vptr at +0x0; a u32
  accumulator at +0x8 (Update at 0x61cd1a0 reads it as the seed of the
  registered CRC32C extend and stores the result back; the factory at
  0x61cd2e0 zeroes it); a std::string at +0x10 (pointer +0x10, length
  +0x18, SSO buffer/capacity +0x20). The object is 0x30 bytes.
* Finalize itself: ``mov eax, [rdi+0x8]`` then ``bswap eax`` (at
  0x61cd1d9), stores the swapped word on the stack, then appends those
  4 bytes to the string at [rdi+0x10] with one call to
  ``std::__cxx11::basic_string::_M_append(const char*, size_t)`` through
  the PLT entry at 0x63f0f40. The appended bytes are therefore the
  big-endian form of the accumulated CRC32C word.
* No Mask/Unmask step: there is no rotate and no add of 0xa282ead8
  anywhere in the body -- unlike ComputeBuiltinChecksum (0x616bca0,
  PR #5413), whose CRC32C arm applies Mask inline. The checksum string
  holds the raw accumulator, byte-swapped only.
* Length guard, before the append: ``movabs rax, 0x3fffffffffffffff``
  (the std::string max_size), ``sub rax, [rdi+0x18]`` (current length),
  ``cmp rax, 0x3``; if the remainder is <= 3 the body throws
  ``__throw_length_error`` (PLT 0x63f0de0). The append is therefore
  allowed exactly when ``len <= max_size - 4``.
* The body keeps the usual stack canary (fs:0x28, checked on both exits;
  mismatch calls ``__stack_chk_fail`` at 0x63f0d70). The canary is an
  environment detail, not part of the modelled behaviour.

The Python model below implements the append twice independently
(struct.pack('>I') vs manual byte-swap + bytearray extend) and
cross-checks them on 2400 deterministic cases. The node binary is
never executed.
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
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-file-checksum-finalize-115'
POLY = 0x82F63B78
FUNCTION_START = 0x61CD1C0
FUNCTION_END = 0x61CD23F
UPDATE_START = 0x61CD1A0
UPDATE_END = 0x61CD1B5
EXTEND_STUB = 0x61C25F0
EXTEND_STUB_END = 0x61C25FA
FNPTR_SLOT = 0x6508908
APPEND_PLT = 0x63F0F40
APPEND_PLT_END = 0x63F0F50
THROW_LENGTH_ERROR_PLT = 0x63F0DE0
STACK_CHK_FAIL_PLT = 0x63F0D70
MAX_SIZE = 0x3FFFFFFFFFFFFFFF
CASE_COUNT = 2400
CASE_SEED = 20261109

# Census body hash for Finalize
# (research/work-items/RE-002-node115-vendor-census/census.json and
# research/byte-windows.json).
CENSUS_BODY = {
    'function': 'd3e24d9354044c97cd94d122250a157da9131c7ccd36d49330e912d3fd1c7007',
}

# (label, start, end) of the byte-checked instruction windows. The seven
# Finalize windows tile 0x61cd1c0..0x61cd23f exactly; the Update window
# pins what the +0x8 word is, and the two stub windows pin the calls the
# body makes.
WINDOWS = (
    ('prologue_canary', FUNCTION_START, 0x61CD1D6),
    ('load_bswap', 0x61CD1D6, 0x61CD1DF),
    ('length_guard', 0x61CD1DF, 0x61CD1F3),
    ('append_call', 0x61CD1F3, 0x61CD209),
    ('canary_check_ret', 0x61CD209, 0x61CD21E),
    ('length_error_path', 0x61CD21E, 0x61CD23A),
    ('stack_fail_path', 0x61CD23A, 0x61CD23F),
    ('update', UPDATE_START, UPDATE_END),
    ('extend_stub', EXTEND_STUB, EXTEND_STUB_END),
    ('append_plt', APPEND_PLT, APPEND_PLT_END),
)

BOUNDARY_LENGTHS = (0, 1, 2, 3, 4, 5, 15, 16, 17, 31, 32, 100, 1024)
STRUCTURED_CRCS = (0x00000000, 0x00000001, 0xFFFFFFFF, 0xE3069283,
                   0xA282EAD8, 0x80000000, 0x12345678)


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


# --- Big-endian word encoding ---

def be32_pack(crc):
    """The appended bytes, via struct (big-endian u32)."""
    return struct.pack('>I', crc & 0xFFFFFFFF)


def be32_bswap(crc):
    """The same bytes, via the manual byte-swap the binary performs."""
    crc &= 0xFFFFFFFF
    return bytes(((crc >> 24) & 0xFF, (crc >> 16) & 0xFF,
                  (crc >> 8) & 0xFF, crc & 0xFF))


def guard_allows(length):
    """True iff the binary's length guard lets the 4-byte append run.

    The binary throws when (max_size - length) <= 3, i.e. the append
    runs exactly when length <= max_size - 4.
    """
    return length <= MAX_SIZE - 4


def finalize(crc, prior):
    """Model of Finalize: prior checksum bytes + BE32(crc)."""
    if not guard_allows(len(prior)):
        raise LengthError('string length would exceed max_size')
    return prior + be32_pack(crc)


def finalize_reference(crc, prior):
    """Independent reference: manual bswap + bytearray extend."""
    if (MAX_SIZE - len(prior)) <= 3:
        raise LengthError('string length would exceed max_size')
    out = bytearray(prior)
    out.extend(be32_bswap(crc))
    return bytes(out)


class LengthError(ValueError):
    """The model's stand-in for __throw_length_error."""


# --- CRC32C extend, bitwise only (one end-to-end check value) ---

def _step(state):
    """One reflected CRC32C bit step."""
    return (state >> 1) ^ POLY if state & 1 else state >> 1


def extend_bitwise(crc, data):
    """Stored-form CRC32C extend, bit by bit (complement-in/out)."""
    crc ^= 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = _step(crc)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


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


def verify(data):
    """Authenticate the binary and check every pinned byte of the packet."""
    authenticate(data)
    secs = unique_sections(data)
    if secs['.text']['address'] != 0x1419300 or secs['.rodata']['address'] != 0x430400:
        raise ValueError('unexpected section layout')
    extent = fde_extent(data, FUNCTION_START)
    if extent != (FUNCTION_START, FUNCTION_END):
        raise ValueError(f'FDE extent mismatch: {extent}')
    update_extent = fde_extent(data, UPDATE_START)
    if update_extent != (UPDATE_START, UPDATE_END):
        raise ValueError(f'Update FDE extent mismatch: {update_extent}')
    if be32_pack(0xE3069283) != b'\xe3\x06\x92\x83':
        raise ValueError('big-endian check value mismatch')
    if be32_bswap(0xE3069283) != b'\xe3\x06\x92\x83':
        raise ValueError('bswap check value mismatch')
    if extend_bitwise(0, b'123456789') != 0xE3069283:
        raise ValueError('bitwise extend check value mismatch')
    if not guard_allows(MAX_SIZE - 4) or guard_allows(MAX_SIZE - 3):
        raise ValueError('length-guard boundary mismatch')
    checked = {
        'window_hashes': window_hashes(data, secs),
        'body_hash': body_hash(data, secs, FUNCTION_START, FUNCTION_END),
        'update_hash': body_hash(data, secs, UPDATE_START, UPDATE_END),
        'extend_stub_hash': body_hash(data, secs, EXTEND_STUB, EXTEND_STUB_END),
        'append_plt_hash': body_hash(data, secs, APPEND_PLT, APPEND_PLT_END),
        'sections': secs,
    }
    if checked['body_hash'] != CENSUS_BODY['function']:
        raise ValueError('body hash does not match the census')
    return checked


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic (crc, prior) cases: boundary priors, then random.

    Prior lengths cover the std::string SSO boundary (15/16) and long
    inputs; crc words cover 0, all-ones, the known CRC32C vector
    0xe3069283 and the Mask constant 0xa282ead8. Prior bytes are capped
    at 1024 so every sampled case fits in cases.tsv in full.
    """
    rng = random.Random(seed)
    cases = []
    for length in BOUNDARY_LENGTHS:
        prior = bytes(rng.randrange(256) for _ in range(length))
        for crc in STRUCTURED_CRCS:
            cases.append((crc, prior))
    while len(cases) < count:
        crc = rng.randrange(0, 1 << 32)
        length = rng.choice((0, 1, 2, 3, 4, 5, 15, 16, 17, 31, 32,
                             rng.randrange(0, 65), rng.randrange(0, 1025)))
        prior = bytes(rng.randrange(256) for _ in range(length))
        cases.append((crc, prior))
    return cases[:count]


def run_cases(cases):
    """Run the model against the independent reference; return rows."""
    rows = []
    for crc, prior in cases:
        out = finalize(crc, prior)
        ref = finalize_reference(crc, prior)
        if out != ref:
            raise ValueError(
                f'model disagrees with the reference for crc {crc:#010x}, '
                f'prior len {len(prior)}')
        rows.append((crc, prior, out))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for crc, prior, out in rows:
        hasher.update(struct.pack('<I', crc))
        hasher.update(struct.pack('<Q', len(prior)))
        hasher.update(prior)
        hasher.update(out)
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

    # cases.tsv keeps the first 64 rows (all boundary priors for the
    # first structured crc words); the full 2400-case run is summarised
    # in result.json by its aggregate digest.
    sample = rows[:64]
    with (dest / 'cases.tsv').open('w', encoding='utf-8') as handle:
        handle.write('idx\tcrc\tprior_len\tprior_hex\tout_hex\n')
        for idx, (crc, prior, out) in enumerate(sample):
            handle.write(f"{idx}\t{crc:#010x}\t{len(prior)}\t"
                         f"{prior.hex()}\t{out.hex()}\n")

    long_prior = bytes(0xAB for _ in range(1024))
    check_values = {
        'crc32c_vector_empty_prior': {
            'crc': '0xe3069283', 'prior_hex': '',
            'out_hex': finalize(0xE3069283, b'').hex(),
            'note': 'BE32 of the known CRC32C vector for b"123456789"'},
        'zero_crc_abc_prior': {
            'crc': '0x00000000', 'prior_hex': b'abc'.hex(),
            'out_hex': finalize(0, b'abc').hex(),
            'note': 'four zero bytes appended after the prior bytes'},
        'mask_constant_empty_prior': {
            'crc': '0xa282ead8', 'prior_hex': '',
            'out_hex': finalize(0xA282EAD8, b'').hex(),
            'note': 'the Mask constant itself, byte-swapped only'},
        'prefix_12345678': {
            'crc': '0x12345678', 'prior_hex': b'prefix'.hex(),
            'out_hex': finalize(0x12345678, b'prefix').hex()},
        'end_to_end_update_then_finalize': {
            'data_hex': b'123456789'.hex(),
            'crc': '0xe3069283',
            'out_hex': finalize(extend_bitwise(0, b'123456789'), b'').hex(),
            'note': 'Update accumulates extend(0, data) = 0xe3069283; '
                    'Finalize then appends its big-endian form'},
        'long_prior_1024_ab': {
            'crc': '0x12345678', 'prior': '1024 bytes of 0xab',
            'out_tail_hex': finalize(0x12345678, long_prior)[-4:].hex(),
            'note': 'only the appended tail differs from the prior'},
        'guard_boundary_allowed': {
            'prior_len': f'{MAX_SIZE - 4:#x}',
            'allowed': guard_allows(MAX_SIZE - 4),
            'note': 'append runs when length == max_size - 4'},
        'guard_boundary_throws': {
            'prior_len': f'{MAX_SIZE - 3:#x}',
            'allowed': guard_allows(MAX_SIZE - 3),
            'note': 'append throws when length == max_size - 3'},
    }
    result = {
        'target_digest': DIGEST,
        'function': {'start': f'{FUNCTION_START:#x}', 'end': f'{FUNCTION_END:#x}',
                     'body_sha256': checked['body_hash'],
                     'fde': [f'{FUNCTION_START:#x}', f'{FUNCTION_END:#x}'],
                     'census_symbol': 'rocksdb::FileChecksumGenCrc32c::Finalize',
                     'census_body_sha256': checked['body_hash']},
        'layout': {'vtable_address_point': '0x64d7970', 'vtable_slot': 3,
                   'vptr': '+0x0', 'crc_accumulator_u32': '+0x8',
                   'checksum_string': '+0x10 (ptr +0x10, length +0x18, '
                                      'SSO buffer/capacity +0x20)',
                   'object_size': '0x30'},
        'semantics': 'append BE32(crc at +0x8) to the std::string at +0x10; '
                     'throw length_error when len > max_size - 4; '
                     'no Mask/Unmask rotate or add',
        'append_call': {'plt': [f'{APPEND_PLT:#x}', f'{APPEND_PLT_END:#x}'],
                        'plt_sha256': checked['append_plt_hash'],
                        'target': 'std::__cxx11::basic_string::_M_append'
                                  '(const char*, size_t)',
                        'args': 'this = object+0x10, data = stack word, '
                                'n = 4'},
        'update': {'start': f'{UPDATE_START:#x}', 'end': f'{UPDATE_END:#x}',
                   'body_sha256': checked['update_hash'],
                   'semantics': 'crc at +0x8 = extend(crc at +0x8, data, n) '
                                'through the PLT stub',
                   'extend_stub': [f'{EXTEND_STUB:#x}', f'{EXTEND_STUB_END:#x}'],
                   'extend_stub_sha256': checked['extend_stub_hash'],
                   'fnptr_slot': f'{FNPTR_SLOT:#x}',
                   'extend_target': '0x61c21d0 '
                                    '(rocksdb::crc32c::ExtendImpl<Slow_CRC32>)'},
        'length_guard': {'max_size': f'{MAX_SIZE:#x}',
                         'throws_when': '(max_size - len) <= 3',
                         'throw_target': f'{THROW_LENGTH_ERROR_PLT:#x} '
                                         '(__throw_length_error)'},
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
             'identity': 'rocksdb::FileChecksumGenCrc32c::Finalize '
                         '(vendor census)',
             'contract': 'finalize(this) -> void; appends to this->checksum_',
             'semantics': 'append BE32(u32 at +0x8) to the std::string at '
                          '+0x10; throw length_error when its length exceeds '
                          'max_size - 4; no Mask/Unmask step'},
            {'kind': 'layout', 'subject': 'FileChecksumGenCrc32c object',
             'vptr': '+0x0', 'crc_accumulator_u32': '+0x8',
             'checksum_string': '+0x10',
             'observation': 'Update (0x61cd1a0) reads/writes the u32 at +0x8 '
                            'as the extend seed/result; the factory '
                            '(0x61cd2e0) zeroes it and initialises the '
                            'string at +0x10 with length 0 and SSO buffer '
                            'at +0x20; the object is 0x30 bytes'},
            {'kind': 'bswap', 'address': '0x61cd1d9',
             'observation': 'the crc word is byte-swapped (bswap eax) and '
                            'the 4 stack bytes are appended in memory order, '
                            'so the appended bytes are big-endian; this is '
                            'not the little-endian PutFixed32 used elsewhere '
                            'in RocksDB'},
            {'kind': 'no_mask', 'address': f'{FUNCTION_START:#x}',
             'observation': 'no rotate and no add of 0xa282ead8 occurs in '
                            'the body; unlike ComputeBuiltinChecksum '
                            '(0x616bca0, PR #5413), Finalize does not Mask or '
                            'Unmask the accumulator -- the checksum string '
                            'holds the raw CRC32C, byte-swapped only'},
            {'kind': 'guard', 'address': '0x61cd1df',
             'max_size': f'{MAX_SIZE:#x}',
             'observation': 'throw length_error iff (max_size - len) <= 3; '
                            'the append runs exactly when len <= max_size - 4'},
            {'kind': 'append_call', 'plt': f'{APPEND_PLT:#x}',
             'plt_sha256': checked['append_plt_hash'],
             'target': 'std::__cxx11::basic_string::_M_append'
                       '(const char*, size_t)',
             'observation': 'single call, this = object+0x10, n = 4'},
            {'kind': 'update_call', 'address': f'{UPDATE_START:#x}',
             'end': f'{UPDATE_END:#x}',
             'body_sha256': checked['update_hash'],
             'stub': f'{EXTEND_STUB:#x}',
             'stub_sha256': checked['extend_stub_hash'],
             'fnptr_slot': f'{FNPTR_SLOT:#x}',
             'observation': 'Update calls the registered extend once '
                            'through the PLT stub at 0x61c25f0, which jumps '
                            'through the .bss slot at 0x6508908; the '
                            'initializer at 0x61c26d0 stores 0x61c21d0 there; '
                            'Update is not in the vendor census, so its body '
                            'hash is recorded from the binary only'},
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'aggregate_sha256': aggregate,
             'mismatches_vs_reference': 0,
             'note': 'each case cross-checked against an independent '
                     'implementation (struct.pack big-endian vs manual '
                     'byte-swap + bytearray extend); the binary itself was '
                     'never executed'},
            {'kind': 'unknown', 'subject': 'callers of Finalize',
             'status': 'no caller census was run for this packet'},
            {'kind': 'unknown', 'subject': 'Reset method',
             'status': 'the 6-slot vtable has no Reset entry (slots are '
                       'D1, D0, Update, Finalize, GetChecksum, Name); '
                       'whether Reset exists as a non-virtual or was removed '
                       'is not determined from this packet'},
            {'kind': 'unknown', 'subject': 'GetChecksum before Finalize',
             'status': 'GetChecksum (slot 4, 0x61cd510) copies the string '
                       'at +0x10; what it returns before any Finalize call '
                       '(empty string) was not verified against a caller'},
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
              f"finalize(0xe3069283, b'') = "
              f"{finalize(0xE3069283, b'').hex()}; "
              f"finalize(0, b'abc') = {finalize(0, b'abc').hex()}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
