#!/usr/bin/env python3
"""Reconstruct the node #115 FileChecksumGenCrc32c GetChecksum behaviour.

Bounded question (RE-002): what does the function at 0x61cd510 do with
the FileChecksumGenCrc32c object, and which bytes in the node #115 binary
pin that behaviour?

Observed answer, from the disassembly of work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* The function is vtable slot 4 of FileChecksumGenCrc32c (address point
  0x64d7970; the vtable itself was reconstructed in the merged packet
  research/work-items/RE-002-node115-rocksdb-checksum-vtable/). The
  vendor census records this address as
  ``node115-vendor-61cd510``: "one of 2 identical bodies, e.g.
  _ZNK7rocksdb11Transaction7GetNameB5cxx11Ev", and the body SHA-256 below
  matches the census target_body_sha256 (also recorded in
  research/byte-windows.json). The FDE is 0x61cd510..0x61cd5c4.
* It returns the generator's checksum string by value: the hidden
  return-storage pointer arrives in rdi and ``this`` in rsi. That is
  the only reading consistent with the body -- ``mov %rdi,(%rbx)``
  stores ``rdi+0x10`` into the storage object, which would clobber the
  vptr if rdi were ``this``; the length and pointer are read from
  ``[rsi+0x18]`` and ``[rsi+0x10]``, i.e. the std::string member at
  ``this+0x10`` (``checksum_``); and the function returns the storage
  pointer in rax. An out-pointer ``void GetChecksum(string*)`` form
  would read the *caller's* length and overwrite the vptr, so it is
  ruled out by the bytes.
* The copy itself is the std::string SSO copy: length 0 stores an
  empty string (length 0, NUL at the SSO buffer); length 1 copies one
  byte; lengths 2..15 memcpy the bytes into the SSO buffer at
  ``out+0x10``; length > 15 calls
  ``std::__cxx11::basic_string::_M_create`` (PLT 0x63f0e10) and then
  ``memcpy`` (PLT 0x63f0a60) into the heap buffer. Every path stores
  the length at ``out+0x8`` and a NUL terminator after the last byte.
* Object layout, read off the sibling methods: vptr at +0x0; a u32
  accumulator at +0x8 (Update at 0x61cd1a0 reads it as the extend seed
  and stores the result back; the factory at 0x61cd2e0 zeroes it); a
  std::string at +0x10 (pointer +0x10, length +0x18, SSO buffer/capacity
  +0x20). The object is 0x30 bytes.
* The body keeps the usual stack canary (fs:0x28, checked before the
  return; mismatch calls ``__stack_chk_fail`` at 0x63f0d70). The canary
  is an environment detail, not part of the modelled behaviour.

The Python model below implements the copy twice independently (an
explicit length-branch transliteration vs a plain byte copy) and
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

TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-file-checksum-get-checksum-115'
FUNCTION_START = 0x61CD510
FUNCTION_END = 0x61CD5C4
CREATE_PLT = 0x63F0E10
CREATE_PLT_END = 0x63F0E20
MEMCPY_PLT = 0x63F0A60
MEMCPY_PLT_END = 0x63F0A70
STACK_CHK_FAIL_PLT = 0x63F0D70
STACK_CHK_FAIL_PLT_END = 0x63F0D80
CASE_COUNT = 2400
CASE_SEED = 20261109

# Census body hash for GetChecksum
# (research/work-items/RE-002-node115-vendor-census/census.json and
# research/byte-windows.json, id node115-vendor-61cd510).
CENSUS_BODY = {
    'function': '1454dfd1b600941130fbbd7f637e0b279b1dd9ad62d01146458f985428943055',
}

# (label, start, end) of the byte-checked instruction windows. The
# seven GetChecksum windows tile 0x61cd510..0x61cd5c4 exactly; the three
# PLT windows pin the calls the body makes.
WINDOWS = (
    ('prologue_canary', FUNCTION_START, 0x61CD537),
    ('copy_setup', 0x61CD537, 0x61CD548),
    ('len_one_path', 0x61CD548, 0x61CD57A),
    ('align_nop', 0x61CD57A, 0x61CD580),
    ('len_zero_path', 0x61CD580, 0x61CD590),
    ('heap_alloc_path', 0x61CD590, 0x61CD5AB),
    ('memcpy_epilogue', 0x61CD5AB, 0x61CD5BF),
    ('stack_fail_path', 0x61CD5BF, 0x61CD5C4),
    ('create_plt', CREATE_PLT, CREATE_PLT_END),
    ('memcpy_plt', MEMCPY_PLT, MEMCPY_PLT_END),
    ('stack_chk_fail_plt', STACK_CHK_FAIL_PLT, STACK_CHK_FAIL_PLT_END),
)

BOUNDARY_LENGTHS = (0, 1, 2, 3, 4, 5, 15, 16, 17, 31, 32, 100, 1024)
STRUCTURED_CONTENTS = (
    b'',
    b'a',
    b'ab',
    bytes(range(15)),
    bytes(range(16)),
    bytes(range(17)),
    b'\xe3\x06\x92\x83',
    b'FileChecksumCrc32c',
    b'123456789',
    bytes(32),
    bytes([0xFF]) * 32,
    bytes([0xAB]) * 1024,
)


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


# --- std::string copy, as the binary performs it ---

def copy_string(source):
    """Model of GetChecksum: copy the checksum_ string, branch by length.

    Length 0 stores an empty string; length 1 copies one byte; lengths
    2..15 copy into the SSO buffer; length > 15 goes through the heap
    (_M_create + memcpy) path. Every path yields exactly the source
    bytes, with the length stored and a NUL terminator after them.
    """
    length = len(source)
    if length == 0:
        return b''
    if length == 1:
        return bytes([source[0]])
    if length <= 15:
        out = bytearray(16)
        out[:length] = source
        return bytes(out[:length])
    out = bytearray(length)
    out[:length] = source
    return bytes(out)


def copy_string_reference(source):
    """Independent reference: a plain byte copy of the source."""
    return bytes(bytearray(source))


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
    if copy_string(b'') != b'':
        raise ValueError('empty copy check value mismatch')
    if copy_string(b'a') != b'a':
        raise ValueError('one-byte copy check value mismatch')
    if copy_string(bytes(range(15))) != bytes(range(15)):
        raise ValueError('SSO-boundary copy check value mismatch')
    if copy_string(bytes(range(16))) != bytes(range(16)):
        raise ValueError('heap-path copy check value mismatch')
    if copy_string(b'\xe3\x06\x92\x83') != b'\xe3\x06\x92\x83':
        raise ValueError('finalize-output copy check value mismatch')
    checked = {
        'window_hashes': window_hashes(data, secs),
        'body_hash': body_hash(data, secs, FUNCTION_START, FUNCTION_END),
        'create_plt_hash': body_hash(data, secs, CREATE_PLT, CREATE_PLT_END),
        'memcpy_plt_hash': body_hash(data, secs, MEMCPY_PLT, MEMCPY_PLT_END),
        'stack_chk_fail_plt_hash': body_hash(
            data, secs, STACK_CHK_FAIL_PLT, STACK_CHK_FAIL_PLT_END),
        'sections': secs,
    }
    if checked['body_hash'] != CENSUS_BODY['function']:
        raise ValueError('body hash does not match the census')
    return checked


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic source-string cases: structured contents, boundary
    lengths (including the std::string SSO boundary at 15/16), then
    random pairs. Sources are capped at 1024 bytes so every sampled
    case fits in cases.tsv in full.
    """
    rng = random.Random(seed)
    cases = list(STRUCTURED_CONTENTS)
    for length in BOUNDARY_LENGTHS:
        cases.append(bytes(rng.randrange(256) for _ in range(length)))
    while len(cases) < count:
        length = rng.choice((0, 1, 2, 3, 4, 5, 15, 16, 17, 31, 32,
                             rng.randrange(0, 65), rng.randrange(0, 1025)))
        cases.append(bytes(rng.randrange(256) for _ in range(length)))
    return cases[:count]


def run_cases(cases):
    """Run the model against the independent reference; return rows."""
    rows = []
    for source in cases:
        out = copy_string(source)
        ref = copy_string_reference(source)
        if out != ref:
            raise ValueError(
                f'model disagrees with the reference for source len '
                f'{len(source)}')
        rows.append((source, out))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for source, out in rows:
        hasher.update(struct.pack('<Q', len(source)))
        hasher.update(source)
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

    # cases.tsv keeps the first 64 rows (all structured contents and
    # boundary lengths); the full 2400-case run is summarised in
    # result.json by its aggregate digest.
    sample = rows[:64]
    with (dest / 'cases.tsv').open('w', encoding='utf-8') as handle:
        handle.write('idx\tsource_len\tsource_hex\tout_hex\n')
        for idx, (source, out) in enumerate(sample):
            handle.write(f"{idx}\t{len(source)}\t{source.hex()}\t"
                         f"{out.hex()}\n")

    sso_max = bytes(range(15))
    heap_min = bytes(range(16))
    long_source = bytes(0xAB for _ in range(1024))
    check_values = {
        'empty': {
            'source_hex': '', 'out_hex': copy_string(b'').hex(),
            'note': 'length 0 stores an empty string (NUL at the SSO buffer)'},
        'one_byte': {
            'source_hex': b'a'.hex(), 'out_hex': copy_string(b'a').hex(),
            'note': 'length 1 copies a single byte, then the NUL terminator'},
        'sso_max_15': {
            'source_hex': sso_max.hex(),
            'out_hex': copy_string(sso_max).hex(),
            'note': 'length 15 is the longest SSO copy (no allocation)'},
        'heap_min_16': {
            'source_hex': heap_min.hex(),
            'out_hex': copy_string(heap_min).hex(),
            'note': 'length 16 takes the _M_create + memcpy heap path'},
        'finalize_output_round_trip': {
            'source_hex': b'\xe3\x06\x92\x83'.hex(),
            'out_hex': copy_string(b'\xe3\x06\x92\x83').hex(),
            'note': 'the Finalize output (BE32 of 0xe3069283) copies back unchanged'},
        'name_round_trip': {
            'source_hex': b'FileChecksumCrc32c'.hex(),
            'out_hex': copy_string(b'FileChecksumCrc32c').hex(),
            'note': 'the 18-byte generator name (heap path) copies back unchanged'},
        'long_source_1024_ab': {
            'source': '1024 bytes of 0xab',
            'out_tail_hex': copy_string(long_source)[-4:].hex(),
            'note': 'only the copied bytes differ from nothing; the copy is exact'},
        'end_to_end_update_finalize_get': {
            'data_hex': b'123456789'.hex(),
            'crc': '0xe3069283',
            'finalize_out_hex': b'\xe3\x06\x92\x83'.hex(),
            'get_out_hex': copy_string(b'\xe3\x06\x92\x83').hex(),
            'note': 'Update accumulates extend(0, data) = 0xe3069283; '
                    'Finalize appends its big-endian form; GetChecksum '
                    'returns those same 4 bytes'},
    }
    result = {
        'target_digest': DIGEST,
        'function': {'start': f'{FUNCTION_START:#x}', 'end': f'{FUNCTION_END:#x}',
                     'body_sha256': checked['body_hash'],
                     'fde': [f'{FUNCTION_START:#x}', f'{FUNCTION_END:#x}'],
                     'census_symbol': 'rocksdb::FileChecksumGenCrc32c::GetChecksum',
                     'census_id': 'node115-vendor-61cd510',
                     'census_body_sha256': checked['body_hash'],
                     'census_note': 'one of 2 identical bodies, e.g. '
                                    '_ZNK7rocksdb11Transaction7GetNameB5cxx11Ev'},
        'layout': {'vtable_address_point': '0x64d7970', 'vtable_slot': 4,
                   'vptr': '+0x0', 'crc_accumulator_u32': '+0x8',
                   'checksum_string': '+0x10 (ptr +0x10, length +0x18, '
                                      'SSO buffer/capacity +0x20)',
                   'object_size': '0x30'},
        'semantics': 'return a copy of the std::string at +0x10 '
                     '(checksum_): length 0 -> empty; length 1 -> one byte; '
                     'lengths 2..15 -> SSO memcpy; length > 15 -> '
                     '_M_create + memcpy; NUL terminator after the last byte',
        'abi': {'return': 'std::string by value (hidden return-storage '
                          'pointer in rdi, this in rsi)',
                'evidence': 'mov %rdi,(%rbx) stores rdi+0x10 into the '
                            'storage object (would clobber the vptr if rdi '
                            'were this); length/pointer read from '
                            '[rsi+0x18]/[rsi+0x10], i.e. this+0x18/+0x10; '
                            'rax returns the storage pointer'},
        'sso_threshold': {'cmp': 'cmp $0xf,%rbp at 0x61cd542',
                          'heap_when': 'length > 15'},
        'heap_alloc_call': {'plt': [f'{CREATE_PLT:#x}', f'{CREATE_PLT_END:#x}'],
                            'plt_sha256': checked['create_plt_hash'],
                            'target': 'std::__cxx11::basic_string::_M_create'
                                      '(size_type&, size_type)',
                            'args': 'this = out, capacity slot on the stack, '
                                    'old capacity 0'},
        'memcpy_call': {'plt': [f'{MEMCPY_PLT:#x}', f'{MEMCPY_PLT_END:#x}'],
                        'plt_sha256': checked['memcpy_plt_hash'],
                        'target': 'memcpy',
                        'args': 'dst = out buffer, src = [rsi+0x10], n = length'},
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
             'identity': 'rocksdb::FileChecksumGenCrc32c::GetChecksum '
                         '(vtable slot 4; vendor census: one of 2 identical '
                         'bodies, e.g. '
                         '_ZNK7rocksdb11Transaction7GetNameB5cxx11Ev)',
             'contract': 'get_checksum(this) -> std::string; returns a copy '
                         'of this->checksum_',
             'semantics': 'copy the std::string at +0x10 into the caller\'s '
                          'return storage; SSO for length <= 15, heap '
                          '(_M_create + memcpy) above; NUL terminator after '
                          'the last byte'},
            {'kind': 'abi', 'address': f'{FUNCTION_START:#x}',
             'observation': 'by-value std::string return: hidden return '
                            'pointer in rdi, this in rsi; [rbx] = rdi+0x10 '
                            'stores the SSO pointer into the return storage, '
                            'and rax returns that storage pointer. The '
                            'out-pointer void form is ruled out: it would '
                            'read the caller\'s length and overwrite the vptr'},
            {'kind': 'layout', 'subject': 'FileChecksumGenCrc32c object',
             'vptr': '+0x0', 'crc_accumulator_u32': '+0x8',
             'checksum_string': '+0x10',
             'observation': 'Update (0x61cd1a0) reads/writes the u32 at +0x8 '
                            'as the extend seed/result; Finalize (0x61cd1c0) '
                            'appends BE32(crc) to the string at +0x10; the '
                            'factory (0x61cd2e0) zeroes the accumulator and '
                            'initialises the string with length 0 and SSO '
                            'buffer at +0x20; the object is 0x30 bytes'},
            {'kind': 'sso_threshold', 'address': '0x61cd542',
             'observation': 'cmp $0xf,%rbp; lengths above 15 jump to the '
                            'heap path at 0x61cd590, lengths 0..15 stay in the '
                            'SSO buffer at out+0x10'},
            {'kind': 'len_one_path', 'address': '0x61cd548',
             'observation': 'length 1 copies a single byte with movzbl '
                            '(%r12),%eax then mov %al,0x10(%rbx); length 0 '
                            'skips the copy at 0x61cd580..0x61cd585'},
            {'kind': 'heap_call', 'plt': f'{CREATE_PLT:#x}',
             'plt_sha256': checked['create_plt_hash'],
             'target': 'std::__cxx11::basic_string::_M_create',
             'observation': 'single call on the length > 15 path, this = out, '
                            'capacity slot on the stack, old capacity 0; the '
                            'returned pointer is stored at [out] and the '
                            'capacity at [out+0x10]'},
            {'kind': 'memcpy_call', 'plt': f'{MEMCPY_PLT:#x}',
             'plt_sha256': checked['memcpy_plt_hash'],
             'target': 'memcpy',
             'observation': 'copies length bytes from [rsi+0x10] (the '
                            'checksum_ pointer) into the out buffer on both '
                            'the SSO (2..15) and heap (> 15) paths'},
            {'kind': 'identical_body', 'address': f'{FUNCTION_START:#x}',
             'observation': 'the vendor census records this address as one '
                            'of 2 identical bodies (e.g. '
                            'Transaction::GetName); the name attribution for '
                            'this instance rests on vtable slot 4 of '
                            'FileChecksumGenCrc32c and on the copy of the '
                            'string at +0x10, not on a unique body'},
            {'kind': 'sibling', 'address': '0x61cd020',
             'end': '0x61cd02c',
             'observation': 'Name (slot 5) returns the pointer at 0x43336e, '
                            'the string "FileChecksumCrc32c" (inference from '
                            'its 12-byte body: endbr64; lea 0x43336e(%rip),%rax; '
                            'ret); not modelled here'},
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'aggregate_sha256': aggregate,
             'mismatches_vs_reference': 0,
             'note': 'each case cross-checked against an independent '
                     'implementation (explicit length-branch transliteration '
                     'vs plain byte copy); the binary itself was never '
                     'executed'},
            {'kind': 'unknown', 'subject': 'callers of GetChecksum',
             'status': 'no caller census was run for this packet'},
            {'kind': 'unknown', 'subject': 'GetChecksum before Finalize',
             'status': 'returns the current checksum_ string, which is empty '
                       'until Finalize appends; no caller was verified'},
            {'kind': 'unknown', 'subject': 'identical-body twin',
             'status': 'the census lists a second function with this exact '
                       'body (e.g. Transaction::GetName); which other call '
                       'sites share it was not traced'},
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
              f"copy(b'') = {copy_string(b'').hex()!r}; "
              f"copy(b'a') = {copy_string(b'a').hex()!r}; "
              f"copy(16 bytes) = {copy_string(bytes(range(16))).hex()!r}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
