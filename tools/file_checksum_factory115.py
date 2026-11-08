#!/usr/bin/env python3
"""Reconstruct the node #115 FileChecksumGenCrc32cFactory behaviour.

Bounded question (RE-002): what does the function at 0x61cd2e0 do --
which requested checksum names make it create a FileChecksumGenCrc32c
generator, and how is the new object initialised?

Observed answer, from the disassembly of work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* The function is the vendor-census entry
  ``_ZN7rocksdb28FileChecksumGenCrc32cFactory27CreateFileChecksumGeneratorERKNS_22FileChecksumGenContextE``
  (librocksdb-sys). The census pins its body exactly to the FDE
  0x61cd2e0..0x61cd36f, and the body SHA-256 below matches the census
  target_body_sha256 (also recorded in research/byte-windows.json).
  It is vtable slot 19 of FileChecksumGenCrc32cFactory (address point
  0x64d79b0; the factory vtable itself was reconstructed in the merged
  packet research/work-items/RE-002-node115-rocksdb-checksum-factory-vtable/).
* The result is returned through a hidden out-pointer (rdi): the
  function stores the new generator pointer, or null, at [rdi] and
  returns rdi. rdx is the FileChecksumGenContext pointer; the requested
  name is the std::string at context+0x20 (data pointer +0x20, length
  +0x28, SSO buffer +0x30).
* Name gate, read off the control flow:
  - length 0 -> create (the empty-name path jumps straight to the
    allocation at 0x61cd334, skipping the byte compare);
  - length 0x12 (18) and all 18 bytes equal "FileChecksumCrc32c" ->
    create;
  - anything else -> store null and return.
  The 18-byte compare is two 8-byte xor/or steps against the movabs
  immediates "FileChec" and "ksumCrc3", then a 2-byte compare against
  "2c" (cmpw $0x6332 at 0x61cd32c).
* Creation: ``operator new(0x30)`` through the PLT entry at 0x63f0dd0,
  then the object is initialised: vptr = 0x64d7970 (the
  FileChecksumGenCrc32c vtable address point, the same point the
  Finalize packet pins), crc_ u32 at +0x8 = 0, checksum_ std::string
  at +0x10 with pointer object+0x20 (SSO), length 0 at +0x18 and a NUL
  first byte at +0x20. The object is 0x30 bytes, matching the layout
  the Finalize (0x61cd1c0) and Update (0x61cd1a0) packets read off the
  sibling methods.
* The function has no stack canary and makes no other call.

The Python model below implements the name gate twice independently
(a transliteration of the two-word xor compare vs a plain equality
check) and cross-checks them on 2400 deterministic cases. The node
binary is never executed.
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
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-file-checksum-factory-115'
FUNCTION_START = 0x61CD2E0
FUNCTION_END = 0x61CD36F
NEW_PLT = 0x63F0DD0
NEW_PLT_END = 0x63F0DE0
VTABLE_ADDRESS_POINT = 0x64D7970
OBJECT_SIZE = 0x30
EXPECTED_NAME = b'FileChecksumCrc32c'
NAME_LENGTH = 0x12
CASE_COUNT = 2400
CASE_SEED = 20261109

# The name-compare immediates, as they appear in the binary:
# movabs $0x63656843656c6946 ("FileChec"), movabs $0x336372436d75736b
# ("ksumCrc3"), cmpw $0x6332 ("2c").
WORD0 = 0x63656843656C6946
WORD1 = 0x336372436D75736B
TAIL = 0x6332

# Census body hash for CreateFileChecksumGenerator
# (research/work-items/RE-002-node115-vendor-census/census.json and
# research/byte-windows.json).
CENSUS_BODY = {
    'function': '469590278ff13b8ed347c4085fc75e93a54c8c18fecbbff38b086c2f92fc22cb',
}

# (label, start, end) of the byte-checked instruction windows. The six
# body windows tile 0x61cd2e0..0x61cd36f exactly; the PLT window pins
# the allocation call the body makes.
WINDOWS = (
    ('gate_load', FUNCTION_START, 0x61CD2F1),
    ('gate_length', 0x61CD2F1, 0x61CD2F7),
    ('null_return', 0x61CD2F7, 0x61CD308),
    ('name_compare', 0x61CD308, 0x61CD334),
    ('create_alloc', 0x61CD334, 0x61CD33E),
    ('create_init', 0x61CD33E, 0x61CD36F),
    ('new_plt', NEW_PLT, NEW_PLT_END),
)

# Structured names: the exact name, the empty name, every truncation,
# every one-byte extension, a case flip, and one wrong byte at each
# position (three replacement values each).
STRUCTURED_NAMES = [b'', EXPECTED_NAME]
STRUCTURED_NAMES += [EXPECTED_NAME[:n] for n in range(0, 18)]
STRUCTURED_NAMES += [EXPECTED_NAME + b'x', EXPECTED_NAME + b'\x00',
                     EXPECTED_NAME + b'c']
STRUCTURED_NAMES.append(EXPECTED_NAME.lower())
STRUCTURED_NAMES.append(EXPECTED_NAME.upper())
STRUCTURED_NAMES.append(b'FileChecksumCrc32d')
STRUCTURED_NAMES.append(b'FileChecksumCrc32')
STRUCTURED_NAMES.append(b'FileChecksumCrc32cc')
for pos in range(18):
    for repl in (0x00, 0x78, EXPECTED_NAME[pos] ^ 0x20):
        mutated = bytearray(EXPECTED_NAME)
        mutated[pos] = repl
        STRUCTURED_NAMES.append(bytes(mutated))


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


# --- Name gate: model (transliteration) vs reference (plain) ---

def name_matches_model(name):
    """The binary's gate, transliterated: two u64 xor/or steps + u16.

    Length 0 creates (the empty-name jump skips the compare); length
    18 creates only when both 8-byte words and the trailing 2 bytes
    equal the immediates; any other length returns null.
    """
    if len(name) == 0:
        return True
    if len(name) != NAME_LENGTH:
        return False
    word0 = struct.unpack('<Q', name[0:8])[0]
    word1 = struct.unpack('<Q', name[8:16])[0]
    if (word0 ^ WORD0) | (word1 ^ WORD1):
        return False
    tail = struct.unpack('<H', name[16:18])[0]
    return tail == TAIL


def name_matches_reference(name):
    """Independent reference: plain length + equality check."""
    if len(name) == 0:
        return True
    return name == EXPECTED_NAME


def create(name):
    """Model of CreateFileChecksumGenerator: True iff a generator is made."""
    return name_matches_model(name)


def init_object():
    """The initialised object fields, as the create_init window stores them.

    Values are the constants the binary writes: vptr from lea+add
    (0x64d7960 + 0x10), crc_ = 0, string pointer = object+0x20 (SSO),
    string length = 0, first SSO byte = 0.
    """
    return {
        'vptr': VTABLE_ADDRESS_POINT,
        'crc_u32_at_0x8': 0,
        'checksum_string_ptr': 'object+0x20',
        'checksum_string_len_at_0x18': 0,
        'checksum_string_first_byte_at_0x20': 0,
        'object_size': OBJECT_SIZE,
    }


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
    if struct.unpack('<Q', EXPECTED_NAME[0:8])[0] != WORD0:
        raise ValueError('word0 immediate mismatch')
    if struct.unpack('<Q', EXPECTED_NAME[8:16])[0] != WORD1:
        raise ValueError('word1 immediate mismatch')
    if struct.unpack('<H', EXPECTED_NAME[16:18])[0] != TAIL:
        raise ValueError('tail immediate mismatch')
    if not create(b'') or not create(EXPECTED_NAME):
        raise ValueError('accepting check value mismatch')
    if create(b'FileChecksumCrc32') or create(EXPECTED_NAME + b'x'):
        raise ValueError('rejecting check value mismatch')
    checked = {
        'window_hashes': window_hashes(data, secs),
        'body_hash': body_hash(data, secs, FUNCTION_START, FUNCTION_END),
        'new_plt_hash': body_hash(data, secs, NEW_PLT, NEW_PLT_END),
        'sections': secs,
    }
    if checked['body_hash'] != CENSUS_BODY['function']:
        raise ValueError('body hash does not match the census')
    return checked


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Deterministic names: structured near-misses, then random.

    Random names cover lengths 0..40 (the gate boundary 17/18/19, the
    SSO boundary and longer inputs) with random bytes, plus mutations
    of the expected name at a random position.
    """
    rng = random.Random(seed)
    cases = list(STRUCTURED_NAMES)
    while len(cases) < count:
        choice = rng.randrange(4)
        if choice == 0:
            length = rng.choice((0, 1, 2, 17, 18, 19, 32, 40,
                                 rng.randrange(0, 41)))
            name = bytes(rng.randrange(256) for _ in range(length))
        elif choice == 1:
            name = bytearray(EXPECTED_NAME)
            pos = rng.randrange(18)
            name[pos] = rng.randrange(256)
            name = bytes(name)
        elif choice == 2:
            length = rng.randrange(0, 19)
            name = EXPECTED_NAME[:length]
        else:
            length = rng.randrange(18, 41)
            name = EXPECTED_NAME + bytes(rng.randrange(256)
                                         for _ in range(length - 18))
        cases.append(name)
    return cases[:count]


def run_cases(cases):
    """Run the model against the independent reference; return rows."""
    rows = []
    for name in cases:
        out = create(name)
        ref = name_matches_reference(name)
        if out != ref:
            raise ValueError(
                f'model disagrees with the reference for name {name!r}')
        if out and init_object() != {
                'vptr': VTABLE_ADDRESS_POINT, 'crc_u32_at_0x8': 0,
                'checksum_string_ptr': 'object+0x20',
                'checksum_string_len_at_0x18': 0,
                'checksum_string_first_byte_at_0x20': 0,
                'object_size': OBJECT_SIZE}:
            raise ValueError('init layout mismatch')
        rows.append((name, out))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for name, created in rows:
        hasher.update(struct.pack('<Q', len(name)))
        hasher.update(name)
        hasher.update(b'\x01' if created else b'\x00')
    return hasher.hexdigest()


def generate(data, dest):
    """Write the evidence packet files into dest (deterministic)."""
    checked = verify(data)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    cases = generate_cases()
    rows = run_cases(cases)
    aggregate = case_aggregate(rows)
    created_count = sum(1 for _, created in rows if created)

    with (dest / 'windows.tsv').open('w', encoding='utf-8') as handle:
        handle.write('label\tstart\tend\tbytes\tsha256\n')
        for label, start, end in WINDOWS:
            handle.write(f"{label}\t{start:#x}\t{end:#x}\t{end - start}"
                         f"\t{checked['window_hashes'][label]}\n")

    # cases.tsv keeps the first 64 rows (all structured names); the
    # full 2400-case run is summarised in result.json by its aggregate
    # digest.
    sample = rows[:64]
    with (dest / 'cases.tsv').open('w', encoding='utf-8') as handle:
        handle.write('idx\tname_len\tname_hex\tcreated\n')
        for idx, (name, created) in enumerate(sample):
            handle.write(f"{idx}\t{len(name)}\t{name.hex()}\t"
                         f"{'1' if created else '0'}\n")

    check_values = {
        'empty_name_creates': {
            'name_hex': b''.hex(), 'created': create(b''),
            'note': 'length 0 jumps straight to the allocation'},
        'exact_name_creates': {
            'name_hex': EXPECTED_NAME.hex(), 'created': create(EXPECTED_NAME),
            'note': 'the 18-byte name the factory gates creation on'},
        'one_short_rejected': {
            'name_hex': b'FileChecksumCrc32'.hex(),
            'created': create(b'FileChecksumCrc32'),
            'note': 'length 17 never reaches the byte compare'},
        'one_long_rejected': {
            'name_hex': (EXPECTED_NAME + b'x').hex(),
            'created': create(EXPECTED_NAME + b'x'),
            'note': 'length 19 never reaches the byte compare'},
        'lowercase_rejected': {
            'name_hex': EXPECTED_NAME.lower().hex(),
            'created': create(EXPECTED_NAME.lower()),
            'note': 'the xor compare is case-sensitive'},
        'last_byte_rejected': {
            'name_hex': b'FileChecksumCrc32d'.hex(),
            'created': create(b'FileChecksumCrc32d'),
            'note': 'the trailing cmpw $0x6332 ("2c") fails'},
        'init_layout': init_object(),
    }
    result = {
        'target_digest': DIGEST,
        'function': {'start': f'{FUNCTION_START:#x}', 'end': f'{FUNCTION_END:#x}',
                     'body_sha256': checked['body_hash'],
                     'fde': [f'{FUNCTION_START:#x}', f'{FUNCTION_END:#x}'],
                     'census_symbol': 'rocksdb::FileChecksumGenCrc32cFactory::'
                                      'CreateFileChecksumGenerator',
                     'census_body_sha256': checked['body_hash']},
        'factory_vtable_slot': 19,
        'factory_vtable_address_point': '0x64d79b0',
        'layout': {'vtable_address_point': f'{VTABLE_ADDRESS_POINT:#x}',
                   'vptr': '+0x0', 'crc_accumulator_u32': '+0x8',
                   'checksum_string': '+0x10 (ptr +0x10, length +0x18, '
                                      'SSO buffer/capacity +0x20)',
                   'object_size': f'{OBJECT_SIZE:#x}'},
        'semantics': 'create a FileChecksumGenCrc32c iff the requested '
                     'name is empty or exactly "FileChecksumCrc32c" '
                     '(18 bytes); otherwise return null',
        'name_gate': {'expected_name': EXPECTED_NAME.decode(),
                      'expected_length': NAME_LENGTH,
                      'empty_name_creates': True,
                      'compare': 'two u64 xor/or steps against the movabs '
                                 'immediates "FileChec"/"ksumCrc3", then a '
                                 'u16 compare against "2c"',
                      'context_name': 'std::string at context+0x20 '
                                      '(data +0x20, length +0x28)'},
        'create_alloc': {'plt': [f'{NEW_PLT:#x}', f'{NEW_PLT_END:#x}'],
                         'plt_sha256': checked['new_plt_hash'],
                         'target': 'operator new',
                         'size': f'{OBJECT_SIZE:#x}'},
        'init': init_object(),
        'check_values': check_values,
        'cases': {'count': len(rows), 'seed': CASE_SEED,
                  'created': created_count,
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
             'identity': 'rocksdb::FileChecksumGenCrc32cFactory::'
                         'CreateFileChecksumGenerator (vendor census)',
             'contract': 'create(context) -> FileChecksumGenCrc32c* via a '
                         'hidden out-pointer in rdi; rdx = context',
             'semantics': 'store a new 0x30-byte FileChecksumGenCrc32c at '
                          '[rdi] iff the requested name is empty or exactly '
                          '"FileChecksumCrc32c"; otherwise store null'},
            {'kind': 'layout', 'subject': 'FileChecksumGenCrc32c object',
             'vptr': '+0x0', 'crc_accumulator_u32': '+0x8',
             'checksum_string': '+0x10',
             'observation': 'the factory zeroes crc_ at +0x8, stores the '
                            'vtable address point 0x64d7970 at +0x0, and '
                            'initialises the string at +0x10 with pointer '
                            'object+0x20 (SSO), length 0 and a NUL first '
                            'byte; the object is 0x30 bytes, matching the '
                            'layout the Finalize (0x61cd1c0) and Update '
                            '(0x61cd1a0) packets read off the siblings'},
            {'kind': 'name_gate', 'address': f'{FUNCTION_START:#x}',
             'expected_name': EXPECTED_NAME.decode(),
             'observation': 'length 0 jumps straight to the allocation at '
                            '0x61cd334 (je at 0x61cd2ef); length 0x12 falls '
                            'through to the byte compare at 0x61cd308; any '
                            'other length falls through to the null return '
                            'at 0x61cd2f7'},
            {'kind': 'name_compare', 'address': '0x61cd308',
             'observation': 'two movabs immediates ("FileChec", '
                            '"ksumCrc3") are xored against the name bytes '
                            'and or-ed together; a nonzero result jumps to '
                            'the null return; then cmpw $0x6332 ("2c") '
                            'checks the last two bytes'},
            {'kind': 'create_alloc', 'plt': f'{NEW_PLT:#x}',
             'plt_sha256': checked['new_plt_hash'],
             'target': 'operator new', 'size': f'{OBJECT_SIZE:#x}',
             'observation': 'single call, size 0x30, result in rax'},
            {'kind': 'create_init', 'address': '0x61cd33e',
             'vtable_address_point': f'{VTABLE_ADDRESS_POINT:#x}',
             'observation': 'lea loads 0x64d7960 and add $0x10 gives the '
                            'vtable address point 0x64d7970 (the same point '
                            'the Finalize packet pins); the new pointer is '
                            'stored at [rdi] and rdi is returned in rax'},
            {'kind': 'vtable_slot', 'slot': 19,
             'factory_vtable_address_point': '0x64d79b0',
             'observation': 'the merged factory-vtable packet lists this '
                            'function at slot 19 with the same body hash; '
                            'that packet records the slot only, this packet '
                            'reconstructs the behaviour'},
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'created': created_count,
             'aggregate_sha256': aggregate,
             'mismatches_vs_reference': 0,
             'note': 'each case cross-checked against an independent '
                     'implementation (two-word xor transliteration vs '
                     'plain equality); the binary itself was never executed'},
            {'kind': 'unknown', 'subject': 'callers of '
             'CreateFileChecksumGenerator',
             'status': 'no caller census was run for this packet'},
            {'kind': 'unknown', 'subject': 'empty-name acceptance',
             'status': 'observed: an empty requested name creates a '
                       'generator; whether that is the caller treating an '
                       'empty name as "use the default" or the factory\'s '
                       'own rule is not determined from this packet'},
            {'kind': 'unknown', 'subject': 'GetFileChecksumGenCrc32cFactory',
             'status': 'the singleton getter at 0x61cd600 is not modelled '
                       'here; it is the noted next candidate'},
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
        created = sum(1 for _, c in rows if c)
        print(f"verified: body {checked['body_hash'][:16]}...; "
              f"{len(rows)} cases agree with the references "
              f"({created} create); "
              f"create(b'') = {create(b'')}; "
              f"create(b'FileChecksumCrc32c') = {create(EXPECTED_NAME)}; "
              f"create(b'FileChecksumCrc32') = {create(b'FileChecksumCrc32')}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
