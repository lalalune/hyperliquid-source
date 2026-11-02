#!/usr/bin/env python3
"""Extract node 94 precision-byte transport and its keyed output (static only)."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK = (1 << 64) - 1
# Start, end and digest of each complete FDE-described range. These fingerprints
# bind the semantics of the fixed windows to the complete admitted code body.
FUNCTIONS = (
    ('collector_allocation', 0x2a10590, 0x2a10682, '3185cbfa83f2c1e911f83cb3360b5eb2c6d5c94f9232fff4dadda087b5b2d6e2'),
    ('row_iterator', 0x2a22520, 0x2a2273a, 'e3e49c3fd0aa08ec2d56ae114f9cd0f302e11b4e29b910f7c379a9a7cbc6dff0'),
    ('row_builder', 0x2a2baa0, 0x2a2bcd9, '7826f2bdfe34d88ba5683fa765992615b219be042e25fbe058882cf1bf8e3707'),
    ('keyed_writer', 0x2a2be60, 0x2a2c0e3, '16271773c11cd5f65b0d407b5c1e3254d0a43bf85afbb8bc80a869be3f5c7cd3'),
    ('writer_list', 0x29f6160, 0x29f638e, '715323d54c5e3aa1dbd0c959a0d4ce57c5ba6d5120a9cbc186c19052b6257c6a'),
    ('universe_adapter', 0x29fc340, 0x29fc571, '9fa2865fa1c43372439962cf3243041673d04c3b48cf4c5aa5b7eb174d544485'),
    ('outer_writer', 0x2a2bce0, 0x2a2be57, '58494d599deeb5b6ae1b23ae2f4dc9747f73573c1fd00f26ebc4a726e716db28'),
)
# Exact instruction windows, including opcode and displacements, intentionally
# fail on any byte change rather than accepting a guessed equivalent sequence.
WINDOWS = {
    'identifier_and_input_byte': (0x2a225a0, 'b810270000488b4c243848f761304c894424080f801f0100004889c54c01f50f8222010000420fb6442b2a88442407'),
    'byte_to_builder_argument': (0x2a22635, '420fb7442b284a8b4c2b200fb65424078854247266894424704a8b442b18488944246048894c2468488d7c24784889ee488d542448488b4c2428'),
    'write_and_increment': (0x2a2268e, '488b442418420f11542820420f114c2810420f11042849ffc64c8b44240874484983c53049ffc049ffcf0f85e2feffff488b44'),
    'panic_arms': (0x2a226d8, '488d3d7927cb02ff15cbbad402eb34488d3d6a27cb02ff1524bad402eb2549ffc04c89442408488d3dab26cb02ff150dbad402eb0e'),
    'builder_byte_load': (0x2a2baba, '0fb6422a8844240d488b024889442410488b'),
    'builder_byte_store': (0x2a2bc55, '0fb64c240f84c90fb654240d88532d0fb654240c88532c896b180f954328'),
    'writer_key_and_pointer': (0x2a2bef1, '498d4e2d488d35b03d9ffd488d7c2410ba0a000000e8e534fdff4885c075'),
    'writer_loop': (0x29f6246, '4883c5d0742b4c89ff4c89f6e8095c03004c396c2420743c4c8b6424184c3b6424087596488d7c2408ff15cb99d702eb8948'),
    'iterator_call': (0x2a10634, '488d4424184889f74889c6e8dc1e0100488b442410'),
}
FIELDS = (
    (0x2a2bef5, 'szDecimals', 45, 'always'),
    (0x2a2bf10, 'name', 0, 'always'),
    (0x2a2bf32, 'maxLeverage', 44, 'always'),
    (0x2a2bf51, 'marginTableId', 24, 'always'),
    (0x2a2bf9f, 'onlyIsolated', 40, 'byte_40_nonzero'),
    (0x2a2bfc3, 'isDelisted', 41, 'byte_41_nonzero'),
    (0x2a2bfe7, 'marginMode', 42, 'byte_42_nonzero'),
    (0x2a2c011, 'growthMode', 43, 'byte_43_not_one'),
    (0x2a2c03b, 'lastGrowthModeChangeTime', 28, 'word_28_nonzero'),
)
CALLS = ((0x2a1063f, 0x2a22520), (0x2a22674, 0x2a2baa0),
         (0x29f6252, 0x2a2be60), (0x29fc3f3, 0x29f6160),
         (0x2a2bd66, 0x29fc340))


def checked_target(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 94 digest mismatch')
    return data


def file_offset(sec, va, size):
    if size < 0 or va < 0 or va + size > 1 << 64:
        raise ValueError('invalid address range')
    hits = [s for s in sec if s['type'] != 8 and s['size'] and
            s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError('range lacks one file-backed section')
    return hits[0]['offset'] + va - hits[0]['address']


def read_va(data, sec, va, size):
    off = file_offset(sec, va, size)
    return data[off:off + size]


def checked_window(data, sec, va, expected):
    want = bytes.fromhex(expected)
    got = read_va(data, sec, va, len(want))
    if got != want:
        raise ValueError('instruction window changed at %#x' % va)
    return got


def decode_call(data, sec, site):
    raw = read_va(data, sec, site, 5)
    if raw[:1] != b'\xe8':
        raise ValueError('not an immediate call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def decode_jcc(data, sec, site, opcode):
    raw = read_va(data, sec, site, 6)
    if raw[:2] != bytes((0x0f, opcode)):
        raise ValueError('unexpected conditional branch')
    return site + 6 + struct.unpack_from('<i', raw, 2)[0]


def decode_short_jcc(data, sec, site, opcode):
    raw = read_va(data, sec, site, 2)
    if raw[0] != opcode:
        raise ValueError('unexpected short conditional branch')
    return site + 2 + struct.unpack_from('<b', raw, 1)[0]


def identity_byte(n):
    if not 0 <= n <= 255:
        raise ValueError('expected one byte')
    # movzx byte followed by a byte store preserves exactly the source octet.
    return n & 255


def replay_byte_path(data, sec, value):
    if not 0 <= value <= 255:
        raise ValueError('expected one byte')
    # Four fixed byte transfers, replayed from the checked opcodes. Callees are
    # assumed to respect the ABI and not alias the caller's saved stack bytes.
    chunks = ((0x2a225c5, '420fb6442b2a88442407'),
              (0x2a22640, '0fb654240788542472'),
              (0x2a2baba, '0fb6422a8844240d'),
              (0x2a2bc5c, '0fb654240d88532d'))
    for va, pattern in chunks:
        checked_window(data, sec, va, pattern)
    source_row = bytearray(48)
    source_row[42] = value
    caller_stack = bytearray(128)
    caller_stack[7] = source_row[42]
    caller_stack[0x72] = caller_stack[7]
    builder_argument = caller_stack[0x48:0x78]
    builder_stack = bytearray(16)
    builder_stack[13] = builder_argument[42]
    output_row = bytearray(48)
    output_row[45] = builder_stack[13]
    return output_row[45]


def id_step(dex, local):
    if not (0 <= dex <= MASK and 0 <= local <= MASK):
        raise ValueError('word outside u64')
    if dex * 10000 > MASK:
        return ('multiply_overflow', None)
    base = dex * 10000
    if local > MASK - base:
        return ('addition_overflow', None)
    return ('row', base + local)


def analyse(data):
    checked_target(data)
    sec = sections(data)
    _, fdes = eh_frame_records(data, sec)
    result = []
    for name, start, end, expected_hash in FUNCTIONS:
        matches = [f for f in fdes if f['start'] == start and f['end'] == end]
        if len(matches) != 1:
            raise ValueError('missing or ambiguous FDE')
        off = file_offset(sec, start, end - start)
        raw = read_va(data, sec, start, end - start)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected_hash:
            raise ValueError('function bytes changed')
        result.append({'role': name, 'start_va': hex(start), 'end_va': hex(end),
                       'fde_va': hex(matches[0]['fde']), 'file_offset': hex(off),
                       'length': len(raw), 'sha256': digest, 'bytes': raw.hex()})
    windows = []
    for name, (va, expected) in sorted(WINDOWS.items()):
        raw = checked_window(data, sec, va, expected)
        windows.append({'name': name, 'va': hex(va), 'file_offset': hex(file_offset(sec, va, len(raw))), 'bytes': raw.hex()})
    calls = []
    for site, target in CALLS:
        resolved = decode_call(data, sec, site)
        if resolved != target:
            raise ValueError('unexpected call target')
        calls.append({'site_va': hex(site), 'target_va': hex(resolved)})
    branches = []
    for name, site, opcode, target in (('multiply_overflow', 0x2a225b3, 0x80, 0x2a226d8),
                                      ('addition_overflow', 0x2a225bf, 0x82, 0x2a226e7)):
        got = decode_jcc(data, sec, site, opcode)
        if got != target:
            raise ValueError('unexpected branch target')
        branches.append({'name': name, 'site_va': hex(site), 'target_va': hex(got)})
    for name, site, opcode, target in (('index_increment_wrap', 0x2a226ac, 0x74, 0x2a226f6),
                                      ('key_writer_error', 0x2a2bf0e, 0x75, 0x2a2bf6c)):
        got = decode_short_jcc(data, sec, site, opcode)
        if got != target:
            raise ValueError('unexpected short branch target')
        branches.append({'name': name, 'site_va': hex(site), 'target_va': hex(got)})
    for name, site, opcode, target in (
        ('only_isolated_absent', 0x2a2bf99, 0x74, 0x2a2bfba),
        ('is_delisted_absent', 0x2a2bfbd, 0x74, 0x2a2bfde),
        ('margin_mode_absent', 0x2a2bfe1, 0x74, 0x2a2c006),
        ('growth_mode_absent', 0x2a2c00b, 0x74, 0x2a2c030),
        ('growth_time_absent', 0x2a2c035, 0x74, 0x2a2c05d),
        ('name_error', 0x2a2bf2c, 0x75, 0x2a2bf6c),
        ('leverage_error', 0x2a2bf4b, 0x75, 0x2a2bf6c),
        ('table_id_success', 0x2a2bf6a, 0x74, 0x2a2bf96),
        ('isolated_error', 0x2a2bfb8, 0x75, 0x2a2bf6c),
        ('delisted_error', 0x2a2bfdc, 0x75, 0x2a2bf6c)):
        got = decode_short_jcc(data, sec, site, opcode)
        if got != target:
            raise ValueError('unexpected short branch target')
        branches.append({'name': name, 'site_va': hex(site), 'target_va': hex(got)})
    for name, site, target in (('margin_mode_error', 0x2a2c000, 0x2a2bf6c),
                               ('growth_mode_error', 0x2a2c02a, 0x2a2bf6c),
                               ('growth_time_error', 0x2a2c057, 0x2a2bf6c)):
        got = decode_jcc(data, sec, site, 0x85)
        if got != target:
            raise ValueError('unexpected conditional branch target')
        branches.append({'name': name, 'site_va': hex(site), 'target_va': hex(got)})
    for name, site, opcode, target in (
        ('empty_source_rows', 0x2a22547, 0x84, 0x2a226be),
        ('row_name_allocation_failure', 0x2a225f5, 0x84, 0x2a2270d),
        ('builder_lookup_empty', 0x2a2bb1c, 0x84, 0x2a2bbc0),
        ('writer_context_missing', 0x2a2be9e, 0x84, 0x2a2c0bb)):
        got = decode_jcc(data, sec, site, opcode)
        if got != target:
            raise ValueError('unexpected conditional branch target')
        branches.append({'name': name, 'site_va': hex(site), 'target_va': hex(got)})
    for name, site, opcode, target in (
        ('empty_row_name', 0x2a225dc, 0x74, 0x2a22610),
        ('builder_lookup_miss', 0x2a2bc37, 0x72, 0x2a2bc44),
        ('list_writer_error', 0x29f625c, 0x74, 0x29f629a)):
        got = decode_short_jcc(data, sec, site, opcode)
        if got != target:
            raise ValueError('unexpected short branch target')
        branches.append({'name': name, 'site_va': hex(site), 'target_va': hex(got)})
    for name, site, opcode, target in (
        ('outer_universe_success', 0x2a2bd6e, 0x74, 0x2a2bd95),
        ('margin_tables_absent', 0x2a2bd98, 0x74, 0x2a2bdb7),
        ('margin_tables_error', 0x2a2bdb5, 0x75, 0x2a2bd70),
        ('collateral_error', 0x2a2bdd5, 0x75, 0x2a2bd70)):
        got = decode_short_jcc(data, sec, site, opcode)
        if got != target:
            raise ValueError('unexpected outer writer branch')
        branches.append({'name': name, 'site_va': hex(site), 'target_va': hex(got)})
    outer_keys = []
    for site, length, expected in ((0x2a2bd54, 8, 'universe'),
                                    (0x2a2bd9e, 12, 'marginTables'),
                                    (0x2a2bdbb, 15, 'collateralToken')):
        insn = read_va(data, sec, site, 7)
        if insn[:3] != b'\x48\x8d\x35':
            raise ValueError('unexpected outer key reference')
        va = site + 7 + struct.unpack_from('<i', insn, 3)[0]
        length_insn = read_va(data, sec, site + 10, 5)
        if length_insn[0] != 0xba or struct.unpack_from('<I', length_insn, 1)[0] != length:
            raise ValueError('unexpected outer key length')
        length = struct.unpack_from('<I', length_insn, 1)[0]
        literal = read_va(data, sec, va, length)
        if literal != expected.encode('ascii'):
            raise ValueError('unexpected outer key')
        outer_keys.append({'key': literal.decode('ascii'), 'key_va': hex(va),
                           'key_length': length, 'lea_va': hex(site)})
    key_site = 0x2a2bef5
    lea = read_va(data, sec, key_site, 7)
    if lea[:3] != b'\x48\x8d\x35':
        raise ValueError('unexpected key reference')
    key_va = key_site + 7 + struct.unpack_from('<i', lea, 3)[0]
    key = read_va(data, sec, key_va, 10)
    if key != b'szDecimals':
        raise ValueError('unexpected key')
    fields = []
    for site, expected_name, offset, condition in FIELDS:
        insn = read_va(data, sec, site, 17)
        if insn[:3] != b'\x48\x8d\x35' or insn[12] != 0xba:
            raise ValueError('unexpected field literal encoding')
        literal_va = site + 7 + struct.unpack_from('<i', insn, 3)[0]
        length = struct.unpack_from('<I', insn, 13)[0]
        literal = read_va(data, sec, literal_va, length)
        if literal != expected_name.encode('ascii'):
            raise ValueError('unexpected field literal')
        if expected_name == 'name':
            if read_va(data, sec, site + 17, 3) != b'\x4c\x89\xf1':
                raise ValueError('unexpected name pointer')
            actual_offset = 0
        else:
            address_insn = read_va(data, sec, site - 4, 4)
            prefix = b'\x49\x83\xc6' if expected_name == 'lastGrowthModeChangeTime' else b'\x49\x8d\x4e'
            if address_insn[:3] != prefix:
                raise ValueError('unexpected field address encoding')
            actual_offset = address_insn[3]
        if actual_offset != offset:
            raise ValueError('unexpected field offset')
        fields.append({'key': literal.decode('ascii'), 'key_va': hex(literal_va),
                       'key_length': length, 'row_offset': actual_offset, 'condition': condition,
                       'lea_va': hex(site)})
    source_offset = read_va(data, sec, 0x2a225ca, 1)[0]
    builder_offset = read_va(data, sec, 0x2a2babd, 1)[0]
    output_offset = read_va(data, sec, 0x2a2bc63, 1)[0]
    stride = read_va(data, sec, 0x2a226b1, 1)[0]
    multiplier = struct.unpack('<I', read_va(data, sec, 0x2a225a1, 4))[0]
    if (source_offset, builder_offset, output_offset, stride, multiplier) != (42, 42, 45, 48, 10000):
        raise ValueError('unexpected dataflow operand')
    return {'schema_version': 1, 'target_sha256': DIGEST,
            'coordinate_system': 'ELF linked virtual addresses',
            'functions': result, 'windows': windows, 'calls': calls, 'branches': branches, 'fields': fields, 'outer_keys': outer_keys,
            'key': {'va': hex(key_va), 'file_offset': hex(file_offset(sec, key_va, len(key))), 'bytes': key.hex(), 'text': key.decode('ascii')},
            'dataflow': {'source_row_byte_offset': source_offset, 'builder_argument_byte_offset': builder_offset,
                         'output_row_byte_offset': output_offset, 'row_stride': stride,
                         'identifier_multiplier': multiplier, 'source_byte_bits': 8},
            'qualification': 'The producer and keyed writer have compatible 48-byte row layouts; an actual handoff between these separately traced paths is not established.'}


def write_outputs(out, data):
    evidence = analyse(data)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    rows = ['name\tsite_va\ttarget_va']
    rows.extend(f"{x['name']}\t{x['site_va']}\t{x['target_va']}" for x in evidence['branches'])
    (out / 'branches.tsv').write_text('\n'.join(rows) + '\n', encoding='utf-8')
    rows = ['key\tkey_va\tkey_length\tlea_va']
    rows.extend(f"{x['key']}\t{x['key_va']}\t{x['key_length']}\t{x['lea_va']}" for x in evidence['outer_keys'])
    (out / 'outer-fields.tsv').write_text('\n'.join(rows) + '\n', encoding='utf-8')
    rows = ['key\tkey_va\tkey_length\trow_offset\tcondition']
    rows.extend(f"{x['key']}\t{x['key_va']}\t{x['key_length']}\t{x['row_offset']}\t{x['condition']}" for x in evidence['fields'])
    (out / 'fields.tsv').write_text('\n'.join(rows) + '\n', encoding='utf-8')
    rows = ['input_byte\tbyte_replay\tidentity_model']
    sec = sections(data)
    for i in range(256):
        replay = replay_byte_path(data, sec, i)
        model = identity_byte(i)
        if replay != model:
            raise ValueError('byte transfer disagrees with identity model')
        rows.append(f'{i}\t{replay}\t{model}')
    (out / 'byte-domain.tsv').write_text('\n'.join(rows) + '\n', encoding='utf-8')
    cases = [(0, 0), (1, 9999), (MASK // 10000, MASK % 10000),
             (MASK // 10000, MASK % 10000 + 1), (MASK // 10000 + 1, 0)]
    rows = ['dex\tlocal\tmodel_result\tmodel_identifier']
    for dex, local in cases:
        kind, value = id_step(dex, local)
        rows.append(f'{dex}\t{local}\t{kind}\t{value if value is not None else "-"}')
    (out / 'identifier-boundaries.tsv').write_text('\n'.join(rows) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    write_outputs(args.out, TARGET.read_bytes())


if __name__ == '__main__':
    main()
