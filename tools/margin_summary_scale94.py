#!/usr/bin/env python3
"""Extract a node94 margin-summary scaling path using only ELF bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = (
    (0x2565260, 0x256533f, 'e9b4d7048bf63b9b7ff3e67bd8d6cc1cd778255ad6a1dc82148d3ea4614bc9ec', 'allocate_and_collect'),
    (0x26b1100, 0x26b142d, '357a0ea10aac179ce1a247fe3800652e4e066b55b6f7880eac6ce11f38dae801', 'collect_rows'),
    (0x26b9e20, 0x26ba248, '74e8974503896d1a07e00dcfa1f98eabbded6c4fdf016e934ea3b5486970035a', 'summary_and_scale'),
)
WINDOWS = (
 (0x2565272, '48b8401aa4411aa4411a4939c7760b', 'allocation size guard'),
 (0x256528f, '49c1ef064d69f738010000', '64-byte input and 312-byte output stride'),
 (0x25652ff, 'e8fcbd1400', 'call collector'),
 (0x26b111f, '4939d50f8494020000', 'empty input'),
 (0x26b11fd, 'e81e8c0000', 'call summary'),
 (0x26b1391, '488b44242048ffc84981c6380100004983c540', 'advance rows'),
 (0x26b9e44, '4d85c07527', 'existing row or lookup'),
 (0x26b9e68, 'e883b90301', 'lookup'),
 (0x26b9e87, '4c89eeba01000000b9010000004989e9ffd3', 'summary mode 1,1'),
 (0x26b9ea5, '4531ff4c89ee31d2b9010000004989e9ffd3', 'summary mode 0,1'),
 (0x26b9ec0, '4c89ee31d2b9020000004989e9ffd3', 'summary mode 0,2'),
 (0x26ba097, 'f2490f2ac6f20f100dbc0db5fdf20f5ec1', 'signed result and scalar divisor'),
 (0x26ba145, 'f2490f2af5f20f5ef1', 'second signed result'),
 (0x26ba14e, 'f20f107c24300f143d259db4fd660f5c3d3d8db4fd66440f28c766440f15c7f2440f58c7f2440f5ec1', 'unsigned result'),
 (0x26ba1af, '0f57d2f2480f2ad3f20f5ed1488b542438f20f115218', 'signed result to output'),
 (0x26ba1cd, '660f5ef9660f117a20f2440f114230f20f11723866440f5ed166440f11524066440f5ec966440f114a50f20f114260', 'vector divide and output writes'),
)
STORES = (
 (0x26ba1c0, 'f20f1152', 1),
 (0x26ba1d1, '660f117a', 2),
 (0x26ba1d6, 'f2440f1142', 1),
 (0x26ba1dc, 'f20f1172', 1),
 (0x26ba1e6, '66440f1152', 2),
 (0x26ba1f1, '66440f114a', 2),
 (0x26ba1f7, 'f20f1142', 1),
)

DECISIONS = (
 (0x256527f, '760b', 'byte span within allocation bound', 'allocate or empty path', 'allocation error'),
 (0x256529d, '7422', 'allocation size is zero', 'empty allocation', 'allocate'),
 (0x25652b1, '7516', 'allocation succeeded', 'initialize output vector', 'allocation error'),
 (0x26b1122, '0f8494020000', 'input endpoints equal', 'return without row', 'iterate'),
 (0x26b1180, '741e', 'copied key length is zero', 'empty key representation', 'allocate key'),
 (0x26b118e, '7515', 'key allocation succeeded', 'copy key', 'allocation error'),
 (0x26b13a9, '0f85c1fdffff', 'rows remain', 'next row', 'store output count'),
 (0x26b9e47, '7527', 'optional row argument nonzero', 'use supplied row', 'lookup row'),
 (0x26b9f0c, '740d', 'row field at +8 is zero', 'zero optional payload', 'copy optional payload'),
)

# Symbolic locations refer to values produced by the three summary calls, not proven economic names.
FIELDS = (
 (0x18, 'signed', 'first summary word 0'),
 (0x20, 'unsigned', 'first summary word 2'),
 (0x28, 'signed', 'first summary word 3'),
 (0x30, 'unsigned', 'first summary word 1'),
 (0x38, 'signed', 'second summary word 0'),
 (0x40, 'unsigned', 'second summary word 2'),
 (0x48, 'signed', 'second summary word 3'),
 (0x50, 'unsigned', 'second summary word 1'),
 (0x58, 'unsigned', 'third summary word 1'),
 (0x60, 'signed', 'auxiliary call return'),
)


def checked_hash(data, expected=None):
    if hashlib.sha256(data).hexdigest() != (SHA if expected is None else expected):
        raise ValueError('target digest mismatch')


def offset(sections, va, size):
    matches = [s['offset'] + va - s['address'] for s in sections if s['type'] != 8
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1 or size < 0:
        raise ValueError('address lacks unique file-backed section')
    return matches[0]


def extract(data):
    checked_hash(data)
    secs = elf_index.sections(data)
    _, fdes = fde_extents.eh_frame_records(data, secs)
    funcs = []
    for start, end, digest, name in FUNCTIONS:
        rows = [r for r in fdes if r['start'] == start and r['end'] == end]
        if len(rows) != 1:
            raise ValueError('FDE extent mismatch')
        off = offset(secs, start, end-start)
        raw = data[off:off+end-start]
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('function byte mismatch')
        funcs.append({'name': name, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                      'fde_va': hex(rows[0]['fde']), 'file_offset': hex(off),
                      'sha256': digest, 'bytes_hex': raw.hex()})
    windows = []
    for va, expected, meaning in WINDOWS:
        size = len(bytes.fromhex(expected))
        off = offset(secs, va, size)
        raw = data[off:off+size]
        if raw.hex() != expected:
            raise ValueError('instruction contract mismatch')
        windows.append({'va': hex(va), 'bytes_hex': raw.hex(), 'interpretation': meaning})
    constants = []
    for va, size in ((0x20ae60, 8), (0x203b10, 16)):
        off = offset(secs, va, size)
        raw = data[off:off+size]
        if raw != bytes.fromhex('0000000080842e41') * (size // 8):
            raise ValueError('divisor byte mismatch')
        constants.append({'va': hex(va), 'file_offset': hex(off), 'bytes_hex': raw.hex()})
    conversion_constants = []
    for va, size in ((0x209020, 16), (0x2076e0, 16), (0x204c20, 16),
                     (0x204c30, 16), (0x203e80, 8), (0x202ea0, 16)):
        off = offset(secs, va, size)
        conversion_constants.append({'va': hex(va), 'bytes_hex': data[off:off+size].hex()})
    for site, dest in ((0x25652ff, 0x26b1100), (0x26b11fd, 0x26b9e20)):
        off = offset(secs, site, 5)
        if data[off] != 0xe8 or site + 5 + struct.unpack_from('<i', data, off+1)[0] != dest:
            raise ValueError('direct call target mismatch')
    store_offsets = []
    for va, prefix, lanes in STORES:
        op = bytes.fromhex(prefix)
        off = offset(secs, va, len(op) + 1)
        if data[off:off+len(op)] != op:
            raise ValueError('store instruction mismatch')
        displacement = data[off+len(op)]
        store_offsets.extend(displacement + 8*i for i in range(lanes))
    if sorted(store_offsets) != [r[0] for r in FIELDS]:
        raise ValueError('field destinations mismatch')
    decisions = []
    for va, expected, condition, taken, fallthrough in DECISIONS:
        raw = bytes.fromhex(expected)
        off = offset(secs, va, len(raw))
        if data[off:off+len(raw)] != raw:
            raise ValueError('decision bytes mismatch')
        if raw[0] == 0x0f:
            disp = struct.unpack_from('<i', raw, 2)[0]
        else:
            disp = struct.unpack_from('<b', raw, 1)[0]
        decisions.append({'va': hex(va), 'bytes_hex': raw.hex(), 'taken_target': hex(va + len(raw) + disp),
                          'fallthrough_target': hex(va + len(raw)), 'condition': condition,
                          'taken': taken, 'fallthrough': fallthrough})
    return {'target_sha256': SHA, 'coordinate_system': 'ELF VA; exclusive end',
            'functions': funcs, 'windows': windows, 'decisions': decisions, 'field_offsets': store_offsets, 'divisors': constants,
            'conversion_constants': conversion_constants}


def unsigned_sse_bits(value, words):
    """Interpret the packed low/high conversion algebra from the recorded constants."""
    if not 0 <= value < 1 << 64:
        raise ValueError('unsigned input out of range')
    mask, low_bias, high_bias, combined_bias = words
    low_word = (value & mask) | low_bias
    high_word = (value >> 32) | high_bias
    low = struct.unpack('<d', struct.pack('<Q', low_word))[0]
    high = struct.unpack('<d', struct.pack('<Q', high_word))[0]
    bias = struct.unpack('<d', struct.pack('<Q', combined_bias))[0]
    value64 = (high - bias) + low
    return struct.unpack('<Q', struct.pack('<d', value64 / 1000000.0))[0]


def unsigned_scalar_bits(value, scalar_constants):
    """Interpret the scalar unpack/subtract/add integer conversion sequence."""
    if not 0 <= value < 1 << 64:
        raise ValueError('unsigned input out of range')
    unpacked, low_bias, high_bias = scalar_constants
    low_tag = (unpacked & 0xffffffff) << 32
    high_tag = (unpacked >> 32) << 32
    as_float = lambda n: struct.unpack('<d', struct.pack('<Q', n))[0]
    low = as_float(low_tag | (value & 0xffffffff)) - as_float(low_bias)
    high = as_float(high_tag | (value >> 32)) - as_float(high_bias)
    return struct.unpack('<Q', struct.pack('<d', (high + low) / 1000000.0))[0]


def scaled_bits(value, signed):
    low = -(1 << 63) if signed else 0
    high = (1 << 63)-1 if signed else (1 << 64)-1
    if not low <= value <= high:
        raise ValueError('integer out of range')
    return struct.unpack('<Q', struct.pack('<d', float(value) / 1000000.0))[0]


def generate(out, data):
    evidence = extract(data)
    out.mkdir(parents=True, exist_ok=True)
    (out/'evidence.json').write_text(json.dumps(evidence, indent=2)+'\n')
    rows = ['branch_va\ttaken_target\tfallthrough_target\tcondition\ttaken\tfallthrough']
    for branch in evidence['decisions']:
        rows.append('\t'.join(branch[k] for k in ('va', 'taken_target', 'fallthrough_target', 'condition', 'taken', 'fallthrough')))
    (out/'decisions.tsv').write_text('\n'.join(rows)+'\n')
    rows = ['summary_offset\trow_offset\twidth\tsource\toperation']
    for off, width, source in FIELDS:
        rows.append(f'0x{off:02x}\t0x{off + 0xa0:02x}\t{width} 64-bit\t{source}\tbinary64 divide by 1000000')
    (out/'fields.tsv').write_text('\n'.join(rows)+'\n')
    constants = {int(x['va'], 16): bytes.fromhex(x['bytes_hex']) for x in evidence['conversion_constants']}
    words = tuple(struct.unpack_from('<Q', constants[va])[0]
                  for va in (0x209020, 0x2076e0, 0x204c20, 0x204c30))
    scalar_constants = (struct.unpack_from('<Q', constants[0x203e80])[0],
                        *struct.unpack('<QQ', constants[0x202ea0]))
    rows = ['width\tinput\toutput_binary64_bits\tunsigned_sse_agrees']
    signed = [-(1 << 63), -(1 << 53)-1, -1000001, -1, 0, 1, 999999, 1000000, 1000001, (1 << 53)+3, (1 << 63)-1]
    unsigned = [0, 1, 999999, 1000000, 1000001, (1 << 53)-1, 1 << 53, (1 << 53)+3, (1 << 63)-1, 1 << 63, (1 << 64)-1]
    for label, values in (('signed', signed), ('unsigned', unsigned)):
        for n in values:
            result = scaled_bits(n, label == 'signed')
            agrees = 'not_applicable'
            if label == 'unsigned':
                if unsigned_sse_bits(n, words) != result or unsigned_scalar_bits(n, scalar_constants) != result:
                    raise ValueError('packed unsigned conversion disagreement')
                agrees = 'yes'
            rows.append(f'{label}\t{n}\t0x{result:016x}\t{agrees}')
    (out/'model-vectors.tsv').write_text('\n'.join(rows)+'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    generate(args.out, BINARY.read_bytes())

if __name__ == '__main__':
    main()
