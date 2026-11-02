#!/usr/bin/env python3
"""Recover a PDI row decimal byte and its binary64 display consumers, statically."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TABLE = 0x5b8f60
FUNCTIONS = {
    0x36ff3c0: (0x36ff4e2, '21ec533a85c217e7189497db597caf125041df371f90c1369cd56305adcfd3ab', 'decimal-byte-writer'),
    0x3be4510: (0x3be46f3, '51387a72235cf608dfa5c70d34498f06bb9616cef53caa53dac686d03549daad', 'row-list-display'),
    0x4a06c30: (0x4a06dba, 'ac6823cf01232899e5bc07364f8ddff160b912d2d5886f252c255e27da9b46dd', 'optional-pair-display'),
}
WINDOWS = {
    0x36ff45b: '48b94b598638d6c56d344c89f048f7e148c1ea0b493b573075254869ca102700004c89f04829c8493b47107312498b4f08488d044048c1e004885c012a',
    0x3be45ce: '488b4df84889c849f7e048c1ea0b483b5630755e4869c2102700004829c1483b4e10734e488b',
    0x3be466b: '488b45004885c00f8415ffffff488b4c24300fb64c192a0f57c0f2480f2ac0488d05cf489dfcf20f5e04c8',
    0x4a06c60: 'f60601660f57db74694c8b76084d85f674604989d74c8b0248ba4b598638d6c56d344c89c048f7e248c1ea0b483b51300f85170100004869c2102700004929c04c3b41100f8303010000488b41084b8d144048c1e2040f57dbf2490f2ade0fb644102a488d159622bbfbf20f5e1cc24c89faf6',
    0x4a06cd2: 'f6c301745f4d85db745a4c8b0248ba4b598638d6c56d344c89c048f7e248c1ea0b483b51300f85b00000004869c2102700004929c04c3b41100f839c000000488b41084b8d0c4048c1e1040f57d2f2490f2ad30fb644082a488d0d2f22bbfbf20f5e14c1',
}

# Instruction starts reviewed within the three FDEs; opcode condition is checked.
BRANCHES = {
    0x36ff3ea: (0x84, 'writer_lookup_absent'),
    0x36ff459: (0x75, 'writer_record_word_nonzero'),
    0x36ff473: (0x75, 'writer_wrong_quotient'),
    0x36ff486: (0x73, 'writer_index_out_of_range'),
    0x3be452f: (0x84, 'list_empty'),
    0x3be45e0: (0x75, 'list_wrong_quotient'),
    0x3be45f0: (0x73, 'list_index_out_of_range'),
    0x3be4645: (0x75, 'list_missing_nonzero_failure'),
    0x3be4672: (0x84, 'list_zero_value'),
    0x4a06c67: (0x74, 'pair_first_absent'),
    0x4a06c70: (0x74, 'pair_first_zero'),
    0x4a06c90: (0x85, 'pair_first_wrong_quotient'),
    0x4a06ca4: (0x83, 'pair_first_index_out_of_range'),
    0x4a06cd2 + 3: (0x74, 'pair_second_absent'),
    0x4a06cda: (0x74, 'pair_second_zero'),
    0x4a06cf7: (0x85, 'pair_second_wrong_quotient'),
    0x4a06d0b: (0x83, 'pair_second_index_out_of_range'),
}


def decode_branch(data, sections, va, expected):
    off = offset(sections, va, 6)
    if data[off] == 0x0f:
        opcode = data[off + 1]
        length = 6
        displacement = struct.unpack_from('<i', data, off + 2)[0]
    else:
        opcode = data[off]
        length = 2
        displacement = struct.unpack_from('<b', data, off + 1)[0]
    if opcode != expected or not (0x70 <= opcode <= 0x7f or 0x80 <= opcode <= 0x8f):
        raise ValueError('branch opcode changed')
    return va + length + displacement, bytes(data[off:off + length]).hex()


def offset(sections, va, size):
    if size < 0:
        raise ValueError('negative size')
    matches = [s['offset'] + va - s['address'] for s in sections
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size'] and size > 0]
    if len(matches) != 1:
        raise ValueError('address range has no unique file-backed section')
    return matches[0]


def round_binary64_integer(n, exp2=0):
    """Round positive n*2**exp2 exactly to a normal binary64 bit pattern."""
    if n <= 0:
        raise ValueError('positive values only')
    shift = n.bit_length() - 53
    if shift > 0:
        mant, rem = divmod(n, 1 << shift)
        half = 1 << (shift - 1)
        if rem > half or (rem == half and mant & 1):
            mant += 1
        if mant == 1 << 53:
            mant >>= 1
            shift += 1
    else:
        mant = n << -shift
    exponent = exp2 + shift + 52
    if not -1022 <= exponent <= 1023:
        raise ValueError('normal finite values only')
    return ((exponent + 1023) << 52) | (mant - (1 << 52))


def multiply_ten(bits):
    exponent = ((bits >> 52) & 0x7ff) - 1023 - 52
    significand = (bits & ((1 << 52) - 1)) | (1 << 52)
    return round_binary64_integer(significand * 10, exponent)


def validate(data, check_digest=True):
    digest = hashlib.sha256(data).hexdigest()
    if check_digest and digest != DIGEST:
        raise ValueError('node 94 SHA-256 mismatch')
    sections = elf_index.sections(data)
    _, records = fde_extents.eh_frame_records(data, sections)
    indexed = {}
    for r in records:
        if r['start'] in FUNCTIONS:
            if r['start'] in indexed:
                raise ValueError('duplicate FDE')
            indexed[r['start']] = r
    if len(indexed) != len(FUNCTIONS):
        raise ValueError('missing FDE')
    funcs = []
    for start, (end, expected, label) in sorted(FUNCTIONS.items()):
        row = indexed[start]
        if row['end'] != end:
            raise ValueError('FDE extent changed')
        off = offset(sections, start, end-start)
        body = data[off:off+end-start]
        body_hash = hashlib.sha256(body).hexdigest()
        if body_hash != expected:
            raise ValueError('function bytes changed')
        funcs.append({'role': label, 'start_va': hex(start), 'end_va': hex(end),
                      'fde_va': hex(row['fde']), 'file_offset': hex(off),
                      'byte_length': len(body), 'sha256': body_hash, 'bytes_hex': body.hex()})
    windows = []
    for va, expected in sorted(WINDOWS.items()):
        raw = bytes.fromhex(expected)
        off = offset(sections, va, len(raw))
        if data[off:off+len(raw)] != raw:
            raise ValueError('instruction window changed')
        windows.append({'va': hex(va), 'file_offset': hex(off), 'bytes_hex': raw.hex()})
    branches = []
    for va, (opcode, label) in sorted(BRANCHES.items()):
        target, raw = decode_branch(data, sections, va, opcode)
        branches.append((hex(va), label, raw, hex(target)))
    table_off = offset(sections, TABLE, 256 * 8)
    bits = struct.unpack_from('<256Q', data, table_off)
    if bits[0] != 0x3ff0000000000000:
        raise ValueError('bad table start')
    for i in range(1, len(bits)):
        if bits[i] != multiply_ten(bits[i-1]):
            raise ValueError('table recurrence mismatch')
    table = []
    for i, bit in enumerate(bits):
        ideal = round_binary64_integer(10 ** i)
        table.append((i, hex(TABLE + 8*i), f'{bit:016x}', f'{ideal:016x}', int(bit != ideal)))
    magic = int.from_bytes(bytes.fromhex(WINDOWS[0x36ff45b])[2:10], 'little')
    divisor = int.from_bytes(bytes.fromhex(WINDOWS[0x36ff45b])[29:33], 'little')
    if divisor != 10000 or magic != 0x346dc5d63886594b:
        raise ValueError('division constants changed')
    error = divisor * magic - (1 << 75)
    if not (0 < error and ((1 << 64)-1)*error < (1 << 75)):
        raise ValueError('reciprocal proof failed')
    return {'artifact_sha256': digest, 'functions': funcs, 'windows': windows,
            'table_va': hex(TABLE), 'table_file_offset': hex(table_off),
            'table_rows': len(table), 'recurrence_mismatches': 0,
            'differ_from_independently_rounded_power': sum(r[-1] for r in table),
            'reciprocal': hex(magic), 'divisor': divisor, 'reciprocal_error': error,
            'proof': '0 < divisor*reciprocal - 2^75 and (2^64-1)*error < 2^75'}, table, branches


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    evidence, table, branches = validate(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    buf = io.StringIO(newline='')
    w = csv.writer(buf, delimiter='\t', lineterminator='\n')
    w.writerow(('index', 'va', 'bits', 'correctly_rounded_power_bits', 'different'))
    w.writerows(table)
    (args.out / 'power-table.tsv').write_text(buf.getvalue(), encoding='utf-8')
    buf = io.StringIO(newline='')
    w = csv.writer(buf, delimiter='\t', lineterminator='\n')
    w.writerow(('va', 'condition', 'bytes', 'target_va'))
    w.writerows(branches)
    (args.out / 'branches.tsv').write_text(buf.getvalue(), encoding='utf-8')


if __name__ == '__main__':
    main()
