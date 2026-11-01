#!/usr/bin/env python3
"""Static evidence for two node 94 quantity float conversion paths."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x3c06160: (0x3c0620a, '7182f118bff4cdbae8c62b2fc452ff2f04d503c0bdd56166dd43ec2b87684593'),
    0x4cda1a0: (0x4cda253, '85be9531efd115b8f651d4093f2e6d7da03e0ae582f3a11aedf510bfd1901784'),
}
CONSTANTS = {0x20a730: 0x3ff0000000000000, 0x20acb8: 0xc3e0000000000000,
             0x20a7f0: 0x43e0000000000000, 0x20a2c8: 0x43dfffffffffffff}


def resolve(data, va, size):
    found = [s for s in sections(data) if s['type'] != 8 and s['address'] <= va
             and va + size <= s['address'] + s['size']]
    if size < 0 or len(found) != 1:
        raise ValueError('range is not in exactly one file-backed section')
    s = found[0]
    off = s['offset'] + va - s['address']
    return off, data[off:off + size]


def inspect(data, check_digest=True):
    digest = hashlib.sha256(data).hexdigest()
    if check_digest and digest != DIGEST:
        raise ValueError('target digest mismatch')
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    functions = []
    for start, (end, expected) in sorted(FUNCTIONS.items()):
        matches = [f for f in fdes if f['start'] == start]
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError('unexpected FDE extent')
        off, raw = resolve(data, start, end - start)
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ValueError('function bytes differ')
        functions.append({'start_va': hex(start), 'end_va_exclusive': hex(end),
                          'fde_va': hex(matches[0]['fde']), 'file_offset': hex(off),
                          'size': len(raw), 'bytes_hex': raw.hex(), 'sha256': actual})
    constants = []
    for va, expected in sorted(CONSTANTS.items()):
        off, raw = resolve(data, va, 8)
        bits = struct.unpack('<Q', raw)[0]
        if bits != expected:
            raise ValueError('constant bytes differ')
        constants.append({'va': hex(va), 'file_offset': hex(off), 'bytes_hex': raw.hex(),
                          'binary64_bits': f'{bits:016x}'})
    rela = next(s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8)
    relocations = {}
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, pos)
        if info == 8:
            relocations[where] = addend
    locations = []
    for va in (0x5714c10, 0x57444f0):
        off, raw = resolve(data, va, 24)
        length, line, column = struct.unpack_from('<QII', raw, 8)
        if length > 300 or va not in relocations:
            raise ValueError('invalid location record')
        _, path = resolve(data, relocations[va], length)
        suffix = b'l1/src/qtys/mod.rs'
        if not path.endswith(suffix) or (line, column) != (843, 1):
            raise ValueError('unexpected location')
        locations.append({'va': hex(va), 'file_offset': hex(off),
                          'path_suffix': suffix.decode('ascii'), 'line': line, 'column': column})
    return {'target_sha256': digest, 'functions': functions, 'constants': constants,
            'locations': locations}


def model(kind, n, factor):
    """Closed-form reading of the pinned instructions; not target execution."""
    if kind not in ('product_nonnegative', 'complement_signed') or not 0 <= n < 1 << 64:
        raise ValueError('invalid model input')
    if n >= 1 << 63:
        return 'panic'
    p = float(n) * (factor if kind == 'product_nonnegative' else 1.0 - factor)
    if not math.isfinite(p):
        return 0
    v = min((1 << 63) - 1, max(-(1 << 63), int(p)))
    return max(v, 0) if kind == 'product_nonnegative' else v


def prove_conversion():
    """Check the ends of every finite sign/exponent interval of the pinned tail.

    Within one interval the encoded mantissa is monotone. Every finite interval
    is wholly inside the conversion range or wholly at/beyond an endpoint.
    The range partition and truncating conversion establish the interior cases.
    """
    checked = 0
    classes = {'inside': 0, 'at_or_outside': 0}
    limit = 1 << 63
    below = struct.unpack('<d', struct.pack('<Q', CONSTANTS[0x20a2c8]))[0]
    for sign in (0, 1):
        for exponent in range(2047):
            category = 'inside' if exponent < 1086 else 'at_or_outside'
            classes[category] += 1
            for mantissa in (0, (1 << 52) - 1):
                bits = (sign << 63) | (exponent << 52) | mantissa
                x = struct.unpack('<d', struct.pack('<Q', bits))[0]
                if category == 'inside' and not (-limit < x < limit):
                    raise AssertionError('inside partition')
                if category == 'at_or_outside' and abs(x) < limit:
                    raise AssertionError('outside partition')
                # Emulate only the conversion tail, including x86's indefinite
                # signed result at +2^63 and the subsequent upper correction.
                clamped = min(float(limit), max(-float(limit), x))
                machine = -limit if clamped >= limit else int(clamped)
                if clamped > below:
                    machine = limit - 1
                specification = min(limit - 1, max(-limit, int(x)))
                if machine != specification or max(machine, 0) != max(specification, 0):
                    raise AssertionError('conversion tail mismatch')
                checked += 1
    return {'finite_sign_exponent_classes': classes,
            'finite_interval_endpoints_checked': checked,
            'nonfinite_exponent_classes': 2,
            'nonfinite_result': 0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True, type=Path)
    args = ap.parse_args()
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    evidence = inspect(data)
    evidence['conversion_partition'] = prove_conversion()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    factors = [('negative_infinity', float('-inf')), ('negative_two', -2.0), ('negative_half', -0.5),
               ('zero', 0.0), ('half', 0.5), ('one', 1.0), ('one_half', 1.5),
               ('two', 2.0), ('positive_infinity', float('inf')), ('nan', float('nan'))]
    values = (0, 1, 3, (1 << 53) - 1, 1 << 53, (1 << 53) + 1, (1 << 63) - 1,
              1 << 63, (1 << 64) - 1)
    with (args.out / 'model-vectors.tsv').open('w', newline='') as out:
        w = csv.writer(out, delimiter='\t', lineterminator='\n')
        w.writerow(('function', 'n', 'factor', 'factor_bits', 'model_result'))
        for kind in ('product_nonnegative', 'complement_signed'):
            for n in values:
                for name, factor in factors:
                    bits = struct.unpack('<Q', struct.pack('<d', factor))[0]
                    w.writerow((kind, n, name, f'{bits:016x}', model(kind, n, factor)))


if __name__ == '__main__':
    main()
