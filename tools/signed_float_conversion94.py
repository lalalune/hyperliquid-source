#!/usr/bin/env python3
"""Static checks and boundary models for two #94 quantity float conversions."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = (
    ('positive', 0x3c06160, 0x3c0620a, '7182f118bff4cdbae8c62b2fc452ff2f04d503c0bdd56166dd43ec2b87684593'),
    ('complement', 0x4cda1a0, 0x4cda253, '85be9531efd115b8f651d4093f2e6d7da03e0ae582f3a11aedf510bfd1901784'),
)
CONSTANTS = {0x20acb8: 0xc3e0000000000000, 0x20a7f0: 0x43e0000000000000,
             0x20a2c8: 0x43dfffffffffffff, 0x20a730: 0x3ff0000000000000}
# Start, opcode bytes and mnemonic description. Relative destinations are read from bytes.
BRANCHES = (
    ('positive', 0x3c06163, 'js', 'input sign -> panic'),
    ('positive', 0x3c06191, 'jg', 'nonfinite -> zero'),
    ('positive', 0x3c0619f, 'ja', 'below lower clamp'),
    ('positive', 0x3c061a9, 'ja', 'above upper clamp'),
    ('positive', 0x3c061af, 'jmp', 'within bounds'),
    ('complement', 0x4cda1a3, 'js', 'input sign -> panic'),
    ('complement', 0x4cda1e1, 'jg', 'nonfinite -> zero'),
    ('complement', 0x4cda1ef, 'ja', 'below lower clamp'),
    ('complement', 0x4cda1f9, 'ja', 'above upper clamp'),
    ('complement', 0x4cda1ff, 'jmp', 'within bounds'),
)


def checked_digest(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('target SHA-256 mismatch')


def resolve(sections, va, size):
    if size < 0:
        raise ValueError('negative size')
    found = [s['offset'] + va - s['address'] for s in sections
             if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('address not uniquely backed by file bytes')
    return found[0]


def branch(data, sections, va, mnemonic):
    pos = resolve(sections, va, 6)
    op = data[pos]
    short = {0x78: 'js', 0x7f: 'jg', 0x77: 'ja', 0xeb: 'jmp'}
    near = {0x88: 'js', 0x8f: 'jg', 0x87: 'ja'}
    if op in short and short[op] == mnemonic:
        size, disp = 2, struct.unpack_from('<b', data, pos + 1)[0]
    elif op == 0x0f and data[pos + 1] in near and near[data[pos + 1]] == mnemonic:
        size, disp = 6, struct.unpack_from('<i', data, pos + 2)[0]
    else:
        raise ValueError('branch opcode mismatch')
    return va + size + disp


def checked_image(data):
    checked_digest(data)
    secs = elf_index.sections(data)
    _, records = fde_extents.eh_frame_records(data, secs)
    bounds = {(r['start'], r['end']) for r in records}
    funcs = []
    for name, start, end, expected in FUNCTIONS:
        if (start, end) not in bounds:
            raise ValueError('FDE extent mismatch')
        off = resolve(secs, start, end - start)
        raw = data[off:off + end - start]
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('function bytes mismatch')
        funcs.append({'name': name, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                      'file_offset': hex(off), 'size': len(raw), 'sha256': expected, 'bytes_hex': raw.hex()})
    constants = []
    for va, expected in sorted(CONSTANTS.items()):
        off = resolve(secs, va, 8)
        value = struct.unpack_from('<Q', data, off)[0]
        if value != expected:
            raise ValueError('constant mismatch')
        constants.append({'va': hex(va), 'file_offset': hex(off), 'bits': f'{value:016x}'})
    # Rust Location records have a RELATIVE relocation to the source path.
    # Retain only the repository-relative suffix; host build prefixes are private.
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    wanted = {0x5714c10, 0x57444f0}
    locations = []
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, pos)
        if where not in wanted or info & 0xffffffff != 8:
            continue
        offset = resolve(secs, where, 24)
        length, line, column = struct.unpack_from('<QII', data, offset + 8)
        if length > 256:
            raise ValueError('Location length out of bounds')
        path = data[resolve(secs, addend, length):][:length]
        suffix = b'l1/src/qtys/mod.rs'
        if not path.endswith(suffix) or (line, column) != (843, 1):
            raise ValueError('Location mismatch')
        locations.append({'va': hex(where), 'source_suffix': suffix.decode(),
                          'line': line, 'column': column})
    if {int(x['va'], 16) for x in locations} != wanted:
        raise ValueError('Location relocation missing')
    locations.sort(key=lambda x: int(x['va'], 16))
    decisions = []
    for name, va, op, reason in BRANCHES:
        destination = branch(data, secs, va, op)
        start, end = next((s, e) for n, s, e, _ in FUNCTIONS if n == name)
        if not start <= destination < end:
            raise ValueError('branch outside FDE')
        decisions.append({'function': name, 'va': hex(va), 'opcode': op,
                          'destination_va': hex(destination), 'meaning': reason})
    return {'artifact_sha256': SHA, 'coordinate_system': 'ELF virtual addresses',
            'functions': funcs, 'constants': constants, 'locations': locations, 'branches': decisions}


def bits_float(bits):
    return struct.unpack('<d', struct.pack('<Q', bits))[0]


def projection(raw, factor_bits, complement=False):
    """A mathematical model, not an x86 emulator or execution of the target."""
    if not 0 <= raw < 1 << 64 or not 0 <= factor_bits < 1 << 64:
        raise ValueError('input out of range')
    if raw >> 63:
        return 'panic'
    factor = bits_float(factor_bits)
    if complement:
        factor = 1.0 - factor
    product = float(raw) * factor
    if not math.isfinite(product):
        return 0
    result = max(-(1 << 63), min((1 << 63) - 1, int(product)))
    return result if complement else max(0, result)


def lift(data, sections, raw, factor_bits, complement=False):
    """Manually lifted basic blocks, with branch destinations read from the image.

    This is not a general x86 emulator. checked_image must first validate all
    bytes. The floating operations assume round-to-nearest binary64.
    """
    if not 0 <= raw < 1 << 64 or not 0 <= factor_bits < 1 << 64:
        raise ValueError('input out of range')
    base = 0x4cda1a0 if complement else 0x3c06160
    sign_branch = base + (3 if complement else 3)
    if raw & (1 << 63):
        return 'panic', [hex(sign_branch), hex(branch(data, sections, sign_branch, 'js'))]
    factor = bits_float(factor_bits)
    if complement:
        factor = bits_float(struct.unpack_from('<Q', data, resolve(sections, 0x20a730, 8))[0]) - factor
    product = float(raw) * factor
    word = struct.unpack('<Q', struct.pack('<d', product))[0]
    trace = []
    nonfinite_branch = 0x4cda1e1 if complement else 0x3c06191
    trace.append(hex(nonfinite_branch))
    if (word & 0x7fffffffffffffff) > 0x7fefffffffffffff:
        trace.append(hex(branch(data, sections, nonfinite_branch, 'jg')))
        bounded = 0.0
    else:
        lower = bits_float(struct.unpack_from('<Q', data, resolve(sections, 0x20acb8, 8))[0])
        upper = bits_float(struct.unpack_from('<Q', data, resolve(sections, 0x20a7f0, 8))[0])
        low_branch = 0x4cda1ef if complement else 0x3c0619f
        high_branch = 0x4cda1f9 if complement else 0x3c061a9
        trace.append(hex(low_branch))
        if product < lower:
            trace.append(hex(branch(data, sections, low_branch, 'ja')))
            bounded = max(lower, product)
            bounded = min(upper, bounded)
        else:
            trace.append(hex(high_branch))
            if product > upper:
                trace.append(hex(branch(data, sections, high_branch, 'ja')))
                bounded = max(lower, product)
                bounded = min(upper, bounded)
            else:
                bounded = product
    # cvttsd2si returns the signed minimum for an out-of-range operand.
    n = int(bounded) if -(1 << 63) <= bounded < (1 << 63) else -(1 << 63)
    below_upper = bits_float(struct.unpack_from('<Q', data, resolve(sections, 0x20a2c8, 8))[0])
    if bounded > below_upper:
        n = (1 << 63) - 1
    if not complement:
        n = max(0, n)
    return n, trace


def generate(data, out):
    evidence = checked_image(data)
    factors = [0, 0x8000000000000000, 1, 0x3fd0000000000000, 0x3fe0000000000000,
               0x3fefffffffffffff, 0x3ff0000000000000, 0x3ff0000000000001,
               0x4000000000000000, 0xbfe0000000000000, 0xbff0000000000000,
               0x43dfffffffffffff, 0x43e0000000000000, 0xc3e0000000000000,
               0x7fefffffffffffff, 0x7ff0000000000000, 0xfff0000000000000,
               0x7ff8000000000001, 0xfff8000000000001]
    amounts = [0, 1, 2, 3, 10, (1 << 53)-1, 1 << 53, (1 << 53)+1,
               (1 << 63)-1025, (1 << 63)-1024, (1 << 63)-1, 1 << 63, (1 << 64)-1]
    lines = ['mode\traw\tfactor_bits\tmodel_result\tlift_result\tbranch_trace']
    sections = elf_index.sections(data)
    for mode in ('positive', 'complement'):
        for raw in amounts:
            for factor in factors:
                result = projection(raw, factor, mode == 'complement')
                lifted, trace = lift(data, sections, raw, factor, mode == 'complement')
                if result != lifted:
                    raise ValueError('lift/model disagreement')
                lines.append(f'{mode}\t{raw}\t{factor:016x}\t{result}\t{lifted}\t{",".join(trace)}')
    # Exhaust the exponent and sign fields, with three mantissas including the
    # finite/nonfinite boundary. The mask comparison is the observed integer test.
    classes = {'finite': 0, 'nonfinite': 0}
    for sign in range(2):
        for exponent in range(2048):
            for fraction in (0, 1, (1 << 52)-1):
                word = (sign << 63) | (exponent << 52) | fraction
                by_mask = (word & ((1 << 63)-1)) <= 0x7fefffffffffffff
                by_exponent = exponent != 2047
                if by_mask != by_exponent:
                    raise ValueError('finite classification disagreement')
                classes['finite' if by_mask else 'nonfinite'] += 1
    evidence['finite_mask_control'] = {'representatives': classes,
        'finite_bit_patterns': 2 * 2047 * (1 << 52),
        'nonfinite_bit_patterns': 2 * (1 << 52),
        'argument': 'Magnitude is exponent concatenated with 52-bit fraction; exponent 2047 is exactly the range above 0x7fefffffffffffff.'}
    evidence['model_vector_count'] = len(lines)-1
    evidence['model_notice'] = 'Vectors compare a mathematical model with manually lifted blocks. This is not target execution or a general x86 emulator.'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    (out / 'vectors.tsv').write_text('\n'.join(lines)+'\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(BINARY.read_bytes(), args.out)


if __name__ == '__main__':
    main()
