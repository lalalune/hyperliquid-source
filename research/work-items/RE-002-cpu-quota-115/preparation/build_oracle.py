#!/usr/bin/env python3
"""Freeze binary64 quota expectations using integer/rational arithmetic only.

The captured initializer converts both unsigned inputs separately, divides,
calls its bound ceil helper and saturates to u64. No captured code runs.
"""
import hashlib
import json
from pathlib import Path
import random

PACKET = Path(__file__).resolve().parents[1]
MAX = (1 << 64) - 1


def binary64(numerator, denominator=1):
    """Round a nonnegative normal-range rational to binary64, ties to even."""
    if numerator == 0:
        return 0
    exponent = numerator.bit_length() - denominator.bit_length()
    if exponent >= 0:
        exponent -= numerator < denominator << exponent
    else:
        exponent -= numerator << -exponent < denominator
    shift = 52 - exponent
    n, d = (numerator << shift, denominator) if shift >= 0 else (numerator, denominator << -shift)
    significand, remainder = divmod(n, d)
    significand += 2 * remainder > d or (2 * remainder == d and significand & 1)
    if significand == 1 << 53:
        significand >>= 1
        exponent += 1
    if not (1 << 52 <= significand < 1 << 53 and -1022 <= exponent <= 1023):
        raise ValueError('outside the normal finite quota-input domain')
    return ((exponent + 1023) << 52) | (significand - (1 << 52))


def fraction(bits):
    if bits == 0:
        return 0, 1
    exponent = (bits >> 52) - 1023 - 52
    significand = (1 << 52) | (bits & ((1 << 52) - 1))
    return (significand << exponent, 1) if exponent >= 0 else (significand, 1 << -exponent)


def expected(quota, period, logical):
    if period == 0:
        return {'quota_bits': None, 'period_bits': None, 'ratio_bits': None, 'rounded_quota': None, 'store': None}
    qb, pb = binary64(quota), binary64(period)
    qn, qd = fraction(qb)
    pn, pd = fraction(pb)
    rb = binary64(qn * pd, qd * pn)
    rn, rd = fraction(rb)
    rounded = min(MAX, (rn + rd - 1) // rd)
    return {'quota_bits': f'{qb:016x}', 'period_bits': f'{pb:016x}', 'ratio_bits': f'{rb:016x}',
            'rounded_quota': rounded, 'store': min(rounded, logical) if rounded else None}


def generate():
    values = {0, 1, 2, 3, 10, 99999, 100000, 100001, MAX}
    for bit in [31, 32, 52, 53, 54, 62, 63, 64]:
        values.update(x for delta in [-2049, -2048, -1025, -1024, -3, -2, -1, 0, 1, 2, 3, 1023, 1024, 2047, 2048]
                      if 0 <= (x := (1 << bit) + delta) <= MAX)
    pairs = {(q, p) for q in values for p in [0, 1, 2, 3, 100000, (1 << 53), MAX]}
    pairs.update((q, p) for q in [(1 << 53) - 1, 1 << 53, (1 << 53) + 1, MAX] for p in values)
    rng = random.Random(0x4e058a4)
    pairs.update((rng.getrandbits(64), rng.getrandbits(64)) for _ in range(1024))
    rows = []
    for ordinal, (q, p) in enumerate(sorted(pairs)):
        logical = [0, 1, 2, 3, 8, 64, 1024, MAX][ordinal % 8]
        rows.append({'quota': q, 'period': p, 'logical': logical, **expected(q, p, logical)})
    # A concrete counterexample to replacing the observed float path by ceildiv.
    rows.append({'quota': (1 << 53) + 1, 'period': 1 << 53, 'logical': 8,
                 **expected((1 << 53) + 1, 1 << 53, 8)})
    out = PACKET / 'oracle'
    out.mkdir(exist_ok=True)
    raw = (json.dumps(rows, indent=2) + '\n').encode()
    (out / 'vectors.json').write_bytes(raw)
    record = {'method': 'integer-only IEEE754 round-to-nearest ties-to-even input conversions and quotient; bit-derived ceil and saturation',
              'target_sha256': 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301',
              'target_arithmetic_va': ['0x5ba91d2', '0x5ba9268'],
              'target_publication_va': ['0x5ba95f6', '0x5ba96ee'],
              'vectors': len(rows), 'vectors_sha256': hashlib.sha256(raw).hexdigest(),
              'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'captured_binary_executed': False,
              'ancestry': {'commit': '91965a40c3a8a07d3c74f08acff2982a5714f1ae', 'generator_blob_sha256': '79dd9e9c51a612329023b0f20ea18b1544cd3e075551914027488025258ab2ab', 'reuse': 'Previously authored integer oracle; old Rust implementation already existed. Fresh115 evidence independently binds the same selected arithmetic. Not a newly invented blind oracle.'},
              'limits': 'Synthetic successfully parsed u64 quota/period and supplied logical count. File/parser/once/unwind and scheduling behavior excluded. Default floating environment only.'}
    (out / 'FREEZE.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    generate()
