#!/usr/bin/env python3
"""Exact-rational binary64 fixture oracle, not captured execution/emulation."""
import argparse
from fractions import Fraction as F
from pathlib import Path

MASK = (1 << 96) - 1
SIGN = 1 << 63

def rounded_bits(value):
    """Round a nonnegative rational to normal IEEE binary64, nearest/even."""
    assert value >= 0
    if not value:
        return 0
    n, d = value.numerator, value.denominator
    exponent = n.bit_length() - d.bit_length()
    if (n < d << exponent) if exponent >= 0 else (n << -exponent < d):
        exponent -= 1
    assert -1022 <= exponent <= 1023
    shift = 52 - exponent
    n, d = (n << shift, d) if shift >= 0 else (n, d << -shift)
    q, r = divmod(n, d)
    if 2 * r > d or (2 * r == d and q & 1):
        q += 1
    if q == 1 << 53:
        q >>= 1
        exponent += 1
    return ((exponent + 1023) << 52) | (q - (1 << 52))

def exact(bits):
    if bits == 0:
        return F(0)
    exponent = ((bits >> 52) & 2047) - 1023 - 52
    mantissa = (1 << 52) | (bits & ((1 << 52) - 1))
    return F(mantissa << exponent) if exponent >= 0 else F(mantissa, 1 << -exponent)

def rnd(value):
    return exact(rounded_bits(value))

def expected(coefficient, scale, negative):
    if scale == 0:
        bits = rounded_bits(F(coefficient))
        return bits | (SIGN if negative and coefficient else 0)
    divisor = 10 ** scale
    quotient, remainder = divmod(coefficient, divisor)
    fraction = rnd(rnd(F(remainder)) / rnd(F(divisor)))
    value = rnd(F(quotient))
    if fraction:
        value = rnd(value + fraction)
        # Independently evaluate the multiplication expression tree for 10^s.
        powers = [F(10)]
        for _ in range(scale.bit_length() - 1):
            powers.append(rnd(powers[-1] ** 2))
        multiplier = F(1)
        for bit, power in enumerate(powers):
            if scale & (1 << bit):
                multiplier = rnd(multiplier * power)
        product = rnd(value * multiplier)
        shifted = rnd(product + F((1 << 53) - 1, 1 << 54))
        integer = shifted.numerator // shifted.denominator
        value = rnd(F(integer) / multiplier)
    return rounded_bits(value) | (SIGN if negative else 0)

def fixtures():
    # Fixed edges plus deterministic 96-bit coverage; no target samples used.
    base = {0, 1, 2, 5, 9, 10, 11, 99, 100, 101, MASK, MASK - 1, MASK // 2}
    for exponent in (31, 32, 52, 53, 54, 63, 64, 65, 94, 95):
        base.update((1 << exponent) + delta for delta in (-1, 0, 1))
    state = 0x7a12c3de98b5f12409abcde
    rows = []
    for scale in range(29):
        values = set(base)
        denominator = 10 ** scale
        for multiplier in (1, 2, 7):
            values.update(multiplier * denominator + d for d in (-1, 0, 1))
        for _ in range(12):
            state = (state * 6364136223846793005 + 1442695040888963407) & MASK
            values.add(state)
        for coefficient in sorted(v for v in values if 0 <= v <= MASK):
            for negative in (False, True):
                rows.append(f'{coefficient}\t{scale}\t{int(negative)}\t{expected(coefficient, scale, negative):016x}')
    return '# coefficient\tscale\tnegative\texpected_binary64_bits\n' + '\n'.join(rows) + '\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    text = fixtures()
    if args.write:
        args.fixtures.write_text(text)
    else:
        assert args.fixtures.read_text() == text, 'frozen independent fixtures differ'
    print(f'PASS: {len(text.splitlines()) - 1} independently rounded fixture cases')

if __name__ == '__main__':
    main()
