#!/usr/bin/env python3
"""Exact-rational witnesses for the independently authored Rust projection.

No target file or instruction stream is loaded, interpreted or executed.
The domain is positive normal binary64 values in the selected formatting path.
"""
import argparse
from fractions import Fraction
import json
from pathlib import Path

PRODUCTS = [
    1844674407370955162, 1844674407370955163,
    1844674407370955289, 1844674407370955290,
    2305843009213693951, 2305843009213693952,
    2305843009213694208, 2305843009213694720,
    4611686018427387903, 4611686018427388416,
    9223372036854775807,
]


def round_normal(value):
    """Round a positive rational by quotient/remainder and an even tie rule."""
    if value <= 0:
        raise ValueError('positive normal domain required')
    numerator, denominator = value.numerator, value.denominator
    exponent = numerator.bit_length() - denominator.bit_length()
    if exponent >= 0:
        if numerator < denominator << exponent:
            exponent -= 1
    elif numerator << -exponent < denominator:
        exponent -= 1
    if not -1022 <= exponent <= 1023:
        raise ValueError('positive normal domain required')
    shift = 52 - exponent
    scaled, divisor = ((numerator << shift, denominator) if shift >= 0
                       else (numerator, denominator << -shift))
    significand, remainder = divmod(scaled, divisor)
    if 2 * remainder > divisor or (2 * remainder == divisor and significand & 1):
        significand += 1
    if significand == 1 << 53:
        significand >>= 1
        exponent += 1
    if exponent > 1023:
        raise ValueError('finite normal domain required')
    bits = ((exponent + 1023) << 52) | (significand - (1 << 52))
    exact = (Fraction(significand << (exponent - 52)) if exponent >= 52
             else Fraction(significand, 1 << (52 - exponent)))
    return bits, exact


def witnesses():
    rows = []
    for product in PRODUCTS:
        cast, cast_value = round_normal(Fraction(product))
        quotient, _ = round_normal(cast_value / 1_000_000)
        single, _ = round_normal(Fraction(product, 1_000_000))
        rows.append({'product': product, 'cast_bits': f'{cast:016x}',
                     'quotient_bits': f'{quotient:016x}',
                     'one_round_rational_bits': f'{single:016x}'})
    # Independently checked rational midpoint separation at the high threshold.
    assert rows[0]['quotient_bits'] == '427ad7f29abcaf49'
    assert rows[0]['one_round_rational_bits'] == '427ad7f29abcaf48'
    return {'method': 'exact rational nearest-even arithmetic; no target execution or instruction evaluation',
            'rounding_premise': 'separate nearest-even integer conversion and division; precision exception masked',
            'cases': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = Path(__file__).with_name('rounding.json')
    encoded = json.dumps(witnesses(), indent=2) + '\n'
    if args.check:
        if path.read_text() != encoded:
            raise SystemExit('rounding witness drift')
        print('11 exact-rational rounding witnesses match')
    else:
        path.write_text(encoded)


if __name__ == '__main__':
    main()
