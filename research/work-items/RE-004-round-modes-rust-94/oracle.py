#!/usr/bin/env python3
"""Exact-rational addition and rounding, not captured instruction evaluation."""
import hashlib
import json
from pathlib import Path
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
SIGN, FRACTION = 1 << 63, (1 << 52) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rational_round(bits, mode, daz=False):
    """Return trunc(RC64(x + copysign(1/2 - 2^-54, x))).

    Mode codes are MXCSR.RC: 0 nearest-even, 1 toward -infinity,
    2 toward +infinity, 3 toward zero. All target SIMD exceptions masked.
    """
    sign, exponent, fraction = bits & SIGN, (bits >> 52) & 2047, bits & FRACTION
    if exponent == 2047:
        return bits | (1 << 51) if fraction else bits
    significand = fraction if exponent == 0 else (1 << 52) + fraction
    power = -1074 if exponent == 0 else exponent - 1075
    if daz and exponent == 0:
        significand = 0
    denominator_power = max(54, -power)
    numerator = (significand << (power + denominator_power)) + (
        ((1 << 53) - 1) << (denominator_power - 54))
    # Quantize this exact positive magnitude to a 53-bit significand.
    top = numerator.bit_length() - 1 - denominator_power
    discarded = numerator.bit_length() - 1 - 52
    if discarded > 0:
        quotient, remainder = divmod(numerator, 1 << discarded)
        upward = (mode == 1 and bool(sign)) or (mode == 2 and not sign)
        if mode == 0:
            halfway = 1 << (discarded - 1)
            quotient += remainder > halfway or (remainder == halfway and quotient % 2 == 1)
        elif upward:
            quotient += remainder != 0
    else:
        quotient = numerator << -discarded
    if quotient == 1 << 53:
        quotient >>= 1
        top += 1
    if top > 1023:
        return sign | (2047 << 52)
    # Truncate the rounded binary64 value mathematically, then encode the
    # resulting integer exactly. No Rust mask/increment rule is used here.
    integer = quotient << (top - 52) if top >= 52 else quotient // (1 << (52 - top))
    if integer == 0:
        return sign
    highest = integer.bit_length() - 1
    mantissa = integer << (52 - highest) if highest <= 52 else integer >> (highest - 52)
    require(highest <= 52 or integer == mantissa << (highest - 52), 'inexact integer result')
    return sign | ((highest + 1023) << 52) | (mantissa - (1 << 52))


def corpus():
    values = set()
    for exponent in range(2048):
        fractions = {0, 1, 2, (1 << 51) - 1, 1 << 51, FRACTION - 1, FRACTION}
        if 1023 <= exponent <= 1074:
            unit = 1 << (1075 - exponent)
            for center in (unit // 2, unit, 3 * unit // 2, 2 * unit, FRACTION - unit // 2):
                fractions.update(v for v in (center - 1, center, center + 1) if 0 <= v <= FRACTION)
        values.update(sign | exponent << 52 | fraction
                      for sign in (0, SIGN) for fraction in fractions)
    values.update(int.from_bytes(hashlib.sha256(f'round-modes94:{i}'.encode()).digest()[:8], 'little')
                  for i in range(4096))
    return sorted(values)


def fixtures():
    values = corpus()
    inputs, expected = bytearray(), bytearray()
    for bits in values:
        for mode in range(4):
            answer = rational_round(bits, mode)
            require(answer == rational_round(bits, mode, daz=True), 'DAZ changes output bits')
            inputs += struct.pack('<QB', bits, mode)
            expected += struct.pack('<Q', answer)
    witnesses = {}
    for label, bits in [('positive-half', 0x3fe0000000000000),
                        ('negative-half', 0xbfe0000000000000),
                        ('positive-2pow52', 0x4330000000000000),
                        ('negative-2pow52', 0xc330000000000000),
                        ('largest-finite', 0x7fefffffffffffff),
                        ('signaling-nan', 0x7ff0000000000001),
                        ('negative-zero', SIGN)]:
        witnesses[label] = {'input': f'{bits:016x}',
                            'outputs_rc_0_1_2_3': [f'{rational_round(bits, m):016x}' for m in range(4)]}
    return bytes(inputs), bytes(expected), {'input_words': len(values), 'cases': len(values) * 4,
        'exponents': 2048, 'rounding_modes': 4, 'daz_modes_checked_equal': 2,
        'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected), 'witnesses': witnesses}


if __name__ == '__main__':
    require(not (ROOT / 'src/node94-round-modes/lib.rs').exists(), 'freeze must precede Rust')
    inputs, expected, record = fixtures()
    record['oracle_sha256_at_freeze'] = sha(Path(__file__).read_bytes())
    record['rust_source_existed_at_freeze'] = False
    with (PACKET / 'frozen.json').open('x') as file:
        json.dump(record, file, indent=2, sort_keys=True)
        file.write('\n')
    print(json.dumps(record, indent=2))
