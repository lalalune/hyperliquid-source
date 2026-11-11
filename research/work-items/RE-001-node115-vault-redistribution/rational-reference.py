#!/usr/bin/env python3
"""Independent integer/Fraction binary64 oracle; never executes target code.

Round every scalar operation to nearest, ties to even, with gradual underflow.
No host floating-point arithmetic is used by the reference calculation.
"""
from fractions import Fraction
import argparse
import hashlib
import json
from pathlib import Path

SIGN = 1 << 63
INF = 0x7FF0000000000000
NAN = 0x7FF8000000000000
MAX = 0x7FEFFFFFFFFFFFFF
MILLION = 0x412E848000000000
FLOOR = 0x3E7AD7F29ABCAF48
TINY = 0x3CD203AF9EE75616


def finite(bits):
    return (bits & ~SIGN) < INF


def rational(bits):
    assert finite(bits)
    exponent = (bits >> 52) & 2047
    mantissa = bits & ((1 << 52) - 1)
    if exponent:
        mantissa += 1 << 52
        power = exponent - 1075
    else:
        power = -1074
    value = Fraction(mantissa) * Fraction(2) ** power
    return -value if bits & SIGN else value


def round_integer(numerator, denominator):
    value, remainder = divmod(numerator, denominator)
    if 2 * remainder > denominator or (2 * remainder == denominator and value & 1):
        value += 1
    return value


def rounded(value, negative_zero=False):
    sign = SIGN if value < 0 or (value == 0 and negative_zero) else 0
    value = abs(value)
    if not value:
        return sign
    n, d = value.numerator, value.denominator
    exponent = n.bit_length() - d.bit_length()
    if value < Fraction(2) ** exponent:
        exponent -= 1
    if exponent > 1023:
        return sign | INF
    shift = max(52 - exponent, 0) if exponent >= -1022 else 1074
    if exponent > 52:
        d <<= exponent - 52
    else:
        n <<= shift
    mantissa = round_integer(n, d)
    if exponent < -1022:
        return sign | mantissa  # A carry becomes the smallest normal value.
    if mantissa == 1 << 53:
        mantissa >>= 1
        exponent += 1
    if exponent > 1023:
        return sign | INF
    return sign | ((exponent + 1023) << 52) | (mantissa - (1 << 52))


def multiply(a, b):
    sign = (a ^ b) & SIGN
    if (a & ~SIGN) > INF or (b & ~SIGN) > INF:
        return NAN
    if not finite(a) or not finite(b):
        return NAN if (a & ~SIGN) == 0 or (b & ~SIGN) == 0 else sign | INF
    return rounded(rational(a) * rational(b), bool(sign))


def add(a, b):
    if (a & ~SIGN) > INF or (b & ~SIGN) > INF:
        return NAN
    if not finite(a) or not finite(b):
        if not finite(a) and not finite(b) and (a ^ b) & SIGN:
            return NAN
        return a if not finite(a) else b
    return rounded(rational(a) + rational(b), a == SIGN and b == SIGN)


def divide(a, b):
    # All denominators used by this oracle are finite and strictly positive.
    assert finite(b) and rational(b) > 0
    if not finite(a):
        return NAN if (a & ~SIGN) > INF else a
    return rounded(rational(a) / rational(b), bool(a & SIGN))


def reference(prior, delta, weight, selected, mutation=None):
    total = min(max(prior + delta, -(1 << 63)), (1 << 63) - 1)
    if mutation == "wrapping-total":
        total = ((prior + delta + (1 << 63)) % (1 << 64)) - (1 << 63)
    denominator = divide(rounded(Fraction(max(total, 0))), MILLION)
    if mutation == "floating-total":
        total_bits = add(rounded(Fraction(prior)), rounded(Fraction(delta)))
        denominator = divide(total_bits if rational(total_bits) > 0 else 0, MILLION)
    prior_scale = divide(rounded(Fraction(prior)), MILLION)
    numerator = multiply(weight, prior_scale)
    if selected and mutation != "omit-selected-addition":
        numerator = add(numerator, divide(rounded(Fraction(delta)), MILLION))
    if not finite(numerator):
        return 0
    below_floor = rational(numerator) < rational(FLOOR)
    if mutation == "inclusive-floor":
        below_floor = rational(numerator) <= rational(FLOOR)
    if below_floor or rational(denominator) < rational(TINY):
        return 0
    if mutation == "cancel-scales":
        value = (rational(weight) * prior + (delta if selected else 0)) / total
        quotient = rounded(value)
    else:
        quotient = divide(numerator, denominator)
    return quotient if finite(quotient) else 0


def inputs():
    priors = [
        -(1 << 63), -(1 << 63) + 1, -(1 << 53) - 1, -(1 << 53),
        -2_000_000, -1_000_001, -1_000_000, -999_999, -3, -1, 0, 1,
        2, 3, 999_999, 1_000_000, 1_000_001, 2_000_000, (1 << 31) - 1,
        (1 << 53) - 1, 1 << 53, (1 << 53) + 1, (1 << 63) - 2, (1 << 63) - 1,
    ]
    deltas = [
        -(1 << 63), -(1 << 53) - 1, -2_000_000, -1_000_001, -1_000_000,
        -999_999, -1, 0, 1, 3, 999_999, 1_000_000, 1_000_001,
        (1 << 53) + 1, (1 << 63) - 2, (1 << 63) - 1,
    ]
    weights = [
        SIGN | INF, SIGN | MAX, 0xBFF0000000000000, SIGN | (1 << 52),
        SIGN | 1, SIGN, 0, 1, (1 << 52) - 1, 1 << 52,
        FLOOR - 1, FLOOR, FLOOR + 1, TINY,
        0x3FD0000000000000, 0x3FE0000000000000, 0x3FF0000000000000,
        0x3FF0000000000001, 0x4000000000000000, MAX, INF, NAN,
        SIGN | NAN, INF | 1,
    ]
    assert (len(priors), len(deltas), len(weights)) == (24, 16, 24)
    for prior in priors:
        for delta in deltas:
            for weight in weights:
                for selected in (False, True):
                    yield prior, delta, weight, selected


def self_check():
    assert rounded(Fraction(1)) == 0x3FF0000000000000
    assert rounded(Fraction(1_000_000)) == MILLION
    assert rounded(Fraction(1, 10_000_000)) == FLOOR
    assert rounded(Fraction(1, 10**15)) == TINY
    assert rounded(Fraction((1 << 53) + 1)) == rounded(Fraction(1 << 53))
    assert rounded(Fraction((1 << 53) + 3)) == rounded(Fraction((1 << 53) + 4))
    assert rounded(Fraction(1, 1 << 1075)) == 0
    assert rounded(Fraction(3, 1 << 1075)) == 2
    assert rounded(rational(MAX) + Fraction(2) ** 970) == INF
    for _, _, bits, _ in inputs():
        if finite(bits):
            assert rounded(rational(bits), bits == SIGN) == bits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate fixture and summary")
    args = parser.parse_args()
    self_check()
    directory = Path(__file__).resolve().parent
    root = directory.parents[2]
    fixture = root / "src/node115-vault-redistribution/tests/rational-vectors.txt"
    summary_path = directory / "rational-comparison.json"
    mutations = {key: 0 for key in (
        "wrapping-total", "floating-total", "omit-selected-addition", "inclusive-floor", "cancel-scales"
    )}
    lines = ["# prior_i64 delta_i64 weight_binary64_bits selected expected_binary64_bits"]
    for prior, delta, weight, selected in inputs():
        expected = reference(prior, delta, weight, selected)
        lines.append(f"{prior} {delta} {weight:016x} {int(selected)} {expected:016x}")
        for mutation in mutations:
            mutations[mutation] += reference(prior, delta, weight, selected, mutation) != expected
    count = len(lines) - 1
    assert count == 18432 and all(mutations.values()), mutations
    contents = "\n".join(lines) + "\n"
    summary = {
        "method": "independent exact integer/Fraction binary64 rounding; synthetic cases, not target execution",
        "rounding": "nearest, ties to even; gradual underflow; separate rounding at every operation",
        "dimensions": {"prior_i64": 24, "delta_i64": 16, "weight_bits": 24, "selected": 2},
        "cases": count,
        "fixture_sha256": hashlib.sha256(contents.encode()).hexdigest(),
        "negative_controls_differing_cases": mutations,
        "limits": ["not a runtime differential test", "no assertion about native floating environment setup", "no NaN payload identity claim"],
    }
    summary_text = json.dumps(summary, indent=2) + "\n"
    if args.write:
        fixture.write_text(contents)
        summary_path.write_text(summary_text)
    else:
        assert fixture.read_text() == contents, "reference fixture differs"
        assert summary_path.read_text() == summary_text, "reference summary differs"
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
