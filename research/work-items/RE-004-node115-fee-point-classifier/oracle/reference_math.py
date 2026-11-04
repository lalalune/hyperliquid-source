"""Scalar-only exact-rational reference for the bounded fee point projection.

This module does not read captured artifacts, decode instructions, model a CPU,
or access files/network/processes. Finite binary64 arithmetic is reconstructed
from exact Fractions with one explicit RN-even rounding per mathematical
operation. FP exceptions are assumed masked, with gradual underflow. Only the
five chosen classification strings are exposed by classify_point().
"""
from fractions import Fraction

SIGN = 1 << 63
FRACTION_MASK = (1 << 52) - 1
EXPONENT_MASK = 0x7FF
POSITIVE_INFINITY = 0x7FF0000000000000
CANONICAL_NAN = 0x7FF8000000000000
ONE = 0x3FF0000000000000
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1
U64_MAX = (1 << 64) - 1
SCALE_BITS = (
    0x3FF0000000000000,
    0x3FC999999999999A,
    0x4018000000000000,
    0x3FB999999999999A,
    0x4000000000000000,
    0x4044000000000000,
)
CLASSIFICATIONS = (
    "FirstProductNegative",
    "NetAndBaseNegative",
    "SecondProductNegative",
    "RoundedMagnitudeAtLeastQuantity",
    "Pass",
)


def require_bits(bits: int) -> int:
    if type(bits) is not int or not 0 <= bits <= U64_MAX:
        raise ValueError("binary64 input must be an unsigned 64-bit integer")
    return bits


def is_nonfinite(bits: int) -> bool:
    return ((bits >> 52) & EXPONENT_MASK) == EXPONENT_MASK


def is_nan(bits: int) -> bool:
    return is_nonfinite(bits) and (bits & FRACTION_MASK) != 0


def is_zero(bits: int) -> bool:
    return (bits & ~SIGN) == 0


def finite_fraction(bits: int) -> Fraction:
    """Decode a scalar binary64 representation as an exact rational value."""
    require_bits(bits)
    if is_nonfinite(bits):
        raise ValueError("nonfinite scalar has no rational value")
    exponent = (bits >> 52) & EXPONENT_MASK
    significand = bits & FRACTION_MASK
    if exponent == 0:
        power = -1074
    else:
        significand += 1 << 52
        power = exponent - 1023 - 52
    if bits & SIGN:
        significand = -significand
    if power >= 0:
        return Fraction(significand << power)
    return Fraction(significand, 1 << -power)


def _nearest_even_integer(numerator: int, denominator: int) -> int:
    """Round a nonnegative rational to its nearest integer; ties choose even."""
    quotient, remainder = divmod(numerator, denominator)
    comparison = 2 * remainder - denominator
    if comparison > 0 or (comparison == 0 and quotient % 2 == 1):
        quotient += 1
    return quotient


def _scaled_nearest(numerator: int, denominator: int, power: int) -> int:
    """Round (numerator / denominator) / 2**power without host floats."""
    if power >= 0:
        return _nearest_even_integer(numerator, denominator << power)
    return _nearest_even_integer(numerator << -power, denominator)


def round_binary64(value: Fraction, *, negative_zero: bool = False) -> int:
    """Round an exact rational to binary64 RN-even with gradual underflow."""
    if type(value) is not Fraction:
        raise TypeError("round_binary64 requires an exact Fraction")
    if value == 0:
        return SIGN if negative_zero else 0
    sign = SIGN if value < 0 else 0
    numerator = abs(value.numerator)
    denominator = value.denominator
    exponent = numerator.bit_length() - denominator.bit_length()
    if exponent >= 0:
        if numerator < (denominator << exponent):
            exponent -= 1
    elif (numerator << -exponent) < denominator:
        exponent -= 1

    if exponent < -1022:
        significand = _scaled_nearest(numerator, denominator, -1074)
        # The integer encoding also handles a rounded carry into min-normal.
        return sign | significand

    significand = _scaled_nearest(numerator, denominator, exponent - 52)
    if significand == (1 << 53):
        significand >>= 1
        exponent += 1
    if exponent > 1023:
        return sign | POSITIVE_INFINITY
    exponent_field = exponent + 1023
    return sign | (exponent_field << 52) | (significand - (1 << 52))


def rn_sub(left: int, right: int) -> int:
    """One separately rounded mathematical binary64 subtraction."""
    require_bits(left)
    require_bits(right)
    if is_nan(left) or is_nan(right):
        return CANONICAL_NAN
    if is_nonfinite(left):
        if is_nonfinite(right) and ((left ^ right) & SIGN) == 0:
            return CANONICAL_NAN
        return left
    if is_nonfinite(right):
        return right ^ SIGN
    exact = finite_fraction(left) - finite_fraction(right)
    return round_binary64(exact, negative_zero=(left == SIGN and right == 0))


def rn_mul(left: int, right: int) -> int:
    """One separately rounded mathematical binary64 multiplication."""
    require_bits(left)
    require_bits(right)
    if is_nan(left) or is_nan(right):
        return CANONICAL_NAN
    sign = (left ^ right) & SIGN
    if is_nonfinite(left) or is_nonfinite(right):
        if is_zero(left) or is_zero(right):
            return CANONICAL_NAN
        return sign | POSITIVE_INFINITY
    exact = finite_fraction(left) * finite_fraction(right)
    return round_binary64(exact, negative_zero=bool(sign))


def rounded_i64(value: int) -> int:
    """Signed-i64 to binary64, rounded independently with RN-even."""
    if type(value) is not int or not I64_MIN <= value <= I64_MAX:
        raise ValueError("signed conversion input is outside i64")
    return round_binary64(Fraction(value))


def nonfinite_zero_integer(bits: int) -> int:
    """Nonfinite ->0; otherwise toward-zero conversion saturated to i64."""
    require_bits(bits)
    if is_nonfinite(bits):
        return 0
    exact = finite_fraction(bits)
    if exact <= I64_MIN:
        return I64_MIN
    if exact >= (1 << 63):
        return I64_MAX
    magnitude = abs(exact.numerator) // exact.denominator
    return -magnitude if exact < 0 else magnitude


def _saturate_i64(value: int) -> int:
    return max(I64_MIN, min(I64_MAX, value))


def classify_point(*, t: int, d: int, q: int, m: int, h: int,
                   scale: int, quantity: int) -> str:
    """First numerical rejection or Pass in the fixed admitted value domain.

    Domain refusal is host policy, not a recovered native rejection. There is
    no helper-result argument and no returned diagnostic/winner/native state.
    """
    for bits in (t, d, q, m, h, scale):
        require_bits(bits)
    if scale not in SCALE_BITS:
        raise ValueError("scale is outside the six admitted encodings")
    if type(quantity) is not int or not 1 <= quantity <= 10_000_000:
        raise ValueError("quantity is outside 1..=10,000,000")

    n_float = rounded_i64(quantity)
    a = nonfinite_zero_integer(
        rn_mul(rn_mul(rn_mul(rn_sub(ONE, d), t), scale), n_float)
    )
    b = nonfinite_zero_integer(rn_mul(rounded_i64(a), q))
    if b < 0:
        return "FirstProductNegative"

    base = nonfinite_zero_integer(rn_mul(rn_mul(m, scale), n_float))
    net = _saturate_i64(a - b)
    combined = _saturate_i64(net + base)
    if combined < 0:
        return "NetAndBaseNegative"

    other = nonfinite_zero_integer(rn_mul(rn_mul(scale, h), n_float))
    other_product = nonfinite_zero_integer(rn_mul(q, rounded_i64(other)))
    if other_product < 0:
        return "SecondProductNegative"

    # This first sum is <=2**64-2; abs(I64_MIN) is mathematically 2**63.
    # base==I64_MIN cannot reach here after the combined-negative guard.
    positive_sum = other_product + max(other, 0)
    total = min(U64_MAX, positive_sum + abs(base))
    if total >= quantity:
        return "RoundedMagnitudeAtLeastQuantity"
    return "Pass"
