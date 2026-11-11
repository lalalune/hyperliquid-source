"""Model of node #115 routine 0x5a00fc0: the spot scale
round-up wrapper.

The routine takes (rdi = object, rsi = second argument,
edx = flag, xmm0 = an f64 value v, rcx = a u64 n) and returns a
u64. The object and the second argument are forwarded unchanged
to the spot scale selector at 0x5a01310 (pinned by the open
RE-001-spot-scale-select-1310-115 packet, PR #3320); everything
the wrapper itself computes is modelled here:

* Front: if the flag in edx is nonzero, v is negated (an xorpd
  against the -0.0 mask). n is converted to an f64 by the
  magic-number sequence transcribed in u64_to_f64_sim (two
  biased partial values, one subtracted bias each, one addsd:
  the correctly rounded conversion). The product
  (v + 1.0) * (f64)n is formed with one addsd and one mulsd.
* Round leaf: the product is passed to the leaf at 0x63efe40,
  reached only through slot 0x64e1890. The leaf is the
  add-copysign(0.49999999999999994)-then-truncate construction:
  round to the nearest integer, halves away from zero. It is
  transcribed instruction by instruction in round_leaf_sim and
  proven equal to the exact rational spec round_half_away.
* Reference: the rounded value is clamped below by 0.0 with a
  maxsd against +0.0 (NaN becomes 0.0), then put through the
  saturating f64-to-u64 cast sequence transcribed in
  reference_sim: a +inf input takes the zeroed-scratch path and
  yields a cast of 0.0, values at or above 2**64 saturate to
  u64::MAX, and a cast result of exactly 0 is raised to 1.
* Rounding: the reference is divided by the selector's scale
  (a 32-bit div when both operands fit in 32 bits, else a
  64-bit div; the quotient is the same). The flag selects the
  quotient (flag == 0) or the quotient plus one (flag != 0,
  the increment saturating at u64::MAX). The chosen count is
  multiplied back by the scale; a multiplication overflow
  saturates to u64::MAX, and a product of 0 is raised to 1.

All four call sites in the binary pass the constant 0.1 as v
(the f64 at 0x4593e0), so in practice the reference is
round(0.9 * n) or round(1.1 * n) clamped as above, and the
result snaps that reference down (flag == 0) or up (flag != 0)
to a multiple of the spot scale, never returning 0.

The selector's return value is an input of this model (its
body is another packet's question). The model raises on
inputs the binary cannot express through that callee (a scale
of 0 would fault the division; the pinned selector contract
returns at least 1); those guards are model safety properties,
not binary claims.
"""

import math
import struct

_MASK64 = (1 << 64) - 1
_SIGN = 0x8000000000000000
_ABS_MASK = 0x7FFFFFFFFFFFFFFF

SELECTOR = 0x5A01310
ROUND_LEAF = 0x63EFE40
ROUND_SLOT = 0x64E1890

_TWO64 = 18446744073709551616.0          # 2**64 as an f64
_TWO64_MINUS_2048 = 18446744073709549568.0  # largest f64 below 2**64
_TWO63 = 9223372036854775808.0           # 2**63 as an f64
_INT_INDEFINITE = 0x8000000000000000     # cvttsd2si failure pattern


def _bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def _dbl(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & _MASK64))[0]


def _check_u64(name, value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an int" % name)
    if value < 0 or value > _MASK64:
        raise ValueError("%s out of u64 range" % name)


def u64_to_f64_sim(n):
    """Literal simulation of the wrapper's magic conversion:
    movq/punpckldq against the dwords at 0x451210 (0x43300000,
    0x45300000), subpd against the pair at 0x450170 (2**52,
    2**84), unpckhpd, addsd. Returns the f64 the sequence
    leaves in xmm2."""
    _check_u64("n", n)
    lo = _dbl(0x4330000000000000 | (n & 0xFFFFFFFF)) - _dbl(0x4330000000000000)
    hi = _dbl(0x4530000000000000 | (n >> 32)) - _dbl(0x4530000000000000)
    return hi + lo


def round_leaf_sim(x):
    """Literal simulation of the leaf at 0x63efe40: form
    s = x + copysign(0.49999999999999994, x), then, when the
    biased exponent of s is at most 0x432, clear the fraction
    bits of s below its binary point (a sign-only mask when
    |s| < 1) unless they are already clear."""
    bits_in = _bits(x)
    t = _dbl((bits_in & _SIGN) | 0x3FDF_FFFF_FFFF_FFFF)
    s = x + t
    sb = _bits(s)
    exp = (sb >> 52) & 0x7FF
    if exp > 0x432:
        return s
    if exp >= 0x3FF:
        signed = 0xFFF0000000000000 - (1 << 64)  # as a signed value
        mask = (signed >> (exp - 0x3FF)) & _MASK64
    else:
        mask = _SIGN
    if sb & (~mask & _MASK64) == 0:
        return s
    return _dbl(sb & mask)


def round_half_away(x):
    """Exact spec of the leaf: round to the nearest integer,
    halves away from zero; NaN and the infinities return
    themselves; -0.0 and small negatives return -0.0."""
    from fractions import Fraction
    if math.isnan(x) or math.isinf(x):
        return x
    mag = math.floor(abs(Fraction(x)) + Fraction(1, 2))
    result = float(mag)
    return math.copysign(result, x)


def _cvtt_bits(x):
    """The 64-bit pattern cvttsd2si produces for the f64 x:
    truncation toward zero, or the integer-indefinite pattern
    when x is NaN or outside the i64 range."""
    if math.isnan(x):
        return _INT_INDEFINITE
    t = int(x)  # int() truncates toward zero
    if t >= (1 << 63) or t < -(1 << 63):
        return _INT_INDEFINITE
    return t & _MASK64


def reference_sim(rounded):
    """Literal simulation of the wrapper's post-round sequence:
    maxsd against +0.0, the +inf scratch path, the 2**64 clamp,
    the two-part cvttsd2si cast, the sign guard, the
    2**64-2048 saturation threshold, and the raise of a 0
    result to 1. Input is the leaf's return value."""
    y = rounded if rounded > 0.0 else 0.0  # maxsd: NaN -> 0.0 too
    absbits = _bits(y) & _ABS_MASK
    if absbits > 0x7FEFFFFFFFFFFFFF:
        x2 = 0.0  # +inf: the jg path skips the clamp with xmm2 = 0
    elif y <= _TWO64:
        x2 = y
    else:
        x2 = _TWO64
    lo = _cvtt_bits(x2)
    hi = _cvtt_bits(x2 - _TWO63)
    sign_mask = _MASK64 if lo & _SIGN else 0  # sar by 63
    cand = lo | (hi & sign_mask)
    result = cand if x2 >= 0.0 else 0  # cmovae on ucomisd(x2, 0.0)
    if x2 > _TWO64_MINUS_2048:
        result = _MASK64  # cmovbe not taken: saturate
    if result == 0:
        result = 1  # cmp/adc: a zero reference is raised to 1
    return result


def reference_spec(rounded):
    """Closed form of reference_sim: NaN and non-positive
    values give 1 (through the 0 cast and its raise); +inf
    gives 1 (the scratch path casts 0.0); a finite value at or
    above 2**64 saturates to u64::MAX; any other value is its
    truncation toward zero, with 0 raised to 1."""
    if math.isnan(rounded) or rounded <= 0.0:
        return 1
    if math.isinf(rounded):
        return 1
    if rounded >= _TWO64:
        return _MASK64
    result = int(rounded)
    return result if result != 0 else 1


def reference(flag, value, n):
    """The wrapper's reference integer: negate the value when
    the flag is nonzero, convert n, form (value + 1.0) * (f64)n,
    round it through the leaf, and put it through the cast
    sequence. `value` is the f64 input, `n` the u64 input."""
    if not isinstance(value, float):
        raise TypeError("value must be a float")
    _check_u64("n", n)
    v = _dbl(_bits(value) ^ _SIGN) if flag else value
    product = (v + 1.0) * u64_to_f64_sim(n)
    return reference_sim(round_leaf_sim(product))


def reference_closed(flag, value, n):
    """Closed form of reference(), with float(n) and
    round_half_away in place of the transcribed sequences."""
    if not isinstance(value, float):
        raise TypeError("value must be a float")
    _check_u64("n", n)
    v = -value if flag else value
    product = (v + 1.0) * float(n)
    return reference_spec(round_half_away(product))


def round_to_scale(ref, scale, flag):
    """The wrapper's final stage: divide the reference by the
    selector's scale, take the quotient (flag == 0) or the
    quotient plus one (flag != 0, saturating), multiply back
    by the scale with overflow saturation, and raise a 0
    product to 1."""
    _check_u64("ref", ref)
    _check_u64("scale", scale)
    if scale == 0:
        raise ValueError("scale 0 would fault the binary's division; "
                         "the pinned selector never returns it")
    q = ref // scale  # the 32-bit and 64-bit div paths agree
    nxt = q + 1
    if nxt > _MASK64:
        nxt = _MASK64  # inc wrapped to 0; the cmove restores -1
    chosen = nxt if flag else q
    product = chosen * scale
    if product > _MASK64:
        product = _MASK64  # mul overflow: the result stays -1
    if product == 0:
        product = 1  # cmp/adc
    return product


def round_to_scale_spec(ref, scale, flag):
    """Closed form of round_to_scale()."""
    _check_u64("ref", ref)
    _check_u64("scale", scale)
    if scale == 0:
        raise ValueError("scale 0 would fault the binary's division; "
                         "the pinned selector never returns it")
    q, _rem = divmod(ref, scale)
    chosen = min(q + 1, _MASK64) if flag else q
    result = min(chosen * scale, _MASK64)
    return result if result != 0 else 1


def wrapper(value, n, flag, scale):
    """The whole routine: the reference from (value, n, flag),
    rounded to a multiple of the selector's scale. The object
    and second argument are not modelled; they only reach the
    selector, whose return value is `scale`."""
    return round_to_scale(reference(flag, value, n), scale, flag)


def wrapper_closed(value, n, flag, scale):
    """Closed form of wrapper()."""
    return round_to_scale_spec(reference_closed(flag, value, n), scale, flag)
