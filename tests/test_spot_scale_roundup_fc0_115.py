#!/usr/bin/env python3
"""Checks for the 0x5a00fc0 spot scale round-up wrapper model.

Proves, on directed and random inputs:

* the magic u64-to-f64 conversion sequence equals float(n),
  the correctly rounded conversion, on every input tried;
* the round leaf's instruction transcription equals the
  exact round-half-away-from-zero spec;
* the reference's transcription (maxsd, +inf scratch path,
  2**64 clamp, two-part cast, saturation threshold, 0 -> 1
  raise) equals its closed form;
* the final stage's transcription equals its closed form,
  and the full wrapper equals the composed closed form,
  including the four call sites' actual constant 0.1 input.

Every numeric expectation is derived from exact rational or
integer arithmetic or from Python's correctly rounded float
operations, never from the transcription under test alone.

Run: python3 tests/test_spot_scale_roundup_fc0_115.py
"""

import math
import random
import struct
import sys
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import spot_scale_roundup_fc0_115 as M  # noqa: E402

CHECKS = 0
MASK64 = (1 << 64) - 1


def eq(got, want, label):
    global CHECKS
    CHECKS += 1
    if got != want:
        raise AssertionError("%s: got %r, want %r" % (label, got, want))


def same_double(got, want, label):
    """Bitwise f64 equality (NaN payloads and zero signs count)."""
    global CHECKS
    CHECKS += 1
    g = struct.pack("<d", got).hex()
    w = struct.pack("<d", want).hex()
    if math.isnan(want):
        if not math.isnan(got):
            raise AssertionError("%s: got %r, want NaN" % (label, got))
        return
    if g != w:
        raise AssertionError("%s: got %r (%s), want %r (%s)"
                             % (label, got, g, want, w))


def raises(fn, kinds, label):
    global CHECKS
    CHECKS += 1
    try:
        fn()
    except kinds:
        return
    raise AssertionError("%s: expected %s" % (label, kinds))


# -- the magic conversion -------------------------------------------

def check_conversion(rng):
    directed = [0, 1, 2, 3, 10, 2**31 - 1, 2**31, 2**32 - 1, 2**32,
                2**32 + 1, 2**52 - 1, 2**52, 2**53 - 1, 2**53, 2**53 + 1,
                2**53 + 2, 2**63 - 1, 2**63, 2**64 - 2048, 2**64 - 1,
                12345678901234567890]
    for n in directed:
        same_double(M.u64_to_f64_sim(n), float(n), "conv directed %d" % n)
    for _ in range(3000):
        n = rng.getrandbits(64)
        same_double(M.u64_to_f64_sim(n), float(n), "conv random")
    for bits in range(0, 64):
        for delta in (-2, -1, 0, 1, 2):
            n = (1 << bits) + delta
            if 0 <= n <= MASK64:
                same_double(M.u64_to_f64_sim(n), float(n), "conv edges")


# -- the round leaf ---------------------------------------------------

def exact_round(x):
    """Independent oracle: Fraction arithmetic implementing
    round-half-away-from-zero."""
    if math.isnan(x) or math.isinf(x):
        return x
    mag = math.floor(abs(Fraction(x)) + Fraction(1, 2))
    return math.copysign(float(mag), x)


def check_leaf(rng):
    directed = [0.0, -0.0, 0.1, -0.1, 0.4, 0.5, -0.5, 0.49999999999999994,
                -0.49999999999999994, 0.5000000000000001, 1.5, -1.5, 2.5,
                -2.5, 3.5, 123456.5, -123456.5, 0.9999999999999999,
                4503599627370495.5, 4503599627370496.0, 2.0**52 - 0.5,
                2.0**52, 2.0**52 + 2.0, 2.0**53, 1e15 + 0.5, 1e16,
                1.5e300, -1.5e300, 5e-324, -5e-324, 0.05, 2.675,
                float("inf"), float("-inf")]
    for x in directed:
        same_double(M.round_leaf_sim(x), exact_round(x),
                    "leaf directed %r" % x)
        same_double(M.round_half_away(x), exact_round(x),
                    "spec directed %r" % x)
    same_double(M.round_leaf_sim(float("nan")), float("nan"), "leaf NaN")
    # Every half-integer boundary in a wide range, both signs.
    for k in range(0, 200000, 977):
        for x in (k + 0.5, -(k + 0.5), float(k), float(-k)):
            same_double(M.round_leaf_sim(x), exact_round(x), "leaf halves")
    # Random raw bit patterns (any exponent), random "nice" values.
    for _ in range(6000):
        bits = rng.getrandbits(64)
        x = struct.unpack("<d", struct.pack("<Q", bits))[0]
        if math.isnan(x):
            continue
        same_double(M.round_leaf_sim(x), exact_round(x), "leaf bits")
    for _ in range(6000):
        x = rng.uniform(-1e6, 1e6) + rng.choice([0.0, 0.5, -0.5, 0.25])
        same_double(M.round_leaf_sim(x), exact_round(x), "leaf uniform")
    # The exact inputs the wrapper produces: (v + 1) * m for
    # v = +/-0.1 and converted counts m.
    for _ in range(3000):
        n = rng.getrandbits(rng.choice([8, 16, 32, 48, 64]))
        for v in (0.1, -0.1):
            x = (v + 1.0) * float(n)
            same_double(M.round_leaf_sim(x), exact_round(x), "leaf product")


# -- the reference cast -------------------------------------------------

def check_reference(rng):
    directed = [
        # (flag, value, n, expected reference or None for spec-only)
        (0, 0.1, 0, 1),        # product 0.0 -> round 0 -> cast 0 -> 1
        (1, 0.1, 0, 1),        # product 0.0 as well (0 * -0.9)
        (0, 0.1, 10, 11),      # round(1.1 * 10) = 11
        (1, 0.1, 10, 9),       # round(0.9 * 10) = 9
        (0, 0.1, 5, 6),        # round(5.5) = 6 (half away from zero)
        (1, 0.1, 5, 5),        # round(4.5) = 5 (half away from zero)
        (0, 0.1, 15, 17),      # round(16.5) = 17
        (1, 0.1, 15, 14),      # round(13.5) = 14
        (0, 0.1, 100, 110),
        (1, 0.1, 100, 90),
        (0, -2.0, 10, 1),      # product -10 -> maxsd 0 -> 1
        (0, float("nan"), 10, 1),   # NaN -> maxsd 0.0 -> 1
        (0, float("inf"), 10, 1),   # +inf product -> scratch path -> 1
        (1, float("inf"), 10, 1),   # product -inf -> maxsd 0 -> 1
        (0, 1e308, 2**64 - 1, 1),   # product overflows to +inf -> 1
        (0, 1.0, 2**63, MASK64),    # product exactly 2**64 -> saturate
    ]
    for flag, value, n, want in directed:
        eq(M.reference(flag, value, n), want,
           "reference directed %r" % ((flag, value, n),))
        eq(M.reference_closed(flag, value, n), want,
           "reference closed %r" % ((flag, value, n),))
    # Cast-level directed values through reference_sim/spec.
    cast_cases = [0.0, -0.0, -1.5, 0.4, 0.5, 0.9999999999999999, 1.0,
                  42.9, 2.0**63 - 1024.0, 2.0**63, 2.0**63 + 2048.0,
                  2.0**64 - 2048.0, 2.0**64, 1.7e308,
                  float("inf"), float("-inf"), float("nan")]
    for y in cast_cases:
        eq(M.reference_sim(y), M.reference_spec(y), "cast %r" % y)
    eq(M.reference_sim(2.0**64 - 2048.0), 2**64 - 2048, "cast max finite")
    eq(M.reference_sim(2.0**64), MASK64, "cast 2**64 saturates")
    eq(M.reference_sim(float("inf")), 1, "cast +inf scratch path")
    eq(M.reference_sim(0.5), 1, "cast sub-one raises to 1")
    # Random products through both forms.
    for _ in range(4000):
        n = rng.getrandbits(rng.choice([8, 24, 40, 53, 64]))
        flag = rng.getrandbits(1)
        v = rng.choice([0.1, -0.1, rng.uniform(-3, 3),
                        rng.uniform(-1e18, 1e18)])
        eq(M.reference(flag, v, n), M.reference_closed(flag, v, n),
           "reference random")


# -- the final stage and the whole wrapper ------------------------------

def check_final(rng):
    directed = [
        # (ref, scale, flag, expected)
        (11, 10, 0, 10),       # floor snap
        (11, 10, 1, 20),       # ceiling snap
        (10, 10, 0, 10),
        (10, 10, 1, 20),
        (9, 10, 1, 10),
        (1, 10, 0, 1),         # quotient 0 -> product 0 -> raised to 1
        (1, 10, 1, 10),
        (0, 10, 0, 1),         # unreachable reference, still total
        (0, 10, 1, 10),
        (2**64 - 1, 1, 0, 2**64 - 1),
        (2**64 - 1, 1, 1, 2**64 - 1),   # q+1 saturates, product = max
        (2**64 - 1, 2, 1, 2**64 - 1),   # (q+1)*2 overflows -> saturate
        (2**63, 2**63, 1, MASK64),
        (123456789, 1000, 0, 123456000),
        (123456789, 1000, 1, 123457000),
    ]
    for ref, scale, flag, want in directed:
        eq(M.round_to_scale(ref, scale, flag), want,
           "final directed %r" % ((ref, scale, flag),))
        eq(M.round_to_scale_spec(ref, scale, flag), want,
           "final spec %r" % ((ref, scale, flag),))
    for _ in range(6000):
        ref = rng.getrandbits(rng.choice([8, 32, 63, 64]))
        scale = rng.choice([1, 2, 10, 100, 1000, 10**6, 10**9,
                            rng.getrandbits(32) + 1,
                            rng.getrandbits(64) + 1 if rng.random() < 0.3
                            else rng.getrandbits(16) + 1])
        if scale > MASK64 or scale == 0:
            continue
        flag = rng.getrandbits(1)
        eq(M.round_to_scale(ref, scale, flag),
           M.round_to_scale_spec(ref, scale, flag), "final random")
    raises(lambda: M.round_to_scale(5, 0, 0), (ValueError,), "scale 0")
    raises(lambda: M.round_to_scale(-1, 10, 0), (ValueError,), "ref range")
    raises(lambda: M.round_to_scale(5, 10, 0) if False else
           M.reference(0, 0.1, 2**64), (ValueError,), "n range")
    raises(lambda: M.reference(0, 1, 10), (TypeError,), "value type")
    # Whole wrapper: transcription vs closed form, caller inputs.
    for _ in range(4000):
        n = rng.getrandbits(rng.choice([8, 24, 40, 64]))
        flag = rng.getrandbits(1)
        scale = rng.choice([1, 10, 100, 10**4, 10**6,
                            rng.getrandbits(20) + 1])
        for v in (0.1,):
            eq(M.wrapper(v, n, flag, scale),
               M.wrapper_closed(v, n, flag, scale), "wrapper random")
    # Caller-shaped end-to-end values (v = 0.1 at all four sites).
    eq(M.wrapper(0.1, 10, 0, 10), 10, "wrapper site shape floor")
    eq(M.wrapper(0.1, 10, 1, 10), 10, "wrapper site shape ceiling")
    eq(M.wrapper(0.1, 19, 0, 10), 20, "wrapper 1.1*19 floor")
    eq(M.wrapper(0.1, 19, 1, 10), 20, "wrapper 0.9*19 ceiling")
    eq(M.wrapper(0.1, 100, 1, 25), 100, "wrapper 0.9*100 ceil 25")
    eq(M.wrapper(0.1, 0, 0, 10), 1, "wrapper zero count")


def main():
    rng = random.Random(0xFC0)
    check_conversion(rng)
    check_leaf(rng)
    check_reference(rng)
    check_final(rng)
    print("spot-scale-roundup checks pass (%d checks)" % CHECKS)


if __name__ == "__main__":
    main()
