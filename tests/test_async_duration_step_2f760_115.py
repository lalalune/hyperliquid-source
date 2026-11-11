"""Tests for tools/async_duration_step_2f760_115.py, the model of
node #115 routine 0x5a2f760.

The conversion oracle is exact rational arithmetic: for a
non-negative finite f64 the result is the split of
round-to-nearest-even(value * 1e9) into (secs, nanos); the panic
arms are checked against their error kinds and message strings.
The step tests pin the tag transitions and the ordered callee
effects for every arm of the routine.
"""

import math
import random
import struct
import sys
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from async_duration_step_2f760_115 import (
    CONVERSION_MESSAGES,
    GUARD_MESSAGES,
    ConversionPanic,
    GuardPanic,
    StepObject,
    convert_f64_seconds,
    step,
    unwind_poisons_tag,
)

CHECKS = [0]
NANOS = 1_000_000_000


def check(condition, label):
    CHECKS[0] += 1
    if not condition:
        raise AssertionError(label)


def expect_raises(kind, fn, label):
    CHECKS[0] += 1
    try:
        fn()
    except kind as exc:
        return exc
    except Exception as exc:  # noqa: BLE001 - any other error is a failure
        raise AssertionError("%s: wrong exception %r" % (label, exc))
    raise AssertionError("%s: no exception" % label)


def bits_of(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def oracle(bits):
    """Exact spec: ("ok", (secs, nanos)) or ("panic", kind)."""
    value = struct.unpack("<d", struct.pack("<Q", bits))[0]
    if math.isnan(value) or 0.0 > value:
        return ("panic", 0)
    if math.isinf(value):
        return ("panic", 1)
    total = Fraction(value) * NANOS
    whole = total.numerator // total.denominator
    rem = total - whole
    if rem > Fraction(1, 2) or (rem == Fraction(1, 2) and whole % 2 == 1):
        whole += 1
    if whole >= (1 << 64) * NANOS:
        return ("panic", 1)
    return ("ok", divmod(whole, NANOS))


def model_outcome(bits):
    try:
        return ("ok", convert_f64_seconds(bits))
    except ConversionPanic as panic:
        return ("panic", panic.kind)


def test_conversion_against_oracle():
    cases = []
    # Every band boundary with a spread of mantissas.
    for exponent in range(0x3D0, 0x450):
        for frac in (0, 1, 2, 3, 0x8000000000000, 0xFFFFFFFFFFFFF,
                     0xFFFFFFFFFFFFE, 0x5555555555555, 0xAAAAAAAAAAAAA,
                     0x123456789ABCD, 0x0000000000001):
            cases.append((exponent << 52) | frac)
    # Directed exact ties in the 1 <= x < 2**52 band: odd mantissa
    # with exponent 1065 makes value * 1e9 an exact half integer.
    for extra in (0, 2, 4, 6, 100, 2 ** 20, 2 ** 40):
        cases.append((1065 << 52) | (1 + extra))
        cases.append((1065 << 52) | (3 + extra))
    # Random patterns per band and overall.
    rng = random.Random(0x2F760)
    for lo, hi in ((0, 0x3E0), (0x3E0, 0x3FF), (0x3FF, 0x433),
                   (0x433, 0x43F)):
        for _ in range(4000):
            cases.append((rng.randrange(lo, hi) << 52)
                         | rng.getrandbits(52))
    for _ in range(8000):
        bits = rng.getrandbits(64)
        value = struct.unpack("<d", struct.pack("<Q", bits))[0]
        if math.isnan(value) or math.isinf(value) or value < 0:
            continue
        cases.append(bits)
    # Named scalars.
    for value in (0.0, -0.0, 5e-324, 2 ** -31, 0.1, 0.3, 0.5, 1.5,
                  2.5, 5.0, 123456789.25, 2.0 ** 52, 2.0 ** 60,
                  2.0 ** 63, 18446744073709549568.0):
        cases.append(bits_of(value))
    for bits in cases:
        check(model_outcome(bits) == oracle(bits),
              "conversion mismatch for bits %#x" % bits)


def test_conversion_panics():
    for value in (-1.0, -0.5, -5e-324, float("-inf")):
        panic = expect_raises(
            ConversionPanic,
            lambda v=value: convert_f64_seconds(bits_of(v)),
            "negative %r must panic" % value)
        check(panic.kind == 0, "negative kind for %r" % value)
        check(panic.message
              == "cannot convert float seconds to Duration: "
                 "value is negative",
              "negative message")
    for bits in (0x7FF8000000000000, 0x7FF0000000000001,
                 0xFFF8000000000000):
        panic = expect_raises(
            ConversionPanic, lambda b=bits: convert_f64_seconds(b),
            "NaN %#x must panic" % bits)
        check(panic.kind == 0, "NaN takes the kind-0 arm")
    for value in (float("inf"), 2.0 ** 64, 1e300):
        panic = expect_raises(
            ConversionPanic,
            lambda v=value: convert_f64_seconds(bits_of(v)),
            "too-big %r must panic" % value)
        check(panic.kind == 1, "too-big kind for %r" % value)
        check(panic.message
              == "cannot convert float seconds to Duration: "
                 "value is either too big or NaN",
              "too-big message")
    check(convert_f64_seconds(0x8000000000000000) == (0, 0),
          "-0.0 converts to (0, 0)")
    check(CONVERSION_MESSAGES[0].endswith("value is negative"),
          "kind 0 message recorded")
    check(CONVERSION_MESSAGES[1].endswith("or NaN"),
          "kind 1 message recorded")


def test_conversion_rejects_non_bits():
    expect_raises(TypeError, lambda: convert_f64_seconds(1.5),
                  "float input rejected")
    expect_raises(TypeError, lambda: convert_f64_seconds(True),
                  "bool input rejected")
    expect_raises(ValueError, lambda: convert_f64_seconds(-1),
                  "negative bits rejected")
    expect_raises(ValueError, lambda: convert_f64_seconds(1 << 64),
                  "oversize bits rejected")


def test_step_tag0_true():
    obj = StepObject(0, f64_bits=bits_of(2.5))
    returned, effects = step(obj, predicate_result=True)
    check(returned is True, "tag0 true returns True")
    check(obj.tag == 3, "tag0 true stores tag 3")
    check(effects == [("construct", 0x5CF2150, 2, 500000000),
                      ("predicate", 0x5CF2D30)],
          "tag0 true effects: %r" % (effects,))


def test_step_tag0_false_paths():
    # flag 0 + counter reaches zero -> destructor 0x5ce86d0
    obj = StepObject(0, f64_bits=bits_of(0.25))
    returned, effects = step(obj, predicate_result=False,
                             counter_reaches_zero=True,
                             constructed_flag=0)
    check(returned is False and obj.tag == 1, "tag0 false -> tag 1")
    check(effects == [("construct", 0x5CF2150, 0, 250000000),
                      ("predicate", 0x5CF2D30),
                      ("decq",),
                      ("destroy", 0x5CE86D0),
                      ("release", 0x5A52490)],
          "tag0 false flag0 effects: %r" % (effects,))
    # flag 1 -> destructor 0x5ce8da0
    obj = StepObject(0, f64_bits=bits_of(0.25))
    _, effects = step(obj, predicate_result=False,
                      counter_reaches_zero=True, constructed_flag=1)
    check(("destroy", 0x5CE8DA0) in effects,
          "flag 1 selects destructor 0x5ce8da0")
    # counter does not reach zero -> no destructor call, release
    # still runs, tag still becomes 1
    obj = StepObject(0, f64_bits=bits_of(0.25))
    returned, effects = step(obj, predicate_result=False,
                             counter_reaches_zero=False,
                             constructed_flag=0)
    check(returned is False and obj.tag == 1, "no-zero -> tag 1")
    check(all(effect[0] != "destroy" for effect in effects),
          "no destructor when the counter survives")
    check(effects[-1] == ("release", 0x5A52490),
          "release still runs")


def test_step_tag0_conversion_panic_precedes_effects():
    obj = StepObject(0, f64_bits=bits_of(-1.0))
    panic = expect_raises(ConversionPanic,
                          lambda: step(obj, predicate_result=True),
                          "negative input panics inside step")
    check(panic.kind == 0 and obj.tag == 0,
          "conversion panic leaves the tag at 0")


def test_step_tag3():
    obj = StepObject(3, value_flag=1)
    returned, effects = step(obj, predicate_result=True)
    check(returned is True and obj.tag == 3, "tag3 true keeps tag 3")
    check(effects == [("predicate", 0x5CF2D30)],
          "tag3 performs no construction")
    obj = StepObject(3, value_flag=1)
    returned, effects = step(obj, predicate_result=False,
                             counter_reaches_zero=True)
    check(returned is False and obj.tag == 1, "tag3 false -> tag 1")
    check(effects == [("predicate", 0x5CF2D30), ("decq",),
                      ("destroy", 0x5CE8DA0), ("release", 0x5A52490)],
          "tag3 false effects use the stored flag: %r" % (effects,))


def test_step_guards():
    panic = expect_raises(GuardPanic,
                          lambda: step(StepObject(1), True),
                          "tag 1 guard panics")
    check(panic.message == "`async fn` resumed after completion",
          "tag 1 guard message")
    panic = expect_raises(GuardPanic,
                          lambda: step(StepObject(2), True),
                          "tag 2 guard panics")
    check(panic.message == "`async fn` resumed after panicking",
          "tag 2 guard message")
    check(GUARD_MESSAGES[1].endswith("completion"), "guard 1 text")
    check(GUARD_MESSAGES[2].endswith("panicking"), "guard 2 text")


def test_unwind_poisons_tag():
    obj = StepObject(3)
    check(unwind_poisons_tag(obj) == 2 and obj.tag == 2,
          "unwind writes tag 2")


def main():
    test_conversion_against_oracle()
    test_conversion_panics()
    test_conversion_rejects_non_bits()
    test_step_tag0_true()
    test_step_tag0_false_paths()
    test_step_tag0_conversion_panic_precedes_effects()
    test_step_tag3()
    test_step_guards()
    test_unwind_poisons_tag()
    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
