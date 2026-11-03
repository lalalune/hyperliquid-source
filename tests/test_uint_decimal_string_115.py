"""Tests for tools/uint_decimal_string_115.py, the model of node #115
routine 0x5d4f970. The oracle is plain decimal conversion; the model
itself follows the binary's threshold, divide-by-10000 count and
divide-by-100 pair-fill structure.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from uint_decimal_string_115 import _digit_count, format_uint

CHECKS = [0]


def check(condition, label):
    CHECKS[0] += 1
    if not condition:
        raise AssertionError(label)


def expect_raises(kind, fn, label):
    CHECKS[0] += 1
    try:
        fn()
    except kind:
        return
    except Exception as exc:  # noqa: BLE001 - any other error is a failure
        raise AssertionError("%s: wrong exception %r" % (label, exc))
    raise AssertionError("%s: no exception" % label)


def main():
    # Exact values across every digit length, including every
    # threshold boundary the binary branches on.
    values = [0, 1, 5, 9, 10, 11, 42, 99, 100, 101, 123, 999, 1000,
              1001, 1234, 9999, 10000, 10001, 12345, 99999, 100000,
              100001, 123456, 999999, 1000000, 1234567, 9999999,
              10000000, 12345678, 99999999, 100000000, 123456789,
              999999999, 1000000000, 1234567890, 9999999999,
              10000000000, 12345678901, 99999999999, 100000000000,
              123456789012, 999999999999, 1000000000000,
              1234567890123, 9999999999999, 10000000000000,
              12345678901234, 99999999999999, 100000000000000,
              123456789012345, 999999999999999, 1000000000000000,
              1234567890123456, 9999999999999999, 10000000000000000,
              12345678901234567, 99999999999999999,
              100000000000000000, 123456789012345678,
              999999999999999999, 1000000000000000000,
              1234567890123456789, 9999999999999999999,
              10000000000000000000, 12345678901234567890,
              (1 << 64) - 2, (1 << 64) - 1]
    for value in values:
        check(format_uint(value) == str(value),
              "format %d" % value)
        check(len(format_uint(value)) == len(str(value)),
              "length %d" % value)
        check(_digit_count(value) == len(str(value)),
              "digit count %d" % value)

    # Powers of 10 and 100, and values just either side of them.
    for exp in range(0, 20):
        for delta in (-2, -1, 0, 1, 2):
            value = 10 ** exp + delta
            if 0 <= value <= (1 << 64) - 1:
                check(format_uint(value) == str(value),
                      "power10 %d" % value)
    for exp in range(0, 10):
        for delta in (-1, 0, 1):
            value = 100 ** exp + delta
            if 0 <= value <= (1 << 64) - 1:
                check(format_uint(value) == str(value),
                      "power100 %d" % value)

    # A sweep across every digit length: first, middle and last
    # value of each length, plus a strided sample inside it.
    for digits in range(1, 21):
        low = 10 ** (digits - 1) if digits > 1 else 0
        high = 10 ** digits - 1
        if high > (1 << 64) - 1:
            high = (1 << 64) - 1
        for value in (low, (low + high) // 2, high):
            check(format_uint(value) == str(value),
                  "sweep %d digits %d" % (digits, value))
        step = max(1, (high - low) // 50)
        value = low
        while value <= high:
            check(format_uint(value) == str(value),
                  "strided %d digits %d" % (digits, value))
            value += step

    # Inputs the unsigned 64-bit argument cannot express.
    expect_raises(ValueError, lambda: format_uint(-1), "negative rejected")
    expect_raises(ValueError, lambda: format_uint(1 << 64),
                  "overflow rejected")
    expect_raises(TypeError, lambda: format_uint("42"), "string rejected")
    expect_raises(TypeError, lambda: format_uint(4.0), "float rejected")
    expect_raises(TypeError, lambda: format_uint(True), "bool rejected")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
