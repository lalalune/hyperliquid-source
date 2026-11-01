#!/usr/bin/env python3
"""Model for node #94's 21-key map format line 0x514d0c0 (RE-001).

The window function reads every key 1..21 from an int32-keyed map of
doubles (object header at +0x8, root at +0x10; node left +0x10,
right +0x18, signed int32 key +0x20, double value +0x28), throwing
out_of_range("map::at") on any missing key, and writes one line with
__snprintf_chk (destination = first argument, limit 2000) using the
format at 0x7e99c0:

    %4s %6d/%-3d %8s %5.1f %8.1f %7.1f %8.1f %9.1f %8.1f %9.1f %5.1f
    %8.1f %8.1f %9.2f %17.2f %9d %8.3f %7s %6s %9.1f %9.1f

Argument order (records.json pins every placeholder): the first
string is the pointer stored at [second argument + 0x0]; then key 1
and key 2 as ints, key 3's size string, keys 4..15 as floats, key 16
as an int, key 17 as a float, keys 18 and 19 as compact strings, and
keys 20 and 21 as floats.

Helpers, transliterated from the bytes:

* 0x5430310 (compact int): by abs(value): <= 9999 -> "%li" value;
  <= 9999999 -> "%liK" trunc(value / 1000); <= 9999999999 -> "%liM"
  trunc(value / 1000000); otherwise "%liG" trunc(value / 1000000000).
  Divisions truncate toward zero, including for negative values.

* 0x5430570 (scaled size): the input is read as uint64. scaled =
  uint / 1024; while scaled >= 1024 and a larger unit remains,
  scaled /= 1024. Units KB, MB, GB, TB. Formatted "%.2f %s".

* Key 3's uint conversion: if the double is below 2^63, the int is
  trunc(value); at or above 2^63, the code subtracts 2^63, converts
  and flips bit 63, i.e. trunc(value) as uint64.

A missing key raises KeyError (the model's out_of_range). The
formatted line is truncated to 1999 characters, as __snprintf_chk
with a 2000 limit would. Non-finite doubles are not modelled: the
bytes' cvttsd2si behaviour for them is left as an unknown.
Stdlib only.
"""

import math

FORMAT = ("%4s %6d/%-3d %8s %5.1f %8.1f %7.1f %8.1f %9.1f %8.1f "
          "%9.1f %5.1f %8.1f %8.1f %9.2f %17.2f %9d %8.3f %7s %6s "
          "%9.1f %9.1f\n")
TWO_POW_63 = 2 ** 63
REQUIRED_KEYS = tuple(range(1, 22))


def _trunc_div(value, divisor):
    """Integer division truncating toward zero (the bytes' rule)."""
    return math.trunc(value / divisor) if divisor != 1 else value


def format_int_compact(value):
    """Helper 0x5430310: compact suffixed decimal string for an int."""
    magnitude = abs(value)
    if magnitude <= 9999:
        return "%d" % value
    if magnitude <= 9999999:
        return "%dK" % _trunc_div(value, 1000)
    if magnitude <= 9999999999:
        return "%dM" % _trunc_div(value, 1000000)
    return "%dG" % _trunc_div(value, 1000000000)


def format_size_uint(value):
    """Helper 0x5430570: scaled size string for a uint64."""
    units = ("KB", "MB", "GB", "TB")
    index = 0
    scaled = value / 1024.0
    while scaled >= 1024.0 and index < 3:
        scaled /= 1024.0
        index += 1
    return "%.2f %s" % (scaled, units[index])


def uint_from_double(value):
    """Key 3's conversion: trunc(value) read as uint64."""
    truncated = math.trunc(value)
    if truncated < TWO_POW_63:
        # Negative inputs are read as uint64 by the size helper's
        # halve-and-double path, so mask to 64 bits in all cases.
        return truncated % (1 << 64)
    return truncated % (1 << 64)


def lookup(values, key):
    """Map lookup: missing keys throw, like map::at / the inline
    searches (which throw out_of_range("map::at") on a miss)."""
    try:
        return values[key]
    except KeyError:
        raise KeyError("map::at") from None


def format_line(values, first_string):
    """Format the full line for keys 1..21 plus the first string."""
    for key in REQUIRED_KEYS:
        lookup(values, key)
    trunc = lambda key: math.trunc(lookup(values, key))
    line = FORMAT % (
        first_string,
        trunc(1),
        trunc(2),
        format_size_uint(uint_from_double(lookup(values, 3))),
        lookup(values, 4),
        lookup(values, 5),
        lookup(values, 6),
        lookup(values, 7),
        lookup(values, 8),
        lookup(values, 9),
        lookup(values, 10),
        lookup(values, 11),
        lookup(values, 12),
        lookup(values, 13),
        lookup(values, 14),
        lookup(values, 15),
        trunc(16),
        lookup(values, 17),
        format_int_compact(trunc(18)),
        format_int_compact(trunc(19)),
        lookup(values, 20),
        lookup(values, 21),
    )
    return line[:1999]
