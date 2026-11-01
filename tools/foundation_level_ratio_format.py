#!/usr/bin/env python3
"""Model for node #94's level-ratio formatter 0x514cc10 (RE-001).

The window function takes an outer object, a destination string and a
(pointer, length) view holding a decimal level index, and formats that
level's ratio with "%f" into the destination, returning 1 -- or returns
0 without touching the destination when the view is not exactly one
in-range decimal index.

Pipeline, transliterated from the bytes:
  * 0x54307c0 parses the decimal view (uint64, checked against
    UINT64_MAX; a non-digit stops the scan; the view struct is left
    pointing at the stopping character).
  * The caller requires full consumption (remaining length 0) and
    parsed < level count at [outer+0x778] (unsigned compare).
  * 0x51ca8a0 computes the level's ratio: over the level entry's
    record pointers, numerator = sum([record+0x90] + [record+0x98]),
    denominator = sum([record+0x10]); both sums wrap modulo 2**64.
    An empty entry or a zero wrapped denominator yields -1.0.
    The result is (double)(uint64)numerator / (double)(uint64)denominator.
  * 0x514c050 formats the double with "%f" into a temporary string and
    0x514b4f0 move-assigns it into the destination (both bound by their
    own RE-001 items and cited here as callees only). The -1.0
    sentinel is NOT checked by the caller: it formats as "-1.000000"
    and still returns 1.

A level entry is modelled as a list of (field_0x10, field_0x90,
field_0x98) int64 triples; a level array is a list of entries.
Stdlib only.
"""

MASK64 = (1 << 64) - 1
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1
OVERFLOW_LIMIT = 0x1999999999999999


def to_int64(value):
    value &= MASK64
    return value - (1 << 64) if value >= (1 << 63) else value


def to_uint64(value):
    return value & MASK64


def parse_decimal(text):
    """Model 0x54307c0 over a bytes view.

    Returns (ok, value, remaining). ``remaining`` is the unconsumed
    tail of the view. On overflow ok is False; value is then the
    accumulation before the overflowing digit, which the binary never
    writes to the output slot -- call sites must ignore it when ok
    is False.
    """
    value = 0
    digits = 0
    index = 0
    while index < len(text):
        byte = text[index]
        if not 0x30 <= byte <= 0x39:
            break
        digit = byte - 0x30
        if value > OVERFLOW_LIMIT or (value == OVERFLOW_LIMIT and digit > 5):
            return False, value, text[index:]
        value = value * 10 + digit
        digits += 1
        index += 1
    if digits == 0:
        return False, 0, text
    return True, value, text[index:]


def level_ratio(entry):
    """Model 0x51ca8a0 for one level entry (list of triples)."""
    if not entry:
        return -1.0
    numerator = 0
    denominator = 0
    for field_0x10, field_0x90, field_0x98 in entry:
        numerator = (numerator + to_int64(field_0x90)
                     + to_int64(field_0x98)) & MASK64
        denominator = (denominator + to_int64(field_0x10)) & MASK64
    if denominator == 0:
        return -1.0
    return float(to_uint64(numerator)) / float(to_uint64(denominator))


def format_ratio(value):
    """Model the "%f" formatting step (0x514c050 on the ratio double)."""
    return "%f" % value


def level_ratio_format(level_count, level_array, destination, view):
    """Model 0x514cc10.

    ``view`` is bytes; ``destination`` is the current destination
    string value. Returns (success, new_destination). On failure the
    destination is returned unchanged. The index passed to the ratio
    callee is the signed 32-bit truncation of the parsed value; a
    negative truncation is outside the modelled range and raises
    ValueError, as is an index beyond the supplied level array (the
    binary's caller gate guarantees parsed < count on a valid target,
    where the array length equals the count).
    """
    ok, value, remaining = parse_decimal(view)
    if not ok:
        return False, destination
    if remaining:
        return False, destination
    if value >= level_count:
        return False, destination
    index = value & 0xFFFFFFFF
    if index >= (1 << 31):
        index -= 1 << 32
    if index < 0:
        raise ValueError("truncated level index is negative: %d" % index)
    if index >= len(level_array):
        raise ValueError("level index %d beyond supplied array" % index)
    return True, format_ratio(level_ratio(level_array[index]))
