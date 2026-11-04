"""Model for node #115's decimal-index group ratio.

Maps the getter-shaped function at 0x5eed240 together with its ratio
callee at 0x5f6aed0 and its decimal parser callee at 0x61d0df0 (see
research/work-items/RE-001-decimal-index-group-ratio-115/).

The function takes an outer object, an output string, and a decimal
text view; it parses the view as an unsigned 64-bit index, requires
the whole view to be consumed, and requires the parsed index to be
below the signed 32-bit bound at [outer + 0x778] under an unsigned
compare against the sign-extended bound. On success it calls the
ratio callee on the sub-object at [[outer + 0x788] + 0x30] + 0x40,
which indexes the 24-byte group array at [sub + 0xad8] by the
(low-32-bit sign-extended) index, sums one field pair over the
entry's element range, and returns a double: the numerator sum over
the divisor sum, or -1.0 when the range is empty or the divisor sum
is zero. The caller formats that double with the "%f" format string
at 0x432165 through the helper at 0x5eec680 and assigns the result
into the output string through the helper at 0x5eebb20, returning
True. On parse failure, trailing garbage, or a bound failure it
returns False and leaves the output string unchanged.

Memory is modelled with plain values: ``bound`` is the signed 32-bit
value at [outer + 0x778], ``groups`` is the list of element lists for
the 24-byte group entries (the third qword of each entry is never
read by the binary, and each element is a (f10, f90, f98) triple of
signed 64-bit field values, in binary order). The model raises
ValueError only where a required value is missing or the index is
outside the modelled array; those guards are model-only and are
documented in the packet README.
"""

U64_MAX = (1 << 64) - 1
# (2**64 - 1) // 10, the overflow threshold the parser compares against.
OVERFLOW_THRESHOLD = 0x1999999999999999


def to_i32(value):
    """Wrap an integer to signed 32-bit, as the binary's movslq does."""
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >= (1 << 31) else value


def to_i64(value):
    """Wrap an integer to signed 64-bit, as the binary's adds do."""
    value &= U64_MAX
    return value - (1 << 64) if value >= (1 << 63) else value


def parse_decimal_u64(text):
    """Parse ``text`` (bytes) as an unsigned 64-bit decimal.

    Returns (ok, value, rest):
    - ``ok`` is False when no digit is present, when the value overflows
      u64, or when ``text`` is empty. On the overflow path the binary
      leaves the output slot unwritten, so ``value`` is None there; on
      the no-digit paths ``value`` is 0, matching the binary's
      zeroed accumulator.
    - ``rest`` is the unconsumed tail of the input. The binary advances
      its view past every consumed digit, so on overflow ``rest`` starts
      at the overflowing digit, and on a non-digit stop it starts at
      that non-digit.
    - Leading zeros are accepted; no sign, whitespace, or other prefix
      is accepted.
    """
    if not text:
        return False, 0, text
    value = 0
    consumed = 0
    for byte in text:
        digit = byte - 0x30
        if digit < 0 or digit > 9:
            break
        if value > OVERFLOW_THRESHOLD or (
            value == OVERFLOW_THRESHOLD and digit > 5
        ):
            return False, None, text[consumed:]
        value = value * 10 + digit
        consumed += 1
    if consumed == 0:
        return False, 0, text
    return True, value, text[consumed:]


def group_ratio(elements):
    """Run the 0x5f6aed0 ratio over one entry's element list.

    ``elements`` is a list of (f10, f90, f98) signed 64-bit field
    triples. Returns -1.0 when the range is empty or when the divisor
    sum (the sum of the f10 fields, 64-bit wrapping) is zero;
    otherwise returns float(numerator) / float(divisor), where the
    numerator is the 64-bit wrapping sum of (f90 + f98) per element
    and Python's int-to-float conversion matches the binary's
    cvtsi2sd rounding.
    """
    if not elements:
        return -1.0
    numerator = 0
    divisor = 0
    for f10, f90, f98 in elements:
        numerator = to_i64(numerator + to_i64(f90 + f98))
        divisor = to_i64(divisor + f10)
    if divisor == 0:
        return -1.0
    return float(numerator) / float(divisor)


def indexed_group_ratio(key_text, bound, groups):
    """Run the 0x5eed240 behavior end to end.

    ``key_text`` is the decimal view bytes, ``bound`` the signed
    32-bit bound at [outer + 0x778], ``groups`` the list of element
    lists (each element a (f10, f90, f98) triple). Returns
    (ok, ratio): ``ok`` is False on parse failure, trailing garbage,
    or the bound failure, with ``ratio`` None and the output string
    untouched; otherwise ``ratio`` is the double from group_ratio
    over groups[index], where index is the low-32-bit sign-extended
    parsed value. The binary indexes the array unconditionally after
    the bound check, so a bound larger than the modelled array is a
    model error (ValueError), not a binary failure.
    """
    if groups is None:
        raise ValueError("groups is required")
    if bound is None:
        raise ValueError("bound is required")
    ok, index, rest = parse_decimal_u64(key_text)
    if not ok or rest:
        return False, None
    if index >= (bound & U64_MAX):
        return False, None
    index32 = to_i32(index)
    if index32 < 0 or index32 >= len(groups):
        raise ValueError("index outside the modelled group array")
    return True, group_ratio(groups[index32])


def format_result(key_text, bound, groups):
    """Format the 0x5eed240 result with "%f", or None on failure."""
    ok, ratio = indexed_group_ratio(key_text, bound, groups)
    if not ok:
        return None
    return "%f" % ratio
