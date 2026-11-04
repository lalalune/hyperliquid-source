"""Model for node #115's decimal-keyed group sum.

Maps the getter-shaped function at 0x5eee310 together with its decimal
parser callee at 0x61d0df0 (see
research/work-items/RE-001-decimal-keyed-group-sum-115/).

The function takes an outer object, an output string, and a decimal
text view; it parses the view as an unsigned 64-bit key, requires the
whole view to be consumed, and on success sums the ``+0x10`` field of
every element whose ``+0xb7`` byte equals the parsed key, over the
first ``count`` 24-byte groups at [sub + 0xad8] where sub =
[[outer + 0x788] + 0x30] and count is the signed 32-bit value at
[sub + 0x50]. The sum is formatted into a temporary string by the
helper at 0x5d4f970 and assigned into the output string by the helper
at 0x5eebb20, and the function returns True. On parse failure or
trailing garbage it returns False and leaves the output string
unchanged. A parsed key above 255 can never equal a byte, so it sums
to zero but still succeeds.

Memory is modelled with plain values: ``count`` is the signed 32-bit
value at [sub + 0x50], ``groups`` is the list of element lists for the
24-byte group entries (the third qword of each entry is never read by
the binary, and each element is a (key_byte, value) pair). The model
raises ValueError only where a required value is missing; those
guards are model-only and are documented in the packet README.
"""

U64_MAX = (1 << 64) - 1
# (2**64 - 1) // 10, the overflow threshold the parser compares against.
OVERFLOW_THRESHOLD = 0x1999999999999999


def to_i32(value):
    """Wrap an integer to signed 32-bit, as the binary's 32-bit compare does."""
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >= (1 << 31) else value


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


def keyed_group_sum(key_text, count, groups):
    """Run the 0x5eee310 behavior end to end.

    ``key_text`` is the decimal view bytes, ``count`` the signed 32-bit
    group count, ``groups`` the list of element lists (each element a
    (key_byte, value) pair, in binary order). Returns (ok, total):
    ``ok`` is False on parse failure or trailing garbage, with
    ``total`` None and the output string untouched; otherwise ``total``
    is the 64-bit wrapping sum over the first ``count`` groups of the
    values whose key byte equals the parsed key (an empty group, a
    non-positive count, or a key above 255 contributes nothing).
    """
    if groups is None:
        raise ValueError("groups is required")
    ok, key, rest = parse_decimal_u64(key_text)
    if not ok or rest:
        return False, None
    total = 0
    if count is None:
        raise ValueError("count is required")
    if count > 0:
        for group in groups[:count]:
            for key_byte, value in group:
                if key_byte == key:
                    total = (total + value) & U64_MAX
    return True, total


def format_result(key_text, count, groups):
    """Return the output string the binary would write, or None.

    Returns None when the function returns False (output untouched);
    otherwise the decimal text of the summed total, as the 0x5d4f970
    formatter plus 0x5eebb20 assign would leave it in the output
    string.
    """
    ok, total = keyed_group_sum(key_text, count, groups)
    if not ok:
        return None
    return str(total)
