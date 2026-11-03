"""Model for node #115's decimal-index group-count formatter.

Maps the caller at 0x5eeb9c0 together with its decimal parser callee
at 0x61d0df0 (see research/work-items/RE-001-decimal-index-group-count-115/).

The caller takes an outer object, an output string, and a decimal text
view; it parses the view as an unsigned 64-bit index, requires the
whole view to be consumed and the index to be below the bound stored
at [outer + 0x778], and on success replaces the output string with the
decimal element count of the indexed group: the group array lives at
[sub + 0xad8] where sub = [[outer + 0x788] + 0x30], each entry is 24
bytes, and the count is (entry_end - entry_begin) >> 3, formatted with
"%d". On any failure the output string is left unchanged and the
function returns False; on success it returns True.

Memory is modelled with plain values: ``bound`` is the signed 32-bit
value at [outer + 0x778], ``groups`` is the list of (begin, end) byte
addresses of the 24-byte entries (the third qword of each entry is
never read by the binary). The model raises ValueError only where the
binary would read out of bounds or where a required value is missing;
those guards are model-only and are documented in the packet README.
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
    if len(text) == 0:
        return False, 0, b""
    value = 0
    digits = 0
    i = 0
    while i < len(text) and 0x30 <= text[i] <= 0x39:
        digit = text[i] - 0x30
        if value > OVERFLOW_THRESHOLD or (
            value == OVERFLOW_THRESHOLD and digit > 5
        ):
            return False, None, text[i:]
        value = value * 10 + digit
        digits += 1
        i += 1
    if digits == 0:
        return False, 0, text
    return True, value, text[i:]


def decimal_index_group_count(bound, groups, text):
    """Run the 0x5eeb9c0 formatter over ``text``.

    ``bound`` is the signed 32-bit value at [outer + 0x778];
    ``groups`` is the list of (begin, end) pairs. Returns
    (True, formatted_string) on success, or (False, None) on any
    failure (parse failure, trailing garbage, or index at/above the
    bound). Raises ValueError if the 32-bit-truncated index is negative
    (the binary would then index before the group array) or if the
    index names no group (the binary would read past the array).
    """
    ok, value, rest = parse_decimal_u64(text)
    if not ok:
        return False, None
    if rest != b"":
        return False, None
    index = to_i32(value)
    if index >= to_i32(bound):
        return False, None
    if index < 0:
        raise ValueError("negative 32-bit index: binary reads out of bounds")
    if index >= len(groups):
        raise ValueError("index names no group: binary reads past the array")
    begin, end = groups[index]
    count = (end - begin) >> 3  # arithmetic shift, as the binary's sar
    return True, str(to_i32(count))  # "%d" reads the value as 32-bit int
