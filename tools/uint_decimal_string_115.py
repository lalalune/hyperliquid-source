"""Model of node #115 routine 0x5d4f970: decimal conversion of one
unsigned 64-bit integer into a string.

The routine's input is the unsigned 64-bit integer in rsi and the
destination string object at rdi (pointer +0x00, size +0x08,
capacity-or-inline slot +0x10). The model follows the binary's own
structure rather than shortcutting to a library format call:

* Digit count: values up to 9, 99, 999 and 9999 take the 1, 2, 3 and
  4 digit paths directly. Larger values loop dividing by 10000 and
  counting 4 digits per step, with the final partial group resolved
  by unsigned thresholds at 99999, 999999, 9999999 and 99999999.
* Fill: the routine copies the 200-byte digit-pair table
  ("00", "01", ..., "99") onto the stack, then fills the string
  from the last character backwards, dividing the remaining value
  by 100 at each step and writing the pair for the remainder. It
  stops once the value before a step is at most 9999; a remainder
  of 100..9999 then writes one more digit pair, and a remainder of
  0..999 writes one single leading digit. The 1-digit and 2-digit
  entries write their digit or pair directly through the same tail
  blocks.

Net result: the decimal representation of the unsigned input, with
no sign, no leading zeroes and no separator. The model raises on
inputs the binary's unsigned 64-bit argument cannot express
(negative values, values above 2**64 - 1, non-integers); that guard
is a model safety property, not a binary claim.
"""

_PAIR_TABLE = "".join("%02d" % i for i in range(100))

_UINT64_MAX = (1 << 64) - 1


def _digit_count(value):
    if value <= 9:
        return 1
    if value <= 99:
        return 2
    if value <= 999:
        return 3
    if value <= 9999:
        return 4
    count = 1
    remaining = value
    while True:
        before = count
        old = remaining
        remaining = old // 10000
        count += 4
        if old <= 99999:
            return count
        if old <= 999999:
            return before + 5
        if old <= 9999999:
            return before + 6
        if old <= 99999999:
            return before + 7
        # Otherwise loop again with remaining = old // 10000.


def format_uint(value):
    """Return the decimal string for unsigned 64-bit ``value``."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("value must be an int")
    if value < 0 or value > _UINT64_MAX:
        raise ValueError("value is not an unsigned 64-bit integer")
    count = _digit_count(value)
    chars = ["\x00"] * count  # the library construct call's fill
    if count == 1:
        chars[0] = chr(ord("0") + value)
        return "".join(chars)
    if count == 2:
        chars[0], chars[1] = _PAIR_TABLE[2 * value:2 * value + 2]
        return "".join(chars)
    pos = count
    remaining = value
    while True:
        quotient, remainder = divmod(remaining, 100)
        pair = _PAIR_TABLE[2 * remainder:2 * remainder + 2]
        chars[pos - 2] = pair[0]
        chars[pos - 1] = pair[1]
        pos -= 2
        old = remaining
        remaining = quotient
        if old <= 9999:
            break
    if old > 999:
        # Remainder of 100..9999: one more digit pair.
        pair = _PAIR_TABLE[2 * remaining:2 * remaining + 2]
        chars[0] = pair[0]
        chars[1] = pair[1]
    else:
        # Remainder of 0..999: one single leading digit.
        chars[0] = chr(ord("0") + remaining)
    return "".join(chars)
