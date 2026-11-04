"""Model of the node #115 delimited-key parse routine at 0x606eb60.

The routine parses a '#' delimited versioned key. It takes an input
string and a bound (minimum accepted sequence, compared unsigned) and
returns a record (sequence, key):

* no '#' in the input -> (0xffffffffffffffff, "")
* prefix before the first '#' parsed as a decimal number (helper
  0x61d1540: strtoull base 10 with an optional single K/M/G/T suffix
  multiplier); the parsed value below the bound -> (0xffffffffffffffff, "")
* otherwise -> (parsed value, input bytes after the first '#')

The prefix parser follows strtoull: leading ASCII whitespace is
skipped, an optional '+'/'-' sign applies (a leading '-' wraps modulo
2**64), no digits raises ValueError ("stoull" invalid_argument), and a
magnitude overflow raises OverflowError ("stoull" out_of_range). The
single character after the consumed digits may be a suffix letter
(K/k << 10, M/m << 20, G/g << 30, T/t << 40, 64-bit wrap); any other
next character, and any content after the suffix character, is ignored.
A suffix extraction with position > size raises ValueError, mirroring
the std::string::substr check carried by the routine (unreachable from
its own find result, since a found position is always below the size).
"""

MASK64 = 0xFFFFFFFFFFFFFFFF
SENTINEL = 0xFFFFFFFFFFFFFFFF

_SUFFIX_SHIFTS = {
    "K": 10, "k": 10,
    "M": 20, "m": 20,
    "G": 30, "g": 30,
    "T": 40, "t": 40,
}

_WHITESPACE = " \t\n\v\f\r"


def _parse_prefix_number(prefix):
    """Parse a prefix the way helper 0x61d1540 does.

    Returns the u64 value. Raises ValueError for no digits
    (invalid_argument) and OverflowError for magnitude overflow
    (out_of_range). The input is treated as a C string for the
    strtoull step: parsing stops at the first NUL byte.
    """
    if prefix is None:
        raise TypeError("prefix must be a string, got None")
    # strtoull reads a NUL-terminated copy; bytes after a NUL do not
    # affect the digit scan, but the suffix check below reads the
    # original string at the consumed index.
    cstr = prefix.split("\x00", 1)[0]
    i = 0
    while i < len(cstr) and cstr[i] in _WHITESPACE:
        i += 1
    negative = False
    if i < len(cstr) and cstr[i] in "+-":
        negative = cstr[i] == "-"
        i += 1
    digits_start = i
    value = 0
    overflow = False
    while i < len(cstr) and cstr[i].isdigit() and cstr[i] in "0123456789":
        digit = ord(cstr[i]) - ord("0")
        if not overflow:
            if value > (MASK64 - digit) // 10:
                overflow = True
            else:
                value = value * 10 + digit
        i += 1
    if i == digits_start:
        raise ValueError("stoull: invalid_argument (no digits converted)")
    if overflow:
        raise OverflowError("stoull: out_of_range (ERANGE)")
    if negative:
        value = (-value) & MASK64
    consumed = i
    if consumed < len(prefix):
        suffix = prefix[consumed]
        shift = _SUFFIX_SHIFTS.get(suffix)
        if shift is not None:
            value = (value << shift) & MASK64
    return value


def _extract_suffix(text, pos):
    """Return text[pos:], mirroring the substr bounds check."""
    if pos > len(text):
        raise ValueError(
            "basic_string::substr: __pos (%d) > this->size() (%d)"
            % (pos, len(text)))
    return text[pos:]


def parse_delimited_key(input_string, bound):
    """Parse one delimited key. Returns (sequence, key).

    sequence is a u64; 0xffffffffffffffff is the reject sentinel used
    for both the no-separator path and the below-bound path.
    """
    if input_string is None:
        raise TypeError("input_string must be a string, got None")
    if not isinstance(input_string, str):
        raise TypeError("input_string must be a string")
    if not isinstance(bound, int) or isinstance(bound, bool):
        raise TypeError("bound must be an integer")
    if bound < 0 or bound > MASK64:
        raise ValueError("bound must fit in a u64")
    pos = input_string.find("#")
    if pos < 0:
        return (SENTINEL, "")
    prefix = input_string[:pos]
    value = _parse_prefix_number(prefix)
    if value < bound:
        return (SENTINEL, "")
    return (value, _extract_suffix(input_string, pos + 1))
