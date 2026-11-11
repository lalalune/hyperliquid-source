"""Node #115 value serializer 0x60ba600 (RE-001).

The serializer turns one Find-pipeline value into its text form.
It is the single documented boundary of the RE-001-registry-find-115
(#3485) packet: its 25 per-kind rules are pinned here, end to end,
with the helpers that make each rule observable.

    serialize(kind, value, enum_maps) -> (ok, text)

ABI (from the excerpt): ``serialize(value_ptr, kind, out_string*)`` --
rdi is the value, esi is the kind (0..0x18), rdx is the out
``std::string``; it returns 1 and fills out on success, 0 with out
untouched when the kind is not handled. Kinds 0x11..0x16 and any kind
above 0x18 are unhandled. The model returns ``(False, None)`` for
those, exactly as the binary leaves out alone.

Kind rules (jump table at 0x978650, 25 entries, 19 distinct targets):

    kind  value read        rule
    ----  ----------------  ----------------------------------------------
    0     u8 at *value      "true" / "false" (literals 0x43f883 / 0x430e89)
    1     i32 at *value     signed decimal via int_to_string 0x5f06bb0
    2     i32 at *value     same helper, same value (identical behaviour)
    3     i64 at *value     signed decimal (abs + '-' fill, INT64_MIN ok)
    4     u32 at *value     unsigned decimal (two-digit table loop)
    5     u8 at *value      signed decimal via int_to_string (zero-extended)
    6     u32 at *value     unsigned decimal (second copy of kind 4)
    7     u64 at *value     unsigned decimal (two-digit table loop)
    8     u64 at *value     unsigned decimal (second copy of kind 7)
    9     (ptr, len) pair   backslash-escaped copy (escape_copy 0x61d0f30)
    10    f64 at *value     "%f" via vsnprintf (snprintf_string 0x60ba450)
    11    u8 at *value      enum name, map 0x65070a0
    12    u8 at *value      enum name, map 0x6507060
    13    u8 at *value      enum name, map 0x6507120
    14    u32 at *value     enum name, map 0x6507020 (the one u32 map)
    15    u8 at *value      enum name, map 0x6507160
    16    u8 at *value      enum name, map 0x65070e0
    17-22 --               unhandled, returns 0
    23    (ptr, len) pair   UPPERCASE hex (hex_encode 0x61c7e30, flag 1)
    24    u8 at *value      enum name, map 0x6506fe0

The decimal paths are the libstdc++ ``__to_chars`` shape: the digit
count is computed from magnitude thresholds, the string is built
filled with ``'-'`` (signed) or NUL (unsigned), and the digits are
written from the end two at a time from a 200-byte two-digit table
("00".."99", reloaded from the same 13 .rodata chunks at every site).
The model implements that table loop literally instead of calling
``str()`` on the whole value, so the table itself is exercised.

The seven enum maps live in .bss (runtime-built, see #3560); the
model takes them as harness-injected ``EnumMap`` objects keyed by
their global address, never as binary reads. The enum lookup the
serializer inlines is a plain linear walk of the head list at
map+0x10 (node: next +0x00, name string +0x08, key +0x28) -- it does
NOT use the hash-bucket walk the #3560 parsers use in the other
direction. A miss returns 0 with out untouched.

Escape rules (escape_copy 0x61d0f30 with predicate 0x61d0e90 and
letter 0x61d0f00): a byte is escaped iff it is 0x0a, 0x0d, '#' (0x23),
':' (0x3a) or '\\\\' (0x5c); the escape is '\\\\' + letter, where the
letter is 'n' for 0x0a, 'r' for 0x0d, and the byte itself otherwise.
Every other byte -- including 0x5d..0x7f, 0x80..0xff and NUL -- is
copied raw. This is the inverse of the escape decoder 0x61d0ee0
pinned by #3560.

Hex rules (hex_encode 0x61c7e30 with hexchar 0x61c7da0): with the
flag the serializer passes (1), each byte becomes two UPPERCASE hex
chars (hexchar adds 0x37 past 9, so 10..15 -> 'A'..'F'); with
flag 0 the helper copies the input raw instead. The flag-0 path is
modelled (and tested) even though the serializer never takes it.

Double rules: snprintf_string 0x60ba450 calls the function pointer
in GOT 0x64ed730 -- vsnprintf@GLIBC_2.2.5 -- with a 328-byte stack
buffer and the format "%f" (literal 0x432165), then installs the
result in the out string. ``"%f" % value`` in Python is the same
C ``%f`` (six decimals, correctly rounded); every finite double
fits the 328-byte buffer, so no truncation is modelled.
"""

import math

# --- addresses -----------------------------------------------------------

SERIALIZER = 0x60BA600
SERIALIZER_END = 0x60BB855
INT_TO_STRING = 0x5F06BB0
SNPRINTF_STRING = 0x60BA450
ESCAPE_COPY = 0x61D0F30
ESCAPE_COPY_CLEANUP = 0x61D0F1C
ESCAPE_PREDICATE = 0x61D0E90
ESCAPE_LETTER = 0x61D0F00
HEX_ENCODE = 0x61C7E30
HEXCHAR = 0x61C7DA0
MOVE_ASSIGN = 0x60B79E0

JUMP_TABLE = 0x978650
KIND_COUNT = 25
KIND_MAX = 0x18
UNSUPPORTED_KINDS = frozenset(range(0x11, 0x17))

# kind -> jump-table target, decoded from the binary (verify.py
# re-decodes the table at 0x978650 and requires an exact match).
KIND_TARGETS = {
    0: 0x60BAB78, 1: 0x60BA678, 2: 0x60BA678, 3: 0x60BA8A8,
    4: 0x60BAF78, 5: 0x60BAF60, 6: 0x60BAD90, 7: 0x60BABB0,
    8: 0x60BA6B0, 9: 0x60BB2B0, 10: 0x60BB280, 11: 0x60BB240,
    12: 0x60BB200, 13: 0x60BB1C0, 14: 0x60BB180, 15: 0x60BB140,
    16: 0x60BAAF8, 17: 0x60BA648, 18: 0x60BA648, 19: 0x60BA648,
    20: 0x60BA648, 21: 0x60BA648, 22: 0x60BA648, 23: 0x60BAAC8,
    24: 0x60BAB40,
}

BOOL_FALSE_LITERAL = 0x430E89   # "false"
BOOL_TRUE_LITERAL = 0x43F883    # "true"
DOUBLE_FORMAT_LITERAL = 0x432165  # "%f"
DOUBLE_FORMAT_BUFFER = 328
VSNPRINTF_GOT = 0x64ED730

# The 13 .rodata chunks the decimal paths reload the table from
# (12 movaps at rsp+0x30+16*i, then one movups at rsp+0xe9).
DIGITS_TABLE_CHUNKS = (
    0x451750, 0x453230, 0x456910, 0x453E00, 0x451DB0, 0x452BA0,
    0x455590, 0x456240, 0x456920, 0x4528D0, 0x456250, 0x453240,
    0x454870,
)
DIGITS_TABLE = "".join("%02d" % i for i in range(100))
DIGITS_TABLE_SHA256 = (
    "bedfbc17dfedc3a783c817da8b2eec13baff8e36c4e6a61c346332973895315a"
)

# Bit-test mask in escape_predicate 0x61d0e90: bits {0, 23, 57} over
# (byte - 0x23) select '#', ':' and '\\'.
ESCAPE_MASK = 0x0200000000800001

# kind -> enum-map global (the seven .bss maps, cf. #3560)
ENUM_MAPS = {
    11: 0x65070A0,
    12: 0x6507060,
    13: 0x6507120,
    14: 0x6507020,   # the one u32 map
    15: 0x6507160,
    16: 0x65070E0,
    24: 0x6506FE0,
}

INT32_MIN = -(2 ** 31)
INT32_MAX = 2 ** 31 - 1
UINT32_MAX = 2 ** 32 - 1
INT64_MIN = -(2 ** 63)
INT64_MAX = 2 ** 63 - 1
UINT64_MAX = 2 ** 64 - 1


# --- decimal via the two-digit table -------------------------------------


def _decimal_u64(value):
    """Unsigned decimal, the binary's two-digit-table loop.

    Takes value % 100 two digits at a time from DIGITS_TABLE, then
    the leading one or two digits -- the same order the binary
    writes them from the end of the string backwards.
    """
    if not 0 <= value <= UINT64_MAX:
        raise ValueError("u64 out of range: %r" % (value,))
    if value == 0:
        return "0"
    pairs = []
    v = value
    while v >= 100:
        v, rem = divmod(v, 100)
        pairs.append(DIGITS_TABLE[2 * rem:2 * rem + 2])
    if v >= 10:
        pairs.append(DIGITS_TABLE[2 * v:2 * v + 2])
    else:
        pairs.append(DIGITS_TABLE[2 * v + 1])
    return "".join(reversed(pairs))


def _decimal_u32(value):
    if not 0 <= value <= UINT32_MAX:
        raise ValueError("u32 out of range: %r" % (value,))
    return _decimal_u64(value)


def _decimal_i64(value):
    """Signed decimal: '-' + the unsigned decimal of the magnitude.

    The binary takes the absolute value in 64-bit arithmetic, so
    INT64_MIN formats as "-9223372036854775808" (magnitude 2**63).
    """
    if not INT64_MIN <= value <= INT64_MAX:
        raise ValueError("i64 out of range: %r" % (value,))
    if value < 0:
        return "-" + _decimal_u64((-value) & UINT64_MAX)
    return _decimal_u64(value)


def int_to_string(value):
    """0x5f06bb0: signed 32-bit decimal (``std::to_string(int)``).

    INT32_MIN formats as "-2147483648" (magnitude 2**31).
    """
    if not INT32_MIN <= value <= INT32_MAX:
        raise ValueError("i32 out of range: %r" % (value,))
    if value < 0:
        return "-" + _decimal_u32((-value) & UINT32_MAX)
    return _decimal_u32(value)


# --- escape helpers -------------------------------------------------------


def escape_predicate(byte):
    """0x61d0e90: does this byte need a backslash escape?

    True for 0x0a, 0x0d, '#' (0x23), ':' (0x3a) and '\\\\' (0x5c)
    only. The mask in the bit-test arm is 0x0200000000800001,
    bits {0, 23, 57} over (byte - 0x23); bytes above 0x5c fall
    through to an early return-0, so 0x5d..0x7f and 0x80..0xff
    are NOT escaped.
    """
    if not 0 <= byte <= 0xFF:
        raise ValueError("byte out of range: %r" % (byte,))
    if byte > 0x5C:
        return False
    if byte > 0x22:
        return (ESCAPE_MASK >> (byte - 0x23)) & 1 == 1
    if byte == 0x0A:
        return True
    return byte == 0x0D


def escape_letter(byte):
    """0x61d0f00: the letter after the backslash.

    0x0a -> 'n', 0x0d -> 'r', anything else -> the byte itself.
    """
    if not 0 <= byte <= 0xFF:
        raise ValueError("byte out of range: %r" % (byte,))
    if byte == 0x0A:
        return 0x6E  # 'n'
    if byte == 0x0D:
        return 0x72  # 'r'
    return byte


def escape_copy(data):
    """0x61d0f30: backslash-escape a (ptr, len) value into a string."""
    out = bytearray()
    for byte in bytes(data):
        if escape_predicate(byte):
            out.append(0x5C)
            out.append(escape_letter(byte))
        else:
            out.append(byte)
    return bytes(out)


# --- hex helpers ----------------------------------------------------------


def hexchar(nibble):
    """0x61c7da0: nibble -> UPPERCASE hex char ('0'-'9', 'A'-'F')."""
    if not 0 <= nibble <= 0xF:
        raise ValueError("nibble out of range: %r" % (nibble,))
    if nibble <= 9:
        return 0x30 + nibble
    return 0x37 + nibble


def hex_encode(data, uppercase_flag):
    """0x61c7e30: bytes -> hex string (flag 1) or raw copy (flag 0).

    The serializer always passes flag 1 (UPPERCASE hex, two chars
    per byte). With flag 0 the helper replaces out with the raw
    input bytes instead -- modelled and tested, never taken here.
    """
    data = bytes(data)
    if not uppercase_flag:
        return data
    out = bytearray()
    for byte in data:
        out.append(hexchar(byte >> 4))
        out.append(hexchar(byte & 0xF))
    return bytes(out)


# --- double ---------------------------------------------------------------


def format_double(value):
    """Kind 10: "%f" via vsnprintf into a 328-byte buffer."""
    if not isinstance(value, float):
        raise ValueError("double kind needs a float: %r" % (value,))
    text = "%f" % value
    if len(text) >= DOUBLE_FORMAT_BUFFER:
        raise ValueError("%%f output exceeds the 328-byte buffer")
    return text


# --- enum maps ------------------------------------------------------------


class EnumMap:
    """One harness-injected enum map: {key int: name str}.

    The binary's node layout is next +0x00, name string +0x08,
    key +0x28; the serializer walks the head list at map+0x10
    linearly and returns the first node whose key matches.
    """

    def __init__(self, entries):
        self.entries = dict(entries)

    def lookup(self, key):
        return self.entries.get(key)


# --- the serializer -------------------------------------------------------


def serialize(kind, value, enum_maps=None):
    """0x60ba600: serialize one value. Returns (ok, text).

    ``value`` is an int for the numeric/bool/enum kinds, a float
    for kind 10, and bytes for kinds 9 and 23. ``enum_maps`` maps
    a global address (see ENUM_MAPS) to an EnumMap; a missing map
    or a missing key behaves like the binary's empty .bss map:
    the kind reports 0, i.e. (False, None).
    """
    if enum_maps is None:
        enum_maps = {}
    if not 0 <= kind <= KIND_MAX or kind in UNSUPPORTED_KINDS:
        return (False, None)
    if kind == 0:
        if not 0 <= value <= 0xFF:
            raise ValueError("bool kind needs a byte: %r" % (value,))
        return (True, "true" if value != 0 else "false")
    if kind in (1, 2):
        return (True, int_to_string(value))
    if kind == 3:
        return (True, _decimal_i64(value))
    if kind in (4, 6):
        return (True, _decimal_u32(value))
    if kind == 5:
        if not 0 <= value <= 0xFF:
            raise ValueError("u8 kind needs a byte: %r" % (value,))
        return (True, int_to_string(value))
    if kind in (7, 8):
        return (True, _decimal_u64(value))
    if kind == 9:
        return (True, escape_copy(value).decode("latin-1"))
    if kind == 10:
        return (True, format_double(value))
    if kind in ENUM_MAPS:
        enum_map = enum_maps.get(ENUM_MAPS[kind])
        if enum_map is None:
            return (False, None)
        name = enum_map.lookup(value)
        if name is None:
            return (False, None)
        return (True, name)
    if kind == 23:
        return (True, hex_encode(value, 1).decode("latin-1"))
    return (False, None)
