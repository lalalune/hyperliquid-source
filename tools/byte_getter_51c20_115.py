"""Model of node #115 routine 0x5d51c20: a one-byte getter.

The routine takes two arguments: a flag-holder pointer in rdi
(only its first byte is read) and an object pointer in rsi, and
returns one byte. The decision, in order, read from the
whole-function excerpt in the packet:

  1. If the flag byte at (rdi) is NOT exactly 1, the selector at
     object +0x100 is never read: return the first byte of the
     vector at +0x1c8 (begin) / +0x1d0 (end) when begin != end,
     else the default byte at +0x153. Note the test is equality
     with 1, not truthiness: flag values 0, 2, 255 all take this
     path.
  2. If the flag byte IS 1, read the signed 32-bit selector at
     +0x100. If it is >= 0, return 0 without reading the vector
     or the default byte.
  3. If the flag byte is 1 and the selector is negative, fall
     back to the vector rule of step 1: first byte when the
     vector is non-empty, else the default byte at +0x153.

The routine makes no calls, writes nothing, and never reads any
object byte besides the selector dword, the vector begin/end
pointers, and the default byte -- in particular it never reads
vector bytes past the first, and it never reads a size field.
"""

FLAG_OFFSET = 0x00
SELECTOR_OFFSET = 0x100
VECTOR_BEGIN_OFFSET = 0x1C8
VECTOR_END_OFFSET = 0x1D0
DEFAULT_OFFSET = 0x153

INT32_MIN = -(2 ** 31)
INT32_MAX = 2 ** 31 - 1


def _check_byte(value, label):
    if not isinstance(value, int) or isinstance(value, bool) \
            or not 0 <= value <= 255:
        raise ValueError("%s must be an integer byte 0..255" % label)


def _check_selector(value):
    if not isinstance(value, int) or isinstance(value, bool) \
            or not INT32_MIN <= value <= INT32_MAX:
        raise ValueError("selector must be a signed 32-bit integer")


class ByteSource:
    """The two inputs as the routine sees them.

    ``flag`` is the single byte at the rdi pointer. ``selector``
    is the signed 32-bit integer at object +0x100. ``vector`` is
    the byte string of the vector at +0x1c8..+0x1d0 (only its
    first byte is ever read). ``default`` is the byte at +0x153.
    """

    def __init__(self, flag, selector, vector=b"", default=0):
        _check_byte(flag, "flag")
        _check_selector(selector)
        if not isinstance(vector, (bytes, bytearray)):
            raise TypeError("vector must be bytes")
        _check_byte(default, "default")
        self.flag = flag
        self.selector = selector
        self.vector = bytes(vector)
        self.default = default


def byte_getter(source):
    """Return the single byte the routine returns for ``source``."""
    if not isinstance(source, ByteSource):
        raise TypeError("source must be a ByteSource")
    if source.flag != 1:
        return source.vector[0] if source.vector else source.default
    if source.selector >= 0:
        return 0
    return source.vector[0] if source.vector else source.default
