r"""Model of node #115 routine 0x141c3a0: a backslash-root prefix test.

The routine (FDE 0x141c3a0..0x141c3d3, 51 bytes) takes a byte
buffer as a pointer/length pair -- ``rdi`` is the pointer, ``rsi``
is the length -- makes no calls, writes nothing, and returns a
single boolean byte in ``al``. Recovered verbatim from the
whole-function excerpt in the packet (main.txt), the decision is,
in order:

  1. If the length is 0, return false (``test %rsi,%rsi; je``).
  2. If the first byte is 0x5c (``\``), return true
     (``cmpb $0x5c,(%rdi); je``) -- the length-1-and-up leading
     separator case.
  3. If the length is 1, return false (``cmp $0x1,%rsi; je``).
  4. If byte[1] is a UTF-8 continuation byte, return false. The
     test is ``cmpb $0xc0,0x1(%rdi); jl``: a signed-byte compare
     that is taken exactly when ``(int8)byte[1] < -64``, i.e. for
     byte[1] in 0x80..0xbf. This is the standard ``is_char_boundary``
     guard -- byte[1] must begin a character.
  5. If the length is 2, return false (``cmp $0x3,%rsi`` with
     neither ``ja`` nor ``je`` taken falls through to ``xor``).
  6. If the length is greater than 3 and byte[3] is a UTF-8
     continuation byte, return false (``cmpb $0xc0,0x3(%rdi); jl``);
     for length exactly 3 byte[3] is never read.
  7. Otherwise return ``byte[1] == 0x3a and byte[2] == 0x5c``
     (``cmpw $0x5c3a,0x1(%rdi); sete``) -- i.e. the buffer begins
     with ``<one char>:\`` (a drive-letter-style root).

So the routine returns true exactly for a buffer that begins with
a backslash separator root: a leading ``\``, or ``?:\`` where the
first character is any single-byte character, byte 1 is ``:`` and
byte 2 is ``\``, with byte 3 (when present) starting a new
character. Its ``/`` twin (leading ``/`` or ``?:/``) is inlined in
the sole caller at 0x141c3d3, which selects the path separator
from the two results; that interpretation is recorded in the
packet but not claimed by this model, which only reproduces the
bytes this routine reads.

The routine never reads any buffer byte past index 3, never reads
a byte it has not proven in-bounds against the length, and makes
no calls.
"""

BACKSLASH = 0x5C
COLON = 0x3A


def _signed8(byte):
    return byte - 256 if byte >= 128 else byte


def _is_continuation(byte):
    """True for a UTF-8 continuation byte 0x80..0xbf.

    Mirrors the routine's ``cmpb $0xc0,mem; jl`` guard, which is
    taken when ``(int8)byte < -64``.
    """
    return _signed8(byte) < -64


def backslash_root_prefix(buf):
    """Return the boolean the routine returns for byte buffer ``buf``.

    ``buf`` is the pointer/length pair the routine receives; the
    length is ``len(buf)``. Raises on a non-bytes argument, the
    model's own safety guard rather than a claim about the binary
    (the routine dereferences ``rdi`` unconditionally once the
    length is nonzero).
    """
    if not isinstance(buf, (bytes, bytearray)):
        raise TypeError("buf must be bytes")
    n = len(buf)
    if n == 0:                       # step 1
        return False
    if buf[0] == BACKSLASH:          # step 2
        return True
    if n == 1:                       # step 3
        return False
    if _is_continuation(buf[1]):     # step 4
        return False
    if n == 2:                       # step 5
        return False
    if n > 3 and _is_continuation(buf[3]):  # step 6
        return False
    return buf[1] == COLON and buf[2] == BACKSLASH  # step 7
