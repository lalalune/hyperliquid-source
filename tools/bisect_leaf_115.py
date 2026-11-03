"""Node #115 bisect leaf.

Maps RE-001 window 0x5f6bba0 (106 bytes) from the digest-verified
node #115 binary (work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Object layout (all offsets are from the object base):

  +0xad8  begin pointer of the record array.
  +0xae0  end pointer of the record array.

Each record is 16 bytes. The key of a record is reached through two
loads: the record's first qword is an element pointer, and the key is
the first qword at the address held in the element's first qword, i.e.
key = [[record]]. Only that first qword chain is read; no other
record or element field is touched.

Search rule, stated literally from the native loop:

  diff = (end - begin) as a wrapping 64-bit difference, read signed.
  If diff <= 0 (signed), return the begin index at once, without
  reading any record.
  Otherwise let count = diff >> 4 (arithmetic shift, so a byte span
  that is not a multiple of 16 floors to whole records), and run:

    lo = begin index; remaining = count
    loop:
      half = remaining >> 1 (arithmetic; remaining > 0 at the loop head)
      mid = lo + half
      key = [[record[mid]]]
      if key >= target (unsigned):
          if half == 0: return lo
          remaining = half
      else:
          remaining = remaining - half - 1
          lo = mid + 1
          if remaining > 0: continue
          return lo

  The result is the index of the first record whose key is >= the
  target under unsigned comparison, or the index one past the last
  record examined when every examined key is below the target. For a
  well-formed array (byte span exactly 16 * record count) that is the
  usual lower bound, or the record count when the target exceeds all
  keys.

Notes on fidelity:

  * The comparison is unsigned (jae on the native cmp). A key with
    its high bit set is above every key without it, which a signed
    reading would reverse.
  * The loop is reproduced exactly, not replaced by an idealised
    lower bound, so a partial byte span behaves as the native code
    does: a span of 8 with one record returns 0 when that record's
    key is >= the target and 1 when it is below it.
  * The native code reads memory without checks. The model raises
    BisectLeafError instead when the loop would read past the
    supplied records, when a key or the target is outside the
    unsigned 64-bit range, or when a record entry is missing.
"""


MASK64 = (1 << 64) - 1


class BisectLeafError(Exception):
    """Raised for inputs the native code would read unchecked."""


def _u64(value):
    if not isinstance(value, int) or isinstance(value, bool):
        raise BisectLeafError("value is not an integer: %r" % (value,))
    if value < 0 or value > MASK64:
        raise BisectLeafError("value outside unsigned 64-bit range: %r"
                              % (value,))
    return value


def _s64(value):
    value &= MASK64
    return value - (1 << 64) if value >> 63 else value


def bisect_leaf(records, target, byte_span=None):
    """Return the lower-bound index for target over records.

    records is the list of record keys in array order, i.e. the
    [[record]] qword of each 16-byte record. target is the unsigned
    64-bit key sought. byte_span overrides the native (end - begin)
    byte difference; it defaults to 16 * len(records).
    """
    target = _u64(target)
    keys = [_u64(k) for k in records]
    if byte_span is None:
        span = 16 * len(keys)
    else:
        if not isinstance(byte_span, int) or isinstance(byte_span, bool):
            raise BisectLeafError("byte_span is not an integer: %r"
                                  % (byte_span,))
        span = byte_span & MASK64
    diff = _s64(span)
    if diff <= 0:
        return 0
    remaining = diff >> 4
    lo = 0
    while True:
        half = remaining >> 1
        mid = lo + half
        if mid < 0 or mid >= len(keys):
            raise BisectLeafError(
                "loop would read past the supplied records (mid=%d, "
                "records=%d)" % (mid, len(keys)))
        key = keys[mid]
        if key >= target:
            if half == 0:
                return lo
            remaining = half
        else:
            remaining = remaining - half - 1
            lo = mid + 1
            if remaining > 0:
                continue
            return lo
