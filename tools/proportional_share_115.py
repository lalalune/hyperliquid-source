"""Node #115 proportional share at 0x5f6ad70 (RE-001).

A whole 350-byte leaf function, modelled end to end from the verbatim
excerpt in research/work-items/RE-001-proportional-share-115/.

Layout of the single object argument (rdi):
  +0xfc0  total   unsigned 64-bit divisor / threshold
  +0xfb0  hi      unsigned 64-bit upper bound
  +0xfb8  lo      unsigned 64-bit lower bound
  +0x10   count   signed 32-bit entry count
  +0xa98  entries pointer to count 24-byte entries; each entry contributes
          (qword at +0x08 minus qword at +0x00) arithmetic-shifted right by 3

Semantics, stated literally from the disassembly:
  - total == 0 returns 0 at once.
  - lo >= hi (unsigned) returns 0; otherwise span = hi - lo.
  - count <= 0 (signed) returns span with no loop.
  - Otherwise sum = the wrapping 64-bit sum over exactly count entries of
    the signed entry difference shifted arithmetically right by 3.
  - total >= sum (unsigned) returns span.
  - Otherwise the return is the unsigned 64-bit truncation of the IEEE
    double value (double)span * (double)sum / (double)total, where each
    unsigned-to-double conversion rounds to nearest even (the binary's
    shr/or/addsd path) and the double-to-unsigned conversion follows the
    binary's comisd/subsd/cvttsd2si/btc path: values at or above 2**63
    subtract 2**63 first, then set bit 63; a value at or above 2**64
    converts to the integer indefinite, which the bit flip turns into 0.

The function's only caller in the whole binary is the composite getter
at 0x5eeb570 (call site 0x5eeb5b3, mapped by PR #2215), which passes its
object (inner + 0x30 + 0x40) and adds the return into its base sum. The
model here covers the function itself; the caller is claimed only as a
call site, as in the packet's census.
"""

MASK64 = (1 << 64) - 1
TWO63 = 1 << 63


def _s64(value):
    value &= MASK64
    return value - (1 << 64) if value >> 63 else value


def _s32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >> 31 else value


def _trunc_double_to_u64(x):
    """Truncate a non-negative double to u64 the way the binary does.

    The binary compares against 2**63, subtracts it when at or above,
    converts with truncation, then flips bit 63. Out-of-range values
    (>= 2**64) yield the integer indefinite, which the flip turns to 0.
    """
    two63 = float(TWO63)
    if x >= two63:
        y = x - two63
        if y >= two63:
            return 0
        return int(y) + TWO63
    return int(x)


class ShareObject:
    """Model-level stand-in for the object at 0x5f6ad70's rdi.

    ``entries`` is a list of (first, second) qword pairs, one per 24-byte
    entry; the third qword of each entry is never read by this function.
    """

    def __init__(self, total, hi, lo, count, entries):
        self.total = total & MASK64
        self.hi = hi & MASK64
        self.lo = lo & MASK64
        self.count = _s32(count)
        self.entries = list(entries)


def proportional_share(obj):
    """Return the proportional share for ``obj`` (see module docstring)."""
    total = obj.total
    if total == 0:
        return 0
    hi = obj.hi
    lo = obj.lo
    if lo >= hi:
        return 0
    span = (hi - lo) & MASK64
    if obj.count <= 0:
        return span
    if len(obj.entries) < obj.count:
        raise ValueError("fewer entries than count")
    total_sum = 0
    for first, second in obj.entries[: obj.count]:
        diff = _s64(second - first)
        total_sum = (total_sum + (diff >> 3)) & MASK64
    if total >= total_sum:
        return span
    value = float(span) * float(total_sum) / float(total)
    return _trunc_double_to_u64(value)
