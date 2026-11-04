"""Python model of node #115's flag-variant index leaf at 0x5f6b740.

RE-001 work item: research/work-items/RE-001-flag-variant-115/.
The leaf takes an object pointer in rdi and a flag in rsi, of which
only the low byte participates. It reads the dword at obj+0x10 and
returns, modulo 2**32, that dword minus 2 plus 1 when the flag low
byte is zero, plus 0 when it is nonzero. It makes no call and
writes nothing. No meaning for the field or the flag beyond that
rule is claimed.

The site disposition helper models the sole call site at 0x5df5bff
only: the caller compares the leaf's return against ebx, jumps to
0x5df4ad0 on mismatch, otherwise runs the virtual call (slot
+0x200) and rejoins 0x5df4ad0 when that call's signed 32-bit
result is less than or equal to zero. Only a leaf match plus a
positive virtual result continues past the site.
"""

MASK32 = (1 << 32) - 1


def flag_variant(obj, flag):
    """Apply the 0x5f6b740 rule.

    ``obj`` maps field offsets to values; only 0x10 is read.
    ``flag`` is the caller's flag value; only its low byte is
    used. Raises ValueError when the field the leaf reads is
    absent, so a caller cannot silently model a partially known
    record. Returns the 32-bit result.
    """
    if 0x10 not in obj:
        raise ValueError("obj is missing field 0x10")
    field = obj[0x10] & MASK32
    bonus = 1 if (flag & 0xFF) == 0 else 0
    return (field - 2 + bonus) & MASK32


def site_disposition(leaf_result, ebx, virtual_result):
    """Model the 0x5df5bff site's result disposition.

    Returns "away" when the caller reaches 0x5df4ad0 (leaf
    mismatch, or a virtual result less than or equal to zero
    signed) and "continue" only when the leaf matches ebx and
    the virtual result is positive. ``virtual_result`` is the
    signed 32-bit value the virtual call returned.
    """
    if (leaf_result & MASK32) != (ebx & MASK32):
        return "away"
    if virtual_result <= 0:
        return "away"
    return "continue"
