"""Python model of node #115's +0x70 incrementer leaf at 0x5d8d0b0.

RE-001 work item: research/work-items/RE-001-incrementer-115/.

The leaf is 14 bytes (endbr64, mov, add, mov, ret). It takes an
object in rdi, reads the dword at obj+0x70, adds 1 to it as a
32-bit quantity, stores the result back at obj+0x70, and returns
the new value in eax. It makes no calls and writes nothing else.
The addition wraps modulo 2**32: a field holding 0xFFFFFFFF
becomes 0, and the returned value is 0 in that case.

The leaf is the fourth operation on the same +0x70 field whose
getter (0x5d8d0c0) and unsigned-max raiser (0x5d8d0d0) are mapped
by open PR #2397; those two leaves are
referenced here, not re-claimed. The incrementer's only direct
call site in the binary (whole-file census, reproduced by the
packet's census.py) is 0x5d69d70, on the null arm of the caller
0x5d69a00..0x5d6a6d9: the caller first calls the lookup routine
0x5d8cf70 and, when that call returns zero, takes the null arm,
prepares a stack object, calls the incrementer with
rdi = qword at [qword at [r13+0x68] + 0x40], and stores the
returned value at [rbp-0x540]. When the lookup returns nonzero
the caller falls through past the null-arm jump and never calls
the incrementer on that path.

The object is represented as a dict mapping byte offsets to
integer field values. A missing field raises ValueError; the
binary would simply read whatever bytes lie at that address, so
a missing field is a modelling gap, not a binary behavior. The
+0x70 value is masked to 32 bits, matching the mov width.

NOT claimed: what the objects or their +0x70 field denote, the
lookup routine's own semantics, the caller semantics beyond the
recorded site (including the stack-object preparation and the
taken path's later calls), or what the caller does with the
stored value afterwards -- a whole-function scan shows the
[rbp-0x540] slot is never read again inside the caller function.
"""

MASK32 = (1 << 32) - 1


def _field70(obj):
    if 0x70 not in obj:
        raise ValueError("missing +0x70 field")
    return obj[0x70] & MASK32


def increment_field70(obj):
    """Apply the 0x5d8d0b0 leaf to obj; return the new +0x70 value."""
    new_value = (_field70(obj) + 1) & MASK32
    obj[0x70] = new_value
    return new_value


def site_disposition(obj, lookup_result):
    """Model the sole site's branch: lookup zero -> increment + store.

    Returns the value stored at the caller's stack slot on the
    null arm, or None on the taken arm (no increment, no store).
    The stack slot itself is modelled as the returned value; the
    binary stores it at [rbp-0x540] and never reads it again in
    the caller function.
    """
    if lookup_result == 0:
        return increment_field70(obj)
    return None
