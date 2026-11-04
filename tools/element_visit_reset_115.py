"""Python model of node #115's element-visit-and-reset routine at 0x5f6eac0.

RE-001 work item: research/work-items/RE-001-element-visit-reset-115/.
The routine takes an object pointer in rdi and returns void. It
reads begin from obj+0x08 and end from obj+0x10, stores 0 at
obj+0x00 at once (also on the empty path), then, for a
0x180-step-aligned nonempty range, calls the 0x5d516f0 callee once
per element pointer begin + k * 0x180 in increasing order, the
callee's return discarded, and finally stores the original begin
at obj+0x10, so the range is empty. The qword at obj+0x08 is never
written. The callee's own semantics are not modelled; the caller
supplies it as a function taking one element pointer.

The site helpers model only the two call sites: site 1
(0x5f76388) passes the loaded pointer plus 0x18, but only when
that pointer is nonzero, after zeroing the byte at the unshifted
pointer + 0x321; site 2 (0x5fa1796) passes the object at
[rsp + 0x30]. Caller semantics beyond the sites are not modelled.
An unaligned or inverted range raises instead of being silently
modelled, because the literal loop advances by 0x180 until the
cursor equals end.
"""

MASK64 = (1 << 64) - 1
STEP = 0x180


def element_visit_reset(obj, visit):
    """Apply the 0x5f6eac0 rule.

    ``obj`` maps field offsets to values; 0x00, 0x08 and 0x10 are
    all read. Raises ValueError when any of them is absent, or
    when the range is not a non-negative multiple of 0x180.
    ``visit`` is called once per element pointer, in increasing
    order, and its return value is discarded. Returns the list of
    visited element pointers. Mutates ``obj``: 0x00 becomes 0 and
    0x10 becomes the original begin; 0x08 is untouched.
    """
    for offset in (0x00, 0x08, 0x10):
        if offset not in obj:
            raise ValueError("obj is missing field %#x" % offset)
    begin = obj[0x08] & MASK64
    end = obj[0x10] & MASK64
    obj[0x00] = 0
    if begin == end:
        return []
    span = (end - begin) & MASK64
    if end < begin or span % STEP != 0:
        raise ValueError("range is not a non-negative multiple of 0x180")
    visited = []
    cursor = begin
    while cursor != end:
        visit(cursor)
        visited.append(cursor)
        cursor = (cursor + STEP) & MASK64
    obj[0x10] = begin
    return visited


def site1_call_arg(loaded_pointer):
    """Argument for the 0x5f76388 call site.

    Returns None when the loaded pointer is zero (the caller jumps
    away and never calls); otherwise the loaded pointer plus 0x18.
    The caller also zeroes the byte at the unshifted pointer +
    0x321 before the call; that byte is outside this routine's
    object and is not modelled here.
    """
    if loaded_pointer == 0:
        return None
    return (loaded_pointer + 0x18) & MASK64


def site2_call_arg(stack_object):
    """Argument for the 0x5fa1796 call site: the object itself."""
    return stack_object
