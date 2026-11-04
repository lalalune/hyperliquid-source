"""Python model of node #115's span-count predicate at 0x5f6ea90.

RE-001 work item: research/work-items/RE-001-span-count-predicate-115/.
The predicate takes an object pointer in rdi, reads the qwords at
obj+0x00, obj+0x08 and obj+0x10, and returns 1 exactly when the
qword at obj+0x00 equals ((qword at obj+0x10 minus qword at
obj+0x08, arithmetic-shifted right by 7) multiplied, modulo 2**64,
by 0xAAAAAAAAAAAAAAAB). It makes no call and writes nothing. No
meaning for the fields beyond that rule is claimed.

The site disposition helper models the sole call site at
0x5fa159d only: the caller loads the object from [rsp+0x30],
calls the predicate, and on a zero result jumps straight to the
shared cleanup block at 0x5fa129c, skipping the loop and the
follow-up call. On a nonzero result it loads begin from
[rbx+0x20] and end from [rbx+0x28]; an empty range reaches the
0x5fa1786 arm (follow-up call when the stack byte at [rsp+0x70]
is zero, otherwise the 0x5fa1674 block), and a nonempty range
enters the loop whose head issues the virtual call at slot +0x18
and whose back edge advances by 0x180 until the cursor reaches
the stored end, after which the caller issues the follow-up call
to 0x5f6eac0 on the same object and then jumps to cleanup. The
per-iteration post-call block beyond the loop head call is not
modelled; the step count is the head/back-edge arithmetic, which
assumes the range is 0x180-step-aligned, and an unaligned or
inverted range raises instead of being silently modelled.
"""

MASK64 = (1 << 64) - 1
MAGIC = 0xAAAAAAAAAAAAAAAB
STEP = 0x180


def span_count_predicate(obj):
    """Apply the 0x5f6ea90 rule.

    ``obj`` maps field offsets to values; 0x00, 0x08 and 0x10
    are all read. Raises ValueError when any of them is absent,
    so a caller cannot silently model a partially known record.
    Returns 1 for a match, 0 otherwise.
    """
    for offset in (0x00, 0x08, 0x10):
        if offset not in obj:
            raise ValueError("obj is missing field %#x" % offset)
    first = obj[0x00] & MASK64
    begin = obj[0x08] & MASK64
    end = obj[0x10] & MASK64
    raw = (end - begin) & MASK64
    signed = raw - (1 << 64) if raw >> 63 else raw
    shifted = signed >> 7
    product = (shifted * MAGIC) & MASK64
    return 1 if product == first else 0


def loop_steps(begin, end):
    """Head/back-edge step count for the site's element loop.

    The cursor starts at ``begin`` and advances by 0x180 per pass
    until it equals ``end``. Raises ValueError for an empty,
    inverted or unaligned range, whose loop behaviour is not
    claimed here.
    """
    if end <= begin:
        raise ValueError("loop_steps needs a nonempty range")
    span = end - begin
    if span % STEP != 0:
        raise ValueError("range is not 0x180-step-aligned")
    return span // STEP


def site_disposition(pred, begin, end, stack70):
    """Model the 0x5fa159d site's result disposition.

    Returns "cleanup" when the predicate is false (the caller
    jumps to 0x5fa129c at once); "followup" when the range is
    empty and the stack byte is zero (the caller calls 0x5f6eac0
    on the same object, then cleanup); "block-0x5fa1674" when
    the range is empty and the stack byte is nonzero; and
    "loop:<n>:followup" when the range is nonempty, where <n>
    is the head/back-edge step count.
    """
    if pred == 0:
        return "cleanup"
    if begin == end:
        return "followup" if stack70 == 0 else "block-0x5fa1674"
    return "loop:%d:followup" % loop_steps(begin, end)
