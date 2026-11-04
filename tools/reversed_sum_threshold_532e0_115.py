"""Model of node #115 flag-gated range reverse and sum threshold,
routine 0x5d532e0 (RE-001).

The routine answers one boolean question about a range of 16-byte
elements: after normalizing the range's order, is the scaled sum of
the elements' second fields large enough?

Pinned layout (see
research/work-items/RE-001-reversed-sum-threshold-532e0-115/):

- The routine takes a single holder pointer in rsi (rdi is ignored;
  the binary never reads it). The holder's first qword points at a
  {begin, end} pair for the element range, and a flag byte lives at
  holder + 0x10. The holder's +0x08 qword is never read, so this
  model does not pin it.
- Each element is 16 bytes; the routine reads only the second qword
  (offset +0x08) of each element. The first qwords are never read,
  so the model carries them but never uses them in the decision.
- When the holder's range pointer is null, the routine substitutes
  the global pair at 0x6500780 (begin) and 0x6500788 (end) instead
  and ignores the flag byte entirely. Those slots sit in BSS, so
  they start as zero (an empty range, which answers false); other
  code writes them (a 16-byte store at 0x5d83fab), but the producer
  is not pinned here.

Pinned behavior, reproduced exactly:

- Flag set (non-null range only): the range is reversed in place,
  swapping 16-byte elements front-to-back until the cursors cross,
  and the flag byte is cleared to zero. Empty and single-element
  ranges reverse to themselves, but the flag is still cleared.
- Sum: the second qwords of all elements are added with 64-bit
  wrapping arithmetic (the binary sums with paddq/add, so the sum
  wraps mod 2**64). Ranges of at most two elements take a scalar
  tail path; longer ranges take a SIMD pair loop plus a one- or
  two-element tail; both paths sum exactly the same set of fields.
- Threshold: a sum of at most 0x7fff answers false immediately.
  Otherwise the sum is shifted right by 8 and the answer is
  (sum >> 8) >= element count.
- The binary also contains a second reversal block after the sum
  (0x5d533b8 loop, flag cleared at 0x5d533dd), but it is statically
  unreachable: every path that reaches the sum has either cleared
  the flag already (the entry-flag path) or has a null range pointer
  (the globals path), so its flag test always takes the compare
  branch. The model implements only the reachable behavior and
  records the dead block as an observation, not as semantics.

The single consumer (call site 0x5d61e1d in 0x5d60fa0..0x5d623e0)
tests the returned byte: nonzero jumps to its 0x60-byte allocation
path at 0x5d61f51, zero falls through to its range-walk append path
at 0x5d61e2a. The caller's body beyond that branch is not pinned
here; consumer_branch() reproduces only the branch.
"""

MASK64 = (1 << 64) - 1
THRESHOLD = 0x7FFF
SHIFT = 8


class Holder:
    """The holder object the routine reads through rsi.

    range_pair is None (null range pointer) or a list of
    (first, second) element pairs; flag is the holder + 0x10 byte
    (any nonzero value counts as set).
    """

    def __init__(self, range_pair, flag=0):
        self.range_pair = None if range_pair is None else list(range_pair)
        self.flag = 1 if flag else 0


def reverse_in_place(elements):
    """Swap 16-byte elements front-to-back until cursors cross."""
    elements = list(elements)
    lo, hi = 0, len(elements) - 1
    while lo < hi:
        elements[lo], elements[hi] = elements[hi], elements[lo]
        lo += 1
        hi -= 1
    return elements


def sum_second_fields(elements):
    """Sum of the second qwords, wrapping mod 2**64."""
    total = 0
    for _first, second in elements:
        if not 0 <= second <= MASK64:
            raise ValueError("second field must be an unsigned 64-bit value")
        total = (total + second) & MASK64
    return total


def evaluate_range(elements):
    """The sum/threshold decision over an already-ordered range."""
    total = sum_second_fields(elements)
    if total <= THRESHOLD:
        return False
    return (total >> SHIFT) >= len(elements)


def check(holder, global_pair=()):
    """Run the routine over a holder.

    Returns (elements, flag_after, result), where elements is the
    range after any reversal (None when the global pair was used,
    since the routine then operates on the caller's global range,
    not on a holder-owned list) and flag_after is the holder's flag
    byte afterwards (untouched on the null-pair path).
    """
    if holder.range_pair is None:
        # Globals path: the flag byte is never read or written.
        return None, holder.flag, evaluate_range(list(global_pair))
    elements = list(holder.range_pair)
    flag_after = holder.flag
    if holder.flag:
        elements = reverse_in_place(elements)
        flag_after = 0
    return elements, flag_after, evaluate_range(elements)


def consumer_branch(result):
    """The single consumer's branch on the returned byte."""
    return "allocate" if result else "walk"
