"""Model of node #115 pair insertion sort, 0x5d497e0..0x5d498b5 (RE-001).

The routine sorts a range of 16-byte elements in place (rdi = begin,
rsi = end, exclusive). Each element is a pair of qwords, ordered
ascending by unsigned lexicographic order on (first, second): the
first qwords are compared unsigned, and only when they are equal
are the second qwords compared unsigned.

Pinned algorithm: empty and single-element ranges are no-ops. For
each element from the second to the last, hold the current pair,
scan backward over the already-sorted prefix, shift right each
predecessor strictly greater than the current pair, stop at the
first predecessor less than or equal to it, and store the current
pair in the freed slot. When the current pair is strictly less
than the begin element, the binary's separate block shifts the
whole prefix right and stores it at begin; the observable result
is identical to the backward scan, so the model implements the
scan uniformly. The walk stops at predecessors equal to the
current pair instead of shifting them; because an element carries
no identity beyond its two compared qwords, that has no
observable effect on the output, and no stability claim is made.

A pair is a (first, second) tuple of unsigned ints in
[0, 2**64). Ranges whose length is not a multiple of 16 elements
and inverted ranges are not characterized: all six call sites
pass element-aligned ranges with begin at most end. The model
raises ValueError on out-of-range qwords as a model-only guard,
not a binary claim (the binary compares raw qwords with no check).
"""

MASK = (1 << 64) - 1


def insertion_sort(pairs):
    """Sort a list of (first, second) pairs in place, return the list."""
    out = list(pairs)
    for first, second in out:
        if not (0 <= first <= MASK and 0 <= second <= MASK):
            raise ValueError("qword out of range")
    for i in range(1, len(out)):
        cur = out[i]
        j = i - 1
        while j >= 0 and out[j] > cur:
            out[j + 1] = out[j]
            j -= 1
        out[j + 1] = cur
    return out
