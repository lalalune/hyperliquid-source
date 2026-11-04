"""Model of node #115 pair introsort loop, 0x5d4a3f0..0x5d4a698, with
its adjust-heap helper 0x5d49530..0x5d496cd (RE-001).

The routine sorts a range of 16-byte elements in place (rdi = begin,
rsi = end, exclusive; rdx = depth budget). Each element is a pair of
qwords, ordered ascending by unsigned lexicographic order on
(first, second): the first qwords are compared unsigned, and only
when they are equal are the second qwords compared unsigned.

Pinned algorithm (see research/work-items/RE-001-introsort-loop-4a3f0-115/):

1. Small range: byte count at most 0x100 (16 elements) returns at
   once, sorting nothing. The caller runs the final insertion sort
   over such ranges (see PR #2602's helper and PR #2600's driver).
2. Depth exhausted: depth exactly zero at entry, or the decremented
   depth reaching zero after a partition, runs the heapsort fallback
   over the current range and returns.
3. Otherwise the depth is decremented once per partition level, the
   median of the three candidates (second element, middle element,
   last element) is moved to begin by the compare/swap network, the
   range is Hoare-partitioned around the begin element, the right
   part is sorted by recursion with the decremented depth, and the
   left part is handled by tail iteration.
4. Heapsort fallback: heapify by calling adjust_heap for every parent
   index from (count - 2) // 2 down to 0, then repeatedly move the
   maximum to the end and re-adjust the remaining heap.
5. adjust_heap(first, hole, length, value): sift-down phase moves
   the larger child up into the hole (the right child wins exact
   ties), the even-length tail moves a lone left child up when the
   hole is the last parent, and the push-up phase moves parents
   strictly smaller than the value down until the value's slot is
   found.

The partition scans are unguarded in the binary: the left scan stops
at the first element greater than or equal to the pivot, and the
right scan stops at the first element less than or equal to it. They
cannot run out of range after the median step, because at least one
candidate greater than or equal to the pivot and at least one
candidate less than or equal to it remain inside the range (the
median's two companion candidates). The model indexes directly, so
a partition called without the median step on an unguarded array
may raise IndexError instead of reading out of range.

A pair is a (first, second) tuple of unsigned ints in [0, 2**64).
Ranges are element-aligned with begin at most end. The model raises
ValueError on out-of-range qwords as a model-only guard, not a
binary claim (the binary compares raw qwords with no check). The
libstdc++ names (introsort loop, adjust heap) are inference from
the structure; the pinned facts are the disassembly behavior and
the call sites.
"""

MASK = (1 << 64) - 1
SMALL_RANGE_BYTES = 0x100


def _check(pairs):
    for first, second in pairs:
        if not (0 <= first <= MASK and 0 <= second <= MASK):
            raise ValueError("qword out of range")


def median_to_first(pairs, lo, hi):
    """Move the median of pairs[lo+1], pairs[mid], pairs[hi-1] to lo.

    Implements the binary's compare/swap network (blocks at
    0x5d4a458, 0x5d4a520, 0x5d4a574, 0x5d4a683) exactly, including
    its tie arms: the first comparison sends an exactly equal
    second element to the greater-or-equal arm, and the shared
    seconds block decides equal-first comparisons by the second
    qword. Equal pairs are indistinguishable, so a tie arm's choice
    among equal candidates has no observable effect.
    """
    a = pairs
    p1 = lo + 1
    mid = lo + (hi - lo) // 2
    last = hi - 1
    first_elem, mid_elem, last_elem = a[p1], a[mid], a[last]

    def swap(i, j):
        a[i], a[j] = a[j], a[i]

    if first_elem < mid_elem:
        # Block 0x5d4a458: second element below middle.
        if mid_elem < last_elem:
            swap(lo, mid)  # 0x5d4a478
        elif mid_elem > last_elem:
            # Block 0x5d4a574: middle above last.
            if first_elem < last_elem:
                swap(lo, last)  # 0x5d4a54d
            else:
                swap(lo, p1)  # 0x5d4a590 (includes exact equality)
        else:
            # Middle equals last: the binary takes the 0x5d4a574
            # arm, and the first element is below both.
            swap(lo, last)  # 0x5d4a54d
    else:
        # Block 0x5d4a520: second element at or above middle.
        if first_elem < last_elem:
            swap(lo, p1)  # 0x5d4a590
        elif first_elem > last_elem:
            # Block 0x5d4a683.
            if mid_elem < last_elem:
                swap(lo, last)  # 0x5d4a54d
            elif mid_elem > last_elem:
                swap(lo, mid)  # 0x5d4a478
            elif mid_elem[1] >= last_elem[1]:
                swap(lo, mid)  # 0x5d4a478 via the seconds block
            else:
                swap(lo, last)  # 0x5d4a54d via the seconds block
        else:
            # First element at or above last with equal first
            # qwords (fallthrough to 0x5d4a53a): middle below last
            # takes the last arm; otherwise the seconds block
            # decides. A middle first qword above last's is
            # unreachable here (it would contradict the second
            # element being at or above middle with equal first
            # qwords to last), and the binary's shared seconds
            # block decides it the same way.
            if mid_elem[0] < last_elem[0]:
                swap(lo, last)  # 0x5d4a54d
            elif mid_elem[1] >= last_elem[1]:
                swap(lo, mid)  # 0x5d4a478
            else:
                swap(lo, last)  # 0x5d4a54d


def partition(pairs, lo, hi):
    """Hoare-partition pairs[lo:hi] around pairs[lo]; return the cut.

    The pivot stays at lo. The left scan advances while the element
    is strictly below the pivot; the right scan retreats while the
    element is strictly above it; when the cursors meet or cross,
    the cut is the left cursor. On return, every element in
    [lo, cut) is at most the pivot and every element in [cut, hi)
    is at least the pivot. Assumes the median step ran first (see
    the module docstring for the guard argument).
    """
    a = pairs
    pivot = a[lo]
    i = lo + 1
    j = hi
    while True:
        while a[i] < pivot:
            i += 1
        while True:
            j -= 1
            if a[j] <= pivot:
                break
        if i >= j:
            return i
        a[i], a[j] = a[j], a[i]
        i += 1


def adjust_heap(pairs, lo, hole, length, value):
    """Restore the max-heap over pairs[lo:lo+length] around a hole.

    Sift-down: while the hole is above the last parent index
    (length - 1) // 2, move the larger child up into it; the right
    child wins exact ties. Even-length tail: when the length is
    even and the hole is the last parent, move its lone left child
    up. Push-up: while the hole is below its start and its parent
    is strictly below the value, move the parent down. Finally the
    value is stored in the hole. The old hole slot's value is never
    read, only overwritten.

    Caller precondition (as in both binary uses): the value is at
    most every ancestor above the original hole. Heapify passes the
    hole's own element, and the pop loop passes a leaf element with
    the hole at the root, so the push-up never needs to rise above
    the original hole; a value larger than an ancestor above the
    hole would be left below that ancestor, exactly as the binary
    leaves it.
    """
    a = pairs
    top = hole
    limit = 0 if length == 0 else (length - 1) // 2
    if hole < limit:
        while True:
            second = 2 * (hole + 1)
            first = second - 1
            if a[lo + second] < a[lo + first]:
                winner = first
            else:
                winner = second
            a[lo + hole] = a[lo + winner]
            hole = winner
            if hole >= limit:
                break
    if length % 2 == 0 and hole == (length - 2) // 2:
        child = 2 * hole + 1
        a[lo + hole] = a[lo + child]
        hole = child
    while hole > top:
        parent = (hole - 1) // 2
        if a[lo + parent] < value:
            a[lo + hole] = a[lo + parent]
            hole = parent
        else:
            break
    a[lo + hole] = value


def heapsort(pairs, lo, hi):
    """Sort pairs[lo:hi] with the binary's heapify/pop sequence."""
    a = pairs
    count = hi - lo
    hole = (count - 2) // 2
    while True:
        adjust_heap(a, lo, hole, count, a[lo + hole])
        if hole == 0:
            break
        hole -= 1
    last = hi - 1
    while last - lo >= 1:
        old_last = a[last]
        a[last] = a[lo]
        adjust_heap(a, lo, 0, last - lo, old_last)
        last -= 1


def _loop(pairs, lo, hi, depth):
    a = pairs
    while True:
        if (hi - lo) * 16 <= SMALL_RANGE_BYTES:
            return
        if depth == 0:
            heapsort(a, lo, hi)
            return
        depth -= 1
        median_to_first(a, lo, hi)
        cut = partition(a, lo, hi)
        _loop(a, cut, hi, depth)
        hi = cut


def introsort_loop(pairs, depth):
    """Run the introsort loop over a list of pairs; return the list.

    Ranges of at most 16 elements are returned unchanged: the
    binary leaves them for the caller's final insertion sort.
    Otherwise the result is the loop's output, which the caller's
    final insertion sort completes to fully sorted order (the loop
    leaves every element within a small partition whose elements
    are already ordered relative to the other partitions).
    """
    out = list(pairs)
    _check(out)
    _loop(out, 0, len(out), depth)
    return out
