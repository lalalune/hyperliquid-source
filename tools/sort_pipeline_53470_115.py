"""Python model of the node #115 sort pipeline pinned by
RE-001-sort-pipeline-53470-115.

Routines (node #115, work/hl-node-115.bin):
  * sort entry        0x5d53470..0x5d53577
  * introsort loop    0x5d4c1c0..0x5d4c8cf
  * heap sift-down    0x5d4bce0..0x5d4c15a
  * less-than predicate 0x5d4a830..0x5d4a90f
  * element swap      0x5d496d0..0x5d49739
  * insertion-sort pass 0x5d4ba10..0x5d4bcd7
  * single-element insertion step 0x5d4b3f0..0x5d4b5c0

The container is an SSO indexed store of 8-byte element handles:
slots 0..31 live inline (base + 0x108); slots 32 and up live in a
heap table whose stored pointer (base + 0x110) points at the slot
for element 32, so slot i > 31 sits at heap - 0x100 + i * 8.

Elements carry an int32 key read through the virtual slot +0x30
and a tie-break read through the virtual slot +0x10 (taken only
when the keys are equal and the object's vtable slot +0xd0 matches
the expected function at 0x5d48410, the value the RELATIVE
relocation at 0x64ecfb0 installs at load time; on a mismatch the
binary instead calls the +0xd0 slot itself). The model injects
those two reads as callables so the ordering is testable without
the target's vtables.
"""

THRESHOLD = 16
INLINE_CAPACITY = 32


def depth_limit(count):
    """2 * floor(log2(count)), exactly as the sort entry computes
    it: bsr(count), then doubled. count 0 never reaches this."""
    return 2 * (count.bit_length() - 1)


class SsoList:
    """The indexed container. `data` is the element sequence;
    `address_kind(i)` reports where the binary stores slot i."""

    def __init__(self, elements):
        self.data = list(elements)

    def __len__(self):
        return len(self.data)

    def address_kind(self, i):
        return "inline" if i <= INLINE_CAPACITY - 1 else "heap"

    def slot(self, i):
        return self.data[i]

    def store(self, i, value):
        self.data[i] = value


def less_than(a, b, key, tiebreak):
    """The 0x5d4a830 predicate: 1 exactly when key(a) < key(b),
    0 when key(a) > key(b); on equal keys the sign of
    tiebreak(a, b) decides (1 when negative, else 0)."""
    ka, kb = key(a), key(b)
    if ka < kb:
        return 1
    if ka > kb:
        return 0
    return 1 if tiebreak(a, b) < 0 else 0


def swap_elements(container, i, j):
    """The 0x5d496d0 element swap, across either addressing kind."""
    a, b = container.slot(i), container.slot(j)
    container.store(i, b)
    container.store(j, a)


def median_to_first(container, lo, hi, key, tiebreak):
    """The 0x5d4c1c0 pivot selection: the libstdc++
    __move_median_to_first of (lo + 1, mid, hi - 1) into lo,
    using the less-than predicate exactly in the binary's order:
    comp(a, b); then comp(b, c) / comp(a, c) / comp(b, c) arms."""
    a, b, c = lo + 1, lo + (hi - lo) // 2, hi - 1
    if less_than(container.slot(a), container.slot(b), key, tiebreak):
        if less_than(container.slot(b), container.slot(c), key, tiebreak):
            swap_elements(container, lo, b)
        elif less_than(container.slot(a), container.slot(c), key, tiebreak):
            swap_elements(container, lo, c)
        else:
            swap_elements(container, lo, a)
    else:
        if less_than(container.slot(a), container.slot(c), key, tiebreak):
            swap_elements(container, lo, a)
        elif less_than(container.slot(b), container.slot(c), key, tiebreak):
            swap_elements(container, lo, c)
        else:
            swap_elements(container, lo, b)


def partition(container, lo, hi, key, tiebreak):
    """The 0x5d4c1c0 Hoare partition around the pivot now at lo
    (libstdc++ __unguarded_partition): the low cursor advances
    from lo + 1 while its element is less than the pivot, the
    high cursor retreats from hi - 1 while the pivot is less than
    its element, and the cursors' elements are swapped until they
    cross; returns the cut index."""
    pivot = container.slot(lo)
    i, j = lo + 1, hi
    while True:
        while less_than(container.slot(i), pivot, key, tiebreak):
            i += 1
        j -= 1
        while less_than(pivot, container.slot(j), key, tiebreak):
            j -= 1
        if i >= j:
            return i
        swap_elements(container, i, j)
        i += 1


def adjust_heap(container, first, hole, length, value, key, tiebreak):
    """The 0x5d4bce0 sift-down (__adjust_heap) over [first,
    first + length): the value starts in the hole (a relative
    index); the larger child (right child 2 * hole + 2 when it
    exists and beats the left) is moved up until the hole reaches
    a leaf, then the value is pushed back up to its place."""
    second_child = 2 * hole + 2
    top = hole
    while second_child < length:
        left = second_child - 1
        right = second_child
        if less_than(container.slot(first + right),
                     container.slot(first + left), key, tiebreak):
            second_child = left
        else:
            second_child = right
        container.store(first + hole,
                        container.slot(first + second_child))
        hole = second_child
        second_child = 2 * hole + 2
    if second_child == length:
        container.store(first + hole,
                        container.slot(first + second_child - 1))
        hole = second_child - 1
    # Push the value up from the hole (the 0x5d4bfc0 block), but
    # only as far as the hole it started in: above that point the
    # heap order already holds for this value, and later sift-downs
    # from higher nodes assume the subtree below them is a heap.
    while hole > top:
        parent = (hole - 1) // 2
        if less_than(value, container.slot(first + parent),
                     key, tiebreak):
            break
        container.store(first + hole,
                        container.slot(first + parent))
        hole = parent
    container.store(first + hole, value)


def heapsort(container, lo, hi, key, tiebreak):
    """The 0x5d4c1c0 depth-exhausted fallback: make_heap over
    [lo, hi) by sifting down from (n - 2) / 2 to 0, then sort_heap
    by repeatedly swapping the root with the last element and
    sifting the new root down over the shrinking range."""
    n = hi - lo
    if n <= 1:
        return
    for i in range((n - 2) // 2, -1, -1):
        adjust_heap(container, lo, i, n,
                    container.slot(lo + i), key, tiebreak)
    for end in range(n - 1, 0, -1):
        swap_elements(container, lo, lo + end)
        adjust_heap(container, lo, 0, end,
                    container.slot(lo), key, tiebreak)


def introsort_loop(container, lo, hi, depth, key, tiebreak):
    """The 0x5d4c1c0 loop: ranges of 16 or fewer are left for the
    insertion-sort tail; a zero depth falls back to heapsort;
    otherwise the median pivot is selected, the range is
    partitioned, the left half recurses and the right half is
    processed the same way (the binary tail-loops the right half;
    the model recurses, which orders the same way)."""
    while hi - lo > THRESHOLD:
        if depth == 0:
            heapsort(container, lo, hi, key, tiebreak)
            return
        depth -= 1
        median_to_first(container, lo, hi, key, tiebreak)
        cut = partition(container, lo, hi, key, tiebreak)
        introsort_loop(container, lo, cut, depth, key, tiebreak)
        lo = cut


def unguarded_linear_insert(container, index, key, tiebreak):
    """The 0x5d4b3f0 step: take the element at `index` and walk it
    down through the sorted prefix, shifting each larger element
    up one slot, until its place is found. The binary has no lower
    bound check: the caller (the insertion pass) only reaches this
    step when the element at lo is not greater than the value, so
    the walk stops at lo at the latest. The `hole > 0` guard here
    is a Python safety net that never triggers on that call path;
    it is not part of the pinned semantics."""
    value = container.slot(index)
    hole = index
    while hole > 0 and less_than(
            value, container.slot(hole - 1), key, tiebreak):
        container.store(hole, container.slot(hole - 1))
        hole -= 1
    container.store(hole, value)


def insertion_sort(container, lo, hi, key, tiebreak):
    """The 0x5d4ba10 pass (__insertion_sort): for each element
    past lo, if it is less than the element at lo the prefix is
    shifted right by one and it is stored at lo; otherwise the
    single-element insertion step finishes it."""
    for i in range(lo + 1, hi):
        if less_than(container.slot(i), container.slot(lo),
                     key, tiebreak):
            value = container.slot(i)
            for j in range(i, lo, -1):
                container.store(j, container.slot(j - 1))
            container.store(lo, value)
        else:
            unguarded_linear_insert(container, i, key, tiebreak)


def sort_entry(container, flag, key, tiebreak):
    """The 0x5d53470 entry: a nonzero flag byte or an empty range
    sorts nothing; otherwise the introsort loop runs with depth
    2 * floor(log2(n)), then the insertion-sort tail finishes the
    range (one pass when n <= 16, else a 16-element pass plus a
    linear insert per remaining element). Returns True when the
    sort ran."""
    count = len(container)
    if flag:
        return False
    if count == 0:
        return False
    introsort_loop(container, 0, count, depth_limit(count),
                   key, tiebreak)
    if count <= THRESHOLD:
        insertion_sort(container, 0, count, key, tiebreak)
    else:
        insertion_sort(container, 0, THRESHOLD, key, tiebreak)
        for i in range(THRESHOLD, count):
            unguarded_linear_insert(container, i, key, tiebreak)
    return True
