"""Model of node #115 routine 0x5d527a0 (FDE 0x5d527a0..0x5d52b60).

The routine drains a chunked source range into a std::deque-style
destination and then resets the source.  Everything here is pinned
to the disassembly in research/work-items/RE-001-drain-append-527a0-115/;
see that packet's README.md for the field map and the per-branch
derivation.  The model records an observable-effect trace instead of
touching real memory: allocation, chunk stores, map moves, frees and
throws are trace entries, in the order the routine produces them.

Source layout (holder at rsi):
  +0x148  base count (elements held inline before the heap range)
  +0x190  inline table, eight qword slots (elements 0..7)
  +0x198  heap begin pointer (elements 8..)
  +0x1a0  heap end pointer
  count = base + (heap_end - heap_begin) // 8
  element i = inline[i] for i < 8, heap[i - 8] for i >= 8

Destination layout (holder at rdi, deque at +0x1388):
  +0x1388 map (chunk-pointer array), +0x1390 map slot count
  +0x1398/+0x13a0/+0x13a8/+0x13b0 start iterator
  (current, first, last, node)
  +0x13b8/+0x13c0/+0x13c8/+0x13d0 finish iterator
  (current, first, last, node)
  chunks hold 64 qwords (0x200 bytes); a chunk's first slot is 0
  and its last slot is 64 in slot units.

Per element the routine calls the guard at 0x60d5390 with the member
at owner +0x700 (that callee is endbr64; ret only, so it changes
nothing observable), then appends the element to the deque.  When
the finish chunk has exactly one free slot left (finish slot 63)
the append takes the growth path: a fresh 0x200-byte chunk when the
map has a free slot after the finish node, otherwise a map
reallocation (recenter inside the map, or a new doubled map) and
then the chunk allocation.  A deque size of exactly
0xfffffffffffffff raises the length error.
"""

CHUNK_SLOTS = 64
CHUNK_BYTES = 0x200
MAX_SIZE = 0xFFFFFFFFFFFFFFF
GUARD = 0x60D5390
PLT_NEW = 0x63F0DD0
PLT_DELETE = 0x63F0D80
PLT_MEMMOVE = 0x63F0A70

INLINE_CAPACITY = 8


class LengthError_(ValueError):
    """__throw_length_error (PLT 0x63f0de0)."""


class BadArrayNewLength(ValueError):
    """__throw_bad_array_new_length (PLT 0x63f0ec0)."""


class BadAlloc(ValueError):
    """__throw_bad_alloc (PLT 0x63f0ed0)."""


class Source:
    """The drained range: eight inline slots, a heap tail, a base count."""

    def __init__(self, inline, heap, base):
        self.inline = list(inline)
        self.heap = list(heap)
        self.base = base

    def count(self):
        return self.base + len(self.heap)

    def element(self, i):
        if i < INLINE_CAPACITY:
            return self.inline[i]
        return self.heap[i - INLINE_CAPACITY]


class Deque:
    """A deque as the routine sees it: map slots, iterators in slot units.

    ``slots`` holds one chunk (a list of 64 values) or None per map
    slot.  ``start``/``finish`` are (node index, slot offset) pairs;
    slot offsets run 0..63 and a chunk's first/last are 0/64.
    """

    def __init__(self, slots, start, finish):
        self.slots = list(slots)
        self.start = tuple(start)
        self.finish = tuple(finish)

    @property
    def map_size(self):
        return len(self.slots)

    def size(self):
        """Element count, exactly as the routine computes it at 0x5d52890.

        (finish.node - start.node - 1) * 64 + finish slot used
        + start chunk remaining.
        """
        span = self.finish[0] - self.start[0]
        return ((span - 1) * CHUNK_SLOTS + self.finish[1]
                + (CHUNK_SLOTS - self.start[1]))


def _alloc_chunk(trace):
    trace.append(("alloc_chunk", PLT_NEW, CHUNK_BYTES))
    return [None] * CHUNK_SLOTS


def map_growth_slots(map_size):
    """New map slot count for the 0x5d52970 growth branch.

    Three slots when the map is empty; otherwise twice the map size
    plus two, with the routine's overflow throws when the count
    passes 0xfffffffffffffff.
    """
    if map_size == 0:
        return 3
    new_slots = 2 * (map_size + 1)
    if new_slots > MAX_SIZE:
        if (new_slots >> 61) == 0:
            raise BadAlloc("new map slots exceed the length limit")
        raise BadArrayNewLength("new map slots exceed the length limit")
    return new_slots


def _grow_map(trace, dq):
    """Map reallocation, the 0x5d52970 path.

    Returns the new start-node index.  Recenter when the map is more
    than twice the node span plus two; otherwise allocate a new map
    of 2 * (map_size + 1) slots (3 slots when the map is empty) and
    centre the node pointers in it.  Mirrors the routine's memmove
    and free exactly, including the overflow throws.
    """
    span = dq.finish[0] - dq.start[0]
    if 2 * (span + 2) < dq.map_size:
        new_start = (dq.map_size - span - 2) // 2
        moved = dq.slots[dq.start[0]:dq.finish[0] + 1]
        trace.append(("memmove_map", PLT_MEMMOVE, new_start,
                      dq.start[0], len(moved)))
        for i, chunk in enumerate(moved):
            dq.slots[new_start + i] = chunk
        for i in range(dq.start[0], new_start):
            dq.slots[i] = None
        for i in range(new_start + len(moved), dq.finish[0] + 1):
            dq.slots[i] = None
        return new_start
    if dq.map_size == 0:
        new_slots = 3
    else:
        new_slots = map_growth_slots(dq.map_size)
    trace.append(("alloc_map", PLT_NEW, new_slots * 8))
    new_start = (new_slots - span - 2) // 2
    new_map = [None] * new_slots
    moved = dq.slots[dq.start[0]:dq.finish[0] + 1]
    if len(moved) == 1:
        trace.append(("copy_one_pointer", dq.start[0], new_start))
    elif len(moved) > 1:
        trace.append(("memmove_map", PLT_MEMMOVE, new_start,
                      dq.start[0], len(moved)))
    for i, chunk in enumerate(moved):
        new_map[new_start + i] = chunk
    old_size = dq.map_size
    trace.append(("free_map", PLT_DELETE, old_size, old_size * 8))
    dq.slots = new_map
    return new_start


def _append_one(trace, dq, value):
    """One deque push, the fast path plus the 0x5d52890 growth path."""
    f_node, f_slot = dq.finish
    if f_slot == CHUNK_SLOTS - 1:
        # Growth: the element fills the last slot of the old chunk.
        if dq.size() == MAX_SIZE:
            raise LengthError_("deque size at the length limit")
        free_after = dq.map_size - f_node
        if free_after <= 1:
            new_start = _grow_map(trace, dq)
            shift = new_start - dq.start[0]
            dq.start = (dq.start[0] + shift, dq.start[1])
            dq.finish = (dq.finish[0] + shift, dq.finish[1])
            f_node, f_slot = dq.finish
        chunk = _alloc_chunk(trace)
        dq.slots[f_node + 1] = chunk
        trace.append(("store", f_node, f_slot, value))
        dq.slots[f_node][f_slot] = value
        dq.finish = (f_node + 1, 0)
        return
    trace.append(("store", f_node, f_slot, value))
    dq.slots[f_node][f_slot] = value
    dq.finish = (f_node, f_slot + 1)


def drain(owner_guard_target, dq, source):
    """Run the 0x5d527a0 drain; returns the observable-effect trace.

    ``owner_guard_target`` is the guard callee address the routine
    calls with owner +0x700 (0x60d5390 in the binary).  The trace
    records one ("guard", ...) entry per call: one at entry plus one
    per drained element.
    """
    trace = [("guard", owner_guard_target)]
    count = source.count()
    if count == 0:
        return trace
    for i in range(count):
        trace.append(("guard", owner_guard_target))
        _append_one(trace, dq, source.element(i))
    if source.base != 0:
        trace.append(("zero_base",))
        source.base = 0
    if source.heap:
        trace.append(("drain_heap",))
        source.heap = []
    return trace
