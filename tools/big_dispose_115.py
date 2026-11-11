"""Model of node #115's big-control _M_dispose 0x5f061b0.

Ground: research/work-items/RE-001-big-dispose-115/ (this
packet). All addresses are node #115 virtual addresses; the target
digest is a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

The pinned behaviour, end to end (the big control is the 0x48-byte
_Sp_counted_ptr_inplace<FragmentedRangeTombstoneListCache> block
built by the owner 0x5f103f0 in #3304: vtable 0x64cc718, counts
0x100000001, the 0x38-byte cache object at +0x10 zero-filled, no
constructor runs; the cache object's +0x28 field -- control+0x38
-- holds the 0xe8-byte heap state this dispose tears down):

  * Entry: rdi is the control. state = *(control+0x38). When
    state is null the dispose returns at once, freeing nothing.
  * The state holds an embedded clear object at +0x98 (0x40
    bytes: head fn +0x98, args +0xa0/+0xa8, chain head +0xb0,
    flag byte +0xb8, pair array begin/end/cap +0xc0/+0xc8/+0xd0)
    with exactly the layout the merged
    RE-001-sorted-unique-clear-50470-115 packet pins for the
    standalone routine 0x5d50470. The flag selects the path:
      - flag clear: skip the sort/unique/destroy/reset/virtual
        phases entirely; free the pair-array buffer when its
        begin is non-null, then drain the Cleanable at +0x98
        with 0x61bd0e0 (head fn + chain nodes).
      - flag set: clear the flag first, then sort the 0x10-byte
        pairs {arg, disposer} ascending by unsigned (first,
        second) with __introsort_loop 0x5f053d0 (depth limit
        2*floor(log2(count)), or the literal -2 left in the
        register when the byte count is below 16) followed by
        the final insertion sort (insertion sort 0x5f05120 over
        the whole range when it is at most 0x100 bytes, else
        over the first 0x100 bytes plus an inlined unguarded
        insertion tail for the rest); unique the sorted array
        (keep the first copy of each distinct pair, in order);
        dispose each kept pair once, in sorted order, by
        calling its disposer with its arg; abandon the
        duplicate copies beyond the new end (never disposed,
        storage freed with the buffer); set the array end back
        to begin; then the virtual phase: when the head fn is
        non-null, call it with (+0xa0, +0xa8) and walk the
        +0xb0 chain, calling each 0x20-byte node's fn with
        (node+0x08, node+0x10) and freeing the node with size
        0x20, then zero +0x98 and +0xb0. When the head fn is
        null, the chain is NOT walked: the nodes are abandoned
        under the zeroed pointer. The empty-range path still
        runs the virtual phase. After the virtual phase the
        pair-array buffer is freed, and the later 0x61bd0e0
        call at 0x5f0620a finds an empty head and returns at
        once (it is a no-op on this path only).
  * The Cleanable drain 0x61bd0e0(head): when *head is null it
    returns at once; otherwise it calls *head with (head+0x08,
    head+0x10), then walks the +0x18 chain, calling each
    node's fn with (node+0x08, node+0x10) and freeing the node
    with size 0x20. The head storage itself is never freed by
    the drain (it is freed with the state below). The init
    0x61bd0c0 zeroes +0x00 and +0x18 of a Cleanable.
  * The +0x80 std::list<std::string>: the sentinel lives at
    state+0x80 (next +0x80, prev +0x88). Each 0x30-byte node
    is {next +0x00, prev +0x08, string {ptr +0x10, size +0x18,
    buf +0x20}}; a heap string (ptr != &buf) has its buffer
    freed with _ZdlPvm(ptr, *(node+0x20)+1), then the node is
    freed with size 0x30. SSO strings free no buffer.
  * The +0x60 singly-linked list: each 0x28-byte node is
    {opaque +0x00, opaque +0x08, next +0x10, subtree +0x18};
    the node's +0x18 subtree is destroyed by 0x5f059b0 and the
    node itself is freed with size 0x28.
  * The tree destroy 0x5f059b0(node): a left-child/right-sibling
    destroy -- for each node in the +0x10 sibling chain it
    recursively destroys the +0x18 child subtree, frees the
    node with size 0x28, and advances to the next sibling.
    A null node destroys nothing.
  * Three vectors are freed with _ZdlPvm(begin, cap-begin):
    +0x00/+0x08/+0x10, +0x18/+0x20/+0x28 and +0x30/+0x38/+0x40
    (begin/end/cap each). A null begin frees nothing. Their
    element types are not touched by the dispose and are not
    modelled.
  * Finally the state itself is freed with _ZdlPvm(state, 0xe8)
    via a tail jump. The fields +0x48/+0x50/+0x58,
    +0x68/+0x70/+0x78 and +0xd8/+0xe0 are never read or written
    by the dispose; their roles are unknown.
  * The dispose is reached only through the big control's
    vtable slot 2 (RELATIVE record at 0x64cc728), via the
    destroy dispatch 0x5d35070 (merged ground, #3263/#3304);
    it has no direct callers. The small control's _M_dispose
    0x5f0a290 (#3304) is the contrast: it releases the big
    control it holds instead of tearing down a cache object.
  * The sort helpers are shared: __introsort_loop 0x5f053d0,
    __insertion_sort 0x5f05120 and the tree destroy 0x5f059b0
    are also called from the three sibling routines
    0x5f0a3d0..0x5f0a909, 0x5f0a9c0..0x5f0b04c and
    0x5f0b080..0x5f0b418 and from 0x5f10d40..0x5f11798 (see the
    packet census); __adjust_heap 0x5f04f80 is called only from
    the introsort fallback. The merged 0x5d50470 routine uses a
    different instantiation of the same sort shape
    (0x5d4a3f0/0x5d497e0); only the call sites are pinned there.

CORRECTION to #3304: its records named the neighbour typeinfo
at 0x64cc580 "rocksdb::MemTableIterator" with name_address
0x96e660. The name pointer is the RELATIVE record at 0x64cc588
-> 0x970970, whose string is N7rocksdb16MemTableIteratorE; the
0x96e660 string (N7rocksdb20InternalIteratorBaseINS_5SliceEEE)
is the name of its BASE typeinfo 0x64ca638 (RELATIVE record at
0x64ca640 -> 0x96e660). This packet records the neighbour
correctly; #3304 itself is not edited.
"""

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

BIG_DISPOSE = 0x5F061B0
BIG_DISPOSE_END = 0x5F06548
INTROSORT = 0x5F053D0
INTROSORT_END = 0x5F05678
INSERTION_SORT = 0x5F05120
INSERTION_SORT_END = 0x5F051F5
ADJUST_HEAP = 0x5F04F80
ADJUST_HEAP_END = 0x5F0511D
TREE_DESTROY = 0x5F059B0
TREE_DESTROY_END = 0x5F05B79
CLEANABLE_DRAIN = 0x61BD0E0
CLEANABLE_DRAIN_END = 0x61BD131
CLEANABLE_INIT = 0x61BD0C0
CLEANABLE_INIT_END = 0x61BD0D4
SORTED_UNIQUE_CLEAR = 0x5D50470     # merged RE-001-sorted-unique-clear-50470-115
SORTED_UNIQUE_INTROSORT = 0x5D4A3F0  # that routine's sort callees
SORTED_UNIQUE_INSERTION = 0x5D497E0

BIG_CONTROL_SIZE = 0x48
SMALL_CONTROL_SIZE = 0x20
BIG_CONTROL_VTABLE = 0x64CC718
SMALL_CONTROL_VTABLE = 0x64CC750
CONTROL_COUNTS = 0x100000001        # {use=1, weak=1} from .rodata 0x459b20
CACHE_OBJECT_SIZE = 0x38             # at big control +0x10
STATE_SIZE = 0xE8
STATE_PTR_OFF = 0x38                 # control+0x38 == cache object +0x28

# State layout (offsets within the 0xe8-byte heap state).
STATE_VEC1_BEGIN = 0x00
STATE_VEC1_END = 0x08
STATE_VEC1_CAP = 0x10
STATE_VEC2_BEGIN = 0x18
STATE_VEC2_END = 0x20
STATE_VEC2_CAP = 0x28
STATE_VEC3_BEGIN = 0x30
STATE_VEC3_END = 0x38
STATE_VEC3_CAP = 0x40
STATE_NODE_LIST = 0x60
STATE_STRING_LIST = 0x80             # sentinel node {next +0x80, prev +0x88}
STATE_CLEANABLE = 0x98               # {fn +0x98, arg1 +0xa0, arg2 +0xa8, next +0xb0}
STATE_CLEANABLE_ARG1 = 0xA0
STATE_CLEANABLE_ARG2 = 0xA8
STATE_CLEANABLE_NEXT = 0xB0
STATE_FLAG = 0xB8
STATE_PAIRS_BEGIN = 0xC0
STATE_PAIRS_END = 0xC8
STATE_PAIRS_CAP = 0xD0

PAIR_SIZE = 0x10
NODE_SIZE = 0x28                     # +0x60 list nodes and tree nodes
STRING_NODE_SIZE = 0x30              # std::list<std::string> nodes
CLEANABLE_NODE_SIZE = 0x20
INSERTION_THRESHOLD_BYTES = 0x100    # 16 pairs: introsort returns, insertion sort takes over
INTROSORT_SMALL_BYTES = 0x100        # __introsort_loop returns at once below this

BIG_TYPEINFO = 0x64CC598
SMALL_TYPEINFO = 0x64CC5B0
BASE_TYPEINFO = 0x64C81A8
NEIGHBOUR_TYPEINFO = 0x64CC580       # rocksdb::MemTableIterator
NEIGHBOUR_BASE_TYPEINFO = 0x64CA638  # rocksdb::InternalIteratorBase<rocksdb::Slice>

VTABLE_SLOTS = {
    BIG_CONTROL_VTABLE: {
        0x00: 0x5F04E30,  # slot 0: trivial complete dtor
        0x08: 0x5F04E50,  # slot 1: deleting dtor
        0x10: BIG_DISPOSE,  # slot 2: _M_dispose
        0x18: 0x5F04F70,  # slot 3: _M_destroy (frees 0x48)
        0x20: 0x5F057C0,  # slot 4: _M_get_deleter
    },
    SMALL_CONTROL_VTABLE: {
        0x00: 0x5F04E20,  # slot 0: trivial complete dtor
        0x08: 0x5F04E60,  # slot 1: deleting dtor
        0x10: 0x5F0A290,  # slot 2: _M_dispose (releases the big control)
        0x18: 0x5F04F60,  # slot 3: _M_destroy (frees 0x20)
        0x20: 0x5F05380,  # slot 4: _M_get_deleter
    },
}

TYPEINFO_POINTERS = {
    BIG_CONTROL_VTABLE: BIG_TYPEINFO,
    SMALL_CONTROL_VTABLE: SMALL_TYPEINFO,
}

TYPEINFO_NAME_POINTERS = {
    BIG_TYPEINFO: 0x9709A0,
    SMALL_TYPEINFO: 0x970A20,
    BASE_TYPEINFO: 0x96C540,
    NEIGHBOUR_TYPEINFO: 0x970970,
    NEIGHBOUR_BASE_TYPEINFO: 0x96E660,
}

TYPEINFO_BASE_POINTERS = {
    BIG_TYPEINFO: BASE_TYPEINFO,
    SMALL_TYPEINFO: BASE_TYPEINFO,
    NEIGHBOUR_TYPEINFO: NEIGHBOUR_BASE_TYPEINFO,
}

TYPEINFO_NAMES = {
    BIG_TYPEINFO: "St23_Sp_counted_ptr_inplaceIN7rocksdb33FragmentedRangeTombstoneListCacheESaIvELN9__gnu_cxx12_Lock_policyE2EE",
    SMALL_TYPEINFO: "St23_Sp_counted_ptr_inplaceIKSt10shared_ptrIN7rocksdb33FragmentedRangeTombstoneListCacheEESaIvELN9__gnu_cxx12_Lock_policyE2EE",
    BASE_TYPEINFO: "St16_Sp_counted_baseILN9__gnu_cxx12_Lock_policyE2EE",
    NEIGHBOUR_TYPEINFO: "N7rocksdb16MemTableIteratorE",
    NEIGHBOUR_BASE_TYPEINFO: "N7rocksdb20InternalIteratorBaseINS_5SliceEEE",
}


class Memory:
    """A flat byte-addressable stand-in for the target's memory,
    with allocation/free accounting so the tests can observe
    exactly which blocks the dispose frees, and with what size."""

    def __init__(self):
        self._bytes = {}
        self._next = 0x100000000
        self.freed = []          # [(address, size)] in free order
        self.live = {}           # address -> size for live blocks

    def alloc(self, size, addr=None):
        if addr is None:
            addr = self._next
            self._next += max(size, 0x1000)
        for i in range(size):
            self._bytes.setdefault(addr + i, 0)
        self.live[addr] = size
        return addr

    def free(self, addr, size):
        self.freed.append((addr, size))
        self.live.pop(addr, None)

    def write_qword(self, addr, value):
        for i in range(8):
            self._bytes[addr + i] = (value >> (8 * i)) & 0xFF

    def write_u16(self, addr, value):
        self._bytes[addr] = value & 0xFF
        self._bytes[addr + 1] = (value >> 8) & 0xFF

    def write_u32(self, addr, value):
        for i in range(4):
            self._bytes[addr + i] = (value >> (8 * i)) & 0xFF

    def write_byte(self, addr, value):
        self._bytes[addr] = value & 0xFF

    def write_bytes(self, addr, blob):
        for i, byte in enumerate(blob):
            self._bytes[addr + i] = byte

    def read_qword(self, addr):
        return sum(self._bytes.get(addr + i, 0) << (8 * i) for i in range(8))

    def read_u16(self, addr):
        return self._bytes.get(addr, 0) | (self._bytes.get(addr + 1, 0) << 8)

    def read_u32(self, addr):
        return sum(self._bytes.get(addr + i, 0) << (8 * i) for i in range(4))

    def read_byte(self, addr):
        return self._bytes.get(addr, 0)

    def read_bytes(self, addr, size):
        return bytes(self._bytes.get(addr + i, 0) for i in range(size))


def pair_less(a, b):
    """Lexicographic unsigned comparison of two 16-byte pairs
    (arg, disposer): first qwords, then second qwords. This is
    the comparison the sort helpers use (insertion sort 0x5f05120,
    introsort 0x5f053d0, adjust-heap 0x5f04f80)."""
    if a[0] != b[0]:
        return a[0] < b[0]
    return a[1] < b[1]


def depth_limit(count):
    """The introsort depth limit 0x5f061b0 computes before calling
    0x5f053d0: 2*floor(log2(count)) for count >= 1, or the literal
    -2 left in the register when the byte count is below 16
    (count == 0)."""
    if count == 0:
        return -2
    return 2 * (count.bit_length() - 1)


def insertion_sort(pairs, first=0, last=None):
    """__insertion_sort 0x5f05120 over pairs[first:last] in place:
    each element is shifted left over larger predecessors until
    its slot is found; an element already >= its predecessor
    does not move. Sorts ascending by pair_less."""
    if last is None:
        last = len(pairs)
    for i in range(first + 1, last):
        value = pairs[i]
        j = i - 1
        while j >= first and pair_less(value, pairs[j]):
            pairs[j + 1] = pairs[j]
            j -= 1
        pairs[j + 1] = value
    return pairs


def adjust_heap(pairs, first, hole, length, value):
    """__adjust_heap 0x5f04f80(first, hole, length, value): sift
    the hole down a max-heap over pair_less (the larger child
    moves up; when the length is even the single last child is
    handled by the odd tail), then sift the value up from the
    hole while it is greater than its parent. `hole` and
    `length` are relative to `first`; only indices below
    first+length are touched."""
    top = hole
    second_child = 2 * hole + 2
    while second_child < length:
        # Pick the larger child: first child is at second-1.
        if pair_less(pairs[first + second_child],
                     pairs[first + second_child - 1]):
            second_child -= 1
        pairs[first + hole] = pairs[first + second_child]
        hole = second_child
        second_child = 2 * (second_child + 1)
    if second_child == length:
        pairs[first + hole] = pairs[first + second_child - 1]
        hole = second_child - 1
    # Sift the value up from the hole.
    while hole > top:
        parent = (hole - 1) // 2
        if not pair_less(pairs[first + parent], value):
            break
        pairs[first + hole] = pairs[first + parent]
        hole = parent
    pairs[first + hole] = value
    return pairs


def _make_heap(pairs, first, last):
    """The introsort depth-0 fallback's first half: build a
    max-heap by adjusting every parent from (n-2)/2 down to 0."""
    n = last - first
    for start in range((n - 2) // 2, -1, -1):
        adjust_heap(pairs, first, start, n, pairs[first + start])
    return pairs


def _sort_heap(pairs, first, last):
    """The fallback's second half: repeatedly swap the heap top
    with the last element and re-adjust the shrunk heap."""
    n = last - first
    for end in range(n - 1, 0, -1):
        pairs[first], pairs[first + end] = pairs[first + end], pairs[first]
        adjust_heap(pairs, first, 0, end, pairs[first])
    return pairs


def _median_to_first(pairs, first, mid, last):
    """__move_median_to_first: order the three candidates
    (first+1, mid, last-1) so the median lands at `first`.
    The binary compares first+1, mid and last-1 and swaps the
    median into the first slot; the other two keep their order
    relative to the median (the exact swap pattern is in the
    excerpt; the observable effect is the median at first)."""
    a = pairs[first + 1]
    b = pairs[mid]
    c = pairs[last - 1]
    median = sorted([a, b, c], key=lambda p: (p[0], p[1]))[1]
    if median == a:
        pairs[first], pairs[first + 1] = pairs[first + 1], pairs[first]
    elif median == b:
        pairs[first], pairs[mid] = pairs[mid], pairs[first]
    else:
        pairs[first], pairs[last - 1] = pairs[last - 1], pairs[first]
    return pairs


def _unguarded_partition(pairs, first, last, pivot):
    """__unguarded_partition(first+1, last, pivot): Hoare
    partition -- scan from the left while < pivot, from the
    right while > pivot, swap the out-of-place pair, repeat
    until the scans meet; returns the cut index."""
    lo = first + 1
    hi = last - 1
    while True:
        while pair_less(pairs[lo], pivot):
            lo += 1
        while pair_less(pivot, pairs[hi]):
            hi -= 1
        if lo >= hi:
            return lo
        pairs[lo], pairs[hi] = pairs[hi], pairs[lo]
        lo += 1


def introsort_loop(pairs, first=0, last=None, depth=None):
    """__introsort_loop 0x5f053d0(first, last, depth) over
    pairs[first:last] in place. Ranges of at most 16 pairs
    return at once (the final insertion sort finishes them); a
    zero depth falls back to make-heap + sort-heap; otherwise
    the median of (first+1, middle, last-1) is moved to first,
    the range is partitioned around it, the right part is
    recursed on with depth-1 and the left part is looped on."""
    if last is None:
        last = len(pairs)
    if depth is None:
        depth = depth_limit(last - first)
    while last - first > 16:
        if depth == 0:
            _make_heap(pairs, first, last)
            _sort_heap(pairs, first, last)
            return pairs
        depth -= 1
        mid = first + (last - first) // 2
        _median_to_first(pairs, first, mid, last)
        pivot = pairs[first]
        cut = _unguarded_partition(pairs, first, last, pivot)
        introsort_loop(pairs, cut, last, depth)
        last = cut
    return pairs


def final_insertion_sort(pairs, first=0, last=None):
    """The dispose's final insertion sort after introsort_loop:
    byte count at most 0x100 sorts the whole range with
    __insertion_sort 0x5f05120; otherwise the first 0x100 bytes
    (16 pairs) are insertion-sorted and the rest are inserted
    one by one by the inlined unguarded tail (which has no
    lower-bound check -- it relies on the introsort partition
    having left a sentinel; the observable result is a fully
    sorted array, which this model produces with the bounded
    walk)."""
    if last is None:
        last = len(pairs)
    if (last - first) * PAIR_SIZE <= INSERTION_THRESHOLD_BYTES:
        return insertion_sort(pairs, first, last)
    insertion_sort(pairs, first, first + 16)
    for i in range(first + 16, last):
        value = pairs[i]
        j = i - 1
        while j >= first and pair_less(value, pairs[j]):
            pairs[j + 1] = pairs[j]
            j -= 1
        pairs[j + 1] = value
    return pairs


def sort_pairs(pairs):
    """The dispose's whole sort phase for the pair array:
    __introsort_loop with the computed depth limit, then the
    final insertion sort. Returns the sorted list."""
    depth = depth_limit(len(pairs))
    introsort_loop(pairs, 0, len(pairs), depth)
    final_insertion_sort(pairs, 0, len(pairs))
    return pairs


def unique_pairs(pairs):
    """std::unique over the sorted pairs: keep the first copy of
    each distinct pair, in order. (The binary compacts the kept
    pairs to the front; the duplicates beyond the new end are
    never disposed.)"""
    kept = []
    for pair in pairs:
        if not kept or kept[-1] != pair:
            kept.append(pair)
    return kept


def cleanable_init(mem, addr):
    """Cleanable init 0x61bd0c0: zeroes the head fn (+0x00) and
    the chain head (+0x18)."""
    mem.write_qword(addr, 0)
    mem.write_qword(addr + 0x18, 0)


def cleanable_drain(mem, addr, fns, trace):
    """Cleanable drain 0x61bd0e0(head): when *head is null it
    returns at once; otherwise it calls *head with (head+0x08,
    head+0x10), then walks the +0x18 chain, calling each node's
    fn with (node+0x08, node+0x10) and freeing the node with
    size 0x20. The head storage itself is never freed here.
    `fns` maps function addresses to callables; `trace` records
    calls and frees."""
    fn = mem.read_qword(addr)
    if fn == 0:
        trace["cleanable_drain_noop"] += 1
        return
    fns[fn](mem.read_qword(addr + 0x08), mem.read_qword(addr + 0x10))
    trace["cleanable_calls"].append((fn, mem.read_qword(addr + 0x08),
                                     mem.read_qword(addr + 0x10)))
    node = mem.read_qword(addr + 0x18)
    while node != 0:
        node_fn = mem.read_qword(node)
        arg1 = mem.read_qword(node + 0x08)
        arg2 = mem.read_qword(node + 0x10)
        nxt = mem.read_qword(node + 0x18)
        fns[node_fn](arg1, arg2)
        trace["cleanable_calls"].append((node_fn, arg1, arg2))
        mem.free(node, CLEANABLE_NODE_SIZE)
        trace["freed"].append((node, CLEANABLE_NODE_SIZE))
        node = nxt


def tree_destroy(mem, node, trace):
    """Tree destroy 0x5f059b0(node): for each node in the +0x10
    sibling chain, recursively destroy its +0x18 child subtree,
    free the node with size 0x28, and advance to the next
    sibling. A null node destroys nothing."""
    while node != 0:
        tree_destroy(mem, mem.read_qword(node + 0x18), trace)
        nxt = mem.read_qword(node + 0x10)
        mem.free(node, NODE_SIZE)
        trace["freed"].append((node, NODE_SIZE))
        trace["tree_frees"].append(node)
        node = nxt


def _free_vector(mem, state, begin_off, cap_off, trace):
    """Free one vector triple (begin, end, cap) with
    _ZdlPvm(begin, cap-begin); a null begin frees nothing."""
    begin = mem.read_qword(state + begin_off)
    if begin == 0:
        return
    cap = mem.read_qword(state + cap_off)
    mem.free(begin, cap - begin)
    trace["freed"].append((begin, cap - begin))


def _clear_embedded(mem, state, fns, trace):
    """The embedded clear object at state+0x98 (same layout as
    the merged 0x5d50470 routine): flag gate, sort/unique/
    destroy of the pair array, reset of the array end, and the
    virtual phase (head call + chain walk). Returns the list of
    pairs whose disposers were called, in call order."""
    flag = mem.read_byte(state + STATE_FLAG)
    begin = mem.read_qword(state + STATE_PAIRS_BEGIN)
    end = mem.read_qword(state + STATE_PAIRS_END)
    cap = mem.read_qword(state + STATE_PAIRS_CAP)
    if flag == 0:
        # Flag-clear path: free the buffer when non-null, then
        # drain the Cleanable; head/chain are left untouched.
        if begin != 0:
            mem.free(begin, cap - begin)
            trace["freed"].append((begin, cap - begin))
        cleanable_drain(mem, state + STATE_CLEANABLE, fns, trace)
        return []
    mem.write_byte(state + STATE_FLAG, 0)
    pairs = []
    if begin != end:
        count = (end - begin) // PAIR_SIZE
        for i in range(count):
            arg = mem.read_qword(begin + i * PAIR_SIZE)
            fn = mem.read_qword(begin + i * PAIR_SIZE + 0x08)
            pairs.append((arg, fn))
        sort_pairs(pairs)
        kept = unique_pairs(pairs)
        trace["pairs_sorted"] = list(pairs)
        trace["pairs_kept"] = list(kept)
        for arg, fn in kept:
            fns[fn](arg)
            trace["disposer_calls"].append((arg, fn))
    # Reset: the array end is set back to begin.
    mem.write_qword(state + STATE_PAIRS_END, begin)
    # Virtual phase: head call, then the chain walk -- but a
    # null head abandons the chain entirely.
    head_fn = mem.read_qword(state + STATE_CLEANABLE)
    if head_fn != 0:
        arg1 = mem.read_qword(state + STATE_CLEANABLE_ARG1)
        arg2 = mem.read_qword(state + STATE_CLEANABLE_ARG2)
        fns[head_fn](arg1, arg2)
        trace["cleanable_calls"].append((head_fn, arg1, arg2))
        node = mem.read_qword(state + STATE_CLEANABLE_NEXT)
        while node != 0:
            node_fn = mem.read_qword(node)
            narg1 = mem.read_qword(node + 0x08)
            narg2 = mem.read_qword(node + 0x10)
            nxt = mem.read_qword(node + 0x18)
            fns[node_fn](narg1, narg2)
            trace["cleanable_calls"].append((node_fn, narg1, narg2))
            mem.free(node, CLEANABLE_NODE_SIZE)
            trace["freed"].append((node, CLEANABLE_NODE_SIZE))
            node = nxt
    else:
        trace["chain_abandoned"] = mem.read_qword(state + STATE_CLEANABLE_NEXT) != 0
    mem.write_qword(state + STATE_CLEANABLE, 0)
    mem.write_qword(state + STATE_CLEANABLE_NEXT, 0)
    # The pair-array buffer is freed (begin may be null).
    if begin != 0:
        mem.free(begin, cap - begin)
        trace["freed"].append((begin, cap - begin))
    # The later 0x61bd0e0 call finds the zeroed head: no-op.
    cleanable_drain(mem, state + STATE_CLEANABLE, fns, trace)
    return trace["disposer_calls"]


def big_dispose(mem, control, fns):
    """The big control's _M_dispose 0x5f061b0. `control` is the
    address of the 0x48-byte control block; `fns` maps function
    addresses to callables for every indirect call the dispose
    can make (pair disposers, Cleanable fns). Returns a trace
    dict: freed [(address, size)] in order, disposer_calls,
    cleanable_calls, tree_frees, and flags."""
    trace = {"freed": [], "disposer_calls": [], "cleanable_calls": [],
             "tree_frees": [], "pairs_sorted": [], "pairs_kept": [],
             "cleanable_drain_noop": 0, "chain_abandoned": False,
             "state_null": False}
    state = mem.read_qword(control + STATE_PTR_OFF)
    if state == 0:
        trace["state_null"] = True
        return trace
    _clear_embedded(mem, state, fns, trace)
    # The +0x80 std::list<std::string>: sentinel at state+0x80.
    sentinel = state + STATE_STRING_LIST
    node = mem.read_qword(sentinel)
    while node != sentinel:
        ptr = mem.read_qword(node + 0x10)
        nxt = mem.read_qword(node)
        if ptr != node + 0x20:
            # Heap string: free (ptr, *(node+0x20)+1).
            size = mem.read_qword(node + 0x20) + 1
            mem.free(ptr, size)
            trace["freed"].append((ptr, size))
        mem.free(node, STRING_NODE_SIZE)
        trace["freed"].append((node, STRING_NODE_SIZE))
        node = nxt
    # The +0x60 singly-linked list of 0x28-byte nodes.
    node = mem.read_qword(state + STATE_NODE_LIST)
    while node != 0:
        tree_destroy(mem, mem.read_qword(node + 0x18), trace)
        nxt = mem.read_qword(node + 0x10)
        mem.free(node, NODE_SIZE)
        trace["freed"].append((node, NODE_SIZE))
        node = nxt
    # The three vectors, in +0x30, +0x18, +0x00 order.
    _free_vector(mem, state, STATE_VEC3_BEGIN, STATE_VEC3_CAP, trace)
    _free_vector(mem, state, STATE_VEC2_BEGIN, STATE_VEC2_CAP, trace)
    _free_vector(mem, state, STATE_VEC1_BEGIN, STATE_VEC1_CAP, trace)
    # The state itself, freed with size 0xe8 (tail jump).
    mem.free(state, STATE_SIZE)
    trace["freed"].append((state, STATE_SIZE))
    return trace
