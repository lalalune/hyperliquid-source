"""Python model for node #115 fragmented-range-tombstone construction.

RE-001 work item: MemTable::ConstructFragmentedRangeTombstones
(0x5f0a3d0). The model pins the observable behaviour of the host, the
ReadOptions default construction, the std::sort machinery that sorts
and deduplicates the old cache index, and the old-cache teardown.
The cache ctor (0x5f37410) and its FragmentTombstones finalize
(0x5f36c70) are modelled by contract only: the model takes the
fragmented result as an input, exactly as the host takes it from the
cache ctor. Nothing here claims the repo gates; run the packet's
verify.py and the tests in tests/test_fragmented_range_tombstones_115.py.
"""

# --- ReadOptions default construction (0x60b21f0) -----------------------
# Exact byte-level init map, offset -> (size_in_bytes, value). The
# per-field source names are open (see records.json unknowns); the
# values below are the pinned observations.
READOPTS_INIT = [
    (0x00, 16, 0),
    (0x10, 8, 0),
    (0x18, 16, 0),
    (0x28, 4, 0),
    (0x2C, 8, 0x101),
    (0x34, 2, 0),
    (0x38, 16, 0),
    (0x48, 8, 0),
    (0x50, 8, 0),
    (0x58, 16, 0),
    (0x68, 16, 0),
    (0x78, 8, -1),
    (0x80, 1, 0),
    (0x84, 4, 4),
    (0x88, 2, 0x0100),
]
READOPTS_SPAN = 0x8A


def default_readopts():
    """The ReadOptions temp as the ctor leaves it: offset -> value.

    Multi-byte fields are returned as the integer the ctor stores
    (little-endian); +0x2c is 0x101 (bytes 01 01), +0x78 is -1
    (all-bits-one), +0x88 is 0x0100.
    """
    out = {}
    for off, _size, value in READOPTS_INIT:
        out[off] = value
    return out


def readopts_slot_48_callable(opts):
    """The host's indirect call through the temp's +0x48 slot.

    The ctor zeroes +0x48 and no store in the host flow rewrites it,
    so the slot is always null here and the call never fires.
    """
    return opts.get(0x48, 0) != 0


# --- 16-byte index entries and the (first, second) order ----------------
# Entries are (first, second) unsigned qword pairs. In the teardown
# the pair is (arg, fn-id); the sort compares the raw qwords.

def compare_entry(a, b):
    """Lexicographic unsigned order on (first, second); -1/0/1."""
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    if a[1] != b[1]:
        return -1 if a[1] < b[1] else 1
    return 0


def _less(a, b):
    return compare_entry(a, b) < 0


# --- std::__insertion_sort (0x5f05120) -----------------------------------

def insertion_sort(entries):
    """Faithful insertion sort over 16-byte entries (in place)."""
    entries = list(entries)
    for i in range(1, len(entries)):
        value = entries[i]
        j = i - 1
        while j >= 0 and _less(value, entries[j]):
            entries[j + 1] = entries[j]
            j -= 1
        entries[j + 1] = value
    return entries


# --- std::__adjust_heap (0x5f04f80) --------------------------------------
# adjust_heap(first, hole, length, value): sift the hole down by
# moving the larger child up, then sift the value back up.

def adjust_heap(entries, hole, length, value):
    """Faithful __adjust_heap over 16-byte entries (in place)."""
    entries = list(entries)
    top = hole
    child = hole
    # Sift down while the hole has two children: (len-1)/2 bound.
    while child < (length - 1) // 2:
        child = 2 * (child + 1)
        if _less(entries[child], entries[child - 1]):
            child -= 1
        entries[hole] = entries[child]
        hole = child
    # Even length with a single last child.
    if length % 2 == 0 and child == (length - 2) // 2:
        child = 2 * (child + 1)
        entries[hole] = entries[child - 1]
        hole = child - 1
    # Sift the value back up (__push_heap from the hole to the top).
    while hole > top:
        parent = (hole - 1) // 2
        if not _less(entries[parent], value):
            break
        entries[hole] = entries[parent]
        hole = parent
    entries[hole] = value
    return entries


def make_heap(entries):
    """__make_heap: adjust_heap from parent (n-2)/2 down to 0."""
    entries = list(entries)
    n = len(entries)
    if n <= 1:
        return entries
    parent = (n - 2) // 2
    while True:
        entries = adjust_heap(entries, parent, n, entries[parent])
        if parent == 0:
            break
        parent -= 1
    return entries


def sort_heap(entries):
    """__sort_heap: move the max to the end, re-heap the rest."""
    entries = list(entries)
    n = len(entries)
    while n > 1:
        entries[0], entries[n - 1] = entries[n - 1], entries[0]
        n -= 1
        entries = adjust_heap(entries, 0, n, entries[0])
    return entries


# --- std::__introsort_loop (0x5f053d0) ------------------------------------
# depth limit 2*floor(log2(n)); ranges of <= 16 entries are left for
# the caller's insertion sort.

def depth_limit(n):
    """The host's depth computation: -2 when n == 0, else 2*bsr(n)."""
    if n == 0:
        return -2
    return 2 * (n.bit_length() - 1)


def _median_of_three(entries, a, b, c):
    """Median of entries[a], entries[b], entries[c] by the order."""
    x, y, z = entries[a], entries[b], entries[c]
    if _less(x, y):
        if _less(y, z):
            return y
        if _less(x, z):
            return z
        return x
    if _less(x, z):
        return x
    if _less(y, z):
        return z
    return y


def _unguarded_partition(entries, first, last, pivot):
    """libstdc++ __unguarded_partition over [first, last)."""
    entries = list(entries)
    i, j = first, last
    while True:
        while _less(entries[i], pivot):
            i += 1
        j -= 1
        while _less(pivot, entries[j]):
            j -= 1
        if not (i < j):
            return i
        entries[i], entries[j] = entries[j], entries[i]
        i += 1
    return i


def introsort_loop(entries, depth):
    """Faithful __introsort_loop over 16-byte entries (in place)."""
    entries = list(entries)
    first, last = 0, len(entries)
    while last - first > 16:
        if depth == 0:
            head = entries[:first]
            tail = sort_heap(make_heap(entries[first:last]))
            return head + tail + entries[last:]
        depth -= 1
        mid = first + (last - first) // 2
        pivot = _median_of_three(entries, first, mid, last - 1)
        cut = _unguarded_partition(entries, first, last, pivot)
        entries = introsort_loop_range(entries, cut, last, depth)
        last = cut
    return entries


def introsort_loop_range(entries, first, last, depth):
    """__introsort_loop restricted to [first, last) (recursion)."""
    sub = introsort_loop(entries[first:last], depth)
    return entries[:first] + sub + entries[last:]


def final_insertion_sort(entries):
    """__final_insertion_sort as the host inlines it.

    Ranges over 16 entries: insertion-sort the first 16, then an
    unguarded insertion loop for the rest; otherwise insertion-sort
    the whole range.
    """
    entries = list(entries)
    if len(entries) > 16:
        head = insertion_sort(entries[:16])
        rest = head + entries[16:]
        for i in range(16, len(rest)):
            value = rest[i]
            j = i - 1
            # Guarded here (the binary's unguarded loop relies on the
            # introsort partition invariant; the guard cannot change
            # the result, only protect the model from running past
            # the start on an input that violates it).
            while j >= 0 and _less(value, rest[j]):
                rest[j + 1] = rest[j]
                j -= 1
            rest[j + 1] = value
        return rest
    return insertion_sort(entries)


def sort_index(entries):
    """The host's sort sequence: __introsort_loop, then final insertion sort."""
    return final_insertion_sort(
        introsort_loop(list(entries), depth_limit(len(entries))))


# --- adjacent-duplicate compaction (host, inlined at 0x5f0a823) ----------

def dedup_sorted(entries):
    """Compact adjacent duplicates in a sorted list (keep the first)."""
    out = []
    for e in entries:
        if not out or compare_entry(out[-1], e) != 0:
            out.append(e)
    return out


# --- Cleanable (0x61bd0c0 ctor / 0x61bd0e0 DoCleanup) ---------------------

class Cleanable:
    """A Cleanable: head fn + arg1/arg2, plus a chain of 0x20-byte nodes."""

    def __init__(self):
        self.fn = None
        self.arg1 = None
        self.arg2 = None
        self.chain = []  # list of (fn, arg1, arg2), in link order

    def do_cleanup(self, trace):
        """DoCleanup: run the head fn, then each chain node's fn."""
        if self.fn is not None:
            trace.append(("head", self.fn, self.arg1, self.arg2))
            self.fn(self.arg1, self.arg2)
        for fn, arg1, arg2 in self.chain:
            trace.append(("chain", fn, arg1, arg2))
            fn(arg1, arg2)
        self.fn = None
        self.arg1 = None
        self.arg2 = None
        self.chain = []


# --- node-tree release (0x5f059b0) ----------------------------------------

def release_tree(node, trace):
    """Recursively release a tree of 0x28-byte nodes.

    node is None or {"child": ..., "sibling": ...}; the order is
    child first, then the node, then the sibling.
    """
    if node is None:
        return
    release_tree(node.get("child"), trace)
    trace.append(("node", node.get("name")))
    release_tree(node.get("sibling"), trace)


# --- the 0xe8-byte FragmentedRangeTombstoneListCache ----------------------

class TombstoneCache:
    """The cache object: index vector, ready flag, Cleanable, node lists."""

    def __init__(self, index_entries=None, ready=False):
        self.index = list(index_entries or [])  # (arg, fn-id) pairs
        self.ready = ready  # +0xb8 flag byte
        self.cleanable = Cleanable()  # +0x98
        self.nodes_80 = []  # +0x80 list of 0x30-byte nodes (names)
        self.tree_60 = None  # +0x60 list head (0x28-byte node tree)
        self.buffers = {"+0x00": None, "+0x18": None, "+0x30": None}

    def teardown(self, fn_registry, trace):
        """The old-cache teardown exactly as the host runs it.

        fn_registry maps fn-id -> callable. trace records each
        observable step in order.
        """
        if self.ready:
            trace.append("ready_sort")
            self.index = dedup_sorted(sort_index(self.index))
            trace.append("ready_dedup")
            for arg, fn_id in self.index:
                fn = fn_registry[fn_id]
                trace.append(("entry_dtor", arg, fn_id))
                fn(arg)
            # Head cleanup, then the +0xb0 chain, then zero both.
            if self.cleanable.fn is not None:
                trace.append(("head", self.cleanable.fn,
                              self.cleanable.arg1, self.cleanable.arg2))
                self.cleanable.fn(self.cleanable.arg1, self.cleanable.arg2)
            for fn, arg1, arg2 in self.cleanable.chain:
                trace.append(("chain", fn, arg1, arg2))
                fn(arg1, arg2)
            self.cleanable.fn = None
            self.cleanable.arg1 = None
            self.cleanable.arg2 = None
            self.cleanable.chain = []
            trace.append("zero_98_b0")
        # Common tail.
        if self.index is not None:
            trace.append("free_index_array")
        self.cleanable.do_cleanup(trace)  # no-op after the ready path zeroed it
        for name in self.nodes_80:
            trace.append(("free_node_80", name))
        release_tree(self.tree_60, trace)
        for slot in ("+0x30", "+0x18", "+0x00"):
            if self.buffers[slot] is not None:
                trace.append(("free_buffer", slot))
        trace.append("delete_cache")


# --- the 0x80-byte temp iterator (MemTableIterator) -----------------------

def build_iterator(owner, rep_iterator):
    """The host's field-wise temp-iterator build.

    owner: dict with the MemTable fields the host copies
    (+0x10, +0x31, +0x60, +0x6c, +0xa58, +0xc58). rep_iterator is
    the (owner+0xa58)->vtable slot 0x90 result, by contract.
    """
    return {
        "+0x00": "vtable 0x64cc648 (rocksdb::MemTableIterator)",
        "+0x08": Cleanable(),
        "+0x28": 0,
        "+0x30": owner["+0xc58"],
        "+0x38": "vtable 0x64cc610 (rocksdb::MemTable::KeyComparator)",
        "+0x40": "vtable 0x64c8ff8 (rocksdb::InternalKeyComparator)",
        "+0x48": owner["+0x10"],
        "+0x50": rep_iterator,
        "+0x58": 0,
        "+0x5a": owner["+0x31"] ^ 1,
        "+0x60": owner["+0x6c"],
        "+0x68": 0,
        "+0x6c": 0,
        "+0x70": 0,
        "+0x78": owner["+0x60"],
    }


# --- the host state machine (0x5f0a3d0) ------------------------------------

class Owner:
    """A MemTable owner: the flag, the cache slot, and the copied fields."""

    def __init__(self, fields, already_built=False, old_cache=None):
        self.fields = fields  # owner field map for build_iterator
        self.already_built = already_built  # +0xa60 flag byte
        self.cache = old_cache  # owner+0xce0 slot


def construct_fragmented_range_tombstones(owner, build_cache, fn_registry):
    """The host end to end. Returns (trace, new_cache_or_None).

    build_cache(iterator) is the cache-ctor contract: it returns a
    fresh TombstoneCache built from the temp iterator. fn_registry
    maps fn-ids to callables for the teardown.
    """
    trace = []
    if owner.already_built:
        trace.append("early_return")
        return trace, None
    opts = default_readopts()
    if readopts_slot_48_callable(opts):
        trace.append("readopts_callback")
    iterator = build_iterator(owner.fields, rep_iterator="rep_iter")
    trace.append("build_iterator")
    new_cache = build_cache(iterator)
    trace.append("build_cache")
    old = owner.cache
    owner.cache = new_cache
    trace.append("install_cache")
    if old is not None:
        old.teardown(fn_registry, trace)
    trace.append("destroy_iterator")
    trace.append("free_scratch")
    return trace, new_cache
