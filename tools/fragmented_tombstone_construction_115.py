"""Model of node #115 FragmentedRangeTombstoneIterator construction paths.

Pinned from the node #115 binary (SHA-256 a6e2897c...; see
research/work-items/RE-001-fragmented-tombstone-construction-115/):
the three constructors of the 0xc8-byte iterator, the per-caller
arg6, SplitBySnapshot with its list probe and once-initializer, and
the TruncatedRangeDelIterator consumer that re-wraps the split map.

Constructors (vendor symbols in research/catalogue/byte-coverage.json):
- ctor A 0x5f31380: C1(FragmentedRangeTombstoneList*, icmp, seq, slice, arg6)
- ctor List 0x5f31470: C1(shared_ptr<FragmentedRangeTombstoneList>, ...)
- ctor Cache 0x5f315a0: C1(shared_ptr<FragmentedRangeTombstoneListCache>, ...)
All take (this, list-or-shared_ptr, icmp, seq, upper_bound slice, arg6)
in (rdi, rsi, rdx, rcx, r8, r9). The List struct is 0xe8 bytes (built
by 0x5f37410); the Cache struct carries its embedded List* at +0x28.

Field map of the 0xc8 iterator (from #3674/#3900, corrected here):
+0x00 vtable 0x64ccae0+0x10; +0x08 Cleanable; +0x28/+0x30 icmp+0x8;
+0x38 icmp; +0x40 icmp+0x8; +0x48/+0x50 List holder (ctor List only);
+0x58/+0x60 Cache holder (ctor Cache only); +0x68 list/cache+0x28;
+0x70 read seq; +0x78 arg6; +0x80 upper_bound; +0x88/+0x98 frag ptr;
+0x90/+0xa0 seq ptr; +0xa8 cached-key string (inline buffer at +0xb8).
"""

# --- layout constants -------------------------------------------------------
ITERATOR_SIZE = 0xC8
LIST_SIZE = 0xE8
TRUNCATED_SIZE = 0x48
VTABLE = 0x64CCAF0  # 0x64ccae0+0x10
VTABLE_START = 0x64CCAE0
GLOBAL_ATOMICITY_SELECTOR = 0x64ED290  # byte: 0 -> lock addl, else plain addl
PACKED_COUNTS = 0x100000001  # use_count 1 + weak_count 1 packed

# Offsets within the iterator.
OFF_VTABLE = 0x00
OFF_LIST_HOLDER_PTR = 0x48
OFF_LIST_HOLDER_CTRL = 0x50
OFF_CACHE_HOLDER_PTR = 0x58
OFF_CACHE_HOLDER_CTRL = 0x60
OFF_LIST_PTR = 0x68
OFF_READ_SEQ = 0x70
OFF_ARG6 = 0x78
OFF_UPPER_BOUND = 0x80
OFF_FRAG = 0x88
OFF_SEQ = 0x90

# Offsets within the List (0xe8) and Cache structs.
LIST_FRAG_END = 0x08    # iterator +0x88/+0x98 copy this
LIST_SEQ_BASE = 0x18    # iterator +0x90/+0xa0 copy this (ctor A / List)
CACHE_SEQ_BASE = 0x20   # iterator +0x90/+0xa0 copy this (ctor Cache)
CACHE_LIST_PTR = 0x28   # iterator +0x68 copies this (ctor Cache)
LIST_ONCE_FLAG = 0x48  # pthread_once_t for the seqnum index
LIST_INDEX_HEADER = 0x58  # _Rb_tree header (sentinel); root at +0x60
LIST_INDEX_COUNT = 0x78

MAX_SEQNUM = 0xFFFFFFFFFFFFFFFF  # kMaxSequenceNumber: -1 as u64


class SharedPtr:
    """A std::shared_ptr {ptr, ctrl} with packed use/weak counts.

    The copy in the ctors bumps the use count at ctrl+0x8: `lock addl`
    when the global byte at 0x64ed290 is 0, else a plain `addl`
    (the _Sp_locker rule, same as #3674). Release (_M_release
    0x5d350c0) disposes when the packed counts are 0x100000001
    (use 1, weak 1); otherwise it decrements the use count and
    disposes via 0x5d35070 when it reaches 0.
    """

    def __init__(self, ptr, ctrl, use_count=1, weak_count=1):
        self.ptr = ptr
        self.ctrl = ctrl
        self.use_count = use_count
        self.weak_count = weak_count

    def packed(self):
        return self.use_count | (self.weak_count << 32)

    def copy(self):
        """Copy-construct: bump the use count, return the new holder."""
        if self.ctrl is None:
            return SharedPtr(None, None, 0, 0)
        return SharedPtr(self.ptr, self.ctrl,
                         self.use_count + 1, self.weak_count)

    def release(self):
        """Returns 'dispose' when this release destroys the object,
        else 'decrement'."""
        if self.ctrl is None:
            return "noop"
        if self.packed() == PACKED_COUNTS:
            return "dispose"
        if self.use_count == 1:
            return "dispose"
        return "decrement"


class FragmentList:
    """The 0xe8 FragmentedRangeTombstoneList as the ctors see it.

    frag_end: the value at list+0x08 (iterator frag pointer source).
    seq_base: the value at list+0x18 (iterator seq pointer source).
    seqs: the u64 seqnum array at list+0x18..+0x20 (the per-fragment
    seqnums the once-initializer indexes). index: the lazily built
    sorted deduped set of seqs, or None before the first probe.
    """

    def __init__(self, frag_end, seq_base, seqs):
        self.frag_end = frag_end
        self.seq_base = seq_base
        self.seqs = list(seqs)
        self.index = None
        self.index_count = 0

    def ensure_index(self):
        """Once-initializer 0x5f2eb90: build the deduped sorted seqnum
        set (an _Rb_tree keyed by seqnum, nodes 0x28 bytes, key +0x20)
        from the seq array. Idempotent: pthread_once guards it."""
        if self.index is None:
            self.index = sorted(set(self.seqs))
            self.index_count = len(self.index)
        return self.index


class FragmentCache:
    """The FragmentedRangeTombstoneListCache as ctor Cache sees it.

    frag_end: the value at cache+0x08 (iterator frag pointer source).
    seq_base: the value at cache+0x20 (iterator seq pointer source).
    list_ptr: the value at cache+0x28 (iterator +0x68 source).
    """

    def __init__(self, frag_end, seq_base, list_ptr):
        self.frag_end = frag_end
        self.seq_base = seq_base
        self.list_ptr = list_ptr


class Iterator:
    """The 0xc8 FragmentedRangeTombstoneIterator field state."""

    def __init__(self, fields):
        self.fields = fields

    def __getitem__(self, off):
        return self.fields[off]

    @property
    def list_holder(self):
        return self.fields[OFF_LIST_HOLDER_PTR]

    @property
    def cache_holder(self):
        return self.fields[OFF_CACHE_HOLDER_PTR]

    @property
    def arg6(self):
        return self.fields[OFF_ARG6]

    @property
    def read_seq(self):
        return self.fields[OFF_READ_SEQ]


def _base_fields(icmp, seq, upper_bound, arg6, frag_end, seq_base):
    """Fields shared by all three ctors: vtable, comparator quad,
    read seq, arg6, upper bound, frag/seq pointers and their shadows,
    and the empty inline cached-key string."""
    return {
        OFF_VTABLE: VTABLE,
        0x28: icmp + 0x8,
        0x30: icmp + 0x8,
        0x38: icmp,
        0x40: icmp + 0x8,
        OFF_READ_SEQ: seq,
        OFF_ARG6: arg6,
        OFF_UPPER_BOUND: upper_bound,
        OFF_FRAG: frag_end,
        0x98: frag_end,
        OFF_SEQ: seq_base,
        0xA0: seq_base,
        0xA8: "inline",
        0xB0: 0,
        0xB8: 0,
    }


def ctor_a(frag_list, icmp, seq, upper_bound, arg6):
    """Ctor A 0x5f31380 (raw list): both holders null, +0x68 = list,
    frag/seq pointers from list+0x08/+0x18."""
    fields = _base_fields(icmp, seq, upper_bound, arg6,
                          frag_list.frag_end, frag_list.seq_base)
    fields[OFF_LIST_HOLDER_PTR] = None
    fields[OFF_LIST_HOLDER_CTRL] = None
    fields[OFF_CACHE_HOLDER_PTR] = None
    fields[OFF_CACHE_HOLDER_CTRL] = None
    fields[OFF_LIST_PTR] = frag_list
    return Iterator(fields)


def ctor_list(shared_list, icmp, seq, upper_bound, arg6):
    """Ctor List 0x5f31470 (shared_ptr<List>): the shared_ptr is copied
    into +0x48/+0x50 with the use-count bump; +0x68 = the list pointer;
    the Cache holder stays null; bounds from list+0x08/+0x18."""
    fields = _base_fields(icmp, seq, upper_bound, arg6,
                          shared_list.ptr.frag_end, shared_list.ptr.seq_base)
    holder = shared_list.copy()
    fields[OFF_LIST_HOLDER_PTR] = holder.ptr
    fields[OFF_LIST_HOLDER_CTRL] = holder.ctrl
    fields[OFF_CACHE_HOLDER_PTR] = None
    fields[OFF_CACHE_HOLDER_CTRL] = None
    fields[OFF_LIST_PTR] = shared_list.ptr
    it = Iterator(fields)
    it.holder_use_count = holder.use_count
    return it


def ctor_cache(shared_cache, icmp, seq, upper_bound, arg6):
    """Ctor Cache 0x5f315a0 (shared_ptr<Cache>): the shared_ptr is copied
    into +0x58/+0x60 with the use-count bump; +0x68 = cache+0x28; the
    List holder stays null; bounds from cache+0x08/+0x20."""
    fields = _base_fields(icmp, seq, upper_bound, arg6,
                          shared_cache.ptr.frag_end, shared_cache.ptr.seq_base)
    holder = shared_cache.copy()
    fields[OFF_LIST_HOLDER_PTR] = None
    fields[OFF_LIST_HOLDER_CTRL] = None
    fields[OFF_CACHE_HOLDER_PTR] = holder.ptr
    fields[OFF_CACHE_HOLDER_CTRL] = holder.ctrl
    fields[OFF_LIST_PTR] = shared_cache.ptr.list_ptr
    it = Iterator(fields)
    it.holder_use_count = holder.use_count
    return it


def probe(frag_list, lower, snapshot):
    """List probe 0x5f31250(list, lower, snapshot): pthread_once over
    list+0x48 builds the index, then lower_bound(lower) over the
    sorted seqnum set; returns True iff a key exists and it is >=
    snapshot, i.e. iff NO indexed seqnum lies in [lower, snapshot)."""
    index = frag_list.ensure_index()
    lo = None
    for key in index:
        if key >= lower:
            lo = key
            break
    if lo is None:
        return False
    return lo >= snapshot


def split_by_snapshot(frag_list, icmp, snapshots, upper_bound):
    """SplitBySnapshot 0x5f33950: for each snapshot ascending, with
    lower starting at 0 and then prev+1, probe(list, lower, snapshot);
    when the probe is true, build an iterator via ctor A with (list,
    icmp, seq = snapshot, slice = upper_bound, arg6 = lower) and
    emplace it into the snapshot -> iterator map (first wins: a
    duplicate snapshot key keeps the first iterator and the new one
    is destroyed via D1). Returns the map, ascending by key."""
    result = {}
    lower = 0
    for snapshot in snapshots:
        if probe(frag_list, lower, snapshot):
            if snapshot not in result:
                result[snapshot] = ctor_a(
                    frag_list, icmp, snapshot, upper_bound, lower)
        lower = snapshot + 1
    return result


def truncated_split_by_snapshot(inner_map, truncated_fields):
    """TruncatedRangeDelIterator::SplitBySnapshot 0x5f269e0: for each
    (snapshot, iterator) in the inner map ascending, wrap the iterator
    in a fresh 0x48-byte TruncatedRangeDelIterator (ctor 0x5f25960,
    by contract) and insert it into the outer snapshot -> truncated
    map. This model records the wrapping and the key order, not the
    wrapper ctor's internals."""
    result = {}
    for snapshot in sorted(inner_map):
        result[snapshot] = {
            "wrapped_iterator": inner_map[snapshot],
            "outer_fields": dict(truncated_fields),
        }
    return result


def block_table_new_iterator(shared_list, icmp, snapshot, upper_bound):
    """BlockBasedTable::NewRangeTombstoneIterator 0x60fcee0: null list
    -> null; else ctor List with seq = snapshot (or -1 when the
    ReadOptions snapshot is absent), slice = ReadOptions+0x58,
    arg6 = 0."""
    if shared_list is None or shared_list.ptr is None:
        return None
    seq = MAX_SEQNUM if snapshot is None else snapshot
    return ctor_list(shared_list, icmp, seq, upper_bound, 0)


def compaction_new_iterator(frag_list, icmp):
    """CompactionRangeDelAggregator::NewIterator 0x5f29140: build a
    make_shared<FragmentedRangeTombstoneList> via the List ctor
    0x5f37410 from a TruncatedRangeDelMergingIter source (by contract),
    then ctor List with seq = -1, slice = null, arg6 = 0."""
    shared = SharedPtr(frag_list, ctrl=id(frag_list), use_count=1)
    return ctor_list(shared, icmp, MAX_SEQNUM, None, 0)
