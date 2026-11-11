"""Model of the node #115 fragmented range-tombstone cache destruction.

Faithful model of the behaviour pinned by
research/work-items/RE-001-tombstone-cache-destruction-115/ (RE-001):
the shared_ptr control-block dispose (0x5f061b0), the unique_ptr<List>
destructor (0x5f0b080), MemTable::~MemTable (0x5f10d40), the
AllocTracker / WriteBufferManager pair (0x605e8a0 / 0x605e860 /
0x606a890), the shared_ptr release chain (0x5f0a290), the
ConcurrentArena destructors (0x5f10180 / 0x5f10d00), the RB-tree erase
helpers (0x5f05b80 / 0x5f06770) and the FlushJobInfo destruction
(0x5ecd650).

All offsets, sizes and flag positions come from the packet's
records.json and the verbatim objdump excerpts. The model is a
state machine over the observable effects (which buffers are freed,
which flags are set, which callees run, in which order); it does not
re-implement the binary.
"""

CACHE_SIZE = 0xE8
CACHE_LIST_OFFSET = 0x38
CACHE_READY_FLAG_OFFSET = 0xB8
CACHE_INDEX_OFFSET = 0xC0
CACHE_END_OFFSET = 0xC8
CACHE_CLEANABLE_OFFSET = 0x98
CACHE_LIST_HEAD_OFFSET = 0x80
CACHE_TREE_OFFSET = 0x60
CACHE_CHAIN_OFFSET = 0xB0

ALLOC_TRACKER_DONE_OFFSET = 0x10
ALLOC_TRACKER_FREED_OFFSET = 0x11
ALLOC_TRACKER_AMOUNT_OFFSET = 0x08

WBM_FIRST_COUNTER_OFFSET = 0x10
WBM_SECOND_COUNTER_OFFSET = 0x18
WBM_CACHE_GATE_OFFSET = 0x20

ARENA_SIZE = 0x9B0
SKIPLIST_REP_SIZE = 0x58
FLUSH_JOB_INFO_SIZE = 0x340
CORE_LOCAL_ARRAY_OFFSET = 0xD10
MEMTABLE_CACHE_OFFSET = 0xCE0
MEMTABLE_FLUSH_JOB_INFO_OFFSET = 0xCD8

MEMTABLE_DTOR_ORDER = [
    "alloc_tracker_free_mem",
    "core_local_array_release",
    "cache_teardown",
    "flush_job_info_destroy",
    "free_c90_chain",
    "memset_c80_array",
    "free_c60",
    "destroy_c40_rwlock_vector",
    "dispose_bf8_bd0_strings",
    "free_ba8_b90_buffers",
    "destroy_b78_vector",
    "destroy_b60_vector",
    "destroy_b40_rbtree",
    "destroy_b18_vector",
    "dispose_ac0_aa0_strings",
    "rep_slot_88_calls",
    "concurrent_arena_destroy",
    "alloc_tracker_dtor",
]

SORT_DEPTH_LIMIT_FACTOR = 2  # introsort depth limit is 2*log2(n)


def depth_limit(n):
    """libstdc++ __introsort_loop depth limit: 2 * floor(log2(n))."""
    if n <= 1:
        return -2 if n == 0 else 0
    return 2 * (n.bit_length() - 1)


def sort_index(entries):
    """The index sort: __introsort_loop then __insertion_sort.

    The binary sorts the index of (key, seq) pairs by key, then by
    sequence number; adjacent duplicates are removed afterwards by a
    std::unique-style scan (see dedup_sorted).
    """
    return sorted(entries, key=lambda e: (e[0], e[1]))


def dedup_sorted(entries):
    """std::unique-style adjacent scan over the sorted index."""
    out = []
    for e in entries:
        if not out or out[-1] != e:
            out.append(e)
    return out


class Cache:
    """A FragmentedRangeTombstoneListCache (0xe8 bytes)."""

    def __init__(self, entries=None, index=None, cleanable_head=None,
                 list_head=None, tree=None, chain=None, buffers=None):
        # entries=None models a null List* (control-block +0x38 is null):
        # the dispose returns without freeing anything.
        self.entries = None if entries is None else list(entries)
        self.index = list(index if index is not None
                          else (self.entries or []))
        self.flag_set = False
        self.cleanable_head = cleanable_head or []
        self.list_head = list_head or []
        self.tree = tree
        self.chain = chain or []
        self.buffers = dict(buffers or {})
        self.freed = False
        self.invoked = []

    def invoke_entry_dtor(self, entry):
        self.invoked.append(entry)


def dispose(cache, flag_set):
    """The 0x5f061b0 dispose. Returns the trace of observable steps."""
    trace = []
    if cache.entries is None:
        return ["return_null_list"]
    if flag_set:
        trace.append("sort_dedup_invoke")
        cache.flag_set = False
        cache.index = dedup_sorted(sort_index(cache.index))
        for entry in cache.index:
            cache.invoke_entry_dtor(entry)
        cache.chain = []
        trace.append("chain_walked")
    else:
        trace.append("free_array")
    trace.append("free_index_array")
    trace.append("do_cleanup")
    for fn in cache.cleanable_head:
        fn()
    trace.append("walk_0x80_list")
    cache.list_head = []
    trace.append("release_0x60_tree")
    cache.tree = None
    trace.append("free_buffers")
    cache.buffers = {}
    trace.append("delete_0xe8")
    cache.freed = True
    return trace


def unique_ptr_list_dtor(cache, flag_set):
    """The 0x5f0b080 unique_ptr<List> destructor.

    Structurally identical to dispose() except the owner-load offset
    (cache at owner +0x00 instead of control-block +0x38); the same
    flag-gated teardown runs.
    """
    return dispose(cache, flag_set)


class WriteBufferManager:
    """WriteBufferManager with the two counters and the cache gate."""

    def __init__(self, first=0, second=0, has_cache=False):
        self.first = first
        self.second = second
        self.has_cache = has_cache
        self.cache_freed = False
        self.stall_checked = False

    def free_mem(self, amount):
        """WriteBufferManager::FreeMem (0x606a890)."""
        if self.has_cache:
            self.cache_freed = True
            self.stall_checked = True
            return "free_mem_with_cache"
        if self.first != 0:
            self.first -= amount
        self.stall_checked = True
        return "atomic_sub_first"

    def done_allocating_amount(self, amount):
        """The 0x606a110 helper: atomic sub of the second counter."""
        if self.first != 0:
            self.second -= amount
            return "atomic_sub_second"
        return "no_manager"


class AllocTracker:
    """AllocTracker with the +0x10 done and +0x11 freed flags."""

    def __init__(self, manager=None, amount=0):
        self.manager = manager
        self.amount = amount
        self.done = False
        self.freed = False

    def done_allocating(self):
        """AllocTracker::DoneAllocating (0x605e860)."""
        if self.manager is None:
            return "no_manager"
        if self.done:
            return "already_done"
        if self.manager.first != 0 or self.manager.has_cache:
            self.manager.done_allocating_amount(self.amount)
        self.done = True
        return "done"

    def free_mem(self):
        """AllocTracker::FreeMem (0x605e8a0)."""
        if not self.done:
            self.done_allocating()
        if self.manager is None:
            return "no_manager"
        if self.freed:
            return "already_freed"
        if self.manager.first != 0 or self.manager.has_cache:
            self.manager.free_mem(self.amount)
        self.freed = True
        return "freed"


class SharedPtrChain:
    """The shared_ptr release chain: array element -> inner dispose ->
    Cache control block -> Cache dispose -> List teardown."""

    def __init__(self, cache, use_count=1, weak_count=1):
        self.cache = cache
        self.use_count = use_count
        self.weak_count = weak_count
        self.destroyed = False

    def inner_dispose(self):
        """The 0x5f0a290 inner control-block dispose."""
        if self.use_count == 0 and self.weak_count == 0:
            return "already_released"
        # single-threaded fast path: (use, weak) == (1, 1) encoded as
        # 0x100000001; otherwise the lock-xadd slow path.
        if self.use_count == 1 and self.weak_count == 1:
            self.use_count = 0
            self.weak_count = 0
            trace = dispose(self.cache, flag_set=self.cache.flag_set)
            self.destroyed = True
            return ["cache_dispose"] + trace + ["cache_destroy"]
        self.use_count -= 1
        return "decremented"


def rb_erase(nodes, node_size):
    """RB-tree erase (0x5f05b80 for 0x30-byte nodes, 0x5f06770 for
    0x60-byte nodes): recurse on the right child, dispose the value
    strings inline, delete the node, move to the left child."""
    freed = []

    def erase(node):
        if node is None:
            return
        erase(node.get("right"))
        freed.append(node["id"])
        erase(node.get("left"))

    erase(nodes)
    return freed


def destroy_flush_job_info(info):
    """The 0x5ecd650 unique_ptr<FlushJobInfo> destructor: 13 strings,
    two maps at +0x2d0/+0x300 (0x60-byte nodes), one vector at +0x328
    of 0x38-byte elements."""
    trace = []
    for name in info.get("strings", []):
        trace.append("dispose_string:" + name)
    for name in info.get("maps", []):
        trace.append("erase_map:" + name)
    for i in range(info.get("vector_len", 0)):
        trace.append("destroy_vector_element:%d" % i)
    trace.append("delete_0x340")
    return trace


def memtable_dtor_order():
    """The MemTable::~MemTable member-destruction order (0x5f10d40)."""
    return list(MEMTABLE_DTOR_ORDER)


def concurrent_arena_d1(arena):
    """ConcurrentArena D1 (0x5f10180): install the Arena vtable, call
    Arena::~Arena(this+0x60), operator delete[] on *(this+0x48)."""
    trace = ["install_arena_vtable", "arena_dtor"]
    if arena.get("blocks") is not None:
        trace.append("delete_array_blocks")
    return trace


def concurrent_arena_d0(arena):
    """ConcurrentArena D0 (0x5f10d00): D1, then operator delete this
    with size 0x9b0."""
    return concurrent_arena_d1(arena) + ["delete_0x9b0"]
