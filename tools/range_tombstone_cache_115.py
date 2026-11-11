"""Python model of RE-001 range-tombstone cache (node #115).

Models the behaviour pinned by research/work-items/
RE-001-range-tombstone-cache-115/ from the digest-verified work
binary (SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):
MemTable::NewRangeTombstoneIteratorInternal (0x5f0a9c0, catalogue
librocksdb-sys _ZN7rocksdb8MemTable33NewRangeTombstoneIteratorInternalERKNS_11ReadOptionsEmb,
1536/1676 raw bytes) hands a calling thread a 0xc8-byte
FragmentedRangeTombstoneIterator either fresh (ctor A 0x5f31380,
from a raw FragmentedRangeTombstoneList) or from the per-CPU
FragmentedRangeTombstoneListCache slot (ctor B 0x5f315a0, from the
slot's shared_ptr). The slot is picked by the CPUID logical-core
count (0x60d5cd0, rocksdb::port::PhysicalCoreID) with the per-thread
LCG seed (0x61c4080) as fallback; a clear ready flag forces the
mutex path, which lazily builds a 0x80-byte list and a 0xe8-byte
cache (0x5f37410) and installs it, tearing down the old cache.
The sibling shard-pointer helper 0x605e170 picks a 0x40-stride slot
the same way and records the choice in TLS.

The picker/seed helpers and the mersenne step are reused from open
PR #3613 (RE-001-statistics-shard-record-115), whose model in turn
follows open PR #3575; the picker and seed excerpts are re-derived
fresh from the binary in this packet.
"""

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# ---------------------------------------------------------------------------
# 0x60d5cd0: CPUID logical-processor picker (catalogue
# rocksdb::port::PhysicalCoreID, 32/32)
# ---------------------------------------------------------------------------


def cpuid_logical_count(max_leaf, leaf1_ebx):
    """The picker's exact rule.

    cpuid leaf 0 gives the max leaf in eax; when it is 0 the picker
    returns -1. Otherwise cpuid leaf 1 is read and the count is
    EBX >> 24 (the maximum number of addressable logical-processor
    IDs). max_leaf / leaf1_ebx are the injected cpuid results.
    """
    if max_leaf == 0:
        return -1
    return (leaf1_ebx >> 24) & 0xFF


def pick_shard(source_value, exponent):
    """Shard index: source & ((1 << exponent) - 1)."""
    return source_value & ((1 << exponent) - 1)


# ---------------------------------------------------------------------------
# 0x61c4080: per-thread hash seed (libstdc++ _Hash_bytes over
# pthread_self); reused from open PR #3613.
# ---------------------------------------------------------------------------

_MURMUR_M = 0xC6A4A7935BD1E995
_MURMUR_R = 47
_MASK64 = (1 << 64) - 1


def _hash_bytes(data, seed):
    """libstdc++ _Hash_bytes (MurmurHash64A) over data with the given seed."""
    h = (seed ^ ((len(data) * _MURMUR_M) & _MASK64)) & _MASK64
    nblocks = len(data) // 8
    for i in range(nblocks):
        k = int.from_bytes(data[i * 8:(i + 1) * 8], "little")
        k = (k * _MURMUR_M) & _MASK64
        k ^= k >> _MURMUR_R
        k = (k * _MURMUR_M) & _MASK64
        h ^= k
        h = (h * _MURMUR_M) & _MASK64
    tail = data[nblocks * 8:]
    if tail:
        h ^= int.from_bytes(tail, "little")
        h = (h * _MURMUR_M) & _MASK64
    h ^= h >> _MURMUR_R
    h = (h * _MURMUR_M) & _MASK64
    h ^= h >> _MURMUR_R
    return h


class ThreadSeed:
    """The per-thread cached seed at thread-0x20 (pointer at thread-0x10).

    First use computes _Hash_bytes(&pthread_self, 8, 0xc70f6907) &
    0x7fffffff (or 1 when that is 0) and caches it; later uses return
    the cached value. Callers advance the cached value in place.
    """

    SEED_CONSTANT = 0xC70F6907

    def __init__(self, tid_bytes):
        self._tid_bytes = bytes(tid_bytes)
        self._cached = None

    def pointer(self):
        """Return the cached seed value, computing it on first use."""
        if self._cached is None:
            v = _hash_bytes(self._tid_bytes, self.SEED_CONSTANT) & 0x7FFFFFFF
            self._cached = v if v != 0 else 1
        return self._cached

    def store(self, value):
        self._cached = value & 0xFFFFFFFF


def mersenne_step(seed):
    """One LCG advance: (seed * 0x41a7) mod 0x7fffffff, Mersenne fold.

    The binary computes x = seed * 0x41a7, then
    (x & 0x7fffffff) + (x >> 31), subtracting 0x7fffffff once when
    the sum is negative as a signed 32-bit value. A true 0 result is
    kept as 0x7fffffff by the fold (bit 31 of 0x7fffffff is 0, so no
    subtract fires for it).
    """
    x = (seed * 0x41A7) & 0xFFFFFFFFFFFFFFFF
    folded = (x & 0x7FFFFFFF) + (x >> 31)
    if folded & 0x80000000:
        folded -= 0x7FFFFFFF
    return folded & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# The shared atomicity selector at 0x64ed290: 0 selects the locked
# read-modify-write, nonzero the plain one. It is read by the host,
# ctor B and _M_release alike.
# ---------------------------------------------------------------------------

ATOMIC_FLAG_ADDR = 0x64ED290


def atomic_rmw(global_flag):
    """True iff the global flag byte selects the locked RMW (flag == 0)."""
    return global_flag == 0


# ---------------------------------------------------------------------------
# 0x5d350c0: _Sp_counted_base::_M_release (catalogue
# _ZNSt16_Sp_counted_baseILN9__gnu_cxx12_Lock_policyE2EE10_M_releaseEv,
# 126/133 raw bytes)
# ---------------------------------------------------------------------------


class CountedBase:
    """The +0x8 qword of a _Sp_counted_base: low dword use count,
    high dword weak count. A fresh shared_ptr control block holds
    (use=1, weak=1), i.e. the qword 0x100000001."""

    def __init__(self, use=1, weak=1):
        self.use = use
        self.weak = weak

    def packed(self):
        return (self.weak << 32) | (self.use & 0xFFFFFFFF)

    def add_ref(self):
        """The host/ctor-B increment: plain or locked by the global
        flag; the count effect is the same either way."""
        self.use += 1

    def release(self):
        """_M_release. Returns True when the object must be disposed
        (the use count reached 0), False otherwise.

        Fast path: the packed qword equals 0x100000001 (use 1,
        weak 1) disposes at once without a decrement. Otherwise the
        use count is decremented (locked iff the global flag is 0)
        and disposal follows iff the old count was 1.
        """
        if self.packed() == 0x100000001:
            self.use = 0
            return True
        old = self.use
        self.use -= 1
        return old == 1


# ---------------------------------------------------------------------------
# Cleanable (0x61bd0c0 ctor / 0x61bd0e0 DoCleanup, catalogue
# "one of 2 identical copies ... _ZN7rocksdb9Cleanable9DoCleanupEv")
# ---------------------------------------------------------------------------


class Cleanable:
    """A Cleanable subobject: head at +0x0, chain link at +0x18.
    Each cleanup node is 0x20 bytes: (fn, arg1, arg2, next@+0x18);
    the ctor zeroes the head and the link, the dtor runs the head's
    fn(head+0x8, head+0x10) then walks the +0x18 chain running each
    node's fn and freeing the 0x20-byte nodes."""

    def __init__(self):
        self.head = None  # (fn, arg1, arg2, next) or None
        self.next = None

    def add(self, fn, arg1, arg2):
        node = {"fn": fn, "arg1": arg1, "arg2": arg2, "next": self.head}
        self.head = node
        return node

    def do_cleanup(self):
        """Returns the list of (fn, arg1, arg2) calls made, in order,
        and empties the chain."""
        calls = []
        node = self.head
        if node is None:
            return calls
        calls.append((node["fn"], node["arg1"], node["arg2"]))
        node = node["next"]
        while node is not None:
            calls.append((node["fn"], node["arg1"], node["arg2"]))
            node = node["next"]
        self.head = None
        self.next = None
        return calls


# ---------------------------------------------------------------------------
# 0x5f059b0: recursive node-tree release
# ---------------------------------------------------------------------------


class TreeNode:
    """A 0x28-byte node of the tree released by 0x5f059b0: child at
    +0x18 (released recursively first), sibling at +0x10."""

    def __init__(self, name, child=None, sibling=None):
        self.name = name
        self.child = child
        self.sibling = sibling


def release_tree(node, freed=None):
    """Release the tree rooted at node: null returns at once;
    otherwise the +0x18 child subtree is released first (recursion
    at 0x5f05a41), then the node itself is freed (0x28 bytes) and
    the +0x10 sibling is released. Returns the freed node names in
    release order."""
    if freed is None:
        freed = []
    if node is None:
        return freed
    if node.child is not None:
        release_tree(node.child, freed)
    freed.append(node.name)
    if node.sibling is not None:
        release_tree(node.sibling, freed)
    return freed


# ---------------------------------------------------------------------------
# The 0x80-byte fragmented list built by the host (0x5f0a9c0) and the
# 0xe8-byte cache built by 0x5f37410.
# ---------------------------------------------------------------------------

LIST_VTABLE = 0x64CC638 + 0x10
LIST_FIELD_30 = 0x64CC600 + 0x10  # vtable-valued slot at list+0x38
LIST_FIELD_38 = 0x64C8FE8 + 0x10  # vtable-valued slot at list+0x40
ITER_VTABLE = 0x64CCAE0 + 0x10
CACHE_ITER_VTABLE = 0x64CCA10 + 0x10


class TombstoneList:
    """The 0x80-byte list the host builds when the slot has no cache.
    Fields are the host's exact writes (see records.json); the
    +0x30/+0x38/+0x40 vtable-valued slots' subobject identities are
    open, and the Cleanable at +0x8 is modelled by Cleanable."""

    SIZE = 0x80

    def __init__(self, owner):
        self.vtable = LIST_VTABLE
        self.cleanable = Cleanable()
        self.field_28 = 0
        self.field_30 = owner["field_c58"]
        self.field_38 = LIST_FIELD_30
        self.field_40 = LIST_FIELD_38
        self.field_48 = owner["field_10"]
        self.field_50 = owner["vtable_slot_90"]()
        self.field_58 = 0
        self.field_5a = owner["field_31"] ^ 1
        self.field_60 = owner["field_6c"]
        self.field_68 = 0
        self.field_6c = 0
        self.field_70 = 0
        self.field_78 = owner["field_60"]
        self.destroyed = False

    def destroy_via_slot1(self):
        """The host destroys the temporary list through its vtable
        slot 1 after the cache is built."""
        self.destroyed = True


class TombstoneCache:
    """The 0xe8-byte cache built by 0x5f37410 from a list.

    Zero-init (see records.json): +0x0..+0x10, +0x10..+0x40,
    +0x40, +0x48 (dword), +0x58 (dword), +0x60, +0x68/+0x70 =
    &cache+0x58, +0x78, +0x80..0x90 = (cache+0x80, cache+0x80),
    +0x90, +0xb8 (byte flag), +0xc0..+0xd0 (index vector triple),
    +0xd8..+0xe8 (entry count +0xd8, total size +0xe0). The +0x98
    Cleanable and the +0x8/+0x20 bound pair are modelled; the
    iteration walks the list via its vtable slots (0x10 Valid,
    0x18 Next, 0x50 key, 0x60 size, 0x38, 0x90), counting entries
    at +0xd8 and summing sizes at +0xe0, then finalizes through
    0x5f36c70."""

    SIZE = 0xE8

    def __init__(self, entries):
        """entries: the list's (key, size) pairs, in iteration order.
        The cache ctor's iteration counts them at +0xd8 and sums
        their sizes at +0xe0."""
        self.field_68 = "self+0x58"
        self.field_70 = "self+0x58"
        self.field_80_head = "self+0x80"
        self.cleanable = Cleanable()
        self.flag_b8 = 0
        self.index = []  # the +0xc0/+0xc8/+0xd0 vector (entry layout open)
        self.count_d8 = len(entries)
        self.total_size_e0 = sum(size for _key, size in entries)
        self.bound_08 = None  # populated by the iteration/finalize (open)
        self.bound_20 = None
        self.finalized = False
        self.list60 = []  # the +0x60 node list (0x28-byte nodes)
        self.list80 = []  # the +0x80 node list (0x30-byte nodes)
        self.buffers = {"30": None, "18": None, "00": None}

    def finalize(self):
        """The 0x5f36c70 finalize step at the end of the cache ctor."""
        self.finalized = True


def teardown_cache(cache):
    """The host's teardown of a replaced old cache (0x5f0a9c0,
    0x5f0ac24..0x5f0ad26). Returns the ordered release steps.

    Order: (1) when the +0xb8 flag is set, the +0xc0 array fixup
    (memmove/memcpy + insertion-sort dedup, entry dtors, the +0x98
    cleanup chain run, +0x98/+0xb0 zeroed); (2) operator delete[]
    of the +0xc0 array; (3) DoCleanup(+0x98); (4) walk the +0x80
    list freeing each 0x30-byte node and its +0x10 buffer;
    (5) walk the +0x60 list releasing each 0x28-byte node through
    0x5f059b0; (6) free the +0x30, +0x18 and +0x0 buffers;
    (7) operator delete of the 0xe8 cache."""
    steps = []
    if cache.flag_b8:
        steps.append("array_fixup")
        cache.cleanable.do_cleanup()
        steps.append("cleanup_chain")
        cache.flag_b8 = 0
    if cache.index:
        steps.append("delete_index_array")
        cache.index = []
    cache.cleanable.do_cleanup()
    steps.append("do_cleanup_98")
    for _node in cache.list80:
        steps.append("free_list80_node")
    cache.list80 = []
    for node in cache.list60:
        release_tree(node)
        steps.append("release_list60_node")
    cache.list60 = []
    for off in ("30", "18", "00"):
        if cache.buffers[off] is not None:
            steps.append("free_buffer_%s" % off)
            cache.buffers[off] = None
    steps.append("delete_cache")
    return steps


# ---------------------------------------------------------------------------
# The 0xc8-byte FragmentedRangeTombstoneIterator (ctors 0x5f31380 /
# 0x5f315a0) and the slot object it is built from.
# ---------------------------------------------------------------------------

ITER_SIZE = 0xC8


def iterator_from_list(lst, comparator, seq, slice_arg, arg6):
    """Ctor A 0x5f31380: (this, list, comparator, seq, slice, arg6).
    The comparator subobject at +0x8 is built by 0x61bd0c0; the
    iterator stores the comparator's +0x8 qword twice (+0x28/+0x30)
    and (comparator, comparator+0x8) at +0x38/+0x40; +0x68 = list,
    +0x70 = seq, +0x78 = arg6, +0x80 = slice; the bounds pairs at
    +0x88/+0x98 = list+0x8 and +0x90/+0xa0 = list+0x18; +0xa8 =
    &this+0xb8, +0xb0 = 0, +0xb8 = 0; the shared_ptr at +0x58 is
    null (raw-list iterator)."""
    it = {
        "vtable": ITER_VTABLE,
        "comparator": comparator,
        "cmp_plus8": comparator["plus8"],
        "field_28": comparator["plus8"],
        "field_30": comparator["plus8"],
        "field_38": comparator,
        "field_40": comparator["plus8"],
        "field_48": 0, "field_58": 0,
        "shared_ptr": None,
        "list": lst, "cache": None,
        "field_68": lst,
        "field_70": seq,
        "field_78": arg6,
        "field_80": slice_arg,
        "field_88": lst["plus8"], "field_90": lst["plus18"],
        "field_98": lst["plus8"], "field_a0": lst["plus18"],
        "field_a8": "self+0xb8", "field_b0": 0, "field_b8": 0,
    }
    return it


def iterator_from_cache(shared, comparator, seq, slice_arg, arg6):
    """Ctor B 0x5f315a0: (this, shared_ptr<Cache>, comparator, seq,
    slice, arg6). Same vtable and comparator fields as ctor A; the
    16-byte shared_ptr is copied to +0x58 and its control block's
    use count is bumped (locked iff the global flag is 0); +0x68 =
    the shared_ptr's object +0x28 (the cache); +0x70 = seq,
    +0x78 = arg6; an empty slice (non-null with +0x8 == 0) is
    treated as null; the bounds pairs are +0x88/+0x98 = cache+0x8
    and +0x90/+0xa0 = cache+0x20 (the cache's bound pair, populated
    by its iteration/finalize)."""
    ptr, ctrl = shared
    if ctrl is not None:
        ctrl.add_ref()
    if slice_arg is not None and slice_arg.get("plus8", 1) == 0:
        slice_arg = None
    cache = ptr.cache
    it = {
        "vtable": ITER_VTABLE,
        "comparator": comparator,
        "cmp_plus8": comparator["plus8"],
        "field_28": comparator["plus8"],
        "field_30": comparator["plus8"],
        "field_38": comparator,
        "field_40": comparator["plus8"],
        "field_48": 0, "field_58": 0,
        "shared_ptr": (ptr, ctrl),
        "list": None, "cache": cache,
        "field_68": cache,
        "field_70": seq,
        "field_78": arg6,
        "field_80": slice_arg,
        "field_88": cache.bound_08, "field_90": cache.bound_20,
        "field_98": cache.bound_08, "field_a0": cache.bound_20,
        "field_a8": "self+0xb8", "field_b0": 0, "field_b8": 0,
    }
    return it


class SlotObject:
    """The object a per-CPU shared_ptr slot points at: a
    pthread_mutex_t at +0x0 (0x28 bytes), the cache pointer at
    +0x28, the ready flag byte at +0x30."""

    def __init__(self):
        self.mutex_locked = False
        self.cache = None
        self.ready = False


class Owner:
    """The MemTable-side shard state the host reads: the 16-byte
    shared_ptr slots at owner+0xd10 with exponent at owner+0xd18,
    plus the owner fields the list build copies (field_10, field_31,
    field_60, field_6c, field_c58, vtable_slot_90)."""

    def __init__(self, shift, slot_count, fields=None):
        self.shift = shift
        self.slots = [None] * slot_count  # (SlotObject, CountedBase) or None
        self.fields = fields or {
            "field_10": "owner+0x10", "field_31": 1, "field_60": "owner+0x60",
            "field_6c": "owner+0x6c", "field_c58": "owner+0xc58",
            "vtable_slot_90": lambda: "owner->slot90",
        }
        self.thread_seed = None

    def source_value(self, max_leaf, leaf1_ebx, tid_bytes):
        """Shard source: the CPUID picker, or the advanced per-thread
        seed when the picker returns -1."""
        src = cpuid_logical_count(max_leaf, leaf1_ebx)
        if src >= 0:
            return src
        if self.thread_seed is None:
            self.thread_seed = ThreadSeed(tid_bytes)
        v = mersenne_step(self.thread_seed.pointer())
        self.thread_seed.store(v)
        return v

    def new_range_tombstone_iterator_internal(self, key, seq, flag,
                                             comparator, slice_arg, arg6,
                                             max_leaf, leaf1_ebx, tid_bytes,
                                             global_flag=0):
        """The host 0x5f0a9c0 state machine (single-threaded model;
        the mutex/locker steps are modelled as state, not real
        locking). Returns (iterator, trace) where trace is the
        ordered list of steps taken."""
        trace = []
        if flag:
            # Fast path: fresh list iterator, no slot involved.
            lst = {"plus8": "fresh-list+0x8", "plus18": "fresh-list+0x18"}
            it = iterator_from_list(lst, comparator, seq, slice_arg, arg6)
            trace.append("flag_path_ctor_a")
            return it, trace
        src = self.source_value(max_leaf, leaf1_ebx, tid_bytes)
        idx = pick_shard(src, self.shift)
        trace.append("shard_%d" % idx)
        slot = self.slots[idx]
        if slot is None:
            slot = (SlotObject(), CountedBase())
            self.slots[idx] = slot
        obj, ctrl = slot
        # _Sp_locker + 16-byte copy + claim-time add_ref.
        trace.append("locker_claim")
        if ctrl is not None:
            ctrl.add_ref()
        if obj.ready:
            trace.append("ready_ctor_b")
            it = iterator_from_cache((obj, ctrl), comparator, seq,
                                     slice_arg, arg6)
            ctrl.release()  # the claim-time reference is released
            trace.append("release_claim_ref")
            return it, trace
        obj.mutex_locked = True
        trace.append("mutex_lock")
        if obj.cache is not None:
            obj.mutex_locked = False
            trace.append("cache_present_ctor_b")
            it = iterator_from_cache((obj, ctrl), comparator, seq,
                                     slice_arg, arg6)
            ctrl.release()
            trace.append("release_claim_ref")
            return it, trace
        # Lazy build: fresh list, fresh cache, install, teardown old.
        lst = TombstoneList(self.fields)
        trace.append("build_list")
        cache = TombstoneCache(key)
        cache.finalize()
        trace.append("build_cache")
        old = obj.cache
        obj.cache = cache
        trace.append("install_cache")
        if old is not None:
            trace.extend(teardown_cache(old))
        lst.destroy_via_slot1()
        trace.append("destroy_list")
        obj.ready = True
        obj.mutex_locked = False
        trace.append("set_ready_unlock")
        it = iterator_from_cache((obj, ctrl), comparator, seq,
                                 slice_arg, arg6)
        ctrl.release()
        trace.append("release_claim_ref")
        return it, trace


# ---------------------------------------------------------------------------
# 0x605e170: the 0x40-stride shard-pointer sibling
# ---------------------------------------------------------------------------


class ShardTable40:
    """The sibling shard system: table at owner+0x48, exponent at
    owner+0x50, 0x40-byte stride. The helper returns the slot pointer
    and records idx | (1 << shift) in TLS at fs:0-0x408."""

    def __init__(self, shift, slot_count):
        self.shift = shift
        self.slots = ["slot%d" % i for i in range(slot_count)]
        self.tls_record = None

    def shard_pointer(self, source_value, thread_seed, tid_bytes):
        """0x605e170: picker, or the advanced seed on -1; mask to the
        shard; bts the exponent bit into the index; record it in TLS;
        return the slot pointer."""
        src = source_value
        if src < 0:
            if thread_seed is None:
                thread_seed = ThreadSeed(tid_bytes)
            v = mersenne_step(thread_seed.pointer())
            thread_seed.store(v)
            src = v
        idx = pick_shard(src, self.shift)
        record = idx | (1 << self.shift)
        self.tls_record = record
        return self.slots[idx], record
