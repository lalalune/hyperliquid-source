"""Python model for RE-001 node #115 stats-emit caller 0x5d7dfc0.

The routine is the DB dump entry (db/db_impl/db_impl.cc lines
1084-1093 in the format strings): it walks the version list under
the mutex at obj+0x700, refreshes each flagged version, produces a
per-version key object, de-duplicates the keys in a small hash
table, dispatches each new key once, invokes two registry factories
by trimmed name, emits the accumulated dump string twice, runs the
malloc-stats hook branch, calls the stats-emit routine 0x5d52020,
and cleans up.

Every claim below is pinned to the verbatim excerpts in
research/work-items/RE-001-stats-emit-caller-7dfc0-115/; the
README.md separates observations from inferences and unknowns.
The opaque callees (per-version refresh 0x5eef8a0, the rehash helper
0x5d7dda0, and the virtual produce/dispatch targets) are injectable
hooks: the model records their call-site contracts, it does not
invent their internals.
"""

SENTINEL = 0xFFFFFFFF
ROUTINE_START = 0x5D7DFC0
ROUTINE_STOP = 0x5D7E627
CLEANUP_START = 0x5D7DEDE
CLEANUP_STOP = 0x5D7DFBA

ACQUIRE = 0x606CA40
MUTEX_UNLOCK = 0x60D52F0
STRING_ASSIGN = 0x5D4AB80
VERSION_RELEASE = 0x5D911E0
STATS_EMIT = 0x5D52020
LOG_DISPATCH = 0x5FCF060
REGISTRY_LOOKUP = 0x5EEE790
TRIM_INVOKE = 0x5EEE9F0
REFRESH = 0x5EEF8A0
NOOP_HOOK = 0x5F04CE0
IDENTITY = 0x5D3A940

FORMAT_DUMPING = "[%s:1084] ------- DUMPING STATS -------"
FORMAT_DUMP = "[%s:1086] %s"
FORMAT_MALLOC = "[%s:1091] ------- Malloc STATS -------"
FORMAT_MALLOC_DUMP = "[%s:1093] %s"
FILE_NAME = "db/db_impl/db_impl.cc"
PRODUCE_NAME = "BlockCache"

# The two BSS {ptr, len} slices the routine looks up in the global
# registry. Their bytes are not in the file (BSS); only the access
# pattern is pinned, so the model names them by address.
REGISTRY_SLICE_FIRST = 0x65030E0
REGISTRY_SLICE_SECOND = 0x6502A80

# libstdc++ prime bucket counts used by _Prime_rehash_policy.
_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
           53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 103, 109, 113,
           127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
           181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
           241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
           311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373,
           379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
           443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
           509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587,
           593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647,
           653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727,
           733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
           811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
           881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
           967, 971, 977, 983, 991, 997)


def next_prime_at_least(n):
    """First prime in the libstdc++ prime list >= n (0 when n < 2)."""
    for p in _PRIMES:
        if p >= n:
            return p
    raise ValueError("bucket count beyond modelled prime list")


class LogicError(ValueError):
    """std::logic_error from basic_string construction from null."""


class SystemError(OSError):
    """std::__throw_system_error from a failed pthread lock call."""


class AbortError(RuntimeError):
    """abort() after the mutex-unlock error report."""


class StdString:
    """A std::string with the 16-byte SSO inline buffer.

    Layout: ptr (+0x00), size (+0x08), inline buffer (+0x10, 16
    bytes). Heap form when len > 15.
    """

    SSO_LIMIT = 15

    def __init__(self, value=b""):
        self._value = bytes(value)

    @property
    def data(self):
        return self._value

    def __len__(self):
        return len(self._value)

    def is_heap(self):
        return len(self._value) > self.SSO_LIMIT

    def dispose(self):
        """_M_dispose: heap form frees the buffer, SSO frees nothing."""
        freed = self._value if self.is_heap() else None
        self._value = b""
        return freed


def string_assign(dst, cstr):
    """0x5d4ab80: assign a std::string from a NUL-terminated C string.

    Raises LogicError (the binary's 'basic_string: construction from
    null is not valid') when cstr is None. SSO (len <= 15) copies
    inline; longer strings allocate. Returns dst.
    """
    if cstr is None:
        raise LogicError(
            "basic_string: construction from null is not valid")
    if isinstance(cstr, str):
        cstr = cstr.encode("utf-8")
    dst._value = bytes(cstr)
    return dst


class VersionNode:
    """One node of the circular version list (+0x938 links).

    marker: the u32 at +0x00, compared against SENTINEL (0xffffffff).
    refcount: the s32 at +0x38 (lock xadd in the release routine).
    flag: the byte at +0x3c; only set nodes are processed.
    subobject: the pointer at +0x8d8, passed to the refresh callee.
    produce_obj: the pointer at +0x620, whose vtable slot +0x38 is
    the per-version produce call.
    """

    def __init__(self, marker=SENTINEL, refcount=1, flag=0,
                 subobject=None, produce_obj=None):
        self.marker = marker
        self.refcount = refcount
        self.flag = flag
        self.subobject = subobject
        self.produce_obj = produce_obj
        self.next = None
        # Doubly-linked-list pair unlinked on the old==2 release path.
        self.link_prev = None
        self.link_next = None

    def __repr__(self):
        return ("VersionNode(marker=%#x, refcount=%d, flag=%d)"
                % (self.marker, self.refcount, self.flag))


class VersionRelease:
    """0x5d911e0: refcount release of a version node.

    lock xadd -1 to the refcount at +0x38; the old value decides:
    old == 1 -> full teardown (hook teardown) and sized delete of
    0x9e8 bytes, returns 1; old == 2 -> unlink the +0x920/+0x930
    pair, delete the +0x930 object, then the conditional free
    (hook conditional_free) decides the rest, returns 1 when it
    frees and 0 when it does not; any other old value -> return 0.
    The opaque sub-callees (0x5d8fef0, 0x61d3c90, 0x5d8bc70,
    0x5d910e0, 0x5d8d820) are hooks, not modelled internals.
    """

    def __init__(self, teardown=None, conditional_free=None):
        self.teardown = teardown or (lambda node: None)
        self.conditional_free = conditional_free or (lambda node: False)
        self.calls = []

    def __call__(self, node):
        self.calls.append(node)
        old = node.refcount
        node.refcount = old - 1
        if old == 1:
            self.teardown(node)
            return 1
        if old == 2:
            node.link_prev = None
            node.link_next = None
            if self.conditional_free(node):
                return 1
            return 0
        return 0


def mutex_unlock(status):
    """0x60d52f0: pthread_mutex_unlock wrapper.

    Returns silently when the unlock status is 0, 0x10 or 0x6e;
    any other status prints 'pthread unlock: %s' (format at
    0x43742f, 'unlock' at 0x43948f) and aborts.
    """
    if status in (0, 0x10, 0x6E):
        return None
    raise AbortError("pthread unlock: status %#x" % status)


class LoggerSink:
    """The log sink object behind the +0x360 field.

    slot +0x40 is the level gate (GetInfoLogLevel), slot +0x18 the
    level-5 log call, slot +0x28 the general log call taking
    (level, format, va_list). The model records calls instead of
    formatting.
    """

    def __init__(self, level=2):
        self.level = level
        self.calls = []

    def get_level(self):
        return self.level

    def log_general(self, level, fmt, varargs):
        self.calls.append(("general", level, fmt, tuple(varargs)))

    def log_level5(self, fmt, varargs):
        self.calls.append(("level5", fmt, tuple(varargs)))


def log_dispatch(level, sink, fmt, file_name, *varargs):
    """0x5fcf060: level-gated log dispatch.

    When the sink is null, nothing happens. When level exceeds the
    sink's level (slot +0x40), nothing is logged. Level 5 goes to
    slot +0x18; every other admitted level goes to slot +0x28 with
    the constructed va_list whose varargs are (file_name, *varargs).
    """
    if sink is None:
        return None
    if level > sink.get_level():
        return None
    if level == 5:
        sink.log_level5(fmt, (file_name,) + tuple(varargs))
    else:
        sink.log_general(level, fmt, (file_name,) + tuple(varargs))
    return None


def trim_trailing_digits(data):
    """The trailing-digit trim shared by 0x5eee790 and 0x5eee9f0.

    Counts the trailing ASCII digits ('0'..'9') and returns
    (trimmed_data, trailing_count). An all-digit input trims to
    empty with the full length as the count.
    """
    count = 0
    end = len(data)
    while end > 0 and 0x30 <= data[end - 1] <= 0x39:
        end -= 1
        count += 1
    return data[:end], count


class Registry:
    """The global registry behind 0x5eee790 (global at 0x6502a40).

    Lookup by the digit-trimmed name. At most 0x14 (20) entries the
    binary scans a linked list comparing (length, bytes); above
    that it hashes with _Hash_bytes and seed 0xc70f6907 and walks
    the bucket chain comparing the stored hash, length and bytes.
    Both paths return the entry's +0x28 slot, or None on a miss.
    The model keeps one dict; the two paths are an implementation
    detail of the same lookup.
    """

    SMALL_LIMIT = 0x14
    HASH_SEED = 0xC70F6907

    def __init__(self):
        self.entries = {}

    def register(self, name, value):
        if isinstance(name, str):
            name = name.encode("utf-8")
        self.entries[bytes(name)] = value

    def lookup(self, name):
        """0x5eee790: return the entry's +0x28 slot, or None."""
        if isinstance(name, str):
            name = name.encode("utf-8")
        trimmed, _count = trim_trailing_digits(bytes(name))
        return self.entries.get(trimmed)


def trim_invoke(obj, entry, name, dump_string, factories):
    """0x5eee9f0: trim the name, then tail-jump to the factory.

    The factory is selected from the registry entry (its +0x08
    slot, or the double-dereferenced slot when the entry's flag bit
    is set). The model takes the factory map as an argument: the
    entry names the factory, the call appends to dump_string.
    Returns the factory's result (the binary tail-jumps, so the
    caller never sees a return frame of its own).
    """
    if entry is None:
        return None
    trimmed, _count = trim_trailing_digits(
        name if isinstance(name, bytes) else name.encode("utf-8"))
    factory = factories.get(entry)
    if factory is None:
        return None
    return factory(obj, trimmed, dump_string)


class HashTable:
    """The stack-built libstdc++ _Hashtable at rsp+0x30.

    Single-bucket start (buckets point at the inline slot), bucket
    count 1, max load factor 1.0. Nodes are 16 bytes: next at +0x00,
    key pointer at +0x08. The bucket array stores the node BEFORE
    the first node of each bucket; the before-begin chain holds
    every node in insertion order. _M_need_rehash is consulted on
    every insert with (element_count, bucket_count, 1); the exact
    trigger formula is an inference from the call shape and the
    libstdc++ prime policy, recorded as such in the README.
    """

    def __init__(self):
        self.buckets = [None]  # single-bucket start
        self.bucket_count = 1
        self.before_begin = None  # head of the node chain
        self.count = 0
        self.max_load_factor = 1.0
        self.rehashes = []  # (old_count, new_count) trace
        self.nodes = []  # nodes in insertion order (for cleanup)
        self.inserted = []  # keys ever inserted (survives cleanup)

    def _bucket_of(self, key):
        return (id(key) % self.bucket_count
                if self.bucket_count else 0)

    def _need_rehash(self):
        # Inference: rehash when the new element would push the
        # load past max_load_factor; grow to the next prime above
        # the required minimum bucket count.
        if self.count + 1 <= self.bucket_count * self.max_load_factor:
            return None
        needed = int((self.count + 1) / self.max_load_factor) + 1
        return next_prime_at_least(max(needed, self.bucket_count + 1))

    def find(self, key):
        """True when a node with this key pointer is already stored."""
        node = self.before_begin
        while node is not None:
            if node["key"] is key:
                return True
            node = node["next"]
        return False

    def insert(self, key):
        """Insert the key pointer; returns True when it was new."""
        if self.find(key):
            return False
        new_count = self._need_rehash()
        if new_count is not None:
            self.rehashes.append((self.bucket_count, new_count))
            self.bucket_count = new_count
            self.buckets = [None] * new_count
        node = {"key": key, "next": self.before_begin}
        self.before_begin = node
        self.nodes.append(node)
        self.inserted.append(key)
        # Rebuild the bucket heads (predecessor pointers) for the
        # new chain; the binary stores the predecessor node per
        # bucket, which the model keeps as bucket -> first node.
        bucket = self._bucket_of(key)
        self.buckets[bucket] = node
        self.count += 1
        return True

    def cleanup(self):
        """Free every node, zero the buckets, drop the array.

        Returns the list of freed nodes (the binary deletes each
        16-byte node via the before-begin chain, memsets the bucket
        array, and deletes the array only when it is not the inline
        single-bucket slot).
        """
        freed = list(self.nodes)
        self.nodes = []
        self.before_begin = None
        self.buckets = [None] * len(self.buckets)
        self.count = 0
        return freed


class StatsEmitCaller:
    """The 0x5d7dfc0 routine with injectable callee hooks.

    Hooks (all optional; defaults record calls and return the
    neutral value):
      acquire(mutex): the instrumented lock 0x606ca40.
      unlock(mutex): the mutex-unlock wrapper 0x60d52f0.
      refresh(subobject): the per-version refresh 0x5eef8a0
          (opaque here; a separate work item pins its internals).
      produce(produce_obj, name): the virtual slot +0x38 call;
          returns a key object or None.
      key_dispatch(key, sink): the virtual slot +0xd0 call, run
          only for a newly inserted key whose slot differs from
          the identity function 0x5d3a940.
      key_slot(key): returns the slot +0xd0 function identity for
          a key (default IDENTITY, i.e. no dispatch).
      registry_lookup(name): the 0x5eee790 lookup.
      emit(level, sink, fmt, file_name, *args): the 0x5fcf060 call.
      stats_emit(obj): the 0x5d52020 call.
      malloc_hook(dump_string): the 0x5f04ce0 hook; the binary's
          hook is a 5-byte no-op, so the default fills nothing.
      release(node): the 0x5d911e0 version release.
    """

    def __init__(self, obj, hooks=None):
        self.obj = obj
        self.hooks = hooks or {}
        self.dump_string = StdString()
        self.table = HashTable()
        self.trace = []
        self._acquire = self.hooks.get("acquire", lambda m: None)
        self._unlock = self.hooks.get("unlock", lambda m: None)
        self._refresh = self.hooks.get("refresh", lambda s: None)
        self._produce = self.hooks.get(
            "produce", lambda o, n: None)
        self._key_dispatch = self.hooks.get(
            "key_dispatch", lambda k, s: None)
        self._key_slot = self.hooks.get(
            "key_slot", lambda k: IDENTITY)
        self._registry_lookup = self.hooks.get(
            "registry_lookup", lambda n: None)
        self._emit = self.hooks.get("emit", lambda *a: None)
        self._stats_emit = self.hooks.get("stats_emit", lambda o: None)
        self._malloc_hook = self.hooks.get(
            "malloc_hook", lambda d: None)
        self._release = self.hooks.get("release", lambda n: 0)

    # -- version-list helpers -------------------------------------
    def _head(self):
        chain = self.obj["versions_chain"]
        return chain["head"]

    def _advance(self, cur):
        """The 0x5d7e1c9 advance: release cur, move to next.

        If cur's marker differs from SENTINEL, release it; then
        cur = next; if next's marker differs, bump its refcount
        and resume at the loop head.
        """
        nxt = cur.next
        if cur.marker != SENTINEL:
            self._release(cur)
        if nxt.marker != SENTINEL:
            nxt.refcount += 1
        return nxt

    def _walk(self):
        """Phase 1: the version walk with per-node work."""
        obj = self.obj
        head = self._head()
        cur = head.next
        # Entry refcount protocol: bump cur (and reload the head)
        # when the marker differs from the sentinel.
        if cur.marker != SENTINEL:
            cur.refcount += 1
            head = self._head()
            if head.marker != SENTINEL:
                head.refcount += 1
        elif head.marker != SENTINEL:
            head.refcount += 1
        while cur is not head:
            if cur.flag == 0:
                cur = self._advance(cur)
                continue
            self._unlock(obj["mutex"])
            self._refresh(cur.subobject)
            if obj["sink"] is not None:
                name = StdString()
                string_assign(name, PRODUCE_NAME)
                key = self._produce(cur.produce_obj, PRODUCE_NAME)
                name.dispose()
                if key is not None:
                    if self.table.insert(key):
                        if self._key_slot(key) != IDENTITY:
                            self._key_dispatch(key, obj["sink"])
            self._acquire(obj["mutex"])
            cur = self._advance(cur)
        # Head release dance on loop exit (0x5d7e1f8/0x5d7e4a8):
        # release the head while its marker differs, re-testing
        # after each call; the binary shows at most two calls.
        if head.marker != SENTINEL:
            self._release(head)
            if head.marker != SENTINEL:
                self._release(head)

    def _registry_phase(self):
        """Phase 2: two registry factory invocations."""
        obj = self.obj
        first = self._registry_lookup(
            obj["registry_slice_first"])
        trim_invoke(obj["factory_obj"], first,
                    obj["registry_slice_first"], self.dump_string,
                    obj["factories"])
        second = self._registry_lookup(
            obj["registry_slice_second"])
        head = self._head()
        cur = head.next
        while cur is not head:
            if cur.flag != 0:
                trim_invoke(cur.subobject, second,
                            obj["registry_slice_second"],
                            self.dump_string, obj["factories"])
            cur = cur.next

    def _emit_phase(self):
        """Phase 3: the two dump emits, malloc branch, stats emit."""
        obj = self.obj
        self._unlock(obj["mutex"])
        self._emit(1, obj["sink"], FORMAT_DUMPING, FILE_NAME)
        self._emit(1, obj["sink"], FORMAT_DUMP,
                   FILE_NAME, self.dump_string.data)
        if obj["malloc_flag"] != 0:
            # Truncate the dump string, run the hook, emit the
            # malloc stats only when the hook filled the string.
            self.dump_string = StdString()
            self._malloc_hook(self.dump_string)
            if len(self.dump_string) != 0:
                self._emit(1, obj["sink"], FORMAT_MALLOC, FILE_NAME)
                self._emit(1, obj["sink"], FORMAT_MALLOC_DUMP,
                           FILE_NAME, self.dump_string.data)
        self._stats_emit(obj)

    def _cleanup(self):
        """Free the hash nodes, clear the table, dispose the string."""
        freed = self.table.cleanup()
        self.dump_string.dispose()
        return freed

    def run(self):
        """The whole routine, in order. Returns the freed nodes."""
        obj = self.obj
        if obj["skip_flag"] != 0:
            self.dump_string.dispose()
            self.trace.append("skipped")
            return []
        self._acquire(obj["mutex"])
        self._walk()
        self._registry_phase()
        self._emit_phase()
        freed = self._cleanup()
        self.trace.append("done")
        return freed


def new_obj(**overrides):
    """A fresh owner object with the fields the routine reads."""
    head = VersionNode()
    head.next = head
    obj = {
        "skip_flag": 0,
        "mutex": object(),
        "sink": LoggerSink(),
        "malloc_flag": 0,
        "stats_ptr": object(),
        "factory_obj": object(),
        "registry_slice_first": b"first-slice",
        "registry_slice_second": b"second-slice",
        "factories": {},
        "versions_chain": {"head": head},
    }
    obj.update(overrides)
    return obj
