"""Python model of node #115's ObjectLibrary registry end-to-end (RE-001).

Faithful model of the 31 windows in
research/work-items/RE-001-objectlibrary-registry-115/:
the function-local-static Default getter 0x61f8b60, the registry
count 0x61f8700, the unordered-map find-or-insert 0x5fd1da0 with
its rehash 0x5fd1c60 and vector-insert 0x5fd17c0, the registration
entry points insert 0x5fd24c0 / default-init 0x5fd20d0 / register
0x5fd27c0 (both reached through pthread_once guards), the
_Sp_counted_ptr_inplace<ObjectLibrary> control block (D1 0x5fefc70,
D0 0x5fefd00, _M_dispose 0x5ff7900, _M_destroy 0x5fefd50,
_M_get_deleter 0x5feff70) with the map destroy 0x5ff7820, the
PatternEntry vtable (D2 0x5ff2030, D0 0x5ff2150, Matches 0x61f8670,
pattern accessor 0x61f8120) with the string matcher 0x61f8430 and
the per-element matcher 0x61f8280, and the FactoryEntry node
vtables for Env (D2 0x5fcc700, D0 0x5fcd840, forwarders 0x5fcc7e0 /
0x5fcc7f0) and for SystemClock (D2 0x5fcc6b0, D0 0x5fcd7f0,
forwarders 0x5fcc7c0 / 0x5fcc7d0) plus the _Sp_counted_ptr<Env*>
control block (D1 0x5fcc6a0, D0 0x5fcc830).

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

The one behaviour this model does NOT reproduce byte-for-byte is
the hash itself: the binary calls libstdc++ _Hash_bytes(key, len,
0xc70f6907) and the model substitutes a deterministic stand-in
hash. Bucket placement (hash % bucket_count), the chain walk
(hash, then length, then memcmp), rehashing and every count are
modelled exactly; the stand-in only changes WHICH bucket a key
lands in, never whether it is found.
"""

# --- constants pinned by the binary -----------------------------------

# ObjectLibrary object: 0x80 bytes; name "default" at +0x60.
REGISTRY_SIZE = 0x80
REGISTRY_NAME = "default"
# The function-local-static holder (16 bytes: object ptr, control ptr).
HOLDER_ADDR = 0x6509110
HOLDER_GUARD_ADDR = 0x6509108
# make_shared block: 0x90 bytes (0x10 control + 0x80 object).
CONTROL_BLOCK_SIZE = 0x90
OBJECT_SIZE = 0x80
# A fresh control block starts at counts 0x100000001 = (use 1, weak 1).
FRESH_COUNTS = 0x100000001
# _Hash_bytes seed.
HASH_SEED = 0xC70F6907
# unordered_map node: 0x48 bytes.
MAP_NODE_SIZE = 0x48
# PatternEntry: 0x70 bytes. FactoryEntry node: 0x30 bytes.
PATTERN_ENTRY_SIZE = 0x70
FACTORY_NODE_SIZE = 0x30
# The map key every insert() registration lands under; the
# exception is default-init, which uses SYSTEMCLOCK_KEY.
ENVIRONMENT_KEY = "Environment"
SYSTEMCLOCK_KEY = "SystemClock"
# Pattern strings registered through insert() / default-init().
MOCK_ENV_PATTERN = "MockEnv"
COMPOSITE_ENV_PATTERN = "CompositeEnv"
TIME_EMULATED_PATTERN = "TimeEmulatedSystemClock"
# pthread_once guards that make registration run exactly once.
REGISTER_ONCE_GUARD = 0x6504BB8
DEFAULT_INIT_ONCE_GUARD = 0x6504B68
# The _Sp_make_shared_tag typeinfo GOT slot (cb _M_get_deleter).
MAKE_SHARED_TAG_GOT = 0x64ECDC8
# Vtable bases.
CONTROL_BLOCK_VTABLE = 0x64D00F0
PATTERN_ENTRY_VTABLE = 0x64D8ED0
NODE_ENV_VTABLE = 0x64CDE68
NODE_CLOCK_VTABLE = 0x64CDE98
ENV_PTR_CB_VTABLE = 0x64CDEC8
# The neighbouring _Sp_counted_ptr_inplace<ObjectRegistry> control
# block vtable that follows PatternEntry's vtable in .data.rel.ro
# (its dispose 0x61f8760 destroys a 0xc0-byte ObjectRegistry, a
# different class; recorded here only as the boundary).
OBJECT_REGISTRY_CB_VTABLE = 0x64D8F00
OBJECT_REGISTRY_SIZE = 0xC0
# FactoryEntry<Env> / <SystemClock> typeinfo names (mangled).
NODE_ENV_TYPEINFO = "N7rocksdb13ObjectLibrary12FactoryEntryINS_3EnvEEE"
NODE_CLOCK_TYPEINFO = (
    "N7rocksdb13ObjectLibrary12FactoryEntryINS_11SystemClockEEE"
)
PATTERN_ENTRY_TYPEINFO = "N7rocksdb13ObjectLibrary12PatternEntryE"

# libstdc++ prime bucket counts (the _Prime_rehash_policy table the
# binary's inlined _M_need_rehash consults). The model only needs
# the first few: the registry starts at 1 bucket and grows from
# there.
_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
           53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def _is_ascii_digits(s):
    """The binary's digit loops test ('0' <= c <= '9') on bytes;
    Python's str.isdigit() also accepts non-ASCII digits."""
    return bool(s) and all("0" <= c <= "9" for c in s)


def _next_prime(n):
    for p in _PRIMES:
        if p >= n:
            return p
    raise ValueError("bucket count beyond modelled prime table")


def _hash_bytes(data, seed=HASH_SEED):
    """Stand-in for libstdc++ _Hash_bytes: deterministic, same
    contract (bytes + seed -> 64-bit hash). The binary's hash is
    MurmurHash64A-style; the model pins placement and lookup, not
    the hash value itself."""
    h = seed ^ 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


# --- the map ------------------------------------------------------------

class MapNode:
    """One unordered_map node (0x48 bytes): next, key string,
    value vector of FactoryEntry pointers, stored hash."""

    __slots__ = ("next", "key", "values", "hash")

    def __init__(self, key, h):
        self.next = None
        self.key = key
        self.values = []  # vector<FactoryEntry*>: begin/end/cap
        self.hash = h


class UnorderedMap:
    """std::unordered_map<std::string, vector<FactoryEntry*>> as
    laid out in the registry: buckets, bucket_count, before_begin,
    element_count, max_load_factor 1.0, next_resize, single bucket."""

    def __init__(self):
        self.buckets = [None]  # single bucket at +0x58
        self.bucket_count = 1
        self.element_count = 0
        self.max_load_factor = 1.0
        self.next_resize = 0
        self.destroyed = False

    def _need_rehash(self, n):
        """_Prime_rehash_policy::_M_need_rehash: rehash when the
        incoming element count exceeds next_resize."""
        if n <= self.next_resize:
            return None
        new_count = _next_prime(max(self.next_resize * 2, n))
        return new_count

    def _rehash(self, new_count):
        """0x5fd1c60 _M_rehash_aux: fresh bucket array, re-link
        every node by hash % new_count, free the old array unless
        it was the single bucket."""
        new_buckets = [None] * new_count
        for head in self.buckets:
            node = head
            while node is not None:
                nxt = node.next
                b = node.hash % new_count
                node.next = new_buckets[b]
                new_buckets[b] = node
                node = nxt
        self.buckets = new_buckets
        self.bucket_count = new_count
        self.next_resize = int(new_count * self.max_load_factor)

    def find_or_insert(self, key):
        """0x5fd1da0: hash, walk the bucket chain comparing stored
        hash, then key length, then memcmp; on a miss allocate a
        0x48-byte node, rehash if the policy demands, link it and
        return its value vector."""
        h = _hash_bytes(key.encode())
        b = h % self.bucket_count
        node = self.buckets[b]
        while node is not None:
            if (node.hash == h and len(node.key) == len(key)
                    and node.key == key):
                return node.values
            node = node.next
        new_count = self._need_rehash(self.element_count + 1)
        if new_count is not None:
            self._rehash(new_count)
            b = h % self.bucket_count
        node = MapNode(key, h)
        node.next = self.buckets[b]
        self.buckets[b] = node
        self.element_count += 1
        return node.values

    def find(self, key):
        """Read-only lookup (the registry's find path): same chain
        walk, no insertion."""
        h = _hash_bytes(key.encode())
        node = self.buckets[h % self.bucket_count]
        while node is not None:
            if (node.hash == h and len(node.key) == len(key)
                    and node.key == key):
                return node.values
            node = node.next
        return None

    def destroy(self):
        """0x5ff7820: walk before_begin, per node destroy each
        value-vector element through its vtable slot 1 (D0), free
        the vector buffer, destroy the key string, delete the
        0x48-byte node; free the bucket array unless single."""
        for head in list(self.buckets):
            node = head
            while node is not None:
                nxt = node.next
                for entry in node.values:
                    entry.destroy()  # node vtable slot 1 (D0)
                node.values = []
                node = nxt
        self.buckets = [None]
        self.bucket_count = 1
        self.element_count = 0
        self.destroyed = True


# --- PatternEntry -------------------------------------------------------

class SubPattern:
    """One 0x28-byte element of the +0x58 vector: a string plus the
    mode that governs the NEXT element's match (element 0 is
    governed by the initial mode 2; the last element's mode
    governs the tail)."""

    __slots__ = ("text", "mode")

    def __init__(self, text, mode):
        self.text = text
        self.mode = mode


def _elem_match(entry, pos, query, mode, elem):
    """0x61f8280: match one sub-pattern element starting at pos in
    the query. Returns the new position, or -1 on failure.

    mode 2: the element string must occur AT pos; returns
    pos + len(elem). mode 0/1: std::string::find from pos+1, so the
    element may occur anywhere later; returns found + len(elem).
    mode 3: like 0/1, but the gap between pos and the found
    position (after an optional '-') must be all digits. mode 4:
    like 3, but the gap may contain at most one '.' and must hold
    at least one digit. An empty element in modes 0/1 returns
    pos+1; mode 2 with an empty element returns pos."""
    text = elem.text
    qlen = len(query)
    if pos + len(text) > qlen:
        return -1
    if mode == 2:
        if pos > qlen:
            raise ValueError("pos out of range")
        if query[pos:pos + len(text)] != text:
            return -1
        return pos + len(text)
    # modes 0/1/3/4: find the element string from pos+1.
    start = pos + 1
    if len(text) == 0:
        found = start
    else:
        found = query.find(text, start)
    if found == -1:
        return -1
    if mode == 3:
        gap = query[pos:found]
        if gap.startswith("-"):
            gap = gap[1:]
        if not _is_ascii_digits(gap):
            return -1
    elif mode == 4:
        gap = query[pos:found]
        if gap.startswith("-"):
            gap = gap[1:]
        digits = gap.replace(".", "", 1)
        if not _is_ascii_digits(digits) or gap.count(".") > 1:
            return -1
    return found + len(text)


def _str_match(entry, pattern, query):
    """0x61f8430: match pattern (a string) against the query.

    Empty sub-pattern vector: exact match only, no flag check.
    Equal lengths with a non-empty vector: exact match, and the
    entry's +0x48 flag must be set. Otherwise the query must start
    with the pattern (query_len >= entry.offset + pattern_len,
    where entry.offset is the +0x50 field, 0 for fresh entries),
    then every sub-pattern element must match in sequence, and
    the tail decides by the last element's mode: mode 2 requires
    the position to reach the end of the query; modes 3/4 require
    the remainder (after an optional '-') to be digits / dotted
    digits with at least one digit; any other mode accepts."""
    vec = entry.elements
    plen = len(pattern)
    qlen = len(query)
    if not vec:
        return plen == qlen and pattern == query
    if plen == qlen:
        if not entry.flag:
            return False
        return pattern == query
    if qlen < entry.offset + plen:
        return False
    if query[:plen] != pattern:
        return False
    pos = plen
    mode = 2
    for elem in vec:
        pos = _elem_match(entry, pos, query, mode, elem)
        if pos == -1:
            return False
        mode = elem.mode
    if mode == 2:
        return pos == qlen
    if qlen < pos:
        return False
    if mode != 0 and pos == qlen:
        return False
    if mode == 3:
        rest = query[pos:]
        if rest.startswith("-"):
            rest = rest[1:]
        return _is_ascii_digits(rest)
    if mode == 4:
        rest = query[pos:]
        if rest.startswith("-"):
            rest = rest[1:]
        digits = rest.replace(".", "", 1)
        return _is_ascii_digits(digits) and rest.count(".") <= 1
    return True


class PatternEntry:
    """rocksdb::ObjectLibrary::PatternEntry (0x70 bytes): vtable,
    pattern string, pattern-length copy, sub-pattern strings
    (+0x30), flag byte (+0x48, 1), pointer (+0x50, 0), sub-pattern
    elements (+0x58)."""

    __slots__ = ("pattern", "pattern_len", "subpatterns", "flag",
                 "offset", "elements", "destroyed")

    def __init__(self, pattern):
        self.pattern = pattern
        self.pattern_len = len(pattern)
        self.subpatterns = []  # vector<string> at +0x30
        self.flag = 1
        self.offset = 0  # +0x50
        self.elements = []  # vector<SubPattern> at +0x58
        self.destroyed = False

    def matches(self, query):
        """0x61f8670 (vtable slot 2): the pattern itself, then each
        string in the +0x30 vector, through _str_match."""
        if _str_match(self, self.pattern, query):
            return True
        for sub in self.subpatterns:
            if _str_match(self, sub, query):
                return True
        return False

    def pattern_string(self):
        """0x61f8120 (vtable slot 3): returns &pattern."""
        return self.pattern

    def destroy(self):
        """0x5ff2030 (D2): destroy the +0x58 vector elements, free
        its buffer; destroy the +0x30 vector elements, free its
        buffer; destroy the pattern string. D0 (0x5ff2150) does
        the same and deletes the 0x70-byte object."""
        self.elements = []
        self.subpatterns = []
        self.destroyed = True


# --- FactoryEntry nodes ---------------------------------------------------

class FactoryEntry:
    """One 0x30-byte FactoryEntry node: vtable (Env or
    SystemClock), PatternEntry pointer, std::function (functor,
    manager, invoker). The manager/invoker pair is the factory
    callable; the model stores the callable directly."""

    __slots__ = ("kind", "entry", "factory", "destroyed")

    def __init__(self, kind, entry, factory):
        self.kind = kind  # "Env" or "SystemClock"
        self.entry = entry
        self.factory = factory
        self.destroyed = False

    def matches(self, query):
        """Node vtable slot 2 forwards to the entry's Matches."""
        return self.entry.matches(query)

    def pattern(self):
        """Node vtable slot 3 forwards to the entry's accessor."""
        return self.entry.pattern_string()

    def destroy(self):
        """Node D2 (0x5fcc700 / 0x5fcc6b0): destroy the
        std::function (manager op 3), then tail-jump to the
        entry's D0. D0 (0x5fcd840 / 0x5fcd7f0) also deletes the
        0x30-byte node."""
        self.entry.destroy()
        self.destroyed = True


# --- the registry ---------------------------------------------------------

class ObjectLibrary:
    """rocksdb::ObjectLibrary (0x80 bytes): mutex (+0x00..0x28),
    unordered_map (+0x28), name string (+0x60, "default").
    The singleton is created once by Default(); the model keeps
    the pthread_once guards that make register() and
    default_init() run exactly once."""

    def __init__(self):
        self.map = UnorderedMap()
        self.name = REGISTRY_NAME
        self.locked = False
        self._register_done = False
        self._default_init_done = False
        self.destroyed = False
        self._dispose_order = []

    # -- 0x61f8b60 Default() -------------------------------------------
    @staticmethod
    def default():
        """Function-local-static singleton: first call allocates
        the 0x10-byte holder and the 0x90-byte make_shared block,
        fills the control block (vtable 0x64D00F0, counts
        0x100000001), zeroes the mutex, builds the map (1 bucket)
        and the name "default"; later calls return the holder."""
        return ObjectLibrary()

    # -- 0x61f8700 count ------------------------------------------------
    def count(self):
        """Lock the mutex; *out = number of distinct map keys;
        return the total number of registered entries."""
        self.locked = True
        try:
            keys = self.map.element_count
            total = 0
            for head in self.map.buckets:
                node = head
                while node is not None:
                    total += len(node.values)
                    node = node.next
            return keys, total
        finally:
            self.locked = False

    # -- 0x5fd24c0 insert ------------------------------------------------
    def insert(self, pattern, kind, factory):
        """Build a 0x30-byte FactoryEntry node (vtable A for Env,
        B for SystemClock) and a 0x70-byte PatternEntry, lock the
        registry, find-or-insert the key "Environment", append the
        node to the returned vector (fast path inline, slow path
        through vector-insert 0x5fd17c0 which moves the value out
        of the source slot, zeroing it), unlock."""
        entry = PatternEntry(pattern)
        node = FactoryEntry(kind, entry, factory)
        self.locked = True
        try:
            vec = self.map.find_or_insert(ENVIRONMENT_KEY)
            vec.append(node)  # vector-insert: move semantics
        finally:
            self.locked = False
        return node

    # -- 0x5fd20d0 default-init ------------------------------------------
    def default_init(self):
        """Registers "TimeEmulatedSystemClock" under the map key
        "SystemClock" (the only registration that does NOT use
        the "Environment" key), then calls count(). Reached
        through pthread_once guard 0x6504B68, so it runs once."""
        if self._default_init_done:
            return None
        self._default_init_done = True
        entry = PatternEntry(TIME_EMULATED_PATTERN)
        node = FactoryEntry("SystemClock", entry, "SystemClockFactory")
        self.locked = True
        try:
            vec = self.map.find_or_insert(SYSTEMCLOCK_KEY)
            vec.append(node)
        finally:
            self.locked = False
        self.count()
        return node

    # -- 0x5fd27c0 register ----------------------------------------------
    def register(self):
        """Registers "MockEnv" then "CompositeEnv" through
        insert() (both under "Environment"), then calls count().
        Reached through pthread_once guard 0x6504BB8 from two
        hosts, so it runs once."""
        if self._register_done:
            return None
        self._register_done = True
        self.insert(MOCK_ENV_PATTERN, "Env", "MockEnvFactory")
        self.insert(COMPOSITE_ENV_PATTERN, "Env", "CompositeEnvFactory")
        self.count()
        return True

    # -- control block teardown -----------------------------------------
    def dispose(self):
        """0x5ff7900 _M_dispose: destroy the name string, destroy
        the map (0x5ff7820), free the bucket array unless it is
        the single bucket. _M_destroy (0x5fefd50) then deletes
        the 0x90-byte block; D1 (0x5fefc70) is a bare return."""
        self.name = ""
        self.map.destroy()
        self.destroyed = True

    def get_deleter(self, type_name):
        """0x5feff70 _M_get_deleter: returns the object address
        (+0x10) only for the _Sp_make_shared_tag typeinfo (name
        "St19_Sp_make_shared_tag"), else null; a name starting
        with '*' also returns null."""
        if type_name.startswith("*"):
            return None
        if type_name == "St19_Sp_make_shared_tag":
            return self
        return None


def vector_insert(vec, pos, value):
    """0x5fd17c0 std::vector<T*>::insert: grow by doubling (cap at
    0x7ffffffffffffff8), shift the tail, move the value OUT of
    the source slot (the source is zeroed), free the old buffer.
    The model returns the moved value; the caller's slot is
    cleared by setting vec[pos] to None first in the test."""
    if pos < 0 or pos > len(vec):
        raise IndexError("insert position out of range")
    vec.insert(pos, value)
    return value
