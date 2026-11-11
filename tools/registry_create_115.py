"""RE-001: create a Statistics object from a registered factory by
name (node #115).

Bounded question: after the host 0x6077820 has looked a name up in
the registry (Find pair 0x609e510/0x609a410), how does node #115
turn the found factory into a live ``shared_ptr<Statistics>`` --
and what does it report when there is no factory, or when the
factory's creator fails?

Behaviour, pinned from the node #115 binary
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

  * Translator 0x6076b20: calls the registry find 0x6076620, then
    invokes the found creator (functor slot +0x00, manager +0x10,
    creator +0x18) with (functor, name, &slot, &err_string). The
    creator returns the new object pointer, or null on failure.
  * Find 0x6076620: locks the registry mutex at +0x98, walks the
    registry's vector (begin +0x00, end +0x08) last-to-first; each
    0x10-byte entry points at a {pthread_mutex_t, unordered_map}
    struct (map at +0x28). The map is keyed by type name: the
    ``"Statistics"`` key (10 bytes) is found by a linear
    before-begin walk while the element count is <= 20, else by a
    hash-bucket walk (_Hash_bytes, seed 0xc70f6907). The first
    FactoryEntry whose pattern Matches the name wins; its creator
    functor is cloned (manager op 2) into the 32-byte result
    {functor[16], manager, creator}. No match in this registry
    recurses into the parent at +0x60; no parent at all zeroes
    the result (manager null = not found).
  * Status builder 0x61cf670: out = {code u8 +0x00, subcode u8
    +0x01, severity u8 +0x02, msg char* +0x08}; the message is
    msg1, or msg1 + ": " + msg2 when the second string is
    non-empty. The translator reports three failures this way:
    no factory -> code 3, "Could not load to Statistics";
    creator returned null with an empty error string -> code 4,
    "Could not load to Statistics"; creator returned null with
    a message -> code 4, that message; creator returned a
    non-null pointer without installing it in the slot ->
    code 4, "Cannot make a shared Statistics from unguarded
    one ". The success path wraps the installed object in a
    shared_ptr<Statistics> (control 0x18 bytes, vptr 0x64d2f00,
    counts 0x100000001), installs the {obj, control} pair into
    the caller's slot and then releases the caller's old control
    (0x5d35070 protocol); the out Status is OK.
  * Manager 0x606fa50: op 0 returns the functor typeinfo
    0x64d2d28, op 1 returns the functor pointer, ops 2 (clone)
    and 3 (destroy) are no-ops -- the BasicStatistics creator
    lambda captures nothing, so the functor slot stays zero.
  * Creator 0x6071ba0 (re-shipped from #3386): builds a fresh
    0x70-byte StatisticsImpl (ctor 0x6071a00, vptr 0x64d2d88,
    flags byte 3), installs it into the caller's Statistics*
    slot, deleting any old occupant through dtor 0x6070ea0, and
    returns the new object. It ignores the name and the
    error-string arguments, so it never writes the error string
    and never returns null for this factory.
  * PatternEntry::Matches (0x61f8670) via helper 0x61f8430 and
    sub-matcher 0x61f8280 (re-shipped from #3386): the
    registered "BasicStatistics" entry has empty sub-pattern
    vectors, so it matches exactly "BasicStatistics"; the helper
    also supports prefix-plus-token patterns (modes 2 substring,
    3 integer, 4 float).
  * On the error paths the translator disposes any object left
    in the slot (dtor 0x6070ea0 when the vtable slot 1 is
    0x6071040, else the virtual deleting destructor); an
    exception escaping after creation destroys the created
    object the same way and rethrows. The "unguarded" path does
    NOT delete the object the creator returned.

Evidence packet: research/work-items/RE-001-registry-create-115/
"""

# --- Pinned addresses (node #115) -------------------------------------

TRANSLATOR = 0x6076B20
FIND_WRAPPER = 0x6076620
STATUS_BUILDER = 0x61CF670
HOST = 0x6077820
CREATOR = 0x6071BA0
MANAGER = 0x606FA50
STATS_CTOR = 0x6071A00
STATS_DTOR = 0x6070EA0
STATS_DTOR_DELETE = 0x6071040
SHARED_RELEASE = 0x5D35070

STATISTICS_IMPL_SIZE = 0x70
STATISTICS_IMPL_VPTR = 0x64D2D88
COUNTED_STATS_VPTR = 0x64D2F00
COUNTED_IMPL_VPTR = 0x64D2EC8
FACTORY_ENTRY_VPTR = 0x64D2E98
PATTERN_ENTRY_VPTR = 0x64D8ED0
FUNCTOR_TYPEINFO = 0x64D2D28

REGISTRY_MUTEX_OFFSET = 0x98
REGISTRY_PARENT_OFFSET = 0x60
ENTRY_STRUCT_SIZE = 0x60
MAP_OFFSET_IN_ENTRY = 0x28
LINEAR_WALK_LIMIT = 20
HASH_SEED = 0xC70F6907
TYPE_KEY = "Statistics"
TYPE_KEY_HASH = 0xD971F53C71278410

NOT_SUPPORTED = 3
INVALID_ARGUMENT = 4

MSG_COULD_NOT_LOAD = "Could not load to Statistics"
MSG_UNGUARDED = "Cannot make a shared Statistics from unguarded one "

MASK64 = (1 << 64) - 1


def hash_bytes(data, seed=HASH_SEED):
    """libstdc++ _Hash_bytes (MurmurHash64A, m 0xc6a4a7935bd1e995,
    r 47). Verified byte-for-byte against the system libstdc++ for
    21 inputs (empty, 1..12 bytes, the registry type names)."""
    if isinstance(data, str):
        data = data.encode()
    m = 0xC6A4A7935BD1E995
    r = 47
    h = (seed ^ ((len(data) * m) & MASK64)) & MASK64
    i = 0
    n = len(data)
    while i + 8 <= n:
        k = int.from_bytes(data[i:i + 8], "little")
        k = (k * m) & MASK64
        k ^= k >> r
        k = (k * m) & MASK64
        h ^= k
        h = (h * m) & MASK64
        i += 8
    if i < n:
        k = int.from_bytes(data[i:], "little")
        h ^= k
        h = (h * m) & MASK64
    h ^= h >> r
    h = (h * m) & MASK64
    h ^= h >> r
    return h


class Status:
    """The 16-byte result struct written by 0x61cf670 and by the
    translator/host: {code u8 +0x00, subcode u8 +0x01, severity
    u8 +0x02, u16 zero +0x03, u8 zero +0x05, msg char* +0x08}.
    The message is msg1, or msg1 + ": " + msg2."""

    def __init__(self, code=0, subcode=0, msg=None, severity=0):
        self.code = code
        self.subcode = subcode
        self.severity = severity
        self.msg = msg

    @classmethod
    def ok(cls):
        return cls(0, 0, None, 0)

    @classmethod
    def build(cls, code, subcode, msg1, msg2=None, severity=0):
        """0x61cf670: msg1 + ": " + msg2 when msg2 is non-empty."""
        if msg2:
            msg = msg1 + ": " + msg2
        else:
            msg = msg1
        return cls(code, subcode, msg, severity)

    def is_ok(self):
        return self.code == 0

    def __eq__(self, other):
        return (isinstance(other, Status)
                and self.code == other.code
                and self.subcode == other.subcode
                and self.severity == other.severity
                and self.msg == other.msg)

    def __repr__(self):
        return "Status(code=%d, subcode=%d, severity=%d, msg=%r)" % (
            self.code, self.subcode, self.severity, self.msg)


def submatch(mode, pattern, query, pos):
    """Sub-pattern matcher 0x61f8280 (re-shipped from #3386).

    Consumes one token from ``query`` starting at ``pos`` and
    returns the position after it, or -1 on failure. ``pattern``
    is the 0x28-byte record's string field; ``mode`` is its +0x20
    field: 2 = literal substring, 3 = integer, 4 = float, any
    other value = find the pattern text first.
    """
    if pos > len(query):
        return -1
    if mode == 2:
        if query[pos:pos + len(pattern)] != pattern:
            return -1
        end = pos + len(pattern)
        if end != len(query):
            return -1
        return end
    if mode == 3:
        i = pos
        if i < len(query) and query[i] == "-":
            i += 1
        start = i
        while i < len(query) and query[i].isdigit():
            i += 1
        if i == start:
            return -1
        return i
    if mode == 4:
        i = pos
        if i < len(query) and query[i] == "-":
            i += 1
        digits = 0
        seen_dot = False
        while i < len(query):
            ch = query[i]
            if ch.isdigit():
                digits += 1
                i += 1
            elif ch == "." and not seen_dot:
                seen_dot = True
                i += 1
            else:
                break
        if digits == 0:
            return -1
        return i
    found = query.find(pattern, pos)
    if found == -1:
        return -1
    return submatch(3, pattern, query, found + len(pattern))


class PatternEntry:
    """A 0x70-byte PatternEntry (vptr 0x64d8ed0).

    +0x8: name string, +0x28: name-length copy, +0x30: vector of
    additional 0x20-byte patterns, +0x48: exact-match flag,
    +0x50: prefix offset, +0x58: vector of 0x28-byte sub-pattern
    records. The registered "BasicStatistics" entry has both
    vectors empty, flag 1 and offset 0.
    """

    def __init__(self, name, flag=1, offset=0, extra_patterns=(),
                 sub_patterns=()):
        self.vptr = PATTERN_ENTRY_VPTR
        self.name = name
        self.name_length = len(name)
        self.flag = flag
        self.offset = offset
        self.extra_patterns = list(extra_patterns)
        self.sub_patterns = list(sub_patterns)

    def _helper(self, pattern, prefix_len, query):
        """Helper 0x61f8430 for one (pattern, prefix_len) pair."""
        if not self.sub_patterns:
            # Empty sub-pattern vector: the stored length must equal
            # the query length and the bytes must match exactly
            # (0x61f8580; the flag is not consulted on this path).
            return prefix_len == len(query) and pattern == query
        if prefix_len == len(query):
            # Whole query equals the pattern: the flag gates it
            # (0x61f8550); the sub-patterns are not consulted.
            return bool(self.flag) and pattern == query
        if self.offset + prefix_len > len(query):
            return False
        if len(pattern) > prefix_len or not query.startswith(pattern):
            return False
        pos = prefix_len
        for mode, text in self.sub_patterns:
            pos = submatch(mode, text, query, pos)
            if pos == -1:
                return False
        return pos == len(query)

    def matches(self, query):
        """Slot 2 (0x61f8670): own name, then each extra pattern."""
        if self._helper(self.name, self.name_length, query):
            return True
        for pattern, prefix_len in self.extra_patterns:
            if self._helper(pattern, prefix_len, query):
                return True
        return False

    def entry_name(self):
        """Slot 3 (0x61f8120): the name string's data pointer."""
        return self.name


class StatisticsImpl:
    """The 0x70-byte object built by ctor 0x6071a00 (from #3386)."""

    def __init__(self, hardware_concurrency=8, name=""):
        self.vptr = STATISTICS_IMPL_VPTR
        self.size = STATISTICS_IMPL_SIZE
        self.options_records = []
        self.flags_byte = 3
        self.name = name
        self.shared_slot = None
        self.mutex_locked = False
        self.shard_bits = 3 if hardware_concurrency <= 8 else 4
        self.shard_count = 1 << self.shard_bits
        self.destroyed = False
        self.deleted_size = None
        self.options_records.append(("StatisticsOptions", name, 0x6506200))

    def destroy(self):
        """Destructor 0x6070ea0: destroy shards, mutex, shared slot."""
        if self.destroyed:
            return
        self.destroyed = True
        self.mutex_locked = False
        self.shared_slot = None


def delete_object(obj):
    """The translator tail (0x6076cfb) / creator (0x6071bec) disposal:
    when the object's vtable slot 1 (deleting destructor) is
    0x6071040, call dtor 0x6070ea0 then sized delete 0x70; else
    call the virtual deleting destructor. Either way the object
    is destroyed; the size is recorded for the fast path."""
    if obj is None:
        return
    if obj.vptr == STATISTICS_IMPL_VPTR:
        obj.destroy()
        obj.deleted_size = STATISTICS_IMPL_SIZE
    else:
        obj.destroy()
        obj.deleted_size = None


class CountedPtr:
    """A shared_ptr control block (0x18 bytes).

    +0x0: counted_ptr vtable, +0x8: use 1 / weak 1 packed as
    0x100000001, +0x10: the managed object. _M_dispose deletes
    the object through its destructor; _M_destroy deletes the
    block. Release (0x5d35070): drop one use; at zero, dispose
    then destroy. The translator's 0x100000001 fast path and its
    atomic-dec path both converge on this.
    """

    def __init__(self, obj, vptr):
        self.vptr = vptr
        self.obj = obj
        self.use_count = 1
        self.weak_count = 1
        self.disposed = False
        self.destroyed = False

    def release(self):
        self.use_count -= 1
        if self.use_count == 0:
            self.dispose()
            self.destroy()

    def dispose(self):
        if self.obj is not None and not self.disposed:
            self.disposed = True
            delete_object(self.obj)
            self.obj = None

    def destroy(self):
        self.destroyed = True


class SharedPtrSlot:
    """A caller-side shared_ptr<T> slot: {obj, control}."""

    def __init__(self):
        self.obj = None
        self.control = None

    def install(self, obj, control):
        self.obj = obj
        self.control = control


class PtrSlot:
    """A plain Statistics* slot (the translator's rsp+0x38)."""

    def __init__(self):
        self.obj = None

    def get(self):
        return self.obj

    def set(self, obj):
        self.obj = obj


class FactoryEntry:
    """A 0x30-byte FactoryEntry<Statistics> (vptr 0x64d2e98).

    +0x8: PatternEntry*, +0x10..+0x1f: functor storage (zero for
    the stateless creator lambda), +0x20: manager 0x606fa50,
    +0x28: creator 0x6071ba0.
    """

    def __init__(self, pattern, creator=None):
        self.vptr = FACTORY_ENTRY_VPTR
        self.pattern = pattern
        self.manager = MANAGER
        # The functor slot is all zeros: the creator lambda
        # captures nothing (manager ops 2/3 are no-ops).
        self.functor = bytes(16)
        self.creator = creator if creator is not None else self._basic_creator

    def matches(self, query):
        """Slot 2 (0x606fb40): forward to the pattern's Matches."""
        return self.pattern.matches(query)

    def entry_name(self):
        """Slot 3 (0x606fb50): forward to the pattern's Name."""
        return self.pattern.entry_name()

    def _basic_creator(self, functor, name, slot, err_string):
        """Creator 0x6071ba0: build a fresh StatisticsImpl, install
        it into the caller's Statistics* slot (deleting any old
        occupant through 0x6070ea0), return the new object. The
        name and error-string arguments are ignored."""
        obj = StatisticsImpl()
        old = slot.get()
        slot.set(obj)
        if old is not None:
            delete_object(old)
        return obj


def manager_call(op, dest, src=None):
    """std::function manager 0x606fa50 for the creator lambda.

    op 0 returns the functor typeinfo 0x64d2d28; op 1 stores the
    functor pointer into dest; ops 2 (clone) and 3 (destroy) are
    no-ops returning 0. Returns (value, dest_after)."""
    if op == 0:
        dest[0] = FUNCTOR_TYPEINFO
        return 0, dest
    if op == 1:
        dest[0] = src
        return 0, dest
    return 0, dest


class RegistryMap:
    """An unordered_map<string, list[FactoryEntry]> in the binary's
    layout: buckets, bucket_count, before_begin list, element
    count, max_load_factor 1.0, next_resize, single_bucket. Nodes
    are {next +0x00, key string +0x08 (ptr/len/cap), value vector
    +0x28 (begin/end/cap), hash +0x40}, 0x48 bytes."""

    def __init__(self, bucket_count=1):
        self.bucket_count = bucket_count
        self.buckets = [None] * bucket_count
        self.before_begin = None
        self.element_count = 0
        self.max_load_factor = 1.0
        self.next_resize = 0

    def _find_node(self, key):
        """0x6076620's map search: a linear before-begin walk
        while the element count is <= 20 (comparing the stored
        length, then the key bytes in 8+2 chunks), else a
        hash-bucket walk (hash, length, memcmp)."""
        if self.element_count <= LINEAR_WALK_LIMIT:
            node = self.before_begin
            while node is not None:
                if node["key_len"] == len(key) and node["key"] == key:
                    return node
                node = node["next_list"]
            return None
        h = hash_bytes(key)
        bucket = h % self.bucket_count
        node = self.buckets[bucket]
        while node is not None:
            if node["hash"] == h and node["key_len"] == len(key) \
                    and node["key"] == key:
                return node
            node = node["next_bucket"]
        return None

    def find(self, key):
        node = self._find_node(key)
        return None if node is None else node["value"]

    def insert(self, key, value):
        """Insert mirroring the binary's node build: a 0x48-byte
        node linked at the head of its bucket chain and at the
        head of the before-begin list; rehash when the load
        factor would exceed 1.0 (prime growth, libstdc++ list)."""
        if self._find_node(key) is not None:
            raise KeyError("duplicate key %r" % key)
        if (self.element_count + 1) > self.bucket_count * self.max_load_factor:
            self._rehash()
        h = hash_bytes(key)
        bucket = h % self.bucket_count
        node = {"key": key, "key_len": len(key), "value": list(value),
                "hash": h, "next_list": self.before_begin,
                "next_bucket": self.buckets[bucket]}
        self.before_begin = node
        self.buckets[bucket] = node
        self.element_count += 1
        return node

    def _rehash(self):
        primes = [2, 3, 5, 7, 11, 13, 17, 23, 29, 37, 47, 59, 71, 89,
                  109, 131, 163, 197, 239, 293, 353, 431, 521, 631,
                  761, 919, 1103, 1327, 1597, 1931, 2333, 2801, 3371,
                  4049, 4861, 5839, 7013, 8419, 10103, 12143, 14591,
                  17519, 21023, 25229, 30293, 36353, 43627, 52361,
                  62851, 75431, 90523, 108631, 130363, 156437, 187751,
                  225307, 270371, 324449, 389357, 467237, 560689]
        target = self.element_count + 1
        # libstdc++ _M_next_bkt: the smallest prime >= target.
        new_count = next(p for p in primes if p >= target)
        nodes = []
        node = self.before_begin
        while node is not None:
            nodes.append(node)
            node = node["next_list"]
        self.bucket_count = new_count
        self.buckets = [None] * new_count
        for node in nodes:
            bucket = node["hash"] % new_count
            node["next_bucket"] = self.buckets[bucket]
            self.buckets[bucket] = node


class RegistryEntry:
    """One 0x10-byte vector entry: a {pthread_mutex_t (0x28),
    unordered_map (at +0x28)} struct, 0x60 bytes. The second
    vector word is not read by 0x6076620."""

    def __init__(self, registry_map=None):
        self.map = registry_map if registry_map is not None else RegistryMap()
        self.mutex_locked = False


class Registry:
    """An ObjectRegistry/ObjectLibrary node: a vector of
    RegistryEntry (searched last-to-first), a parent at +0x60,
    and a mutex at +0x98. Locks are modelled as no-ops."""

    def __init__(self, parent=None):
        self.entries = []
        self.parent = parent
        self.mutex_locked = False

    def add_entry(self, entry):
        self.entries.append(entry)


class FoundFactory:
    """The 32-byte find result: {functor[16] +0x00, manager
    +0x10, creator +0x18}. manager None means not found."""

    def __init__(self, manager=None, creator=None, functor=None):
        self.functor = functor if functor is not None else bytes(16)
        self.manager = manager
        self.creator = creator

    @property
    def found(self):
        return self.manager is not None


def find_factory(registry, name, type_key=TYPE_KEY):
    """Registry find 0x6076620: lock the registry mutex, walk the
    entry vector last-to-first; in each entry lock its mutex and
    look the type key up in the map; the first FactoryEntry whose
    pattern Matches the name wins and its functor is cloned
    (manager op 2, a no-op for the stateless lambda) into the
    result. No match recurses into the parent; no parent at all
    returns a zeroed result (manager None)."""
    if registry is None:
        return FoundFactory()
    registry.mutex_locked = True
    try:
        for entry in reversed(registry.entries):
            entry.mutex_locked = True
            try:
                factories = entry.map.find(type_key)
                if factories is None:
                    continue
                for factory in factories:
                    if factory.matches(name):
                        # Clone the functor (op 2, no-op) into a
                        # fresh 16-byte slot; copy manager+creator.
                        manager_call(2, [None], factory.functor)
                        return FoundFactory(manager=factory.manager,
                                            creator=factory.creator,
                                            functor=factory.functor)
            finally:
                entry.mutex_locked = False
        if registry.parent is not None:
            return find_factory(registry.parent, name, type_key)
        return FoundFactory()
    finally:
        registry.mutex_locked = False


def create_by_name(registry, name, shared_slot):
    """Translator 0x6076b20: create a Statistics object from a
    registered factory by name, wrapping it in a
    shared_ptr<Statistics> in ``shared_slot``. Returns the out
    Status. The creator receives (functor, name, &slot,
    &err_string); ``slot`` is the Statistics* slot at rsp+0x38
    and ``err_string`` is its error-message channel."""
    found = find_factory(registry, name)
    if not found.found:
        # No factory: code 3, "Could not load to Statistics".
        return Status.build(NOT_SUPPORTED, 0, MSG_COULD_NOT_LOAD, name)
    slot = PtrSlot()
    err_string = [""]
    returned = found.creator(found.functor, name, slot, err_string)
    # The translator destroys the cloned functor (manager op 3)
    # once the creator has run; a no-op for this manager.
    manager_call(3, [found.functor], found.functor)
    if returned is None:
        # Creator failed. An object left in the slot is disposed
        # (translator tail 0x6076cfb); the message is the creator's
        # error string when it wrote one, else the generic text.
        left = slot.get()
        if left is not None:
            delete_object(left)
            slot.set(None)
        if err_string[0]:
            return Status.build(INVALID_ARGUMENT, 0, err_string[0], name)
        return Status.build(INVALID_ARGUMENT, 0, MSG_COULD_NOT_LOAD, name)
    # Creator returned non-null. The translator wraps *slot*, not
    # the return value: a creator that returns an object without
    # installing it reports "unguarded", and the returned object
    # is NOT deleted on this path.
    if slot.get() is None:
        return Status.build(INVALID_ARGUMENT, 0, MSG_UNGUARDED, name)
    # Success: fresh control block, install the pair, then release
    # the caller's old control (0x5d35070 protocol).
    obj = slot.get()
    slot.set(None)
    control = CountedPtr(obj, COUNTED_STATS_VPTR)
    old_control = shared_slot.control
    shared_slot.install(obj, control)
    if old_control is not None:
        old_control.release()
    return Status.ok()
