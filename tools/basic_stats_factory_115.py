"""RE-001: create a Statistics object by name through the global
ObjectLibrary (node #115).

Bounded question: how does node #115 build a ``Statistics`` object
when a caller asks for one by name, and what does the registered
``BasicStatistics`` factory pin down about that object?

Behaviour, pinned from the node #115 binary
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

  * Host 0x6077820: on first use it runs the once-init 0x6075bc0
    (``rocksdb::RegisterBuiltinStatistics`` lambda) through
    ``pthread_once`` on flag 0x6506238, then dispatches on the
    name: empty or ``"BasicStatistics"`` is constructed directly
    through ctor 0x6071a00; any other name goes through the
    registry lookup 0x609e510.
  * Once-init 0x6075bc0: locks the default ObjectLibrary (singleton
    accessor 0x61f8b60), builds a PatternEntry named
    ``"BasicStatistics"`` and a FactoryEntry holding the creator
    0x6071ba0 and the std::function manager 0x606fa50, and appends
    the entry to the ``"Statistics"`` vector in the registry map
    (map-op 0x5fd1da0, vector-grow 0x5fd17c0).
  * Ctor 0x6071a00: a 0x70-byte StatisticsImpl (vptr 0x64d2d88,
    byte 3 at +0x20, options-record vector at +0x8, std::string at
    +0x28, shared_ptr slot at +0x30, mutex at +0x38, shard store
    at +0x60). It appends the ``"StatisticsOptions"`` record
    (0x6099ce0) and builds the ticker shard store (0x60716d0).
  * Creator 0x6071ba0: builds a fresh StatisticsImpl and installs
    it into the caller's ``Statistics*`` slot, deleting any old
    occupant through the destructor 0x6070ea0.
  * PatternEntry::Matches (0x61f8670) via helper 0x61f8430 and
    sub-matcher 0x61f8280: the registered entry has empty
    sub-pattern vectors, so it matches exactly ``"BasicStatistics"``;
    the helper also supports prefix-plus-token patterns (modes 2
    substring, 3 integer, 4 float).
  * Destructor 0x6070ea0: destroys the shard store, the mutex and
    the +0x30 shared_ptr; the counted_ptr vtables
    (0x64d2ec8 / 0x64d2f00) dispose the object through it.

Evidence packet: research/work-items/RE-001-basic-stats-factory-115/
"""

# --- Pinned addresses (node #115) -------------------------------------

HOST = 0x6077820
REGISTER_ONCE = 0x6075BC0
ONCE_FLAG = 0x6506238
STATS_CTOR = 0x6071A00
CREATOR = 0x6071BA0
MANAGER = 0x606FA50
REGISTRY_DEFAULT = 0x61F8B60
MAP_OP = 0x5FD1DA0
VECTOR_GROW = 0x5FD17C0
MUTEX_INIT = 0x60D50C0
SHARD_STORE = 0x60716D0
OPTIONS_RECORD = 0x6099CE0
STATS_DTOR = 0x6070EA0
STATS_DTOR_DELETE = 0x6071040

STATISTICS_IMPL_SIZE = 0x70
STATISTICS_IMPL_VPTR = 0x64D2D88
COUNTED_IMPL_VPTR = 0x64D2EC8
COUNTED_STATS_VPTR = 0x64D2F00
FACTORY_ENTRY_VPTR = 0x64D2E98
PATTERN_ENTRY_VPTR = 0x64D8ED0

SHARD_SIZE = 0xCE40
SHARD_BLOCK_HEAD = 0x40
SHARD_ALLOC_LIMIT = 0x9EE009EE009E

# The third field of the "StatisticsOptions" record is a BSS address
# whose identity is not pinned by this packet (open unknown).
OPTIONS_RECORD_OPAQUE = 0x6506200


def shard_bits_for(hardware_concurrency):
    """Shard-bit count chosen by 0x60716d0.

    hardware_concurrency <= 8 -> 3 bits (8 shards, the 0x607187c
    default). Above 8, the smallest bit count >= 4 with
    2**bits >= hardware_concurrency. A count above the
    0x9ee009ee009e sanity bound throws bad_array_new_length.
    """
    if hardware_concurrency <= 8:
        return 3
    bits = 4
    while (1 << bits) < hardware_concurrency:
        bits += 1
    if (1 << bits) > SHARD_ALLOC_LIMIT:
        raise OverflowError("bad_array_new_length: shard count %d" % (1 << bits))
    return bits


def shard_block_size(shard_bits):
    """Allocation size for a shard store: count * 0xce40 + 0x40."""
    return (1 << shard_bits) * SHARD_SIZE + SHARD_BLOCK_HEAD


class StatisticsImpl:
    """The 0x70-byte object built by ctor 0x6071a00."""

    def __init__(self, hardware_concurrency=8, name=""):
        self.vptr = STATISTICS_IMPL_VPTR
        self.size = STATISTICS_IMPL_SIZE
        # +0x8/+0x10/+0x18: options-record vector (begin/end/capacity).
        self.options_records = []
        # +0x20: byte 3.
        self.flags_byte = 3
        # +0x28: std::string member; the creator passes a zeroed
        # 16-byte slot, i.e. the empty string.
        self.name = name
        # +0x30: shared_ptr slot (control block or None).
        self.shared_slot = None
        # +0x38: mutex (unlocked after construction).
        self.mutex_locked = False
        # +0x60: shard store (0x60716d0).
        self.shard_bits = shard_bits_for(hardware_concurrency)
        self.shard_count = 1 << self.shard_bits
        self.shard_block_size = shard_block_size(self.shard_bits)
        self.shards = [0] * self.shard_count
        self.destroyed = False
        self.append_options_record()

    def append_options_record(self):
        """0x6099ce0: append {"StatisticsOptions", obj+0x28, opaque}."""
        self.options_records.append(
            ("StatisticsOptions", self.name, OPTIONS_RECORD_OPAQUE))

    def destroy(self):
        """Destructor 0x6070ea0: destroy shards, mutex, shared slot."""
        if self.destroyed:
            return
        self.destroyed = True
        self.shards = []
        self.mutex_locked = False
        self.shared_slot = None


class CountedPtr:
    """A shared_ptr control block (0x18 bytes).

    +0x0: counted_ptr vtable, +0x8: use 1 / weak 1 packed as
    0x100000001, +0x10: the managed object. _M_dispose deletes the
    object through its destructor; _M_destroy deletes the block.
    """

    def __init__(self, obj, vptr):
        self.vptr = vptr
        self.obj = obj
        self.use_count = 1
        self.weak_count = 1
        self.disposed = False
        self.destroyed = False

    def release(self):
        """0x5d35070: drop one use; at zero, dispose then destroy."""
        self.use_count -= 1
        if self.use_count == 0:
            self.dispose()
            self.destroy()

    def dispose(self):
        """_M_dispose: delete the managed object (0x6070ea0)."""
        if self.obj is not None and not self.disposed:
            self.disposed = True
            self.obj.destroy()
            self.obj = None

    def destroy(self):
        """_M_destroy: delete the 0x18-byte control block."""
        self.destroyed = True


def submatch(mode, pattern, query, pos):
    """Sub-pattern matcher 0x61f8280.

    Consumes one token from ``query`` starting at ``pos`` and
    returns the position after it, or -1 on failure. ``pattern``
    is the 0x28-byte record's string field; ``mode`` is its +0x20
    field: 2 = literal substring, 3 = integer, 4 = float, any
    other value = find the pattern text first.
    """
    if pos > len(query):
        return -1
    if mode == 2:
        # Literal: the query text at pos must start with pattern,
        # and the whole remaining query must be consumed exactly.
        if query[pos:pos + len(pattern)] != pattern:
            return -1
        end = pos + len(pattern)
        if end != len(query):
            return -1
        return end
    if mode == 3:
        # Integer: optional '-' then at least one digit.
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
        # Float: optional '-' then digits with at most one '.',
        # at least one digit overall.
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
    # Other modes: find the pattern text at or after pos, then
    # fall through to the digit scan of mode 3/4.
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


class FactoryEntry:
    """A 0x30-byte FactoryEntry<Statistics> (vptr 0x64d2e98).

    +0x8: PatternEntry*, +0x10..+0x1f: zero, +0x20: manager
    0x606fa50, +0x28: creator 0x6071ba0.
    """

    def __init__(self, pattern):
        self.vptr = FACTORY_ENTRY_VPTR
        self.pattern = pattern
        self.manager = MANAGER
        self.creator = CREATOR
        self.functor_slots_zero = True

    def create(self, slot):
        """Creator 0x6071ba0: build a fresh StatisticsImpl, install
        it into the caller's Statistics* slot, deleting any old
        occupant through 0x6070ea0. The name/unique_ptr arguments
        are ignored."""
        obj = StatisticsImpl()
        old = slot.get()
        slot.set(obj)
        if old is not None:
            old.destroy()
        return obj

    def destroy(self):
        """Destructor 0x606fad0: destroy the std::function via
        manager op 3, then delete the PatternEntry."""
        self.pattern = None


class ObjectLibrary:
    """The default ObjectLibrary behind singleton 0x61f8b60.

    The registry map (unordered_map at object+0x28) maps a type
    name to a vector of FactoryEntry pointers. Guard byte
    0x6509108 and holder 0x6509110 make the singleton construct
    exactly once; the holder's 0x90-byte control block carries
    the "default" name and the map (bucket count 1, float 1.0).
    """

    def __init__(self):
        self.name = "default"
        self.map = {}
        self.locked = False

    def register(self, type_name, entry):
        """The once-init append: map-op 0x5fd1da0 finds (or
        creates) the vector for type_name; 0x5fd17c0 grows it
        when full; the entry is appended (replacing any entry
        already present for that key)."""
        self.locked = True
        try:
            vec = self.map.setdefault(type_name, [])
            vec.append(entry)
        finally:
            self.locked = False

    def factories_for(self, type_name):
        return list(self.map.get(type_name, []))


class _DefaultLibrary:
    """Function-local static behind 0x61f8b60."""

    def __init__(self):
        self._library = None
        self._constructed = False

    def get(self):
        if not self._constructed:
            self._library = ObjectLibrary()
            self._constructed = True
        return self._library


_default_library = _DefaultLibrary()
_once_done = False


def reset_for_tests():
    """Test-only reset of the once-init state."""
    global _once_done
    _default_library._library = None
    _default_library._constructed = False
    _once_done = False


def register_builtin_statistics():
    """Once-init 0x6075bc0: register the BasicStatistics factory
    under the "Statistics" key of the default library."""
    global _once_done
    if _once_done:
        return
    library = _default_library.get()
    pattern = PatternEntry("BasicStatistics")
    entry = FactoryEntry(pattern)
    library.register("Statistics", entry)
    _once_done = True


def create_by_name(name, hardware_concurrency=8):
    """Host 0x6077820: create a Statistics object by name.

    Runs the once-init first, then: empty name or
    "BasicStatistics" is constructed directly (ctor 0x6071a00)
    with a fresh shared_ptr control block (use 1 / weak 1);
    any other name goes through the registry lookup 0x609e510,
    which finds the factory whose pattern matches and runs its
    creator. Returns (status, counted_ptr_or_None): status is
    "ok" or "not_found".
    """
    register_builtin_statistics()
    library = _default_library.get()
    if name == "" or name == "BasicStatistics":
        obj = StatisticsImpl(hardware_concurrency=hardware_concurrency)
        return "ok", CountedPtr(obj, COUNTED_IMPL_VPTR)
    for entry in library.factories_for("Statistics"):
        if entry.pattern.matches(name):
            slot = _Slot()
            entry.create(slot)
            return "ok", CountedPtr(slot.get(), COUNTED_IMPL_VPTR)
    return "not_found", None


class _Slot:
    """A Statistics* slot (the creator's rdx argument)."""

    def __init__(self, value=None):
        self._value = value

    def get(self):
        return self._value

    def set(self, value):
        self._value = value
