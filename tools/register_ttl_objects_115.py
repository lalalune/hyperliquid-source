"""Model of node #115's RegisterTtlObjects registrar.

Pins the complete behavior of ``rocksdb::RegisterTtlObjects``
(creator 0x6208290..0x6208afa, catalogue 1,882/2,154, 87.37%
published-crate rebuild), reached exactly once through the
once-wrapper 0x6202da0 (pthread_once on the control at 0x65093a8,
callable 0x62069f0 via the TLS __once_callable slots) from two
entry points:

  * ``rocksdb::DBWithTTL::Open`` (0x6206100..0x62065e5) at
    call site 0x620615d, and
  * ``rocksdb::DBWithTTLImpl::CreateColumnFamilyWithTtl``
    (0x6205d20..0x6205e08) at call site 0x6205d61.

The register function 0x62069f0..0x6206d29:

  * calls the registry getter 0x61f92b0 (pinned by PR #4015),
    builds a 0x90-byte make_shared ObjectLibrary block named
    ``TTL`` (control-block vtable 0x64d00f0, counts 0x100000001
    from the global at 0x459b20) and appends it to the
    ObjectRegistry libraries vector under the registry mutex
    (registry+0x98; full vector goes through vec-insert
    0x5ff7960, pinned by PR #4015; the use-count bump is a
    ``lock addl`` gated on the byte at GOT 0x64ed290);
  * invokes the creator through a std::function (functor
    0x6208290, manager 0x6201000, invoker 0x6200a30) with the
    library and an empty-string name, then destroys the function
    (manager op 3) and releases the registry copy.

The creator registers three FactoryEntry records (each an
operator-new 0x30 block with an operator-new 0x70 PatternEntry):

  1. name ``MergeOperator``, creator invoker 0x62056b0 /
     manager 0x62009a0, pattern ``TtlMergeOperator``,
     FactoryEntry vtable 0x64d86a0 -- inline find-or-insert
     0x5fd1da0 (pinned by PR #3983) plus vector append;
  2. name ``CompactionFilterFactory``, creator invoker
     0x6205c60 / manager 0x62009d0, pattern
     ``TtlCompactionFilterFactory``, FactoryEntry vtable
     0x64d9d38 -- through the register helper 0x5ff8260
     (pinned by PR #4028);
  3. name ``CompactionFilter``, creator invoker 0x6202ca0 /
     manager 0x6200a00, pattern ``TtlCompactionFilter``,
     FactoryEntry vtable 0x64d7da0 -- inline find-or-insert
     plus vector append.

All three PatternEntry records have empty sub-pattern and
element vectors and flag 1, so matching is exact-match only
(per the PR #3983 matcher semantics).  The creator ends by
calling count 0x61f8700 (pinned by PR #3983) on the library;
both the returned total-entry count and the element-count out
value are discarded.

The creator lambdas build default (empty) objects:

  * MergeOperator (invoker 0x62056b0): new 0x38, C1 0x6205560
    with an empty shared_ptr<MergeOperator> and a null
    SystemClock, registers ``TtlMergeOptions`` (global
    0x6509480); installs into the out unique_ptr (replacing
    and D1-destroying any previous object) and returns the
    new pointer;
  * CompactionFilterFactory (invoker 0x6205c60): new 0x40,
    C2 0x6205790 with ttl 0, a null clock and an empty
    shared_ptr<CompactionFilterFactory>, registers
    ``UserOptions`` (global 0x6509400) and ``TTL`` (global
    0x6509440); installs into the out unique_ptr and returns
    the new pointer;
  * CompactionFilter (invoker 0x6202ca0): new 0x40, C2
    0x6202a10 with ttl 0, a null clock, a null filter and an
    empty unique_ptr, registers ``TTL`` (global 0x6509440)
    and ``UserFilter`` (global 0x65093c0); returns the raw
    pointer directly, installing into no out slot.

Consumers (cited by call site, FDE and catalogue row, not
re-excerpted): ``DBWithTTLImpl::SanitizeOptions``
(0x6205a00..0x6205c18) calls the MergeOperator C1 at
0x6205aa0, the CompactionFilter C2 at 0x6205a5d and the
CompactionFilterFactory C2 at 0x6205b6c;
``TtlCompactionFilterFactory::CreateCompactionFilter``
(0x6202ba0..0x6202c60) calls the CompactionFilter C2 at
0x6202c01.

Object layouts (all three objects carry a 0x18-byte field at
+0x08, zeroed by their ctors; the CompactionFilter ctor's
unwind path destroys it as a std::vector<std::string>,
element stride 0x30):

  * TtlMergeOperator, 0x38 bytes, vtable 0x64d9558
    (header 0x64d9548, typeinfo N7rocksdb16TtlMergeOperatorE):
    +0x08 vector<string>, +0x20 shared_ptr<MergeOperator>
    (ptr + control block), +0x30 SystemClock*.
  * TtlCompactionFilterFactory, 0x40 bytes, vtable 0x64d9718
    (header 0x64d9708, typeinfo
    N7rocksdb26TtlCompactionFilterFactoryE): +0x08
    vector<string>, +0x20 ttl (int), +0x28 SystemClock*,
    +0x30 shared_ptr<CompactionFilterFactory>.
  * TtlCompactionFilter, 0x40 bytes, vtable 0x64d9630
    (header 0x64d9620, typeinfo N7rocksdb19TtlCompactionFilterE):
    +0x08 vector<string>, +0x20 const CompactionFilter*,
    +0x28 owned unique_ptr<CompactionFilter> pointer, +0x30
    ttl (int), +0x38 SystemClock*.

FactoryEntry layout (0x30 bytes): +0x00 vtable, +0x08
PatternEntry*, +0x10..+0x20 the std::function functor
storage (16 zero bytes for these stateless lambdas), +0x20
manager, +0x28 invoker.  D2 installs the base vtable, calls
manager(this+0x10, this+0x10, op 3) when the manager is
non-null, then deletes the PatternEntry through its vtable
slot 1; D0 adds operator delete(node, 0x30).  Slots 2/3
forward to the PatternEntry vtable slots 2 (Matches
0x61f8670) and 3 (accessor 0x61f8120).

ObjectLibrary layout (0x80-byte object inside the 0x90-byte
make_shared block; control block is the first 0x10 bytes:
vtable 0x64d00f0, counts 0x100000001): +0x00 mutex (0x28
bytes, zero-initialized), +0x28 unordered_map (0x38 bytes:
buckets = single-bucket self-pointer, bucket_count 1,
before_begin 0, element_count 0, max_load_factor 1.0f,
next_resize 0, single_bucket 0), +0x60 name string (``TTL``).

CORRECTION to PR #4028: the 1.0f word at block+0x58 is the
unordered_map's max_load_factor (library+0x48), not a
library version float -- the 0x80-byte library object
(0x28 mutex + 0x38 map + 0x20 name) has no version field.

Environment limits: no cargo/rustc on this VM; the model is
the deterministic Python layer, verified against the raw
binary.
"""

# --- pinned addresses -------------------------------------------------

TRIGGER_OPEN = 0x6206100
TRIGGER_OPEN_CALL = 0x620615D
TRIGGER_CREATE_CF = 0x6205D20
TRIGGER_CREATE_CF_CALL = 0x6205D61
ONCE_WRAPPER = 0x6202DA0
ONCE_CONTROL = 0x65093A8
REGISTER_FN = 0x62069F0
REGISTER_MANAGER = 0x6201000
REGISTER_INVOKER = 0x6200A30
CREATOR = 0x6208290
CREATOR_COLD = 0x62080A4
REGISTER_HELPER = 0x5FF8260  # pinned by PR #4028
REG_GETTER = 0x61F92B0  # pinned by PR #4015
FIND_OR_INSERT = 0x5FD1DA0  # pinned by PR #3983
VEC_INSERT = 0x5FD17C0  # pinned by PR #3983
VEC_INSERT_LIBRARIES = 0x5FF7960  # pinned by PR #4015
COUNT = 0x61F8700  # pinned by PR #3983
SHARED_PTR_RELEASE = 0x5D350C0  # pinned by PR #4015
REGISTER_OPTIONS = 0x6099CE0  # Configurable::RegisterOptions
STRING_BUILD = 0x6201040
STRING_ASSIGN = 0x62010F0

LIBRARY_VTABLE = 0x64D00F0
LIBRARY_TYPEINFO = 0x64CF808
LIBRARY_COUNTS = 0x100000001
LIBRARY_NAME = "TTL"

PATTERN_VTABLE = 0x64D8ED0
PATTERN_TYPEINFO = 0x64D8E90

CREATORS = {
    "MergeOperator": {
        "invoke": 0x62056B0, "manager": 0x62009A0,
        "typeinfo": 0x64D9350, "kind": "MergeOperator",
        "pattern": "TtlMergeOperator",
        "factory_vtable": 0x64D86A0,
        "factory_typeinfo": 0x64D85E0,
    },
    "CompactionFilterFactory": {
        "invoke": 0x6205C60, "manager": 0x62009D0,
        "typeinfo": 0x64D9360, "kind": "CompactionFilterFactory",
        "pattern": "TtlCompactionFilterFactory",
        "factory_vtable": 0x64D9D38,
        "factory_typeinfo": 0x64D9338,
    },
    "CompactionFilter": {
        "invoke": 0x6202CA0, "manager": 0x6200A00,
        "typeinfo": 0x64D9370, "kind": "CompactionFilter",
        "pattern": "TtlCompactionFilter",
        "factory_vtable": 0x64D7DA0,
        "factory_typeinfo": 0x64D7D50,
    },
}

MERGE_OPERATOR_CTOR = 0x6205560
MERGE_OPERATOR_VTABLE = 0x64D9558
MERGE_OPERATOR_TYPEINFO = "N7rocksdb16TtlMergeOperatorE"
MERGE_OPERATOR_SIZE = 0x38
MERGE_OPERATOR_OPTIONS = ("TtlMergeOptions", 0x6509480)

FILTER_FACTORY_CTOR = 0x6205790
FILTER_FACTORY_VTABLE = 0x64D9718
FILTER_FACTORY_TYPEINFO = "N7rocksdb26TtlCompactionFilterFactoryE"
FILTER_FACTORY_SIZE = 0x40
FILTER_FACTORY_OPTIONS = (("UserOptions", 0x6509400),
                          ("TTL", 0x6509440))

FILTER_CTOR = 0x6202A10
FILTER_VTABLE = 0x64D9630
FILTER_TYPEINFO = "N7rocksdb19TtlCompactionFilterE"
FILTER_SIZE = 0x40
FILTER_OPTIONS = (("TTL", 0x6509440), ("UserFilter", 0x65093C0))

SANITIZE_OPTIONS = 0x6205A00
SANITIZE_MO_CALL = 0x6205AA0
SANITIZE_CF_CALL = 0x6205A5D
SANITIZE_CFF_CALL = 0x6205B6C
CREATE_COMPACTION_FILTER = 0x6202BA0
CREATE_COMPACTION_FILTER_CALL = 0x6202C01


# --- small helpers ----------------------------------------------------

class GrowableVector:
    """std::vector growth as used by the libraries vector and the
    per-name FactoryEntry vectors: capacity doubles on growth
    (vec-insert 0x5fd17c0 / 0x5ff7960), elements are preserved
    in order."""

    def __init__(self):
        self.items = []
        self.capacity = 0

    def _grow(self):
        self.capacity = 1 if self.capacity == 0 else 2 * self.capacity

    def append(self, item):
        if len(self.items) == self.capacity:
            self._grow()
        self.items.append(item)

    def __len__(self):
        return len(self.items)


class StdFunction:
    """A libstdc++ std::function over a stateless lambda: 16 bytes
    of functor storage (all zeros here), a manager at +0x10 and
    an invoker at +0x18.  Manager ops (pinned by PR #4028):
    0 stores the typeinfo address at *to; 1 stores from at *to
    (functor clone); 2 and 3 return False with no memory effect
    (the effective clone is the bitwise pair copy; destroy is a
    no-op for stateless lambdas)."""

    def __init__(self, functor, manager, invoker, typeinfo,
                 target=None):
        self.functor = functor
        self.manager = manager
        self.invoker = invoker
        self.typeinfo = typeinfo
        self.target = target
        self._manager_slot = None

    def invoke(self, *args):
        """The invoker (an arg-shifting tail-jump thunk) calls
        the functor with the shifted arguments."""
        if self.target is None:
            raise ValueError("no target bound to this std::function")
        return self.target(*args)

    def manager_call(self, to, from_, op):
        if op == 0:
            to[0] = self.typeinfo
            return True
        if op == 1:
            to[0] = from_[0]
            return True
        if op in (2, 3):
            return False
        raise ValueError("unknown manager op %d" % op)

    def clone(self):
        """Bitwise copy of the (manager, invoker) pair; the
        manager op 2 call the compiler emits is a no-op."""
        return StdFunction(self.functor, self.manager,
                           self.invoker, self.typeinfo)

    def destroy(self):
        """Manager op 3: a no-op for these stateless lambdas."""
        self.manager_call([None], [None], 3)


class OutSlot:
    """The out unique_ptr slot a creator installs into.  The
    machine takes the slot behind one more indirection (the
    invoker loads *(rdx) as the slot address, then replaces the
    stored pointer); the model collapses that level.  Installing
    destroys any previous object through its vtable slot 1
    (D1)."""

    def __init__(self):
        self.ptr = None
        self.disposed = []

    def install(self, new):
        old = self.ptr
        self.ptr = new
        if old is not None:
            old.destroy_via_d1()
            self.disposed.append(old)
        return new


# --- records ----------------------------------------------------------

class PatternEntry:
    """0x70-byte record: +0x00 vtable, +0x08 std::string pattern,
    +0x28 size_t pattern-length copy, +0x30 vector<string>
    sub-patterns, +0x48 bool byte (1), +0x50 pointer (0),
    +0x58 vector<0x28-byte> elements (string + mode u32 at
    +0x20).  All three TTL records have empty sub-pattern and
    element vectors."""

    SIZE = 0x70

    def __init__(self, pattern):
        self.vtable = PATTERN_VTABLE
        self.typeinfo = PATTERN_TYPEINFO
        self.pattern = pattern
        self.pattern_length = len(pattern)
        self.sub_patterns = []
        self.flag = 1
        self.pointer = 0
        self.elements = []

    def matches(self, name):
        """Matcher per PR #3983 (str-match 0x61f8430 +
        elem-match 0x61f8280): an empty +0x58 vector means
        exact match only (flag not checked); otherwise the
        query must start with the pattern, every element must
        match in sequence, and the tail is decided by the last
        element's mode (2: reach the end; 3/4: remainder after
        an optional '-' is digits / dotted digits with at least
        one digit; other modes accept)."""
        if not self.elements:
            return name == self.pattern
        if not name.startswith(self.pattern):
            return False
        pos = len(self.pattern)
        for i, (text, mode) in enumerate(self.elements):
            if i == 0:
                prev_mode = 2
            else:
                prev_mode = self.elements[i - 1][1]
            if prev_mode == 2:
                if not name.startswith(text, pos):
                    return False
                pos += len(text)
            elif prev_mode == 3:
                if not name.startswith(text, pos):
                    return False
                pos += len(text)
            else:
                if not name.startswith(text, pos):
                    return False
                pos += len(text)
        tail = name[pos:]
        last_mode = self.elements[-1][1]
        if last_mode == 2:
            return tail == ""
        if last_mode in (3, 4):
            if tail.startswith("-"):
                tail = tail[1:]
            if last_mode == 3:
                return tail.isdigit() and len(tail) > 0
            parts = tail.split(".")
            return (len(parts) > 0
                    and all(p.isdigit() and p for p in parts))
        return True


class FactoryEntry:
    """0x30-byte record: +0x00 vtable, +0x08 PatternEntry*,
    +0x10..+0x20 std::function functor storage (zeros),
    +0x20 manager, +0x28 invoker."""

    SIZE = 0x30

    def __init__(self, name, pattern, creator):
        self.name = name
        self.pattern_entry = PatternEntry(pattern)
        self.functor = 0
        self.manager = creator["manager"]
        self.invoker = creator["invoke"]
        self.vtable = creator["factory_vtable"]
        self.typeinfo = creator["factory_typeinfo"]
        self.creator = creator
        self.destroyed = False

    def destroy_d2(self):
        """D2: install the base vtable, call manager(op 3) when
        non-null (a no-op here), delete the PatternEntry via
        its D0 (vtable slot 1)."""
        if self.manager is not None:
            StdFunction(self.functor, self.manager, self.invoker,
                        self.creator["typeinfo"]).destroy()
        self.pattern_entry = None
        self.destroyed = True

    def destroy_d0(self):
        self.destroy_d2()
        # operator delete(node, 0x30) -- the block is freed.

    def matches(self, name):
        return self.pattern_entry.matches(name)

    def accessor(self):
        """Forward to the PatternEntry vtable slot 3."""
        return self.pattern_entry


class ObjectLibrary:
    """0x80-byte object inside the 0x90-byte make_shared block
    (control block is the first 0x10 bytes: vtable 0x64d00f0,
    counts 0x100000001).  +0x00 mutex (0x28, zeroed), +0x28
    unordered_map (0x38: buckets = single-bucket self-pointer,
    bucket_count 1, before_begin 0, element_count 0,
    max_load_factor 1.0f, next_resize 0, single_bucket 0),
    +0x60 name string."""

    BLOCK_SIZE = 0x90
    SIZE = 0x80

    def __init__(self, name=LIBRARY_NAME):
        self.vtable = LIBRARY_VTABLE
        self.typeinfo = LIBRARY_TYPEINFO
        self.counts = LIBRARY_COUNTS
        self.name = name
        self.mutex_locked = False
        self.map_buckets = 1
        self.map_element_count = 0
        self.map_max_load_factor = 1.0
        self.entries = {}  # name -> GrowableVector[FactoryEntry]

    def lock(self):
        assert not self.mutex_locked
        self.mutex_locked = True

    def unlock(self):
        assert self.mutex_locked
        self.mutex_locked = False

    def register(self, name, entry):
        """find-or-insert 0x5fd1da0 on the map, then append one
        qword to that name's vector (vec-insert 0x5fd17c0 on
        the full path)."""
        vec = self.entries.get(name)
        if vec is None:
            vec = GrowableVector()
            self.entries[name] = vec
            self.map_element_count += 1
        vec.append(entry)

    def count(self):
        """count 0x61f8700: returns (total entries, element
        count).  Locks the library mutex while counting."""
        self.lock()
        try:
            total = sum(len(v) for v in self.entries.values())
            return total, self.map_element_count
        finally:
            self.unlock()

    def find_factory(self, name):
        vec = self.entries.get(name)
        return list(vec.items) if vec is not None else []


class ObjectRegistry:
    """The ObjectRegistry copy the register function works on:
    the libraries vector lives at +0x00 (begin/end/capacity)
    and its mutex at +0x98."""

    def __init__(self):
        self.libraries = GrowableVector()
        self.mutex_locked = False

    def append_library(self, library):
        self.libraries.append(library)


# --- the three TTL objects --------------------------------------------

class TtlObject:
    """Shared shape of the three created objects: a 0x18-byte
    vector<string> at +0x08 (zeroed by the ctor; the
    CompactionFilter ctor's unwind path destroys it element
    by element, stride 0x30), the installed vtable, and the
    options registered through Configurable::RegisterOptions
    0x6099ce0."""

    def __init__(self, vtable, typeinfo, size):
        self.vtable = vtable
        self.typeinfo = typeinfo
        self.size = size
        self.options_vector = []
        self.options = []  # (name, global, field) triples
        self.destroyed_via_d1 = False

    def register_options(self, name, option_global, field):
        self.options.append((name, option_global, field))

    def destroy_via_d1(self):
        self.destroyed_via_d1 = True


class TtlMergeOperator(TtlObject):
    """C1 0x6205560 (0x38 bytes): +0x20 shared_ptr<MergeOperator>
    (ptr + control block, use-count bump gated on the byte at
    GOT 0x64ed290), +0x30 SystemClock*.  Registers
    ``TtlMergeOptions`` (global 0x6509480)."""

    def __init__(self, wrapped=None, wrapped_cb=None, clock=None):
        super().__init__(MERGE_OPERATOR_VTABLE,
                         MERGE_OPERATOR_TYPEINFO, MERGE_OPERATOR_SIZE)
        self.wrapped = wrapped
        self.wrapped_cb = wrapped_cb
        self.clock = clock
        name, option_global = MERGE_OPERATOR_OPTIONS
        self.register_options(name, option_global, "wrapped_shared_ptr")


class TtlCompactionFilterFactory(TtlObject):
    """C2 0x6205790 (0x40 bytes): +0x20 ttl (int), +0x28
    SystemClock*, +0x30 shared_ptr<CompactionFilterFactory>.
    Registers ``UserOptions`` (global 0x6509400) and ``TTL``
    (global 0x6509440).  Unwind path installs base vtable
    0x64d3430 and calls base destructor 0x5d35b50."""

    BASE_VTABLE = 0x64D3430
    BASE_DTOR = 0x5D35B50

    def __init__(self, ttl=0, clock=None, wrapped=None,
                 wrapped_cb=None):
        super().__init__(FILTER_FACTORY_VTABLE,
                         FILTER_FACTORY_TYPEINFO, FILTER_FACTORY_SIZE)
        self.ttl = ttl
        self.clock = clock
        self.wrapped = wrapped
        self.wrapped_cb = wrapped_cb
        for name, option_global in FILTER_FACTORY_OPTIONS:
            field = ("wrapped_shared_ptr" if name == "UserOptions"
                     else "ttl")
            self.register_options(name, option_global, field)


class TtlCompactionFilter(TtlObject):
    """C2 0x6202a10 (0x40 bytes): +0x20 const CompactionFilter*
    (the moved unique_ptr's object when the const arg is null),
    +0x28 owned unique_ptr pointer, +0x30 ttl (int), +0x38
    SystemClock*.  Registers ``TTL`` (global 0x6509440) and
    ``UserFilter`` (global 0x65093c0).  Unwind path installs
    base vtables 0x64d93e0 then 0x64d3430, destroying the owned
    filter and the +0x08 string vector between them."""

    BASE_VTABLES = (0x64D93E0, 0x64D3430)

    def __init__(self, ttl=0, clock=None, filter_=None,
                 owned=None):
        super().__init__(FILTER_VTABLE, FILTER_TYPEINFO,
                         FILTER_SIZE)
        self.filter = filter_ if filter_ is not None else owned
        self.owned = owned
        self.ttl = ttl
        self.clock = clock
        for name, option_global in FILTER_OPTIONS:
            field = "ttl" if name == "TTL" else "filter"
            self.register_options(name, option_global, field)


# --- creators -----------------------------------------------------------

def create_merge_operator(name, out_slot):
    """Invoker 0x62056b0: new 0x38, C1 with an empty shared_ptr
    and a null clock; installs into the out unique_ptr
    (replacing and D1-destroying any previous object) and
    returns the new pointer.  The name argument is ignored by
    the creator (the entry pattern is fixed)."""
    obj = TtlMergeOperator(wrapped=None, wrapped_cb=None, clock=None)
    return out_slot.install(obj)


def create_compaction_filter_factory(name, out_slot):
    """Invoker 0x6205c60: new 0x40, C2 with ttl 0, a null clock
    and an empty shared_ptr; installs into the out unique_ptr
    and returns the new pointer."""
    obj = TtlCompactionFilterFactory(ttl=0, clock=None)
    return out_slot.install(obj)


def create_compaction_filter(name):
    """Invoker 0x6202ca0: new 0x40, C2 with ttl 0, a null clock,
    a null filter and an empty unique_ptr; returns the raw
    pointer directly, installing into no out slot."""
    return TtlCompactionFilter(ttl=0, clock=None, filter_=None,
                               owned=None)


CREATOR_FUNCS = {
    "MergeOperator": create_merge_operator,
    "CompactionFilterFactory": create_compaction_filter_factory,
    "CompactionFilter": create_compaction_filter,
}


# --- the registrar ------------------------------------------------------

class OnceControl:
    """pthread_once on the control at 0x65093a8: the first call
    runs the callable (register function 0x62069f0 via the TLS
    __once_callable slots); later calls are no-ops.  A
    pthread_once failure throws __throw_system_error."""

    def __init__(self):
        self.done = False
        self.runs = 0

    def run_once(self, fn):
        if self.done:
            return False
        self.runs += 1
        fn()
        self.done = True
        return True


ONCE = OnceControl()


def _creator(library, name):
    """Creator 0x6208290: registers the three entries, locking
    the library mutex around each registration block (block 1
    inline, block 2 inside the register helper, block 3
    inline), then calls count 0x61f8700 (both results
    discarded).  Block 1 uses inline find-or-insert + append;
    block 2 uses the register helper 0x5ff8260 (which moves
    the record pointer out of its slot and zeroes the slot);
    block 3 uses inline find-or-insert + append.  The name
    argument is ignored -- the register function always passes
    the empty string."""
    assert name == ""
    for entry_name in ("MergeOperator", "CompactionFilterFactory",
                       "CompactionFilter"):
        creator = CREATORS[entry_name]
        entry = FactoryEntry(entry_name, creator["pattern"], creator)
        if entry_name == "CompactionFilterFactory":
            # Register helper: (library, name, slot) -- moves
            # the record pointer out of the slot.
            slot = [entry]
            _register_helper(library, entry_name, slot)
            assert slot[0] is None
        else:
            library.lock()
            try:
                library.register(entry_name, entry)
            finally:
                library.unlock()
    total, element_count = library.count()
    return total, element_count


def _register_helper(library, name, slot):
    """Register helper 0x5ff8260: locks the library mutex,
    builds the name string from the C-string literal, calls
    find-or-insert 0x5fd1da0 on the map, appends ONE qword
    (the record pointer, moved then zeroed) to that name's
    vector, unlocks."""
    library.lock()
    try:
        entry = slot[0]
        slot[0] = None
        library.register(name, entry)
    finally:
        library.unlock()


def register_ttl_objects(registry=None):
    """Register function 0x62069f0, invoked through the register
    std::function (functor 0x6208290, manager 0x6201000,
    invoker 0x6200a30) with the library and an empty-string
    name: creates the ``TTL`` ObjectLibrary, appends it to the
    registry libraries vector, runs the creator, destroys the
    std::function (manager op 3) and releases the registry
    copy."""
    if registry is None:
        registry = ObjectRegistry()
    library = ObjectLibrary(LIBRARY_NAME)
    registry.append_library(library)
    fn = StdFunction(CREATOR, REGISTER_MANAGER, REGISTER_INVOKER,
                     "*Z18RegisterTtlObjectsEUlRKNSt7__cxx1112basic_"
                     "stringIcSt11char_traitsIcESaIcEEEPSt10unique_"
                     "ptrIN7rocksdb13MergeOperatorESt14default_"
                     "deleteIS9_EEPS4_E_", target=_creator)
    fn.invoke(library, "")
    fn.destroy()
    return registry


def ensure_ttl_registered():
    """Once-wrapper 0x6202da0: pthread_once on the control at
    0x65093a8 with the register function as the callable."""
    return ONCE.run_once(lambda: register_ttl_objects(_REGISTRY))


_REGISTRY = ObjectRegistry()


def _reset_state():
    """Test-only reset: the real once control and registry are
    process-global, so the tests reset them to re-run the flow."""
    global _REGISTRY, ONCE
    _REGISTRY = ObjectRegistry()
    ONCE = OnceControl()


def db_with_ttl_open():
    """DBWithTTL::Open 0x6206100: calls the once-wrapper at
    0x620615d first, then opens the database."""
    ensure_ttl_registered()
    return _REGISTRY


def create_column_family_with_ttl():
    """DBWithTTLImpl::CreateColumnFamilyWithTtl 0x6205d20:
    calls the once-wrapper at 0x6205d61 first, then sanitizes
    options (which constructs the TTL objects) and delegates
    to the base CreateColumnFamily."""
    ensure_ttl_registered()
    return _REGISTRY


def sanitize_options(ttl, clock=None, wrapped_merge=None,
                     wrapped_factory=None, wrapped_filter=None):
    """DBWithTTLImpl::SanitizeOptions 0x6205a00: constructs the
    three TTL objects -- MergeOperator C1 at 0x6205aa0,
    CompactionFilter C2 at 0x6205a5d, CompactionFilterFactory
    C2 at 0x6205b6c -- with the configured ttl/clock/wrapped
    instances."""
    merge = TtlMergeOperator(wrapped=wrapped_merge, clock=clock)
    filt = TtlCompactionFilter(ttl=ttl, clock=clock,
                               filter_=wrapped_filter)
    factory = TtlCompactionFilterFactory(ttl=ttl, clock=clock,
                                         wrapped=wrapped_factory)
    return merge, filt, factory


def create_compaction_filter_from_factory(factory, ttl,
                                          clock=None,
                                          wrapped_filter=None):
    """TtlCompactionFilterFactory::CreateCompactionFilter
    0x6202ba0: calls the CompactionFilter C2 at 0x6202c01."""
    return TtlCompactionFilter(ttl=ttl, clock=clock,
                               filter_=wrapped_filter)


def create(registry, name, pattern_name, out_slot=None):
    """Create through a registered entry: looks the name up in
    the TTL library, checks the pattern, and runs the creator
    lambda.  Returns the created object (and, for the two
    installing creators, the out slot's new contents)."""
    if len(registry.libraries) == 0:
        return None
    entries = registry.libraries.items[0].find_factory(name)
    for entry in entries:
        if entry.matches(pattern_name):
            func = CREATOR_FUNCS[name]
            if name == "CompactionFilter":
                return func(pattern_name)
            return func(pattern_name, out_slot)
    return None
