"""Python model of node #115's SystemClockWrapper vtable installers
(RE-001).

Faithful model of the 22 windows in
research/work-items/RE-001-systemclock-installers-115/:
the five installer routines (wrapper ctor C1 0x5fd0090, Emulated D2
0x6029110, wrapper D2 0x6029230, wrapper D0 0x6029500, Emulated D0
0x6029620), the shared record-append 0x6099ce0 and grow 0x6099790
helpers, the shared_ptr last-use helper 0x5d35070, the Emulated
ctor C1 0x6029390 with its landing pad 0x602934c, the three entry
thunks (0x5fcc5d0, 0x5fcc600, 0x5fcc630) and their manager op
dispatch, the three registrations (0x5fd27c0, 0x5fd20d0, 0x5fd24c0)
with the registry node D2 0x5fcc700, the three invokers
(0x5fcd550, 0x5fcd5b0, 0x5fcf450), the make_shared factory
0x60297a0 and the holder accessor 0x5fcf430.

The five installers and the three thunks are re-shipped
byte-identical from the RE-001-canonical-lea-sites-115 packet
(open PR #3352, now merged); the model builds on the same
shared_ptr and slot-24 semantics that packet pinned.

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
"""

# --- constants pinned by the binary -----------------------------------

WRAPPER_VTABLE = 0x64CDD88
BASE_VTABLE = 0x64D3420 + 0x10
EMULATED_VTABLE = 0x64D1650
NODE_VTABLE = 0x64CDE68
ENTRY_VTABLE = 0x64D8ED0
FACTORY_CB_VTABLE = 0x64D1C38

# The three FactoryEntry vtable headers (RELATIVE records).
FACTORY_ENTRY_HEADERS = (0x64CD9C0, 0x64CD9C8, 0x64CD9D8, 0x64CD9E8, 0x64CD9F8)
# The three entry thunks and the vtable each one is installed with.
THUNKS = {0x5FCC5D0: 0x64CD9D0, 0x5FCC600: 0x64CD9E0, 0x5FCC630: 0x64CD9F0}
# The three invokers (name -> (invoker addr, thunk addr, mode)).
INVOKERS = {
    "MockEnv": (0x5FCD5B0, 0x5FCC5D0, None),
    "CompositeEnv": (0x5FCF450, 0x5FCC600, None),
    "TimeEmulatedSystemClock": (0x5FCD550, 0x5FCC630, 0),
}
# The wrapper is 0x30 bytes; the emulated clock is 0x50 bytes.
WRAPPER_SIZE = 0x30
EMULATED_SIZE = 0x50
# The record-append vector element is 0x30 bytes.
RECORD_SIZE = 0x30
# The factory allocates 0x60 bytes for the make_shared object.
FACTORY_ALLOC = 0x60
# The make_shared control block starts at counts 0x100000001.
FACTORY_COUNTS = 0x100000001

# The scaled-add constant from the emulated slot-24 (0x6025eb0),
# re-implemented here exactly as in tools/canonical_lea_sites_115.py.
SCALE = 0x431BDE82D7B634DB


def scaled_add(v40):
    """Mirror the imul/sar sequence at 0x6025f92..0x6025fae."""
    product = SCALE * v40  # signed 128-bit product
    high = product >> 64  # arithmetic shift, floor for negatives
    return (high >> 18) + (1 if v40 < 0 else 0)


# --- shared_ptr ---------------------------------------------------------

class ControlBlock:
    """A shared_ptr control block: (use_count, weak_count) plus the
    dispose/destroy slots. The binary keeps the counts in one 64-bit
    word: low 32 bits use, high 32 bits weak (0x100000001 = (1, 1))."""

    def __init__(self, use=1, weak=1, atomic=False):
        self.use = use
        self.weak = weak
        self.atomic = atomic  # the byte at 0x64ed290 selects lock xadd
        self.disposed = False
        self.destroyed = False
        self.dispose_calls = 0
        self.destroy_calls = 0

    def dispose(self):
        """Control-block slot 0x10: destroy the managed object."""
        self.dispose_calls += 1
        self.disposed = True

    def destroy(self):
        """Control-block slot 0x18: destroy the control block."""
        self.destroy_calls += 1
        self.destroyed = True

    def __repr__(self):
        return "ControlBlock(use=%d, weak=%d)" % (self.use, self.weak)


class SharedPtr:
    """A shared_ptr: (object, control block). Copying bumps the use
    count (0x64ed290 selector in the binary); releasing follows the
    last-use helper 0x5d35070."""

    def __init__(self, obj, control):
        self.obj = obj
        self.control = control

    def copy(self):
        """The wrapper ctor's copy at 0x5fd00f4..0x5fd0104: bump the
        use count and share the control block."""
        if self.control is not None:
            self.control.use += 1
        return SharedPtr(self.obj, self.control)

    def release(self):
        """The last-use helper 0x5d35070: when the use count reaches
        0, dispose the object (slot 0x10); then decrement the weak
        count, and when the old weak count was 1, destroy the
        control block (slot 0x18). Returns the events, in order."""
        events = []
        ctrl = self.control
        if ctrl is None:
            return events
        ctrl.use -= 1
        if ctrl.use == 0:
            ctrl.dispose()
            events.append("dispose")
            old_weak = ctrl.weak
            ctrl.weak -= 1
            events.append("weak--")
            if old_weak == 1:
                ctrl.destroy()
                events.append("destroy")
        self.obj = None
        self.control = None
        return events


def last_use_helper(control):
    """The 0x5d35070 helper on a bare control block: dispose when
    the use count hits 0, weak-decrement, destroy at old weak 1.
    Mirrors SharedPtr.release without the pointer bookkeeping."""
    events = []
    control.use -= 1
    if control.use == 0:
        control.dispose()
        events.append("dispose")
        old_weak = control.weak
        control.weak -= 1
        events.append("weak--")
        if old_weak == 1:
            control.destroy()
            events.append("destroy")
    return events


# --- options vector ------------------------------------------------------

class OptionsVector:
    """The vector at owner+0x08..+0x18: a list of 0x30-byte records
    {std::string name, qword ptr1, qword ptr2}. The append helper
    0x6099ce0 copies short strings inline (SSO, len<=15) and
    allocates for longer ones; at capacity it grows via 0x6099790."""

    SSO_LIMIT = 15
    MAX_CAPACITY = 0x2AAAAAAAAAAAAAA

    def __init__(self):
        self.records = []
        self.capacity = 0
        self.buffer_freed = False

    def append(self, name, ptr1, ptr2):
        """0x6099ce0: grow when full, then copy the record. The
        string is stored inline when len<=15, heap-allocated
        otherwise (the model keeps the heap flag)."""
        if len(self.records) == self.capacity:
            self.grow()
        heap = len(name) > self.SSO_LIMIT
        self.records.append({"name": name, "ptr1": ptr1, "ptr2": ptr2,
                             "heap": heap})
        return self.records[-1]

    def grow(self):
        """0x6099790: double the capacity (0xaaaaaaaaaaaaaaab
        divide-by-48), bounded by the max check; move-construct the
        records (SSO strings copied inline, heap strings moved with
        the source nulled) and free the old buffer."""
        if self.capacity == 0:
            new_capacity = 1
        else:
            new_capacity = self.capacity * 2
        if new_capacity > self.MAX_CAPACITY:
            raise OverflowError("options-vector capacity overflow")
        moved = []
        for record in self.records:
            if record["heap"]:
                moved.append(dict(record))
                record["name"] = None  # the source string is nulled
            else:
                moved.append(dict(record))
        self.records = moved
        self.capacity = new_capacity
        self.buffer_freed = True
        return new_capacity

    def destroy(self):
        """The D2 vector teardown: string-dispose each record, then
        free the buffer."""
        disposed = len(self.records)
        self.records = []
        self.capacity = 0
        self.buffer_freed = True
        return disposed


# --- clocks --------------------------------------------------------------

class Wrapper:
    """The SystemClockWrapper object (0x30 bytes): +0x00 vtable,
    +0x08..+0x18 the options vector, +0x20/+0x28 the wrapped-clock
    shared_ptr. The ctor C1 0x5fd0090 installs the vtable, zeroes
    the vector range, copies the shared_ptr and appends the record
    {"", this+0x20, 0x6504b80}."""

    def __init__(self, wrapped=None):
        self.vtable = WRAPPER_VTABLE
        self.options = OptionsVector()
        self.wrapped = wrapped  # a SharedPtr, or None
        self.deleted = False
        self.size = WRAPPER_SIZE

    @classmethod
    def ctor_c1(cls, wrapped):
        """0x5fd0090: the wrapper ctor. `wrapped` is the caller's
        SharedPtr; the copy bumps the use count."""
        obj = cls.__new__(cls)
        obj.vtable = WRAPPER_VTABLE
        obj.options = OptionsVector()
        obj.wrapped = wrapped.copy() if wrapped is not None else None
        obj.deleted = False
        obj.size = WRAPPER_SIZE
        obj.options.append("", "this+0x20", 0x6504B80)
        return obj

    def dtor_d2(self):
        """0x6029230: the wrapper D2. Releases the wrapped clock,
        installs the base vtable and destroys the options vector."""
        events = []
        if self.wrapped is not None:
            events.extend(self.wrapped.release())
            self.wrapped = None
        self.vtable = BASE_VTABLE
        events.append("vector-destroy:%d" % self.options.destroy())
        return events

    def dtor_d0(self):
        """0x6029500: the wrapper D0. The D2 body plus operator
        delete 0x30. The binary never references it: no direct
        caller, no qword hits, no RELATIVE slot."""
        events = self.dtor_d2()
        self.deleted = True
        events.append("delete:0x30")
        return events


class EmulatedClock(Wrapper):
    """The EmulatedSystemClock (0x50 bytes): a wrapper plus the
    emulated state at +0x30 (seeded time), +0x38/+0x40 (zeroed),
    +0x48/+0x49 (the mode byte, duplicated). The ctor C1 0x6029390
    calls the wrapper ctor, installs the emulated vtable, reads the
    wrapped clock's slot-24 GetCurrentTime to seed +0x30, and
    appends two records."""

    def __init__(self, wrapped=None, mode=0, seed=0):
        super().__init__(wrapped)
        self.vtable = EMULATED_VTABLE
        self.size = EMULATED_SIZE
        self.seeded = seed  # +0x30
        self.offset40 = 0  # +0x40
        self.mode = mode  # +0x48 and +0x49
        self.mode_dup = mode

    @classmethod
    def ctor_c1(cls, wrapped, mode, get_current_time):
        """0x6029390: the emulated ctor. `get_current_time` is the
        wrapped clock's slot-24: it fills (out, value_out) and the
        ctor stores value_out at +0x30. The value_out slot is
        preloaded with the constant 0x4fb647d0, exactly as the
        binary does at 0x60293f3."""
        obj = cls.__new__(cls)
        obj.vtable = WRAPPER_VTABLE  # the wrapper ctor installs this
        obj.options = OptionsVector()
        obj.wrapped = wrapped.copy() if wrapped is not None else None
        obj.deleted = False
        obj.size = EMULATED_SIZE
        obj.options.append("", "this+0x20", 0x6504B80)
        obj.vtable = EMULATED_VTABLE  # then the emulated vtable
        _out, value_out = get_current_time(0x4FB647D0)
        obj.seeded = value_out  # +0x30
        obj.offset40 = 0  # +0x40, zeroed by the ctor
        obj.mode = mode
        obj.mode_dup = mode  # +0x48 and +0x49
        obj.options.append("", "this", 0x6505960)
        obj.options.append("", "this", 0x6505920)
        return obj

    def dtor_d2(self):
        """0x6029110: the Emulated D2. Same shape as the wrapper
        D2: release the wrapped clock, install the base vtable,
        destroy the options vector."""
        return super().dtor_d2()

    def dtor_d0(self):
        """0x6029620: the Emulated D0. The D2 body plus operator
        delete 0x50."""
        events = self.dtor_d2()
        self.deleted = True
        events.append("delete:0x50")
        return events

    def get_current_time(self, value_out):
        """The emulated slot-24 0x6025eb0, mirroring
        tools/canonical_lea_sites_115.py's emulated_slot24: flag
        +0x48 set returns *(node+0x30) plus the scaled add of
        *(node+0x40); flag clear recurses to the wrapped clock,
        merges the result, then runs the scaled add when the
        merged code is 0. Returns (code, value)."""
        if self.mode:
            return 0, self.seeded + scaled_add(self.offset40)
        if self.wrapped is None:
            return 0, value_out
        code, value = self.wrapped.obj.get_current_time(value_out)
        if code == 0:
            value += scaled_add(self.offset40)
        return code, value


# --- thunk manager ---------------------------------------------------------

class ThunkFunction:
    """A std::function built from a {manager, invoker} pair: 0x20
    bytes {storage 0x10, manager, invoker}. The storage starts
    zeroed; the manager thunk dispatches op on it."""

    def __init__(self, manager, invoker):
        self.storage = 0
        self.manager = manager  # a thunk address
        self.invoker = invoker

    def clone(self):
        """Manager op 2: copy the 8-byte functor storage. The
        caller copies the manager/invoker pair separately (as the
        binary does at 0x5fd21a4 and 0x5fd2526)."""
        copy = ThunkFunction(self.manager, self.invoker)
        copy.storage = self.storage
        return copy

    def destroy(self):
        """Manager op 3: destroy the functor. A no-op returning 0
        for a plain function pointer: there is nothing to free."""
        return 0


def manager_dispatch(thunk, dest, src, op):
    """The three entry thunks (0x5fcc5d0, 0x5fcc600, 0x5fcc630),
    one body each: op 0 installs the vtable at (%rdi), op 1 stores
    rsi at (%rdi), op 2 clones the storage, op 3 destroys it.
    Only ops 2 and 3 are ever invoked in the binary."""
    if op == 0:
        dest.storage = src  # install the vtable at (%rdi)
        return 0
    if op == 1:
        dest.storage = src  # store rsi at (%rdi)
        return 0
    if op == 2:
        dest.storage = src.storage
        return 0
    if op == 3:
        return dest.destroy()
    return 0


# --- registry --------------------------------------------------------------

class RegistryEntry:
    """A 0x70-byte registry entry (vtable 0x64d8ed0): the name
    string and the stored {manager, invoker} function."""

    def __init__(self, name, function):
        self.vtable = ENTRY_VTABLE
        self.name = name
        self.function = function
        self.flag_0x48 = 1  # set by default-init at 0x5fd21f3


class RegistryNode:
    """A 0x30-byte registry node (vtable 0x64cde68): the entry
    pointer at +0x08 and the stored function at +0x10..+0x28.
    The node D2 0x5fcc700 installs the base vtable, destroys the
    stored function via manager op 3, then tail-jumps to the
    entry's D0."""

    def __init__(self, entry, function):
        self.vtable = NODE_VTABLE
        self.entry = entry
        self.function = function

    def dtor_d2(self):
        """0x5fcc700: destroy the stored function (op 3), then the
        entry's D0 (slot 1)."""
        events = []
        if self.function is not None:
            events.append("manager-op3")
            self.function.destroy()
            self.function = None
        events.append("entry-d0")
        self.entry = None
        return events


class Registry:
    """The SystemClock registry: name -> RegistryNode. Insert
    clones the caller's function (op 2), builds the node and the
    entry, and destroys the temp function with op 3."""

    def __init__(self):
        self.nodes = {}
        self.locked = False

    def insert(self, name, function):
        """0x5fd24c0: clone the function, build the node and the
        entry, lock the registry, place the node, unlock."""
        cloned = function.clone()
        entry = RegistryEntry(name, cloned)
        node = RegistryNode(entry, cloned)
        self.locked = True
        self.nodes[name] = node
        self.locked = False
        return node

    def register_builtin_system_clocks(self):
        """0x5fd27c0: register MockEnv and CompositeEnv, then
        destroy the temp functions with op 3."""
        for name, (_invoker, thunk, _mode) in INVOKERS.items():
            if name == "TimeEmulatedSystemClock":
                continue
            function = ThunkFunction(thunk, _invoker)
            self.insert(name, function)
            function.destroy()
        return list(self.nodes)

    def default_init(self):
        """0x5fd20d0: build the TimeEmulatedSystemClock entry
        inline (same shape as insert), then destroy the temp
        function with op 3."""
        invoker, thunk, _mode = INVOKERS["TimeEmulatedSystemClock"]
        function = ThunkFunction(thunk, invoker)
        self.insert("TimeEmulatedSystemClock", function)
        function.destroy()
        return self.nodes["TimeEmulatedSystemClock"]


# --- invokers and factory ---------------------------------------------------

def invoker_swap(cell, new_clock):
    """The three invokers' shared swap shape: replace the *(*rdx)
    cell, D0-delete the old clock if non-null. Returns the old
    clock (or None)."""
    old = cell[0]
    cell[0] = new_clock
    if old is not None:
        old.dtor_d0()
    return old


def make_shared_emulated(wrapped, mode, get_current_time):
    """The factory 0x60297a0: make_shared<EmulatedSystemClock>.
    Allocates 0x60 bytes, builds the in-place control block
    (vtable 0x64d1c38, counts (1, 1)), runs the Emulated C1 with
    the given mode, and returns the shared_ptr."""
    control = ControlBlock(use=1, weak=1)
    clock = EmulatedClock.ctor_c1(wrapped, mode, get_current_time)
    return SharedPtr(clock, control)


def holder_accessor(holder):
    """The accessor 0x5fcf430: 9 bytes, returns arg+0x38 (the
    holder's wrapped-clock shared_ptr slot)."""
    return holder.wrapped
