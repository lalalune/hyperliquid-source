"""Python model of node #115's CompositeEnvWrapper construction and
destruction end-to-end (RE-001).

Faithful model of the 40 windows in
research/work-items/RE-001-composite-env-wrapper-115/:
the builder 0x5fd7360 and the install helper 0x5fceb20, the wrapper
D2 0x5fd72d0 and D0 0x5fd7510 with the base D2 0x5fcf4d0, the
wrapper vtable overrides (slot 5 PrepareOptions 0x5fd7560, slot 12
SerializeOptions 0x5fd5e00, slot 14 Name 0x5fd4e60, slot 16
IsInstanceOf 0x5fd6240, slot 17 wrapped-env accessor 0x5fd4e70),
the 20 forwarder slots 45-52, 59, 63-69, 71, 79-81, the default
holder initializer 0x5fe2860, the FactoryEntry node slot 2
0x5fcc7e0, and the factory control-block dispose 0x6025950 and
destroy 0x6025b90. The record-append 0x6099ce0, grow 0x6099790,
holder accessor 0x5fcf430 and CompositeEnv invoker 0x5fcf450 are
re-shipped byte-identical from the RE-001-systemclock-installers-115
packet (open PR #3948); the model builds on the same shared_ptr
and options-vector semantics that packet pinned.

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
"""

# --- constants pinned by the binary -----------------------------------

ENV_VTABLE = 0x64CDAD0
COMPOSITE_ENV_VTABLE = 0x64CE2D8
WRAPPER_VTABLE = 0x64CE590
CONFIGURABLE_VTABLE = 0x64D3430
MOCK_ENV_VTABLE = 0x64D1398
NODE_VTABLE = 0x64CDE68
FACTORY_CB_VTABLE = 0x64D1C38
TSU_VTABLE = 0x64CE8E0

# The wrapper object is 0x60 bytes; the base (CompositeEnv) is 0x50.
WRAPPER_SIZE = 0x60
BASE_SIZE = 0x50
# The options-vector record is 0x30 bytes.
RECORD_SIZE = 0x30
# The factory allocates 0x60 bytes for the make_shared object.
FACTORY_ALLOC = 0x60
# A fresh control block starts at counts 0x100000001 = (use 1, weak 1).
FRESH_COUNTS = 0x100000001

# The selector cell: byte 0 selects the atomic (lock) increment /
# decrement forms, any other byte the plain forms.
SELECTOR_CELL = 0x64ED290

# The three record-global addresses the builder appends as the
# third field of its three empty-named records.
RECORD_GLOBALS = (0x6504C60, 0x6504C20, 0x6504BE0)
# The default holder object and its guard byte.
HOLDER = 0x6504CC0
HOLDER_GUARD = 0x6504CA8
# The holder's ThreadStatusUpdater object and its atexit dtor.
TSU_OBJECT = 0x6504CE0
TSU_DTOR = 0x5FE2C30
DSO_HANDLE = 0x64EFA20

# Literals pinned by the binary.
NAME_STRING = "CompositeEnv"
NAME_STRING_ADDR = 0x43E762
TARGET_PREFIX = "target="
TARGET_PREFIX_ADDR = 0x4496D1
MUTEX_NAME = "mutex_init"
MUTEX_NAME_ADDR = 0x4429A3
FLOAT_ONE_ADDR = 0x459E78

# The 20 forwarder slots: slot -> (address, form). Jmp-form
# forwarders take the wrapped env from this+0x48 and tail-jump to
# the wrapped env's same slot; call-form forwarders take it from
# the second argument's +0x48, call the wrapped env's same slot,
# and return this.
FORWARDERS = {
    45: (0x5FD4E80, "call"), 46: (0x5FD4ED0, "jmp"),
    47: (0x5FD4EF0, "jmp"), 48: (0x5FD4F10, "jmp"),
    49: (0x5FD4F30, "jmp"), 50: (0x5FD4F70, "jmp"),
    51: (0x5FD4F90, "jmp"), 52: (0x5FD4F50, "jmp"),
    59: (0x5FD4FB0, "call"), 63: (0x5FD5000, "jmp"),
    64: (0x5FD5020, "jmp"), 65: (0x5FD5040, "call"),
    66: (0x5FD5090, "jmp"), 67: (0x5FD50B0, "jmp"),
    68: (0x5FD50F0, "call"), 69: (0x5FD50D0, "jmp"),
    71: (0x5FD51D0, "call"), 79: (0x5FD5140, "call"),
    80: (0x5FD5190, "jmp"), 81: (0x5FD51B0, "jmp"),
}

# The 27 slots where the wrapper vtable differs from CompositeEnv's.
WRAPPER_DIFF_SLOTS = (0, 1, 5, 12, 14, 16, 17, 45, 46, 47, 48, 49, 50,
                      51, 52, 59, 63, 64, 65, 66, 67, 68, 69, 71, 79,
                      80, 81)
# The 3 slots where MockEnv's vtable differs from the wrapper's.
MOCK_DIFF_SLOTS = (0, 1, 14)


def selector_is_atomic(selector_byte):
    """The 0x64ed290 selector: byte 0 selects the lock forms,
    any other byte the plain forms."""
    return selector_byte == 0


# --- shared_ptr ---------------------------------------------------------

class ControlBlock:
    """A shared_ptr control block: (use_count, weak_count) in one
    64-bit word at +0x08 plus the dispose/destroy slots at vtable
    +0x10/+0x18. A fresh block starts at (1, 1)."""

    def __init__(self, use=1, weak=1, atomic=False):
        self.use = use
        self.weak = weak
        self.atomic = atomic  # the byte at 0x64ed290 selects lock xadd
        self.disposed = False
        self.destroyed = False
        self.dispose_calls = 0
        self.destroy_calls = 0

    @property
    def counts(self):
        """The packed 64-bit counts word: low 32 use, high 32 weak."""
        return (self.weak << 32) | (self.use & 0xFFFFFFFF)

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
    count (selector-gated); releasing follows _M_release 0x5d350c0
    and its dispose tail 0x5d35070."""

    def __init__(self, obj, control):
        self.obj = obj
        self.control = control

    def copy(self):
        """The install helper's copy at 0x5fceb66..0x5fceb72 and the
        slot-5 copy-in: bump the use count (lock addl when the
        selector byte is 0, plain addl otherwise) and share the
        control block."""
        if self.control is not None:
            self.control.use += 1
        return SharedPtr(self.obj, self.control)

    def release(self):
        """_M_release 0x5d350c0: fast path when counts are
        (1, 1) — dispose then destroy with no count traffic;
        otherwise decrement use (lock xadd when the selector byte
        is 0, plain decrement otherwise); when the old use was 1,
        run the dispose tail 0x5d35070. Returns the events."""
        events = []
        ctrl = self.control
        if ctrl is None:
            return events
        if ctrl.counts == FRESH_COUNTS:
            ctrl.use = 0
            ctrl.weak = 0
            ctrl.dispose()
            events.append("dispose")
            ctrl.destroy()
            events.append("destroy")
        else:
            old_use = ctrl.use
            ctrl.use -= 1
            if old_use == 1:
                events.extend(dispose_tail(ctrl))
        self.obj = None
        self.control = None
        return events


def dispose_tail(control):
    """The 0x5d35070 dispose tail, entered once the use count has
    already reached 0: dispose the object (slot 0x10), decrement
    the weak count (lock xadd when the selector byte is 0, plain
    otherwise), and destroy the control block (slot 0x18) when the
    old weak count was 1. Returns the events, in order."""
    events = []
    control.dispose()
    events.append("dispose")
    old_weak = control.weak
    control.weak -= 1
    events.append("weak--")
    if old_weak == 1:
        control.destroy()
        events.append("destroy")
    return events


def release_with_prior_decrement(control):
    """The holder-init's temp-shared_ptr release at
    0x5fe2921..0x5fe2962: fast path when counts are (1, 1) —
    dispose then destroy inline; otherwise decrement use
    (selector-gated) and, when the old use was 1, call the
    dispose tail 0x5d35070. Returns the events."""
    events = []
    if control.counts == FRESH_COUNTS:
        control.use = 0
        control.weak = 0
        control.dispose()
        events.append("dispose")
        control.destroy()
        events.append("destroy")
        return events
    old_use = control.use
    control.use -= 1
    if old_use == 1:
        events.extend(dispose_tail(control))
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
        """0x6099790: double the capacity, bounded by the max
        check; move-construct the records (SSO strings copied
        inline, heap strings moved with the source nulled) and
        free the old buffer."""
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
        """The base D2 vector teardown: string-dispose each
        record (heap strings freed), then free the buffer."""
        disposed = len(self.records)
        self.records = []
        self.capacity = 0
        self.buffer_freed = True
        return disposed


# --- env objects ---------------------------------------------------------

class CompositeEnv:
    """The base CompositeEnv object (0x50 bytes): +0x00 vtable,
    +0x08..+0x18 the options vector, +0x28/+0x30 shared_ptr A,
    +0x38/+0x40 shared_ptr B, +0x48 the wrapped Env*."""

    def __init__(self):
        self.vtable = COMPOSITE_ENV_VTABLE
        self.options = OptionsVector()
        self.sp_a = None  # shared_ptr at +0x28/+0x30
        self.sp_b = None  # shared_ptr at +0x38/+0x40
        self.wrapped = None  # Env* at +0x48
        self.size = BASE_SIZE

    @classmethod
    def install(cls, obj, sp_a, sp_b):
        """The install helper 0x5fceb20: install the Env vtable,
        zero the vector range (+0x08..+0x20), copy shared_ptr A
        from the caller's slot (selector-gated use-count bump)
        and shared_ptr B from the caller's 16-byte slot the same
        way."""
        obj.vtable = ENV_VTABLE
        obj.options = OptionsVector()
        obj.sp_a = sp_a.copy() if sp_a is not None else None
        obj.sp_b = sp_b.copy() if sp_b is not None else None
        return obj

    def dtor_d2(self):
        """The base D2 0x5fcf4d0: install the Env vtable, release
        shared_ptr B then shared_ptr A via _M_release, install
        the Configurable vtable, destroy the options vector and
        free its buffer."""
        events = []
        self.vtable = ENV_VTABLE
        if self.sp_b is not None:
            events.extend(self.sp_b.release())
            self.sp_b = None
        if self.sp_a is not None:
            events.extend(self.sp_a.release())
            self.sp_a = None
        self.vtable = CONFIGURABLE_VTABLE
        events.append("vector-destroy:%d" % self.options.destroy())
        return events


class CompositeEnvWrapper(CompositeEnv):
    """The CompositeEnvWrapper object (0x60 bytes): a CompositeEnv
    plus shared_ptr C at +0x50/+0x58."""

    def __init__(self):
        super().__init__()
        self.vtable = WRAPPER_VTABLE
        self.sp_c = None  # shared_ptr at +0x50/+0x58
        self.size = WRAPPER_SIZE

    @classmethod
    def builder(cls, wrapped, sp_a, sp_b):
        """The builder 0x5fd7360: install via 0x5fceb20 with
        (sp_a, sp_b) — the invoker 0x5fcf450 passes the
        holder's +0x28 slot (via the helper 0x5fcf390) and
        +0x38 slot (via the accessor 0x5fcf430) — store the
        wrapped env at +0x48, zero shared_ptr C, install the
        wrapper vtable, and append the three empty-named
        records {"", this+0x48, 0x6504c60}, {"", this+0x28,
        0x6504c20}, {"", this+0x38, 0x6504be0}."""
        obj = cls.__new__(cls)
        obj.vtable = ENV_VTABLE
        obj.options = OptionsVector()
        obj.sp_a = None
        obj.sp_b = None
        obj.wrapped = None
        obj.sp_c = None
        obj.size = WRAPPER_SIZE
        cls.install(obj, sp_a, sp_b)
        obj.wrapped = wrapped
        obj.sp_c = None
        obj.vtable = WRAPPER_VTABLE
        obj.options.append("", "this+0x48", 0x6504C60)
        obj.options.append("", "this+0x28", 0x6504C20)
        obj.options.append("", "this+0x38", 0x6504BE0)
        return obj

    def dtor_d2(self):
        """The wrapper D2 0x5fd72d0: install the wrapper vtable,
        release shared_ptr C via _M_release, install the
        CompositeEnv vtable, then tail-jump to the base D2."""
        events = []
        self.vtable = WRAPPER_VTABLE
        if self.sp_c is not None:
            events.extend(self.sp_c.release())
            self.sp_c = None
        self.vtable = COMPOSITE_ENV_VTABLE
        events.extend(super().dtor_d2())
        return events

    def dtor_d0(self):
        """The wrapper D0 0x5fd7510: the D2 body (via a call to
        the base D2, not a tail jump) plus operator delete 0x60."""
        events = self.dtor_d2()
        events.append("delete:0x60")
        return events

    # -- vtable overrides ------------------------------------------------

    def prepare_options(self, target, options, holder=None):
        """Slot 5 PrepareOptions 0x5fd7560: resolve the target's
        wrapped env — the target's shared_ptr C object if set,
        else the target's +0x48 if set, else the default holder
        from 0x5fe2860 — store it at target+0x48; if target's
        shared_ptr A is null, copy the env's +0x28 shared_ptr in
        via the helper 0x5fcf390 (selector-gated bump, old
        release); if target's shared_ptr B is null, copy the
        wrapped env's +0x38 shared_ptr in via the accessor
        0x5fcf430 the same way; then tail-call the base
        PrepareOptions 0x6095e70. `holder` is the default-holder
        object (its wrapped env); pass None to model the
        holder-init call returning the holder."""
        events = []
        if target.sp_c is not None and target.sp_c.obj is not None:
            target.wrapped = target.sp_c.obj
            events.append("wrapped-from-sp-c")
        elif target.wrapped is not None:
            events.append("wrapped-kept")
        else:
            target.wrapped = holder.wrapped if holder is not None else None
            events.append("wrapped-from-holder")
        if target.sp_a is None and target.wrapped is not None:
            src = target.wrapped.sp_a
            if src is not None:
                target.sp_a = src.copy()
                events.append("sp-a-copied-in")
        if target.sp_b is None and target.wrapped is not None:
            src = target.wrapped.sp_b
            if src is not None:
                target.sp_b = src.copy()
                events.append("sp-b-copied-in")
        events.append("base-prepare-options")
        return events

    def serialize_options(self, out, env, options, serialize_wrapped):
        """Slot 12 SerializeOptions 0x5fd5e00: call the base
        0x609de80 first (it fills `out` with the base
        serialization); then, if the env's wrapped env is
        non-null and is not the default holder, append "target="
        plus the wrapped env's serialization (via the helper
        0x60971c0) to `out`. `serialize_wrapped` is the helper
        by contract: wrapped env -> serialized string. Returns
        the output string."""
        base = "base-serialization"
        out.append(base)
        wrapped = env.wrapped
        if wrapped is not None and not wrapped.is_default_holder:
            out.append(TARGET_PREFIX)
            out.append(serialize_wrapped(wrapped, options))
        return "".join(out)

    def name(self):
        """Slot 14 Name 0x5fd4e60: returns "CompositeEnv"."""
        return NAME_STRING

    def is_instance_of(self, arg):
        """Slot 16 IsInstanceOf 0x5fd6240: returns 1 iff the arg
        string has length 12 and equals "CompositeEnv"; else
        falls back to the base 0x5d2e770 (modelled as 0)."""
        if len(arg) == 12 and arg == NAME_STRING:
            return 1
        return 0  # base 0x5d2e770 fallback

    def wrapped_env(self):
        """Slot 17 0x5fd4e70: returns this+0x48, the wrapped env."""
        return self.wrapped

    def forward(self, slot, *args, **kwargs):
        """One of the 20 forwarder slots: jmp-form forwards
        this+0x48's same slot (tail jump); call-form forwards
        the second argument's +0x48 and returns this. The
        wrapped env's slot is modelled by `kwargs["target"]`,
        a callable standing in for the wrapped env's vtable
        slot. Returns (form, result)."""
        addr, form = FORWARDERS[slot]
        if form == "jmp":
            wrapped = self.wrapped
            result = kwargs["target"](wrapped, *args)
            return ("jmp", result)
        wrapped = kwargs["arg_env"].wrapped
        result = kwargs["target"](wrapped, *args)
        return ("call", self)  # call-form returns this

    # -- MockEnv sharing --------------------------------------------------

    @classmethod
    def mock_env_vtable_differs(cls):
        """MockEnv's vtable shares every wrapper slot except
        0, 1 (its own D2/D0 0x6028f90/0x6029050) and 14 (its own
        Name 0x6025790)."""
        return MOCK_DIFF_SLOTS


class Env:
    """A plain Env object for the model: the fields the wrapper
    reads and writes (sp_a at +0x28, sp_b at +0x38, wrapped at
    +0x48, sp_c at +0x50)."""

    def __init__(self, wrapped=None, sp_a=None, sp_b=None, sp_c=None,
                 is_default_holder=False, tag=None):
        self.wrapped = wrapped
        self.sp_a = sp_a
        self.sp_b = sp_b
        self.sp_c = sp_c
        self.is_default_holder = is_default_holder
        self.tag = tag  # test-only label; the binary has no such field


# --- default holder -------------------------------------------------------

class ThreadStatusUpdater:
    """The 0xd8-byte ThreadStatusUpdater at 0x6504ce0 built by the
    holder initializer: vtable 0x64ce8e0, +0x38/+0x70/+0xa8 = 1,
    float 1.0 at +0x50/+0x88/+0xc0, self-pointers +0x30->+0x60,
    +0x68->+0x98, +0xa0->+0xd0, the rest zeroed."""

    SIZE = 0xD8

    def __init__(self, base):
        self.vtable = TSU_VTABLE
        self.base = base
        self.field_38 = 1
        self.field_70 = 1
        self.field_a8 = 1
        self.float_50 = 1.0
        self.float_88 = 1.0
        self.float_c0 = 1.0
        self.ptr_30 = base + 0x60
        self.ptr_68 = base + 0x98
        self.ptr_a0 = base + 0xD0

    def field_map(self):
        """The pinned non-zero fields, as (offset, value)."""
        return [(0x38, 1), (0x70, 1), (0xA8, 1),
                (0x50, 1.0), (0x88, 1.0), (0xC0, 1.0),
                (0x30, self.ptr_30), (0x68, self.ptr_68),
                (0xA0, self.ptr_a0)]


class DefaultHolder:
    """The function-local static holder at 0x6504cc0 built by the
    initializer 0x5fe2860: a CompositeEnv whose wrapped env comes
    from the PosixClock accessor 0x5fe2680 and whose shared_ptrs
    come from the PosixFileSystem holder accessor 0x60029f0, plus
    a 0x40-byte 4x0x10 record array, a "mutex_init" mutex, and
    the ThreadStatusUpdater above. The opaque callees
    (0x61d2ca0, 0x61c21b0, 0x61d4570, 0x61d4740, 0x61d4730,
    0x61d4420, 0x60029f0 internals) are by contract."""

    GUARD = HOLDER_GUARD
    ADDRESS = HOLDER

    def __init__(self):
        self.initialized = False
        self.guard_released = False
        self.env = CompositeEnv()
        self.env.vtable = COMPOSITE_ENV_VTABLE
        self.records = [None] * 4  # the 4x0x10 record array
        self.mutex_name = MUTEX_NAME
        self.tsu = None
        self.atexit_registered = False

    def initialize(self, clock_wrapped, fs_sp):
        """The 0x5fe2860 body after the guard is acquired:
        install the holder via 0x5fceb20 (clock shared_ptr +
        filesystem shared_ptr), release the temp shared_ptr,
        build the 4-entry record array (each entry via the
        by-contract 0x61d4570), init the mutex named
        "mutex_init" and its 4 entries, build the
        ThreadStatusUpdater, register __cxa_atexit with dtor
        0x5fe2c30, release the guard. Returns the events."""
        if self.initialized:
            return ["already-initialized"]
        events = []
        CompositeEnv.install(self.env, fs_sp, clock_wrapped)
        events.append("holder-installed")
        events.extend(release_with_prior_decrement(fs_sp.control))
        self.records = ["record-%d" % i for i in range(4)]
        events.append("records-built:4")
        self.tsu = ThreadStatusUpdater(TSU_OBJECT)
        events.append("tsu-built")
        self.atexit_registered = True
        events.append("atexit-registered")
        self.guard_released = True
        self.initialized = True
        events.append("guard-released")
        return events


# --- registry node and control block --------------------------------------

class RegistryNode:
    """A FactoryEntry<Env> node (vtable 0x64cde68): +0x08 the
    entry pointer. Slot 2 0x5fcc7e0 forwards this+0x08's vtable
    slot 2."""

    def __init__(self, entry):
        self.vtable = NODE_VTABLE
        self.entry = entry

    def slot2(self, *args):
        """0x5fcc7e0: forward this+0x08's vtable slot 2. `entry`
        stands in for the entry object; its slot2 callable is
        invoked with the entry as receiver."""
        return self.entry.slot2(*args)


class FactoryControlBlock(ControlBlock):
    """The make_shared control block (vtable 0x64d1c38,
    _Sp_counted_ptr_inplace<EmulatedSystemClock>): dispose
    0x6025950 calls the managed object's slot 0 (D2) with
    this+0x10; destroy 0x6025b90 is operator delete 0x60."""

    def __init__(self, managed):
        super().__init__(use=1, weak=1)
        self.vtable = FACTORY_CB_VTABLE
        self.managed = managed  # the object at +0x10

    def dispose(self):
        """0x6025950: destroy the managed object via its slot 0
        (D2)."""
        self.dispose_calls += 1
        self.disposed = True
        if self.managed is not None:
            self.managed.dtor_d2()

    def destroy(self):
        """0x6025b90: operator delete 0x60."""
        self.destroy_calls += 1
        self.destroyed = True


def holder_accessor(holder):
    """The accessor 0x5fcf430: 9 bytes, returns arg+0x38 (the
    holder's shared_ptr B slot)."""
    return holder.sp_b
