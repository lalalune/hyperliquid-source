"""Python model of node #115's SystemClock registry factory dispatch (RE-001).

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Models the SystemClock factory dispatch 0x5fd4080 and its name lookup
0x5fd3d00 -- the same template as #4428's BlockCipher dispatch 0x5ff9fe0,
instantiated for the "SystemClock" factory type. Evidence lives in
research/work-items/RE-001-system-clock-dispatch-115/.

Call chain (from the dispatcher 0x5fd46c0, the sole caller of the
dispatch at 0x5fd4aa3):

    dispatcher(out, opts, name, clock_slot)
      -> dispatch(out, registry, name, clock_slot)   [0x5fd4080]
        -> lookup(record, registry, name)             [0x5fd3d00]
        -> factory(record, name, &slot, &string)      [record+0x18]

The registered SystemClock creators are NOT pinned: the only binary lead
is the registrar 0x5fd20d0, which builds "TimeEmulatedSystemClock" and
"SystemClock" and calls the register helper 0x5fd1da0. The test fixture
below uses an exact-match "TimeEmulatedSystemClock" creator to exercise
the dispatch; it is a fixture, not a pinned creator.
"""

# Status codes (rocksdb Status::Code), as observed at the 0x61cf670 calls.
K_OK = 0
K_NOT_FOUND = 1
K_CORRUPTION = 2
K_NOT_SUPPORTED = 3
K_INVALID_ARGUMENT = 4

# The pinned routines.
DISPATCH = 0x5FD4080       # registry factory dispatch (SystemClock)
LOOKUP = 0x5FD3D00         # name lookup (SystemClock)
DISPATCHER = 0x5FD46C0      # registry dispatcher, sole caller of DISPATCH
WRAPPER = 0x5FD4C30        # dispatcher wrapper, calls DISPATCHER at 0x5fd4c60
MAP_FIND = 0x5FD2980        # map lookup helper (cited, not pinned)
STATUS_CTOR = 0x61CF670     # Status ctor (code, subcode, msg1, msg2, severity)
STATUS_MOVE_ASSIGN = 0x5FCDF70
RELEASE = 0x5D350C0         # shared_ptr control-block release
STR_CTOR = 0x5FCD890        # std::string ctor from a C string
REGISTRAR = 0x5FD20D0       # TimeEmulatedSystemClock registration (cited)
REGISTER_HELPER = 0x5FD1DA0  # registry register helper (cited)
COUNTS_QWORD = 0x100000001  # (use, weak) == (1, 1), literal at 0x459b20

# Map key the lookup queries (0x5fd2980 argument).
TYPE_SYSTEM_CLOCK = "SystemClock"  # 11 chars, SSO

# Error-message literals (all in .rodata, NUL-terminated).
MSG_SHARED_PREFIX = "Cannot make a shared "      # 0x4487c0, 21 chars
MSG_UNGUARDED_SUFFIX = " from unguarded one "    # 0x432138, 20 chars
MSG_LOAD_PREFIX = "Could not load "              # 0x439466, 15 chars

# The non-inplace shared_ptr control block built on the success path.
CTRL_VTABLE = 0x64CDF38
CTRL_TYPEINFO_ADDR = 0x64CDA40
CTRL_TYPEINFO = (
    "St15_Sp_counted_ptrIPN7rocksdb11SystemClockE"
    "LN9__gnu_cxx12_Lock_policyE2EE"
)
CTRL_VTABLE_SLOTS = [0x5FCC690, 0x5FCC800, 0x5FCC750, 0x5FCC810, 0x5FCC770]
CTRL_SIZE = 0x18


def status_message(msg1, msg2):
    """The 0x61cf670 message rule: msg1, or msg1 + ': ' + msg2."""
    if not msg2:
        return msg1
    return msg1 + ": " + msg2


class Status:
    """A rocksdb Status: code byte + optional message (state_ at +0x08)."""

    def __init__(self, code, message=""):
        self.code = code
        self.message = message

    def __eq__(self, other):
        return (isinstance(other, Status)
                and self.code == other.code
                and self.message == other.message)

    def __repr__(self):
        return f"Status({self.code}, {self.message!r})"


class FactoryRecord:
    """The 32-byte factory record cloned out of the registry by 0x5fd3d00.

    +0x00 functor storage (16 bytes, zero for these stateless lambdas),
    +0x10 manager function, +0x18 invoker (the creator lambda's _M_invoke).
    """

    SIZE = 0x20

    def __init__(self, manager, invoker, functor=b"\x00" * 16):
        self.functor = bytes(functor)
        self.manager = manager
        self.invoker = invoker

    def clone(self):
        """Manager op 2 (a no-op here) plus the explicit 16-byte copy of
        the {manager, invoker} pair that 0x5fd3d00 performs."""
        return FactoryRecord(self.manager, self.invoker, self.functor)

    def destroy(self):
        """Manager op 3 (a no-op for these stateless lambdas)."""
        return None

    def __eq__(self, other):
        return (isinstance(other, FactoryRecord)
                and self.functor == other.functor
                and self.manager == other.manager
                and self.invoker == other.invoker)

    def __repr__(self):
        return (f"FactoryRecord(manager={self.manager:#x}, "
                f"invoker={self.invoker:#x})")


class ControlBlock:
    """The 0x18-byte non-inplace shared_ptr control block (0x5fd418c).

    +0x00 vtable 0x64cdf38, +0x08 counts (1, 1), +0x10 object pointer.
    """

    def __init__(self, obj):
        self.vtable = CTRL_VTABLE
        self.use_count = 1
        self.weak_count = 1
        self.object = obj

    def __repr__(self):
        return (f"ControlBlock(vtable={self.vtable:#x}, "
                f"counts=({self.use_count},{self.weak_count}), "
                f"object={self.object!r})")


class SharedSlot:
    """A shared_ptr<SystemClock> slot: (object, control block) or empty."""

    def __init__(self):
        self.object = None
        self.control = None

    def store(self, obj, control):
        """Store a new pair, releasing the old control block first."""
        old = self.control
        self.object = obj
        self.control = control
        return old

    def release(self):
        old = self.control
        self.object = None
        self.control = None
        return old


def pattern_matches(pattern, elements, name):
    """The FactoryEntry Matches rule (pinned by PR #3983).

    The query must start with the pattern. With no elements the match is
    exact. Otherwise each element matches in sequence at the current
    position (an element may be absent, ending the match there); the tail
    after the last matched element is decided by that element's mode:
    mode 2 (``://test``) requires an empty tail, mode 3 (``:``) requires
    an all-digit non-empty tail.
    """
    if not name.startswith(pattern):
        return False
    rest = name[len(pattern):]
    if not elements:
        return rest == ""
    pos = 0
    last_mode = None
    for elem, mode in elements:
        if rest[pos:].startswith(elem):
            pos += len(elem)
            last_mode = mode
        else:
            break
    tail = rest[pos:]
    if last_mode is None:
        return tail == ""
    if last_mode == 2:
        return tail == ""
    if last_mode == 3:
        return tail != "" and tail.isdigit()
    return False


class FactoryEntry:
    """One registered factory: a PatternEntry + a std::function record.

    Layout (0x30 bytes, RegisterEncryptionBuiltins packet): +0x00 vtable,
    +0x08 PatternEntry*, +0x10 functor, +0x20 manager, +0x28 invoker.
    Vtable slot 2 forwards Matches to the PatternEntry; slot 3 forwards
    the accessor.
    """

    def __init__(self, pattern, elements, invoker, manager):
        self.pattern = pattern
        self.elements = list(elements)
        self.record = FactoryRecord(manager, invoker)

    def matches(self, name):
        return pattern_matches(self.pattern, self.elements, name)


class ObjectLibrary:
    """One registry library: a mutex plus the type-name -> entries map.

    The map at +0x28 is queried by 0x5fd2980 with the type name
    ("SystemClock").
    """

    def __init__(self, name):
        self.name = name
        self.entries = {}  # type name -> [FactoryEntry]

    def map_get(self, type_name):
        return self.entries.get(type_name)


class ObjectRegistry:
    """An ObjectRegistry: libraries vector, parent pointer (+0x60), mutex.

    The fresh per-ConfigOptions registry built by 0x61f9400 starts with an
    empty libraries vector and its parent set to the global default
    registry returned by the getter 0x61f92b0.
    """

    def __init__(self, parent=None):
        self.libraries = []  # vector of ObjectLibrary, +0x00/+0x08
        self.parent = parent  # +0x60

    def add_library(self, library):
        self.libraries.append(library)


# Fixture manager/invoker addresses for the test library only. The
# registered SystemClock creators are not pinned; these stand in for the
# TimeEmulatedSystemClock registration lead (0x5fd20d0) to exercise the
# dispatch model. They are NOT binary claims.
FIXTURE_MANAGER = 0x5FD20D0
FIXTURE_INVOKER = 0x5FD20D0


def clock_library():
    """Test-fixture library with one exact-match SystemClock creator.

    Fixture only: the binary pins the 'SystemClock' map key and the
    'TimeEmulatedSystemClock' name in the registrar 0x5fd20d0, not the
    creator routine itself.
    """
    lib = ObjectLibrary("clock")
    lib.entries[TYPE_SYSTEM_CLOCK] = [
        FactoryEntry("TimeEmulatedSystemClock", [], FIXTURE_INVOKER,
                     FIXTURE_MANAGER),
    ]
    return lib


def lookup(registry, name, type_name=TYPE_SYSTEM_CLOCK):
    """0x5fd3d00: resolve `name` to a cloned FactoryRecord, or None.

    Walks the libraries vector backwards under the registry mutex
    (+0x98); per library locks its mutex and queries its map for the type
    name; the first candidate whose Matches(name) holds wins. On
    exhaustion recurses into the parent registry (+0x60); with no parent
    the out record is zeroed (None).
    """
    reg = registry
    while reg is not None:
        for lib in reversed(reg.libraries):
            candidates = lib.map_get(type_name)
            if not candidates:
                continue
            for candidate in candidates:
                if candidate.matches(name):
                    return candidate.record.clone()
        reg = reg.parent
    return None


def dispatch(registry, name, out_slot, invokers,
             type_name=TYPE_SYSTEM_CLOCK):
    """0x5fd4080: build the named object into `out_slot`.

    `invokers` maps an invoker address to a callable
    ``(record, name, raw_slot, message_slot) -> raw_ptr`` modelling the
    creator lambda: it stores the new raw object pointer at the slot and
    returns it, or returns None on failure (optionally writing an error
    message into `message_slot[0]`, the dispatch's 4th string arg).
    `out_slot` is a SharedSlot; `raw_slot` is a one-element list holding
    the raw pointer the factory stored (None when the factory stored
    nothing).

    Returns (Status, out_slot).
    """
    record = lookup(registry, name, type_name)
    if record is None:
        return (Status(K_NOT_SUPPORTED,
                       status_message("Could not load " + type_name, name)),
                out_slot)
    raw_slot = [None]
    message_slot = [None]
    raw = invokers[record.invoker](record, name, raw_slot, message_slot)
    if raw is None:
        # 0x5fd4340: the factory's string arg decides the message. Empty
        # (0x88(%rsp) == 0) -> "Could not load SystemClock: <name>";
        # filled -> "<factory message>: <name>". Both are built into the
        # 0x30(%rsp) temp and move-assigned into *out by the shared tail.
        if message_slot[0] is None:
            message = status_message("Could not load " + type_name, name)
        else:
            message = status_message(message_slot[0], name)
        return Status(K_INVALID_ARGUMENT, message), out_slot
    record.destroy()  # manager op 3 (no-op for these lambdas)
    if raw_slot[0] is None:
        return (Status(K_INVALID_ARGUMENT,
                       status_message(
                           "Cannot make a shared " + type_name
                           + " from unguarded one ", name)),
                out_slot)
    control = ControlBlock(raw_slot[0])
    out_slot.store(raw_slot[0], control)
    return Status(K_OK), out_slot


def clock_creator(record, name, raw_slot, message_slot):
    """Fixture creator: stores the new clock, returns it."""
    obj = ("TimeEmulatedSystemClock", name)
    raw_slot[0] = obj
    return obj


def null_creator(record, name, raw_slot, message_slot):
    """A creator that fails: returns null without storing anything."""
    return None


def null_creator_with_message(record, name, raw_slot, message_slot):
    """A creator that fails and fills the string arg with a message."""
    message_slot[0] = "factory refused the name"
    return None


def unguarded_creator(record, name, raw_slot, message_slot):
    """A creator that returns a raw pointer without storing it in the slot."""
    return ("OrphanClock", name)


DEFAULT_INVOKERS = {
    FIXTURE_INVOKER: clock_creator,
}
