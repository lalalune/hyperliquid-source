"""Python model of node #115's registry factory dispatch (RE-001).

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Models the BlockCipher factory dispatch 0x5ff9fe0 and its name lookup
0x5ff9c60, plus the parallel EncryptionProvider pair 0x5ffb250/0x5ffaeb0.
Evidence lives in research/work-items/RE-001-registry-factory-dispatch-115/.

Call chain (from #4402's dispatcher 0x5ffa710, the sole caller of the
dispatch at 0x5ffa962):

    dispatcher(out, opts, name, cipher_slot)
      -> dispatch(out, registry=opts+0x40, name, cipher_slot)   [0x5ff9fe0]
        -> lookup(record, registry, name)                        [0x5ff9c60]
        -> factory(record, name, &slot, &empty_string)           [record+0x18]

ConfigOptions+0x40 is a std::shared_ptr<ObjectRegistry> (object at +0x40,
control block at +0x48), built by the default init 0x60bb890 through
0x61f9400 (fresh 0xd0-byte registry from the getter 0x61f92b0, PR #4015).
"""

# Status codes (rocksdb Status::Code), as observed at the 0x61cf670 calls.
K_OK = 0
K_NOT_FOUND = 1
K_CORRUPTION = 2
K_NOT_SUPPORTED = 3
K_INVALID_ARGUMENT = 4

# The pinned routines.
DISPATCH = 0x5FF9FE0       # registry factory dispatch (BlockCipher)
LOOKUP = 0x5FF9C60         # name lookup (BlockCipher)
TWIN_DISPATCH = 0x5FFB250  # registry factory dispatch (EncryptionProvider)
TWIN_LOOKUP = 0x5FFAEB0    # name lookup (EncryptionProvider)
DISPATCHER = 0x5FFA710      # registry dispatcher, sole caller of DISPATCH
TWIN_DISPATCHER = 0x5FFBA10  # twin dispatcher, sole caller of TWIN_DISPATCH
MAP_FIND = 0x5FD2980        # map lookup helper (cited, not pinned)
STATUS_CTOR = 0x61CF670     # Status ctor (code, subcode, msg1, msg2, severity)
STATUS_MOVE_ASSIGN = 0x5FEFE90
RELEASE = 0x5D350C0         # shared_ptr control-block release
STR_CTOR = 0x5FF0300        # std::string ctor from a C string
REGISTRY_GETTER = 0x61F92B0  # default-registry getter (PR #4015)
REGISTRY_BUILDER = 0x61F9400  # builds the fresh per-ConfigOptions registry
CONFIG_INIT = 0x60BB890     # ConfigOptions default init (cited, #4402)
COUNTS_QWORD = 0x100000001  # (use, weak) == (1, 1), literal at 0x459b20

# Map keys the two lookups query (0x5fd2980 argument).
TYPE_BLOCK_CIPHER = "BlockCipher"                # 11 chars, SSO
TYPE_ENCRYPTION_PROVIDER = "EncryptionProvider"  # 18 chars, heap-backed

# Error-message literals (all in .rodata, NUL-terminated).
MSG_SHARED_PREFIX = "Cannot make a shared "      # 0x4487c0, 21 chars
MSG_UNGUARDED_SUFFIX = " from unguarded one "    # 0x432138, 20 chars
MSG_LOAD_PREFIX = "Could not load "              # 0x439466, 15 chars

# The non-inplace shared_ptr control block built on the success path.
CTRL_VTABLE = 0x64D0198
CTRL_TYPEINFO_ADDR = 0x64CF850
CTRL_TYPEINFO = (
    "St15_Sp_counted_ptrIPN7rocksdb11BlockCipherE"
    "LN9__gnu_cxx12_Lock_policyE2EE"
)
CTRL_VTABLE_SLOTS = [0x5FEFB50, 0x5FEFCE0, 0x5FEFC20, 0x5FEFCF0, 0x5FEFC40]
CTRL_SIZE = 0x18

# std::function manager ops, as observed in 0x5fefa50/0x5fefa80/0x5fefab0
# (pinned by the RegisterEncryptionBuiltins packet): op 0 stores the
# typeinfo address, op 1 clones the functor, op 2 and op 3 are no-ops for
# these stateless creator lambdas.
MANAGER_GET_TYPEINFO = 0
MANAGER_CLONE = 1
MANAGER_NOOP_2 = 2
MANAGER_NOOP_3 = 3
MANAGER_TYPEINFO = {
    0x5FEFA50: 0x64CF7B8,  # CTR creator 0x5ff6d60
    0x5FEFA80: 0x64CF7C8,  # 1://test creator 0x5ff6a00
    0x5FEFAB0: 0x64CF7D8,  # ROT13 creator 0x5ff7120 (address from relocs)
}

# The three registered creator lambdas (RegisterEncryptionBuiltins packet).
CREATORS = {
    # name pattern -> (invoker, manager, elements)
    "CTR": (0x5FF6D60, 0x5FEFA50, [("://test", 2)]),
    "1://test": (0x5FF6A00, 0x5FEFA80, []),
    "ROT13": (0x5FF7120, 0x5FEFAB0, [(":", 3)]),
}


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
    """The 32-byte factory record cloned out of the registry by 0x5ff9c60.

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
        the {manager, invoker} pair that 0x5ff9c60 performs."""
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


def manager_op(manager, dest, src, op):
    """The std::function manager protocol for 0x5fefa50/0x5fefa80/0x5fefab0.

    Returns the typeinfo address for op 0, copies the functor for op 1,
    and does nothing (returns 0) for ops 2 and 3. `dest`/`src` are
    one-element lists standing in for the functor storage cells.
    """
    if op == MANAGER_GET_TYPEINFO:
        dest[0] = MANAGER_TYPEINFO[manager]
        return 0
    if op == MANAGER_CLONE:
        dest[0] = src[0]
        return 0
    return 0


class ControlBlock:
    """The 0x18-byte non-inplace shared_ptr control block (0x5ffa106).

    +0x00 vtable 0x64d0198, +0x08 counts (1, 1), +0x10 object pointer.
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
    """A shared_ptr<BlockCipher> slot: (object, control block) or empty."""

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
    ("BlockCipher" / "EncryptionProvider").
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


def encryption_library():
    """The 'encryption' ObjectLibrary as registered by 0x5ff88c0."""
    lib = ObjectLibrary("encryption")
    lib.entries[TYPE_BLOCK_CIPHER] = [
        FactoryEntry("CTR", [("://test", 2)], 0x5FF6D60, 0x5FEFA50),
        FactoryEntry("1://test", [], 0x5FF6A00, 0x5FEFA80),
        FactoryEntry("ROT13", [(":", 3)], 0x5FF7120, 0x5FEFAB0),
    ]
    return lib


def lookup(registry, name, type_name=TYPE_BLOCK_CIPHER):
    """0x5ff9c60: resolve `name` to a cloned FactoryRecord, or None.

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
             type_name=TYPE_BLOCK_CIPHER):
    """0x5ff9fe0: build the named object into `out_slot`.

    `invokers` maps an invoker address to a callable
    ``(record, name, raw_slot) -> (raw_ptr, stored_ptr)`` modelling the
    creator lambda: it stores the new raw object pointer at the slot and
    returns it, or returns (None, None) on failure. `out_slot` is a
    SharedSlot; `raw_slot` is a one-element list holding the raw pointer
    the factory stored (None when the factory stored nothing).

    Returns (Status, out_slot).
    """
    record = lookup(registry, name, type_name)
    if record is None:
        return (Status(K_NOT_SUPPORTED,
                       status_message("Could not load " + type_name, name)),
                out_slot)
    raw_slot = [None]
    raw = invokers[record.invoker](record, name, raw_slot)
    if raw is None:
        return (Status(K_INVALID_ARGUMENT,
                       status_message("Could not load " + type_name, name)),
                out_slot)
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


def rot13_creator(record, name, raw_slot):
    """The ROT13 creator 0x5ff7120: stores the new cipher, returns it."""
    obj = ("ROT13BlockCipher", 32)
    raw_slot[0] = obj
    return obj


def ctr_creator(record, name, raw_slot):
    """The CTR creator 0x5ff6d60: stores the new provider, returns it."""
    obj = ("CTREncryptionProvider", name)
    raw_slot[0] = obj
    return obj


def test_creator(record, name, raw_slot):
    """The 1://test creator 0x5ff6a00: stores the new provider, returns it."""
    obj = ("CTREncryptionProvider", name)
    raw_slot[0] = obj
    return obj


def null_creator(record, name, raw_slot):
    """A creator that fails: returns null without storing anything."""
    return None


def unguarded_creator(record, name, raw_slot):
    """A creator that returns a raw pointer without storing it in the slot."""
    return ("OrphanCipher", name)


DEFAULT_INVOKERS = {
    0x5FF7120: rot13_creator,
    0x5FF6D60: ctr_creator,
    0x5FF6A00: test_creator,
}
