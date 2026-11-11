"""Python model of node #115 rocksdb::ConfigOptions default construction.

Pinned by research/work-items/RE-001-configoptions-default-ctor-115/:
  - ConfigOptions::ConfigOptions() 0x60bb890..0x60bb932 (162 B)
  - ConfigOptions::~ConfigOptions() 0x5e33fb0..0x5e33fea (58 B)
  - ObjectRegistry::NewInstance() 0x61f9400..0x61f963e
  - the nine construction sites (see SITES) and their per-site overrides.

Layout (80 bytes, 0x50):
  +0x00  flag bytes 0-3 (defaults 0,1,1,1; C++ names open)
  +0x04  flag byte 4 (default 0; C++ name open)
  +0x08  delimiter std::string (default ";", SSO)
  +0x28  u32 scalar (default 0; C++ name open)
  +0x2c  u8 scalar (default 0xff; C++ name open)
  +0x30  u64 scalar (default 0x80000; C++ name open)
  +0x38  env (Env*, raw; Env::Default())
  +0x40  registry (shared_ptr<ObjectRegistry>, NewInstance child of Default)

The model keeps observations, inferred names and unknowns separate: fields
whose C++ name is not pinned are named flag0..flag4 / scalar28 / scalar2c /
scalar30.
"""

# Defaults written by the ctor, in order.
FLAG_DEFAULTS = (0, 1, 1, 1, 0)
DELIMITER_DEFAULT = ";"
SCALAR28_DEFAULT = 0
SCALAR2C_DEFAULT = 0xFF
SCALAR30_DEFAULT = 0x80000
SIZE_BYTES = 0x50

# The nine construction sites: (call site, host, config address, overrides,
# consumer). Overrides are (offset, value) applied after the ctor returns.
SITES = [
    ("0x5d8eacf", "ColumnFamilyData::SetOptions", "rsp+0x510",
     [("+0x04", 1)], "apply helper 0x60c4550"),
    ("0x5e3406f", "CompactionServiceResult::Write", "rsp+0x00",
     [("+0x03", 0)], "OptionTypeInfo::SerializeType 0x60bbe50"),
    ("0x5e34458", "CompactionServiceResult::Read", "rsp+0x50",
     [("+0x00", 1), ("+0x03", 0)], "OptionTypeInfo::ParseType 0x60c1bb0"),
    ("0x5ffad84", "CTREncryptionProvider::AddCipher", "rsp+0x40",
     [], "cipher factory 0x5ffa710"),
    ("0x60a1dcf", "GetMutableDBOptionsFromStrings", "rsp+0x00",
     [], "OptionTypeInfo::ParseType 0x60c18b0"),
    ("0x60a20cd", "MutableDBOptionsAreEqual", "rbp-0x90",
     [], "OptionTypeInfo::StructsAreEqual 0x60bfda0"),
    ("0x60d4a48", "PersistRocksDBOptions (outer)", "rbp-0x90",
     [("+0x08", "\n  "), ("+0x03", 0)],
     "PersistRocksDBOptions (inner) 0x60d2820"),
    ("0x612073b", "BlockBasedTable::Open", "rbp-0x190",
     [], "SliceTransform create host 0x61ca3d0"),
    ("0x61c83aa", "SliceTransform::AsString", "rsp+0x20",
     [("+0x08", ";")], "Configurable::ToString 0x60971c0"),
]


class Env:
    """The default Env singleton returned by Env::Default() 0x5fe2860."""

    _default = None

    def __init__(self, name="PosixEnv"):
        self.name = name

    @classmethod
    def Default(cls):
        if cls._default is None:
            cls._default = cls()
        return cls._default


class ControlBlock:
    """A _Sp_counted_ptr_inplace control block (0xd0 bytes).

    vtable 0x64d8f00 for ObjectRegistry blocks (slot 0 -> D1 0x61f8130).
    Counts are the packed (use, weak) pair from 0x459b20: 0x100000001.
    """

    VTABLE = 0x64D8F00
    SIZE = 0xD0

    def __init__(self, obj, vtable=VTABLE):
        self.obj = obj
        self.vtable = vtable
        self.use_count = 1
        self.weak_count = 1
        self.disposed = False
        self.destroyed = False

    def dispose(self, trace):
        # _M_dispose order (NewInstance block): parent release, map tree,
        # names, libraries. The model records the order, not the contents.
        trace.append("dispose: release parent, destroy map, destroy names, "
                     "destroy libraries")
        self.disposed = True

    def destroy(self, trace):
        trace.append("destroy: operator delete 0xd0")
        self.destroyed = True


class SharedPtr:
    """A std::shared_ptr: (ptr, control block)."""

    def __init__(self, ptr, cb):
        self.ptr = ptr
        self.cb = cb

    def release(self, trace, selector_zero=True):
        """_M_release 0x5d350c0 with the 0x64ed290 selector byte.

        selector_zero=True models the lock-addl path (byte at 0x64ed290 is
        0); False models the plain-addl path. The (1,1) fast path calls
        the vtable dispose slot then the destroy slot.
        """
        if self.cb is None:
            trace.append("release: null control block, return")
            return
        if (self.cb.use_count, self.cb.weak_count) == (1, 1):
            trace.append("release: (1,1) fast path")
            self.cb.dispose(trace)
            self.cb.destroy(trace)
            self.cb.use_count = 0
            self.cb.weak_count = 0
            return
        old = self.cb.use_count
        if selector_zero:
            trace.append("release: selector 0, lock addl -1")
        else:
            trace.append("release: selector non-zero, plain addl -1")
        self.cb.use_count -= 1
        if old == 1:
            # __exchange_and_add_dispatch returned 1: last use.
            trace.append("release: last use, _M_release_last_use_cold")
            self.cb.dispose(trace)
            self.cb.weak_count -= 1
            if self.cb.weak_count == 0:
                self.cb.destroy(trace)


class ObjectRegistry:
    """A 0xc0-byte ObjectRegistry (object at control block +0x10).

    parent lives at registry+0x60; +0x70..+0xb7 are zero at construction
    (NewInstance zeroes them, including the mutex slot at +0x98).
    """

    SIZE = 0xC0
    PARENT_OFFSET = 0x60
    ZEROED_LO = 0x70
    ZEROED_HI = 0xB8

    _default = None

    def __init__(self, parent=None):
        self.parent = parent
        self.libraries = []
        self.names = []
        self.map = {}
        self.zeroed = (self.ZEROED_LO, self.ZEROED_HI)

    @classmethod
    def Default(cls):
        if cls._default is None:
            cls._default = cls()
        return cls._default

    @classmethod
    def NewInstance(cls):
        """ObjectRegistry::NewInstance() 0x61f9400.

        Fresh 0xd0 control block + fresh registry whose parent is the
        Default singleton (held by one reference); +0x70..+0xb7 zeroed.
        Returns the shared_ptr by value (ptr, cb).
        """
        parent = cls.Default()
        child = cls(parent=parent)
        cb = ControlBlock(child)
        # The stack temp's reference to the parent is released after the
        # copy into the child's parent slot: net one reference held.
        return SharedPtr(child, cb)


class ConfigOptions:
    """A 0x50-byte rocksdb::ConfigOptions, as built by the default ctor."""

    def __init__(self):
        # movl $0x1010100,(%rdi); movb $0x0,0x4(%rdi)
        self.flag0, self.flag1, self.flag2, self.flag3, self.flag4 = \
            FLAG_DEFAULTS
        # SSO string ";" at +0x08 (ptr=this+0x18, len 1, buf 0x3b).
        self.delimiter = DELIMITER_DEFAULT
        # movl $0x0,0x28(%rdi); movb $0xff,0x2c(%rdi);
        # movq $0x80000,0x30(%rdi)
        self.scalar28 = SCALAR28_DEFAULT
        self.scalar2c = SCALAR2C_DEFAULT
        self.scalar30 = SCALAR30_DEFAULT
        # Env::Default() twice; the first store is dead (same pointer).
        self.env = Env.Default()
        self.env = Env.Default()
        # ObjectRegistry::NewInstance() returns by value into +0x40.
        self.registry = ObjectRegistry.NewInstance()

    @classmethod
    def default(cls):
        return cls()

    def flags(self):
        return (self.flag0, self.flag1, self.flag2, self.flag3, self.flag4)

    def set_flag(self, index, value):
        setattr(self, "flag%d" % index, value)

    def apply_override(self, offset, value):
        """Apply one post-ctor site override, by field offset."""
        if offset == "+0x00":
            self.set_flag(0, value)
        elif offset == "+0x01":
            self.set_flag(1, value)
        elif offset == "+0x02":
            self.set_flag(2, value)
        elif offset == "+0x03":
            self.set_flag(3, value)
        elif offset == "+0x04":
            self.set_flag(4, value)
        elif offset == "+0x08":
            self.delimiter = value
        elif offset == "+0x28":
            self.scalar28 = value
        elif offset == "+0x2c":
            self.scalar2c = value
        elif offset == "+0x30":
            self.scalar30 = value
        else:
            raise ValueError("unknown ConfigOptions offset " + offset)

    def destroy(self, trace=None):
        """ConfigOptions::~ConfigOptions() 0x5e33fb0: release the registry
        shared_ptr (+0x48 control block), then dispose the delimiter
        string (+0x08). The raw env pointer is not released."""
        trace = [] if trace is None else trace
        self.registry.release(trace)
        if len(self.delimiter) > 15:
            trace.append("dispose delimiter: heap buffer freed")
        else:
            trace.append("dispose delimiter: SSO, no free")
        return trace

    def copy(self, trace=None):
        """The inner PersistRocksDBOptions field-by-field copy
        (0x60d2820..0x60d290f): flags dword + flag byte, delimiter via the
        string copy helper, u32/u8/qword scalars, env pointer, registry
        shared_ptr with the use-count bump."""
        trace = [] if trace is None else trace
        other = ConfigOptions.__new__(ConfigOptions)
        other.flag0, other.flag1, other.flag2, other.flag3, other.flag4 = \
            self.flags()
        other.delimiter = self.delimiter
        trace.append("copy delimiter via string copy helper")
        other.scalar28 = self.scalar28
        other.scalar2c = self.scalar2c
        other.scalar30 = self.scalar30
        other.env = self.env
        other.registry = SharedPtr(self.registry.ptr, self.registry.cb)
        self.registry.cb.use_count += 1
        trace.append("copy registry: use-count bump")
        return other


def site_config(call_site):
    """Build the ConfigOptions a construction site ends up with: default
    ctor plus that site's post-ctor overrides."""
    for site, _host, _addr, overrides, _consumer in SITES:
        if site == call_site:
            cfg = ConfigOptions.default()
            for offset, value in overrides:
                cfg.apply_override(offset, value)
            return cfg
    raise ValueError("unknown construction site " + call_site)


def bbtopen_gate(name_present, transform_present):
    """BlockBasedTable::Open constructs only when a stored prefix-extractor
    name exists and no transform is instantiated yet."""
    return bool(name_present) and not bool(transform_present)


def persist_scalar30(db_options_220):
    """Outer Persist: +0x30 keeps the 0x80000 default unless
    DBOptions+0x220 is non-null, in which case it is overwritten."""
    if db_options_220 is None:
        return SCALAR30_DEFAULT
    return db_options_220
