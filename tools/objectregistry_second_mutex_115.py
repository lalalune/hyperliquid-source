"""Python model of node #115's ObjectRegistry two-mutex discipline.

Pinned by research/work-items/RE-001-objectregistry-second-mutex-115
(RE-001): the +0x70 objects_mutex_ and +0x98 library_mutex_ (both
40-byte pthread_mutex_t), their identical zero-initialization by the
ctor (0x61f91b0) and clone (0x61f9400), the three library-mutex
lockers (AddLibrary 0x61f8dc0, big method 0x5ff88c0, TTL registration
0x62069f0), the never-locked / never-destroyed objects_mutex_, and
the dispose (0x61f8760) that destroys neither mutex.

The model is a small explicit-memory simulation: flat address-keyed
fields plus an ops log, so tests can assert the exact operation
sequence the binary performs.
"""

# --- pinned constants (see records.json) -----------------------------------

REGISTRY_SIZE = 0xC0

# ObjectRegistry field offsets within the 0xc0-byte object.
LIBRARIES = 0x00       # vector<shared_ptr<ObjectLibrary>> (24 B)
NAMES = 0x18           # vector<std::string> / plugins_ (24 B)
MANAGED_MAP = 0x30     # std::map<string, weak_ptr<Customizable>> (48 B)
PARENT = 0x60          # shared_ptr<ObjectRegistry> (16 B)
OBJECTS_MUTEX = 0x70   # std::mutex objects_mutex_ (40 B)
LIBRARY_MUTEX = 0x98   # std::mutex library_mutex_ (40 B)
MUTEX_SIZE = 0x28      # sizeof(pthread_mutex_t) on glibc x86-64

# The 16+16+8 zeroing pattern the ctor and clone use for each 40-byte
# mutex (two movups + one movq).
ZERO_CHUNKS = (16, 16, 8)

# FDE ranges for the 12 packet windows plus the getter.
CTOR_FDE = (0x61F91B0, 0x61F9277)
CLONE_FDE = (0x61F9400, 0x61F963E)
DISPOSE_FDE = (0x61F8760, 0x61F89DB)
ADD_LIBRARY_FDE = (0x61F8DC0, 0x61F913D)
TTL_REGISTER_FDE = (0x62069F0, 0x6206D29)
BIG_METHOD_FDE = (0x5FF88C0, 0x5FF9C50)
DESTROY_HELPER_FDE = (0x60D5170, 0x60D5200)
LOCK70_FDES = (
    (0x5F44C80, 0x5F44D56),
    (0x5F44DB0, 0x5F44E53),
    (0x606A450, 0x606A604),
    (0x606A650, 0x606A88E),
    (0x606A900, 0x606AA82),
)
GETTER_FDE = (0x61F92B0, 0x61F93C5)

# The three library-mutex lock sites (lea disp +0x98, then PLT lock),
# with their unlock sites.
LIBRARY_LOCKERS = (
    {"lock": 0x61F8F09, "unlock": 0x61F8F4F, "fde": 0x61F8DC0,
     "routine": "AddLibrary"},
    {"lock": 0x5FF8A28, "unlock": 0x5FF8A7B, "fde": 0x5FF88C0,
     "routine": "big registry method"},
    {"lock": 0x6206B73, "unlock": 0x6206BB4, "fde": 0x62069F0,
     "routine": "TTL registration"},
)

# Census constants (reproduced by census.py).
LOCK_SITES_TOTAL = 1632
LOCK_CALLS = 224
UNLOCK_CALLS = 916
TRYLOCK_CALLS = 487
INIT_CALLS = 4
DESTROY_PLT_CALLS = 1
DESTROY_HELPER_CALLERS = 74
MARKED_FDES = 32
DISP_HITS = 216
DISP70_SITES = 8
DISP98_SITES = 28
GETTER_CALLERS = (0x5FF88FC, 0x61F9420, 0x6206A3D)
INIT_SITES = (
    (0x5FE2A3E, 0x5FE2860),
    (0x60D50DC, 0x60D50C0),
    (0x63BF8D9, 0x63BF840),
    (0x63BFA21, 0x63BF970),
)
DESTROY_HELPER = 0x60D5170
DESTROY_PLT_SITE = 0x60D5189

# Strings whose absence shows the managed-object methods are not linked.
ABSENT_STRINGS = ("Object already exists: ", "Registered Plugins:")

# The binary's only case-insensitive "managed" string (file offset
# 0x95f620): an unrelated RocksDB iterator error message, not a
# registry managed-object string.
SOLE_MANAGED_STRING = "Managed iterator is not supported anymore."
SOLE_MANAGED_STRING_FILE_OFFSET = 0x95F620


class MutexError(Exception):
    """A lock-discipline violation (double lock / wrong-owner unlock)."""


class MethodAbsent(Exception):
    """A method that does not exist in this binary."""


class Memory:
    """Flat address-keyed fields plus an ops log."""

    def __init__(self):
        self.fields = {}
        self.ops = []

    def put(self, addr, off, value):
        self.fields[addr + off] = value

    def get(self, addr, off, default=None):
        return self.fields.get(addr + off, default)


class Mutex:
    """One 40-byte pthread_mutex_t inside a registry object.

    States: 'zeroed' (fresh from ctor/clone), 'unlocked', 'locked'.
    The binary never calls pthread_mutex_init on a registry mutex and
    never destroys one; the model has no init/destroy path on purpose
    (destroy() raises: it must never be reached).
    """

    def __init__(self, mem, registry_addr, offset, name):
        self.mem = mem
        self.registry_addr = registry_addr
        self.offset = offset
        self.name = name
        self.state = "uninitialised"
        self.holder = None
        self.lock_count = 0

    def zero(self):
        """The ctor/clone zeroing: two movups + one movq (16+16+8)."""
        off = self.offset
        for i, chunk in enumerate(ZERO_CHUNKS):
            self.mem.ops.append(("zero", self.registry_addr,
                                 off + sum(ZERO_CHUNKS[:i]), chunk))
        self.mem.put(self.registry_addr, self.offset, 0)
        self.state = "zeroed"
        self.holder = None

    def lock(self, owner):
        if self.state == "locked":
            raise MutexError("%s double-locked by %r" % (self.name, owner))
        if self.state != "zeroed" and self.state != "unlocked":
            raise MutexError("%s locked while %s" % (self.name, self.state))
        self.state = "locked"
        self.holder = owner
        self.lock_count += 1
        self.mem.ops.append(("lock", self.registry_addr, self.offset, owner))

    def unlock(self, owner):
        if self.state != "locked" or self.holder != owner:
            raise MutexError("%s unlocked by non-holder %r"
                             % (self.name, owner))
        self.state = "unlocked"
        self.holder = None
        self.mem.ops.append(("unlock", self.registry_addr, self.offset,
                             owner))

    def destroy(self):
        # No path in the binary reaches this: the dispose never calls
        # the mutex-destructor helper, and the binary's only
        # pthread_mutex_destroy site is elsewhere.
        raise MutexError("%s must never be destroyed" % self.name)


class Registry:
    """An ObjectRegistry object with its two mutexes."""

    def __init__(self, mem, addr):
        self.mem = mem
        self.addr = addr
        self.libraries = []
        self.names = []
        self.managed = {}
        self.parent = None
        self.objects_mutex = Mutex(mem, addr, OBJECTS_MUTEX,
                                   "objects_mutex_")
        self.library_mutex = Mutex(mem, addr, LIBRARY_MUTEX,
                                   "library_mutex_")
        self.disposed = False

    def _zero_fields(self):
        mem = self.mem
        for off, size in ((LIBRARIES, 24), (NAMES, 24)):
            mem.put(self.addr, off, 0)
            mem.put(self.addr, off + 8, 0)
            mem.put(self.addr, off + 16, 0)
            mem.ops.append(("zero-vector", self.addr, off, size))
        # Map header at +0x38: color 0, root 0, left = right = &header,
        # node count 0.
        mem.put(self.addr, MANAGED_MAP + 8, 0)
        mem.put(self.addr, MANAGED_MAP + 16, 0)
        mem.put(self.addr, MANAGED_MAP + 24, self.addr + MANAGED_MAP + 8)
        mem.put(self.addr, MANAGED_MAP + 32, self.addr + MANAGED_MAP + 8)
        mem.put(self.addr, MANAGED_MAP + 40, 0)
        mem.ops.append(("zero-map-header", self.addr, MANAGED_MAP + 8, 40))
        mem.put(self.addr, PARENT, None)
        mem.put(self.addr, PARENT + 8, None)
        mem.ops.append(("zero-shared-ptr", self.addr, PARENT, 16))

    def ctor(self):
        """The ctor 0x61f91b0: zero everything, seed libraries[0].

        The default library seed (via vec-insert 0x5ff7960) is modelled
        by the caller passing it in afterwards; this method only does
        the zeroing the excerpt shows.
        """
        self._zero_fields()
        self.objects_mutex.zero()
        self.library_mutex.zero()
        self.mem.ops.append(("ctor", self.addr))

    def clone(self, singleton):
        """The clone 0x61f9400: a fresh zeroed registry whose parent is
        the singleton shared_ptr returned by the getter."""
        self._zero_fields()
        self.objects_mutex.zero()
        self.library_mutex.zero()
        self.parent = singleton
        self.mem.put(self.addr, PARENT, singleton)
        self.mem.ops.append(("clone", self.addr, "parent=singleton"))

    def _locked_libraries_append(self, owner, name, library,
                                 record_name=True):
        """The shared shape of the three library-mutex lockers: lock,
        append the library, unlock. Raises unless the caller holds the
        library lock."""
        if (self.library_mutex.state != "locked"
                or self.library_mutex.holder != owner):
            raise MutexError(
                "libraries_ mutated without holding library_mutex_")
        self.libraries.append(library)
        if record_name:
            self.names.append(name)
        self.mem.ops.append(("libraries-append", self.addr, name))

    def add_library(self, owner, name, library):
        """AddLibrary 0x61f8dc0: lock +0x98, append name + library."""
        self.library_mutex.lock(owner)
        try:
            self._locked_libraries_append(owner, name, library)
        finally:
            self.library_mutex.unlock(owner)

    def ttl_register(self, owner, library):
        """TTL registration 0x62069f0: lock +0x98, append ONLY to the
        libraries vector (not the names vector)."""
        self.library_mutex.lock(owner)
        try:
            self._locked_libraries_append(owner, "TTL", library,
                                          record_name=False)
        finally:
            self.library_mutex.unlock(owner)

    def big_method_register(self, owner, name, library):
        """Big registry method 0x5ff88c0: lock +0x98, append library."""
        self.library_mutex.lock(owner)
        try:
            self._locked_libraries_append(owner, name, library)
        finally:
            self.library_mutex.unlock(owner)

    def set_managed_object(self, *args):
        """SetManagedObject: ABSENT from this binary."""
        raise MethodAbsent(
            "SetManagedObject is not linked into node #115")

    def get_managed_object(self, *args):
        """GetManagedObject: ABSENT from this binary."""
        raise MethodAbsent(
            "GetManagedObject is not linked into node #115")

    def list_managed_objects(self, *args):
        """ListManagedObjects: ABSENT from this binary."""
        raise MethodAbsent(
            "ListManagedObjects is not linked into node #115")

    def dispose(self):
        """Control-block _M_dispose 0x61f8760: destroy parent, map
        tree, names vector, libraries vector -- in that order -- and
        touch neither mutex."""
        if self.disposed:
            raise AssertionError("double dispose")
        self.disposed = True
        self.mem.ops.append(("dispose-parent", self.addr))
        self.parent = None
        self.managed = {}
        self.mem.ops.append(("dispose-map", self.addr))
        self.names = []
        self.mem.ops.append(("dispose-names", self.addr))
        self.libraries = []
        self.mem.ops.append(("dispose-libraries", self.addr))
        # Neither mutex is locked, unlocked, zeroed or destroyed here:
        # the dispose's ops log must contain no mutex op at all.


def lifecycle(mem):
    """A full registry lifecycle through the model, as the binary
    performs it: getter -> ctor -> AddLibrary -> TTL -> big method ->
    clone -> dispose. Returns (singleton, clone)."""
    singleton = Registry(mem, 0x1000000)
    singleton.ctor()
    singleton.libraries.append("default-library")
    singleton.add_library("AddLibrary", "encryption", "enc-library")
    singleton.ttl_register("TTL", "ttl-library")
    singleton.big_method_register("big-method", "Statistics",
                                  "stats-library")
    clone = Registry(mem, 0x10000C0)
    clone.clone(singleton)
    singleton.dispose()
    clone.dispose()
    return singleton, clone
