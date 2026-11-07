"""Python model of the node #115 ObjectRegistry lifecycle (RE-001).

Models the behaviour pinned by research/work-items/RE-001-objectregistry-lifecycle-115:
the ObjectRegistry control block (vtable 0x64d8f00), the 0xc0-byte
registry layout, the constructor that seeds the libraries vector
with the default library and then replays the global registrar
map, AddLibrary, the function-local-static singleton getter, the
clone that links its parent to the singleton, the TTL library
registration, and the teardown order of _M_dispose.

The model mirrors the binary's observable semantics only. The
0x70..0x98 region of the registry is 40 bytes the binary
zero-initialises and never reads or writes in any pinned
routine; the model keeps it as opaque zeroed bytes and records
that as an open unknown. The map insert is a plain binary-tree
insert: the binary uses std::_Rb_tree (with balancing), but the
destroy order the model exercises depends only on the node
links, not on the balance. The TTL creator at 0x6208290 is a
large unpinned function; the model takes it as an opaque
callable, exactly as the binary invokes it through the
std::function invoker.
"""

ARTIFACT_DIGEST = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
CONTROL_BLOCK_VTABLE = 0x64D8F00
CONTROL_BLOCK_TYPEINFO = (
    "St23_Sp_counted_ptr_inplace"
    "IN7rocksdb14ObjectRegistryESaIvE"
    "LN9__gnu_cxx12_Lock_policyE2EE"
)
MAKE_SHARED_TAG = "St19_Sp_make_shared_tag"
PATTERN_ENTRY_TYPEINFO = "N7rocksdb13ObjectLibrary12PatternEntryE"
LIBRARY_CB_VTABLE = 0x64D00F0
FRESH_COUNTS = 0x100000001
BLOCK_SIZE = 0xD0
OBJECT_SIZE = 0xC0
LIBRARY_BLOCK_SIZE = 0x90
NODE_SIZE = 0x50

# Registry layout (offsets inside the 0xc0-byte object).
LIBRARIES_OFFSET = 0x00
NAMES_OFFSET = 0x18
MAP_OFFSET = 0x30
PARENT_OFFSET = 0x60
UNKNOWN_OFFSET = 0x70
UNKNOWN_SIZE = 0x28
MUTEX_OFFSET = 0x98

# Globals.
PACKED_COUNTS = 0x459B20
SELECTOR = 0x64ED290
REGISTRY_GUARD = 0x65090F8
REGISTRY_HOLDER = 0x6509100
LIBRARY_GUARD = 0x6509108
LIBRARY_HOLDER = 0x6509110
REGISTRAR_MAP = 0x6509540
TTL_CREATOR = 0x6208290
BUILD_GIT_SHA = "6a436150417120a3f9732d65a2a5c2b8d19b60fc"
BUILD_GIT_TAG = "rocksdb_build_git_tag:v8.1.1"
BUILD_DATE = "rocksdb_build_date:2023-04-06 16:38:52"

# The selector byte at 0x64ed290: 0 selects `lock xadd`, nonzero
# selects a plain `addl`. Both paths produce the same counts.
selector = 0


class ControlBlock:
    """The 0x10-byte header of a make-shared block."""

    def __init__(self, vtable, use=1, weak=1):
        self.vtable = vtable
        self.use = use
        self.weak = weak
        self.disposed = False
        self.destroyed = False
        self.events = []

    def _update(self, delta):
        # The binary gates every count update on the selector byte.
        self.events.append("lock xadd" if selector == 0 else "plain addl")
        self.use += delta

    def release_use(self, owner):
        """_M_release on the use count. Returns True when this
        release is the last use, so _M_dispose + _M_destroy run."""
        if self.use == 1 and self.weak == 1:
            # Fast path (1, 1): dispose + destroy inline.
            self._dispose(owner)
            self._destroy()
            return True
        self._update(-1)
        if self.use == 0:
            self._dispose(owner)
            self.release_weak()
            return True
        return False

    def release_weak(self):
        self.weak -= 1
        if self.weak == 0:
            self._destroy()

    def _dispose(self, owner):
        self.disposed = True
        # Only an ObjectRegistry owner has a dispose the model
        # pins here; an ObjectLibrary owner's teardown is the
        # library packet's behaviour (RE-001 #3983), not this
        # packet's, so it is not invoked from this model.
        if owner is not None and hasattr(owner, "dispose"):
            owner.dispose()

    def _destroy(self):
        self.destroyed = True

    def get_deleter(self, typeinfo_name):
        """_M_get_deleter: the _Sp_make_shared_tag typeinfo
        returns the object; `*`-prefixed names return None;
        otherwise the name must equal this block's typeinfo."""
        if typeinfo_name == MAKE_SHARED_TAG:
            return self
        if typeinfo_name.startswith("*"):
            return None
        return self if typeinfo_name == CONTROL_BLOCK_TYPEINFO else None


class SharedPtr:
    """A 16-byte shared_ptr {object, control block}."""

    def __init__(self, obj, cb):
        self.obj = obj
        self.cb = cb

    def copy(self):
        if self.cb is not None:
            self.cb._update(1)
        return SharedPtr(self.obj, self.cb)

    def release(self):
        if self.cb is None:
            return False
        done = self.cb.release_use(self.obj)
        self.cb = None
        self.obj = None
        return done


class WeakPtr:
    """A 16-byte weak_ptr {object, control block}."""

    def __init__(self, obj, cb):
        self.obj = obj
        self.cb = cb

    def release(self):
        if self.cb is None:
            return
        self.cb.release_weak()
        self.cb = None
        self.obj = None


class MapNode:
    """A 0x50-byte map node: color, parent, left, right, the
    0x20-byte string key, and the weak_ptr value."""

    def __init__(self, key, weak):
        self.color = 0
        self.parent = None
        self.left = None
        self.right = None
        self.key = key
        self.weak = weak

    def destroy(self, events):
        """The rec-destroy routine 0x61f81d0: recurse the right
        child, release the weak_ptr, destroy the string key,
        delete the node, then move to the left sibling."""
        if self.right is not None:
            self.right.destroy(events)
        if self.weak is not None:
            self.weak.release()
            events.append("release weak %s" % self.key)
        events.append("destroy key %s" % self.key)
        events.append("delete node %s" % self.key)
        if self.left is not None:
            self.left.destroy(events)


class RegistryMap:
    """The std::map at registry +0x30: key-compare, the RB
    header (color 0, parent = root, left/right = header when
    empty), and the node count."""

    def __init__(self):
        self.color = 0
        self.root = None
        self.leftmost = self
        self.rightmost = self
        self.count = 0
        self.nodes = {}

    def insert(self, key, weak):
        node = MapNode(key, weak)
        self.nodes[key] = node
        if self.root is None:
            self.root = node
            self.count = 1
            return node
        cur = self.root
        while True:
            if key < cur.key:
                if cur.left is None:
                    cur.left = node
                    node.parent = cur
                    break
                cur = cur.left
            else:
                if cur.right is None:
                    cur.right = node
                    node.parent = cur
                    break
                cur = cur.right
        self.count += 1
        return node

    def destroy(self, events):
        """The dispose-time tree teardown: the loop at
        0x61f87a0 walks the root the same way rec-destroy does."""
        if self.root is not None:
            self.root.destroy(events)
        self.root = None
        self.count = 0
        self.nodes = {}


class SharedPtrVector:
    """A vector<shared_ptr> with the binary's growth rule:
    _M_realloc_insert doubles the capacity (minimum one
    element) and bumps the copied control block's use count."""

    def __init__(self):
        self.items = []
        self.capacity = 0
        self.events = []

    def append(self, shared):
        if len(self.items) == self.capacity:
            new_capacity = max(1, self.capacity * 2)
            self.capacity = new_capacity
            self.events.append("grow to %d" % new_capacity)
        # _M_realloc_insert copies the 16-byte element from *rdx
        # and bumps the copied control block's use count, on
        # both the grow and the in-place paths.
        if shared.cb is not None:
            shared.cb._update(1)
        self.items.append(SharedPtr(shared.obj, shared.cb))

    def destroy(self, events):
        """The vec-sharedptr-destroy routine 0x61f89e0:
        release every element's control block, then free the
        buffer."""
        for shared in self.items:
            shared.release()
            events.append("release library")
        self.items = []
        self.capacity = 0
        events.append("free buffer")


class ObjectLibrary:
    """A make-shared ObjectLibrary (0x90-byte block, control
    block vtable 0x64d00f0). Only the name matters here."""

    def __init__(self, name):
        self.name = name
        self.cb = ControlBlock(LIBRARY_CB_VTABLE)


class ObjectRegistry:
    """The 0xc0-byte ObjectRegistry object."""

    def __init__(self):
        self.libraries = SharedPtrVector()
        self.names = []
        self.map = RegistryMap()
        self.parent = None
        self.unknown = bytearray(UNKNOWN_SIZE)
        self.mutex_locked = False
        self.events = []

    def lock(self):
        # pthread_mutex_lock on this+0x98; the binary throws
        # __throw_system_error on failure.
        self.mutex_locked = True

    def unlock(self):
        self.mutex_locked = False

    def add_library(self, name, creator):
        """AddLibrary 0x61f8dc0. Returns -1 when the name is
        empty or the creator's manager is null; otherwise 0.
        The creator is invoked with (new library, name) after
        the library is appended and the mutex released."""
        if not name or creator is None:
            return -1
        self.names.append(name)
        library = ObjectLibrary(name)
        temp = SharedPtr(library, library.cb)
        self.lock()
        self.libraries.append(temp)
        self.unlock()
        creator(library, name)
        temp.release()
        return 0

    def dispose(self):
        """Control-block _M_dispose 0x61f8760: release the
        parent shared_ptr, destroy the map tree, destroy the
        names vector, destroy the libraries vector."""
        if self.parent is not None:
            self.parent.release()
            self.events.append("release parent")
            self.parent = None
        self.map.destroy(self.events)
        for name in self.names:
            self.events.append("destroy name %s" % name)
        self.names = []
        self.libraries.destroy(self.events)

    def clone(self):
        """Clone 0x61f9400: a new registry whose parent
        shared_ptr is the singleton, otherwise zeroed."""
        child = ObjectRegistry()
        child.parent = singleton_shared()
        return child


# The function-local-static singleton (guard 0x65090f8, holder
# 0x6509100) and the default library it is seeded with.
_singleton = None
_singleton_cb = None
_default_library = None


def default_library():
    """ObjectLibrary::Default 0x61f8b60: returns the holder
    address 0x6509110 (the singleton shared_ptr), building
    the library named "default" on the first call."""
    global _default_library
    if _default_library is None:
        _default_library = ObjectLibrary("default")
    return _default_library


def construct(default_lib, registrar_nodes):
    """The registry constructor 0x61f91b0: zero the fields,
    seed libraries[0] with the default library via
    _M_realloc_insert, then replay the global registrar map,
    calling AddLibrary once per node in map order."""
    registry = ObjectRegistry()
    registry.libraries.append(SharedPtr(default_lib, default_lib.cb))
    for name, creator in registrar_nodes:
        registry.add_library(name, creator)
    return registry


def singleton():
    """The registry getter 0x61f92b0."""
    global _singleton, _singleton_cb
    if _singleton is None:
        _singleton_cb = ControlBlock(CONTROL_BLOCK_VTABLE)
        _singleton = construct(default_library(), REGISTRAR_NODES)
    return _singleton


def singleton_shared():
    """The getter's by-value return: a shared_ptr copy of the
    singleton (one use-count bump), as stored into a clone's
    +0x60 parent slot."""
    registry = singleton()
    _singleton_cb._update(1)
    return SharedPtr(registry, _singleton_cb)


# The global registrar map at 0x6509540, replayed by the
# constructor. The binary's map is empty at static-init time;
# the names below are the registration calls the constructor
# replays in map order (the packet records the map itself, not
# a fabricated entry list).
REGISTRAR_NODES = []


def registrar_init():
    """Static initializer 0x620b470: initialise the registrar
    unordered_map (buckets = self+0x30, bucket_count 1,
    before_begin 0, element_count 0, max_load_factor 1.0,
    next_resize 0) and the three build-info globals."""
    return {
        "buckets": "self+0x30",
        "bucket_count": 1,
        "before_begin": 0,
        "element_count": 0,
        "max_load_factor": 1.0,
        "next_resize": 0,
        "git_sha": BUILD_GIT_SHA,
        "git_tag": BUILD_GIT_TAG,
        "build_date": BUILD_DATE,
    }


def register_ttl(creator):
    """TTL registration 0x62069f0: register a hardcoded "TTL"
    library into the singleton. Unlike AddLibrary it appends
    only to the libraries vector (not the names vector) and
    invokes the creator with (new library, empty string)."""
    registry = singleton()
    library = ObjectLibrary("TTL")
    temp = SharedPtr(library, library.cb)
    registry.lock()
    registry.libraries.append(temp)
    registry.unlock()
    creator(library, "")
    temp.release()
    return library
