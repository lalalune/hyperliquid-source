"""Model of node #115's BlockBasedTableFactory copy tail (RE-001).

Pins the behaviour of the 0x60db710 copy routine after the
deterministic prefix (pinned in PR #3254) and the record-vector
registration (pinned in PR #3257): how the role map at
factory+0xa8 is populated from the source, which role the tail
looks up, and what shared holder it builds at factory+0x118 /
+0x120 when the looked-up entry is still 0.

Established in
research/work-items/RE-001-table-factory-role9-115/.

The factory object is 0x260 bytes (vtable
rocksdb::BlockBasedTableFactory at 0x64d39b8). Its role map is
a std::map<int, int>: 0x28-byte nodes (color +0x00, parent
+0x08, left +0x10, right +0x18, key int +0x20, value int
+0x24), header at +0xa8 (color +0xa8, root +0xb0, leftmost
+0xb8, rightmost +0xc0, count +0xc8). The copy populates the
destination map by a deep structural copy of the source tree
(0x60d7fb0, libstdc++ _Rb_tree::_M_copy: same entries, same
colors, same shape, independent nodes), then runs
map::at(9): lower_bound(9) must land on a node whose key is
exactly 9, else std::out_of_range("map::at") is thrown (the
literal is pinned at 0x4408a7; an empty map throws too, since
the root is null).

When the role-9 entry exists, the build is gated twice: the
factory's shared_ptr at +0x58 must be non-null, and the
role-9 value must be 0 (the mapped int is used as a presence
flag: 0 means no manager built for this role yet). When both
hold, the copy builds a fresh shared holder:

* A 0x78-byte _Sp_counted_ptr_inplace control block O78
  (vtable 0x64d3a80, typeinfo
  std::_Sp_counted_ptr_inplace<rocksdb::
  CacheReservationManagerImpl<rocksdb::CacheEntryRole::9>,
  ...>) holding the 0x68-byte CacheReservationManagerImpl
  object in place at +0x10 (vtable 0x64ca1b0). The impl is
  built by 0x5db8800 from a copy of the factory's +0x58
  shared_ptr (stored at impl+0x18, its control addref'd),
  flag byte 0 at impl+0x28, the rest zeroed. The impl
  derives from enable_shared_from_this: its weak_ptr at
  impl+0x08/+0x10 is set to {&impl, O78}, which raises
  O78's weak count from 1 to 2 (use stays 1).
* A 0x50-byte rocksdb::ConcurrentCacheReservationManager
  object O50 (vtable 0x64c9a50), zeroed except for the
  shared_ptr to the impl at +0x40 (ptr &impl) / +0x48
  (control O78). The manager is also
  enable_shared_from_this: its weak_ptr at +0x08/+0x10 is
  set to {&O50, O18}.
* A 0x18-byte _Sp_counted_ptr control block O18 (vtable
  0x64c9c70, typeinfo std::_Sp_counted_ptr<rocksdb::
  ConcurrentCacheReservationManager*, ...>) with refcounts
  {use=1, weak=2} and _M_ptr O50 at +0x10. The factory's
  +0x118/+0x120 shared_ptr is installed as {O50, O18};
  a previous holder, if any, is released first.

Both control blocks start with the refcount pair {use=1,
weak=1} loaded as one 8-byte constant (0x100000001) from
.rodata at 0x459b20. The release helper 0x5d350c0 models
shared release: when the pair is exactly {1,1} it destroys
immediately (vtable slot 2 then slot 3, counts to 0);
otherwise it decrements the use count and, when the old
use count was 1, runs the destroy dispatch 0x5d35070
(vtable slot 2, then decrements the weak count and calls
vtable slot 3 when the old weak count was 1).

The pointee type of the factory's +0x58 shared_ptr is not
pinned by this packet (it is copied structurally); neither
is which code inserts role entries into a source factory's
map. Both are recorded as unknowns in the packet README.
"""

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

FACTORY_SIZE = 0x260
MANAGER_SIZE = 0x50
IMPL_SIZE = 0x68
CTRL_INPLACE_SIZE = 0x78
CTRL_SIZE = 0x18
NODE_SIZE = 0x28

VTABLE_FACTORY = 0x64D39B8
VTABLE_MANAGER = 0x64C9A50
VTABLE_IMPL = 0x64CA1B0
VTABLE_CTRL_INPLACE_IMPL = 0x64D3A80
VTABLE_CTRL_MANAGER = 0x64C9C70

ROLE = 9
MAP_AT_MESSAGE = "map::at"
REFCOUNT_INIT = (1, 1)  # {use=1, weak=1} as one qword 0x100000001
REFCOUNT_INIT_QWORD = 0x100000001

# Installed entries of the five vtable groups, from the RELATIVE
# records in relocations.txt: {slot offset from the stored vptr
# (in bytes; -8 is the typeinfo-pointer slot): installed addend}.
# An entry whose addend is a .data.rel.ro / .rodata address (not
# a .text function) is recorded as-is: the file does not say
# whether that slot is a function, a secondary-vtable header or
# a data pointer, so no claim is made here. Offsets with no
# RELATIVE record are absent (their file value is not recovered).
VTABLE_SLOTS = {
    VTABLE_FACTORY: {
        -8: 0x64D3830,
        0x00: 0x60B2270, 0x08: 0x60B25E0, 0x10: 0x609D760,
        0x18: 0x609DC40, 0x20: 0x60DA1F0, 0x28: 0x60DB570,
        0x30: 0x60D8B10, 0x38: 0x60D74E0, 0x40: 0x60956F0,
        0x48: 0x609D0E0, 0x50: 0x60D7D20, 0x58: 0x6095710,
        0x60: 0x609DE80, 0x68: 0x609D980, 0x70: 0x60B1D90,
        0x78: 0x5D32A30, 0x80: 0x5D2E770, 0x88: 0x5D2CA00,
        0x90: 0x5D2CA10, 0x98: 0x5D44FF0, 0xA0: 0x60DAE50,
        0xA8: 0x60D6580, 0xB0: 0x60D6260,
    },
    VTABLE_CTRL_INPLACE_IMPL: {
        -8: 0x64D3978,
        0x00: 0x60D6500, 0x08: 0x60D6550, 0x10: 0x60D6510,
        0x18: 0x60D7350, 0x20: 0x60D70C0, 0x30: 0x64D3990,
        0x38: 0x60D64C0, 0x40: 0x60D6530, 0x48: 0x60D64D0,
        0x50: 0x60D6540, 0x58: 0x60D64F0, 0x68: 0x979D80,
        0x70: 0x64C8238,
    },
    VTABLE_MANAGER: {
        -8: 0x64C98D8,
        0x00: 0x5D8D560, 0x08: 0x5D8D660, 0x10: 0x5D8AEE0,
        0x18: 0x5D8A980, 0x20: 0x5D8D970, 0x28: 0x5D8A050,
        0x30: 0x5D8A600, 0x40: 0x64C9930, 0x48: 0x5D8D4F0,
        0x50: 0x5D8D520, 0x58: 0x5D897D0, 0x60: 0x5D895A0,
        0x70: 0x64C9948,
    },
    VTABLE_CTRL_MANAGER: {
        -8: 0x64C99F0,
        0x00: 0x5D896C0, 0x08: 0x5D89790, 0x10: 0x5D8D6E0,
        0x18: 0x5D897A0, 0x20: 0x5D89700, 0x30: 0x64C9A08,
        0x38: 0x5D896B0, 0x40: 0x5D89770, 0x48: 0x5D896D0,
        0x50: 0x5D89780, 0x58: 0x5D896F0, 0x68: 0x96DB60,
        0x78: 0x64C9CD0,
    },
    VTABLE_IMPL: {
        -8: 0x64C9FC0,
        0x00: 0x5DB9AE0, 0x08: 0x5DB9CC0, 0x10: 0x5DBD440,
        0x18: 0x5DB8680, 0x20: 0x5DBA9A0, 0x28: 0x5DB87A0,
        0x30: 0x5DB86A0, 0x40: 0x64C9FF8, 0x48: 0x5DBD4F0,
    },
}


class OutOfRangeError(Exception):
    """Models std::out_of_range thrown by std::map::at."""


class ControlBlock:
    """One refcount pair {use, weak} with a vtable.

    Models the _Sp_counted_base header (vtable +0x00, use
    count +0x08, weak count +0x0c) shared by the in-place
    control block O78 and the separate control block O18.
    """

    def __init__(self, vtable):
        self.vtable = vtable
        self.use, self.weak = REFCOUNT_INIT
        self.destroyed = False  # vtable slot 2 (dispose) ran
        self.deleted = False  # vtable slot 3 (delete) ran

    def addref_use(self):
        self.use += 1

    def addref_weak(self):
        self.weak += 1

    def _dispose(self):
        self.destroyed = True

    def _delete(self):
        self.deleted = True


def release(control):
    """Model of the shared-release helper 0x5d350c0.

    When the pair is exactly {1,1} the object is destroyed
    at once (dispose, then delete; both counts go to 0).
    Otherwise the use count is decremented; when the old use
    count was 1 the destroy dispatch 0x5d35070 runs: dispose,
    then the weak count is decremented and delete runs when
    the old weak count was 1.
    """
    if (control.use, control.weak) == (1, 1):
        control.use, control.weak = 0, 0
        control._dispose()
        control._delete()
        return "destroyed"
    old_use = control.use
    control.use -= 1
    if old_use == 1:
        control._dispose()
        old_weak = control.weak
        control.weak -= 1
        if old_weak == 1:
            control._delete()
            return "destroyed"
        return "disposed"
    return "released"


class SharedPtr:
    """A {ptr, control} pair; copying addrefs the control."""

    def __init__(self, ptr, control):
        self.ptr = ptr
        self.control = control

    def copy(self):
        self.control.addref_use()
        return SharedPtr(self.ptr, self.control)

    def release(self):
        if self.control is not None:
            release(self.control)

    def is_null(self):
        return self.ptr is None


class WeakPtr:
    """A {ptr, control} weak reference; creating one addrefs weak."""

    def __init__(self, ptr, control):
        self.ptr = ptr
        self.control = control
        if control is not None:
            control.addref_weak()


class RoleMap:
    """A std::map<int, int> (0x28-byte nodes, key +0x20,
    value +0x24), modelled as a sorted dict."""

    def __init__(self, entries=None):
        self.entries = dict(entries or {})

    def clone(self):
        """Deep copy (_M_copy): same entries, independent nodes."""
        return RoleMap(self.entries)

    def lower_bound(self, key):
        """First key >= key, or None (the header sentinel)."""
        for cand in sorted(self.entries):
            if cand >= key:
                return cand
        return None

    def at(self, key):
        """std::map::at: lower_bound must land exactly on key."""
        cand = self.lower_bound(key)
        if cand is None or cand != key:
            raise OutOfRangeError(MAP_AT_MESSAGE)
        return self.entries[cand]


class CacheReservationManagerImpl:
    """The 0x68-byte impl object built by 0x5db8800.

    vtable 0x64ca1b0 at +0x00; weak_ptr to itself at +0x08;
    a copy of the factory's +0x58 shared_ptr at +0x18; flag
    byte 0 at +0x28; the rest zeroed.
    """

    def __init__(self, cache_shared):
        self.vtable = VTABLE_IMPL
        self.size = IMPL_SIZE
        self.weak_this = None  # set by the holder build
        self.cache_shared = cache_shared  # SharedPtr copy (addref'd)
        self.flag = 0


class ConcurrentCacheReservationManager:
    """The 0x50-byte manager object O50.

    vtable 0x64c9a50 at +0x00; weak_ptr to itself at +0x08;
    zeros +0x18..+0x40; shared_ptr to the impl at +0x40.
    """

    def __init__(self):
        self.vtable = VTABLE_MANAGER
        self.size = MANAGER_SIZE
        self.weak_this = None  # set by the holder build
        self.impl_shared = None  # SharedPtr to the impl


class BlockBasedTableFactory:
    """The 0x260-byte factory object copied by 0x60db710.

    vtable 0x64d39b8 at +0x00; shared_ptr at +0x58 (copied
    from the source); role map at +0xa8; shared_ptr holder
    at +0x118 (ptr) / +0x120 (control).
    """

    def __init__(self):
        self.vtable = VTABLE_FACTORY
        self.size = FACTORY_SIZE
        self.cache_shared = None  # SharedPtr or None
        self.role_map = RoleMap()
        self.holder = None  # SharedPtr or None


def _build_holder(factory):
    """Build the role-9 holder and install it at +0x118/+0x120.

    Mirrors the 0x60dbac0 path in table_init.txt: the impl
    control block O78 (in-place, vtable 0x64d3a80), the
    manager O50, and the manager control block O18 (vtable
    0x64c9c70). Each control block starts at {use=1, weak=1};
    each object's weak_ptr to itself raises its control
    block's weak count to 2. The impl holds a copy of the
    factory's +0x58 shared_ptr (one extra use reference on
    its control); the manager holds the impl shared_ptr
    (taking over O78's initial use reference); the factory
    holder takes over O18's initial use reference.
    """
    ctrl_impl = ControlBlock(VTABLE_CTRL_INPLACE_IMPL)
    impl = CacheReservationManagerImpl(factory.cache_shared.copy())
    impl.weak_this = WeakPtr(impl, ctrl_impl)
    manager = ConcurrentCacheReservationManager()
    manager.impl_shared = SharedPtr(impl, ctrl_impl)
    manager.weak_this = WeakPtr(manager, ControlBlock(VTABLE_CTRL_MANAGER))
    ctrl_manager = manager.weak_this.control
    old = factory.holder
    factory.holder = SharedPtr(manager, ctrl_manager)
    if old is not None:
        old.release()
    return factory.holder


def copy_factory(src):
    """Model of the 0x60db710 copy tail (table_init.txt).

    Deep-copies the source role map, runs map::at(9), and
    builds the role-9 holder when the factory's +0x58
    shared_ptr is non-null and the role-9 value is 0. The
    prefix field copies and the record registration are
    modelled in PRs #3254 and #3257 respectively.
    """
    dst = BlockBasedTableFactory()
    dst.cache_shared = src.cache_shared
    dst.role_map = src.role_map.clone()
    value = dst.role_map.at(ROLE)
    if dst.cache_shared is None or dst.cache_shared.is_null():
        return dst
    if value != 0:
        return dst
    _build_holder(dst)
    return dst
