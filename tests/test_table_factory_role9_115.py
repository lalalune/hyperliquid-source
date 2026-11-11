"""Tests for tools/table_factory_role9_115.py (RE-001).

Run directly (pytest is not installed on this VM):
    python3 tests/test_table_factory_role9_115.py
Prints "all N checks passed" on success, else raises.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from table_factory_role9_115 import (  # noqa: E402
    FACTORY_SIZE, MANAGER_SIZE, IMPL_SIZE, CTRL_INPLACE_SIZE,
    CTRL_SIZE, NODE_SIZE, ROLE, MAP_AT_MESSAGE, REFCOUNT_INIT,
    REFCOUNT_INIT_QWORD, VTABLE_FACTORY, VTABLE_MANAGER,
    VTABLE_IMPL, VTABLE_CTRL_INPLACE_IMPL, VTABLE_CTRL_MANAGER,
    VTABLE_SLOTS, BlockBasedTableFactory, CacheReservationManagerImpl,
    ConcurrentCacheReservationManager, ControlBlock, OutOfRangeError,
    RoleMap, SharedPtr, WeakPtr, copy_factory, release,
)

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("check failed: %s" % label)


def make_cache():
    """A stand-in shared_ptr (ptr + control) for the factory +0x58."""
    control = ControlBlock(VTABLE_CTRL_MANAGER)
    return SharedPtr(object(), control)


def make_src(entries, cache=True):
    src = BlockBasedTableFactory()
    src.role_map = RoleMap(entries)
    src.cache_shared = make_cache() if cache else None
    return src


def main():
    # Layout constants from the excerpts.
    check(FACTORY_SIZE == 0x260, "factory is 0x260 bytes")
    check(MANAGER_SIZE == 0x50, "manager is 0x50 bytes")
    check(IMPL_SIZE == 0x68, "impl is 0x68 bytes")
    check(CTRL_INPLACE_SIZE == 0x78, "in-place control block is 0x78")
    check(CTRL_SIZE == 0x18, "separate control block is 0x18")
    check(NODE_SIZE == 0x28, "map node is 0x28 bytes")
    check(ROLE == 9, "looked-up role is 9")
    check(MAP_AT_MESSAGE == "map::at", "throw message is map::at")
    check(REFCOUNT_INIT == (1, 1), "control blocks start at {1,1}")
    check(REFCOUNT_INIT_QWORD == 0x100000001,
          "refcount pair is one qword 0x100000001")
    check(VTABLE_FACTORY == 0x64D39B8, "factory vtable")
    check(VTABLE_MANAGER == 0x64C9A50, "manager vtable")
    check(VTABLE_IMPL == 0x64CA1B0, "impl vtable")
    check(VTABLE_CTRL_INPLACE_IMPL == 0x64D3A80,
          "in-place control vtable")
    check(VTABLE_CTRL_MANAGER == 0x64C9C70, "manager control vtable")

    # Vtable installed entries from relocations.txt (slot offset
    # from the stored vptr -> RELATIVE addend; -8 is the
    # typeinfo-pointer slot).
    check(len(VTABLE_SLOTS[VTABLE_FACTORY]) == 24,
          "factory vtable has 24 recorded entries")
    check(VTABLE_SLOTS[VTABLE_FACTORY][0x00] == 0x60B2270,
          "factory slot +0x00")
    check(VTABLE_SLOTS[VTABLE_FACTORY][0xB0] == 0x60D6260,
          "factory slot +0xb0")
    check(VTABLE_SLOTS[VTABLE_FACTORY][-8] == 0x64D3830,
          "factory typeinfo pointer")
    check(len(VTABLE_SLOTS[VTABLE_CTRL_INPLACE_IMPL]) == 14,
          "in-place control vtable has 14 recorded entries")
    check(VTABLE_SLOTS[VTABLE_CTRL_INPLACE_IMPL][0x00] == 0x60D6500,
          "in-place control slot +0x00")
    check(VTABLE_SLOTS[VTABLE_CTRL_INPLACE_IMPL][0x30] == 0x64D3990,
          "in-place control slot +0x30 is a data-rel pointer")
    check(0x28 not in VTABLE_SLOTS[VTABLE_CTRL_INPLACE_IMPL],
          "in-place control slot +0x28 has no RELATIVE record")
    check(len(VTABLE_SLOTS[VTABLE_MANAGER]) == 14,
          "manager vtable has 14 recorded entries")
    check(VTABLE_SLOTS[VTABLE_MANAGER][0x00] == 0x5D8D560,
          "manager slot +0x00")
    check(0x38 not in VTABLE_SLOTS[VTABLE_MANAGER],
          "manager slot +0x38 has no RELATIVE record")
    check(len(VTABLE_SLOTS[VTABLE_CTRL_MANAGER]) == 14,
          "manager control vtable has 14 recorded entries")
    check(VTABLE_SLOTS[VTABLE_CTRL_MANAGER][0x00] == 0x5D896C0,
          "manager control slot +0x00")
    check(VTABLE_SLOTS[VTABLE_CTRL_MANAGER][0x78] == 0x64C9CD0,
          "manager control slot +0x78")
    check(0x70 not in VTABLE_SLOTS[VTABLE_CTRL_MANAGER],
          "manager control slot +0x70 has no RELATIVE record")
    check(len(VTABLE_SLOTS[VTABLE_IMPL]) == 10,
          "impl vtable has 10 recorded entries")
    check(VTABLE_SLOTS[VTABLE_IMPL][0x00] == 0x5DB9AE0, "impl slot +0x00")
    check(VTABLE_SLOTS[VTABLE_IMPL][0x48] == 0x5DBD4F0, "impl slot +0x48")
    check(0x38 not in VTABLE_SLOTS[VTABLE_IMPL],
          "impl slot +0x38 has no RELATIVE record")

    # map::at semantics: lower_bound(9) must land exactly on 9.
    check(RoleMap({}).lower_bound(9) is None, "empty map has no bound")
    check(RoleMap({9: 0}).at(9) == 0, "role 9 found with value 0")
    check(RoleMap({9: 1}).at(9) == 1, "role 9 found with value 1")
    check(RoleMap({8: 0, 9: 0, 10: 0}).at(9) == 0,
          "neighbours do not disturb the lookup")
    for entries in ({}, {8: 0}, {10: 0}, {8: 0, 10: 0}, {7: 0, 8: 0}):
        try:
            RoleMap(entries).at(9)
            check(False, "at(9) must throw for %r" % (entries,))
        except OutOfRangeError as exc:
            check(str(exc) == "map::at",
                  "at(9) throws out_of_range map::at for %r" % (entries,))

    # _M_copy: deep copy, same entries, independent nodes.
    src_map = RoleMap({9: 0, 3: 1})
    clone = src_map.clone()
    check(clone.entries == {9: 0, 3: 1}, "clone keeps the entries")
    check(clone is not src_map, "clone is a new map object")
    clone.entries[9] = 7
    check(src_map.entries[9] == 0, "mutating the clone spares the source")

    # Happy path: role 9 present and 0, cache shared_ptr set.
    src = make_src({9: 0, 3: 1})
    cache_use_before = src.cache_shared.control.use
    dst = copy_factory(src)
    check(dst is not src, "copy is a new factory object")
    check(dst.role_map.entries == {9: 0, 3: 1}, "map deep-copied")
    check(dst.role_map is not src.role_map, "map object is independent")
    check(dst.holder is not None, "holder built on the happy path")
    manager = dst.holder.ptr
    check(isinstance(manager, ConcurrentCacheReservationManager),
          "holder points at a ConcurrentCacheReservationManager")
    check(manager.vtable == VTABLE_MANAGER, "manager vtable")
    check(manager.size == MANAGER_SIZE, "manager size")
    check(dst.holder.control.vtable == VTABLE_CTRL_MANAGER,
          "holder control is _Sp_counted_ptr<manager*>")
    check(dst.holder.control.use == 1, "manager control use stays 1")
    check(dst.holder.control.weak == 2,
          "manager control weak is 2 (self weak_ptr)")
    check(manager.weak_this is not None, "manager has a self weak_ptr")
    check(manager.weak_this.ptr is manager,
          "manager weak_ptr points at itself")
    check(manager.weak_this.control is dst.holder.control,
          "manager weak_ptr uses the holder control block")
    impl = manager.impl_shared.ptr
    check(isinstance(impl, CacheReservationManagerImpl),
          "manager holds a CacheReservationManagerImpl")
    check(impl.vtable == VTABLE_IMPL, "impl vtable")
    check(impl.size == IMPL_SIZE, "impl size")
    check(impl.flag == 0, "impl flag byte is 0")
    check(manager.impl_shared.control.vtable == VTABLE_CTRL_INPLACE_IMPL,
          "impl control is _Sp_counted_ptr_inplace<impl>")
    check(manager.impl_shared.control.use == 1,
          "impl control use stays 1")
    check(manager.impl_shared.control.weak == 2,
          "impl control weak is 2 (self weak_ptr)")
    check(impl.weak_this is not None, "impl has a self weak_ptr")
    check(impl.weak_this.ptr is impl, "impl weak_ptr points at itself")
    check(impl.weak_this.control is manager.impl_shared.control,
          "impl weak_ptr uses the in-place control block")
    check(impl.cache_shared is not None, "impl holds the cache shared_ptr")
    check(impl.cache_shared.ptr is src.cache_shared.ptr,
          "impl cache ptr is the factory's +0x58 ptr")
    check(impl.cache_shared.control is src.cache_shared.control,
          "impl cache control is the factory's +0x58 control")
    check(src.cache_shared.control.use == cache_use_before + 1,
          "impl copy adds one use reference on the cache control")
    check(isinstance(dst.holder.ptr, ConcurrentCacheReservationManager),
          "holder type re-checked")

    # Role 9 present but already built: no holder.
    dst2 = copy_factory(make_src({9: 1}))
    check(dst2.holder is None, "value 1 skips the build")
    dst3 = copy_factory(make_src({9: 42}))
    check(dst3.holder is None, "value 42 skips the build")

    # No cache shared_ptr: no holder, but the lookup still runs.
    dst4 = copy_factory(make_src({9: 0}, cache=False))
    check(dst4.holder is None, "null +0x58 skips the build")
    try:
        copy_factory(make_src({}, cache=False))
        check(False, "missing role 9 must throw even with null +0x58")
    except OutOfRangeError as exc:
        check(str(exc) == "map::at",
              "lookup precedes the +0x58 null check")

    # Missing role 9 throws (empty map, lower key only, higher only).
    for entries in ({}, {8: 0}, {10: 0}):
        try:
            copy_factory(make_src(entries))
            check(False, "copy must throw for %r" % (entries,))
        except OutOfRangeError as exc:
            check(str(exc) == "map::at",
                  "copy throws map::at for %r" % (entries,))

    # Release helper 0x5d350c0 + destroy dispatch 0x5d35070.
    ctrl = ControlBlock(VTABLE_CTRL_MANAGER)
    check((ctrl.use, ctrl.weak) == (1, 1), "fresh control is {1,1}")
    check(release(ctrl) == "destroyed", "{1,1} release destroys at once")
    check(ctrl.destroyed and ctrl.deleted, "{1,1} dispose+delete ran")
    check((ctrl.use, ctrl.weak) == (0, 0), "{1,1} counts go to 0")
    ctrl = ControlBlock(VTABLE_CTRL_MANAGER)
    ctrl.addref_use()
    check(release(ctrl) == "released", "{2,1} release just decrements")
    check((ctrl.use, ctrl.weak) == (1, 1), "{2,1} release leaves {1,1}")
    check(not ctrl.destroyed and not ctrl.deleted,
          "{2,1} release destroys nothing")
    ctrl = ControlBlock(VTABLE_CTRL_MANAGER)
    ctrl.addref_weak()
    check(release(ctrl) == "disposed", "{1,2} release disposes only")
    check(ctrl.destroyed and not ctrl.deleted,
          "{1,2} dispose ran, delete did not")
    check((ctrl.use, ctrl.weak) == (0, 1), "{1,2} counts become {0,1}")
    ctrl = ControlBlock(VTABLE_CTRL_MANAGER)
    ctrl.addref_use()
    ctrl.addref_weak()
    check(release(ctrl) == "released", "{2,2} release just decrements")
    check((ctrl.use, ctrl.weak) == (1, 2), "{2,2} release leaves {1,2}")

    # SharedPtr copy/release accounting.
    ctrl = ControlBlock(VTABLE_CTRL_MANAGER)
    sp = SharedPtr(object(), ctrl)
    copy = sp.copy()
    check(ctrl.use == 2, "copy addrefs the control")
    check(copy.ptr is sp.ptr, "copy keeps the pointer")
    copy.release()
    check(ctrl.use == 1, "release drops the extra reference")
    check(not ctrl.destroyed, "release to 1 destroys nothing")

    # WeakPtr creation addrefs the weak count only.
    ctrl = ControlBlock(VTABLE_CTRL_MANAGER)
    wp = WeakPtr(object(), ctrl)
    check((ctrl.use, ctrl.weak) == (1, 2),
          "weak_ptr creation bumps weak only")
    check(wp.ptr is not None, "weak_ptr keeps the pointer")

    print("all %d checks passed" % CHECKS[0])


if __name__ == "__main__":
    sys.exit(main())
