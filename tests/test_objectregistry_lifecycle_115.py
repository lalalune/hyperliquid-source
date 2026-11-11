"""Tests for the node #115 ObjectRegistry lifecycle model.

Every expectation is grounded in the verbatim excerpts in
research/work-items/RE-001-objectregistry-lifecycle-115: the
control-block vtable, the 0xc0-byte registry layout, the
dispose order, the add-library contract, the constructor's
registrar replay, the singleton getter, the clone's parent
link, the TTL registration, and the vector growth rule.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import objectregistry_lifecycle_115 as m


def fresh_registry():
    return m.ObjectRegistry()


def test_layout_constants():
    assert m.OBJECT_SIZE == 0xC0
    assert m.BLOCK_SIZE == 0xD0
    assert m.LIBRARIES_OFFSET == 0x00
    assert m.NAMES_OFFSET == 0x18
    assert m.MAP_OFFSET == 0x30
    assert m.PARENT_OFFSET == 0x60
    assert m.UNKNOWN_OFFSET == 0x70
    assert m.UNKNOWN_SIZE == 0x28
    assert m.MUTEX_OFFSET == 0x98
    assert m.NODE_SIZE == 0x50


def test_control_block_constants():
    assert m.CONTROL_BLOCK_VTABLE == 0x64D8F00
    assert m.FRESH_COUNTS == 0x100000001
    assert m.LIBRARY_CB_VTABLE == 0x64D00F0
    assert m.LIBRARY_BLOCK_SIZE == 0x90
    assert m.CONTROL_BLOCK_TYPEINFO == (
        "St23_Sp_counted_ptr_inplace"
        "IN7rocksdb14ObjectRegistryESaIvE"
        "LN9__gnu_cxx12_Lock_policyE2EE")
    assert m.PATTERN_ENTRY_TYPEINFO == (
        "N7rocksdb13ObjectLibrary12PatternEntryE")
    assert m.MAKE_SHARED_TAG == "St19_Sp_make_shared_tag"


def test_get_deleter_tag_returns_object():
    cb = m.ControlBlock(m.CONTROL_BLOCK_VTABLE)
    assert cb.get_deleter(m.MAKE_SHARED_TAG) is cb


def test_get_deleter_star_names_return_none():
    cb = m.ControlBlock(m.CONTROL_BLOCK_VTABLE)
    assert cb.get_deleter("*something") is None
    assert cb.get_deleter("*") is None


def test_get_deleter_matching_typeinfo_returns_object():
    cb = m.ControlBlock(m.CONTROL_BLOCK_VTABLE)
    assert cb.get_deleter(m.CONTROL_BLOCK_TYPEINFO) is cb


def test_get_deleter_other_typeinfo_returns_none():
    cb = m.ControlBlock(m.CONTROL_BLOCK_VTABLE)
    assert cb.get_deleter("St23_Sp_counted_ptr_inplaceIN7rocksdb13ObjectLibraryE") is None


def test_release_fast_path_disposes_and_destroys():
    owner = fresh_registry()
    cb = m.ControlBlock(m.CONTROL_BLOCK_VTABLE)
    shared = m.SharedPtr(owner, cb)
    assert shared.release() is True
    assert cb.disposed and cb.destroyed


def test_release_non_last_use_only_decrements():
    cb = m.ControlBlock(m.CONTROL_BLOCK_VTABLE, use=2, weak=1)
    shared = m.SharedPtr(object(), cb)
    assert shared.release() is False
    assert cb.use == 1
    assert not cb.disposed and not cb.destroyed


def test_selector_switches_count_mechanism():
    cb = m.ControlBlock(m.CONTROL_BLOCK_VTABLE, use=2, weak=1)
    m.selector = 0
    cb._update(-1)
    assert cb.events[-1] == "lock xadd"
    m.selector = 1
    cb._update(1)
    assert cb.events[-1] == "plain addl"
    assert cb.use == 2
    m.selector = 0


def test_weak_release_destroys_block_at_zero():
    cb = m.ControlBlock(m.CONTROL_BLOCK_VTABLE, use=1, weak=1)
    weak = m.WeakPtr(object(), cb)
    weak.release()
    assert cb.weak == 0
    assert cb.destroyed


def test_add_library_happy_path():
    registry = fresh_registry()
    calls = []
    assert registry.add_library("MockEnv", lambda lib, name: calls.append((lib.name, name))) == 0
    assert registry.names == ["MockEnv"]
    assert [s.obj.name for s in registry.libraries.items] == ["MockEnv"]
    assert calls == [("MockEnv", "MockEnv")]
    assert registry.mutex_locked is False


def test_add_library_empty_name_returns_minus_one():
    registry = fresh_registry()
    assert registry.add_library("", lambda lib, name: None) == -1
    assert registry.names == []
    assert registry.libraries.items == []


def test_add_library_null_creator_returns_minus_one():
    registry = fresh_registry()
    assert registry.add_library("MockEnv", None) == -1
    assert registry.names == []
    assert registry.libraries.items == []


def test_add_library_temp_released_after_creator():
    registry = fresh_registry()
    registry.add_library("MockEnv", lambda lib, name: None)
    lib = registry.libraries.items[0]
    # One reference: the vector element. The temp was released.
    assert lib.cb.use == 1


def test_add_library_growth_doubles_capacity():
    registry = fresh_registry()
    for i in range(5):
        registry.add_library("lib%d" % i, lambda lib, name: None)
    assert registry.libraries.capacity == 8
    assert registry.libraries.events == ["grow to 1", "grow to 2", "grow to 4", "grow to 8"]
    assert [s.obj.name for s in registry.libraries.items] == [
        "lib0", "lib1", "lib2", "lib3", "lib4"]


def test_vector_insert_bumps_copied_count():
    vec = m.SharedPtrVector()
    lib = m.ObjectLibrary("x")
    assert lib.cb.use == 1
    vec.append(m.SharedPtr(lib, lib.cb))
    assert lib.cb.use == 2
    vec.destroy([])
    assert lib.cb.use == 1


def test_map_destroy_order_right_node_left():
    registry = fresh_registry()
    cb = m.ControlBlock(m.CONTROL_BLOCK_VTABLE)
    for key in ("b", "a", "c"):
        registry.map.insert(key, m.WeakPtr(object(), cb))
    events = []
    registry.map.destroy(events)
    # rec-destroy: right subtree, node, then left subtree.
    assert events == [
        "release weak c", "destroy key c", "delete node c",
        "release weak b", "destroy key b", "delete node b",
        "release weak a", "destroy key a", "delete node a",
    ]
    assert registry.map.count == 0
    assert registry.map.root is None


def test_dispose_order_parent_map_names_libraries():
    registry = fresh_registry()
    registry.add_library("MockEnv", lambda lib, name: None)
    registry.add_library("CompositeEnv", lambda lib, name: None)
    # A map entry whose weak_ptr points at the registry itself.
    registry.map.insert("MockEnv", m.WeakPtr(registry, m.ControlBlock(0)))
    registry.parent = m.SharedPtr(fresh_registry(), m.ControlBlock(0))
    registry.dispose()
    assert registry.events[0] == "release parent"
    assert "release weak MockEnv" in registry.events
    assert "destroy key MockEnv" in registry.events
    assert "destroy name MockEnv" in registry.events
    assert "destroy name CompositeEnv" in registry.events
    assert registry.events[-1] == "free buffer"
    assert registry.names == []
    assert registry.libraries.items == []
    assert registry.map.count == 0


def test_lock_guard_unlocks_and_clears():
    registry = fresh_registry()
    registry.lock()
    assert registry.mutex_locked is True
    registry.unlock()
    assert registry.mutex_locked is False


def test_singleton_is_single_and_seeded_with_default():
    first = m.singleton()
    second = m.singleton()
    assert first is second
    assert [s.obj.name for s in first.libraries.items] == ["default"]
    assert first.map.count == 0
    assert first.parent is None
    assert first.unknown == bytearray(0x28)


def test_default_library_named_default():
    assert m.default_library().name == "default"
    assert m.default_library() is m.default_library()


def test_clone_links_parent_to_singleton():
    registry = m.singleton()
    before = m._singleton_cb.use
    child = registry.clone()
    assert child.parent.obj is registry
    assert m._singleton_cb.use == before + 1
    assert child.libraries.items == []
    assert child.map.count == 0
    assert child.names == []
    assert child.unknown == bytearray(0x28)
    assert child.parent is not registry.parent


def test_clone_dispose_releases_parent():
    registry = m.singleton()
    before = m._singleton_cb.use
    child = registry.clone()
    child.dispose()
    assert m._singleton_cb.use == before
    assert child.parent is None


def test_registrar_replay_in_constructor():
    # The binary's ctor iterates the global registrar map
    # (empty at static-init time) and calls AddLibrary once
    # per node in map order; the loop is exercised here with
    # two synthetic entries through the extracted constructor.
    seen = []
    registry = m.construct(m.default_library(), [
        ("MockEnv", lambda lib, name: seen.append(name)),
        ("CompositeEnv", lambda lib, name: seen.append(name)),
    ])
    assert seen == ["MockEnv", "CompositeEnv"]
    assert registry.names == ["MockEnv", "CompositeEnv"]
    assert [s.obj.name for s in registry.libraries.items] == [
        "default", "MockEnv", "CompositeEnv"]


def test_ttl_registration_appends_only_libraries():
    registry = m.singleton()
    before_libs = len(registry.libraries.items)
    before_names = list(registry.names)
    calls = []
    library = m.register_ttl(lambda lib, name: calls.append((lib.name, name)))
    assert library.name == "TTL"
    assert len(registry.libraries.items) == before_libs + 1
    assert registry.libraries.items[-1].obj is library
    assert registry.names == before_names  # TTL is NOT in names
    assert "TTL" not in registry.names
    assert calls == [("TTL", "")]  # creator invoked with empty name
    assert registry.mutex_locked is False
    assert library.cb.use == 1  # temp released; vector holds one


def test_registrar_init_empty_map_and_build_info():
    info = m.registrar_init()
    assert info["bucket_count"] == 1
    assert info["before_begin"] == 0
    assert info["element_count"] == 0
    assert info["max_load_factor"] == 1.0
    assert info["next_resize"] == 0
    assert info["git_sha"] == "6a436150417120a3f9732d65a2a5c2b8d19b60fc"
    assert info["git_tag"] == "rocksdb_build_git_tag:v8.1.1"
    assert info["build_date"] == "rocksdb_build_date:2023-04-06 16:38:52"


def test_globals():
    assert m.REGISTRY_GUARD == 0x65090F8
    assert m.REGISTRY_HOLDER == 0x6509100
    assert m.LIBRARY_GUARD == 0x6509108
    assert m.LIBRARY_HOLDER == 0x6509110
    assert m.REGISTRAR_MAP == 0x6509540
    assert m.TTL_CREATOR == 0x6208290
    assert m.PACKED_COUNTS == 0x459B20
    assert m.SELECTOR == 0x64ED290
