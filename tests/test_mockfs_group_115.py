"""Tests for the MockFileSystem option-group model (node #115).

Grounding: research/work-items/RE-001-mockfs-group-115/ — the single
RegisterOptions call site in MockFileSystem 0x6028a60, the element
layout and growth rule from #3257 (RE-001-record-pushback-115), and the
one map entry from the static initializer 0x6029d10 (type 0 = bool per
merged RE-001-optiontypeinfo-mismatches-115).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from mockfs_group_115 import (
    ELEMENT_SIZE,
    MAX_SIZE,
    MOCKFS_ENTRIES,
    MOCKFS_MAP,
    MOCKFS_TYPE,
    OBJECT_SIZE,
    GroupVector,
    MockFileSystem,
    OptionGroup,
    build_mockfs,
    supports_direct_io_entry,
)


def test_element_size_is_0x30():
    assert ELEMENT_SIZE == 0x30


def test_object_size_is_0x98():
    assert OBJECT_SIZE == 0x98
    assert build_mockfs().object_size == 0x98


def test_group_name_is_empty_and_sso():
    fs = build_mockfs()
    group = fs.groups.groups[0]
    assert group.name == ""
    assert len("") == 0
    # Empty name: within the 15-char SSO limit, so the element name is
    # stack/SSO-backed, not heap-backed.
    assert not group.heap_backed


def test_sso_boundary():
    assert not OptionGroup("123456789012345", 0, 0, 0).heap_backed  # 15
    assert OptionGroup("1234567890123456", 0, 0, 0).heap_backed     # 16
    # The map key is 18 chars, so it is heap-backed (unlike the group name).
    assert len("supports_direct_io") == 18
    assert OptionGroup("supports_direct_io", 0, 0, 0).heap_backed


def test_base_and_map():
    fs = build_mockfs()
    group = fs.groups.groups[0]
    assert group.base_offset == 0x90
    assert group.map_addr == MOCKFS_MAP
    assert group.map_entries == MOCKFS_ENTRIES == 1


def test_single_group_vector():
    fs = build_mockfs()
    assert fs.groups.size == 1
    assert fs.groups.capacity == 1
    assert fs.groups.byte_size == ELEMENT_SIZE
    assert [g.name for g in fs.groups.groups] == [""]


def test_vector_grows_0_1():
    vec = GroupVector()
    assert (vec.size, vec.capacity, vec.byte_size) == (0, 0, 0)
    vec.register("", 0x90, MOCKFS_MAP, 1)
    assert (vec.size, vec.capacity) == (1, 1)
    assert vec.byte_size == ELEMENT_SIZE


def test_capacity_doubles_after_first():
    vec = GroupVector()
    for i in range(5):
        vec.register(f"g{i}", 0x20 + i, MOCKFS_MAP, None)
    assert (vec.size, vec.capacity) == (5, 8)


def test_growth_max_size():
    assert MAX_SIZE == (2**63 - 1) // 48
    assert MAX_SIZE == 192153584101141162


def test_map_entry_decodes_to_bool_type():
    entry = supports_direct_io_entry()
    assert entry.key == "supports_direct_io"
    assert entry.pack == 0x0
    assert entry.option_type == MOCKFS_TYPE == 0
    assert entry.verification == 0
    assert entry.flags == 0x0
    assert entry.offset == 0
    assert entry.callbacks is False


def test_creators_default_true():
    # Both creators (invoker 0x5fe58b0, MockEnv::Create 0x6028d80) pass
    # bool=true; the flag is set after construction through the option.
    assert build_mockfs(True).supports_direct_io is True
    assert build_mockfs(False).supports_direct_io is False


def test_group_repr_names_fields():
    g = OptionGroup("", 0x90, MOCKFS_MAP, 1)
    assert "0x65058e0" in repr(g)
    assert "0x90" in repr(g)


def test_mockfs_class_layout_offsets():
    fs = MockFileSystem(True)
    assert fs.groups.groups[0].base_offset == 0x90
