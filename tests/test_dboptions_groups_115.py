"""Tests for the DBOptionsConfigurable option-group model (node #115).

Grounding: research/work-items/RE-001-dboptions-groups-115/ — the two
RegisterOptions call sites in DBOptionsConfigurable 0x60a47f0, the
element layout and growth rule from #3257 (RE-001-record-pushback-115),
and the map entry counts from #4237 (RE-001-optiontypeinfo-maps-115).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from dboptions_groups_115 import (
    ELEMENT_SIZE,
    MAX_SIZE,
    GroupVector,
    OptionGroup,
    build_dboptions_configurable,
)


def test_element_size_is_0x30():
    assert ELEMENT_SIZE == 0x30


def test_group_names_and_heap_split():
    vec = build_dboptions_configurable()
    assert [g.name for g in vec.groups] == [
        "MutableDBOptions", "ImmutableDBOptions"]
    # 16 and 18 chars: both exceed the 15-char SSO limit, so both names
    # are heap-backed in the element (builder _M_create + memcpy path).
    assert all(g.heap_backed for g in vec.groups)
    assert len("MutableDBOptions") == 16
    assert len("ImmutableDBOptions") == 18


def test_sso_boundary():
    assert not OptionGroup("123456789012345", 0, 0, 0).heap_backed  # 15
    assert OptionGroup("1234567890123456", 0, 0, 0).heap_backed     # 16


def test_bases_and_maps():
    vec = build_dboptions_configurable()
    mutable, immutable = vec.groups
    assert mutable.base_offset == 0x20
    assert mutable.map_addr == 0x6506DC0
    assert mutable.map_entries == 19
    assert immutable.base_offset == 0x98
    assert immutable.map_addr == 0x6506D80
    assert immutable.map_entries == 81


def test_registration_order():
    vec = build_dboptions_configurable()
    assert vec.groups[0].name == "MutableDBOptions"
    assert vec.groups[1].name == "ImmutableDBOptions"


def test_vector_grows_0_1_2():
    vec = GroupVector()
    assert (vec.size, vec.capacity, vec.byte_size) == (0, 0, 0)
    vec.register("MutableDBOptions", 0x20, 0x6506DC0, 19)
    assert (vec.size, vec.capacity) == (1, 1)
    vec.register("ImmutableDBOptions", 0x98, 0x6506D80, 81)
    assert (vec.size, vec.capacity) == (2, 2)
    assert vec.byte_size == 2 * ELEMENT_SIZE


def test_capacity_doubles_after_first():
    vec = GroupVector()
    for i in range(5):
        vec.register(f"g{i}", 0x20 + i, 0x6506DC0, 19)
    assert (vec.size, vec.capacity) == (5, 8)


def test_growth_max_size():
    assert MAX_SIZE == (2**63 - 1) // 48
    assert MAX_SIZE == 192153584101141162


def test_append_at_end_keeps_existing():
    vec = build_dboptions_configurable()
    before = list(vec.groups)
    vec.register("Extra", 0x100, 0x6506DC0, 19)
    assert vec.groups[:2] == before
    assert vec.groups[2].name == "Extra"
    assert vec.size == 3


def test_group_repr_names_fields():
    g = OptionGroup("MutableDBOptions", 0x20, 0x6506DC0, 19)
    assert "MutableDBOptions" in repr(g)
    assert "0x6506dc0" in repr(g)
