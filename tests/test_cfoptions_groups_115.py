"""Tests for the ConfigurableCFOptions option-group model (node #115).

Grounding: research/work-items/RE-001-cfoptions-groups-115/ — the two
RegisterOptions call sites in ConfigurableCFOptions 0x6086e00, the
element layout and growth rule from #3257 (RE-001-record-pushback-115),
and the map entry counts from #4263 (RE-001-cfoptions-maps-115).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cfoptions_groups_115 import (
    ELEMENT_SIZE,
    MAX_SIZE,
    GroupVector,
    OptionGroup,
    build_cfoptions_configurable,
)


def test_element_size_is_0x30():
    assert ELEMENT_SIZE == 0x30


def test_group_names_and_heap_split():
    vec = build_cfoptions_configurable()
    assert [g.name for g in vec.groups] == [
        "MutableCFOptions", "ImmutableCFOptions"]
    # 16 and 18 chars: both exceed the 15-char SSO limit, so both names
    # are heap-backed in the element (builder _M_create + memcpy path).
    assert all(g.heap_backed for g in vec.groups)
    assert len("MutableCFOptions") == 16
    assert len("ImmutableCFOptions") == 18


def test_sso_boundary():
    assert not OptionGroup("123456789012345", 0, 0, 0).heap_backed  # 15
    assert OptionGroup("1234567890123456", 0, 0, 0).heap_backed     # 16


def test_bases_and_maps():
    vec = build_cfoptions_configurable()
    mutable, immutable = vec.groups
    assert mutable.base_offset == 0x20
    assert mutable.map_addr == 0x6506B20
    assert mutable.map_entries == 62
    assert immutable.base_offset == 0x218
    assert immutable.map_addr == 0x6506AE0
    assert immutable.map_entries == 31


def test_registration_order():
    vec = build_cfoptions_configurable()
    assert vec.groups[0].name == "MutableCFOptions"
    assert vec.groups[1].name == "ImmutableCFOptions"


def test_vector_grows_0_1_2():
    vec = GroupVector()
    assert (vec.size, vec.capacity, vec.byte_size) == (0, 0, 0)
    vec.register("MutableCFOptions", 0x20, 0x6506B20, 62)
    assert (vec.size, vec.capacity) == (1, 1)
    vec.register("ImmutableCFOptions", 0x218, 0x6506AE0, 31)
    assert (vec.size, vec.capacity) == (2, 2)
    assert vec.byte_size == 2 * ELEMENT_SIZE


def test_capacity_doubles_after_first():
    vec = GroupVector()
    for i in range(5):
        vec.register(f"g{i}", 0x20 + i, 0x6506B20, 62)
    assert (vec.size, vec.capacity) == (5, 8)


def test_growth_max_size():
    assert MAX_SIZE == (2**63 - 1) // 48
    assert MAX_SIZE == 192153584101141162


def test_append_at_end_keeps_existing():
    vec = build_cfoptions_configurable()
    before = list(vec.groups)
    vec.register("Extra", 0x300, 0x6506B20, 62)
    assert vec.groups[:2] == before
    assert vec.groups[2].name == "Extra"
    assert vec.size == 3


def test_group_repr_names_fields():
    g = OptionGroup("MutableCFOptions", 0x20, 0x6506B20, 62)
    assert "MutableCFOptions" in repr(g)
    assert "0x6506b20" in repr(g)
