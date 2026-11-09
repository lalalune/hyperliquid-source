"""Tests for the ChrootFileSystem option-group model (node #115).

Grounding: research/work-items/RE-001-chrootfs-group-115/ — the single
RegisterOptions call site in ChrootFileSystem 0x5feeab0, the element
layout and growth rule from #3257 (RE-001-record-pushback-115), the
base-class empty-name group from open PR #4398 (FileSystemWrapper ctor
0x5fe7210), and the one map entry from the static initializer 0x5fef080
(type 9 = string per merged RE-001-optiontypeinfo-mismatches-115).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from chrootfs_group_115 import (
    BASE_MAP,
    CHROOT_ENTRIES,
    CHROOT_MAP,
    CHROOT_TYPE,
    ELEMENT_SIZE,
    MAX_SIZE,
    GroupVector,
    OptionGroup,
    build_chrootfs,
    chroot_dir_entry,
)


def test_element_size_is_0x30():
    assert ELEMENT_SIZE == 0x30


def test_group_name_is_chroot_dir_and_sso():
    vec = build_chrootfs()
    chroot = vec.groups[1]
    assert chroot.name == "chroot_dir"
    assert len("chroot_dir") == 10
    # 10 chars: within the 15-char SSO limit, so the element name is
    # stack/SSO-backed, not heap-backed (unlike the 16/18-char
    # CFOptions names in #4551).
    assert not chroot.heap_backed


def test_sso_boundary():
    assert not OptionGroup("123456789012345", 0, 0, 0).heap_backed  # 15
    assert OptionGroup("1234567890123456", 0, 0, 0).heap_backed     # 16


def test_bases_and_maps():
    vec = build_chrootfs()
    base, chroot = vec.groups
    assert base.name == ""
    assert base.base_offset == 0x20
    assert base.map_addr == BASE_MAP
    assert chroot.base_offset == 0x30
    assert chroot.map_addr == CHROOT_MAP
    assert chroot.map_entries == CHROOT_ENTRIES == 1


def test_registration_order():
    vec = build_chrootfs()
    assert [g.name for g in vec.groups] == ["", "chroot_dir"]


def test_vector_grows_0_1_2():
    vec = GroupVector()
    assert (vec.size, vec.capacity, vec.byte_size) == (0, 0, 0)
    vec.register("", 0x20, BASE_MAP, None)
    assert (vec.size, vec.capacity) == (1, 1)
    vec.register("chroot_dir", 0x30, CHROOT_MAP, 1)
    assert (vec.size, vec.capacity) == (2, 2)
    assert vec.byte_size == 2 * ELEMENT_SIZE


def test_capacity_doubles_after_first():
    vec = GroupVector()
    for i in range(5):
        vec.register(f"g{i}", 0x20 + i, BASE_MAP, None)
    assert (vec.size, vec.capacity) == (5, 8)


def test_growth_max_size():
    assert MAX_SIZE == (2**63 - 1) // 48
    assert MAX_SIZE == 192153584101141162


def test_map_entry_decodes_to_string_type():
    entry = chroot_dir_entry()
    assert entry.key == "chroot_dir"
    assert entry.pack == 0x9
    assert entry.option_type == CHROOT_TYPE == 9
    assert entry.verification == 0
    assert entry.flags == 0x0
    assert entry.offset == 0
    assert entry.callbacks is False


def test_append_at_end_keeps_existing():
    vec = build_chrootfs()
    before = list(vec.groups)
    vec.register("Extra", 0x40, CHROOT_MAP, 1)
    assert vec.groups[:2] == before
    assert vec.groups[2].name == "Extra"
    assert vec.size == 3


def test_group_repr_names_fields():
    g = OptionGroup("chroot_dir", 0x30, CHROOT_MAP, 1)
    assert "chroot_dir" in repr(g)
    assert "0x6505240" in repr(g)
