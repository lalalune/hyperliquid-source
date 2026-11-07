"""Tests for tools/optiontypeinfo_map_115.py.

The expectations are target-grounded: every offset comes from the
static initializer's immediate stores (research/work-items/
RE-001-optiontypeinfo-mismatches-115/entries.tsv), every ctor-pack
mapping from the ImmutableDBOptions ctor (0x60a3b60), and every
BuildDBOptions read from 0x60c2e20. The tests exercise the behavior
end to end -- name -> map offset -> ctor pack -> DBOptions source
byte -- not only constants.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import optiontypeinfo_map_115 as m


def test_map_has_92_entries():
    assert len(m.MAP) == 92


def test_group_sizes():
    assert len(m.group_entries("A")) == 19
    assert len(m.group_entries("B")) == 8
    assert len(m.group_entries("C")) == 65


def test_group_a_flags():
    for name in m.group_entries("A"):
        assert m.lookup(name)[1] == 0x100, name


def test_avoid_offset_is_0x198():
    # #4146's map offset was right; its DBOptions source offset was not.
    assert m.offset_of("avoid_unnecessary_blocking_io") == 0x198
    assert m.lookup("avoid_unnecessary_blocking_io") == (0x198, 0x0, "C")


def test_tail_fields_map_to_ctor_pack():
    # The full tail, end to end: DBOptions source byte -> map offset.
    assert m.map_offset_for_dboptions_tail(0x217) == 0x196  # wal_compression
    assert m.map_offset_for_dboptions_tail(0x218) == 0x197  # atomic_flush
    assert m.map_offset_for_dboptions_tail(0x219) == 0x198  # avoid
    assert m.map_offset_for_dboptions_tail(0x21A) == 0x19A  # write_dbid
    assert m.dboptions_tail_field(0x217) == "wal_compression"
    assert m.dboptions_tail_field(0x218) == "atomic_flush"
    assert m.dboptions_tail_field(0x219) == "avoid_unnecessary_blocking_io"
    assert m.dboptions_tail_field(0x21A) == "write_dbid_to_manifest"
    # And the map agrees with the pack on every tail field.
    for dboff, name in m.DBOPTIONS_TAIL.items():
        assert m.offset_of(name) == m.map_offset_for_dboptions_tail(dboff)


def test_4146_tail_correction():
    # #4146 put wal_compression at DBOptions+0x218; the ctor pack puts
    # it at +0x217 (map 0x196). The +0x218 byte is atomic_flush.
    assert m.dboptions_tail_field(0x218) == "atomic_flush"
    assert m.offset_of("wal_compression") == 0x196
    assert m.ctor_pack_source(0x196) == (0x217,)
    assert m.ctor_pack_source(0x197) == (0x218, 0x219, 0x138, 0x21A)


def test_21b_is_padding():
    # DBOptions+0x21b..+0x21f: no field, no map offset, no ctor-pack slot.
    for off in (0x21B, 0x21C, 0x21D, 0x21E, 0x21F):
        assert m.is_padding(off)
        assert m.map_offset_for_dboptions_tail(off) is None
        assert m.dboptions_tail_field(off) is None
    assert not m.is_padding(0x21A)
    assert not m.is_padding(0x220)
    assert m.offset_of("log_readahead_size") == 0x1A0


def test_21b_census_shape():
    # Five struct-field uses, all %rbx in one function on a different
    # struct; twenty %rsp stack slots; nothing else.
    assert len(m.CENSUS_21B_STRUCT_FIELD_SITES) == 5
    assert m.CENSUS_21B_STRUCT_FIELD_FDE == (0x5A897E0, 0x5A8A1CC)
    assert m.CENSUS_21B_RSP_SLOTS == 20


def test_max_open_files_is_mutable_offset():
    # #4146's second unknown: 0x40 is a MutableDBOptions offset.
    # BuildDBOptions reads MutableDBOptions+0x40 and stores it at
    # DBOptions+0x44; ImmutableDBOptions+0x40 is info_log_level.
    assert m.mutable_offset("max_open_files") == 0x40
    assert m.offset_of("max_open_files") == 0x40
    assert m.lookup("max_open_files") == (0x40, 0x100, "A")


def test_builddboptions_reads_match_map():
    # All nine group-A map offsets BuildDBOptions reads match the map.
    for name, mutable_off in m.BUILDDBOPTIONS_READS.items():
        assert m.mutable_offset(name) == mutable_off
        assert m.lookup(name)[2] == "A"


def test_env_bool_cluster_pack():
    # The seven group-B bools pack from DBOptions+0x128..0x12d/+0x148
    # into ImmutableDBOptions+0x108..0x10e.
    assert m.ctor_pack_source(0x108) == (0x128, 0x129, 0x12A, 0x12B)
    assert m.ctor_pack_source(0x10C) == (0x12C, 0x12D)
    assert m.ctor_pack_source(0x10E) == (0x148,)
    assert m.offset_of("allow_mmap_reads") == 0x108
    assert m.offset_of("allow_fallocate") == 0x10C
    assert m.offset_of("advise_random_on_open") == 0x10E
    assert m.offset_of("is_fd_close_on_exec") == 0x10D


def test_158_pack_field_identities():
    # The +0x158 word packs DBOptions+0x1c0/+0x1d0/+0x1d1/+0x1d2.
    assert m.ctor_pack_source(0x158) == (0x1C0, 0x1D0, 0x1D1, 0x1D2)
    assert m.offset_of("enable_pipelined_write") == 0x159
    assert m.offset_of("unordered_write") == 0x15A
    assert m.offset_of("allow_concurrent_memtable_write") == 0x15B
    assert m.offset_of("enable_write_thread_adaptive_yield") == 0x15C


def test_offset_zero_entries_are_unresolved():
    # 15 entries carry offset 0 with null parse functions; the model
    # records them as offset 0 (not a real field address) and the packet
    # lists them as open unknowns.
    unresolved = [n for n, (off, _f, _g) in m.MAP.items() if off == 0]
    assert len(unresolved) == 15
    assert "disableDataSync" in unresolved
    assert "disable_data_sync" in unresolved
    assert "use_direct_writes" in unresolved
    assert "seq_per_batch" in unresolved
    assert "create_if_missing" in unresolved
    assert "experimental_mempurge_policy" in unresolved


def test_names_at_offset():
    # rate_limiter and rate_limiter_bytes_per_sec share offset 0x10
    # (in group C; group A has writable_file_max_buffer_size at 0x10).
    assert m.names_at(0x10, "C") == [
        "rate_limiter", "rate_limiter_bytes_per_sec",
    ]
    assert m.names_at(0x198) == ["avoid_unnecessary_blocking_io"]
    assert m.names_at(0x1A0) == ["log_readahead_size"]
    assert m.lookup("no_such_option") is None
    assert m.offset_of("no_such_option") is None
