"""Tests for tools/optiontypeinfo_maps_115.py.

The expectations are target-grounded: every entry comes from the static
initializer 0x60aa2b0 (research/work-items/RE-001-optiontypeinfo-maps-115/
records.json, reproduced by census.py and special_pairs.py), every enum
name from the four enum-name maps built by that initializer, and the
apply/serialize rules from the per-entry apply function 0x60bedc0 and
the serialize dispatch 0x60ba600.  The tests exercise the behavior end
to end -- name -> map -> offset/type/verification -> field write or
ignore -> serialized value -- not only constants.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import optiontypeinfo_maps_115 as m


def _fresh():
    return {"mutable": {}, "dboptions": {}}


def test_two_maps_100_entries():
    # #4233 claimed one 92-entry DBOptions map; the initializer builds
    # two maps (19 + 81) plus four enum-name maps.
    assert len(m.MUTABLE_ENTRIES) == 19
    assert len(m.DBOPTIONS_ENTRIES) == 81
    assert len(m.MUTABLE_ENTRIES) + len(m.DBOPTIONS_ENTRIES) == 100


def test_names_are_unique_within_each_map():
    for table in (m.MUTABLE_ENTRIES, m.DBOPTIONS_ENTRIES):
        names = [e[0] for e in table]
        assert len(names) == len(set(names))


def test_maps_are_disjoint():
    mutable = {e[0] for e in m.MUTABLE_ENTRIES}
    dboptions = {e[0] for e in m.DBOPTIONS_ENTRIES}
    assert not mutable & dboptions


def test_mutable_map_is_the_first_19_blocks():
    # Blocks 0-18, MutableDBOptions fields, all flags 0x100.
    assert m.MUTABLE_ENTRIES[0][0] == "allow_os_buffer"
    assert m.MUTABLE_ENTRIES[18][0] == "max_background_flushes"
    assert all(e[4] == 0x100 for e in m.MUTABLE_ENTRIES)
    assert m.lookup("max_background_compactions") == (
        "mutable", ("max_background_compactions", 4, 1, 0, 0x100, None))


def test_dboptions_map_has_the_eight_specials():
    specials = {"wal_filter", "wal_recovery_mode",
                "access_hint_on_compaction_start", "info_log_level",
                "env", "file_checksum_gen_factory", "statistics",
                "lowest_used_cache_tier"}
    names = {e[0] for e in m.DBOPTIONS_ENTRIES}
    assert specials <= names
    assert m.lookup("wal_filter")[1] == (
        "wal_filter", 0x188, 22, 1, 0x1201, None)
    assert m.lookup("env")[1] == ("env", 0x8, 26, 0, 0x2001, None)
    assert m.lookup("statistics")[1] == (
        "statistics", 0x48, 22, 0, 0x3401, None)
    assert m.lookup("file_checksum_gen_factory")[1] == (
        "file_checksum_gen_factory", 0x1A8, 22, 3, 0x1400, None)


def test_enum_entries_carry_their_maps():
    assert m.lookup("wal_recovery_mode")[1][5] == "0x6506ec0"
    assert m.lookup("access_hint_on_compaction_start")[1][5] == "0x6506e80"
    assert m.lookup("info_log_level")[1][5] == "0x6506e00"
    assert m.lookup("lowest_used_cache_tier")[1][5] == "0x6506e40"
    for name in ("wal_recovery_mode", "access_hint_on_compaction_start",
                 "info_log_level", "lowest_used_cache_tier"):
        assert m.lookup(name)[1][2] == 18  # mid-helper enum type
        assert m.lookup(name)[1][3] == 0   # verification 0
        assert m.lookup(name)[1][4] == 0   # flags 0


def test_enum_maps_have_the_right_contents():
    assert m.ENUM_MAPS["0x6506ec0"] == {
        "kTolerateCorruptedTailRecords": 0, "kAbsoluteConsistency": 1,
        "kPointInTimeRecovery": 2, "kSkipAnyCorruptedRecords": 3}
    assert m.ENUM_MAPS["0x6506e80"] == {
        "NONE": 0, "NORMAL": 1, "SEQUENTIAL": 2, "WILLNEED": 3}
    assert m.ENUM_MAPS["0x6506e40"] == {
        "kVolatileTier": 0, "kNonVolatileBlockTier": 1}
    assert m.ENUM_MAPS["0x6506e00"] == {
        "DEBUG_LEVEL": 0, "INFO_LEVEL": 1, "WARN_LEVEL": 2,
        "ERROR_LEVEL": 3, "FATAL_LEVEL": 4, "HEADER_LEVEL": 5}


def test_offset_zero_splits_two_real_thirteen_ignored():
    real, ignored = m.offset_zero_entries()
    assert {e[0] for _, e in real} == {
        "max_background_jobs", "create_if_missing"}
    assert all(e[3] == 0 for _, e in real)
    assert len(ignored) == 13
    assert all(e[3] == 4 for _, e in ignored)
    assert {e[0] for _, e in ignored} == {
        "allow_os_buffer", "base_background_compactions",
        "use_direct_writes", "disableDataSync", "disable_data_sync",
        "experimental_allow_mempurge", "experimental_mempurge_policy",
        "experimental_mempurge_threshold", "skip_log_error_on_recovery",
        "new_table_reader_for_compaction_inputs", "preserve_deletes",
        "concurrent_prepare", "seq_per_batch"}


def test_real_offset_zero_fields_are_written():
    opts = _fresh()
    status, applied, _ = m.apply(opts, "max_background_jobs", "8")
    assert status == "OK" and applied
    assert opts["mutable"][0] == 8
    status, applied, _ = m.apply(opts, "create_if_missing", "true")
    assert status == "OK" and applied
    assert opts["dboptions"][0] is True
    # The two offset-0 fields live in different structs.
    assert opts["mutable"][0] != opts["dboptions"][0]


def test_verification_4_entries_are_accepted_and_ignored():
    opts = _fresh()
    for name in ("allow_os_buffer", "base_background_compactions",
                 "use_direct_writes", "disableDataSync",
                 "disable_data_sync", "experimental_allow_mempurge",
                 "experimental_mempurge_policy",
                 "experimental_mempurge_threshold",
                 "skip_log_error_on_recovery",
                 "new_table_reader_for_compaction_inputs",
                 "preserve_deletes", "concurrent_prepare",
                 "seq_per_batch", "rate_limiter"):
        status, applied, note = m.apply(opts, name, "true")
        assert status == "OK" and not applied, name
        assert "ignored" in note, name
    assert opts == {"mutable": {}, "dboptions": {}}


def test_enum_apply_and_serialize_round_trip():
    opts = _fresh()
    cases = [
        ("wal_recovery_mode", "kPointInTimeRecovery", 0x172, 2),
        ("access_hint_on_compaction_start", "WILLNEED", 0x128, 3),
        ("info_log_level", "FATAL_LEVEL", 0x40, 4),
        ("lowest_used_cache_tier", "kNonVolatileBlockTier", 0x1F8, 1),
    ]
    for name, text, offset, value in cases:
        status, applied, _ = m.apply(opts, name, text)
        assert status == "OK" and applied, name
        assert opts["dboptions"][offset] == value, name
        assert m.serialize(opts, name) == text, name
    # Integer spellings work too, and unknown names error.
    status, applied, _ = m.apply(opts, "wal_recovery_mode", "1")
    assert status == "OK" and opts["dboptions"][0x172] == 1
    status, applied, _ = m.apply(opts, "wal_recovery_mode", "kNope")
    assert status.startswith("Error parsing") and not applied


def test_scalar_apply_and_serialize():
    opts = _fresh()
    assert m.apply(opts, "max_open_files", "65535")[1]
    assert opts["mutable"][0x40] == 65535
    assert m.serialize(opts, "max_open_files") == "65535"
    assert m.apply(opts, "bytes_per_sync", "1048576")[1]
    assert opts["mutable"][0x48] == 1048576
    assert m.apply(opts, "db_log_dir", "/tmp/logs")[1]
    assert opts["dboptions"][0x78] == "/tmp/logs"
    assert m.serialize(opts, "db_log_dir") == "/tmp/logs"
    assert m.apply(opts, "use_fsync", "false")[1]
    assert opts["dboptions"][0x58] is False
    assert m.serialize(opts, "use_fsync") == "false"
    # Bad values error instead of writing.
    status, applied, _ = m.apply(opts, "max_open_files", "notanint")
    assert status.startswith("Error parsing") and not applied


def test_nested_and_shared_ptr_entries_need_their_custom_parse():
    opts = _fresh()
    for name in ("wal_filter", "statistics", "file_checksum_gen_factory",
                 "env", "rate_limiter_bytes_per_sec", "listeners"):
        status, applied, note = m.apply(opts, name, "x")
        assert status == "OK" and not applied, name
        assert "custom parse" in note, name
    assert opts == {"mutable": {}, "dboptions": {}}


def test_unknown_name_errors_like_the_binary():
    opts = _fresh()
    status, applied, _ = m.apply(opts, "not_an_option", "1")
    assert status == "Unrecognized option: not_an_option"
    assert not applied


def test_wal_compression_takes_integers_only():
    # Type 13 parses through the runtime-built .bss registry 0x6507120,
    # whose names are not recoverable from the static file.
    opts = _fresh()
    assert m.apply(opts, "wal_compression", "2")[1]
    assert opts["dboptions"][0x196] == 2
    status, applied, note = m.apply(
        opts, "wal_compression", "kSnappyCompression")
    assert not applied and "registry" in note


def test_type_widths_match_the_field_offsets():
    # stats_dump_period_sec / stats_persist_period_sec are 4-byte fields
    # (+0x30, +0x34) and parse as type 4; the uint64 fields are type 7.
    assert m.lookup("stats_dump_period_sec")[1][2] == 4
    assert m.lookup("stats_persist_period_sec")[1][2] == 4
    assert m.lookup("delayed_write_rate")[1][2] == 7
    assert m.lookup("writable_file_max_buffer_size")[1][2] == 8
    assert m.lookup("max_subcompactions")[1][2] == 6
