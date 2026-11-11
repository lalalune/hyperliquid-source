"""Tests for tools.cfoptions_maps_115 (RE-001-cfoptions-maps-115).

Every expectation is a value the static initializer 0x6089b50 writes
into the five OptionTypeInfo maps of node #115 (see the packet
records.json); the tests exercise the behaviour end-to-end -- parse a
section through the model to stored values and serialize it back --
rather than pinning constants alone.
"""

import pytest

from tools.cfoptions_maps_115 import (
    ENTRIES,
    MAPS,
    aliases_for_offset,
    ignored_entries,
    lookup,
    map_entries,
    parse_section,
    serialize_section,
)

EXPECTED_COUNTS = {
    "CompressionOptions": 9,
    "CompactionOptionsFIFO": 4,
    "CompactionOptionsUniversal": 8,
    "MutableCFOptions": 62,
    "ImmutableCFOptions": 31,
}

EXPECTED_GLOBALS = {
    "CompressionOptions": "0x6506be0",
    "CompactionOptionsFIFO": "0x6506ba0",
    "CompactionOptionsUniversal": "0x6506b60",
    "MutableCFOptions": "0x6506b20",
    "ImmutableCFOptions": "0x6506ae0",
}


def test_five_maps_with_expected_counts_and_globals():
    assert set(MAPS) == set(EXPECTED_COUNTS)
    assert len(ENTRIES) == 114
    for name, count in EXPECTED_COUNTS.items():
        assert MAPS[name] == EXPECTED_GLOBALS[name]
        assert len(map_entries(name)) == count


def test_every_entry_has_offset_type_verification_flags():
    for (map_name, name), entry in ENTRIES.items():
        assert isinstance(entry["offset"], int) and entry["offset"] >= 0
        assert entry["type"] in range(27)
        assert entry["verification"] in (0, 1, 2, 3, 4, 5)
        assert isinstance(entry["flags"], int) and entry["flags"] >= 0


def test_mutable_immutable_split():
    # A key valid in one map is absent from the other: the split the
    # consumer 0x6086e00 proves by serializing each map under its own
    # section literal.
    assert lookup("MutableCFOptions", "write_buffer_size") is not None
    assert lookup("ImmutableCFOptions", "write_buffer_size") is None
    assert lookup("ImmutableCFOptions", "compaction_style") is not None
    assert lookup("MutableCFOptions", "compaction_style") is None
    assert lookup("MutableCFOptions", "disable_auto_compactions") is not None
    assert lookup("ImmutableCFOptions", "disable_auto_compactions") is None


def test_each_map_first_entry_is_its_struct_offset_zero():
    # A genuine first field (verification 0), not an ignored entry.
    for map_name, name in [
        ("CompressionOptions", "window_bits"),
        ("CompactionOptionsFIFO", "max_table_files_size"),
        ("CompactionOptionsUniversal", "size_ratio"),
        ("MutableCFOptions", "write_buffer_size"),
        ("ImmutableCFOptions", "compaction_style"),
    ]:
        entry = lookup(map_name, name)
        assert entry["offset"] == 0
        assert entry["verification"] == 0


def test_fifo_field_order_and_ttl_ignored():
    fifo = lookup("CompactionOptionsFIFO", "max_table_files_size")
    assert fifo["offset"] == 0 and fifo["type"] == 7
    assert lookup("CompactionOptionsFIFO", "allow_compaction")["offset"] == 8
    assert lookup("CompactionOptionsFIFO", "age_for_warm")["offset"] == 16
    ttl = lookup("CompactionOptionsFIFO", "ttl")
    assert ttl["verification"] == 4 and ttl["offset"] == 0
    # ttl is accepted and ignored: it parses but stores nothing.
    values, ignored = parse_section(
        "CompactionOptionsFIFO",
        "max_table_files_size=1073741824\nallow_compaction=true\n"
        "age_for_warm=3600\nttl=3600\n")
    assert values == {"max_table_files_size": 1073741824,
                      "allow_compaction": True, "age_for_warm": 3600}
    assert ignored == ["ttl"]
    assert "ttl" not in serialize_section("CompactionOptionsFIFO", values)


def test_verification_four_entries_never_store():
    # All 19 verification-4 entries parse but hold no value, in both
    # maps that have them.
    for map_name in ("MutableCFOptions", "ImmutableCFOptions"):
        ignored = ignored_entries(map_name)
        assert ignored
        text = "".join(f"{e['name']}=1\n" for e in ignored)
        values, dropped = parse_section(map_name, text)
        assert values == {}
        assert sorted(dropped) == sorted(e["name"] for e in ignored)
    total = sum(len(ignored_entries(m)) for m in MAPS)
    assert total == 19


def test_table_factory_and_memtable_factory_aliases():
    # Three names, one field at ImmutableCFOptions+0x78, with
    # different verification/flags; two names at +0x68.
    assert aliases_for_offset("ImmutableCFOptions", 0x78) == [
        "block_based_table_factory", "plain_table_factory",
        "table_factory"]
    assert aliases_for_offset("ImmutableCFOptions", 0x68) == [
        "memtable", "memtable_factory"]
    assert lookup("ImmutableCFOptions", "table_factory")["verification"] == 1
    assert lookup("ImmutableCFOptions",
                  "block_based_table_factory")["verification"] == 5
    assert lookup("ImmutableCFOptions", "table_factory")["flags"] == 0xC402
    assert lookup("ImmutableCFOptions",
                  "plain_table_factory")["flags"] == 0x402


def test_nested_entries_route_to_sub_maps():
    fifo = lookup("MutableCFOptions", "compaction_options_fifo")
    assert fifo["type"] == 19 and fifo["sub_map"] == "CompactionOptionsFIFO"
    assert fifo["offset"] == 0xD8
    universal = lookup("MutableCFOptions", "compaction_options_universal")
    assert universal["sub_map"] == "CompactionOptionsUniversal"
    assert universal["offset"] == 0xF0
    opts = lookup("MutableCFOptions", "compression_opts")
    assert opts["sub_map"] == "CompressionOptions"
    assert opts["offset"] == 0x158 and opts["flags"] == 0x101
    bottom = lookup("MutableCFOptions", "bottommost_compression_opts")
    assert bottom["sub_map"] == "CompressionOptions"
    assert bottom["offset"] == 0x188


def test_nested_section_round_trip():
    # Lexicographic key order, as the std::map serializer emits it.
    text = (
        "[compaction_options_fifo]\n"
        "allow_compaction=true\n"
        "max_table_files_size=1073741824\n"
        "[compression_opts]\n"
        "level=6\n"
        "window_bits=15\n"
        "disable_auto_compactions=true\n"
        "write_buffer_size=67108864\n")
    values, ignored = parse_section("MutableCFOptions", text)
    assert ignored == []
    assert values["write_buffer_size"] == 67108864
    assert values["disable_auto_compactions"] is True
    assert values["compression_opts"] == {"window_bits": 15, "level": 6}
    assert values["compaction_options_fifo"] == {
        "max_table_files_size": 1073741824, "allow_compaction": True}
    assert serialize_section("MutableCFOptions", values) == text
    # And the same section parses when the top-level keys come first.
    values2, ignored2 = parse_section(
        "MutableCFOptions",
        "write_buffer_size=67108864\n"
        "disable_auto_compactions=true\n"
        "[compaction_options_fifo]\n"
        "max_table_files_size=1073741824\n"
        "allow_compaction=true\n"
        "[compression_opts]\n"
        "window_bits=15\n"
        "level=6\n")
    assert values2 == values and ignored2 == []


def test_named_enum_parse_and_serialize():
    values, ignored = parse_section(
        "MutableCFOptions",
        "compression=kZSTD\nbottommost_compression=kDisableCompressionOption\n")
    assert ignored == []
    assert values["compression"] == 7
    assert values["bottommost_compression"] == 255
    # The CompressionType anomaly from #4239 round-trips.
    assert serialize_section("MutableCFOptions", values) == (
        "bottommost_compression=kDisableCompressionOption\n"
        "compression=kZSTD\n")
    values, _ = parse_section("ImmutableCFOptions",
                              "compaction_style=kCompactionStyleFIFO\n")
    assert values["compaction_style"] == 2
    with pytest.raises(ValueError):
        parse_section("MutableCFOptions", "compression=kNoSuchType\n")


def test_prepopulate_blob_cache_resolves_to_mutable_map():
    # The first open unknown of #4239: PrepopulateBlobCache lives in
    # MutableCFOptions (offset 0x144, type 18 enum), not in the
    # DBOptions maps.
    entry = lookup("MutableCFOptions", "prepopulate_blob_cache")
    assert entry is not None
    assert entry["offset"] == 0x144 and entry["type"] == 18
    assert entry["verification"] == 0 and entry["flags"] == 0x100
    assert lookup("ImmutableCFOptions", "prepopulate_blob_cache") is None
    values, _ = parse_section("MutableCFOptions",
                              "prepopulate_blob_cache=kFlushOnly\n")
    assert values["prepopulate_blob_cache"] == 1


def test_vector_entries():
    additional = lookup("MutableCFOptions",
                        "max_bytes_for_level_multiplier_additional")
    assert additional["type"] == 20 and additional["offset"] == 0xC0
    per_level = lookup("MutableCFOptions", "compression_per_level")
    assert per_level["type"] == 20 and per_level["offset"] == 0x1C8
    values, _ = parse_section(
        "MutableCFOptions",
        "max_bytes_for_level_multiplier_additional=1:2:3\n")
    assert values["max_bytes_for_level_multiplier_additional"] == [
        "1", "2", "3"]


def test_unknown_key_is_rejected():
    with pytest.raises(KeyError):
        parse_section("MutableCFOptions", "no_such_option=1\n")
    with pytest.raises(KeyError):
        parse_section("MutableCFOptions", "[no_such_section]\nlevel=1\n")
    with pytest.raises(KeyError):
        parse_section("ImmutableCFOptions", "write_buffer_size=1\n")


def test_round_trip_mutable_section():
    text = (
        "compression=kSnappyCompression\n"
        "disable_auto_compactions=false\n"
        "max_write_buffer_number=3\n"
        "write_buffer_size=67108864\n")
    values, ignored = parse_section("MutableCFOptions", text)
    assert ignored == []
    assert serialize_section("MutableCFOptions", values) == text
