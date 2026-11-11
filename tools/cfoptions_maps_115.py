"""Model of node #115's ColumnFamilyOptions OptionTypeInfo maps (RE-001).

Pinned by RE-001 work item RE-001-cfoptions-maps-115 against
work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The static initializer 0x6089b50..0x6091e5c builds FIVE maps,
not one: CompressionOptions (9 entries), CompactionOptionsFIFO
(4), CompactionOptionsUniversal (8), MutableCFOptions (62) and
ImmutableCFOptions (31) -- 114 entries in total. The
Mutable/Immutable split is proven by the consumer 0x6086e00,
which serializes map 0x6506b20 under the literal
"MutableCFOptions" and map 0x6506ae0 under "ImmutableCFOptions".

Verification semantics (from #4237): 0 = normal; 4 = the apply
path accepts and ignores the entry and never dereferences its
offset, so every verification-4 entry records offset 0.
Verification 1 / 2 / 3 / 5 are distinct checked kinds whose
exact checks are not yet pinned (see the packet README).

Type codes follow the #4237 labels; the exact C++ enum names
for types 4 vs 6 and 3 vs 7 vs 8 are still open. Named-enum
name lists are the #4239 registries (tools/enum_registries_115).

Parse and serialize mirror the binary's shared helpers:
- lookup (0x60ba0b0): map lookup by key; a miss rejects the key.
- per-section parser (0x60c1d50): applies one section through
  its map; nested entries (type 19) route to their sub-map
  under a [section] header, as the FIFO parser 0x607e560 and
  the nested CompressionOptions parsers 0x60833b0 / 0x6083490 do.
- per-map serializer (0x6099ce0 via 0x6099790): emits one
  section per map; verification-4 entries are never emitted
  because they hold no stored value.

Usage: python3 -m tools.cfoptions_maps_115
"""

# map name -> .bss global address.
MAPS = {
    "CompressionOptions": "0x6506be0",
    "CompactionOptionsFIFO": "0x6506ba0",
    "CompactionOptionsUniversal": "0x6506b60",
    "MutableCFOptions": "0x6506b20",
    "ImmutableCFOptions": "0x6506ae0",
}

# (map, name) -> entry. offset/type/verification/flags are the
# as-built values the initializer writes into the records.
ENTRIES = {
    ("CompressionOptions", "window_bits"): {"offset": 0, "type": 1, "type_name": "int32", "verification": 0, "flags": 256},
    ("CompressionOptions", "level"): {"offset": 4, "type": 1, "type_name": "int32", "verification": 0, "flags": 256},
    ("CompressionOptions", "strategy"): {"offset": 8, "type": 1, "type_name": "int32", "verification": 0, "flags": 256},
    ("CompressionOptions", "max_dict_bytes"): {"offset": 12, "type": 1, "type_name": "int32", "verification": 0, "flags": 256},
    ("CompressionOptions", "zstd_max_train_bytes"): {"offset": 16, "type": 6, "type_name": "uint32", "verification": 0, "flags": 256},
    ("CompressionOptions", "parallel_threads"): {"offset": 20, "type": 6, "type_name": "uint32", "verification": 0, "flags": 256},
    ("CompressionOptions", "enabled"): {"offset": 24, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("CompressionOptions", "max_dict_buffer_bytes"): {"offset": 32, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("CompressionOptions", "use_zstd_dict_trainer"): {"offset": 40, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("CompactionOptionsFIFO", "max_table_files_size"): {"offset": 0, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("CompactionOptionsFIFO", "ttl"): {"offset": 0, "type": 7, "type_name": "uint64", "verification": 4, "flags": 0},
    ("CompactionOptionsFIFO", "allow_compaction"): {"offset": 8, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("CompactionOptionsFIFO", "age_for_warm"): {"offset": 16, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("CompactionOptionsUniversal", "size_ratio"): {"offset": 0, "type": 4, "type_name": "uint32", "verification": 0, "flags": 256},
    ("CompactionOptionsUniversal", "min_merge_width"): {"offset": 4, "type": 4, "type_name": "uint32", "verification": 0, "flags": 256},
    ("CompactionOptionsUniversal", "max_merge_width"): {"offset": 8, "type": 4, "type_name": "uint32", "verification": 0, "flags": 256},
    ("CompactionOptionsUniversal", "max_size_amplification_percent"): {"offset": 12, "type": 4, "type_name": "uint32", "verification": 0, "flags": 256},
    ("CompactionOptionsUniversal", "compression_size_percent"): {"offset": 16, "type": 1, "type_name": "int32", "verification": 0, "flags": 256},
    ("CompactionOptionsUniversal", "stop_style"): {"offset": 20, "type": 14, "type_name": "named-enum", "verification": 0, "flags": 256},
    ("CompactionOptionsUniversal", "allow_trivial_move"): {"offset": 24, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("CompactionOptionsUniversal", "incremental"): {"offset": 25, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("MutableCFOptions", "bottommost_temperature"): {"offset": 0, "type": 24, "type_name": "named-enum", "verification": 4, "flags": 256},
    ("MutableCFOptions", "expanded_compaction_factor"): {"offset": 0, "type": 1, "type_name": "int32", "verification": 4, "flags": 256},
    ("MutableCFOptions", "filter_deletes"): {"offset": 0, "type": 0, "type_name": "bool", "verification": 4, "flags": 256},
    ("MutableCFOptions", "hard_rate_limit"): {"offset": 0, "type": 10, "type_name": "double", "verification": 4, "flags": 256},
    ("MutableCFOptions", "max_grandparent_overlap_factor"): {"offset": 0, "type": 1, "type_name": "int32", "verification": 4, "flags": 256},
    ("MutableCFOptions", "memtable_prefix_bloom_bits"): {"offset": 0, "type": 6, "type_name": "uint32", "verification": 4, "flags": 256},
    ("MutableCFOptions", "memtable_prefix_bloom_huge_page_tlb_size"): {"offset": 0, "type": 8, "type_name": "size_t", "verification": 4, "flags": 256},
    ("MutableCFOptions", "memtable_prefix_bloom_probes"): {"offset": 0, "type": 6, "type_name": "uint32", "verification": 4, "flags": 256},
    ("MutableCFOptions", "min_partial_merge_operands"): {"offset": 0, "type": 6, "type_name": "uint32", "verification": 4, "flags": 256},
    ("MutableCFOptions", "snap_refresh_nanos"): {"offset": 0, "type": 7, "type_name": "uint64", "verification": 4, "flags": 256},
    ("MutableCFOptions", "soft_rate_limit"): {"offset": 0, "type": 10, "type_name": "double", "verification": 4, "flags": 256},
    ("MutableCFOptions", "source_compaction_factor"): {"offset": 0, "type": 1, "type_name": "int32", "verification": 4, "flags": 256},
    ("MutableCFOptions", "verify_checksums_in_compaction"): {"offset": 0, "type": 0, "type_name": "bool", "verification": 4, "flags": 256},
    ("MutableCFOptions", "write_buffer_size"): {"offset": 0, "type": 8, "type_name": "size_t", "verification": 0, "flags": 256},
    ("MutableCFOptions", "max_write_buffer_number"): {"offset": 8, "type": 1, "type_name": "int32", "verification": 0, "flags": 256},
    ("MutableCFOptions", "arena_block_size"): {"offset": 16, "type": 8, "type_name": "size_t", "verification": 0, "flags": 256},
    ("MutableCFOptions", "memtable_prefix_bloom_size_ratio"): {"offset": 24, "type": 10, "type_name": "double", "verification": 0, "flags": 256},
    ("MutableCFOptions", "memtable_whole_key_filtering"): {"offset": 32, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("MutableCFOptions", "memtable_huge_page_size"): {"offset": 40, "type": 8, "type_name": "size_t", "verification": 0, "flags": 256},
    ("MutableCFOptions", "max_successive_merges"): {"offset": 48, "type": 8, "type_name": "size_t", "verification": 0, "flags": 256},
    ("MutableCFOptions", "inplace_update_num_locks"): {"offset": 56, "type": 8, "type_name": "size_t", "verification": 0, "flags": 256},
    ("MutableCFOptions", "prefix_extractor"): {"offset": 64, "type": 22, "type_name": "struct", "verification": 2, "flags": 4352},
    ("MutableCFOptions", "experimental_mempurge_threshold"): {"offset": 80, "type": 10, "type_name": "double", "verification": 0, "flags": 256},
    ("MutableCFOptions", "disable_auto_compactions"): {"offset": 88, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("MutableCFOptions", "soft_pending_compaction_bytes_limit"): {"offset": 96, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "hard_pending_compaction_bytes_limit"): {"offset": 104, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "level0_file_num_compaction_trigger"): {"offset": 112, "type": 1, "type_name": "int32", "verification": 0, "flags": 256},
    ("MutableCFOptions", "level0_slowdown_writes_trigger"): {"offset": 116, "type": 1, "type_name": "int32", "verification": 0, "flags": 256},
    ("MutableCFOptions", "level0_stop_writes_trigger"): {"offset": 120, "type": 1, "type_name": "int32", "verification": 0, "flags": 256},
    ("MutableCFOptions", "max_compaction_bytes"): {"offset": 128, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "ignore_max_compaction_bytes_for_input"): {"offset": 136, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("MutableCFOptions", "target_file_size_base"): {"offset": 144, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "target_file_size_multiplier"): {"offset": 152, "type": 1, "type_name": "int32", "verification": 0, "flags": 256},
    ("MutableCFOptions", "max_bytes_for_level_base"): {"offset": 160, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "max_bytes_for_level_multiplier"): {"offset": 168, "type": 10, "type_name": "double", "verification": 0, "flags": 256},
    ("MutableCFOptions", "ttl"): {"offset": 176, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "periodic_compaction_seconds"): {"offset": 184, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "max_bytes_for_level_multiplier_additional"): {"offset": 192, "type": 20, "type_name": "vector", "verification": 0, "flags": 256},
    ("MutableCFOptions", "compaction_options_fifo"): {"offset": 216, "type": 19, "type_name": "struct", "verification": 0, "flags": 256, "sub_map": "CompactionOptionsFIFO"},
    ("MutableCFOptions", "compaction_options_universal"): {"offset": 240, "type": 19, "type_name": "struct", "verification": 0, "flags": 256, "sub_map": "CompactionOptionsUniversal"},
    ("MutableCFOptions", "enable_blob_files"): {"offset": 268, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("MutableCFOptions", "min_blob_size"): {"offset": 272, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "blob_file_size"): {"offset": 280, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "blob_compression_type"): {"offset": 288, "type": 13, "type_name": "named-enum", "verification": 0, "flags": 256},
    ("MutableCFOptions", "enable_blob_garbage_collection"): {"offset": 289, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("MutableCFOptions", "blob_garbage_collection_age_cutoff"): {"offset": 296, "type": 10, "type_name": "double", "verification": 0, "flags": 256},
    ("MutableCFOptions", "blob_garbage_collection_force_threshold"): {"offset": 304, "type": 10, "type_name": "double", "verification": 0, "flags": 256},
    ("MutableCFOptions", "blob_compaction_readahead_size"): {"offset": 312, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "blob_file_starting_level"): {"offset": 320, "type": 1, "type_name": "int32", "verification": 0, "flags": 256},
    ("MutableCFOptions", "prepopulate_blob_cache"): {"offset": 324, "type": 18, "type_name": "enum", "verification": 0, "flags": 256},
    ("MutableCFOptions", "max_sequential_skip_in_iterations"): {"offset": 328, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "check_flush_compaction_key_order"): {"offset": 336, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("MutableCFOptions", "paranoid_file_checks"): {"offset": 337, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("MutableCFOptions", "report_bg_io_stats"): {"offset": 338, "type": 0, "type_name": "bool", "verification": 0, "flags": 256},
    ("MutableCFOptions", "compression"): {"offset": 339, "type": 13, "type_name": "named-enum", "verification": 0, "flags": 256},
    ("MutableCFOptions", "bottommost_compression"): {"offset": 340, "type": 13, "type_name": "named-enum", "verification": 0, "flags": 256},
    ("MutableCFOptions", "compression_opts"): {"offset": 344, "type": 19, "type_name": "struct", "verification": 0, "flags": 257, "sub_map": "CompressionOptions"},
    ("MutableCFOptions", "bottommost_compression_opts"): {"offset": 392, "type": 19, "type_name": "struct", "verification": 0, "flags": 257, "sub_map": "CompressionOptions"},
    ("MutableCFOptions", "last_level_temperature"): {"offset": 440, "type": 24, "type_name": "named-enum", "verification": 0, "flags": 256},
    ("MutableCFOptions", "memtable_protection_bytes_per_key"): {"offset": 444, "type": 6, "type_name": "uint32", "verification": 0, "flags": 256},
    ("MutableCFOptions", "sample_for_compression"): {"offset": 448, "type": 7, "type_name": "uint64", "verification": 0, "flags": 256},
    ("MutableCFOptions", "compression_per_level"): {"offset": 456, "type": 20, "type_name": "vector", "verification": 0, "flags": 256},
    ("ImmutableCFOptions", "compaction_measure_io_stats"): {"offset": 0, "type": 0, "type_name": "bool", "verification": 4, "flags": 0},
    ("ImmutableCFOptions", "compaction_style"): {"offset": 0, "type": 11, "type_name": "named-enum", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "max_mem_compaction_level"): {"offset": 0, "type": 1, "type_name": "int32", "verification": 4, "flags": 0},
    ("ImmutableCFOptions", "purge_redundant_kvs_while_flush"): {"offset": 0, "type": 0, "type_name": "bool", "verification": 4, "flags": 0},
    ("ImmutableCFOptions", "rate_limit_delay_max_milliseconds"): {"offset": 0, "type": 4, "type_name": "uint32", "verification": 4, "flags": 0},
    ("ImmutableCFOptions", "table_properties_collectors"): {"offset": 0, "type": 6, "type_name": "uint32", "verification": 4, "flags": 256},
    ("ImmutableCFOptions", "compaction_pri"): {"offset": 1, "type": 12, "type_name": "named-enum", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "comparator"): {"offset": 8, "type": 22, "type_name": "struct", "verification": 1, "flags": 514},
    ("ImmutableCFOptions", "merge_operator"): {"offset": 32, "type": 22, "type_name": "struct", "verification": 3, "flags": 5122},
    ("ImmutableCFOptions", "compaction_filter"): {"offset": 48, "type": 22, "type_name": "struct", "verification": 1, "flags": 4608},
    ("ImmutableCFOptions", "compaction_filter_factory"): {"offset": 56, "type": 22, "type_name": "struct", "verification": 1, "flags": 5120},
    ("ImmutableCFOptions", "min_write_buffer_number_to_merge"): {"offset": 72, "type": 1, "type_name": "int32", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "max_write_buffer_number_to_maintain"): {"offset": 76, "type": 1, "type_name": "int32", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "max_write_buffer_size_to_maintain"): {"offset": 80, "type": 3, "type_name": "uint64", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "inplace_update_support"): {"offset": 88, "type": 0, "type_name": "bool", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "memtable"): {"offset": 104, "type": 22, "type_name": "struct", "verification": 5, "flags": 1024},
    ("ImmutableCFOptions", "memtable_factory"): {"offset": 104, "type": 22, "type_name": "struct", "verification": 1, "flags": 1024},
    ("ImmutableCFOptions", "block_based_table_factory"): {"offset": 120, "type": 22, "type_name": "struct", "verification": 5, "flags": 1026},
    ("ImmutableCFOptions", "plain_table_factory"): {"offset": 120, "type": 22, "type_name": "struct", "verification": 5, "flags": 1026},
    ("ImmutableCFOptions", "table_factory"): {"offset": 120, "type": 22, "type_name": "struct", "verification": 1, "flags": 50178},
    ("ImmutableCFOptions", "bloom_locality"): {"offset": 160, "type": 6, "type_name": "uint32", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "level_compaction_dynamic_level_bytes"): {"offset": 164, "type": 0, "type_name": "bool", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "level_compaction_dynamic_file_size"): {"offset": 165, "type": 0, "type_name": "bool", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "num_levels"): {"offset": 168, "type": 1, "type_name": "int32", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "optimize_filters_for_hits"): {"offset": 172, "type": 0, "type_name": "bool", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "force_consistency_checks"): {"offset": 173, "type": 0, "type_name": "bool", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "preclude_last_level_data_seconds"): {"offset": 176, "type": 7, "type_name": "uint64", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "preserve_internal_time_seconds"): {"offset": 184, "type": 7, "type_name": "uint64", "verification": 0, "flags": 0},
    ("ImmutableCFOptions", "memtable_insert_with_hint_prefix_extractor"): {"offset": 192, "type": 22, "type_name": "struct", "verification": 2, "flags": 0},
    ("ImmutableCFOptions", "sst_partitioner_factory"): {"offset": 248, "type": 22, "type_name": "struct", "verification": 1, "flags": 5120},
    ("ImmutableCFOptions", "blob_cache"): {"offset": 264, "type": 26, "type_name": "shared-ptr/struct", "verification": 0, "flags": 8193},
}

# Named-enum name lists, from the #4239 registries
# (tools/enum_registries_115). Type 18 (PrepopulateBlobCache)
# is a plain enum whose two names live in registry 0x6506fa0.
NAMED_ENUMS = {
    11: {"kCompactionStyleLevel": 0, "kCompactionStyleUniversal": 1,
         "kCompactionStyleFIFO": 2, "kCompactionStyleNone": 3},
    12: {"kByCompensatedSize": 0, "kOldestLargestSeqFirst": 1,
         "kOldestSmallestSeqFirst": 2, "kMinOverlappingRatio": 3,
         "kRoundRobin": 4},
    13: {"kNoCompression": 0, "kSnappyCompression": 1,
         "kZlibCompression": 2, "kBZip2Compression": 3,
         "kLZ4Compression": 4, "kLZ4HCCompression": 5,
         "kXpressCompression": 6, "kZSTD": 7,
         "kZSTDNotFinalCompression": 64,
         "kDisableCompressionOption": 255},
    14: {"kCompactionStopStyleSimilarSize": 0,
         "kCompactionStopStyleTotalSize": 1},
    18: {"kDisable": 0, "kFlushOnly": 1},
    24: {"kUnknown": 0, "kHot": 4, "kWarm": 8, "kCold": 12},
}

VERIFICATION_IGNORED = 4


def map_entries(map_name):
    """All entries of one map, in offset order (name order
    breaks ties at offset 0)."""
    return sorted(
        (dict(name=name, **entry)
         for (m, name), entry in ENTRIES.items() if m == map_name),
        key=lambda e: (e["offset"], e["name"]))


def lookup(map_name, key):
    """Map lookup by key (mirrors 0x60ba0b0); None on a miss."""
    return ENTRIES.get((map_name, key))


def ignored_entries(map_name):
    """The verification-4 entries of one map: accepted and
    ignored by the apply path, never dereferenced."""
    return [e for e in map_entries(map_name)
            if e["verification"] == VERIFICATION_IGNORED]


def aliases_for_offset(map_name, offset):
    """Entry names of one map sharing a struct offset.

    The binary literally builds separate entries at the same
    offset with different verification/flags, so the names
    are aliases of one field with different parse/verify
    behaviour (table_factory x3 at 0x78, memtable_factory /
    memtable at 0x68)."""
    return [e["name"] for e in map_entries(map_name)
            if e["offset"] == offset]


def _coerce(entry, raw):
    """Parse one raw value string into its stored form."""
    t = entry["type"]
    if t == 0:
        if raw not in ("true", "false"):
            raise ValueError(f"bad bool: {raw!r}")
        return raw == "true"
    if t in NAMED_ENUMS:
        registry = NAMED_ENUMS[t]
        if raw not in registry:
            raise ValueError(f"unknown enum name: {raw!r}")
        return registry[raw]
    if t == 20:
        return [v.strip() for v in raw.split(":")] if raw else []
    if t == 10:
        return float(raw)
    if t in (9, 23):
        return raw
    return int(raw)


def _emit(entry, value):
    """Render one stored value back to its raw form."""
    t = entry["type"]
    if t == 0:
        return "true" if value else "false"
    if t in NAMED_ENUMS:
        for name, v in NAMED_ENUMS[t].items():
            if v == value:
                return name
        raise ValueError(f"no enum name for value {value!r}")
    if t == 20:
        return ":".join(value)
    return str(value)


def _parse_lines(map_name, lines, i, values, ignored):
    """Recursive section parser over `lines` starting at index `i`.

    A "[section]" header that is a nested entry of this map recurses
    into the sub-map; a header (or key) that is not this map's ends
    this section and returns the index for the caller to try. Only
    the top level rejects what is left over (see parse_section).
    """
    while i < len(lines):
        line = lines[i].strip()
        if not line or line.startswith("#"):
            i += 1
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            nested = lookup(map_name, section)
            if nested is None or "sub_map" not in nested:
                return i
            values.setdefault(section, {})
            i = _parse_lines(nested["sub_map"], lines, i + 1,
                             values[section], ignored)
            continue
        if "=" not in line:
            raise ValueError(f"bad line: {line!r}")
        key, raw = line.split("=", 1)
        key, raw = key.strip(), raw.strip()
        entry = lookup(map_name, key)
        if entry is None:
            return i
        if entry["verification"] == VERIFICATION_IGNORED:
            ignored.append(key)
        else:
            values[key] = _coerce(entry, raw)
        i += 1
    return i


def parse_section(map_name, text):
    """Parse one OPTIONS-file section through its map.

    Returns (values, ignored): values maps entry names to stored
    values; ignored lists the verification-4 entries that were
    accepted and dropped. Nested entries (type 19) expect a
    "[section]" header and are parsed through the sub-map; the
    nested values land under the entry name. Unknown keys raise
    KeyError (lookup miss rejects the key).
    """
    values, ignored = {}, []
    lines = text.splitlines()
    end = _parse_lines(map_name, lines, 0, values, ignored)
    if end < len(lines):
        raise KeyError(f"unknown option: {lines[end].strip()!r} "
                       f"in {map_name}")
    return values, ignored


def serialize_section(map_name, values):
    """Render stored values back to OPTIONS-file text.

    Nested entries (type 19) are emitted as "[section]" blocks
    parsed through their sub-map. Verification-4 entries hold no
    stored value and are never emitted. Entries are emitted in
    lexicographic key order: the maps are std::map<std::string,
    OptionTypeInfo> and the serializer (0x6099ce0) iterates the map.
    """
    lines = []
    for entry in sorted(map_entries(map_name), key=lambda e: e["name"]):
        name = entry["name"]
        if entry["verification"] == VERIFICATION_IGNORED:
            continue
        if "sub_map" in entry:
            nested = values.get(name)
            if not nested:
                continue
            lines.append(f"[{name}]")
            for sub in sorted(map_entries(entry["sub_map"]),
                              key=lambda e: e["name"]):
                if sub["name"] in nested:
                    lines.append(
                        f"{sub['name']}={_emit(sub, nested[sub['name']])}")
            continue
        if name in values:
            lines.append(f"{name}={_emit(entry, values[name])}")
    return "\n".join(lines) + ("\n" if lines else "")


def main():
    for name in MAPS:
        entries = map_entries(name)
        ignored = ignored_entries(name)
        print(f"{name} ({MAPS[name]}): {len(entries)} entries, "
              f"{len(ignored)} ignored (verification 4)")
    print(f"total: {len(ENTRIES)} entries")


if __name__ == "__main__":
    main()
