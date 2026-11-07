#!/usr/bin/env python3
"""Python model of node #115's ColumnFamilyOptions header dump.

Reconstructs the observable behaviour of 0x60b50c0..0x60b79a6
(RE-001-options-dump-115): the 93 leveled-log lines it emits, the
struct field behind each line, and the name/enum/bool value rules.
Bound to work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

The dump logs every line at level 5 (HEADER) through the helper
0x5fceda0, which emits only when the logger's level is <= the message
level.  Value rules, all read from the binary:
  * names come from vtable slot 14 (0x70) of the pointed-to object;
    null pointers print "None" (operators/filters) or "nullptr"
    (prefix extractors); comparator, memtable_factory and
    table_factory are dereferenced without a null check.
  * CompressionType bytes go through 0x5d8b3c0: 0-7 named, 64
    ZSTDNotFinal, 255 DisableOption, anything else empty.
  * compaction_style / compaction_pri / stop_style bytes go through
    the #4239 std::map registries (0x6507260 / 0x6507220 /
    0x65071e0); a miss prints unknown_<n>.
  * bool bytes print "true" when non-zero, else "false".
  * the scalar compression byte (+0x220) is logged only when
    compression_per_level is empty; otherwise one
    compression[i] line per element is logged.
  * bottommost_compression 0xff prints "Disabled".
"""

# InfoLogLevel values used by the leveled log helper 0x5fceda0.
DEBUG_LEVEL = 0
INFO_LEVEL = 1
WARN_LEVEL = 2
ERROR_LEVEL = 3
FATAL_LEVEL = 4
HEADER_LEVEL = 5

# CompressionType names from the 0x5d8b3c0 jump table at 0x96d4f0
# (65 int32 entries; indices 8..63 hit the default arm, which
# appends the empty string; byte 0xff takes the >0x40 path).
COMPRESSION_NAMES = {
    0: "NoCompression", 1: "Snappy", 2: "Zlib", 3: "BZip2", 4: "LZ4",
    5: "LZ4HC", 6: "Xpress", 7: "ZSTD", 64: "ZSTDNotFinal",
    255: "DisableOption",
}

# Value->name registries consumed by the dump (#4239).
COMPACTION_STYLE_NAMES = {
    0: "kCompactionStyleLevel", 1: "kCompactionStyleUniversal",
    2: "kCompactionStyleFIFO", 3: "kCompactionStyleNone",
}
COMPACTION_PRI_NAMES = {
    0: "kByCompensatedSize", 1: "kOldestLargestSeqFirst",
    2: "kOldestSmallestSeqFirst", 3: "kMinOverlappingRatio",
    4: "kRoundRobin",
}
COMPACTION_STOP_STYLE_NAMES = {
    0: "kCompactionStopStyleSimilarSize",
    1: "kCompactionStopStyleTotalSize",
}

STYLE_REGISTRY = 0x6507260
PRI_REGISTRY = 0x6507220
STOP_STYLE_REGISTRY = 0x65071E0

DUMP_FUNCTION = (0x60B50C0, 0x60B79A6)
HELPER_FUNCTION = (0x5FCEDA0, 0x5FCEE93)
HELPER_NOLEVEL_FUNCTION = (0x5FCEEA0, 0x5FCEF5B)
ENUMFN_FUNCTION = (0x5D8B3C0, 0x5D8B4CB)
HOST_FUNCTION = (0x5D954B0, 0x5D96890)
DUMP_HELPER_CALLS = 93
HELPER_DIRECT_CALLERS = 341

# (line, format, offset, kind, key) for the 91 main-body emissions
# plus the 2 cold-block emissions (lines 91-92).  Lines 10 and 44 are
# loops (one emission per vector element); line 62 joins a vector.
# Kinds: name, scalar, bool, enumfn, enummap, slot, loop.
FIELDS = [
    (0, "Options.comparator: %s", 0x1E8, "name", "comparator"),
    (1, "Options.merge_operator: %s", 0x1F0, "name", "merge_operator"),
    (2, "Options.compaction_filter: %s", 0x200, "name",
     "compaction_filter"),
    (3, "Options.compaction_filter_factory: %s", 0x208, "name",
     "compaction_filter_factory"),
    (4, "Options.sst_partitioner_factory: %s", 0x2F0, "name",
     "sst_partitioner_factory"),
    (5, "Options.memtable_factory: %s", 0x128, "name",
     "memtable_factory"),
    (6, "Options.table_factory: %s", 0x2B8, "name", "table_factory"),
    (7, "table_factory options: %s", 0x2B8, "slot",
     "table_factory_options"),
    (8, "Options.write_buffer_size: %zu", 0x218, "scalar",
     "write_buffer_size"),
    (9, "Options.max_write_buffer_number: %d", 0x0, "scalar",
     "max_write_buffer_number"),
    (10, "Options.compression[%d]: %s", 0x70, "loop",
     "compression_per_level"),
    (11, "Options.bottommost_compression: %s", 0x221, "enumfn",
     "bottommost_compression"),
    (12, "Options.prefix_extractor: %s", 0x290, "name",
     "prefix_extractor"),
    (13, "Options.memtable_insert_with_hint_prefix_extractor: %s",
     0x50, "name", "memtable_insert_with_hint_prefix_extractor"),
    (14, "Options.num_levels: %d", 0x88, "scalar", "num_levels"),
    (15, "Options.min_write_buffer_number_to_merge: %d", 0x4, "scalar",
     "min_write_buffer_number_to_merge"),
    (16, "Options.max_write_buffer_number_to_maintain: %d", 0x8,
     "scalar", "max_write_buffer_number_to_maintain"),
    (17, "Options.max_write_buffer_size_to_maintain: %lu", 0x10,
     "scalar", "max_write_buffer_size_to_maintain"),
    (18, "Options.bottommost_compression_opts.window_bits: %d", 0x228,
     "scalar", "bottommost_compression_opts.window_bits"),
    (19, "Options.bottommost_compression_opts.level: %d", 0x22C,
     "scalar", "bottommost_compression_opts.level"),
    (20, "Options.bottommost_compression_opts.strategy: %d", 0x230,
     "scalar", "bottommost_compression_opts.strategy"),
    (21, "Options.bottommost_compression_opts.max_dict_bytes: %u",
     0x234, "scalar", "bottommost_compression_opts.max_dict_bytes"),
    (22, "Options.bottommost_compression_opts.zstd_max_train_bytes: %u",
     0x238, "scalar",
     "bottommost_compression_opts.zstd_max_train_bytes"),
    (23, "Options.bottommost_compression_opts.parallel_threads: %u",
     0x23C, "scalar", "bottommost_compression_opts.parallel_threads"),
    (24, "Options.bottommost_compression_opts.enabled: %s", 0x240,
     "bool", "bottommost_compression_opts.enabled"),
    (25, "Options.bottommost_compression_opts.max_dict_buffer_bytes: %lu",
     0x248, "scalar",
     "bottommost_compression_opts.max_dict_buffer_bytes"),
    (26, "Options.bottommost_compression_opts.use_zstd_dict_trainer: %s",
     0x250, "bool",
     "bottommost_compression_opts.use_zstd_dict_trainer"),
    (27, "Options.compression_opts.window_bits: %d", 0x258, "scalar",
     "compression_opts.window_bits"),
    (28, "Options.compression_opts.level: %d", 0x25C, "scalar",
     "compression_opts.level"),
    (29, "Options.compression_opts.strategy: %d", 0x260, "scalar",
     "compression_opts.strategy"),
    (30, "Options.compression_opts.max_dict_bytes: %u", 0x264, "scalar",
     "compression_opts.max_dict_bytes"),
    (31, "Options.compression_opts.zstd_max_train_bytes: %u", 0x268,
     "scalar", "compression_opts.zstd_max_train_bytes"),
    (32, "Options.compression_opts.use_zstd_dict_trainer: %s", 0x280,
     "bool", "compression_opts.use_zstd_dict_trainer"),
    (33, "Options.compression_opts.parallel_threads: %u", 0x26C,
     "scalar", "compression_opts.parallel_threads"),
    (34, "Options.compression_opts.enabled: %s", 0x270, "bool",
     "compression_opts.enabled"),
    (35, "Options.compression_opts.max_dict_buffer_bytes: %lu", 0x278,
     "scalar", "compression_opts.max_dict_buffer_bytes"),
    (36, "Options.level0_file_num_compaction_trigger: %d", 0x288,
     "scalar", "level0_file_num_compaction_trigger"),
    (37, "Options.level0_slowdown_writes_trigger: %d", 0x8C, "scalar",
     "level0_slowdown_writes_trigger"),
    (38, "Options.level0_stop_writes_trigger: %d", 0x90, "scalar",
     "level0_stop_writes_trigger"),
    (39, "Options.target_file_size_base: %lu", 0x98, "scalar",
     "target_file_size_base"),
    (40, "Options.target_file_size_multiplier: %d", 0xA0, "scalar",
     "target_file_size_multiplier"),
    (41, "Options.max_bytes_for_level_base: %lu", 0x2A0, "scalar",
     "max_bytes_for_level_base"),
    (42, "Options.level_compaction_dynamic_level_bytes: %d", 0xA4,
     "scalar", "level_compaction_dynamic_level_bytes"),
    (43, "Options.max_bytes_for_level_multiplier: %f", 0xA8, "scalar",
     "max_bytes_for_level_multiplier"),
    (44, "Options.max_bytes_for_level_multiplier_addtl[%zu]: %d", 0xB0,
     "loop", "max_bytes_for_level_multiplier_additional"),
    (45, "Options.max_sequential_skip_in_iterations: %lu", 0x120,
     "scalar", "max_sequential_skip_in_iterations"),
    (46, "Options.max_compaction_bytes: %lu", 0xC8, "scalar",
     "max_compaction_bytes"),
    (47, "Options.ignore_max_compaction_bytes_for_input: %s", 0xD0,
     "bool", "ignore_max_compaction_bytes_for_input"),
    (48, "Options.arena_block_size: %zu", 0x68, "scalar",
     "arena_block_size"),
    (49, "Options.soft_pending_compaction_bytes_limit: %lu", 0xD8,
     "scalar", "soft_pending_compaction_bytes_limit"),
    (50, "Options.hard_pending_compaction_bytes_limit: %lu", 0xE0,
     "scalar", "hard_pending_compaction_bytes_limit"),
    (51, "Options.disable_auto_compactions: %d", 0x2B0, "scalar",
     "disable_auto_compactions"),
    (52, "Options.compaction_style: %s", 0xE8, "enummap",
     "compaction_style"),
    (53, "Options.compaction_pri: %s", 0xE9, "enummap", "compaction_pri"),
    (54, "Options.compaction_options_universal.size_ratio: %u", 0xEC,
     "scalar", "compaction_options_universal.size_ratio"),
    (55, "Options.compaction_options_universal.min_merge_width: %u",
     0xF0, "scalar", "compaction_options_universal.min_merge_width"),
    (56, "Options.compaction_options_universal.max_merge_width: %u",
     0xF4, "scalar", "compaction_options_universal.max_merge_width"),
    (57, "Options.compaction_options_universal.max_size_amplification_percent: %u",
     0xF8, "scalar",
     "compaction_options_universal.max_size_amplification_percent"),
    (58, "Options.compaction_options_universal.compression_size_percent: %d",
     0xFC, "scalar",
     "compaction_options_universal.compression_size_percent"),
    (59, "Options.compaction_options_universal.stop_style: %s", 0x100,
     "enummap", "compaction_options_universal.stop_style"),
    (60, "Options.compaction_options_fifo.max_table_files_size: %lu",
     0x108, "scalar", "compaction_options_fifo.max_table_files_size"),
    (61, "Options.compaction_options_fifo.allow_compaction: %d", 0x110,
     "scalar", "compaction_options_fifo.allow_compaction"),
    (62, "Options.table_properties_collectors: %s", 0x138, "loop",
     "table_properties_collectors"),
    (63, "Options.inplace_update_support: %d", 0x18, "scalar",
     "inplace_update_support"),
    (64, "Options.inplace_update_num_locks: %zu", 0x20, "scalar",
     "inplace_update_num_locks"),
    (65, "Options.memtable_prefix_bloom_size_ratio: %f", 0x38, "scalar",
     "memtable_prefix_bloom_size_ratio"),
    (66, "Options.memtable_whole_key_filtering: %d", 0x40, "scalar",
     "memtable_whole_key_filtering"),
    (67, "Options.memtable_huge_page_size: %zu", 0x48, "scalar",
     "memtable_huge_page_size"),
    (68, "Options.bloom_locality: %d", 0x60, "scalar", "bloom_locality"),
    (69, "Options.max_successive_merges: %zu", 0x150, "scalar",
     "max_successive_merges"),
    (70, "Options.optimize_filters_for_hits: %d", 0x158, "scalar",
     "optimize_filters_for_hits"),
    (71, "Options.paranoid_file_checks: %d", 0x15A, "scalar",
     "paranoid_file_checks"),
    (72, "Options.force_consistency_checks: %d", 0x15B, "scalar",
     "force_consistency_checks"),
    (73, "Options.report_bg_io_stats: %d", 0x15C, "scalar",
     "report_bg_io_stats"),
    (74, "Options.ttl: %lu", 0x160, "scalar", "ttl"),
    (75, "Options.periodic_compaction_seconds: %lu", 0x168, "scalar",
     "periodic_compaction_seconds"),
    (76, "Options.preclude_last_level_data_seconds: %lu", 0x180,
     "scalar", "preclude_last_level_data_seconds"),
    (77, "Options.preserve_internal_time_seconds: %lu", 0x188, "scalar",
     "preserve_internal_time_seconds"),
    (78, "Options.enable_blob_files: %s", 0x190, "bool",
     "enable_blob_files"),
    (79, "Options.min_blob_size: %lu", 0x198, "scalar", "min_blob_size"),
    (80, "Options.blob_file_size: %lu", 0x1A0, "scalar",
     "blob_file_size"),
    (81, "Options.blob_compression_type: %s", 0x1A8, "enumfn",
     "blob_compression_type"),
    (82, "Options.enable_blob_garbage_collection: %s", 0x1A9, "bool",
     "enable_blob_garbage_collection"),
    (83, "Options.blob_garbage_collection_age_cutoff: %f", 0x1B0,
     "scalar", "blob_garbage_collection_age_cutoff"),
    (84, "Options.blob_garbage_collection_force_threshold: %f", 0x1B8,
     "scalar", "blob_garbage_collection_force_threshold"),
    (85, "Options.blob_compaction_readahead_size: %lu", 0x1C0, "scalar",
     "blob_compaction_readahead_size"),
    (86, "Options.blob_file_starting_level: %d", 0x1C8, "scalar",
     "blob_file_starting_level"),
    (87, "Options.blob_cache: %s", 0x1D0, "slot", "blob_cache"),
    (88, "blob_cache options: %s", 0x1D0, "slot", "blob_cache_options"),
    (89, "blob_cache prepopulated: %s", 0x1E0, "scalar",
     "blob_cache_prepopulated"),
    (90, "Options.experimental_mempurge_threshold: %f", 0x28, "scalar",
     "experimental_mempurge_threshold"),
    (91, "Options.bottommost_compression: %s", 0x221, "enumfn",
     "bottommost_compression"),
    (92, "Options.compression: %s", 0x220, "enumfn", "compression"),
]

FIELD_COUNT = 93

# Null defaults for the name lines (None = dereferenced unconditionally).
NAME_NULL_DEFAULTS = {
    "merge_operator": "None",
    "compaction_filter": "None",
    "compaction_filter_factory": "None",
    "sst_partitioner_factory": "None",
    "prefix_extractor": "nullptr",
    "memtable_insert_with_hint_prefix_extractor": "nullptr",
}


def compression_type_name(value):
    """Name of a CompressionType byte, per 0x5d8b3c0."""
    return COMPRESSION_NAMES.get(value & 0xFF, "")


def bool_str(value):
    """A bool byte as the dump prints it in %s lines."""
    return "true" if value else "false"


def registry_name(table, value):
    """A registry byte, or the unknown_<n> fallback the cold blocks build."""
    name = table.get(value)
    if name is not None:
        return name
    return f"unknown_{value}"


def should_log(logger_level, message_level):
    """The 0x5fceda0 gate: emit only when the logger level is <= the
    message level.  A HEADER (5) message therefore always emits."""
    return logger_level <= message_level


def _py_fmt(fmt):
    """The same format string with C size specifiers Python's % lacks."""
    return fmt.replace("%zu", "%d").replace("%lu", "%d")


def dump_lines(opts):
    """Format the dump's lines for one ColumnFamilyOptions value.

    ``opts`` maps field keys to values (names as strings, scalars as
    numbers, bools as 0/1, vectors as lists).  Missing fields default
    to 0 / None / [].  The blob_cache lines 87-89 are skipped when
    blob_cache is None (the dump jumps to the final line).  Returns
    the lines in emission order.
    """
    out = []
    for line, fmt, _off, kind, key in FIELDS:
        if line == 10:
            levels = opts.get(key, [])
            if levels:
                for i, value in enumerate(levels):
                    out.append(_py_fmt(fmt) % (i, compression_type_name(value)))
            else:
                out.append("Options.compression: %s" %
                           compression_type_name(opts.get("compression", 0)))
            continue
        if line == 44:
            for i, value in enumerate(opts.get(key, [])):
                out.append(_py_fmt(fmt) % (i, value))
            continue
        if line == 62:
            out.append(_py_fmt(fmt) % ", ".join(opts.get(key, [])))
            continue
        if line in (87, 88, 89) and opts.get("blob_cache") is None:
            continue
        if line == 91:
            # Cold-block re-emission of line 11; only reached when the
            # byte is not 0xff.  The main-body line 11 already covers
            # the 0xff fast path, so this line is emitted exactly once
            # per dump when reached: skip here, it is line 11's value.
            continue
        if line == 92:
            # Cold-block emission of the scalar compression byte;
            # reached only when compression_per_level is empty, which
            # the line-10 branch above already emitted.
            continue
        value = opts.get(key)
        if kind == "name":
            if value is None:
                value = NAME_NULL_DEFAULTS.get(key)
            if key == "table_factory" and value == "default":
                value = "BlockBasedTable"
            if key == "sst_partitioner_factory" and value == "default":
                value = "SstPartitionerFixedPrefixFactory"
            out.append(_py_fmt(fmt) % value)
        elif kind == "bool":
            out.append(_py_fmt(fmt) % bool_str(value or 0))
        elif kind == "enumfn":
            if line == 11 and (value or 0) == 0xFF:
                out.append(_py_fmt(fmt) % "Disabled")
            else:
                out.append(_py_fmt(fmt) % compression_type_name(value or 0))
        elif kind == "enummap":
            table = (COMPACTION_STYLE_NAMES if key == "compaction_style"
                     else COMPACTION_PRI_NAMES if key == "compaction_pri"
                     else COMPACTION_STOP_STYLE_NAMES)
            out.append(_py_fmt(fmt) % registry_name(table, value or 0))
        elif kind == "slot":
            if key == "blob_cache_options":
                out.append(_py_fmt(fmt) % (opts.get(key) or ""))
            elif key == "blob_cache":
                out.append(_py_fmt(fmt) % value)
            else:
                out.append(fmt % (value or ""))
        else:  # scalar
            if key == "blob_cache_prepopulated":
                out.append(_py_fmt(fmt) % ("flush only" if (value or 0) == 1
                                  else "disabled"))
            elif fmt.endswith("%f"):
                out.append(_py_fmt(fmt) % float(value or 0))
            else:
                out.append(_py_fmt(fmt) % int(value or 0))
    return out
