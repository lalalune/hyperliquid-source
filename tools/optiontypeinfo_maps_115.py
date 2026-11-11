"""Model of the node #115 OptionTypeInfo maps and their consumers.

The static initializer 0x60aa2b0 builds TWO OptionTypeInfo maps (not one,
as RE-001-optiontypeinfo-mismatches-115 claimed) plus four enum-name maps:

  mutable map    0x6506dc0  19 entries  (MutableDBOptions fields)
  dboptions map  0x6506d80  81 entries  (DBOptions fields: 73 pair-ctor
                               pairs + 8 special pairs)
  enum maps      0x6506ec0  WalRecoveryMode (4 names)
                 0x6506e80  AccessHint (4 names)
                 0x6506e40  CacheTier (2 names)
                 0x6506e00  InfoLogLevel (6 names)

Each entry is (name, offset, type, verification, flags, enum_map).
Offsets are byte offsets into the struct the map serves; type and
verification are the two 32-bit halves of the record's +0xa8 qword.
The tables below are generated from
research/work-items/RE-001-optiontypeinfo-maps-115/records.json and
cross-checked against it by that packet's verify.py.

Consumers (all in the same binary, bound to the same artifact digest):
  apply   0x60bedc0  per-entry apply: verification 4 returns Status OK
                     immediately (the entry is accepted and ignored; its
                     offset is never dereferenced); otherwise the field is
                     options_base + offset and the value is parsed by the
                     record's first std::function, or by the built-in type
                     jump table at 0x9786b4 when that function is empty.
  lookup  0x60ba0b0  map lookup; unknown keys split on '.' for nested
                     lookup (e.g. TableOptions.BlockBasedTable.*).
  dump    0x60a47f0  serializes every entry of both maps (OPTIONS-file
                     writer path) via 0x6099ce0 and the serialize dispatch
                     0x60ba600 (jump table 0x978650).

The model implements apply/serialize for the built-in scalar and enum
types.  Nested-struct (types 21/22) and shared-ptr (type 26) entries
carry a custom parse std::function; the model reports them as such
instead of guessing a scalar write.  Type 13 (wal_compression) parses
through the runtime-built .bss name registry 0x6507120, whose names are
not recoverable from the static file, so the model accepts its integer
value only.
"""

MUTABLE_MAP_ADDRESS = 0x6506DC0
DBOPTIONS_MAP_ADDRESS = 0x6506D80
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)

# (name, offset, type, verification, flags, enum_map)
MUTABLE_ENTRIES = [
    ("allow_os_buffer", 0x0, 0, 4, 0x100, None),
    ("base_background_compactions", 0x0, 1, 4, 0x100, None),
    ("max_background_jobs", 0x0, 1, 0, 0x100, None),
    ("max_background_compactions", 0x4, 1, 0, 0x100, None),
    ("max_subcompactions", 0x8, 6, 0, 0x100, None),
    ("avoid_flush_during_shutdown", 0xc, 0, 0, 0x100, None),
    ("writable_file_max_buffer_size", 0x10, 8, 0, 0x100, None),
    ("delayed_write_rate", 0x18, 7, 0, 0x100, None),
    ("max_total_wal_size", 0x20, 7, 0, 0x100, None),
    ("delete_obsolete_files_period_micros", 0x28, 7, 0, 0x100, None),
    ("stats_dump_period_sec", 0x30, 4, 0, 0x100, None),
    ("stats_persist_period_sec", 0x34, 4, 0, 0x100, None),
    ("stats_history_buffer_size", 0x38, 8, 0, 0x100, None),
    ("max_open_files", 0x40, 1, 0, 0x100, None),
    ("bytes_per_sync", 0x48, 7, 0, 0x100, None),
    ("wal_bytes_per_sync", 0x50, 7, 0, 0x100, None),
    ("strict_bytes_per_sync", 0x58, 0, 0, 0x100, None),
    ("compaction_readahead_size", 0x60, 8, 0, 0x100, None),
    ("max_background_flushes", 0x68, 1, 0, 0x100, None),
]

# (name, offset, type, verification, flags, enum_map)
DBOPTIONS_ENTRIES = [
    ("advise_random_on_open", 0x10e, 0, 0, 0x0, None),
    ("allow_mmap_reads", 0x108, 0, 0, 0x0, None),
    ("allow_fallocate", 0x10c, 0, 0, 0x0, None),
    ("allow_mmap_writes", 0x109, 0, 0, 0x0, None),
    ("use_direct_reads", 0x10a, 0, 0, 0x0, None),
    ("use_direct_writes", 0x0, 0, 4, 0x0, None),
    ("use_direct_io_for_flush_and_compaction", 0x10b, 0, 0, 0x0, None),
    ("allow_2pc", 0x173, 0, 0, 0x0, None),
    ("create_if_missing", 0x0, 0, 0, 0x0, None),
    ("create_missing_column_families", 0x1, 0, 0, 0x0, None),
    ("disableDataSync", 0x0, 0, 4, 0x0, None),
    ("disable_data_sync", 0x0, 0, 4, 0x0, None),
    ("enable_thread_tracking", 0x158, 0, 0, 0x0, None),
    ("error_if_exists", 0x2, 0, 0, 0x0, None),
    ("experimental_allow_mempurge", 0x0, 0, 4, 0x0, None),
    ("experimental_mempurge_policy", 0x0, 9, 4, 0x0, None),
    ("experimental_mempurge_threshold", 0x0, 10, 4, 0x0, None),
    ("is_fd_close_on_exec", 0x10d, 0, 0, 0x0, None),
    ("paranoid_checks", 0x3, 0, 0, 0x0, None),
    ("flush_verify_memtable_count", 0x4, 0, 0, 0x0, None),
    ("track_and_verify_wals_in_manifest", 0x5, 0, 0, 0x0, None),
    ("verify_sst_unique_id_in_manifest", 0x6, 0, 0, 0x0, None),
    ("skip_log_error_on_recovery", 0x0, 0, 4, 0x0, None),
    ("skip_stats_update_on_db_open", 0x170, 0, 0, 0x0, None),
    ("skip_checking_sst_file_sizes_on_db_open", 0x171, 0, 0, 0x0, None),
    ("new_table_reader_for_compaction_inputs", 0x0, 0, 4, 0x0, None),
    ("random_access_max_buffer_size", 0x130, 8, 0, 0x0, None),
    ("use_adaptive_mutex", 0x138, 0, 0, 0x0, None),
    ("use_fsync", 0x58, 0, 0, 0x0, None),
    ("max_file_opening_threads", 0x44, 1, 0, 0x0, None),
    ("table_cache_numshardbits", 0xe0, 1, 0, 0x0, None),
    ("db_write_buffer_size", 0x110, 8, 0, 0x0, None),
    ("keep_log_file_num", 0xc8, 8, 0, 0x0, None),
    ("recycle_log_file_num", 0xd0, 8, 0, 0x0, None),
    ("log_file_time_to_roll", 0xc0, 8, 0, 0x0, None),
    ("manifest_preallocation_size", 0x100, 8, 0, 0x0, None),
    ("max_log_file_size", 0xb8, 8, 0, 0x0, None),
    ("db_log_dir", 0x78, 9, 0, 0x0, None),
    ("wal_dir", 0x98, 9, 0, 0x0, None),
    ("WAL_size_limit_MB", 0xf0, 7, 0, 0x0, None),
    ("WAL_ttl_seconds", 0xe8, 7, 0, 0x0, None),
    ("max_manifest_file_size", 0xd8, 7, 0, 0x0, None),
    ("persist_stats_to_disk", 0x199, 0, 0, 0x0, None),
    ("fail_if_options_file_error", 0x190, 0, 0, 0x0, None),
    ("enable_pipelined_write", 0x159, 0, 0, 0x0, None),
    ("unordered_write", 0x15a, 0, 0, 0x0, None),
    ("allow_concurrent_memtable_write", 0x15b, 0, 0, 0x0, None),
    ("enable_write_thread_adaptive_yield", 0x15c, 0, 0, 0x0, None),
    ("write_thread_slow_yield_usec", 0x168, 7, 0, 0x0, None),
    ("max_write_batch_group_size_bytes", 0xf8, 7, 0, 0x0, None),
    ("write_thread_max_yield_usec", 0x160, 7, 0, 0x0, None),
    ("dump_malloc_stats", 0x191, 0, 0, 0x0, None),
    ("avoid_flush_during_recovery", 0x192, 0, 0, 0x0, None),
    ("allow_ingest_behind", 0x193, 0, 0, 0x0, None),
    ("preserve_deletes", 0x0, 0, 4, 0x0, None),
    ("concurrent_prepare", 0x0, 0, 4, 0x0, None),
    ("two_write_queues", 0x194, 0, 0, 0x0, None),
    ("manual_wal_flush", 0x195, 0, 0, 0x0, None),
    ("wal_compression", 0x196, 13, 0, 0x0, None),
    ("seq_per_batch", 0x0, 0, 4, 0x0, None),
    ("atomic_flush", 0x197, 0, 0, 0x0, None),
    ("avoid_unnecessary_blocking_io", 0x198, 0, 0, 0x0, None),
    ("write_dbid_to_manifest", 0x19a, 0, 0, 0x0, None),
    ("log_readahead_size", 0x1a0, 8, 0, 0x0, None),
    ("best_efforts_recovery", 0x1b8, 0, 0, 0x0, None),
    ("max_bgerror_resume_count", 0x1bc, 1, 0, 0x0, None),
    ("bgerror_resume_retry_interval", 0x1c0, 7, 0, 0x0, None),
    ("db_host_id", 0x1d0, 9, 0, 0x1, None),
    ("rate_limiter", 0x10, 26, 4, 0x2001, None),
    ("rate_limiter_bytes_per_sec", 0x10, 26, 0, 0x2001, None),
    ("allow_data_in_errors", 0x1c8, 0, 0, 0x0, None),
    ("listeners", 0x140, 20, 2, 0x1, None),
    ("enforce_single_del_contracts", 0x238, 0, 0, 0x0, None),
    ("env", 0x8, 26, 0, 0x2001, None),
    ("info_log_level", 0x40, 18, 0, 0x0, "0x6506e00"),
    ("statistics", 0x48, 22, 0, 0x3401, None),
    ("access_hint_on_compaction_start", 0x128, 18, 0, 0x0, "0x6506e80"),
    ("wal_recovery_mode", 0x172, 18, 0, 0x0, "0x6506ec0"),
    ("wal_filter", 0x188, 22, 1, 0x1201, None),
    ("file_checksum_gen_factory", 0x1a8, 22, 3, 0x1400, None),
    ("lowest_used_cache_tier", 0x1f8, 18, 0, 0x0, "0x6506e40"),
]

ENUM_MAPS = {
    "0x6506ec0": {"kTolerateCorruptedTailRecords": 0,
                  "kAbsoluteConsistency": 1,
                  "kPointInTimeRecovery": 2,
                  "kSkipAnyCorruptedRecords": 3},
    "0x6506e80": {"NONE": 0, "NORMAL": 1, "SEQUENTIAL": 2, "WILLNEED": 3},
    "0x6506e40": {"kVolatileTier": 0, "kNonVolatileBlockTier": 1},
    "0x6506e00": {"DEBUG_LEVEL": 0, "INFO_LEVEL": 1, "WARN_LEVEL": 2,
                  "ERROR_LEVEL": 3, "FATAL_LEVEL": 4, "HEADER_LEVEL": 5},
}

# Types with a built-in scalar parse in the 0x9786b4 jump table.
_SCALAR_TYPES = {0, 1, 2, 3, 4, 6, 7, 8, 9, 10}
# Types routed to the nested-struct parse at 0x60bf1e0.
_STRUCT_TYPES = {21, 22}
# Types with a custom parse std::function and no built-in case.
_CUSTOM_TYPES = {20, 26}


def entries(map_name):
    """All entries of one map, in initializer order."""
    if map_name == "mutable":
        return list(MUTABLE_ENTRIES)
    if map_name == "dboptions":
        return list(DBOPTIONS_ENTRIES)
    raise ValueError(f"unknown map {map_name!r}")


def lookup(name):
    """(map_name, entry) for an option name, or None when unknown."""
    for entry in MUTABLE_ENTRIES:
        if entry[0] == name:
            return ("mutable", entry)
    for entry in DBOPTIONS_ENTRIES:
        if entry[0] == name:
            return ("dboptions", entry)
    return None


def offset_zero_entries():
    """The 15 offset-0 entries: (real first fields, ignored entries)."""
    real, ignored = [], []
    for map_name, table in (("mutable", MUTABLE_ENTRIES),
                            ("dboptions", DBOPTIONS_ENTRIES)):
        for entry in table:
            if entry[1] == 0:
                (real if entry[3] == 0 else ignored).append(
                    (map_name, entry))
    return real, ignored


def _parse_scalar(type_, value):
    if type_ == 0:  # bool
        if value in ("true", "True", "1"):
            return True
        if value in ("false", "False", "0"):
            return False
        raise ValueError(f"not a bool: {value!r}")
    if type_ in (1, 2, 4, 6):  # 4-byte int/uint
        v = int(value, 0)
        if type_ in (2, 4, 6) and not 0 <= v <= 0xFFFFFFFF:
            raise ValueError(f"out of uint32 range: {value!r}")
        if type_ == 1 and not -0x80000000 <= v <= 0x7FFFFFFF:
            raise ValueError(f"out of int32 range: {value!r}")
        return v
    if type_ in (3, 7, 8):  # 8-byte int/uint
        v = int(value, 0)
        if not 0 <= v <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f"out of uint64 range: {value!r}")
        return v
    if type_ == 9:  # string
        return value
    if type_ == 10:  # double
        return float(value)
    raise ValueError(f"type {type_} has no built-in scalar parse")


def apply(options, name, value):
    """Apply one name=value pair the way 0x60bedc0 does.

    ``options`` is {"mutable": {offset: value}, "dboptions": {offset: value}}.
    Returns (status, applied, note): status is "OK" or an error string,
    applied says whether a field was written, note explains custom-path
    entries.  Mirrors the binary: unknown names error, verification 4 is
    accepted and ignored, enum names resolve through the enum map, and
    struct/shared-ptr entries need their custom parse function.
    """
    found = lookup(name)
    if found is None:
        return (f"Unrecognized option: {name}", False, "unknown name")
    map_name, entry = found
    _, offset, type_, verification, _flags, enum_map = entry
    if verification == 4:
        # 0x60bedeb: cmpl $0x4,0xac(%rsi); je 0x60bf000 (Status OK).
        return ("OK", False, "verification 4: accepted and ignored")
    if type_ == 18:  # enum via the mid-helper std::functions
        names = ENUM_MAPS[enum_map]
        if value in names:
            options[map_name][offset] = names[value]
            return ("OK", True, f"enum {value}={names[value]}")
        try:
            v = int(value, 0)
        except ValueError:
            return (f"Error parsing: {name}={value}", False,
                    "unknown enum name")
        if v not in names.values():
            return (f"Error parsing: {name}={value}", False,
                    "enum value out of range")
        options[map_name][offset] = v
        return ("OK", True, f"enum value {v}")
    if type_ == 13:  # wal_compression: .bss registry, names not static
        try:
            v = int(value, 0)
        except ValueError:
            return (f"Error parsing: {name}={value}", False,
                    "type-13 names live in the runtime-built registry")
        options[map_name][offset] = v
        return ("OK", True, "type-13 integer value")
    if type_ in _STRUCT_TYPES or type_ in _CUSTOM_TYPES:
        return ("OK", False,
                f"type {type_}: custom parse std::function; "
                "not a built-in scalar write")
    try:
        parsed = _parse_scalar(type_, value)
    except ValueError as exc:
        return (f"Error parsing: {name}={value} ({exc})", False,
                "parse failed")
    options[map_name][offset] = parsed
    return ("OK", True, "scalar write")


def serialize(options, name):
    """Render one option's value the way the 0x60ba600 dispatch does."""
    found = lookup(name)
    if found is None:
        raise KeyError(name)
    map_name, entry = found
    _, offset, type_, verification, _flags, enum_map = entry
    if verification == 4:
        return None  # ignored entries have no serialized value
    value = options[map_name].get(offset)
    if value is None:
        return None
    if type_ == 0:
        return "true" if value else "false"
    if type_ == 9:
        return value
    if type_ == 10:
        return repr(value)
    if type_ == 18:
        names = {v: k for k, v in ENUM_MAPS[enum_map].items()}
        return names.get(value, str(value))
    if type_ in _STRUCT_TYPES or type_ in _CUSTOM_TYPES or type_ == 13:
        return str(value)
    return str(value)
