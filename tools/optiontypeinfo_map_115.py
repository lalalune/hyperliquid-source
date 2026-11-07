"""Model of the node #115 DBOptions OptionTypeInfo map and the three
unknowns #4146 left open (the avoid offset mismatch, the max_open_files
offset mismatch, DBOptions+0x21b).

Pinned against work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).
The map is built by the static initializer
__static_initialization_and_destruction_0v (0x60aa2b0..0x60b1d78):
92 (key, OptionTypeInfo) entries, each a 0xd8-byte pair (0x20-byte key
string + 0xb8-byte OptionTypeInfo record) built by the pair
constructor 0x5d400f0. Offsets and flags are the immediate values the
initializer stores (movq/movl $IMM); the +0xa8 type/verification values
are NOT modelled -- they are loaded into registers the initializer does
not set in the same block, so register tracking is unreliable for them.

Groups: A = MutableDBOptions (flags 0x100, 19 entries), B = the
EnvOptions bool cluster, ImmutableDBOptions-relative (8 entries), C =
DBOptions proper (65 entries). Group B offsets are ImmutableDBOptions
offsets; the ctor packs DBOptions+0x128..0x12d and +0x148 into
+0x108..0x10e. Group C offsets are ImmutableDBOptions offsets; the
ctor packs several from different DBOptions source offsets (see
CTOR_PACK).

Corrections to #4146 (its DBOptions tail was shifted by one byte):
wal_compression is DBOptions+0x217 (not +0x218), atomic_flush +0x218,
avoid_unnecessary_blocking_io +0x219, write_dbid_to_manifest +0x21a.
DBOptions+0x21b..+0x21f is alignment padding before the 8-byte-aligned
log_readahead_size at +0x220.
"""

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
STATIC_INITIALIZER = 0x60AA2B0
STATIC_INITIALIZER_END = 0x60B1D78
IMMUTABLEDBOPTIONS_CTOR = 0x60A3B60
DBOPTIONS_CTOR = 0x60B2DB0
BUILDDBOPTIONS = 0x60C2E20
PAIR_CTOR = 0x5D400F0
RECORD_DTOR = 0x5D3F950
STRING_CTOR = 0x609FB90
OPTIONTYPEINFO_SIZE = 0xB8
PAIR_SIZE = 0xD8

# name -> (offset, flags, group). Offset and flags are the immediate
# values stored by the static initializer.
MAP = {
    "allow_os_buffer": (0x0, 0x100, "A"),
    "base_background_compactions": (0x0, 0x100, "A"),
    "max_background_jobs": (0x0, 0x100, "A"),
    "max_background_compactions": (0x4, 0x100, "A"),
    "max_subcompactions": (0x8, 0x100, "A"),
    "avoid_flush_during_shutdown": (0xc, 0x100, "A"),
    "writable_file_max_buffer_size": (0x10, 0x100, "A"),
    "delayed_write_rate": (0x18, 0x100, "A"),
    "max_total_wal_size": (0x20, 0x100, "A"),
    "delete_obsolete_files_period_micros": (0x28, 0x100, "A"),
    "stats_dump_period_sec": (0x30, 0x100, "A"),
    "stats_persist_period_sec": (0x34, 0x100, "A"),
    "stats_history_buffer_size": (0x38, 0x100, "A"),
    "max_open_files": (0x40, 0x100, "A"),
    "bytes_per_sync": (0x48, 0x100, "A"),
    "wal_bytes_per_sync": (0x50, 0x100, "A"),
    "strict_bytes_per_sync": (0x58, 0x100, "A"),
    "compaction_readahead_size": (0x60, 0x100, "A"),
    "max_background_flushes": (0x68, 0x100, "A"),
    "advise_random_on_open": (0x10e, 0x0, "B"),
    "allow_mmap_reads": (0x108, 0x0, "B"),
    "allow_fallocate": (0x10c, 0x0, "B"),
    "allow_mmap_writes": (0x109, 0x0, "B"),
    "use_direct_reads": (0x10a, 0x0, "B"),
    "use_direct_writes": (0x0, 0x0, "B"),
    "use_direct_io_for_flush_and_compaction": (0x10b, 0x0, "B"),
    "allow_2pc": (0x173, 0x0, "B"),
    "create_if_missing": (0x0, 0x0, "C"),
    "create_missing_column_families": (0x1, 0x0, "C"),
    "disableDataSync": (0x0, 0x0, "C"),
    "disable_data_sync": (0x0, 0x0, "C"),
    "enable_thread_tracking": (0x158, 0x0, "C"),
    "error_if_exists": (0x2, 0x0, "C"),
    "experimental_allow_mempurge": (0x0, 0x0, "C"),
    "experimental_mempurge_policy": (0x0, 0x0, "C"),
    "experimental_mempurge_threshold": (0x0, 0x0, "C"),
    "is_fd_close_on_exec": (0x10d, 0x0, "C"),
    "paranoid_checks": (0x3, 0x0, "C"),
    "flush_verify_memtable_count": (0x4, 0x0, "C"),
    "track_and_verify_wals_in_manifest": (0x5, 0x0, "C"),
    "verify_sst_unique_id_in_manifest": (0x6, 0x0, "C"),
    "skip_log_error_on_recovery": (0x0, 0x0, "C"),
    "skip_stats_update_on_db_open": (0x170, 0x0, "C"),
    "skip_checking_sst_file_sizes_on_db_open": (0x171, 0x0, "C"),
    "new_table_reader_for_compaction_inputs": (0x0, 0x0, "C"),
    "random_access_max_buffer_size": (0x130, 0x0, "C"),
    "use_adaptive_mutex": (0x138, 0x0, "C"),
    "use_fsync": (0x58, 0x0, "C"),
    "max_file_opening_threads": (0x44, 0x0, "C"),
    "table_cache_numshardbits": (0xe0, 0x0, "C"),
    "db_write_buffer_size": (0x110, 0x0, "C"),
    "keep_log_file_num": (0xc8, 0x0, "C"),
    "recycle_log_file_num": (0xd0, 0x0, "C"),
    "log_file_time_to_roll": (0xc0, 0x0, "C"),
    "manifest_preallocation_size": (0x100, 0x0, "C"),
    "max_log_file_size": (0xb8, 0x0, "C"),
    "db_log_dir": (0x78, 0x0, "C"),
    "wal_dir": (0x98, 0x0, "C"),
    "WAL_size_limit_MB": (0xf0, 0x0, "C"),
    "WAL_ttl_seconds": (0xe8, 0x0, "C"),
    "max_manifest_file_size": (0xd8, 0x0, "C"),
    "persist_stats_to_disk": (0x199, 0x0, "C"),
    "fail_if_options_file_error": (0x190, 0x0, "C"),
    "enable_pipelined_write": (0x159, 0x0, "C"),
    "unordered_write": (0x15a, 0x0, "C"),
    "allow_concurrent_memtable_write": (0x15b, 0x0, "C"),
    "enable_write_thread_adaptive_yield": (0x15c, 0x0, "C"),
    "write_thread_slow_yield_usec": (0x168, 0x0, "C"),
    "max_write_batch_group_size_bytes": (0xf8, 0x0, "C"),
    "write_thread_max_yield_usec": (0x160, 0x0, "C"),
    "dump_malloc_stats": (0x191, 0x0, "C"),
    "avoid_flush_during_recovery": (0x192, 0x0, "C"),
    "allow_ingest_behind": (0x193, 0x0, "C"),
    "preserve_deletes": (0x0, 0x0, "C"),
    "concurrent_prepare": (0x0, 0x0, "C"),
    "two_write_queues": (0x194, 0x0, "C"),
    "manual_wal_flush": (0x195, 0x0, "C"),
    "wal_compression": (0x196, 0x0, "C"),
    "seq_per_batch": (0x0, 0x0, "C"),
    "atomic_flush": (0x197, 0x0, "C"),
    "avoid_unnecessary_blocking_io": (0x198, 0x0, "C"),
    "write_dbid_to_manifest": (0x19a, 0x0, "C"),
    "log_readahead_size": (0x1a0, 0x0, "C"),
    "best_efforts_recovery": (0x1b8, 0x0, "C"),
    "max_bgerror_resume_count": (0x1bc, 0x0, "C"),
    "bgerror_resume_retry_interval": (0x1c0, 0x0, "C"),
    "db_host_id": (0x1d0, 0x1, "C"),
    "rate_limiter": (0x10, 0x2001, "C"),
    "rate_limiter_bytes_per_sec": (0x10, 0x2001, "C"),
    "allow_data_in_errors": (0x1c8, 0x0, "C"),
    "listeners": (0x140, 0x1, "C"),
    "enforce_single_del_contracts": (0x238, 0x0, "C"),
}

# ImmutableDBOptions ctor pack: destination slot (ImmutableDBOptions
# offset) -> DBOptions source bytes, in BYTE order (low byte first).
# Only the slots the ctor packs from a different source offset are
# listed; the rest of the struct is copied by the -0x28 shifted
# movdqu block (DBOptions+0x100..0x188 -> ImmutableDBOptions+0xd8..0x138).
CTOR_PACK = {
    0x158: (0x1C0, 0x1D0, 0x1D1, 0x1D2),
    0x15C: (0x1D3,),
    0x190: (0x210, 0x211, 0x212, 0x214),
    0x194: (0x215, 0x216),
    0x196: (0x217,),
    0x197: (0x218, 0x219, 0x138, 0x21A),
    0x108: (0x128, 0x129, 0x12A, 0x12B),
    0x10C: (0x12C, 0x12D),
    0x10E: (0x148,),
}

# BuildDBOptions (0x60c2e20): group-A option name -> MutableDBOptions
# offset the function reads (r12), stored into DBOptions (rbx).
BUILDDBOPTIONS_READS = {
    "max_background_compactions": 0x4,
    "max_subcompactions": 0x8,
    "max_total_wal_size": 0x20,
    "delete_obsolete_files_period_micros": 0x28,
    "max_open_files": 0x40,
    "bytes_per_sync": 0x48,
    "wal_bytes_per_sync": 0x50,
    "strict_bytes_per_sync": 0x58,
    "max_background_flushes": 0x68,
}

# The DBOptions tail, corrected: DBOptions offset -> field name. This
# is the source side of the ctor pack; the map side is MAP above.
# +0x21b..+0x21f is NOT a field (see is_padding).
DBOPTIONS_TAIL = {
    0x217: "wal_compression",
    0x218: "atomic_flush",
    0x219: "avoid_unnecessary_blocking_io",
    0x21A: "write_dbid_to_manifest",
}

# The +0x21b census: the five struct-field uses are all %rbx in one
# function (FDE 0x5a897e0..0x5a8a1cc) that operates on a different
# struct, not DBOptions; the other twenty are %rsp stack slots.
CENSUS_21B_STRUCT_FIELD_SITES = (
    0x5A89943, 0x5A899A2, 0x5A89FCC, 0x5A8A19D, 0x5A8A1B3,
)
CENSUS_21B_STRUCT_FIELD_FDE = (0x5A897E0, 0x5A8A1CC)
CENSUS_21B_RSP_SLOTS = 20


def lookup(name):
    """(offset, flags, group) for a map entry name, or None."""
    return MAP.get(name)


def offset_of(name):
    """The map offset for a name, or None."""
    entry = MAP.get(name)
    return entry[0] if entry else None


def names_at(offset, group=None):
    """Names whose map offset is `offset` (optionally in one group)."""
    return sorted(
        name
        for name, (off, _flags, grp) in MAP.items()
        if off == offset and (group is None or grp == group)
    )


def group_entries(group):
    """Names in one group, in initializer (block) order."""
    return [name for name, (_off, _flags, grp) in MAP.items()
            if grp == group]


def ctor_pack_source(dst_offset):
    """DBOptions source bytes the ImmutableDBOptions ctor packs into
    the destination slot `dst_offset`, or None if the ctor does not
    pack that slot from a different offset."""
    return CTOR_PACK.get(dst_offset)


def mutable_offset(name):
    """The MutableDBOptions offset BuildDBOptions reads for a group-A
    option name, or None."""
    return BUILDDBOPTIONS_READS.get(name)


def dboptions_tail_field(dboptions_offset):
    """Field name at a DBOptions tail offset, or None."""
    return DBOPTIONS_TAIL.get(dboptions_offset)


def is_padding(dboptions_offset):
    """True for DBOptions+0x21b..+0x21f: alignment padding before the
    8-byte-aligned log_readahead_size at +0x220. No DBOptions or
    ImmutableDBOptions function reads or writes these bytes; the only
    +0x21b struct-field accesses binary-wide belong to a different
    struct (see CENSUS_21B_STRUCT_FIELD_SITES)."""
    return 0x21B <= dboptions_offset <= 0x21F


def map_offset_for_dboptions_tail(dboptions_offset):
    """The map (ImmutableDBOptions) offset for a DBOptions tail byte,
    via the ctor pack, or None if the byte is padding."""
    if is_padding(dboptions_offset):
        return None
    for dst, srcs in CTOR_PACK.items():
        if dboptions_offset in srcs:
            return dst + srcs.index(dboptions_offset)
    return None
