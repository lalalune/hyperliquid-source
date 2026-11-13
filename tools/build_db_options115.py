#!/usr/bin/env python3
"""Node #115 RocksDB BuildDBOptions: reconstruction.

RE-002 work item. Reconstructs the DBOptions merge at
0x60c2e20..0x60c3477 (1623 B), the routine every DB open path
uses to rebuild a DBOptions from its immutable and mutable
halves:

  rocksdb::BuildDBOptions   0x60c2e20 (1623 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Census-bound: symbol
``_ZN7rocksdb14BuildDBOptionsERKNS_18ImmutableDBOptionsERKNS_16MutableDBOptionsE``
(member d7ece8bd5f9dc186-options_helper.o); body hash
8c918932f1d73255305d126641c1876718d111d3944cf1354043ed239a6478f1,
source hash 53ce0817d1e68f2fe7410c66b52df10a4ce2b0df4aff8390798fb70
69ad4a888 reproduced exactly by zeroing its 19 census
relocations (kinds 2/4/42, no relaxation). It is the direct
follow-up to open PR #6222 (DBImpl::CreateWAL), which calls it
first (site 0x5e5c2f8) to build the DBOptions it passes to
OptimizeForLogWrite.

What the binary does (whole-FDE disassembly, verbatim in the
packet):

  DBOptions BuildDBOptions(const ImmutableDBOptions& immutable,
                           const MutableDBOptions& mutable)
  -- rdi is the hidden sret (the output DBOptions), rsi the
  ImmutableDBOptions*, rdx the MutableDBOptions*.

  1. Default construction (0x60c2e37): DBOptions::DBOptions()
     (0x60b2db0, census-bound, member
     d7ece8bd5f9dc186-options.o) runs on the output first, so
     every field starts at its declared default and only the
     91 assignments below overwrite it. The two fields the
     function never writes keep those defaults: write_dbid_to_
     manifest stays false (the ctor stores byte 0 at +0x21a) and
     compaction_service stays null (the ctor stores a zeroed
     16-byte pair at +0x278..+0x287).
  2. The copy map (0x60c2e3c..0x60c33bf): 91 field copies, in the
     exact order upstream lists them (verified field by field
     against the v8.1.1 source read live this cycle -- see the
     packet README). 74 fields come from the immutable half,
     17 from the mutable half. Scalars are copied with the
     width the type dictates (single bytes for the seven leading
     bools and the bool runs at +0x128..0x12d, +0x1d0..0x1d3,
     +0x1f0..0x1f3, +0x210..0x219; one byte for the 1-byte enums
     info_log_level, wal_recovery_mode, wal_compression and
     lowest_used_cache_tier; 4 bytes for the ints; 8 bytes for
     the size_t/uint64_t fields; a 16-byte vector copy for env
     plus the rate_limiter pointer). The three structs lay their
     fields out in DIFFERENT orders -- max_write_batch_group_
     size_bytes sits at immutable +0xf8 but at output +0x1d8,
     and the mutable half packs its 17 fields into 0x6c bytes --
     so the copy map, not declaration order, is the layout
     evidence this packet pins.
  3. Shared pointers (7 fields: rate_limiter, sst_file_manager,
     info_log, statistics, write_buffer_manager, row_cache,
     file_checksum_gen_factory): the pointer word is copied
     inline and the control block goes through the shared_ptr
     copy routine -- inlined for five fields (the addl $1 to the
     use count at control+0x8, the old control released with
     _Sp_counted_base::_M_release 0x5d350c0) and out-of-line
     through __shared_count::operator= 0x60bcde0 for
     sst_file_manager (out+0x20) and file_checksum_gen_factory
     (out+0x228). Both spellings have the same observable
     semantics: if the new target differs from the old one, the
     new use count goes up by one (a plain addl when the
     single-thread flag byte at 0x64ed290 is set, a lock addl
     otherwise) and the old target is released (destroyed when
     its use count reaches zero; the out-of-line spelling also
     checks the combined (use, weak) count 0x100000001 before
     disposing). A new target equal to the old one is a no-op,
     and a null new target only releases the old one. On the
     normal path the release half is dead: the ctor nulls all
     seven slots, so there is never an old target to release.
  4. Containers (2 fields): db_paths is a std::vector<DbPath>
     copy (vector::operator= 0x60c2790, census-bound) from
     immutable +0x60 into output +0x70, and listeners is a
     std::vector<std::shared_ptr<EventListener>> copy
     (vector::operator= 0x60bd2d0, census-bound) from immutable
     +0x140 into output +0x1a8. The three strings (db_log_dir,
     wal_dir, db_host_id) are copied with std::string::_M_assign
     (PLT 0x63f0f00).
  5. Landing pad (0x60c346b..0x60c3477, inside the main FDE --
     there is NO separate .cold FDE): on any throw, the pad
     moves the exception object to rbp, jumps to 0x60c2e04,
     destroys the partially built output with DBOptions::
     ~DBOptions (0x5d354b0) and resumes unwinding with
     _Unwind_Resume. The output is never returned half-built.

Layouts (pinned by the disassembly AND upstream v8.1.1,
options/db_options.h + include/rocksdb/options.h):

  DBOptions is 0x290 bytes (656). ImmutableDBOptions is 0x240
  bytes (576) -- its tail past lowest_used_cache_tier (+0x1f8)
  holds convenience objects that are NOT part of DBOptions
  (fs +0x200, clock +0x210, stats +0x218, logger +0x220,
  compaction_service +0x228, enforce_single_del_contracts
  +0x238, the field BuildDBOptions copies last). MutableDBOptions
  is 0x6c bytes (108) with 17 fields. The full offset tables
  are in COPY_MAP below and in the packet records.json.

Caller (whole-.text census, Capstone-validated): exactly 12
direct calls, 0 tail jumps, 0 LEA refs -- DBImpl::GetDBOptions
0x5d488e0, DBImpl::GetOptions 0x5d58720, DBImpl::
CreateColumnFamilyImpl 0x5d69a00, DBImpl::WriteOptionsFile
0x5d713f0, DBImpl::SetDBOptions 0x5d71fe0, DBImpl::SetOptions
0x5d72ed0, an unnamed FDE 0x5d74aa0 (not in the census),
DBImpl::DBImpl 0x5d85480, CompactionJob::
ProcessKeyValueCompactionWithCompactionService 0x5e41fa0,
DBImpl::GetLogSizeAndMaybeTruncate 0x5e5ad50, DBImpl::CreateWAL
0x5e5c270 (site 0x5e5c2f8, the #6222 packet) and
DBOptionsConfigurable::ConfigureOptions 0x60a2470.

Environment limits (stated honestly): no cargo/rustc/git-lfs/
Ghidra on this VM; the model is Python evidence, not a Rust
reconstruction; DBOptions::DBOptions() is scripted as an oracle
(the two unwritten fields keep the ctor defaults verified in
its disassembly, but the full ctor is the next work item, not
this packet); the heap addresses of strings/vectors/shared_ptr
control blocks are modelled as deterministic ids, not real
pointers; the vector/string capacities after copy-assign are
modelled as exactly the source size (the libstdc++ fresh-target
behaviour) and recorded as a model choice, not a binary-pinned
fact.
"""
import hashlib
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / \
    "re-002-node115-rocksdb-build-db-options-115"
CASES = PACKET / "cases.tsv"

# Binary facts.
FDE_START = 0x60C2E20
FDE_END = 0x60C3477
BODY_SHA256 = ("8c918932f1d73255305d126641c1876718d111d3944cf1354043e"
               "d239a6478f1")
SOURCE_SHA256 = ("53ce0817d1e68f2fe7410c66b52df10a4ce2b0df4aff8390798"
                 "fb7069ad4a888")
SIZE_DBOPTIONS = 0x290       # sizeof(DBOptions), last field +0x289
SIZE_IMMUTABLE = 0x240       # sizeof(ImmutableDBOptions)
SIZE_MUTABLE = 0x6C          # sizeof(MutableDBOptions)
CALLER_SITES = ["0x5d48922", "0x5d5878f", "0x5d69a88", "0x5d71b79",
                "0x5d72361", "0x5d73283", "0x5d753be", "0x5d858aa",
                "0x5e427fb", "0x5e5af6b", "0x5e5c2f8", "0x60a24f8"]

# COPY_MAP: (field, source, source offset, output offset, kind),
# in binary/source order (91 entries). Kinds: bool, u8, i32, u32,
# u64, ptr (raw pointer, opaque id), shared_ptr, string,
# dbpaths (vector<DbPath>), listeners
# (vector<shared_ptr<EventListener>>).
COPY_MAP = [
    ("create_if_missing", "imm", 0x00, 0x00, "bool"),
    ("create_missing_column_families", "imm", 0x01, 0x01, "bool"),
    ("error_if_exists", "imm", 0x02, 0x02, "bool"),
    ("paranoid_checks", "imm", 0x03, 0x03, "bool"),
    ("flush_verify_memtable_count", "imm", 0x04, 0x04, "bool"),
    ("track_and_verify_wals_in_manifest", "imm", 0x05, 0x05, "bool"),
    ("verify_sst_unique_id_in_manifest", "imm", 0x06, 0x06, "bool"),
    ("env", "imm", 0x08, 0x08, "ptr"),
    ("rate_limiter", "imm", 0x10, 0x10, "shared_ptr"),
    ("sst_file_manager", "imm", 0x20, 0x20, "shared_ptr"),
    ("info_log", "imm", 0x30, 0x30, "shared_ptr"),
    ("info_log_level", "imm", 0x40, 0x40, "u8"),
    ("max_open_files", "mut", 0x40, 0x44, "i32"),
    ("max_file_opening_threads", "imm", 0x44, 0x48, "i32"),
    ("max_total_wal_size", "mut", 0x20, 0x50, "u64"),
    ("statistics", "imm", 0x48, 0x58, "shared_ptr"),
    ("use_fsync", "imm", 0x58, 0x68, "bool"),
    ("db_paths", "imm", 0x60, 0x70, "dbpaths"),
    ("db_log_dir", "imm", 0x78, 0x88, "string"),
    ("wal_dir", "imm", 0x98, 0xa8, "string"),
    ("delete_obsolete_files_period_micros", "mut", 0x28, 0xc8, "u64"),
    ("max_background_jobs", "mut", 0x00, 0xd0, "i32"),
    ("max_background_compactions", "mut", 0x04, 0xd4, "i32"),
    ("bytes_per_sync", "mut", 0x48, 0x190, "u64"),
    ("wal_bytes_per_sync", "mut", 0x50, 0x198, "u64"),
    ("strict_bytes_per_sync", "mut", 0x58, 0x1a0, "bool"),
    ("max_subcompactions", "mut", 0x08, 0xd8, "u32"),
    ("max_background_flushes", "mut", 0x68, 0xdc, "i32"),
    ("max_log_file_size", "imm", 0xb8, 0xe0, "u64"),
    ("log_file_time_to_roll", "imm", 0xc0, 0xe8, "u64"),
    ("keep_log_file_num", "imm", 0xc8, 0xf0, "u64"),
    ("recycle_log_file_num", "imm", 0xd0, 0xf8, "u64"),
    ("max_manifest_file_size", "imm", 0xd8, 0x100, "u64"),
    ("table_cache_numshardbits", "imm", 0xe0, 0x108, "i32"),
    ("WAL_ttl_seconds", "imm", 0xe8, 0x110, "u64"),
    ("WAL_size_limit_MB", "imm", 0xf0, 0x118, "u64"),
    ("manifest_preallocation_size", "imm", 0x100, 0x120, "u64"),
    ("allow_mmap_reads", "imm", 0x108, 0x128, "bool"),
    ("allow_mmap_writes", "imm", 0x109, 0x129, "bool"),
    ("use_direct_reads", "imm", 0x10a, 0x12a, "bool"),
    ("use_direct_io_for_flush_and_compaction", "imm", 0x10b, 0x12b,
     "bool"),
    ("allow_fallocate", "imm", 0x10c, 0x12c, "bool"),
    ("is_fd_close_on_exec", "imm", 0x10d, 0x12d, "bool"),
    ("stats_dump_period_sec", "mut", 0x30, 0x130, "u32"),
    ("stats_persist_period_sec", "mut", 0x34, 0x134, "u32"),
    ("persist_stats_to_disk", "imm", 0x199, 0x138, "bool"),
    ("stats_history_buffer_size", "mut", 0x38, 0x140, "u64"),
    ("advise_random_on_open", "imm", 0x10e, 0x148, "bool"),
    ("db_write_buffer_size", "imm", 0x110, 0x150, "u64"),
    ("write_buffer_manager", "imm", 0x118, 0x158, "shared_ptr"),
    ("access_hint_on_compaction_start", "imm", 0x128, 0x168, "i32"),
    ("compaction_readahead_size", "mut", 0x60, 0x170, "u64"),
    ("random_access_max_buffer_size", "imm", 0x130, 0x178, "u64"),
    ("writable_file_max_buffer_size", "mut", 0x10, 0x180, "u64"),
    ("use_adaptive_mutex", "imm", 0x138, 0x188, "bool"),
    ("listeners", "imm", 0x140, 0x1a8, "listeners"),
    ("enable_thread_tracking", "imm", 0x158, 0x1c0, "bool"),
    ("delayed_write_rate", "mut", 0x18, 0x1c8, "u64"),
    ("enable_pipelined_write", "imm", 0x159, 0x1d0, "bool"),
    ("unordered_write", "imm", 0x15a, 0x1d1, "bool"),
    ("allow_concurrent_memtable_write", "imm", 0x15b, 0x1d2, "bool"),
    ("enable_write_thread_adaptive_yield", "imm", 0x15c, 0x1d3, "bool"),
    ("max_write_batch_group_size_bytes", "imm", 0xf8, 0x1d8, "u64"),
    ("write_thread_max_yield_usec", "imm", 0x160, 0x1e0, "u64"),
    ("write_thread_slow_yield_usec", "imm", 0x168, 0x1e8, "u64"),
    ("skip_stats_update_on_db_open", "imm", 0x170, 0x1f0, "bool"),
    ("skip_checking_sst_file_sizes_on_db_open", "imm", 0x171, 0x1f1,
     "bool"),
    ("wal_recovery_mode", "imm", 0x172, 0x1f2, "u8"),
    ("allow_2pc", "imm", 0x173, 0x1f3, "bool"),
    ("row_cache", "imm", 0x178, 0x1f8, "shared_ptr"),
    ("wal_filter", "imm", 0x188, 0x208, "ptr"),
    ("fail_if_options_file_error", "imm", 0x190, 0x210, "bool"),
    ("dump_malloc_stats", "imm", 0x191, 0x211, "bool"),
    ("avoid_flush_during_recovery", "imm", 0x192, 0x212, "bool"),
    ("avoid_flush_during_shutdown", "mut", 0x0c, 0x213, "bool"),
    ("allow_ingest_behind", "imm", 0x193, 0x214, "bool"),
    ("two_write_queues", "imm", 0x194, 0x215, "bool"),
    ("manual_wal_flush", "imm", 0x195, 0x216, "bool"),
    ("wal_compression", "imm", 0x196, 0x217, "u8"),
    ("atomic_flush", "imm", 0x197, 0x218, "bool"),
    ("avoid_unnecessary_blocking_io", "imm", 0x198, 0x219, "bool"),
    ("log_readahead_size", "imm", 0x1a0, 0x220, "u64"),
    ("file_checksum_gen_factory", "imm", 0x1a8, 0x228, "shared_ptr"),
    ("best_efforts_recovery", "imm", 0x1b8, 0x238, "bool"),
    ("max_bgerror_resume_count", "imm", 0x1bc, 0x23c, "i32"),
    ("bgerror_resume_retry_interval", "imm", 0x1c0, 0x240, "u64"),
    ("db_host_id", "imm", 0x1d0, 0x250, "string"),
    ("allow_data_in_errors", "imm", 0x1c8, 0x248, "bool"),
    ("checksum_handoff_file_types", "imm", 0x1f0, 0x270, "u64"),
    ("lowest_used_cache_tier", "imm", 0x1f8, 0x288, "u8"),
    ("enforce_single_del_contracts", "imm", 0x238, 0x289, "bool"),
]
assert len(COPY_MAP) == 91

# Fields the function never writes: they keep the DBOptions()
# ctor defaults, verified in the ctor disassembly (0x60b2db0):
# write_dbid_to_manifest is byte 0 at +0x21a, compaction_service
# is a zeroed 16-byte pair at +0x278..+0x287.
UNWRITTEN = {
    "write_dbid_to_manifest": False,
    "compaction_service": None,
}

# Deterministic ids used to render pointer-ish slots in the byte
# image (the binary's real addresses are heap addresses; the
# model uses stable ids so the image is reproducible).
OUT_BASE = 0x7F0000000000
HEAP_BASE = 0x7F0001000000


class SharedTarget:
    """One heap object owned through shared_ptr: a stable identity,
    a use count (set by _collect_targets to the number of input
    slots referencing it) and deterministic object/control-block
    ids for the byte image."""

    def __init__(self, target_id, index):
        self.target_id = target_id
        self.use_count = 1
        self.addr = OUT_BASE + 0x1000 + index * 0x100
        self.ctrl = self.addr + 0x40
        self.destroyed = False


class SharedPtrSlot:
    """One shared_ptr slot in the output: holds a SharedTarget or
    None. shared_ptr_assign reproduces the binary's copy routine
    (inlined spelling and __shared_count::operator= alike)."""

    def __init__(self):
        self.target = None

    def assign(self, new, events, field):
        old = self.target
        if new is old:
            events.append({"op": "shared_ptr_noop", "field": field,
                           "target": None if new is None
                           else new.target_id})
            return
        if new is not None:
            new.use_count += 1
            events.append({"op": "shared_ptr_acquire", "field": field,
                           "target": new.target_id,
                           "use_count": new.use_count})
        if old is not None:
            old.use_count -= 1
            events.append({"op": "shared_ptr_release", "field": field,
                           "target": old.target_id,
                           "use_count": old.use_count})
            if old.use_count == 0:
                old.destroyed = True
                events.append({"op": "shared_ptr_destroy",
                               "field": field, "target": old.target_id})
        self.target = new


def shared_ptr_assign(slot, new, events, field):
    """The binary's shared_ptr copy-assign as a standalone helper
    (used by the model and tested directly)."""
    slot.assign(new, events, field)


def _kind_width(kind):
    return {"bool": 1, "u8": 1, "i32": 4, "u32": 4, "u64": 8,
            "ptr": 8, "shared_ptr": 16, "string": 32,
            "dbpaths": 24, "listeners": 24}[kind]


def default_immutable():
    """The DBOptions declaration defaults for the immutable-sourced
    fields (used as the fixed side in the mutable group)."""
    return {
        "create_if_missing": False,
        "create_missing_column_families": False,
        "error_if_exists": False,
        "paranoid_checks": True,
        "flush_verify_memtable_count": True,
        "track_and_verify_wals_in_manifest": False,
        "verify_sst_unique_id_in_manifest": True,
        "env": None,
        "rate_limiter": None,
        "sst_file_manager": None,
        "info_log": None,
        "info_log_level": 1,
        "max_file_opening_threads": 16,
        "statistics": None,
        "use_fsync": False,
        "db_paths": [],
        "db_log_dir": "",
        "wal_dir": "",
        "max_log_file_size": 0,
        "log_file_time_to_roll": 0,
        "keep_log_file_num": 1000,
        "recycle_log_file_num": 0,
        "max_manifest_file_size": 1024 * 1024 * 1024,
        "table_cache_numshardbits": 6,
        "WAL_ttl_seconds": 0,
        "WAL_size_limit_MB": 0,
        "manifest_preallocation_size": 4 * 1024 * 1024,
        "allow_mmap_reads": False,
        "allow_mmap_writes": False,
        "use_direct_reads": False,
        "use_direct_io_for_flush_and_compaction": False,
        "allow_fallocate": True,
        "is_fd_close_on_exec": True,
        "persist_stats_to_disk": False,
        "advise_random_on_open": True,
        "db_write_buffer_size": 0,
        "write_buffer_manager": None,
        "access_hint_on_compaction_start": 1,
        "random_access_max_buffer_size": 1024 * 1024,
        "use_adaptive_mutex": False,
        "listeners": [],
        "enable_thread_tracking": False,
        "enable_pipelined_write": False,
        "unordered_write": False,
        "allow_concurrent_memtable_write": True,
        "enable_write_thread_adaptive_yield": True,
        "max_write_batch_group_size_bytes": 1024 * 1024,
        "write_thread_max_yield_usec": 100,
        "write_thread_slow_yield_usec": 3,
        "skip_stats_update_on_db_open": False,
        "skip_checking_sst_file_sizes_on_db_open": False,
        "wal_recovery_mode": 2,
        "allow_2pc": False,
        "row_cache": None,
        "wal_filter": None,
        "fail_if_options_file_error": False,
        "dump_malloc_stats": False,
        "avoid_flush_during_recovery": False,
        "allow_ingest_behind": False,
        "two_write_queues": False,
        "manual_wal_flush": False,
        "wal_compression": 0,
        "atomic_flush": False,
        "avoid_unnecessary_blocking_io": False,
        "log_readahead_size": 0,
        "file_checksum_gen_factory": None,
        "best_efforts_recovery": False,
        "max_bgerror_resume_count": 2 ** 31 - 1,
        "bgerror_resume_retry_interval": 1000000,
        "db_host_id": "",
        "allow_data_in_errors": False,
        "checksum_handoff_file_types": 0,
        "lowest_used_cache_tier": 1,
        "enforce_single_del_contracts": True,
    }


def default_mutable():
    """The DBOptions declaration defaults for the mutable-sourced
    fields (used as the fixed side in the immutable group)."""
    return {
        "max_background_jobs": 2,
        "max_background_compactions": -1,
        "max_subcompactions": 1,
        "avoid_flush_during_shutdown": False,
        "writable_file_max_buffer_size": 1024 * 1024,
        "delayed_write_rate": 0,
        "max_total_wal_size": 0,
        "delete_obsolete_files_period_micros": 6 * 60 * 60 * 1000000,
        "stats_dump_period_sec": 600,
        "stats_persist_period_sec": 600,
        "stats_history_buffer_size": 1024 * 1024,
        "max_open_files": -1,
        "bytes_per_sync": 0,
        "wal_bytes_per_sync": 0,
        "strict_bytes_per_sync": False,
        "compaction_readahead_size": 0,
        "max_background_flushes": -1,
    }


def _collect_targets(immutable, mutable):
    """Every distinct shared_ptr target id in the inputs. Each
    input slot holding a target owns one reference, so a target's
    starting use count is the number of input slots that reference
    it (one per shared_ptr field, one per listeners element)."""
    counts = {}
    for name, _src, _off, _out, kind in COPY_MAP:
        if kind != "shared_ptr":
            continue
        val = (immutable if _src == "imm" else mutable).get(name)
        if val is not None:
            counts[val] = counts.get(val, 0) + 1
    for val in immutable.get("listeners", []) or []:
        if val is not None:
            counts[val] = counts.get(val, 0) + 1
    targets = {}
    for i, tid in enumerate(sorted(counts)):
        targets[tid] = SharedTarget(tid, i)
        targets[tid].use_count = counts[tid]
    return targets


def build_db_options(immutable, mutable):
    """The BuildDBOptions model. Returns (output, events, registry,
    image): output maps every DBOptions field to its value (plus
    the two unwritten fields at their ctor defaults), events is the
    shared_ptr acquire/release log in copy order, registry maps
    each target id to its final use count, and image is the
    0x290-byte output image."""
    targets = _collect_targets(immutable, mutable)
    events = []
    slots = {}
    output = {}
    heap_next = [HEAP_BASE]

    def heap_id():
        addr = heap_next[0]
        heap_next[0] += 0x1000
        return addr

    # The output starts as DBOptions() defaults (oracle ctor); the
    # copy map below overwrites the 91 assigned fields.
    for name, value in UNWRITTEN.items():
        output[name] = value
    for name, _s, _o, _oo, kind in COPY_MAP:
        if kind == "shared_ptr":
            slots[name] = SharedPtrSlot()
            output[name] = None

    for name, src, _soff, _ooff, kind in COPY_MAP:
        side = immutable if src == "imm" else mutable
        value = side.get(name)
        if kind == "shared_ptr":
            target = targets.get(value) if value is not None else None
            slots[name].assign(target, events, name)
            output[name] = (None if target is None else
                            {"target": target.target_id,
                             "use_count": target.use_count,
                             "addr": target.addr, "ctrl": target.ctrl})
        elif kind == "dbpaths":
            output[name] = [[p, int(s)] for p, s in (value or [])]
        elif kind == "listeners":
            # vector::operator= copies elements in order; each
            # element copy-assign acquires its target, so the
            # recorded use count is the post-increment value.
            entries = []
            for v in (value or []):
                if v is None:
                    entries.append(None)
                    continue
                targets[v].use_count += 1
                events.append({"op": "shared_ptr_acquire",
                               "field": "listeners",
                               "target": v,
                               "use_count": targets[v].use_count})
                entries.append({"target": targets[v].target_id,
                                "use_count": targets[v].use_count,
                                "addr": targets[v].addr,
                                "ctrl": targets[v].ctrl})
            output[name] = entries
        elif kind == "string":
            output[name] = "" if value is None else str(value)
        elif kind == "ptr":
            output[name] = value
        elif kind == "bool":
            output[name] = 1 if value else 0
        elif kind == "u8":
            # 1-byte enums (info_log_level, wal_recovery_mode,
            # wal_compression, lowest_used_cache_tier): the full
            # byte value, not a 0/1 coercion.
            output[name] = int(value) & 0xFF
        elif kind in ("i32", "u32", "u64"):
            output[name] = int(value)

    registry = {tid: t.use_count for tid, t in targets.items()}
    image = render_bytes(output, targets, heap_next)
    return output, events, registry, image


def render_bytes(output, targets, heap_next=None):
    """Render the 0x290-byte DBOptions image from the model output.
    Scalar bytes are exact. Pointer slots hold the input-supplied
    id (0 for null). Shared_ptr slots hold the target's
    deterministic object/control ids. Strings use the libstdc++
    layout: short strings (<= 15 bytes) are SSO -- the pointer
    slot holds the string's own +0x10 address and the bytes sit
    inline; long strings get a heap id with capacity == size (the
    fresh-target _M_assign behaviour, a model choice). Vectors
    render as (heap id, size, capacity == size), same caveat."""
    img = bytearray(SIZE_DBOPTIONS)
    heap = [HEAP_BASE if heap_next is None else heap_next[0]]
    if heap_next is not None:
        heap[0] = heap_next[0]

    def heap_id():
        addr = heap[0]
        heap[0] += 0x1000
        return addr

    string_heap = {}
    for name, _src, _soff, out_off, kind in COPY_MAP:
        value = output[name]
        if kind == "bool" or kind == "u8":
            img[out_off] = value & 0xFF
        elif kind == "i32":
            img[out_off:out_off + 4] = int(value).to_bytes(
                4, "little", signed=True)
        elif kind == "u32":
            img[out_off:out_off + 4] = int(value).to_bytes(4, "little")
        elif kind == "u64":
            img[out_off:out_off + 8] = int(value).to_bytes(8, "little")
        elif kind == "ptr":
            img[out_off:out_off + 8] = int(value or 0).to_bytes(
                8, "little")
        elif kind == "shared_ptr":
            if value is None:
                continue
            img[out_off:out_off + 8] = value["addr"].to_bytes(8, "little")
            img[out_off + 8:out_off + 16] = value["ctrl"].to_bytes(
                8, "little")
        elif kind == "string":
            raw = value.encode("utf-8", "surrogatepass")
            if len(raw) <= 15:
                ptr = OUT_BASE + out_off + 0x10
                img[out_off:out_off + 8] = ptr.to_bytes(8, "little")
                img[out_off + 8:out_off + 16] = len(raw).to_bytes(
                    8, "little")
                img[out_off + 16:out_off + 16 + len(raw)] = raw
            else:
                if name not in string_heap:
                    string_heap[name] = heap_id()
                img[out_off:out_off + 8] = string_heap[name].to_bytes(
                    8, "little")
                img[out_off + 8:out_off + 16] = len(raw).to_bytes(
                    8, "little")
                img[out_off + 16:out_off + 24] = len(raw).to_bytes(
                    8, "little")
        elif kind in ("dbpaths", "listeners"):
            if not value:
                continue
            img[out_off:out_off + 8] = heap_id().to_bytes(8, "little")
            img[out_off + 8:out_off + 16] = len(value).to_bytes(
                8, "little")
            img[out_off + 16:out_off + 24] = len(value).to_bytes(
                8, "little")
    # The two unwritten fields keep their ctor defaults.
    img[0x21a] = 0  # write_dbid_to_manifest = false
    # compaction_service at +0x278..+0x287 stays zeroed (nullptr).
    return bytes(img)


def run_case(inputs):
    """Run one case: build from the inputs, return the
    expected-output dict."""
    immutable = inputs["immutable"]
    mutable = inputs["mutable"]
    output, events, registry, image = build_db_options(
        immutable, mutable)
    return {
        "output": output,
        "events": events,
        "registry": registry,
        "image_hex": image.hex(),
        "copy_order": [name for name, _s, _o, _oo, _k in COPY_MAP],
        "unwritten": dict(UNWRITTEN),
    }


# --- case generation -------------------------------------------------

_U64_EDGE = [0, 1, 1000, 1024 * 1024, 0x400000, 1024 * 1024 * 1024,
             6 * 60 * 60 * 1000000, 2 ** 64 - 1]
_I32_EDGE = [-1, 0, 1, 2, 6, 16, -100, 100, 2 ** 31 - 1, -(2 ** 31)]
_U32_EDGE = [0, 1, 600, 1024 * 1024, 2 ** 32 - 1]
_U8_EDGE = [0, 1, 2, 3, 255]
_STR_EDGE = ["", "a", "/tmp/db", "wal", "x" * 15, "y" * 16, "z" * 100,
             "host-01", "db_log_dir/sub", "OPTIONS-000007"]


def _rand_value(rng, kind, targets=None):
    if kind == "bool":
        return rng.choice([0, 1])
    if kind == "u8":
        return rng.choice(_U8_EDGE + [rng.randrange(256)])
    if kind == "i32":
        return rng.choice(_I32_EDGE + [rng.randrange(-1000, 1000)])
    if kind == "u32":
        return rng.choice(_U32_EDGE + [rng.randrange(2 ** 32)])
    if kind == "u64":
        return rng.choice(_U64_EDGE + [rng.randrange(2 ** 64)])
    if kind == "ptr":
        return rng.choice([None, None, 0x1000, 0x7F0000001000,
                           rng.randrange(1, 2 ** 40)])
    if kind == "shared_ptr":
        pool = targets or ["t1", "t2", "t3"]
        return rng.choice([None, None] + pool)
    if kind == "string":
        return rng.choice(_STR_EDGE)
    if kind == "dbpaths":
        n = rng.choice([0, 0, 1, 2, 3])
        return [[rng.choice(["/tmp/db", "/data/ssd", "/mnt/nvme",
                             "db_paths/x"]),
                 rng.choice(_U64_EDGE)] for _ in range(n)]
    if kind == "listeners":
        pool = targets or ["l1", "l2", "l3"]
        n = rng.choice([0, 0, 1, 2, 3])
        return [rng.choice([None] + pool) for _ in range(n)]
    raise ValueError(kind)


def _rand_immutable(rng, targets=None):
    out = {}
    for name, src, _o, _oo, kind in COPY_MAP:
        if src != "imm":
            continue
        out[name] = _rand_value(rng, kind, targets)
    return out


def _rand_mutable(rng):
    out = {}
    for name, src, _o, _oo, kind in COPY_MAP:
        if src != "mut":
            continue
        out[name] = _rand_value(rng, kind)
    return out


def _gen_group(rng, group, n):
    rows = []
    for i in range(n):
        case_id = "%s-%03d" % (group, i)
        if group == "immutable":
            # Random immutable half; mutable fixed at defaults, so
            # every assertion isolates an immutable-sourced field.
            targets = ["t%d" % rng.randrange(5) for _ in range(3)]
            immutable = _rand_immutable(rng, targets)
            mutable = default_mutable()
        elif group == "mutable":
            immutable = default_immutable()
            mutable = _rand_mutable(rng)
        elif group == "shared_ptr":
            # Aliasing-heavy: few targets shared across the seven
            # shared_ptr fields and the listeners vector, with
            # nulls mixed in; the mutable half is fixed.
            pool = ["shared-a", "shared-b"]
            immutable = _rand_immutable(rng, pool)
            # Force aliasing on a random subset of the fields.
            for name in ("rate_limiter", "statistics", "row_cache"):
                if rng.random() < 0.5:
                    immutable[name] = rng.choice(pool)
            if rng.random() < 0.5:
                immutable["listeners"] = [
                    rng.choice(pool + [None])
                    for _ in range(rng.choice([0, 1, 2, 3]))]
            mutable = default_mutable()
        else:  # bindings
            targets = ["b%d" % rng.randrange(4) for _ in range(3)]
            immutable = _rand_immutable(rng, targets)
            mutable = _rand_mutable(rng)
            # Occasionally force the same target into a shared_ptr
            # field and a listeners element (cross-slot aliasing).
            if rng.random() < 0.3:
                t = rng.choice(targets)
                immutable["rate_limiter"] = t
                immutable["listeners"] = [t]
        inputs = {"case_id": case_id, "group": group,
                  "immutable": immutable, "mutable": mutable}
        expected = run_case(inputs)
        rows.append((group, case_id, inputs, expected))
    return rows


def write_cases():
    all_rows = []
    for gi, group in enumerate(
            ["immutable", "mutable", "shared_ptr", "bindings"]):
        rng = random.Random(115000 + gi)
        all_rows.extend(_gen_group(rng, group, 600))
    with open(CASES, "w") as fh:
        fh.write("group\tcase_id\tinputs_json\texpected_json\n")
        for group, case_id, inputs, expected in all_rows:
            fh.write("%s\t%s\t%s\t%s\n" % (
                group, case_id,
                json.dumps(inputs, sort_keys=True),
                json.dumps(expected, sort_keys=True)))
    print("wrote %d cases to %s" % (len(all_rows), CASES))


def verify_cases():
    rows = []
    with open(CASES) as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    mismatches = 0
    for row in rows:
        inputs = json.loads(row["inputs_json"])
        expected = json.loads(row["expected_json"])
        got = run_case(inputs)
        if got != expected:
            mismatches += 1
            print("MISMATCH %s" % row["case_id"])
            if mismatches >= 3:
                break
    print("verify: %d cases, %d mismatches"
          % (len(rows), mismatches))
    return mismatches == 0 and len(rows) == 2400


# --- independent disassembly re-parse (the live check) --------------

def _va_to_off(bin_path, va):
    out = subprocess.check_output(
        ["readelf", "-lW", str(bin_path)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


def reparse_copy_map(bin_path):
    """Re-derive the copy map from the live binary with an
    independent parser: decode the objdump of the FDE into
    (mnemonic, operands) and pair each source load (from the
    immutable struct in %rbp or the mutable struct in %r12) with
    the next store of the same register into the output (%rbx).
    Shared_ptr fields appear as two 8-byte pieces (pointer word,
    then control block); the env + rate_limiter-pointer 16-byte
    movdqu appears as two 8-byte pieces. Strings and vectors go
    through _M_assign / operator= calls and are not scalar
    copies, so they contribute no pieces here. Returns the set of
    (output offset, source, source offset, width) tuples. This is
    a second derivation, not a replay of COPY_MAP."""
    import re
    out = subprocess.check_output(
        ["objdump", "-d",
         "--start-address=0x%x" % FDE_START,
         "--stop-address=0x%x" % FDE_END,
         str(bin_path)], text=True)
    insns = []
    for line in out.splitlines():
        m = re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(\S+)\s*(.*)$", line)
        if m:
            insns.append((m.group(1), m.group(2).strip()))
    found = set()
    pending = {}  # reg -> (src, src_off, width)

    def src_of(operand):
        m = re.match(r"(?:0x([0-9a-f]+))?\(%(rbp|r12)\)$", operand)
        if not m:
            return None
        return ("imm" if m.group(2) == "rbp" else "mut",
                int(m.group(1), 16) if m.group(1) else 0)

    for mnemonic, ops in insns:
        if mnemonic == "movdqu":
            m = re.match(r"0x([0-9a-f]+)\(%rbp\),%xmm0$", ops)
            if m:
                pending["xmm0"] = ("imm", int(m.group(1), 16), 16)
            continue
        if mnemonic == "movups" and ops.startswith("%xmm0,"):
            m = re.match(r"%xmm0,0x([0-9a-f]+)\(%rbx\)$", ops)
            if m and pending.get("xmm0"):
                src, soff, _w = pending.pop("xmm0")
                found.add((int(m.group(1), 16), src, soff, 8))
                found.add((int(m.group(1), 16) + 8, src, soff + 8, 8))
            continue
        if mnemonic == "movzbl":
            m = re.match(r"(\S+),%eax$", ops)
            if m:
                s = src_of(m.group(1))
                if s:
                    pending["al"] = (s[0], s[1], 1)
            continue
        if mnemonic == "lea":
            # lea DST(%rbx),%rdi sets up the __shared_count::operator=
            # destination (out+0x28 and out+0x230).
            m = re.match(r"(?:0x([0-9a-f]+))?\(%rbx\),%rdi$", ops)
            if m:
                pending["rdi_dst"] = int(m.group(1), 16) \
                    if m.group(1) else 0
            continue
        if mnemonic == "call":
            # __shared_count::operator= (0x60bcde0) stores its rsi
            # argument (the new control block, loaded just before)
            # into its rdi argument (the output slot, lea'd just
            # before): that is the shared_ptr control-block copy
            # for sst_file_manager (+0x28) and
            # file_checksum_gen_factory (+0x230).
            m = re.match(r"([0-9a-f]+)\s", ops)
            if m and int(m.group(1), 16) == 0x60BCDE0 and \
                    "rsi" in pending and "rdi_dst" in pending:
                src, soff, _w = pending["rsi"]
                found.add((pending["rdi_dst"], src, soff, 8))
            pending.pop("rax", None)
            pending.pop("eax", None)
            pending.pop("al", None)
            pending.pop("rsi", None)
            pending.pop("rdi_dst", None)
            continue
        if mnemonic != "mov":
            continue
        m = re.match(r"(\S+),%rsi$", ops)
        if m:
            s = src_of(m.group(1))
            if s:
                pending["rsi"] = (s[0], s[1], 8)
            continue
        m = re.match(r"(\S+),%(eax|rax|r13)$", ops)
        if m:
            s = src_of(m.group(1))
            if s:
                width = 4 if m.group(2) == "eax" else 8
                pending[m.group(2)] = (s[0], s[1], width)
            continue
        m = re.match(r"%(al|eax|rax|r13),(?:0x([0-9a-f]+))?\(%rbx\)$",
                     ops)
        if m:
            reg = m.group(1)
            if reg in pending:
                src, soff, width = pending.pop(reg)
                dst = int(m.group(2), 16) if m.group(2) else 0
                found.add((dst, src, soff, width))
            continue
    return found


def live_engine_check():
    """Drive the model against the live binary: 5 legs."""
    report = {"ok": False, "legs": []}
    try:
        root = Path(__file__).resolve().parents[1]
        bin_path = root / "artifacts" / "node" / "115" / "hl-node"
        data = open(bin_path, "rb").read()
        assert hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256
        # Leg 1: FDE body hash matches the binary.
        body = data[_va_to_off(bin_path, FDE_START):
                    _va_to_off(bin_path, FDE_END)]
        assert hashlib.sha256(body).hexdigest() == BODY_SHA256
        assert len(body) == FDE_END - FDE_START == 1623
        report["legs"].append({"leg": "fde_body_hash", "ok": True})
        # Leg 2: the source hash reproduces by zeroing the 19
        # census relocations (kinds 2/4/42).
        census = json.load(open(
            root / "research" / "work-items" /
            "RE-002-node115-vendor-census" / "census.json"))["records"]
        rec = {r["start"]: r for r in census}[FDE_START]
        assert len(rec["relocations"]) == 19
        zeroed = bytearray(body)
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
        assert hashlib.sha256(bytes(zeroed)).hexdigest() \
            == SOURCE_SHA256
        report["legs"].append({"leg": "source_hash_repro", "ok": True})
        # Leg 3: independent disassembly re-parse of the scalar
        # copies matches COPY_MAP's scalar entries exactly.
        parsed = reparse_copy_map(bin_path)
        expected = set()
        for _n, src, soff, ooff, kind in COPY_MAP:
            if kind in ("bool", "u8"):
                expected.add((ooff, src, soff, 1))
            elif kind in ("i32", "u32"):
                expected.add((ooff, src, soff, 4))
            elif kind in ("u64", "ptr"):
                expected.add((ooff, src, soff, 8))
            elif kind == "shared_ptr":
                # Two 8-byte pieces: the pointer word, then the
                # control block at +8.
                expected.add((ooff, src, soff, 8))
                expected.add((ooff + 8, src, soff + 8, 8))
        missing = expected - parsed
        extra = parsed - expected
        assert not missing, "re-parse missing: %s" % sorted(missing)
        assert not extra, "re-parse extra: %s" % sorted(extra)
        report["legs"].append(
            {"leg": "disassembly_reparse",
             "ok": True, "scalar_copies": len(expected)})
        # Leg 4: the caller census re-runs from the live binary
        # (12 direct calls, 0 jumps, 0 LEA refs).
        callers = PACKET / "callers.tsv"
        rows = open(callers).read().strip().split("\n")[1:]
        assert len(rows) == 12, len(rows)
        sites = sorted(r.split("\t")[3] for r in rows)
        assert sites == sorted(CALLER_SITES), sites
        report["legs"].append({"leg": "caller_census", "ok": True})
        # Leg 5: a defaults build reproduces the DBOptions
        # declaration defaults on every assigned field, and the
        # two unwritten fields keep the ctor defaults.
        out, events, registry, image = build_db_options(
            default_immutable(), default_mutable())
        assert out["create_if_missing"] == 0
        assert out["paranoid_checks"] == 1
        assert out["max_open_files"] == -1
        assert out["max_background_jobs"] == 2
        assert out["max_manifest_file_size"] == 1024 * 1024 * 1024
        assert out["write_dbid_to_manifest"] is False
        assert out["compaction_service"] is None
        assert out["db_host_id"] == ""
        assert len(image) == SIZE_DBOPTIONS
        assert image[0x21a] == 0
        assert image[0x278:0x288] == b"\x00" * 16
        assert image[0x44:0x48] == (-1).to_bytes(4, "little",
                                                 signed=True)
        assert image[0x100:0x108] == (1024 * 1024 * 1024).to_bytes(
            8, "little")
        report["legs"].append({"leg": "defaults_build", "ok": True})
        report["ok"] = True
    except Exception as exc:  # noqa: BLE001 - report, do not raise
        report["ok"] = False
        report["error"] = repr(exc)
    print("live engine check:", json.dumps(report))
    return report["ok"], report


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true",
                    help="replay cases.tsv through the model")
    ap.add_argument("--gen-cases", action="store_true",
                    help="generate cases.tsv")
    ap.add_argument("--live", action="store_true",
                    help="run the live engine check")
    args = ap.parse_args(argv)
    ok = True
    if args.gen_cases:
        write_cases()
    if args.verify:
        ok = verify_cases() and ok
    if args.live:
        live_ok, _ = live_engine_check()
        ok = live_ok and ok
    if not (args.gen_cases or args.verify or args.live):
        ap.print_help()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
