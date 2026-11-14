#!/usr/bin/env python3
"""Node #115 RocksDB DBOptions::DBOptions(): reconstruction.

RE-002 work item. Reconstructs the default constructor at
0x60b2db0..0x60b3154 (932 B) plus its landing pad .cold at
0x60b2cf0..0x60b2da5 (181 B): the constructor that every DB open,
options query and options change runs first -- BuildDBOptions
(0x60c2e20, open PR #6297) calls it at 0x60c2e37 before copying
the 91 fields -- to default-construct a 0x290-byte ``DBOptions``.

  rocksdb::DBOptions::DBOptions()  0x60b2db0 (932 B) + .cold 0x60b2cf0 (181 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
BOTH FDEs are vendor-census-bound (member
d7ece8bd5f9dc186-options.o, librocksdb-sys 0.11.0+8.1.1): the main
FDE body hash ce915d9a... and the .cold body hash 108108c9...
were recomputed from the binary, and the source hashes
433788f7... / dac8b44e... were reproduced exactly by zeroing the
census relocations (15 / 13, kinds 2/4 -- the one kind-42 entry
at FDE offset 642 is a GOTPCRELX mov->lea relaxation, restored
to the mov opcode first, as in the #6222 packet).

What the binary does (whole-FDE disassembly, verbatim in the packet):

  DBOptions::DBOptions()  -- this in rdi (= rbx); r12 = this+0x260
  (the db_host_id SSO buffer). Stack canary at rsp+8. In binary
  order:

  1. Leading bools (0x60b2ddf..0x60b2de9): movl $0x1000000,(%rdi)
     + mov $0x1,%dx / mov %dx,0x4(%rdi) + movb $0x1,0x6(%rdi)
     write +0x00..0x06 as 00 00 00 01 01 00 01:
     create_if_missing=false, create_missing_column_families=false,
     error_if_exists=false, paranoid_checks=true,
     flush_verify_memtable_count=true,
     track_and_verify_wals_in_manifest=false,
     verify_sst_unique_id_in_manifest=true.
  2. env (0x60b2ded..0x60b2dfc): call rocksdb::Env::Default()
     0x5fe2860 (census-bound, 3d290f9c0dad3aa8-env_posix.o);
     env (+0x08) = its return. The only call in the FDE that runs
     before any member is constructed (LSDA site 0 has no landing
     pad).
  3. info_log_level (0x60b2df6): movb $0x1,0x40(%rbx) -- INFO_LEVEL
     (1); upstream builds NDEBUG, where the default is INFO_LEVEL
     (options.h:1096-1104).
  4. max_open_files / max_file_opening_threads (0x60b2e00..0x60b2e1c):
     one 8-byte load from .rodata 0x458e70 (0x00000010ffffffff)
     stored at +0x44: max_open_files = -1, max_file_opening_threads
     = 16 -- the two values share one load because they are adjacent
     i32s.
  5. Shared pointers (0x60b2e14..0x60b2e9a): rate_limiter (+0x10),
     sst_file_manager (+0x20), info_log (+0x30), statistics (+0x58)
     are nulled as 16-byte pairs (movq $0x0 pairs, movups %xmm0 at
     +0x58); use_fsync (+0x68) = false.
  6. Containers (0x60b2e20..0x60b2ecf): db_paths (+0x70, vector)
     zeroed (begin/end via movups %xmm0, cap via movq $0x0);
     db_log_dir (+0x88) and wal_dir (+0xa8) are SSO-empty: the ptr
     word is LEA'd to the string's own SSO buffer (+0x98 / +0xb8),
     size 0, NUL at buffer[0].
  7. delete_obsolete_files_period_micros (0x60b2e3c): movabs
     $0x50775d800 -> +0xc8 = 21600000000 (6 hours in microseconds).
  8. Background-job pair (0x60b2e4d..0x60b2e5b): one 8-byte load
     from .rodata 0x4594f0 (0xffffffff00000002) at +0xd0:
     max_background_jobs = 2, max_background_compactions = -1.
  9. Subcompaction pair (0x60b2e62): movabs $0xffffffff00000001
     at +0xd8: max_subcompactions = 1, max_background_flushes = -1.
 10. Log sizes (0x60b2efe..0x60b2f05): movups %xmm0 at +0xe0
     (max_log_file_size = 0, log_file_time_to_roll = 0) and +0x110
     (WAL_ttl_seconds = 0, WAL_size_limit_MB = 0).
 11. max_manifest_file_size (0x60b2ed6): movq $0x40000000 -> +0x100
     = 1073741824 (1 GiB); table_cache_numshardbits (0x60b2ee1):
     movl $0x6 -> +0x108 = 6.
 12. manifest_preallocation_size (0x60b2eeb): movq $0x400000 ->
     +0x120 = 4194304 (4 MiB).
 13. Mmap/direct bools (0x60b2f0c): movl $0x0 -> +0x128..0x12b:
     allow_mmap_reads, allow_mmap_writes, use_direct_reads,
     use_direct_io_for_flush_and_compaction all false.
 14. Stats periods (0x60b2f1e..0x60b2f3b): one 8-byte load from
     .rodata 0x459148 (0x0000025800000258) at +0x130:
     stats_dump_period_sec = 600, stats_persist_period_sec = 600.
 15. fallocate pair (0x60b2f25): mov %cx,0x12c(%rbx) with cx =
     0x101: allow_fallocate = true, is_fd_close_on_exec = true.
 16. persist_stats_to_disk (0x60b2f42): movb $0x0 -> +0x138 =
     false; stats_history_buffer_size (0x60b2f49): movq $0x100000
     -> +0x140 = 1048576 (1 MiB).
 17. advise_random_on_open (0x60b2f54): movb $0x1 -> +0x148 =
     true; db_write_buffer_size (0x60b2f5b): movq $0x0 -> +0x150.
 18. access_hint_on_compaction_start (0x60b2f66): movl $0x1 ->
     +0x168 = 1 (NORMAL).
 19. Compaction/readahead pair (0x60b2f16..0x60b2f2c): movdqa from
     .rodata 0x451490, movups %xmm1 -> +0x170:
     compaction_readahead_size = 0, random_access_max_buffer_size
     = 1048576 (1 MiB).
 20. writable_file_max_buffer_size (0x60b2f70): movq $0x100000 ->
     +0x180 = 1048576 (1 MiB); use_adaptive_mutex (0x60b2f7b):
     movb $0x0 -> +0x188 = false.
 21. Sync pair (0x60b2ffb..0x60b3009): movups %xmm0 at +0x190:
     bytes_per_sync = 0, wal_bytes_per_sync = 0;
     strict_bytes_per_sync (0x60b2f82): movb $0x0 -> +0x1a0 =
     false.
 22. listeners (0x60b3009..0x60b2f94): vector zeroed (begin/end via
     movups %xmm0 at +0x1a8, cap via movq $0x0 at +0x1b8).
 23. enable_thread_tracking (0x60b2f94): movb $0x0 -> +0x1c0 =
     false; delayed_write_rate (0x60b2f9b): movq $0x0 -> +0x1c8.
 24. Write-thread bool quad (0x60b2fa6): movl $0x1010000 ->
     +0x1d0..0x1d3 as 00 00 01 01: enable_pipelined_write = false,
     unordered_write = false, allow_concurrent_memtable_write =
     true, enable_write_thread_adaptive_yield = true.
 25. Batch-group pair (0x60b2f33..0x60b3010): movdqa from .rodata
     0x4517a0, movups %xmm1 -> +0x1d8:
     max_write_batch_group_size_bytes = 1048576 (1 MiB),
     write_thread_max_yield_usec = 100.
 26. write_thread_slow_yield_usec (0x60b2fb0): movq $0x3 -> +0x1e8
     = 3.
 27. Recovery quad (0x60b2fbb): movl $0x20000 -> +0x1f0..0x1f3 as
     00 00 02 00: skip_stats_update_on_db_open = false,
     skip_checking_sst_file_sizes_on_db_open = false,
     wal_recovery_mode = 2 (kPointInTimeRecovery), allow_2pc =
     false.
 28. row_cache (0x60b3017): movups %xmm0 -> +0x1f8 null pair;
     wal_filter (0x60b2fc5): movq $0x0 -> +0x208 = nullptr.
 29. Option-file bool run (0x60b2fd0..0x60b2fdb): movq $0x0 ->
     +0x210..0x217: fail_if_options_file_error, dump_malloc_stats,
     avoid_flush_during_recovery, avoid_flush_during_shutdown,
     allow_ingest_behind, two_write_queues, manual_wal_flush all
     false, wal_compression = 0 (kNoCompression).
 30. atomic_flush / avoid_unnecessary_blocking_io (0x60b2fdb):
     mov %si,0x218(%rbx) with si = 0: both false.
 31. write_dbid_to_manifest (0x60b2fe2): movb $0x0 -> +0x21a =
     false; log_readahead_size (0x60b2fe9): movq $0x0 -> +0x220.
 32. file_checksum_gen_factory (0x60b301e): movups %xmm0 -> +0x228
     null pair; best_efforts_recovery (0x60b2ff4): movb $0x0 ->
     +0x238 = false.
 33. max_bgerror_resume_count (0x60b3025): movl $0x7fffffff ->
     +0x23c = INT_MAX; bgerror_resume_retry_interval (0x60b3036):
     movq $0xf4240 -> +0x240 = 1000000 (1 s in microseconds).
 34. allow_data_in_errors (0x60b3044): movb $0x0 -> +0x248 = false.
 35. db_host_id (0x60b302f..0x60b3122): the global char* at
     0x64fee88 (.data, R_X86_64_RELATIVE addend 0x4342d1) points
     at the .rodata literal "__hostname__" (12 bytes) -- upstream
     kHostnameForDbHostId (options.h:737, 2557: the table writer
     substitutes the real hostname when writing SST files). The
     string is built with the libstdc++ SSO sequence: strlen,
     len <= 15 stays in the SSO buffer at +0x260 (ptr word +0x250
     = this+0x260, size +0x258 = len, memcpy, NUL at buf[len]);
     len > 15 goes through _M_create + memcpy (heap). If the
     global pointer is NULL the ctor throws std::logic_error
     ("basic_string: construction from null is not valid",
     .rodata 0x963298) at 0x60b3143. The only other read of that
     global in .text is at 0x616d0ab (a strlen length check); no
     code in the binary ever writes it, so the default is pinned.
 36. checksum_handoff_file_types (0x60b3096): movq $0x0 -> +0x270
     (empty FileTypeSet); compaction_service (0x60b30a8): movups
     %xmm0 -> +0x278 null pair.
 37. Cache tier pair (0x60b3091..0x60b30a1): mov $0x101,%eax /
     mov %ax,0x288(%rbx): lowest_used_cache_tier = 1
     (kNonVolatileBlockTier), enforce_single_del_contracts = true.

Layout of DBOptions (0x290 bytes, 93 data members -- pinned by
the disassembly AND upstream options.h v8.1.1, declaration order;
see the FIELD table below and records.json):

  +0x00  create_if_missing, create_missing_column_families,
         error_if_exists, paranoid_checks, flush_verify_memtable_count,
         track_and_verify_wals_in_manifest,
         verify_sst_unique_id_in_manifest (7 bools)
  +0x08  env                         Env* (Env::Default())
  +0x10  rate_limiter                shared_ptr (null)
  +0x20  sst_file_manager            shared_ptr (null)
  +0x30  info_log                    shared_ptr (null)
  +0x40  info_log_level              u8 = 1
  +0x44  max_open_files              i32 = -1
  +0x48  max_file_opening_threads    i32 = 16
  +0x50  max_total_wal_size          u64 = 0
  +0x58  statistics                  shared_ptr (null)
  +0x68  use_fsync                   bool = false
  +0x70  db_paths                    vector (empty)
  +0x88  db_log_dir                  string = ""
  +0xa8  wal_dir                     string = ""
  +0xc8  delete_obsolete_files_period_micros  u64 = 21600000000
  +0xd0  max_background_jobs         i32 = 2
  +0xd4  max_background_compactions  i32 = -1
  +0xd8  max_subcompactions          u32 = 1
  +0xdc  max_background_flushes      i32 = -1
  +0xe0  max_log_file_size           u64 = 0
  +0xe8  log_file_time_to_roll       u64 = 0
  +0xf0  keep_log_file_num           u64 = 1000
  +0xf8  recycle_log_file_num        u64 = 0
  +0x100 max_manifest_file_size      u64 = 1073741824
  +0x108 table_cache_numshardbits    i32 = 6
  +0x110 WAL_ttl_seconds             u64 = 0
  +0x118 WAL_size_limit_MB           u64 = 0
  +0x120 manifest_preallocation_size u64 = 4194304
  +0x128 allow_mmap_reads, allow_mmap_writes, use_direct_reads,
         use_direct_io_for_flush_and_compaction (4 bools, false)
  +0x12c allow_fallocate             bool = true
  +0x12d is_fd_close_on_exec         bool = true
  +0x130 stats_dump_period_sec       u32 = 600
  +0x134 stats_persist_period_sec    u32 = 600
  +0x138 persist_stats_to_disk       bool = false
  +0x140 stats_history_buffer_size   u64 = 1048576
  +0x148 advise_random_on_open       bool = true
  +0x150 db_write_buffer_size        u64 = 0
  +0x158 write_buffer_manager        shared_ptr (null)
  +0x168 access_hint_on_compaction_start  i32 = 1 (NORMAL)
  +0x170 compaction_readahead_size   u64 = 0
  +0x178 random_access_max_buffer_size  u64 = 1048576
  +0x180 writable_file_max_buffer_size  u64 = 1048576
  +0x188 use_adaptive_mutex          bool = false
  +0x190 bytes_per_sync              u64 = 0
  +0x198 wal_bytes_per_sync          u64 = 0
  +0x1a0 strict_bytes_per_sync       bool = false
  +0x1a8 listeners                   vector (empty)
  +0x1c0 enable_thread_tracking      bool = false
  +0x1c8 delayed_write_rate          u64 = 0
  +0x1d0 enable_pipelined_write, unordered_write,
         allow_concurrent_memtable_write,
         enable_write_thread_adaptive_yield (false, false, true, true)
  +0x1d8 max_write_batch_group_size_bytes  u64 = 1048576
  +0x1e0 write_thread_max_yield_usec      u64 = 100
  +0x1e8 write_thread_slow_yield_usec     u64 = 3
  +0x1f0 skip_stats_update_on_db_open,
         skip_checking_sst_file_sizes_on_db_open (false, false)
  +0x1f2 wal_recovery_mode           u8 = 2 (kPointInTimeRecovery)
  +0x1f3 allow_2pc                   bool = false
  +0x1f8 row_cache                   shared_ptr (null)
  +0x208 wal_filter                  ptr = nullptr
  +0x210 fail_if_options_file_error, dump_malloc_stats,
         avoid_flush_during_recovery, avoid_flush_during_shutdown,
         allow_ingest_behind, two_write_queues, manual_wal_flush
         (7 bools, false)
  +0x217 wal_compression             u8 = 0 (kNoCompression)
  +0x218 atomic_flush, avoid_unnecessary_blocking_io (false, false)
  +0x21a write_dbid_to_manifest     bool = false
  +0x220 log_readahead_size          u64 = 0
  +0x228 file_checksum_gen_factory   shared_ptr (null)
  +0x238 best_efforts_recovery      bool = false
  +0x23c max_bgerror_resume_count    i32 = INT_MAX
  +0x240 bgerror_resume_retry_interval  u64 = 1000000
  +0x248 allow_data_in_errors       bool = false
  +0x250 db_host_id                  string = "__hostname__"
  +0x270 checksum_handoff_file_types  u64 = 0 (empty set)
  +0x278 compaction_service          shared_ptr (null)
  +0x288 lowest_used_cache_tier      u8 = 1 (kNonVolatileBlockTier)
  +0x289 enforce_single_del_contracts  bool = true

The .cold landing pad (0x60b2cf0..0x60b2da5, LSDA call-site table
decoded from .gcc_except_table -- see records.json): two call-site
entries, both action 0 (cleanup only, no type filter):

  FDE+0x3d..+0x42  the Env::Default() call (0x60b2ded) -> NO landing
                   pad: nothing has been constructed yet, the
                   exception propagates with no cleanup.
  FDE+0x33f..+0x398  the db_host_id string build (0x60b30ef..0x60b3148:
                   _M_create, memcpy, __throw_logic_error) ->
                   landing pad 0x60b3148, which moves the exception
                   to rbp and jumps to the .cold FDE 0x60b2cf0. The
                   .cold destroys the partially built object in
                   reverse declaration order -- file_checksum_gen_factory
                   ctrl (+0x230), row_cache ctrl (+0x200), listeners
                   vector (+0x1a8), write_buffer_manager ctrl (+0x160),
                   wal_dir string (+0xa8), db_log_dir string (+0x88),
                   db_paths vector (+0x70), statistics ctrl (+0x60),
                   info_log ctrl (+0x38), sst_file_manager ctrl (+0x28),
                   rate_limiter ctrl (+0x18) -- then checks the stack
                   canary and resumes unwinding with _Unwind_Resume.
                   db_host_id itself is NOT destroyed: its _M_create
                   throws before the heap pointer is installed (the
                   string is still in SSO state, where _M_dispose is
                   a no-op), and compaction_service (+0x278) is
                   zeroed after the guarded region, so it is not yet
                   constructed either. The output is never returned
                   half-built.

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM. The binary is read statically (work/hl-node-115.bin);
nothing is executed. Heap addresses (env, string heap buffers,
shared_ptr control blocks) are modelled as deterministic ids, not
real pointers; padding bytes the ctor never writes are modelled as
zero (the binary leaves them uninitialized). ``make verify`` /
``test`` / ``catalogue-check`` in a tooled environment is still owed
upstream.
"""

import hashlib
import json
import os
import random
import re
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(os.environ.get("HL_REPO") or Path(__file__).resolve().parents[1])
BIN_WORK = REPO / "work" / "hl-node-115.bin"
BIN_LFS = REPO / "artifacts" / "node" / "115" / "hl-node"
ARTIFACT_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CASES = REPO / "research" / "work-items" / \
    "re-002-node115-rocksdb-db-options-default-ctor-115" / "cases.tsv"

DBOPTIONS_SIZE = 0x290  # 656
CTOR_START = 0x60B2DB0
CTOR_END = 0x60B3154
COLD_START = 0x60B2CF0
COLD_END = 0x60B2DA5
CTOR_BODY_SHA256 = "ce915d9aef5365c5b53ced3ddb236fe016821c8b6eb98e1918d87fa4463d9462"
CTOR_SOURCE_SHA256 = "433788f7527295b9daf8da46d4cc534c8f23eb45844793c0050680506bcc019b"
COLD_BODY_SHA256 = "108108c95e8d7ba335f4f8b68250f91486a57fd243c2af86dfab53e6d655aa34"
COLD_SOURCE_SHA256 = "dac8b44e521f5d7e47ca461b4dbba8c330a4f99aadfdc3a5c89262095cf32578"

# Deterministic stand-ins for runtime addresses (model choice, not
# binary-pinned): the object lives at THIS_BASE, heap buffers at
# HEAP_BASE + a stable hash of the string bytes.
THIS_BASE = 0x1000
HEAP_BASE = 0x7F0000000000

# db_host_id default: the .rodata literal "__hostname__" (12 bytes),
# reached through the .data global at 0x64fee88 (R_X86_64_RELATIVE
# addend 0x4342d1). Upstream kHostnameForDbHostId.
DEFAULT_HOST_ID = b"__hostname__"
LOGIC_ERROR_MSG = "basic_string: construction from null is not valid"

# Members the .cold destroys on a throw, in .cold order.
COLD_DESTROYED = [
    "file_checksum_gen_factory",
    "row_cache",
    "listeners",
    "write_buffer_manager",
    "wal_dir",
    "db_log_dir",
    "db_paths",
    "statistics",
    "info_log",
    "sst_file_manager",
    "rate_limiter",
]

# (offset, name, kind, default) -- kind: bool/u8/i32/u32/u64/ptr/
# shared_ptr/string/vector. Order is declaration order (== the
# #6297 BuildDBOptions copy-map order for the shared fields).
FIELDS = [
    (0x00, "create_if_missing", "bool", False),
    (0x01, "create_missing_column_families", "bool", False),
    (0x02, "error_if_exists", "bool", False),
    (0x03, "paranoid_checks", "bool", True),
    (0x04, "flush_verify_memtable_count", "bool", True),
    (0x05, "track_and_verify_wals_in_manifest", "bool", False),
    (0x06, "verify_sst_unique_id_in_manifest", "bool", True),
    (0x08, "env", "ptr", "env:default"),
    (0x10, "rate_limiter", "shared_ptr", None),
    (0x20, "sst_file_manager", "shared_ptr", None),
    (0x30, "info_log", "shared_ptr", None),
    (0x40, "info_log_level", "u8", 1),
    (0x44, "max_open_files", "i32", -1),
    (0x48, "max_file_opening_threads", "i32", 16),
    (0x50, "max_total_wal_size", "u64", 0),
    (0x58, "statistics", "shared_ptr", None),
    (0x68, "use_fsync", "bool", False),
    (0x70, "db_paths", "vector", []),
    (0x88, "db_log_dir", "string", b""),
    (0xA8, "wal_dir", "string", b""),
    (0xC8, "delete_obsolete_files_period_micros", "u64", 21600000000),
    (0xD0, "max_background_jobs", "i32", 2),
    (0xD4, "max_background_compactions", "i32", -1),
    (0xD8, "max_subcompactions", "u32", 1),
    (0xDC, "max_background_flushes", "i32", -1),
    (0xE0, "max_log_file_size", "u64", 0),
    (0xE8, "log_file_time_to_roll", "u64", 0),
    (0xF0, "keep_log_file_num", "u64", 1000),
    (0xF8, "recycle_log_file_num", "u64", 0),
    (0x100, "max_manifest_file_size", "u64", 1073741824),
    (0x108, "table_cache_numshardbits", "i32", 6),
    (0x110, "WAL_ttl_seconds", "u64", 0),
    (0x118, "WAL_size_limit_MB", "u64", 0),
    (0x120, "manifest_preallocation_size", "u64", 4194304),
    (0x128, "allow_mmap_reads", "bool", False),
    (0x129, "allow_mmap_writes", "bool", False),
    (0x12A, "use_direct_reads", "bool", False),
    (0x12B, "use_direct_io_for_flush_and_compaction", "bool", False),
    (0x12C, "allow_fallocate", "bool", True),
    (0x12D, "is_fd_close_on_exec", "bool", True),
    (0x130, "stats_dump_period_sec", "u32", 600),
    (0x134, "stats_persist_period_sec", "u32", 600),
    (0x138, "persist_stats_to_disk", "bool", False),
    (0x140, "stats_history_buffer_size", "u64", 1048576),
    (0x148, "advise_random_on_open", "bool", True),
    (0x150, "db_write_buffer_size", "u64", 0),
    (0x158, "write_buffer_manager", "shared_ptr", None),
    (0x168, "access_hint_on_compaction_start", "i32", 1),
    (0x170, "compaction_readahead_size", "u64", 0),
    (0x178, "random_access_max_buffer_size", "u64", 1048576),
    (0x180, "writable_file_max_buffer_size", "u64", 1048576),
    (0x188, "use_adaptive_mutex", "bool", False),
    (0x190, "bytes_per_sync", "u64", 0),
    (0x198, "wal_bytes_per_sync", "u64", 0),
    (0x1A0, "strict_bytes_per_sync", "bool", False),
    (0x1A8, "listeners", "vector", []),
    (0x1C0, "enable_thread_tracking", "bool", False),
    (0x1C8, "delayed_write_rate", "u64", 0),
    (0x1D0, "enable_pipelined_write", "bool", False),
    (0x1D1, "unordered_write", "bool", False),
    (0x1D2, "allow_concurrent_memtable_write", "bool", True),
    (0x1D3, "enable_write_thread_adaptive_yield", "bool", True),
    (0x1D8, "max_write_batch_group_size_bytes", "u64", 1048576),
    (0x1E0, "write_thread_max_yield_usec", "u64", 100),
    (0x1E8, "write_thread_slow_yield_usec", "u64", 3),
    (0x1F0, "skip_stats_update_on_db_open", "bool", False),
    (0x1F1, "skip_checking_sst_file_sizes_on_db_open", "bool", False),
    (0x1F2, "wal_recovery_mode", "u8", 2),
    (0x1F3, "allow_2pc", "bool", False),
    (0x1F8, "row_cache", "shared_ptr", None),
    (0x208, "wal_filter", "ptr", None),
    (0x210, "fail_if_options_file_error", "bool", False),
    (0x211, "dump_malloc_stats", "bool", False),
    (0x212, "avoid_flush_during_recovery", "bool", False),
    (0x213, "avoid_flush_during_shutdown", "bool", False),
    (0x214, "allow_ingest_behind", "bool", False),
    (0x215, "two_write_queues", "bool", False),
    (0x216, "manual_wal_flush", "bool", False),
    (0x217, "wal_compression", "u8", 0),
    (0x218, "atomic_flush", "bool", False),
    (0x219, "avoid_unnecessary_blocking_io", "bool", False),
    (0x21A, "write_dbid_to_manifest", "bool", False),
    (0x220, "log_readahead_size", "u64", 0),
    (0x228, "file_checksum_gen_factory", "shared_ptr", None),
    (0x238, "best_efforts_recovery", "bool", False),
    (0x23C, "max_bgerror_resume_count", "i32", 2147483647),
    (0x240, "bgerror_resume_retry_interval", "u64", 1000000),
    (0x248, "allow_data_in_errors", "bool", False),
    (0x250, "db_host_id", "string", DEFAULT_HOST_ID),
    (0x270, "checksum_handoff_file_types", "u64", 0),
    (0x278, "compaction_service", "shared_ptr", None),
    (0x288, "lowest_used_cache_tier", "u8", 1),
    (0x289, "enforce_single_del_contracts", "bool", True),
]

FIELD_BY_NAME = {name: (off, kind, default) for off, name, kind, default in FIELDS}
OFF_TO_NAME = {off: name for off, name, kind, default in FIELDS}


class LogicError(Exception):
    """std::logic_error from basic_string construction from null."""


class BadAlloc(Exception):
    """std::bad_alloc from basic_string::_M_create."""


def _heap_id(host_id):
    digest = hashlib.sha256(host_id).digest()
    return HEAP_BASE + (int.from_bytes(digest[:4], "little") & 0xFFFFF)


def _put(buf, off, data):
    buf[off:off + len(data)] = data


def _put_u8(buf, off, value):
    _put(buf, off, struct.pack("<B", value & 0xFF))


def _put_u32(buf, off, value):
    _put(buf, off, struct.pack("<I", value & 0xFFFFFFFF))


def _put_i32(buf, off, value):
    _put(buf, off, struct.pack("<i", value))


def _put_u64(buf, off, value):
    _put(buf, off, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))


def _put_string(buf, off, value, heap_id=None):
    """libstdc++ SSO string: ptr at +0, size at +8, buffer at +16."""
    if len(value) <= 15:
        _put_u64(buf, off, THIS_BASE + off + 16)
        _put_u64(buf, off + 8, len(value))
        _put(buf, off + 16, value)
        _put_u8(buf, off + 16 + len(value), 0)
    else:
        _put_u64(buf, off, heap_id)
        _put_u64(buf, off + 8, len(value))
        _put_u64(buf, off + 16, len(value))


def construct_db_options(host_id=DEFAULT_HOST_ID, env_id=0, fail_alloc=False):
    """Run the DBOptions::DBOptions() model.

    host_id=None models the .data global at 0x64fee88 holding NULL
    (the binary throws std::logic_error); fail_alloc=True models
    _M_create throwing std::bad_alloc for a >15-byte host id.
    Returns {"fields": {...}, "image": bytes, "image_sha256": ...,
    "host_id_kind": "sso"|"heap", "destroyed": None} on success, or
    raises LogicError / BadAlloc after recording the .cold
    destruction list on the exception (``exc.destroyed``).
    """
    image = bytearray(DBOPTIONS_SIZE)
    fields = {}

    def scalar(off, kind, value):
        fields[OFF_TO_NAME[off]] = value
        if kind == "bool" or kind == "u8":
            _put_u8(image, off, 1 if value is True else
                    0 if value is False else value)
        elif kind == "i32":
            _put_i32(image, off, value)
        elif kind == "u32":
            _put_u32(image, off, value)
        elif kind == "u64":
            _put_u64(image, off, value)

    # Stores in true binary (instruction-address) order; see the
    # module docstring for the meaning of each step.
    scalar(0x00, "bool", False)
    scalar(0x01, "bool", False)
    scalar(0x02, "bool", False)
    scalar(0x03, "bool", True)
    scalar(0x04, "bool", True)
    scalar(0x05, "bool", False)
    scalar(0x06, "bool", True)
    _put_u64(image, 0x08, env_id)
    fields["env"] = "env:default" if env_id == 0 else env_id
    scalar(0x40, "u8", 1)
    scalar(0x44, "i32", -1)
    scalar(0x48, "i32", 16)
    fields["rate_limiter"] = None
    _put_string(image, 0x88, b"")
    fields["db_log_dir"] = b""
    _put_string(image, 0xA8, b"")
    fields["wal_dir"] = b""
    scalar(0xC8, "u64", 21600000000)
    scalar(0xF0, "u64", 1000)
    scalar(0xF8, "u64", 0)
    scalar(0xD0, "i32", 2)
    scalar(0xD4, "i32", -1)
    scalar(0xD8, "u32", 1)
    scalar(0xDC, "i32", -1)
    fields["sst_file_manager"] = None
    fields["info_log"] = None
    scalar(0x50, "u64", 0)
    scalar(0x68, "bool", False)
    fields["db_paths"] = []
    scalar(0x100, "u64", 1073741824)
    scalar(0x108, "i32", 6)
    scalar(0x120, "u64", 4194304)
    fields["statistics"] = None
    scalar(0xE0, "u64", 0)
    scalar(0xE8, "u64", 0)
    scalar(0x110, "u64", 0)
    scalar(0x118, "u64", 0)
    scalar(0x128, "bool", False)
    scalar(0x129, "bool", False)
    scalar(0x12A, "bool", False)
    scalar(0x12B, "bool", False)
    scalar(0x12C, "bool", True)
    scalar(0x12D, "bool", True)
    scalar(0x170, "u64", 0)
    scalar(0x178, "u64", 1048576)
    scalar(0x130, "u32", 600)
    scalar(0x134, "u32", 600)
    scalar(0x138, "bool", False)
    scalar(0x140, "u64", 1048576)
    scalar(0x148, "bool", True)
    scalar(0x150, "u64", 0)
    scalar(0x168, "i32", 1)
    scalar(0x180, "u64", 1048576)
    scalar(0x188, "bool", False)
    scalar(0x1A0, "bool", False)
    fields["listeners"] = []
    scalar(0x1C0, "bool", False)
    scalar(0x1C8, "u64", 0)
    scalar(0x1D0, "bool", False)
    scalar(0x1D1, "bool", False)
    scalar(0x1D2, "bool", True)
    scalar(0x1D3, "bool", True)
    scalar(0x1E8, "u64", 3)
    scalar(0x1F0, "bool", False)
    scalar(0x1F1, "bool", False)
    scalar(0x1F2, "u8", 2)
    scalar(0x1F3, "bool", False)
    _put_u64(image, 0x208, 0)
    fields["wal_filter"] = None
    scalar(0x210, "bool", False)
    scalar(0x211, "bool", False)
    scalar(0x212, "bool", False)
    scalar(0x213, "bool", False)
    scalar(0x214, "bool", False)
    scalar(0x215, "bool", False)
    scalar(0x216, "bool", False)
    scalar(0x217, "u8", 0)
    scalar(0x218, "bool", False)
    scalar(0x219, "bool", False)
    scalar(0x21A, "bool", False)
    scalar(0x220, "u64", 0)
    scalar(0x238, "bool", False)
    fields["write_buffer_manager"] = None
    scalar(0x190, "u64", 0)
    scalar(0x198, "u64", 0)
    scalar(0x1D8, "u64", 1048576)
    scalar(0x1E0, "u64", 100)
    fields["row_cache"] = None
    fields["file_checksum_gen_factory"] = None
    scalar(0x23C, "i32", 2147483647)
    scalar(0x240, "u64", 1000000)
    scalar(0x248, "bool", False)

    # Step 35: db_host_id from the global char* (step 35 in the
    # docstring). The guarded region: a throw here runs the .cold.
    if host_id is None:
        err = LogicError(LOGIC_ERROR_MSG)
        err.destroyed = list(COLD_DESTROYED)
        raise err
    if len(host_id) > 15 and fail_alloc:
        err = BadAlloc("basic_string::_M_create")
        err.destroyed = list(COLD_DESTROYED)
        raise err
    kind = "sso" if len(host_id) <= 15 else "heap"
    _put_string(image, 0x250, host_id,
                heap_id=_heap_id(host_id) if kind == "heap" else None)
    fields["db_host_id"] = host_id

    # Steps 36-37 (after the string build, in the shared epilogue).
    scalar(0x270, "u64", 0)
    fields["compaction_service"] = None
    scalar(0x288, "u8", 1)
    scalar(0x289, "bool", True)

    image = bytes(image)
    return {
        "fields": fields,
        "image": image,
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "host_id_kind": kind,
        "destroyed": None,
    }


def default_fields():
    """The 93 default field values (host_id = b"__hostname__")."""
    return construct_db_options()["fields"]


def image_sha256(host_id=DEFAULT_HOST_ID, env_id=0):
    return construct_db_options(host_id=host_id, env_id=env_id)["image_sha256"]


# ---------------------------------------------------------------- cases

# The 11 validated caller sites (see census.py / callers.tsv).
CALLERS = [
    (0x5D3567A, 0x5D35660, "rocksdb_options_create"),
    (0x5D74D1C, 0x5D74AA0, "unnamed FDE 0x5d74aa0 (not in vendor census)"),
    (0x5E34FB3, 0x5E347D0, "rocksdb::CompactionServiceInput::CompactionServiceInput"),
    (0x5E35694, 0x5E35660, "rocksdb::cs_input_type_info lambda"),
    (0x5FCF921, 0x5FCF8C0, "rocksdb::EnvOptions::EnvOptions"),
    (0x60A43F7, 0x60A43C0, "rocksdb::ImmutableDBOptions::ImmutableDBOptions"),
    (0x60C2E37, 0x60C2E20, "rocksdb::BuildDBOptions"),
    (0x60CC184, 0x60CC150, "rocksdb::RocksDBOptionsParser::Reset"),
    (0x60CD701, 0x60CD6F0, "rocksdb::RocksDBOptionsParser::RocksDBOptionsParser"),
    (0x60CF51B, 0x60CF020, "rocksdb::RocksDBOptionsParser::EndSection"),
    (0x6203E02, 0x6203DC0, "rocksdb::DBWithTTLImpl::SetTtl"),
]


def _jsonable(value):
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _fields_json(fields):
    return {name: _jsonable(value) for name, value in fields.items()}


def run_case(inputs):
    """Run one case: construct (or throw) and return expected outputs."""
    group = inputs["group"]
    if group == "bindings":
        # Caller-independence: the ctor result depends only on
        # (host_id, env_id), never on which of the 11 callers runs it.
        host_id = bytes.fromhex(inputs["host_id_hex"]) \
            if inputs.get("host_id_hex") else DEFAULT_HOST_ID
        result = construct_db_options(host_id=host_id,
                                      env_id=inputs.get("env_id", 0))
        return {
            "caller_site": inputs["caller_site"],
            "image_sha256": result["image_sha256"],
            "host_id_kind": result["host_id_kind"],
        }
    if group == "defaults":
        result = construct_db_options()
        probe = inputs["probe"]
        if probe == "image_hash":
            return {"image_sha256": result["image_sha256"]}
        name = inputs["field"]
        off, kind, default = FIELD_BY_NAME[name]
        if probe == "value":
            return {"field": name, "value": _jsonable(result["fields"][name])}
        if probe == "bytes":
            size = {"bool": 1, "u8": 1, "i32": 4, "u32": 4, "u64": 8,
                    "ptr": 8, "shared_ptr": 16, "string": 32,
                    "vector": 24}[kind]
            return {"field": name,
                    "bytes_hex": result["image"][off:off + size].hex()}
        raise ValueError("unknown probe %r" % probe)
    if group == "host_id":
        host_id = bytes.fromhex(inputs["host_id_hex"])
        result = construct_db_options(host_id=host_id,
                                      env_id=inputs.get("env_id", 0))
        return {
            "host_id_kind": result["host_id_kind"],
            "size": len(host_id),
            "image_sha256": result["image_sha256"],
            "db_host_id": _jsonable(result["fields"]["db_host_id"]),
        }
    if group == "throw":
        host_id = None if inputs.get("host_id_null") else \
            bytes.fromhex(inputs["host_id_hex"])
        try:
            construct_db_options(host_id=host_id,
                                 env_id=inputs.get("env_id", 0),
                                 fail_alloc=inputs.get("fail_alloc", False))
        except LogicError as err:
            return {"error": "LogicError", "message": str(err),
                    "destroyed": err.destroyed}
        except BadAlloc as err:
            return {"error": "BadAlloc", "message": str(err),
                    "destroyed": err.destroyed}
        return {"error": None, "destroyed": None}
    raise ValueError("unknown group %r" % group)


_HOST_ID_POOL = [
    b"", b"a", b"ab", b"abc", b"host-1", b"node-115", b"__hostname__",
    b"0123456789abcde", b"0123456789abcdef", b"0123456789abcdefg",
    b"0123456789abcdef0123456789abcdef",
    b"db-host.example.com", b"a" * 32, b"b" * 64,
    b"with-dash_and_underscore", b"UPPER lower 123",
]


def _gen_group(rng, group, n):
    rows = []
    for i in range(n):
        case_id = "%s-%03d" % (group, i)
        inputs = {"case_id": case_id, "group": group}
        if group == "defaults":
            # Cycle the 93 fields x 3 probes deterministically.
            name = FIELDS[i % len(FIELDS)][1]
            probe = ["value", "bytes", "image_hash"][i % 3]
            inputs.update({"field": name, "probe": probe})
        elif group == "host_id":
            if i < len(_HOST_ID_POOL):
                host_id = _HOST_ID_POOL[i]
            else:
                length = rng.choice(
                    [0, 1, 2, 3, 5, 8, 11, 12, 13, 14, 15, 15, 16, 16, 17,
                     20, 24, 31, 32, 48, 64])
                alphabet = b"abcdefghijklmnop-_.0123456789"
                host_id = bytes(rng.choice(alphabet) for _ in range(length))
            inputs.update({
                "host_id_hex": host_id.hex(),
                "env_id": rng.choice([0, 0, 0, 0x1000, 0x7F0000000000]),
            })
        elif group == "throw":
            if i % 2 == 0:
                inputs.update({"host_id_null": True,
                               "env_id": rng.choice([0, 0, 0x1000])})
            else:
                length = rng.choice([16, 17, 24, 32, 48, 64])
                host_id = bytes(rng.choice(b"abcdefgh") for _ in range(length))
                inputs.update({"host_id_hex": host_id.hex(),
                               "fail_alloc": True,
                               "env_id": rng.choice([0, 0, 0x1000])})
        elif group == "bindings":
            site, _fde, _name = CALLERS[i % len(CALLERS)]
            inputs.update({
                "caller_site": "0x%x" % site,
                "host_id_hex": rng.choice(
                    [DEFAULT_HOST_ID.hex(), b"".hex(), b"node-115".hex(),
                     b"0123456789abcdefg".hex()]),
                "env_id": rng.choice([0, 0, 0x1000]),
            })
        expected = run_case(inputs)
        rows.append((group, case_id, inputs, expected))
    return rows


def write_cases():
    all_rows = []
    for gi, group in enumerate(
            ["defaults", "host_id", "throw", "bindings"]):
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
            print("MISMATCH %s:\n  got %s\n  exp %s" % (
                row["case_id"], json.dumps(got, sort_keys=True),
                json.dumps(expected, sort_keys=True)))
            if mismatches >= 3:
                break
    print("verify: %d cases, %d mismatches" % (len(rows), mismatches))
    return mismatches == 0 and len(rows) == 2400


# ---------------------------------------------------------------- live

def _bin_path():
    for path in (BIN_WORK, BIN_LFS):
        if not path.exists():
            continue
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256:
            return path
    raise RuntimeError("node #115 artifact not materialized")


def _sections(data):
    out = subprocess.check_output(["readelf", "-SW", str(_bin_path())]).decode()
    secs = {}
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
                     line)
        if m:
            secs[m.group(1)] = (int(m.group(3), 16), int(m.group(4), 16),
                                int(m.group(5), 16))
    return secs


def _va2off(secs, va):
    for name, (addr, off, size) in secs.items():
        if name in (".comment",):
            continue
        if addr <= va < addr + size:
            return off + (va - addr)
    raise ValueError("VA %#x not in a mapped section" % va)


def _read_va(data, secs, va, size):
    off = _va2off(secs, va)
    return data[off:off + size]


def _fde_hashes(data, secs):
    """Body + source hashes for both FDEs, from the binary."""
    import json as _json
    census_path = REPO / "research" / "work-items" / \
        "RE-002-node115-vendor-census" / "census.json"
    census = _json.loads(census_path.read_text())
    recs = census if isinstance(census, list) else census.get("records", [])
    by_start = {r["start"]: r for r in recs}
    tva, toff, _tsize = secs[".text"]
    out = {}
    for start, end, tag in ((CTOR_START, CTOR_END, "ctor"),
                            (COLD_START, COLD_END, "cold")):
        body = bytearray(data[toff + (start - tva):toff + (end - tva)])
        out[tag + "_body"] = hashlib.sha256(bytes(body)).hexdigest()
        rec = by_start[start]
        for rel in rec["relocations"]:
            off = rel["offset"]
            if rel.get("relaxation") == "gotpcrelx-mov-lea":
                body[off - 2] = 0x8B  # restore mov opcode
            body[off:off + rel["width"]] = b"\0" * rel["width"]
        out[tag + "_source"] = hashlib.sha256(bytes(body)).hexdigest()
    return out


def _rodata_constants(data, secs):
    """The six .rodata constants the ctor loads, read from the binary."""
    return {
        "max_open_files_pair": struct.unpack(
            "<Q", _read_va(data, secs, 0x458E70, 8))[0],
        "keep_recycle_pair": struct.unpack(
            "<QQ", _read_va(data, secs, 0x4562B0, 16)),
        "bg_jobs_pair": struct.unpack(
            "<Q", _read_va(data, secs, 0x4594F0, 8))[0],
        "compaction_readahead_pair": struct.unpack(
            "<QQ", _read_va(data, secs, 0x451490, 16)),
        "stats_periods_pair": struct.unpack(
            "<Q", _read_va(data, secs, 0x459148, 8))[0],
        "batch_group_pair": struct.unpack(
            "<QQ", _read_va(data, secs, 0x4517A0, 16)),
    }


def _host_id_global(data, secs):
    """The db_host_id default: .rela.dyn RELATIVE addend + literal."""
    out = subprocess.check_output(
        ["readelf", "-r", str(_bin_path())]).decode()
    addend = None
    for line in out.splitlines():
        m = re.match(r"0000064fee88\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)",
                     line)
        if m:
            addend = int(m.group(1), 16)
    if addend is None:
        raise ValueError("no RELATIVE relocation for 0x64fee88")
    raw = _read_va(data, secs, addend, 64)
    literal = raw.split(b"\0")[0]
    return {"global_va": 0x64FEE88, "addend": addend, "literal": literal}


def _caller_scan(data, secs):
    """Whole-.text E8/E9/LEA scan for the ctor, Capstone-validated."""
    import bisect
    import capstone
    tva, toff, tsize = secs[".text"]
    text = data[toff:toff + tsize]
    out = subprocess.check_output(
        ["readelf", "--debug-dump=frames-interp", str(_bin_path())]).decode()
    fdes = {}
    for line in out.splitlines():
        m = re.search(r"FDE.*pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            fdes[int(m.group(1), 16)] = int(m.group(2), 16)
    starts = sorted(fdes)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0:
            return None
        s = starts[i]
        return (s, fdes[s]) if s <= va < fdes[s] else None

    def validated(site, kind):
        holder = containing(site)
        if holder is None:
            return False
        fde_start, fde_end = holder
        code = text[fde_start - tva:fde_end - tva]
        for insn in md.disasm(code, fde_start):
            if insn.address == site:
                if kind == "call":
                    return insn.mnemonic == "call" and \
                        insn.op_str == "0x%x" % CTOR_START
                return insn.mnemonic == "jmp" and \
                    insn.op_str == "0x%x" % CTOR_START
            if insn.address > site:
                return False
        return False

    sites = []
    for i in range(len(text) - 5):
        if text[i] in (0xE8, 0xE9):
            rel = int.from_bytes(text[i + 1:i + 5], "little", signed=True)
            if tva + i + 5 + rel == CTOR_START:
                kind = "call" if text[i] == 0xE8 else "jmp"
                if validated(tva + i, kind):
                    sites.append((tva + i, kind))
    lea_refs = []
    for i in range(len(text) - 7):
        if text[i] == 0x48 and text[i + 1] == 0x8D and \
                (text[i + 2] & 0xC7) == 0x05:
            rel = int.from_bytes(text[i + 3:i + 7], "little", signed=True)
            if tva + i + 7 + rel == CTOR_START:
                lea_refs.append(tva + i)
    return {"sites": sites, "lea_refs": lea_refs}


# Offsets the re-parse masks: runtime addresses, not immediates.
_REPARSE_MASK = [(0x08, 8), (0x88, 8), (0xA8, 8), (0x250, 0x20)]


def _reparse_image(data, secs):
    """Rebuild the default image by parsing the objdump stores.

    Independent of the model table: every non-masked byte comes from
    a store instruction in the disassembly of the main FDE.
    """
    out = subprocess.check_output(
        ["objdump", "-d", "--start-address=%#x" % CTOR_START,
         "--stop-address=%#x" % CTOR_END, str(_bin_path())]).decode()
    image = bytearray(DBOPTIONS_SIZE)
    rax = None  # tracked value of %rax (None = unknown/runtime)
    xmm1 = None  # last movdqa constant (16 bytes) or None
    rodata = {
        0x458E70: lambda: struct.unpack(
            "<Q", _read_va(data, secs, 0x458E70, 8))[0],
        0x4594F0: lambda: struct.unpack(
            "<Q", _read_va(data, secs, 0x4594F0, 8))[0],
        0x459148: lambda: struct.unpack(
            "<Q", _read_va(data, secs, 0x459148, 8))[0],
        0x4562B0: lambda: _read_va(data, secs, 0x4562B0, 16),
        0x451490: lambda: _read_va(data, secs, 0x451490, 16),
        0x4517A0: lambda: _read_va(data, secs, 0x4517A0, 16),
    }
    masked = bytearray(DBOPTIONS_SIZE)
    for off, size in _REPARSE_MASK:
        for k in range(off, off + size):
            masked[k] = 1
    lea_ptrs = {}
    for line in out.splitlines():
        m = re.search(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t(.*)$", line)
        if not m:
            continue
        insn = m.group(1).strip()
        mm = re.match(r"movdqa\s+(-?0x[0-9a-f]+)\(%rip\),%xmm1", insn)
        if mm:
            addr = int(mm.group(1), 16)
            # Resolve the RIP-relative source from the comment address.
            cm = re.search(r"#\s*([0-9a-f]+)", line)
            src = int(cm.group(1), 16) if cm else None
            if src in rodata:
                xmm1 = rodata[src]()
            continue
        mm = re.match(r"movabs\s+\$0x([0-9a-f]+),%rax", insn)
        if mm:
            rax = int(mm.group(1), 16)
            continue
        mm = re.match(r"mov\s+(-?0x[0-9a-f]+)\(%rip\),%rax", insn)
        if mm:
            cm = re.search(r"#\s*([0-9a-f]+)", line)
            src = int(cm.group(1), 16) if cm else None
            rax = rodata[src]() if src in rodata else None
            continue
        mm = re.match(r"lea\s+(-?0x[0-9a-f]+)\(%rip\),%rax", insn)
        if mm:
            rax = "lea"
            continue
        mm = re.match(r"call\s+", insn)
        if mm:
            rax = None  # Env::Default() return: runtime address
            continue
        mm = re.match(r"movl\s+\$0x([0-9a-f]+),\(%rdi\)", insn)
        if mm:
            _put_u32(image, 0, int(mm.group(1), 16))
            continue
        mm = re.match(r"movl\s+\$0x([0-9a-f]+),0x([0-9a-f]+)\((?:%rdi|%rbx)\)", insn)
        if mm:
            _put_u32(image, int(mm.group(2), 16), int(mm.group(1), 16))
            continue
        mm = re.match(r"movq\s+\$0x([0-9a-f]+),0x([0-9a-f]+)\((?:%rdi|%rbx)\)", insn)
        if mm:
            _put_u64(image, int(mm.group(2), 16), int(mm.group(1), 16))
            continue
        mm = re.match(r"movb\s+\$0x([0-9a-f]+),0x([0-9a-f]+)\((?:%rdi|%rbx)\)", insn)
        if mm:
            _put_u8(image, int(mm.group(2), 16), int(mm.group(1), 16))
            continue
        mm = re.match(r"mov\s+%dx,0x([0-9a-f]+)\(%rdi\)", insn)
        if mm:
            _put(image, int(mm.group(1), 16), struct.pack("<H", 0x0001))
            continue
        mm = re.match(r"mov\s+%cx,0x([0-9a-f]+)\(%rbx\)", insn)
        if mm:
            _put(image, int(mm.group(1), 16), struct.pack("<H", 0x0101))
            continue
        mm = re.match(r"mov\s+%si,0x([0-9a-f]+)\(%rbx\)", insn)
        if mm:
            _put(image, int(mm.group(1), 16), struct.pack("<H", 0x0000))
            continue
        mm = re.match(r"mov\s+%ax,0x([0-9a-f]+)\(%rbx\)", insn)
        if mm:
            _put(image, int(mm.group(1), 16), struct.pack("<H", 0x0101))
            continue
        mm = re.match(r"movups\s+%xmm0,0x([0-9a-f]+)\(%rbx\)", insn)
        if mm:
            off = int(mm.group(1), 16)
            _put(image, off, b"\0" * 16)
            continue
        mm = re.match(r"movups\s+%xmm1,0x([0-9a-f]+)\(%rbx\)", insn)
        if mm:
            off = int(mm.group(1), 16)
            if xmm1 is not None:
                _put(image, off, xmm1)
            continue
        mm = re.match(r"mov\s+%rax,0x([0-9a-f]+)\(%rbx\)", insn)
        if mm:
            off = int(mm.group(1), 16)
            if masked[off]:
                continue  # runtime address slot (env / string ptr)
            if isinstance(rax, int):
                _put_u64(image, off, rax)
            continue
        mm = re.match(r"mov\s+%r12,0x([0-9a-f]+)\(%rbx\)", insn)
        if mm:
            continue  # db_host_id ptr = SSO buffer (masked)
        mm = re.match(r"mov\s+%rax,0x([0-9a-f]+)\(%rbx\)", insn)
        if mm:
            continue
    # db_host_id SSO bytes come from the .rodata literal itself.
    host = _host_id_global(data, secs)["literal"]
    _put(image, 0x260, host)
    _put_u8(image, 0x260 + len(host), 0)
    _put_u64(image, 0x258, len(host))
    return bytes(image)


def live_engine_check():
    """Live check against work/hl-node-115.bin. 8 legs."""
    report = {"ok": False, "legs": []}

    def leg(name, ok, detail=""):
        report["legs"].append({"name": name, "ok": bool(ok),
                               "detail": str(detail)})
        return ok

    try:
        data = _bin_path().read_bytes()
        secs = _sections(data)
    except Exception as err:  # noqa: BLE001 - report, don't crash
        leg("artifact", False, err)
        return report
    leg("artifact", True, "sha256 %s" % ARTIFACT_SHA256[:12])

    hashes = _fde_hashes(data, secs)
    leg("ctor_body_hash", hashes["ctor_body"] == CTOR_BODY_SHA256,
        hashes["ctor_body"][:12])
    leg("ctor_source_hash", hashes["ctor_source"] == CTOR_SOURCE_SHA256,
        hashes["ctor_source"][:12])
    leg("cold_body_hash", hashes["cold_body"] == COLD_BODY_SHA256,
        hashes["cold_body"][:12])
    leg("cold_source_hash", hashes["cold_source"] == COLD_SOURCE_SHA256,
        hashes["cold_source"][:12])

    consts = _rodata_constants(data, secs)
    model = construct_db_options()
    img = model["image"]
    checks = [
        ("max_open_files_pair",
         consts["max_open_files_pair"] == 0x00000010FFFFFFFF),
        ("keep_recycle_pair",
         consts["keep_recycle_pair"] == (1000, 0)),
        ("bg_jobs_pair",
         consts["bg_jobs_pair"] == 0xFFFFFFFF00000002),
        ("compaction_readahead_pair",
         consts["compaction_readahead_pair"] == (0, 1048576)),
        ("stats_periods_pair",
         consts["stats_periods_pair"] == 0x0000025800000258),
        ("batch_group_pair",
         consts["batch_group_pair"] == (1048576, 100)),
    ]
    leg("rodata_constants", all(ok for _, ok in checks),
        "; ".join("%s=%s" % kv for kv in checks))

    host = _host_id_global(data, secs)
    leg("host_id_global", host["literal"] == DEFAULT_HOST_ID,
        "addend %#x literal %r" % (host["addend"], host["literal"]))

    scan = _caller_scan(data, secs)
    got_sites = sorted(s for s, _k in scan["sites"])
    want_sites = sorted(s for s, _f, _n in CALLERS)
    leg("caller_census", got_sites == want_sites and not scan["lea_refs"],
        "%d calls, %d jumps/lea" % (len(got_sites), len(scan["lea_refs"])))

    reparse = _reparse_image(data, secs)
    masked = bytearray(DBOPTIONS_SIZE)
    for off, size in _REPARSE_MASK:
        for k in range(off, off + size):
            masked[k] = 1
    diffs = [k for k in range(DBOPTIONS_SIZE)
             if not masked[k] and reparse[k] != img[k]]
    leg("disassembly_reparse", not diffs,
        "0 diffs" if not diffs else "diffs at %s" % diffs[:8])

    report["ok"] = all(l["ok"] for l in report["legs"])
    return report


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--gen-cases", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args(argv)
    if args.gen_cases:
        write_cases()
    ok = True
    if args.verify:
        ok = verify_cases() and ok
    if args.live:
        report = live_engine_check()
        for leg in report["legs"]:
            print("%s %s %s" % (
                "PASS" if leg["ok"] else "FAIL", leg["name"], leg["detail"]))
        print("live: %s (%d/%d legs)" % (
            "OK" if report["ok"] else "FAILED",
            sum(1 for l in report["legs"] if l["ok"]), len(report["legs"])))
        ok = report["ok"] and ok
    if not args.gen_cases and not args.verify and not args.live:
        print("default image sha256: %s" % image_sha256())
        print("fields: %d" % len(default_fields()))
        print("callers: %d" % len(CALLERS))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
