#!/usr/bin/env python3
"""Node #115 RocksDB DBOptions::DBOptions(const Options&): reconstruction.

RE-002 work item. Reconstructs the (explicit) Options ctor at
0x60b3280..0x60b3b87 (2311 B, main FDE) plus its .cold landing-pad
FDE at 0x60b3154..0x60b327a (294 B): the constructor every DB open
entry point runs first to build a DBOptions from the caller's
Options -- DB::Open (0x5e65530), DB::OpenForReadOnly (0x5e73160),
CompactedDBImpl::Open (0x5e79c30), DB::OpenAsSecondary (0x5e81f00),
DBWithTTL::Open (0x6207740) and the C API
rocksdb_optimistictransactiondb_open_column_families (0x5d39590)
are the six validated callers. Direct follow-up to the
default-ctor packet (open PR #6337, 0x60b2db0) and the copy-ctor
packet (open PR #6338, 0x5d38750): the default ctor builds the 93
defaults, this ctor copies the DBOptions subobject out of an
Options, and the copy ctor is the same memberwise copy from a
DBOptions source.

  rocksdb::DBOptions::DBOptions(const Options&)  0x60b3280 (2311 B)
  rocksdb::DBOptions::DBOptions(const Options&).cold  0x60b3154 (294 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Both FDEs are vendor-census-bound (member d7ece8bd5f9dc186-options.o,
librocksdb-sys 0.11.0+8.1.1, symbols
_ZN7rocksdb9DBOptionsC1ERKNS_7OptionsE and
_ZN7rocksdb9DBOptionsC2ERKNS_7OptionsE.cold): the body hashes
7c4707c2... / f1428783... and the source hashes e9bc1ce7... /
de25ebd7... were recomputed from the binary, and the source hashes
were reproduced exactly by zeroing the census relocations (main:
28 relocations, kinds 2/4/42, no relaxation; .cold: 18 kind-4
relocations).

What the binary does (whole-FDE disassembly, verbatim in the packet):

  DBOptions::DBOptions(const Options&) -- this in rdi (= rbx),
  source Options in rsi (= rbp); no +0x18 prologue bump (the first
  stores use (%rsi)/(%rdi) directly, the rest use (%rbp)/(%rbx)).
  The source is an Options: struct Options inherits DBOptions
  first (upstream options.h:1399), so the DBOptions subobject sits
  at Options+0x00 and the ctor copies exactly the 0x290-byte
  DBOptions layout at the same offsets as the copy ctor. A stack
  canary IS used (%fs:0x28, checked at the epilogue and in the
  length-throw paths). In binary order:

  1. Leading bools + env (0x60b3298..0x60b32c8): the 7 bools at
     +0x00..0x06 are copied as one u32 (+0x00), one u16 (+0x04)
     and one u8 (+0x06); env (+0x08) and the rate_limiter ptr word
     (+0x10) arrive together in one movdqu (+0x08..+0x17); the
     rate_limiter ctrl word (+0x18) is copied by plain mov, then
     the refcount at ctrl+0x8 is bumped by 1 (see 2).
  2. Shared pointers (0x60b32c4..0x60b3331, 0x60b3355..0x60b336e,
     0x60b3679..0x60b3692, 0x60b3806..0x60b382d, 0x60b387a..0x60b38a1,
     0x60b393c..0x60b3963): each shared_ptr is copied as ptr word
     (plain mov, or inside a 16-byte movdqu/movups chunk) + ctrl
     word (plain mov) + an INLINED refcount bump -- unlike the
     copy ctor, there is NO call to the __shared_count copy helper
     0x5d35c00 anywhere in this FDE. The bump is `addl $0x1,
     0x8(%rax)` when the guard byte at the GOT slot 0x64ed290 is
     non-zero, and `lock addl $0x1, 0x8(%rax)` (a stub at the end
     of the FDE) when it is zero: nine plain + nine lock sites in
     total, one pair per shared_ptr copy -- eight fields
     (rate_limiter +0x18, sst_file_manager +0x28, info_log +0x38,
     statistics +0x60, write_buffer_manager +0x160, row_cache
     +0x200, file_checksum_gen_factory +0x230, compaction_service
     +0x280) plus the per-element bump in the listeners loop
     (0x60b3768 / 0x60b3795). Both paths increment the refcount
     by exactly 1; the copy SHARES each control block, it never
     deep-copies the pointed-to object. A null source stays null
     (the bump is skipped when the ctrl is null). The GOT slot is
     statically zero (a load-time relocation), so the guard flag's
     identity is NOT pinned statically -- recorded as an open
     unknown; the two-path behaviour is what the model pins.
  3. Scalars (throughout): every scalar field is copied verbatim
     by plain mov / movdqu / movups at the same offset as in the
     copy ctor (info_log_level +0x40, max_open_files +0x44,
     max_file_opening_threads +0x48, max_total_wal_size +0x50,
     use_fsync +0x68, delete_obsolete_files_period_micros +0xc8,
     max_background_jobs +0xd0, max_background_compactions +0xd4,
     max_subcompactions +0xd8, max_background_flushes +0xdc,
     max_log_file_size +0xe0, log_file_time_to_roll +0xe8,
     keep_log_file_num +0xf0, recycle_log_file_num +0xf8,
     max_manifest_file_size +0x100, table_cache_numshardbits
     +0x108, WAL_ttl_seconds +0x110, WAL_size_limit_MB +0x118,
     manifest_preallocation_size +0x120, the mmap/direct bool quad
     (+0x128, u32 copy), allow_fallocate/is_fd_close_on_exec
     (+0x12c, u16 copy), stats_dump_period_sec +0x130,
     stats_persist_period_sec +0x134, persist_stats_to_disk +0x138,
     stats_history_buffer_size +0x140, advise_random_on_open
     +0x148, db_write_buffer_size +0x150, access_hint_on_
     compaction_start +0x168, compaction_readahead_size +0x170,
     random_access_max_buffer_size +0x178,
     writable_file_max_buffer_size +0x180, use_adaptive_mutex
     +0x188, bytes_per_sync +0x190, wal_bytes_per_sync +0x198,
     strict_bytes_per_sync +0x1a0, enable_thread_tracking +0x1c0,
     delayed_write_rate +0x1c8, the write-thread bool quad (+0x1d0,
     u32 copy), max_write_batch_group_size_bytes +0x1d8,
     write_thread_max_yield_usec +0x1e0,
     write_thread_slow_yield_usec +0x1e8, the recovery quad (+0x1f0,
     u32 copy), wal_filter (+0x208, raw ptr copy), the option-file
     bool run (+0x210..+0x217, u64 copy),
     atomic_flush/avoid_unnecessary_blocking_io (+0x218, u16 copy),
     write_dbid_to_manifest +0x21a, log_readahead_size +0x220,
     best_efforts_recovery +0x238, max_bgerror_resume_count
     +0x23c, bgerror_resume_retry_interval +0x240,
     allow_data_in_errors +0x248, checksum_handoff_file_types
     +0x270, lowest_used_cache_tier/enforce_single_del_contracts
     (+0x288, u16 copy). Padding bytes are never written (the
     binary leaves them uninitialized; the model zeroes them).
  4. db_paths vector (+0x70, 0x60b336e..0x60b34e0): byte size =
     src end - src begin; the dst vector is zeroed first (begin =
     end = cap = 0); if size == 0 it stays zeroed. Else the size
     is bounds-checked against 0x7ffffffffffffff8 (else
     __throw_bad_array_new_length, PLT 0x63f0ec0); operator new(size)
     (PLT 0x63f0dd0) allocates the dst buffer; begin = end = the new
     buffer, cap = begin + size; then an INLINED element loop
     (0x60b33d5..0x60b34e0) copy-constructs each DbPath (0x28 =
     40 bytes: std::string path at +0x0, uint64_t target_size at
     +0x20) -- each path string is built by the inlined
     _M_construct pattern (_M_create + memcpy for len > 15, SSO
     copy for len <= 15 with the len == 1 single-byte fast path and
     the len == 0 NUL-only path) and the target_size is copied by
     mov -- and stores the new end to dst +0x78. The copy
     allocates EXACTLY size bytes (cap == end, no slack). Unlike
     the copy ctor, there is NO call to __do_uninit_copy
     0x5d386a0: the loop is inlined here.
  5. Strings db_log_dir (+0x88), wal_dir (+0xa8), db_host_id (+0x250)
     (0x60b34e4..0x60b3581, 0x60b38a8..0x60b3926): each is built by
     the INLINED _M_construct pattern -- _M_create (PLT 0x63f0e10)
     + memcpy (PLT 0x63f0a60) for len > 15, SSO copy for len <= 15
     (len == 1 single-byte fast path, len == 0 NUL-only) -- after
     the dst string's ptr word is preset to its own SSO buffer
     (lea this+0x98 / +0xb8 / +0x260). Unlike the copy ctor, there
     is NO call to basic_string::_M_construct 0x5d2e540. The
     db_log_dir this-pointer is saved in r13 and the wal_dir
     this-pointer in r14 for the landing pads.
  6. listeners vector (+0x1a8, 0x60b3692..0x60b37b5): byte size =
     src end - src begin; dst zeroed first; if size == 0 it stays
     zeroed. Else bounds-checked against 0x7ffffffffffffff0 (else
     __throw_bad_array_new_length); operator new(size); begin = end
     = new buffer, cap = begin + size; then the inline loop copies
     each shared_ptr<EventListener> element (0x10 = 16 bytes: ptr
     word by movdqu, ctrl word by mov, refcount bumped by the
     inlined addl/lock-addl pair -- refcount +1 per element, the
     listeners are SHARED, not deep-copied) and stores the new end
     to dst +0x1b0.
  7. Epilogue (0x60b3971..0x60b3993): stack-canary check, add
     $0x38,%rsp; pop rbx/rbp/r12/r13/r14/r15; ret. The result is
     the fully copied object; no field is left at its default
     unless the source had the default there.

  Binary-vs-source observation (recorded, not hidden): upstream
  options/options.cc:128-130 defines this ctor as a DELEGATION to
  the copy ctor (`DBOptions(const Options& options) :
  DBOptions(*static_cast<const DBOptions*>(&options)) {}`), but
  the binary contains NO call to the copy ctor 0x5d38750 -- the
  compiler inlined the implicit copy ctor's memberwise body into
  this FDE (same TU, options.o), with the shared_ptr, vector and
  string helpers inlined as well. The copy ctor's own 3 callers
  (SanitizeOptions, DBOptionsConfigurable x2) do not include this
  ctor, confirming the delegation was inlined rather than called.
  The observable behaviour is the same memberwise copy the copy
  ctor performs; only the code shape differs.

  The LSDA call-site tables (decoded from .gcc_except_table with
  the repo's tools/fde_extents.py FDE index -- main LSDA at
  0x422440, 53 bytes, header ff 9b 39 01 30 + 8 call-site entries,
  all action 0 except the db_paths element-copy entry (action 1,
  a catch pad); .cold LSDA at 0x42247c, 16 bytes, header ff 9b 15
  01 0b + 2 entries). Eight throwing calls in the main FDE; the
  .cold FDE's own LSDA routes the rethrow call to the delete[] +
  chain pad. The six endbr64 stubs at the end of the main FDE
  (0x60b3b3f, 0x60b3b4b, 0x60b3b57, 0x60b3b63, 0x60b3b6f,
  0x60b3b7b) are the landing pads, each jumping into .cold:

    FDE+0x12c..+0x131 operator new, db_paths (0x60b33ac) -> pad
                      0x60b3b7b -> .cold 0x60b31d9 (chain only:
                      statistics, info_log, sst_file_manager,
                      rate_limiter)
    FDE+0x1da..+0x1df _M_create, db_paths element (0x60b345a) ->
                      pad 0x60b3b3f, action 1 (catch) -> .cold
                      0x60b3154 (__cxa_begin_catch, _M_dispose
                      each constructed DbPath string walking
                      FORWARD 0x28 at a time from the buffer
                      start to the first unconstructed element,
                      then __cxa_rethrow) -- the rethrow call
                      itself maps in the .cold LSDA to pad
                      0x60b324d (__cxa_end_catch, raw delete[]
                      of the db_paths buffer, then the chain)
    FDE+0x4a4..+0x4a9 operator new, listeners (0x60b3724) -> pad
                      0x60b3b4b -> .cold 0x60b31b0
                      (write_buffer_manager ctrl release, wal_dir
                      dispose, db_log_dir dispose, db_paths dtor,
                      then the chain)
    FDE+0x76a..+0x76f _M_create, wal_dir (0x60b39ea) -> pad
                      0x60b3b57 -> .cold 0x60b31c8 (db_log_dir
                      dispose, db_paths dtor, then the chain)
    FDE+0x7b2..+0x7b7 _M_create, db_log_dir (0x60b3a32) -> pad
                      0x60b3b63 -> .cold 0x60b31d0 (db_paths
                      vector dtor, then the chain)
    FDE+0x80a..+0x80f _M_create, db_host_id (0x60b3a8a) -> pad
                      0x60b3b6f -> .cold 0x60b3182
                      (file_checksum_gen_factory ctrl,
                      row_cache ctrl, listeners vector dtor
                      0x5d46140, write_buffer_manager ctrl,
                      wal_dir dispose, db_log_dir dispose,
                      db_paths dtor, then the chain)
    FDE+0x8a0..+0x8a5 __throw_bad_array_new_length, db_paths
                      (0x60b3b20) -> pad 0x60b3b7b (chain only)
    FDE+0x8b5..+0x8ba __throw_bad_array_new_length, listeners
                      (0x60b3b35) -> pad 0x60b3b4b
    .cold FDE+0xd0..+0xd5 _Unwind_Resume (0x60b3224) -> NO pad
                      (already inside the cleanup)
    .cold FDE+0xe5..+0xea __cxa_rethrow (0x60b3239) -> pad
                      0x60b324d (__cxa_end_catch, delete[] the
                      db_paths buffer, then the chain at
                      0x60b31d9)

  The chain (.cold 0x60b31d9..0x60b3224) releases, in order, the
  statistics ctrl (+0x60), info_log ctrl (+0x38),
  sst_file_manager ctrl (+0x28) and rate_limiter ctrl (+0x18) --
  each via _Sp_counted_base::_M_release (0x5d350c0) only if
  non-null -- then resumes unwinding. No pad ever touches the
  strings whose _M_create threw (still SSO: _M_create throws
  before the heap pointer is installed, so _M_dispose would be a
  no-op) or compaction_service (+0x278, copied after the guarded
  region). The output is never returned half-built.

  Engine callees: PLT 0x63f0dd0 operator new (db_paths + listeners
  buffers); PLT 0x63f0e10 basic_string::_M_create (4 sites: one
  db_paths element + 3 strings); PLT 0x63f0a60 memcpy (4 sites);
  PLT 0x63f0ec0 __throw_bad_array_new_length (2 sites); PLT
  0x63f0d70 __stack_chk_fail; 0x5d35cb0 vector destructor (117 B;
  census labels the same address
  vector<TableReader::Anchor>::~vector -- the element loop
  strides 0x28, frees a heap string at +0x0 (SSO buffer +0x10)
  and skips the u64 at +0x20, which is exactly DbPath's layout,
  so the two instantiations share the folded address): destroys
  the db_paths vector in the pads; 0x5d46140 vector destructor
  (225 B; census labels the same address
  vector<shared_ptr<const SnapshotImpl>>::~vector -- the element
  loop strides 0x10 and releases each element's ctrl at +0x8,
  which is exactly vector<shared_ptr<EventListener>>'s layout,
  so the two instantiations share the folded address): destroys
  the listeners vector in the db_host_id pad; 0x5d350c0
  _Sp_counted_base::_M_release (133 B, census-bound, cache.o):
  releases each non-null shared_ptr control block in the landing
  pads; PLT 0x63f0db0 basic_string::_M_dispose (the db_log_dir /
  wal_dir strings in the pads, and each constructed DbPath string
  in the .cold catch pad); PLT 0x63f0d80 operator delete[] (the
  db_paths buffer in the rethrow pad 0x60b324d); PLT 0x63f0a50
  _Unwind_Resume; PLT 0x63f0e60 __cxa_begin_catch / 0x63f0e70
  __cxa_rethrow / 0x63f0e80 __cxa_end_catch (the .cold catch pad).

  Callers (whole-.text census, Capstone-validated, census.py):
  exactly 6 direct calls, 0 tail jumps, 0 LEA refs -- the six DB
  open entry points that take a const Options&:
  rocksdb_optimistictransactiondb_open_column_families (0x5d39590,
  site 0x5d396ff, census-bound, c.o),
  rocksdb::DB::Open (0x5e65530, site 0x5e65578, census-bound,
  db_impl_open.o), rocksdb::DB::OpenForReadOnly (0x5e73160, site
  0x5e73442, census-bound, db_impl_readonly.o),
  rocksdb::CompactedDBImpl::Open (0x5e79c30, site 0x5e79d2e,
  census-bound, compacted_db_impl.o), rocksdb::DB::OpenAsSecondary
  (0x5e81f00, site 0x5e81f5a, census-bound, db_impl_secondary.o)
  and rocksdb::DBWithTTL::Open (0x6207740, site 0x6207796,
  census-bound, db_ttl_impl.o).

Layout of DBOptions (0x290 bytes, 93 data members -- pinned by
the disassembly AND upstream options.h v8.1.1, declaration order;
see the FIELD table below and records.json). Identical to the
#6337 default-ctor layout and the #6338 copy-ctor layout; the
Options ctor writes every field the default ctor initializes, at
the same offsets, reading them from the Options' DBOptions
subobject at +0x00.

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM. The binary is read statically (work/hl-node-115.bin);
nothing is executed. Heap addresses (string heap buffers, vector
buffers, shared_ptr control blocks, env) are modelled as
deterministic ids, not real pointers; src and dst are modelled at
the same slot address (THIS_BASE), so their SSO pointers coincide
-- what the copy pins is the values, not the addresses; padding
bytes the ctor never writes are modelled as zero (the binary leaves
them uninitialized). ``make verify`` / ``test`` / ``catalogue-check``
in a tooled environment is still owed upstream.
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
    "re-002-node115-rocksdb-db-options-options-ctor-115" / "cases.tsv"

DBOPTIONS_SIZE = 0x290  # 656
CTOR_START = 0x60B3280
CTOR_END = 0x60B3B87
CTOR_BODY_SHA256 = "7c4707c22eeabfb1ed1d4db475347822af6d2a6bbc6708d3242101d5b4a275c2"
CTOR_SOURCE_SHA256 = "e9bc1ce7a303f7ba21595e4b95abd2edfb009864f03ef9d0072e322674d6eccd"
COLD_START = 0x60B3154
COLD_END = 0x60B327A
COLD_BODY_SHA256 = "f1428783628f1a3844ebb2aadf27fa2d7b07401cab672da980b7c6ec32f6155e"
COLD_SOURCE_SHA256 = "de25ebd703442d1fed35a68fe665eb1c546f9555a4f5cdb8633959601ea0684c"
# The 53-byte main LSDA at .gcc_except_table VA 0x422440 (header
# ff 9b 39 01 30 + 8 call-site entries, all action 0 except the
# db_paths element-copy entry, action 1) + a 7-byte action table
# (01 00) at 0x422475. The 16-byte .cold LSDA at 0x42247c (header
# ff 9b 15 01 0b + 2 entries).
LSDA_VA = 0x422440
LSDA_HEX = ("ff9b390130ac0205fb1100da0305bf1101a40905cb1100ea0e05d71100"
            "b20f05e311008a1005ef1100a01105fb1100b51105cb1100")
LSDA_ACTION_HEX = "0100"
COLD_LSDA_VA = 0x42247c
COLD_LSDA_HEX = "ff9b15010bd001050000e50105f90100"

# Deterministic stand-ins for runtime addresses (model choice, not
# binary-pinned): both objects live at THIS_BASE; heap buffers at
# HEAP_BASE + a stable hash of (role, kind, content).
THIS_BASE = 0x1000
HEAP_BASE = 0x7F0000000000

DEFAULT_HOST_ID = b"__hostname__"

# Members destroyed by each landing pad, in pad order (see the LSDA
# table in the docstring). "db_paths:buffer" is the raw operator
# delete[] in pad A (the DbPath prefix was already disposed inside
# __do_uninit_copy); "db_paths"/"listeners" name the full vector
# destructor (per-element cleanup + buffer free).
PAD_CHAIN = ["statistics", "info_log", "sst_file_manager", "rate_limiter"]
PAD_DESTROYED = {
    "db_paths_new": list(PAD_CHAIN),
    "db_paths_length": list(PAD_CHAIN),
    "db_paths_copy": ["db_paths:buffer"] + list(PAD_CHAIN),
    "db_log_dir": ["db_paths"] + list(PAD_CHAIN),
    "wal_dir": ["db_log_dir", "db_paths"] + list(PAD_CHAIN),
    "listeners_new": ["write_buffer_manager", "wal_dir", "db_log_dir",
                      "db_paths"] + list(PAD_CHAIN),
    "listeners_length": ["write_buffer_manager", "wal_dir", "db_log_dir",
                         "db_paths"] + list(PAD_CHAIN),
    "db_host_id": ["file_checksum_gen_factory", "row_cache", "listeners",
                   "write_buffer_manager", "wal_dir", "db_log_dir",
                   "db_paths"] + list(PAD_CHAIN),
}

# (offset, name, kind, default) -- kind: bool/u8/i32/u32/u64/ptr/
# shared_ptr/string/vector. Order is declaration order (== the
# #6337 default-ctor layout and the #6297 BuildDBOptions copy-map
# order for the shared fields).
FIELDS = [
    (0x00, "create_if_missing", "bool", False),
    (0x01, "create_missing_column_families", "bool", False),
    (0x02, "error_if_exists", "bool", False),
    (0x03, "paranoid_checks", "bool", True),
    (0x04, "flush_verify_memtable_count", "bool", True),
    (0x05, "track_and_verify_wals_in_manifest", "bool", False),
    (0x06, "verify_sst_unique_id_in_manifest", "bool", True),
    (0x08, "env", "ptr", 0),
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

# Shared-pointer field offsets and vector element sizes (binary-pinned).
SHARED_PTR_FIELDS = ("rate_limiter", "sst_file_manager", "info_log",
                     "statistics", "write_buffer_manager", "row_cache",
                     "file_checksum_gen_factory", "compaction_service")
STRING_FIELDS = ("db_log_dir", "wal_dir", "db_host_id")
DB_PATH_ELEM_SIZE = 0x28
LISTENER_ELEM_SIZE = 0x10


class BadAlloc(Exception):
    """std::bad_alloc from operator new or basic_string::_M_create."""


class BadArrayNewLength(Exception):
    """std::bad_array_new_length from a vector byte-size overflow."""


def _heap_id(role, kind, content):
    digest = hashlib.sha256(
        b"options-ctor:" + role.encode() + b":" + kind.encode() + b":" +
        content).digest()
    return HEAP_BASE + (int.from_bytes(digest[:4], "little") & 0xFFFFF)


def _string_heap_id(role, value):
    return _heap_id(role, "str", value)


def _vec_heap_id(role, name, elements_repr):
    return _heap_id(role, "vec:" + name, elements_repr.encode())


def _dbpath_elem_heap_id(role, path):
    return _heap_id(role, "dbpath-str", path)


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


def _put_string(buf, off, value, role):
    """libstdc++ SSO string: ptr at +0, size at +8, buffer at +16."""
    if len(value) <= 15:
        _put_u64(buf, off, THIS_BASE + off + 16)
        _put_u64(buf, off + 8, len(value))
        _put(buf, off + 16, value)
        _put_u8(buf, off + 16 + len(value), 0)
    else:
        _put_u64(buf, off, _string_heap_id(role, value))
        _put_u64(buf, off + 8, len(value))
        _put_u64(buf, off + 16, len(value))


def _put_shared_ptr(buf, off, value):
    if value is None:
        _put(buf, off, b"\0" * 16)
    else:
        _put_u64(buf, off, value["obj"])
        _put_u64(buf, off + 8, value["ctrl"])


def _put_vector(buf, off, name, elements, role):
    if not elements:
        _put(buf, off, b"\0" * 24)
        return None
    size = len(elements) * (DB_PATH_ELEM_SIZE if name == "db_paths"
                            else LISTENER_ELEM_SIZE)
    begin = _vec_heap_id(role, name, repr(elements))
    _put_u64(buf, off, begin)
    _put_u64(buf, off + 8, begin + size)
    _put_u64(buf, off + 16, begin + size)
    return begin


def _scalar_bytes(kind, value):
    if kind in ("bool", "u8"):
        return struct.pack("<B", 1 if value is True else
                           0 if value is False else value)
    if kind == "i32":
        return struct.pack("<i", value)
    if kind == "u32":
        return struct.pack("<I", value & 0xFFFFFFFF)
    if kind == "u64":
        return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
    raise ValueError("not a scalar kind %r" % kind)


def default_fields():
    """The 93 default field values (== the #6337 default ctor)."""
    return {name: default for _off, name, _kind, default in FIELDS}


def build_image(fields, role):
    """Build the 656-byte image of a DBOptions with `fields`.

    role selects the heap-id namespace ("src" or "dst"): the same
    string/vector content gets a different heap id in each role,
    because the copy allocates fresh buffers. Returns
    (image_bytes, heap_dict) where heap_dict maps heap ids to the
    bytes stored there (heap strings, vector element buffers).
    """
    image = bytearray(DBOPTIONS_SIZE)
    heap = {}
    for off, name, kind, _default in FIELDS:
        value = fields[name]
        if kind in ("bool", "u8", "i32", "u32", "u64"):
            _put(image, off, _scalar_bytes(kind, value))
        elif kind == "ptr":
            _put_u64(image, off, value or 0)
        elif kind == "shared_ptr":
            _put_shared_ptr(image, off, value)
        elif kind == "string":
            _put_string(image, off, value, role)
            if len(value) > 15:
                heap[_string_heap_id(role, value)] = value
        elif kind == "vector":
            if name == "db_paths":
                begin = _put_vector(image, off, name, value, role)
                if begin is not None:
                    elems = bytearray()
                    for i, elem in enumerate(value):
                        path = elem["path"]
                        ebuf = bytearray(DB_PATH_ELEM_SIZE)
                        # The element string lives inside the vector
                        # buffer: its SSO pointer is the element's own
                        # buffer (begin + i*0x28 + 16), not THIS_BASE.
                        if len(path) <= 15:
                            _put_u64(ebuf, 0, begin + i * DB_PATH_ELEM_SIZE + 16)
                            _put_u64(ebuf, 8, len(path))
                            _put(ebuf, 16, path)
                            _put_u8(ebuf, 16 + len(path), 0)
                        else:
                            heap[_dbpath_elem_heap_id(role, path)] = path
                            _put_u64(ebuf, 0,
                                     _dbpath_elem_heap_id(role, path))
                            _put_u64(ebuf, 8, len(path))
                            _put_u64(ebuf, 16, len(path))
                        _put_u64(ebuf, 0x20, elem["target_size"])
                        elems += ebuf
                    heap[begin] = bytes(elems)
            else:  # listeners: shared_ptr elements
                begin = _put_vector(image, off, name, value, role)
                if begin is not None:
                    elems = bytearray()
                    for elem in value:
                        ebuf = bytearray(LISTENER_ELEM_SIZE)
                        _put_shared_ptr(ebuf, 0, elem)
                        elems += ebuf
                    heap[begin] = bytes(elems)
    return bytes(image), heap


def _copy_shared(value):
    """The __shared_count copy: same object + ctrl, refcount +1."""
    if value is None:
        return None
    return {"obj": value["obj"], "ctrl": value["ctrl"],
            "refcount": value["refcount"] + 1}


def copy_db_options(src_fields, fail_at=None, fail_index=None):
    """Run the DBOptions::DBOptions(const Options&) model.

    The source is an Options; its DBOptions subobject sits at +0x00
    (Options inherits DBOptions first), so the same 93-field map as
    the copy ctor applies. fail_at models a throw at one of the
    eight throwing sites ("db_paths_new", "db_paths_copy",
    "db_log_dir", "wal_dir", "listeners_new", "db_host_id",
    "db_paths_length", "listeners_length"). On a throw, raises
    BadAlloc or BadArrayNewLength after recording the landing pad's
    destruction list on the exception (``exc.destroyed``); for
    "db_paths_copy" ``exc.prefix_disposed`` counts the DbPath
    elements whose strings the .cold catch pad disposed (walking
    forward 0x28 at a time) before rethrowing. The shared_ptr
    copies are the inlined addl/lock-addl bumps, not calls to the
    __shared_count helper -- the model pins the refcount +1 either
    way.

    Returns {"fields", "image", "image_sha256", "heap", "destroyed"}
    on success. The destination's vectors and heap strings are fresh
    allocations (new heap ids); shared_ptrs share their control
    blocks with refcount +1.
    """
    src_image, _src_heap = build_image(src_fields, "src")
    dst_fields = {}
    # Binary order: scalars + shared ptr words first (the plain mov
    # copies, with the inlined refcount bumps), then db_paths,
    # db_log_dir, wal_dir, the remaining scalars,
    # write_buffer_manager, listeners, the tail scalars,
    # file_checksum_gen_factory, db_host_id, compaction_service.
    # The model below follows that order so a fail_at lands on the
    # same constructed prefix the LSDA pads see.
    for off, name, kind, _default in FIELDS:
        value = src_fields[name]
        if kind in ("bool", "u8", "i32", "u32", "u64", "ptr"):
            dst_fields[name] = value
        elif kind == "shared_ptr":
            dst_fields[name] = _copy_shared(value)
        elif kind == "string":
            dst_fields[name] = value
        elif kind == "vector":
            if name == "listeners":
                # Each listener element is a shared_ptr: the loop's
                # inlined addl/lock-addl bumps share its control
                # block (refcount +1).
                dst_fields[name] = [_copy_shared(e) for e in value]
            else:
                # DbPath elements are deep-copied (new string buffers).
                dst_fields[name] = [dict(e) for e in value]
    # Re-apply the throwing sites in binary order, so the exception
    # carries the right pad list.
    if fail_at in ("db_paths_length",):
        err = BadArrayNewLength(
            "db_paths byte size exceeds 0x7ffffffffffffff8")
        err.destroyed = list(PAD_DESTROYED["db_paths_length"])
        raise err
    if fail_at == "db_paths_new":
        err = BadAlloc("operator new (db_paths)")
        err.destroyed = list(PAD_DESTROYED["db_paths_new"])
        raise err
    if fail_at == "db_paths_copy":
        n = len(src_fields["db_paths"])
        k = n // 2 if fail_index is None else fail_index
        err = BadAlloc("basic_string::_M_create (db_paths element %d)" % k)
        # The .cold catch pad disposes the constructed prefix walking
        # forward from the buffer start (unlike __do_uninit_copy's
        # pad in the copy ctor, which walked backward); the count is
        # the same either way.
        err.destroyed = list(PAD_DESTROYED["db_paths_copy"])
        err.prefix_disposed = k
        raise err
    if fail_at == "db_log_dir":
        err = BadAlloc("basic_string::_M_create (db_log_dir)")
        err.destroyed = list(PAD_DESTROYED["db_log_dir"])
        raise err
    if fail_at == "wal_dir":
        err = BadAlloc("basic_string::_M_create (wal_dir)")
        err.destroyed = list(PAD_DESTROYED["wal_dir"])
        raise err
    if fail_at in ("listeners_length",):
        err = BadArrayNewLength(
            "listeners byte size exceeds 0x7ffffffffffffff0")
        err.destroyed = list(PAD_DESTROYED["listeners_length"])
        raise err
    if fail_at == "listeners_new":
        err = BadAlloc("operator new (listeners)")
        err.destroyed = list(PAD_DESTROYED["listeners_new"])
        raise err
    if fail_at == "db_host_id":
        err = BadAlloc("basic_string::_M_create (db_host_id)")
        err.destroyed = list(PAD_DESTROYED["db_host_id"])
        raise err
    dst_image, dst_heap = build_image(dst_fields, "dst")
    return {
        "fields": dst_fields,
        "image": dst_image,
        "image_sha256": hashlib.sha256(dst_image).hexdigest(),
        "heap": dst_heap,
        "destroyed": None,
    }


# ---------------------------------------------------------------- cases

# The 6 validated caller sites (see census.py / callers.tsv): every
# DB open entry point that takes a const Options&.
CALLERS = [
    (0x5D396FF, 0x5D39590,
     "rocksdb_optimistictransactiondb_open_column_families"),
    (0x5E65578, 0x5E65530, "rocksdb::DB::Open"),
    (0x5E73442, 0x5E73160, "rocksdb::DB::OpenForReadOnly"),
    (0x5E79D2E, 0x5E79C30, "rocksdb::CompactedDBImpl::Open"),
    (0x5E81F5A, 0x5E81F00, "rocksdb::DB::OpenAsSecondary"),
    (0x6207796, 0x6207740, "rocksdb::DBWithTTL::Open"),
]


def _jsonable(value):
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _shared(obj_id, ctrl_id, refcount=1):
    return {"obj": obj_id, "ctrl": ctrl_id, "refcount": refcount}


def _variant_value(name, kind, default, i):
    """A deterministic non-default value for field `name` (case i)."""
    if kind == "bool":
        return not default
    if kind == "u8":
        return (default + 7) % 256 or 3
    if kind == "i32":
        return default - 1000 if default > (1 << 30) else default + 1000
    if kind == "u32":
        return default + 1000
    if kind == "u64":
        return default + 1000 if default < (1 << 63) else default - 1000
    if kind == "ptr":
        return 0x7F0000001000 + i * 0x100 if name == "env" else 0x5000 + i
    if kind == "shared_ptr":
        return _shared(0x3000 + i * 0x100, 0x4000 + i * 0x100, 2)
    if kind == "string":
        pool = [b"short", b"a" * 16, b"longer-path-value-0123456789",
                b"", b"node-115.example.com"]
        return pool[i % len(pool)]
    if kind == "vector":
        if name == "db_paths":
            pool = [
                [{"path": b"/data/db1", "target_size": 1 << 30}],
                [{"path": b"a" * 20, "target_size": 5},
                 {"path": b"b", "target_size": 0}],
                [{"path": b"", "target_size": 7}],
            ]
            return pool[i % len(pool)]
        pool = [
            [_shared(0x3100, 0x4100, 1)],
            [_shared(0x3200, 0x4200, 3), _shared(0x3300, 0x4300, 1)],
        ]
        return pool[i % len(pool)]
    raise ValueError("unknown kind %r" % kind)


def _source_with_overrides(overrides):
    fields = default_fields()
    fields.update(overrides)
    return fields


def run_case(inputs):
    """Run one case: copy (or throw) and return expected outputs."""
    group = inputs["group"]
    if group == "fields":
        name = inputs["field"]
        off, kind, default = FIELD_BY_NAME[name]
        src = _source_with_overrides(
            {name: _variant_value(name, kind, default, inputs["case_n"])})
        result = copy_db_options(src)
        probe = inputs["probe"]
        if probe == "image_hash":
            return {"image_sha256": result["image_sha256"]}
        if probe == "value":
            return {"field": name,
                    "value": _jsonable(result["fields"][name])}
        if probe == "bytes":
            size = {"bool": 1, "u8": 1, "i32": 4, "u32": 4, "u64": 8,
                    "ptr": 8, "shared_ptr": 16, "string": 32,
                    "vector": 24}[kind]
            return {"field": name,
                    "bytes_hex": result["image"][off:off + size].hex()}
        raise ValueError("unknown probe %r" % probe)
    if group == "containers":
        src = _source_with_overrides(inputs["overrides"])
        result = copy_db_options(src)
        heap_hex = {hex(k): v.hex() for k, v in
                    sorted(result["heap"].items())}
        return {
            "image_sha256": result["image_sha256"],
            "db_paths": _jsonable(result["fields"]["db_paths"]),
            "listeners": _jsonable(result["fields"]["listeners"]),
            "db_log_dir": _jsonable(result["fields"]["db_log_dir"]),
            "wal_dir": _jsonable(result["fields"]["wal_dir"]),
            "db_host_id": _jsonable(result["fields"]["db_host_id"]),
            "heap_hex": heap_hex,
        }
    if group == "throw":
        src = _source_with_overrides(inputs["overrides"])
        try:
            copy_db_options(src, fail_at=inputs["fail_at"],
                            fail_index=inputs.get("fail_index"))
        except BadAlloc as err:
            out = {"error": "BadAlloc", "message": str(err),
                   "destroyed": err.destroyed}
            if hasattr(err, "prefix_disposed"):
                out["prefix_disposed"] = err.prefix_disposed
            return out
        except BadArrayNewLength as err:
            return {"error": "BadArrayNewLength", "message": str(err),
                    "destroyed": err.destroyed}
        return {"error": None, "destroyed": None}
    if group == "bindings":
        host_id = bytes.fromhex(inputs["host_id_hex"]) \
            if inputs.get("host_id_hex") else DEFAULT_HOST_ID
        src = _source_with_overrides(
            {"db_host_id": host_id, "env": inputs.get("env_id", 0)})
        result = copy_db_options(src)
        return {
            "caller_site": inputs["caller_site"],
            "image_sha256": result["image_sha256"],
            "host_id_kind": "sso" if len(host_id) <= 15 else "heap",
        }
    raise ValueError("unknown group %r" % group)


_PATH_POOL = [
    b"", b"a", b"/var/lib/db", b"0123456789abcde", b"0123456789abcdef",
    b"0123456789abcdefg", b"/very/long/path/to/a/rocksdb/database/dir",
    b"with-dash_and.dot", b"x" * 40,
]
_LISTENER_POOL = [
    _shared(0x3100, 0x4100, 1),
    _shared(0x3200, 0x4200, 3),
    _shared(0x3300, 0x4300, 2),
]
_STR_POOL = [
    b"", b"a", b"short", b"0123456789abcde", b"0123456789abcdef",
    b"0123456789abcdefg", b"/var/log/rocksdb", b"a" * 32, b"db-host-01",
]


def _gen_group(rng, group, n):
    rows = []
    for i in range(n):
        case_id = "%s-%03d" % (group, i)
        inputs = {"case_id": case_id, "group": group}
        if group == "fields":
            name = FIELDS[i % len(FIELDS)][1]
            probe = ["value", "bytes", "image_hash"][i % 3]
            inputs.update({"field": name, "probe": probe, "case_n": i})
        elif group == "containers":
            overrides = {}
            mode = i % 6
            if mode in (0, 1):
                k = rng.choice([1, 2, 3])
                overrides["db_paths"] = [
                    {"path": rng.choice(_PATH_POOL),
                     "target_size": rng.choice([0, 1, 1 << 30, 1 << 40])}
                    for _ in range(k)]
            if mode in (0, 2):
                k = rng.choice([1, 2, 3])
                overrides["listeners"] = [
                    dict(rng.choice(_LISTENER_POOL)) for _ in range(k)]
            if mode in (0, 3):
                overrides["db_log_dir"] = rng.choice(_STR_POOL)
                overrides["wal_dir"] = rng.choice(_STR_POOL)
            if mode in (0, 4):
                overrides["db_host_id"] = rng.choice(_STR_POOL)
            if mode in (0, 5):
                for name in SHARED_PTR_FIELDS:
                    if rng.random() < 0.5:
                        overrides[name] = _shared(
                            0x3000 + rng.randrange(0x100),
                            0x4000 + rng.randrange(0x100),
                            rng.choice([1, 2, 5]))
            overrides.setdefault("db_paths", [])
            overrides.setdefault("listeners", [])
            inputs.update({"overrides": _jsonable(overrides)})
            # run_case needs native values, not the jsonable form.
            inputs["overrides"] = overrides
        elif group == "throw":
            fail_ats = ["db_paths_new", "db_paths_copy", "db_log_dir",
                        "wal_dir", "listeners_new", "db_host_id",
                        "db_paths_length", "listeners_length"]
            fail_at = fail_ats[i % len(fail_ats)]
            overrides = {
                "db_paths": [{"path": b"0123456789abcdefg", "target_size": 9},
                             {"path": b"s", "target_size": 1},
                             {"path": b"0123456789abcdef0123456789abcdef",
                              "target_size": 2}],
                "listeners": [_shared(0x3100, 0x4100, 1),
                              _shared(0x3200, 0x4200, 2)],
                "db_log_dir": b"/var/log/rocksdb-long",
                "wal_dir": b"/var/wal/rocksdb-long",
                "db_host_id": b"db-host-01.example.com",
                "rate_limiter": _shared(0x3000, 0x4000, 1),
                "statistics": _shared(0x3010, 0x4010, 4),
                "write_buffer_manager": _shared(0x3020, 0x4020, 1),
                "row_cache": _shared(0x3030, 0x4030, 1),
                "file_checksum_gen_factory": _shared(0x3040, 0x4040, 1),
            }
            inputs.update({"fail_at": fail_at, "overrides": overrides})
            if fail_at == "db_paths_copy":
                inputs["fail_index"] = 1
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
        # Store the jsonable form in the ledger.
        ledger_inputs = dict(inputs)
        if "overrides" in ledger_inputs:
            ledger_inputs["overrides"] = _jsonable(
                ledger_inputs["overrides"])
        rows.append((group, case_id, ledger_inputs, expected))
    return rows


def write_cases():
    all_rows = []
    for gi, group in enumerate(
            ["fields", "containers", "throw", "bindings"]):
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


def _unjsonable(value):
    if isinstance(value, dict) and set(value) == {"bytes_hex"}:
        return bytes.fromhex(value["bytes_hex"])
    if isinstance(value, dict):
        return {k: _unjsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unjsonable(v) for v in value]
    return value


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
        if "overrides" in inputs:
            inputs["overrides"] = _unjsonable(inputs["overrides"])
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
        if addr <= va < addr + size:
            return off + (va - addr)
    raise ValueError("VA %#x not in a mapped section" % va)


def _read_va(data, secs, va, size):
    return data[_va2off(secs, va):_va2off(secs, va) + size]


def _fde_hashes(data, secs):
    """Body + source hashes for the main and .cold FDEs, from the binary."""
    census_path = REPO / "research" / "work-items" / \
        "RE-002-node115-vendor-census" / "census.json"
    census = json.loads(census_path.read_text())
    recs = census if isinstance(census, list) else census.get("records", [])
    by_start = {r["start"]: r for r in recs}
    tva, toff, _tsize = secs[".text"]
    out = {}
    for prefix, start, end in (("ctor", CTOR_START, CTOR_END),
                               ("cold", COLD_START, COLD_END)):
        body = bytearray(data[toff + (start - tva):
                              toff + (end - tva)])
        out[prefix + "_body"] = hashlib.sha256(bytes(body)).hexdigest()
        rec = by_start[start]
        for rel in rec["relocations"]:
            off = rel["offset"]
            if rel.get("relaxation") == "gotpcrelx-mov-lea":
                body[off - 2] = 0x8B  # restore mov opcode
            body[off:off + rel["width"]] = b"\0" * rel["width"]
        out[prefix + "_source"] = hashlib.sha256(bytes(body)).hexdigest()
        out[prefix + "_relocations"] = len(rec["relocations"])
        out[prefix + "_kinds"] = sorted(set(r["kind"] for r in rec["relocations"]))
    return out


def _caller_scan(data, secs):
    """Whole-.text E8/E9/LEA scan for the Options ctor, Capstone-validated."""
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


_REG_SIZE = {"al": 1, "bl": 1, "cl": 1, "dl": 1, "sil": 1, "dil": 1,
             "ax": 2, "bx": 2, "cx": 2, "dx": 2, "si": 2, "di": 2,
             "eax": 4, "ebx": 4, "ecx": 4, "edx": 4, "esi": 4, "edi": 4,
             "rax": 8, "rbx": 8, "rcx": 8, "rdx": 8, "rsi": 8, "rdi": 8,
             "r8": 8, "r9": 8, "r10": 8, "r11": 8, "r12": 8, "r13": 8,
             "r14": 8, "r15": 8, "r8d": 4, "r9d": 4, "r10d": 4, "r11d": 4,
             "r12d": 4, "r13d": 4, "r14d": 4, "r15d": 4,
             "r8w": 2, "r9w": 2, "r10w": 2, "r11w": 2, "r12w": 2,
             "r13w": 2, "r14w": 2, "r15w": 2,
             "r8b": 1, "r9b": 1, "r10b": 1, "r11b": 1, "r12b": 1,
             "r13b": 1, "r14b": 1, "r15b": 1}


def _copy_map(data, secs):
    """Parse the objdump of the FDE into value-copy ranges.

    Returns {"src_ranges", "dst_ranges", "calls", "plain_addl",
    "lock_addl"} where the ranges are (start, size) byte ranges of
    the DBOptions image read from the source (%rbp, plus the first
    stores via (%rsi) with NO prologue bump -- unlike the copy ctor,
    this FDE does not bump rsi/rdi by +0x18) and written to the
    destination (%rbx / %rdi), calls counts the engine-callee
    sites, and plain_addl / lock_addl count the inlined shared_ptr
    refcount bumps (plain `addl $0x1,0x8(...)` vs `lock addl`).
    """
    out = subprocess.check_output(
        ["objdump", "-d", "--start-address=%#x" % CTOR_START,
         "--stop-address=%#x" % CTOR_END, str(_bin_path())]).decode()
    src_ranges, dst_ranges, calls = [], [], {}
    plain_addl = lock_addl = 0

    def _off(text):
        # "-0x18" -> -0x18, "0x70" -> 0x70
        return int(text, 16) if not text.startswith("-") else \
            -int(text[1:], 16)

    for line in out.splitlines():
        m = re.search(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t(.*)$", line)
        if not m:
            continue
        insn = m.group(1).strip()
        cm = re.match(r"call\s+([0-9a-f]+)", insn)
        if cm:
            calls[cm.group(1)] = calls.get(cm.group(1), 0) + 1
            continue
        # objdump pads the mnemonic column, so normalise spaces
        # before matching the inlined refcount bumps.
        flat = " ".join(insn.split())
        if "addl $0x1,0x8(" in flat:
            if flat.startswith("lock addl"):
                lock_addl += 1
            else:
                plain_addl += 1
            continue
        # movdqu / movups 16-byte moves.
        mm = re.match(r"movdqu\s+(-?0x[0-9a-f]+)\(%rsi\),%xmm\d", insn)
        if mm:
            src_ranges.append((_off(mm.group(1)), 16))
            continue
        mm = re.match(r"movdqu\s+0x([0-9a-f]+)\(%rbp\),%xmm\d", insn)
        if mm:
            src_ranges.append((int(mm.group(1), 16), 16))
            continue
        mm = re.match(r"movups\s+%xmm\d,(-?0x[0-9a-f]+)\(%rdi\)", insn)
        if mm:
            dst_ranges.append((_off(mm.group(1)), 16))
            continue
        mm = re.match(r"movups\s+%xmm\d,0x([0-9a-f]+)\(%rbx\)", insn)
        if mm:
            dst_ranges.append((int(mm.group(1), 16), 16))
            continue
        # Scalar loads from the source (bare (%rsi) is offset 0: no
        # prologue bump in this FDE).
        mm = re.match(
            r"mov(?:zbl|zwl|zbw|l|q)?\s+\(%rsi\),%(r?\w+)", insn)
        if mm:
            size = _REG_SIZE.get(mm.group(1), 8)
            if "movzb" in insn or "movzw" in insn:
                size = 1 if "movzb" in insn else 2
            src_ranges.append((0, size))
            continue
        mm = re.match(
            r"mov(?:zbl|zwl|zbw|l|q)?\s+(-?0x[0-9a-f]+)\(%rsi\),%(r?\w+)",
            insn)
        if mm:
            size = _REG_SIZE.get(mm.group(2), 8)
            if "movzb" in insn or "movzw" in insn:
                size = 1 if "movzb" in insn else 2
            src_ranges.append((_off(mm.group(1)), size))
            continue
        mm = re.match(
            r"mov(?:zbl|zwl|zbw|l|q)?\s+0x([0-9a-f]+)\(%rbp\),%(r?\w+)",
            insn)
        if mm:
            size = _REG_SIZE.get(mm.group(2), 8)
            if "movzb" in insn or "movzw" in insn:
                size = 1 if "movzb" in insn else 2
            src_ranges.append((int(mm.group(1), 16), size))
            continue
        # Scalar stores to the destination.
        mm = re.match(
            r"mov(?:b|l|q)?\s+%([a-z0-9]+),\(%rdi\)", insn)
        if mm:
            dst_ranges.append((0, _REG_SIZE.get(mm.group(1), 8)))
            continue
        mm = re.match(
            r"mov(?:b|l|q)?\s+%([a-z0-9]+),(-?0x[0-9a-f]+)\(%rdi\)", insn)
        if mm:
            dst_ranges.append((_off(mm.group(2)),
                               _REG_SIZE.get(mm.group(1), 8)))
            continue
        mm = re.match(
            r"mov(?:b|l|q)?\s+%([a-z0-9]+),0x([0-9a-f]+)\(%rbx\)", insn)
        if mm:
            dst_ranges.append((int(mm.group(2), 16),
                               _REG_SIZE.get(mm.group(1), 8)))
            continue
    return {"src_ranges": src_ranges, "dst_ranges": dst_ranges,
            "calls": calls, "plain_addl": plain_addl,
            "lock_addl": lock_addl}


def _covered(ranges, off, size):
    covered = [False] * size
    for start, length in ranges:
        lo = max(0, start - off)
        hi = min(size, start + length - off)
        for k in range(lo, hi):
            covered[k] = True
    return all(covered)


def live_engine_check():
    """Live check against work/hl-node-115.bin. 13 legs."""
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
        hashes["ctor_source"][:12] + " (%d relocs, kinds %s)" % (
            hashes["ctor_relocations"], hashes["ctor_kinds"]))
    leg("cold_body_hash", hashes["cold_body"] == COLD_BODY_SHA256,
        hashes["cold_body"][:12])
    leg("cold_source_hash", hashes["cold_source"] == COLD_SOURCE_SHA256,
        hashes["cold_source"][:12] + " (%d relocs, kinds %s)" % (
            hashes["cold_relocations"], hashes["cold_kinds"]))

    lsda = _read_va(data, secs, LSDA_VA, 53)
    leg("lsda_bytes", lsda.hex() == LSDA_HEX,
        "53 bytes at %#x" % LSDA_VA)
    action = _read_va(data, secs, LSDA_VA + 53, 2)
    leg("lsda_action_table", action.hex() == LSDA_ACTION_HEX,
        "2 bytes at %#x" % (LSDA_VA + 53))
    cold_lsda = _read_va(data, secs, COLD_LSDA_VA, 16)
    leg("cold_lsda_bytes", cold_lsda.hex() == COLD_LSDA_HEX,
        "16 bytes at %#x" % COLD_LSDA_VA)

    scan = _caller_scan(data, secs)
    got_sites = sorted(s for s, _k in scan["sites"])
    want_sites = sorted(s for s, _f, _n in CALLERS)
    leg("caller_census", got_sites == want_sites and not scan["lea_refs"],
        "%d calls, %d lea" % (len(got_sites), len(scan["lea_refs"])))

    cmap = _copy_map(data, secs)
    calls = cmap["calls"]
    want_calls = {"63f0dd0": 2, "63f0e10": 4, "63f0a60": 4,
                  "63f0ec0": 2, "63f0d70": 1}
    call_ok = all(calls.get(k, 0) == v for k, v in want_calls.items())
    leg("engine_calls", call_ok,
        "; ".join("%s=%d/%d" % (k, calls.get(k, 0), v)
                  for k, v in want_calls.items()))
    leg("refcount_bumps", cmap["plain_addl"] == 9 and
        cmap["lock_addl"] == 9,
        "plain=%d/9 lock=%d/9" % (cmap["plain_addl"], cmap["lock_addl"]))
    # Every scalar / raw-ptr / shared_ptr word is copied verbatim.
    missing = []
    for off, name, kind, _d in FIELDS:
        if kind in ("bool", "u8", "i32", "u32", "u64"):
            size = {"bool": 1, "u8": 1, "i32": 4, "u32": 4,
                    "u64": 8}[kind]
        elif kind in ("ptr", "shared_ptr"):
            size = 8
        else:
            continue  # strings/vectors: inlined _M_construct / new
        if not _covered(cmap["src_ranges"], off, size):
            missing.append("src:%s+%#x" % (name, off))
        if not _covered(cmap["dst_ranges"], off, size):
            missing.append("dst:%s+%#x" % (name, off))
    leg("copy_map_coverage", not missing,
        "0 missing" if not missing else "; ".join(missing[:8]))

    # Copying the defaults yields the defaults byte-for-byte (all
    # SSO/empty/null in the default image, so no heap id differs).
    default_image, _h = build_image(default_fields(), "src")
    copied = copy_db_options(default_fields())
    leg("copy_of_defaults",
        copied["image"] == default_image,
        "sha256 %s" % copied["image_sha256"][:12])

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
        copied = copy_db_options(default_fields())
        print("copy-of-defaults sha256: %s" % copied["image_sha256"])
        print("fields: %d" % len(default_fields()))
        print("callers: %d" % len(CALLERS))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
