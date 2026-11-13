# RE-002: reconstruct node #115 `rocksdb::DBOptions::DBOptions()`

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `DBOptions::DBOptions()` -- the default constructor that
every DB open, options query and options change runs first
(BuildDBOptions, open PR #6297, calls it at 0x60c2e37 before copying
the 91 fields) to default-construct a 0x290-byte `DBOptions` (93 data
members). 2,400 byte-checked cases; 31 tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). Two FDEs, census-bound:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::DBOptions::DBOptions()` | `0x60b2db0..0x60b3154` | 932 B | `ce915d9aef5365c5b53ced3ddb236fe016821c8b6eb98e1918d87fa4463d9462` | `d7ece8bd5f9dc186-options.o`, `_ZN7rocksdb9DBOptionsC1Ev` |
| `rocksdb::DBOptions::DBOptions().cold` | `0x60b2cf0..0x60b2da5` | 181 B | `108108c95e8d7ba335f4f8b68250f91486a57fd243c2af86dfab53e6d655aa34` | `d7ece8bd5f9dc186-options.o`, `_ZN7rocksdb9DBOptionsC2Ev.cold` |

The source hashes reproduce exactly by zeroing the census
relocations (15 / 13, kinds 2/4 -- the one kind-42 entry at main-FDE
offset 642 is a GOTPCRELX mov->lea relaxation, restored to the mov
opcode first, as in the #6222 packet):
`433788f7527295b9daf8da46d4cc534c8f23eb45844793c0050680506bcc019b` /
`dac8b44e521f5d7e47ca461b4dbba8c330a4f99aadfdc3a5c89262095cf32578`.
This supersedes the oracle note the #6297 `BuildDBOptions` packet
left for its first call: the full ctor body is now pinned field by
field, including the two fields BuildDBOptions never writes
(`write_dbid_to_manifest` +0x21a = false, `compaction_service`
+0x278..+0x287 = nullptr).

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `DBOptions::DBOptions()` -- this in `rdi` (= `rbx`);
`r12` = this+0x260 (the `db_host_id` SSO buffer). Stack canary at
`rsp+8`. In binary order:

1. Leading bools: `movl $0x1000000,(%rdi)` + `mov %dx,0x4(%rdi)`
   (dx = 1) + `movb $0x1,0x6(%rdi)` write +0x00..0x06 as
   `00 00 00 01 01 00 01`: `create_if_missing` = false,
   `create_missing_column_families` = false, `error_if_exists` =
   false, `paranoid_checks` = true, `flush_verify_memtable_count`
   = true, `track_and_verify_wals_in_manifest` = false,
   `verify_sst_unique_id_in_manifest` = true.
2. `env` (+0x08) = `rocksdb::Env::Default()` 0x5fe2860
   (census-bound, `3d290f9c0dad3aa8-env_posix.o`) -- the only call
   before any member is constructed (LSDA site 0 has no landing
   pad).
3. `info_log_level` (+0x40) = 1 (`INFO_LEVEL`; upstream builds
   NDEBUG, where the default is `INFO_LEVEL`).
4. One 8-byte load from `.rodata` 0x458e70 (`0x00000010ffffffff`)
   stored at +0x44: `max_open_files` = -1,
   `max_file_opening_threads` = 16 -- the two adjacent i32s share
   one load.
5. `rate_limiter` (+0x10), `sst_file_manager` (+0x20), `info_log`
   (+0x30), `statistics` (+0x58) nulled as 16-byte pairs;
   `use_fsync` (+0x68) = false.
6. `db_paths` (+0x70) zeroed (begin/end via `movups %xmm0`, cap
   via `movq $0x0`); `db_log_dir` (+0x88) and `wal_dir` (+0xa8)
   SSO-empty: the ptr word is LEA'd to the string's own SSO buffer
   (+0x98 / +0xb8), size 0, NUL at buffer[0].
7. `delete_obsolete_files_period_micros` (+0xc8) = 21600000000
   (6 hours in microseconds, `movabs $0x50775d800`).
8. One 8-byte load from `.rodata` 0x4594f0
   (`0xffffffff00000002`) at +0xd0: `max_background_jobs` = 2,
   `max_background_compactions` = -1.
9. `movabs $0xffffffff00000001` at +0xd8:
   `max_subcompactions` = 1, `max_background_flushes` = -1.
10. `movups %xmm0` at +0xe0 (`max_log_file_size` = 0,
    `log_file_time_to_roll` = 0) and +0x110 (`WAL_ttl_seconds` =
    0, `WAL_size_limit_MB` = 0).
11. `max_manifest_file_size` (+0x100) = 1073741824 (1 GiB);
    `table_cache_numshardbits` (+0x108) = 6.
12. `manifest_preallocation_size` (+0x120) = 4194304 (4 MiB).
13. `movl $0x0` at +0x128: `allow_mmap_reads`,
    `allow_mmap_writes`, `use_direct_reads`,
    `use_direct_io_for_flush_and_compaction` all false.
14. One 8-byte load from `.rodata` 0x459148
    (`0x0000025800000258`) at +0x130: `stats_dump_period_sec` =
    600, `stats_persist_period_sec` = 600.
15. `mov %cx,0x12c(%rbx)` with cx = 0x101: `allow_fallocate` =
    true, `is_fd_close_on_exec` = true.
16. `persist_stats_to_disk` (+0x138) = false;
    `stats_history_buffer_size` (+0x140) = 1048576 (1 MiB).
17. `advise_random_on_open` (+0x148) = true;
    `db_write_buffer_size` (+0x150) = 0.
18. `access_hint_on_compaction_start` (+0x168) = 1 (NORMAL).
19. `movdqa` from `.rodata` 0x451490, `movups %xmm1` at +0x170:
    `compaction_readahead_size` = 0,
    `random_access_max_buffer_size` = 1048576 (1 MiB).
20. `writable_file_max_buffer_size` (+0x180) = 1048576 (1 MiB);
    `use_adaptive_mutex` (+0x188) = false.
21. `movups %xmm0` at +0x190: `bytes_per_sync` = 0,
    `wal_bytes_per_sync` = 0; `strict_bytes_per_sync` (+0x1a0) =
    false.
22. `listeners` (+0x1a8) zeroed (begin/end via `movups %xmm0`,
    cap via `movq $0x0`).
23. `enable_thread_tracking` (+0x1c0) = false;
    `delayed_write_rate` (+0x1c8) = 0.
24. `movl $0x1010000` at +0x1d0: `enable_pipelined_write` =
    false, `unordered_write` = false,
    `allow_concurrent_memtable_write` = true,
    `enable_write_thread_adaptive_yield` = true.
25. `movdqa` from `.rodata` 0x4517a0, `movups %xmm1` at +0x1d8:
    `max_write_batch_group_size_bytes` = 1048576 (1 MiB),
    `write_thread_max_yield_usec` = 100.
26. `write_thread_slow_yield_usec` (+0x1e8) = 3.
27. `movl $0x20000` at +0x1f0: `skip_stats_update_on_db_open` =
    false, `skip_checking_sst_file_sizes_on_db_open` = false,
    `wal_recovery_mode` = 2 (`kPointInTimeRecovery`), `allow_2pc`
    = false.
28. `row_cache` (+0x1f8) null pair; `wal_filter` (+0x208) =
    nullptr.
29. `movq $0x0` at +0x210: `fail_if_options_file_error`,
    `dump_malloc_stats`, `avoid_flush_during_recovery`,
    `avoid_flush_during_shutdown`, `allow_ingest_behind`,
    `two_write_queues`, `manual_wal_flush` all false,
    `wal_compression` = 0 (`kNoCompression`).
30. `mov %si,0x218(%rbx)` with si = 0: `atomic_flush` = false,
    `avoid_unnecessary_blocking_io` = false.
31. `write_dbid_to_manifest` (+0x21a) = false;
    `log_readahead_size` (+0x220) = 0.
32. `file_checksum_gen_factory` (+0x228) null pair;
    `best_efforts_recovery` (+0x238) = false.
33. `max_bgerror_resume_count` (+0x23c) = INT_MAX;
    `bgerror_resume_retry_interval` (+0x240) = 1000000 (1 s in
    microseconds).
34. `allow_data_in_errors` (+0x248) = false.
35. `db_host_id` (+0x250) from the `.data` global char* at
    0x64fee88 (`R_X86_64_RELATIVE` addend 0x4342d1) pointing at
    the `.rodata` literal `"__hostname__"` (12 bytes, upstream
    `kHostnameForDbHostId`): `strlen`, SSO when len <= 15 (ptr =
    this+0x260, size = len, `memcpy`, NUL at buf[len]), heap via
    `_M_create` + `memcpy` when len > 15; a NULL global throws
    `std::logic_error` ("basic_string: construction from null is
    not valid", `.rodata` 0x963298). The only other read of that
    global in `.text` is `ReifyDbHostIdProperty` at 0x616d0ab (a
    `strlen` length check); no code ever writes it, so the default
    is pinned.
36. `checksum_handoff_file_types` (+0x270) = 0 (empty
    `FileTypeSet`); `compaction_service` (+0x278) null pair.
37. `mov $0x101,%eax` / `mov %ax,0x288(%rbx)`:
    `lowest_used_cache_tier` = 1 (`kNonVolatileBlockTier`),
    `enforce_single_del_contracts` = true.

The `.cold` landing pad (0x60b2cf0..0x60b2da5, LSDA call-site table
decoded from `.gcc_except_table` -- see records.json): two
call-site entries, both action 0 (cleanup only, no type filter):

- FDE+0x3d..+0x42: the `Env::Default()` call (0x60b2ded) -- NO
  landing pad: nothing has been constructed yet, the exception
  propagates with no cleanup.
- FDE+0x33f..+0x398: the `db_host_id` string build
  (0x60b30ef..0x60b3148: `_M_create`, `memcpy`,
  `__throw_logic_error`) -> landing pad 0x60b3148, which moves the
  exception to `rbp` and jumps to the `.cold` FDE 0x60b2cf0. The
  `.cold` destroys the partially built object in reverse
  declaration order -- `file_checksum_gen_factory` ctrl (+0x230),
  `row_cache` ctrl (+0x200), `listeners` vector (+0x1a8),
  `write_buffer_manager` ctrl (+0x160), `wal_dir` string (+0xa8),
  `db_log_dir` string (+0x88), `db_paths` vector (+0x70),
  `statistics` ctrl (+0x60), `info_log` ctrl (+0x38),
  `sst_file_manager` ctrl (+0x28), `rate_limiter` ctrl (+0x18) --
  then checks the stack canary and resumes unwinding with
  `_Unwind_Resume`. `db_host_id` itself is NOT destroyed: its
  `_M_create` throws before the heap pointer is installed (the
  string is still in SSO state, where `_M_dispose` is a no-op),
  and `compaction_service` (+0x278) is zeroed after the guarded
  region, so it is not yet constructed either. The output is never
  returned half-built.

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **11 direct calls** to `DBOptions::DBOptions()`, 0 tail
jumps, 0 LEA refs. Every caller default-constructs a `DBOptions`
before filling it:

| site | caller FDE | caller |
|---|---|---|
| 0x5d3567a | 0x5d35660 | `rocksdb_options_create` (C API) |
| 0x5d74d1c | 0x5d74aa0 | unnamed FDE (not in the vendor census; also a BuildDBOptions caller) |
| 0x5e34fb3 | 0x5e347d0 | `rocksdb::CompactionServiceInput::CompactionServiceInput` |
| 0x5e35694 | 0x5e35660 | `rocksdb::cs_input_type_info` lambda |
| 0x5fcf921 | 0x5fcf8c0 | `rocksdb::EnvOptions::EnvOptions` |
| 0x60a43f7 | 0x60a43c0 | `rocksdb::ImmutableDBOptions::ImmutableDBOptions` |
| 0x60c2e37 | 0x60c2e20 | `rocksdb::BuildDBOptions` (open PR #6297) |
| 0x60cc184 | 0x60cc150 | `rocksdb::RocksDBOptionsParser::Reset` |
| 0x60cd701 | 0x60cd6f0 | `rocksdb::RocksDBOptionsParser::RocksDBOptionsParser` |
| 0x60cf51b | 0x60cf020 | `rocksdb::RocksDBOptionsParser::EndSection` |
| 0x6203e02 | 0x6203dc0 | `rocksdb::DBWithTTLImpl::SetTtl` |

## Evidence

- `tools/db_options_default_ctor115.py` -- the DBOptions default-ctor
  model (93-field default table, 656-byte image renderer, live check
  with an independent disassembly re-parse).
- `tests/test_db_options_default_ctor115.py` -- 31 tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 defaults + 600 host_id
  + 600 throw + 600 bindings), 0 mismatches on replay
  (`python3 tools/db_options_default_ctor115.py --verify`).
- Live check (`--live`): all 9 legs pass -- FDE body/source hashes
  for both FDEs, the six `.rodata` constants, the `db_host_id`
  RELATIVE relocation + literal, the 11-site caller census, and the
  disassembly re-parse (0 diffs outside the masked runtime-address
  slots).
- `records.json` -- semantic records only (never a per-instruction
  mnemonic list); `functions.tsv`, `callers.tsv`, `census.json` -- the
  census above.
- `MANIFEST.sha256` verifies clean; `tools/verify_packets.py` flags
  only the pre-existing mismatch in unrelated packet
  RE-001-adjacent-last-115 (present on clean upstream main, untouched).
- Excerpts are whole-FDE and verbatim (`.hex` + `.objdump.txt`), with
  the repo-relative binary path `work/hl-node-115.bin` (no absolute
  home paths).

## Upstream cross-check

`meta/rocksdb` v8.1.1, read live this cycle
(`include/rocksdb/options.h`), confirms the packet field by field:
`DBOptions` is 0x290 bytes with 93 data members in the exact
declaration order the binary lays out, and every default the binary
stores matches the header -- `create_if_missing` false,
`paranoid_checks` true, `env = Env::Default()`, `info_log_level`
`INFO_LEVEL` under NDEBUG, `max_open_files` -1,
`max_file_opening_threads` 16, `delete_obsolete_files_period_micros`
6h, `max_background_jobs` 2, `max_background_compactions` -1,
`max_subcompactions` 1, `max_background_flushes` -1,
`keep_log_file_num` 1000, `recycle_log_file_num` 0,
`max_manifest_file_size` 1 GiB, `table_cache_numshardbits` 6,
`manifest_preallocation_size` 4 MiB, `allow_fallocate` true,
`is_fd_close_on_exec` true, `stats_dump_period_sec` /
`stats_persist_period_sec` 600, `stats_history_buffer_size` 1 MiB,
`advise_random_on_open` true, `access_hint_on_compaction_start`
NORMAL, `compaction_readahead_size` 0,
`random_access_max_buffer_size` 1 MiB,
`writable_file_max_buffer_size` 1 MiB, `bytes_per_sync` /
`wal_bytes_per_sync` 0, `max_write_batch_group_size_bytes` 1 MiB,
`write_thread_max_yield_usec` 100, `write_thread_slow_yield_usec`
3, `wal_recovery_mode` `kPointInTimeRecovery`,
`wal_compression` `kNoCompression`, `db_host_id` =
`kHostnameForDbHostId` (extern at :737; the table writer
substitutes the real hostname when writing SST files),
`lowest_used_cache_tier` `kNonVolatileBlockTier`,
`enforce_single_del_contracts` true, `max_bgerror_resume_count`
`INT_MAX`, `bgerror_resume_retry_interval` 1000000.

Binary-vs-source observations, recorded not hidden:

- The binary's field order matches the upstream declaration order
  exactly, all 93 fields; the paired i32s (`max_open_files` /
  `max_file_opening_threads`, `max_background_jobs` /
  `max_background_compactions`, `stats_dump_period_sec` /
  `stats_persist_period_sec`) and the paired u64s
  (`keep_log_file_num` / `recycle_log_file_num`,
  `compaction_readahead_size` /
  `random_access_max_buffer_size`,
  `max_write_batch_group_size_bytes` /
  `write_thread_max_yield_usec`) are each loaded with one
  8/16-byte `.rodata` constant, and the bool quads
  (+0x1d0, +0x1f0) with one 4-byte immediate each.
- The `db_host_id` default is the literal `"__hostname__"` via a
  `.data` global and a `R_X86_64_RELATIVE` relocation -- exactly
  upstream's `kHostnameForDbHostId` placeholder, which
  `ReifyDbHostIdProperty` (0x616d080, the only other reader of
  that global) replaces with the real hostname.
- The `.cold` destroys exactly the members constructed before the
  guarded `db_host_id` region, in reverse declaration order; it
  never touches `db_host_id` or `compaction_service`.
- Padding bytes the ctor never writes are modelled as zero; the
  binary leaves them uninitialized.

## Open unknowns (not claimed)

- `Env::Default()` returns the default `Env` singleton; its address
  is modelled as a deterministic id, not a real pointer.
- Heap addresses of strings and shared_ptr control blocks are
  modelled as deterministic ids, not real pointers.
- The unnamed caller FDE 0x5d74aa0 (site 0x5d74d1c) is not in the
  vendor census and is not named here (same FDE as in the #6297
  packet).
- The next natural follow-ups: `DBOptions::DBOptions(const Options&)`
  (the copy ctor, 0x5d38750, census-bound) and
  `DBImpl::Open` 0x5e62c50..0x5e65462 / `DBImpl::SwitchMemtable`
  0x5e8a890..0x5e8c518, the two callers of `CreateWAL` found by the
  #6222 census (both census-bound, 10258 B and 7304 B -- large, and
  they need a live DB for an engine check).

## Environment limits (stated honestly)

No cargo/rustc/git-lfs/Ghidra on this VM. The binary is read statically
(`work/hl-node-115.bin`); nothing is executed. Heap addresses are
modelled as deterministic ids, not real pointers; padding bytes are
modelled as zero (the binary leaves them uninitialized). `make verify` /
`test` / `catalogue-check` in a tooled environment is still owed upstream.
