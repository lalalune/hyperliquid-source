# RE-002: reconstruct node #115 `rocksdb::BuildDBOptions`

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `DBOptions BuildDBOptions(const ImmutableDBOptions&
immutable, const MutableDBOptions& mutable)` -- the merge that every
DB open, options query and options change calls to rebuild a
`DBOptions` from the two halves of the live options: default-construct
the output, then copy 91 fields in the exact upstream order -- 74
from the immutable half, 17 from the mutable half -- with shared_ptr
copy-assign semantics for the seven shared fields, vector copies for
`db_paths` and `listeners`, and a landing pad that destroys a
half-built output instead of returning it. 2,400 byte-checked cases;
30 tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). One FDE, census-bound:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::BuildDBOptions` | `0x60c2e20..0x60c3477` | 1623 B | `8c918932f1d73255305d126641c1876718d111d3944cf1354043ed239a6478f1` | `d7ece8bd5f9dc186-options_helper.o`, `_ZN7rocksdb14BuildDBOptionsERKNS_18ImmutableDBOptionsERKNS_16MutableDBOptionsE` |

The source hash reproduces exactly by zeroing the 19 census
relocations (kinds 2/4/42, no relaxation):
`53ce0817d1e68f2fe7410c66b52df10a4ce2b0df4aff8390798fb7069ad4a888`.
This supersedes the oracle note the #6222 `CreateWAL` packet left for
its first call: the full copy map is now pinned field by field.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `DBOptions BuildDBOptions(const ImmutableDBOptions&
immutable /* rsi=rbp */, const MutableDBOptions& mutable /*
rdx=r12 */)`; the hidden sret output pointer is in `rdi`.

**1. Default construction (0x60c2e37).** `DBOptions::DBOptions()`
0x60b2db0 (census-bound, member `d7ece8bd5f9dc186-options.o`) runs
on the output first. Every field starts at its declared default, so
the two fields the function never writes --
`write_dbid_to_manifest` (output +0x21a) and `compaction_service`
(output +0x278..+0x287) -- keep the ctor defaults: `false` and
`nullptr` (verified in the ctor disassembly: `movb $0x0,0x21a(%rbx)`,
and the 16-byte pair at +0x278..+0x287 zeroed via a zeroed xmm0).
The same ctor check pins `lowest_used_cache_tier` = 1 and
`enforce_single_del_contracts` = true as one `0x101` 16-bit store at
+0x288, `info_log_level` = 1 at +0x40, and the leading bools packed
as `0x1000000` at +0x00.

**2. The copy map (0x60c2e3c..0x60c33bf).** 91 field copies in the
exact upstream assignment order -- the copy order IS the source
order, so the field-name mapping is pinned twice over (by the
disassembly offsets and by the source listing). Scalars copy with the
width the type dictates: bools as single bytes, the three 1-byte
enums (`info_log_level`, `wal_recovery_mode`, `wal_compression`,
`lowest_used_cache_tier`) as single bytes, `max_open_files` /
`max_background_jobs` / `max_background_compactions` /
`max_background_flushes` / `table_cache_numshardbits` /
`max_bgerror_resume_count` as 4-byte ints, `max_subcompactions` /
`stats_dump_period_sec` / `stats_persist_period_sec` as 4-byte
unsigned, everything else 8-byte. The three structs lay their
fields out in different orders: `max_write_batch_group_size_bytes`
is immutable +0xf8 but output +0x1d8, and
`persist_stats_to_disk` is immutable +0x199 (after the bool run)
but output +0x138. A model that assumed declaration order for the
immutable half would place both wrong. Struct sizes: DBOptions
0x290 (656), ImmutableDBOptions 0x240 (576), MutableDBOptions 0x6c
(108, 17 fields).

Immutable-sourced (74 fields, source offset -> output offset):

| source | field | output |
|---|---|---|
| +0x00 | `create_if_missing` bool | +0x00 |
| +0x01 | `create_missing_column_families` bool | +0x01 |
| +0x02 | `error_if_exists` bool | +0x02 |
| +0x03 | `paranoid_checks` bool | +0x03 |
| +0x04 | `flush_verify_memtable_count` bool | +0x04 |
| +0x05 | `track_and_verify_wals_in_manifest` bool | +0x05 |
| +0x06 | `verify_sst_unique_id_in_manifest` bool | +0x06 |
| +0x08 | `env` ptr | +0x08 |
| +0x10 | `rate_limiter` shared_ptr | +0x10 |
| +0x20 | `sst_file_manager` shared_ptr | +0x20 |
| +0x30 | `info_log` shared_ptr | +0x30 |
| +0x40 | `info_log_level` u8 | +0x40 |
| +0x44 | `max_file_opening_threads` i32 | +0x48 |
| +0x48 | `statistics` shared_ptr | +0x58 |
| +0x58 | `use_fsync` bool | +0x68 |
| +0x60 | `db_paths` vector | +0x70 |
| +0x78 | `db_log_dir` string | +0x88 |
| +0x98 | `wal_dir` string | +0xa8 |
| +0xb8 | `max_log_file_size` u64 | +0xe0 |
| +0xc0 | `log_file_time_to_roll` u64 | +0xe8 |
| +0xc8 | `keep_log_file_num` u64 | +0xf0 |
| +0xd0 | `recycle_log_file_num` u64 | +0xf8 |
| +0xd8 | `max_manifest_file_size` u64 | +0x100 |
| +0xe0 | `table_cache_numshardbits` i32 | +0x108 |
| +0xe8 | `WAL_ttl_seconds` u64 | +0x110 |
| +0xf0 | `WAL_size_limit_MB` u64 | +0x118 |
| +0xf8 | `max_write_batch_group_size_bytes` u64 | +0x1d8 |
| +0x100 | `manifest_preallocation_size` u64 | +0x120 |
| +0x108 | `allow_mmap_reads` bool | +0x128 |
| +0x109 | `allow_mmap_writes` bool | +0x129 |
| +0x10a | `use_direct_reads` bool | +0x12a |
| +0x10b | `use_direct_io_for_flush_and_compaction` bool | +0x12b |
| +0x10c | `allow_fallocate` bool | +0x12c |
| +0x10d | `is_fd_close_on_exec` bool | +0x12d |
| +0x10e | `advise_random_on_open` bool | +0x148 |
| +0x110 | `db_write_buffer_size` u64 | +0x150 |
| +0x118 | `write_buffer_manager` shared_ptr | +0x158 |
| +0x128 | `access_hint_on_compaction_start` i32 | +0x168 |
| +0x130 | `random_access_max_buffer_size` u64 | +0x178 |
| +0x138 | `use_adaptive_mutex` bool | +0x188 |
| +0x140 | `listeners` vector | +0x1a8 |
| +0x158 | `enable_thread_tracking` bool | +0x1c0 |
| +0x159 | `enable_pipelined_write` bool | +0x1d0 |
| +0x15a | `unordered_write` bool | +0x1d1 |
| +0x15b | `allow_concurrent_memtable_write` bool | +0x1d2 |
| +0x15c | `enable_write_thread_adaptive_yield` bool | +0x1d3 |
| +0x160 | `write_thread_max_yield_usec` u64 | +0x1e0 |
| +0x168 | `write_thread_slow_yield_usec` u64 | +0x1e8 |
| +0x170 | `skip_stats_update_on_db_open` bool | +0x1f0 |
| +0x171 | `skip_checking_sst_file_sizes_on_db_open` bool | +0x1f1 |
| +0x172 | `wal_recovery_mode` u8 | +0x1f2 |
| +0x173 | `allow_2pc` bool | +0x1f3 |
| +0x178 | `row_cache` shared_ptr | +0x1f8 |
| +0x188 | `wal_filter` ptr | +0x208 |
| +0x190 | `fail_if_options_file_error` bool | +0x210 |
| +0x191 | `dump_malloc_stats` bool | +0x211 |
| +0x192 | `avoid_flush_during_recovery` bool | +0x212 |
| +0x193 | `allow_ingest_behind` bool | +0x214 |
| +0x194 | `two_write_queues` bool | +0x215 |
| +0x195 | `manual_wal_flush` bool | +0x216 |
| +0x196 | `wal_compression` u8 | +0x217 |
| +0x197 | `atomic_flush` bool | +0x218 |
| +0x198 | `avoid_unnecessary_blocking_io` bool | +0x219 |
| +0x199 | `persist_stats_to_disk` bool | +0x138 |
| +0x1a0 | `log_readahead_size` u64 | +0x220 |
| +0x1a8 | `file_checksum_gen_factory` shared_ptr | +0x228 |
| +0x1b8 | `best_efforts_recovery` bool | +0x238 |
| +0x1bc | `max_bgerror_resume_count` i32 | +0x23c |
| +0x1c0 | `bgerror_resume_retry_interval` u64 | +0x240 |
| +0x1c8 | `allow_data_in_errors` bool | +0x248 |
| +0x1d0 | `db_host_id` string | +0x250 |
| +0x1f0 | `checksum_handoff_file_types` u64 | +0x270 |
| +0x1f8 | `lowest_used_cache_tier` u8 | +0x288 |
| +0x238 | `enforce_single_del_contracts` bool | +0x289 |

Mutable-sourced (17 fields, source offset -> output offset):

| source | field | output |
|---|---|---|
| +0x00 | `max_background_jobs` i32 | +0xd0 |
| +0x04 | `max_background_compactions` i32 | +0xd4 |
| +0x08 | `max_subcompactions` u32 | +0xd8 |
| +0x0c | `avoid_flush_during_shutdown` bool | +0x213 |
| +0x10 | `writable_file_max_buffer_size` u64 | +0x180 |
| +0x18 | `delayed_write_rate` u64 | +0x1c8 |
| +0x20 | `max_total_wal_size` u64 | +0x50 |
| +0x28 | `delete_obsolete_files_period_micros` u64 | +0xc8 |
| +0x30 | `stats_dump_period_sec` u32 | +0x130 |
| +0x34 | `stats_persist_period_sec` u32 | +0x134 |
| +0x38 | `stats_history_buffer_size` u64 | +0x140 |
| +0x40 | `max_open_files` i32 | +0x44 |
| +0x48 | `bytes_per_sync` u64 | +0x190 |
| +0x50 | `wal_bytes_per_sync` u64 | +0x198 |
| +0x58 | `strict_bytes_per_sync` bool | +0x1a0 |
| +0x60 | `compaction_readahead_size` u64 | +0x170 |
| +0x68 | `max_background_flushes` i32 | +0xdc |

The immutable half's tail past `lowest_used_cache_tier` (+0x1f8)
holds convenience objects that are NOT part of DBOptions: `fs`
(+0x200), `clock` (+0x210), `stats` (+0x218), `logger` (+0x220),
`compaction_service` (+0x228) and `enforce_single_del_contracts`
(+0x238) -- only the last one is copied out (to +0x289).

**3. Shared pointers (7 fields).** The pointer word copies inline
and the control block goes through the shared_ptr copy routine --
inlined for five fields, out-of-line through
`__shared_count::operator=` 0x60bcde0 for `sst_file_manager`
(+0x20) and `file_checksum_gen_factory` (+0x228). If the new target
differs from the old one the new use count goes up by one (plain
`addl` when the single-thread flag byte at 0x64ed290 is set, `lock
addl` otherwise) and the old target is released via
`_Sp_counted_base::_M_release` 0x5d350c0 (destroyed at zero; the
out-of-line spelling also checks the combined (use, weak) count
`0x100000001` before disposing). Equal targets are a no-op; a null
new target only releases the old one. On the normal path the release
half is dead: the ctor nulls all seven slots, so there is never an
old target to release.

**4. Containers.** `db_paths` is a `std::vector<DbPath>` copy
(`operator=` 0x60c2790) from immutable +0x60 into output +0x70;
`listeners` is a `std::vector<std::shared_ptr<EventListener>>` copy
(`operator=` 0x60bd2d0) from immutable +0x140 into output +0x1a8,
acquiring each element target; the three strings (`db_log_dir`,
`wal_dir`, `db_host_id`) copy with `std::string::_M_assign` (PLT
0x63f0f00).

**5. Landing pad (0x60c346b..0x60c3477, inside the main FDE -- NO
separate `.cold` FDE).** On any throw the pad moves the exception to
`rbp`, jumps to 0x60c2e04, destroys the partially built output with
`DBOptions::~DBOptions` 0x5d354b0 and resumes unwinding with
`_Unwind_Resume`. The output is never returned half-built, even when
a string or vector copy throws midway.

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **12 direct calls** to BuildDBOptions, 0 tail jumps, 0 LEA
refs. Every DB open / options-query / options-change path rebuilds
its DBOptions through this routine:

| site | caller FDE | caller |
|---|---|---|
| 0x5d48922 | 0x5d488e0 | `rocksdb::DBImpl::GetDBOptions` |
| 0x5d5878f | 0x5d58720 | `rocksdb::DBImpl::GetOptions` |
| 0x5d69a88 | 0x5d69a00 | `rocksdb::DBImpl::CreateColumnFamilyImpl` |
| 0x5d71b79 | 0x5d713f0 | `rocksdb::DBImpl::WriteOptionsFile` |
| 0x5d72361 | 0x5d71fe0 | `rocksdb::DBImpl::SetDBOptions` |
| 0x5d73283 | 0x5d72ed0 | `rocksdb::DBImpl::SetOptions` |
| 0x5d753be | 0x5d74aa0 | unnamed FDE (not in the census) |
| 0x5d858aa | 0x5d85480 | `rocksdb::DBImpl::DBImpl` (ctor) |
| 0x5e427fb | 0x5e41fa0 | `rocksdb::CompactionJob::ProcessKeyValueCompactionWithCompactionService` |
| 0x5e5af6b | 0x5e5ad50 | `rocksdb::DBImpl::GetLogSizeAndMaybeTruncate` |
| 0x5e5c2f8 | 0x5e5c270 | `rocksdb::DBImpl::CreateWAL` (the #6222 packet) |
| 0x60a24f8 | 0x60a2470 | `rocksdb::DBOptionsConfigurable::ConfigureOptions` |

## Evidence

- `tools/build_db_options115.py` -- the BuildDBOptions model
  (91-entry copy map, shared_ptr copy-assign semantics, byte-image
  renderer, live check with an independent disassembly re-parse).
- `tests/test_build_db_options115.py` -- 30 tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 immutable + 600
  mutable + 600 shared_ptr + 600 bindings), 0 mismatches on replay
  (`python3 tools/build_db_options115.py --verify`).
- Live check (`--live`): all 5 legs pass -- FDE body hash, source
  hash reproduced by zeroing the 19 census relocations, an
  independent disassembly re-parse (93 scalar pieces match the copy
  map exactly), the 12-site caller census, and the ctor-default
  build.
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

`facebook/rocksdb` v8.1.1, read live this cycle
(`options/options_helper.cc`, `include/rocksdb/options.h`,
`options/db_options.h` -- the repo has since moved to
`meta/rocksdb`), confirms the packet field by field:
`BuildDBOptions` is 91 assignments in the exact order the binary
copies them; `DBOptions` is 0x290 bytes with 93 data members; the two
members the function never assigns are `write_dbid_to_manifest` and
`compaction_service`. In v8.1.1 `max_log_file_size`,
`log_file_time_to_roll`, `keep_log_file_num`,
`recycle_log_file_num`, `max_manifest_file_size` and
`persist_stats_to_disk` come from the immutable half, not the mutable
half; `ImmutableDBOptions` is 0x240 bytes with the convenience tail
past `lowest_used_cache_tier`; `MutableDBOptions` is 0x6c bytes with
17 members.

Binary-vs-source observations, recorded not hidden:

- The binary's copy order matches the upstream assignment order
  exactly, all 91 fields.
- `max_write_batch_group_size_bytes` and `persist_stats_to_disk`
  sit at different offsets in the immutable half than in the output,
  so a declaration-order model would place both wrong.
- The shared_ptr copies come in two spellings -- inlined for five
  fields, out-of-line `__shared_count::operator=` for two -- with
  identical observable semantics.
- The release half of every shared_ptr copy is dead on the normal
  path (the ctor nulls all seven slots).
- The single-thread flag byte at 0x64ed290 only chooses between a
  plain and a lock-prefixed use-count increment.
- There is no `.cold` FDE: the landing pad sits at the tail of the
  main FDE.

## Open unknowns (not claimed)

- `DBOptions::DBOptions()` (0x60b2db0) is scripted as an oracle: the
  full ctor is the next work item, not this packet. Only its two
  unwritten fields' defaults are pinned here (from its disassembly).
- Heap addresses of strings, vectors and shared_ptr control blocks
  are modelled as deterministic ids, not real pointers.
- Vector/string capacities after copy-assign are modelled as exactly
  the source size (the libstdc++ fresh-target behaviour) and recorded
  as a model choice, not a binary-pinned fact.
- The unnamed caller FDE 0x5d74aa0 (site 0x5d753be) is not in the
  vendor census and is not named here.
- The next natural follow-ups: `DBOptions::DBOptions()` 0x60b2db0
  (the ctor; its defaults are this packet's oracle); `DBImpl::Open`
  0x5e62c50..0x5e65462 / `DBImpl::SwitchMemtable` 0x5e8a890..0x5e8c518,
  the two callers of `CreateWAL` found by the #6222 census (both
  census-bound, 10258 B and 7304 B -- large, and they need a live DB
  for an engine check).

## Environment limits (stated honestly)

No cargo/rustc/git-lfs/Ghidra on this VM. The binary is read statically
(`work/hl-node-115.bin`); nothing is executed. `DBOptions::DBOptions()`
is scripted as an oracle (its two unwritten fields keep the defaults
verified in its disassembly); heap addresses of strings, vectors and
shared_ptr control blocks are modelled as deterministic ids, not real
pointers; vector/string capacities after copy-assign are modelled as
exactly the source size and recorded as a model choice, not a
binary-pinned fact. `make verify` / `test` / `catalogue-check` in a
tooled environment is still owed upstream.
