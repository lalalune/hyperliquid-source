# RE-002: reconstruct node #115 `rocksdb::DBOptions::DBOptions(const Options&)`

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `DBOptions::DBOptions(const Options&)` -- the explicit
constructor every DB open entry point runs first to build a
`DBOptions` from the caller's `Options` (DB::Open, DB::OpenForReadOnly,
CompactedDBImpl::Open, DB::OpenAsSecondary, DBWithTTL::Open and the C
API optimistic-transaction open) by memberwise-copying the
`DBOptions` subobject out of the `Options` (93 data members, 0x290
bytes). 2,400 byte-checked cases; 31 tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). Two FDEs, both census-bound:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::DBOptions::DBOptions(const Options&)` | `0x60b3280..0x60b3b87` | 2311 B | `7c4707c22eeabfb1ed1d4db475347822af6d2a6bbc6708d3242101d5b4a275c2` | `d7ece8bd5f9dc186-options.o`, `_ZN7rocksdb9DBOptionsC1ERKNS_7OptionsE` |
| `rocksdb::DBOptions::DBOptions(const Options&).cold` | `0x60b3154..0x60b327a` | 294 B | `f1428783628f1a3844ebb2aadf27fa2d7b07401cab672da980b7c6ec32f6155e` | `d7ece8bd5f9dc186-options.o`, `_ZN7rocksdb9DBOptionsC2ERKNS_7OptionsE.cold` |

The source hashes reproduce exactly by zeroing the census
relocations (main: 28, kinds 2/4/42, no relaxation:
`e9bc1ce7a303f7ba21595e4b95abd2edfb009864f03ef9d0072e322674d6eccd`;
.cold: 18 kind-4:
`de25ebd703442d1fed35a68fe665eb1c546f9555a4f5cdb8633959601ea0684c`).
This is the direct follow-up to the default-ctor packet (open PR
#6337, 0x60b2db0) and the copy-ctor packet (open PR #6338, 0x5d38750):
the default ctor builds the 93 defaults, this ctor copies the
`DBOptions` subobject out of an `Options`, and the copy ctor is the
same memberwise copy from a `DBOptions` source.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `DBOptions::DBOptions(const Options&)` -- this in `rdi`
(= `rbx`), source `Options` in `rsi` (= `rbp`); no +0x18 prologue bump
(the first stores use `(%rsi)`/`(%rdi)` directly, the rest use
`(%rbp)`/`(%rbx)`). `struct Options` inherits `DBOptions` first
(upstream `options.h:1399`), so the `DBOptions` subobject sits at
`Options+0x00` and the ctor copies exactly the 0x290-byte `DBOptions`
layout at the same offsets as the copy ctor. A stack canary IS used
(`%fs:0x28`, checked at the epilogue and in the length-throw paths).
In binary order:

1. Leading bools + env: the 7 bools at +0x00..0x06 are copied as one
   u32 (+0x00), one u16 (+0x04) and one u8 (+0x06); `env` (+0x08)
   and the `rate_limiter` ptr word (+0x10) arrive together in one
   `movdqu` (+0x08..+0x17); the `rate_limiter` ctrl word (+0x18) is
   copied by plain `mov`, then the refcount at ctrl+0x8 is bumped by
   1 (see 2).
2. Shared pointers, each as ptr word (plain `mov`, or inside a
   16-byte `movdqu`/`movups` chunk) + ctrl word (plain `mov`) + an
   INLINED refcount bump -- unlike the copy ctor, there is NO call to
   the `__shared_count` copy helper 0x5d35c00 anywhere in this FDE.
   The bump is `addl $0x1, 0x8(%rax)` when the guard byte at the GOT
   slot 0x64ed290 is non-zero, and `lock addl $0x1, 0x8(%rax)` (a stub
   at the end of the FDE) when it is zero: nine plain + nine lock
   sites in total, one pair per shared_ptr copy -- eight fields
   (`rate_limiter` +0x18, `sst_file_manager` +0x28, `info_log`
   +0x38, `statistics` +0x60, `write_buffer_manager` +0x160,
   `row_cache` +0x200, `file_checksum_gen_factory` +0x230,
   `compaction_service` +0x280) plus the per-element bump in the
   listeners loop. Both paths increment the refcount by exactly 1;
   the copy SHARES each control block (refcount +1); it never
   deep-copies the pointed-to object. A null source stays null (the
   bump is skipped when the ctrl is null).
3. Scalars: every scalar field is copied verbatim by plain `mov` /
   `movdqu` / `movups` at the same offset as in the copy ctor:
   `info_log_level`, `max_open_files`, `max_file_opening_threads`,
   `max_total_wal_size`, `use_fsync`,
   `delete_obsolete_files_period_micros`, `max_background_jobs`,
   `max_background_compactions`, `max_subcompactions`,
   `max_background_flushes`, `max_log_file_size`,
   `log_file_time_to_roll`, `keep_log_file_num`,
   `recycle_log_file_num`, `max_manifest_file_size`,
   `table_cache_numshardbits`, `WAL_ttl_seconds`,
   `WAL_size_limit_MB`, `manifest_preallocation_size`, the mmap/direct
   bool quad (+0x128, one u32), `allow_fallocate` /
   `is_fd_close_on_exec` (+0x12c, one u16), `stats_dump_period_sec`,
   `stats_persist_period_sec`, `persist_stats_to_disk`,
   `stats_history_buffer_size`, `advise_random_on_open`,
   `db_write_buffer_size`, `access_hint_on_compaction_start`,
   `compaction_readahead_size`, `random_access_max_buffer_size`,
   `writable_file_max_buffer_size`, `use_adaptive_mutex`,
   `bytes_per_sync`, `wal_bytes_per_sync`, `strict_bytes_per_sync`,
   `enable_thread_tracking`, `delayed_write_rate`, the write-thread
   bool quad (+0x1d0, one u32), `max_write_batch_group_size_bytes`,
   `write_thread_max_yield_usec`, `write_thread_slow_yield_usec`, the
   recovery quad (+0x1f0, one u32), `wal_filter` (+0x208, raw ptr
   copy), the option-file bool run (+0x210..+0x217, one u64),
   `atomic_flush` / `avoid_unnecessary_blocking_io` (+0x218, one
   u16), `write_dbid_to_manifest`, `log_readahead_size`,
   `best_efforts_recovery`, `max_bgerror_resume_count`,
   `bgerror_resume_retry_interval`, `allow_data_in_errors`,
   `checksum_handoff_file_types`, `lowest_used_cache_tier` /
   `enforce_single_del_contracts` (+0x288, one u16). Padding bytes are
   never written (the binary leaves them uninitialized; the model
   zeroes them).
4. `db_paths` vector (+0x70, 0x60b336e..0x60b34e0): byte size = src
   end - src begin; the dst vector is zeroed first (begin = end =
   cap = 0); if size == 0 it stays zeroed. Else the size is
   bounds-checked against 0x7ffffffffffffff8 (else
   `__throw_bad_array_new_length`, PLT 0x63f0ec0); `operator new(size)`
   (PLT 0x63f0dd0) allocates the dst buffer; begin = end = the new
   buffer, cap = begin + size; then an INLINED element loop
   (0x60b33d5..0x60b34e0) copy-constructs each `DbPath` (0x28 = 40
   bytes: `std::string` path at +0x0 via the inlined `_M_construct`
   pattern, `uint64_t target_size` at +0x20) and stores the new end
   to dst +0x78. The copy allocates EXACTLY size bytes (cap == end,
   no slack). Unlike the copy ctor, there is NO call to
   `__do_uninit_copy` 0x5d386a0: the loop is inlined here.
5. Strings `db_log_dir` (+0x88), `wal_dir` (+0xa8), `db_host_id`
   (+0x250): each built by the INLINED `_M_construct` pattern --
   `_M_create` (PLT 0x63f0e10) + `memcpy` (PLT 0x63f0a60) for len > 15,
   SSO copy for len <= 15 (len == 1 single-byte fast path, len == 0
   NUL-only) -- after the dst string's ptr word is preset to its own
   SSO buffer (lea this+0x98 / +0xb8 / +0x260). Unlike the copy ctor,
   there is NO call to `basic_string::_M_construct` 0x5d2e540. The
   `db_log_dir` this-pointer is saved in `r13` and the `wal_dir`
   this-pointer in `r14` for the landing pads.
6. `listeners` vector (+0x1a8, 0x60b3692..0x60b37b5): byte size = src
   end - src begin; dst zeroed first; if size == 0 it stays zeroed.
   Else bounds-checked against 0x7ffffffffffffff0 (else
   `__throw_bad_array_new_length`); `operator new(size)`; begin =
   end = new buffer, cap = begin + size; then the inline loop copies
   each `shared_ptr<EventListener>` element (0x10 = 16 bytes: ptr word
   by `movdqu`, ctrl word by `mov`, refcount bumped by the inlined
   `addl`/`lock addl` pair -- refcount +1 per element, the listeners
   are SHARED, not deep-copied) and stores the new end to dst +0x1b0.
7. Epilogue (0x60b3971..0x60b3993): stack-canary check, `add
   $0x38,%rsp`; pop `rbx`/`rbp`/`r12`/`r13`/`r14`/`r15`; `ret`. The
   result is the fully copied object; no field is left at its default
   unless the source had the default there.

The landing pads are the six `endbr64` stubs at the end of the main
FDE (0x60b3b3f, 0x60b3b4b, 0x60b3b57, 0x60b3b63, 0x60b3b6f,
0x60b3b7b), each jumping into the separate `.cold` FDE
(0x60b3154..0x60b327a). The main LSDA call-site table was decoded from
`.gcc_except_table` (LSDA at 0x422440, 53 bytes, header `ff 9b 39 01
30` + 8 call-site entries, all action 0 except the db_paths
element-copy entry, action 1 = a catch pad) plus a 2-byte action table
(`01 00`) at 0x422475; the `.cold` LSDA is at 0x42247c (16 bytes,
header `ff 9b 15 01 0b` + 2 entries):

- FDE+0x12c..+0x131: `operator new`, db_paths (0x60b33ac) -> pad
  0x60b3b7b -> `.cold` 0x60b31d9 (chain only: statistics, info_log,
  sst_file_manager, rate_limiter).
- FDE+0x1da..+0x1df: `_M_create`, db_paths element (0x60b345a) -> pad
  0x60b3b3f, action 1 (catch) -> `.cold` 0x60b3154
  (`__cxa_begin_catch`, `_M_dispose` each constructed `DbPath` string
  walking FORWARD 0x28 at a time from the buffer start to the first
  unconstructed element, then `__cxa_rethrow`) -- the rethrow call
  itself maps in the `.cold` LSDA to pad 0x60b324d
  (`__cxa_end_catch`, raw `delete[]` of the db_paths buffer, then the
  chain).
- FDE+0x4a4..+0x4a9: `operator new`, listeners (0x60b3724) -> pad
  0x60b3b4b -> `.cold` 0x60b31b0 (write_buffer_manager ctrl release,
  wal_dir dispose, db_log_dir dispose, db_paths dtor, then the chain).
- FDE+0x76a..+0x76f: `_M_create`, wal_dir (0x60b39ea) -> pad 0x60b3b57
  -> `.cold` 0x60b31c8 (db_log_dir dispose, db_paths dtor, then the
  chain).
- FDE+0x7b2..+0x7b7: `_M_create`, db_log_dir (0x60b3a32) -> pad
  0x60b3b63 -> `.cold` 0x60b31d0 (db_paths vector dtor, then the
  chain).
- FDE+0x80a..+0x80f: `_M_create`, db_host_id (0x60b3a8a) -> pad
  0x60b3b6f -> `.cold` 0x60b3182 (file_checksum_gen_factory ctrl,
  row_cache ctrl, listeners vector dtor 0x5d46140,
  write_buffer_manager ctrl, wal_dir dispose, db_log_dir dispose,
  db_paths dtor, then the chain).
- FDE+0x8a0..+0x8a5: `__throw_bad_array_new_length`, db_paths
  (0x60b3b20) -> pad 0x60b3b7b (chain only).
- FDE+0x8b5..+0x8ba: `__throw_bad_array_new_length`, listeners
  (0x60b3b35) -> pad 0x60b3b4b.
- `.cold` FDE+0xd0..+0xd5: `_Unwind_Resume` (0x60b3224) -> NO pad
  (already inside the cleanup).
- `.cold` FDE+0xe5..+0xea: `__cxa_rethrow` (0x60b3239) -> pad
  0x60b324d (`__cxa_end_catch`, `delete[]` the db_paths buffer, then
  the chain at 0x60b31d9).

The chain (`.cold` 0x60b31d9..0x60b3224) releases, in order, the
statistics ctrl (+0x60), info_log ctrl (+0x38), sst_file_manager ctrl
(+0x28) and rate_limiter ctrl (+0x18) -- each via
`_Sp_counted_base::_M_release` (0x5d350c0) only if non-null -- then
resumes unwinding. No pad ever touches the strings whose `_M_create`
threw (still SSO: `_M_create` throws before the heap pointer is
installed, so `_M_dispose` would be a no-op) or `compaction_service`
(+0x278, copied after the guarded region). The output is never
returned half-built.

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **6 direct calls** to `DBOptions::DBOptions(const Options&)`,
0 tail jumps, 0 LEA refs -- every DB open entry point that takes a
`const Options&`:

| site | caller FDE | caller |
|---|---|---|
| 0x5d396ff | 0x5d39590 | `rocksdb_optimistictransactiondb_open_column_families` (census-bound, `c.o`) |
| 0x5e65578 | 0x5e65530 | `rocksdb::DB::Open` (census-bound, `db_impl_open.o`) |
| 0x5e73442 | 0x5e73160 | `rocksdb::DB::OpenForReadOnly` (census-bound, `db_impl_readonly.o`) |
| 0x5e79d2e | 0x5e79c30 | `rocksdb::CompactedDBImpl::Open` (census-bound, `compacted_db_impl.o`) |
| 0x5e81f5a | 0x5e81f00 | `rocksdb::DB::OpenAsSecondary` (census-bound, `db_impl_secondary.o`) |
| 0x6207796 | 0x6207740 | `rocksdb::DBWithTTL::Open` (census-bound, `db_ttl_impl.o`) |

`DBImpl::Open` 0x5e62c50 is NOT a caller -- it takes a `DBOptions`,
not an `Options`.

## Evidence

- `tools/db_options_options_ctor115.py` -- the DBOptions Options-ctor
  model (93-field table, 656-byte image renderer with src/dst heap-id
  namespaces, live check with a copy-map re-parse of the objdump).
- `tests/test_db_options_options_ctor115.py` -- 31 tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 fields + 600
  containers + 600 throw + 600 bindings), 0 mismatches on replay
  (`python3 tools/db_options_options_ctor115.py --verify`).
- Live check (`--live`): all 13 legs pass -- both FDE body/source
  hashes, both LSDAs plus the action table, the 6-site caller census,
  the engine-call counts (2x `operator new`, 4x `_M_create`, 4x
  `memcpy`, 2x `__throw_bad_array_new_length`, 1x `__stack_chk_fail`),
  the 9 plain + 9 lock inlined refcount-bump sites, the copy-map
  coverage of every scalar/shared_ptr word, and the copy-of-defaults
  identity (copying the defaults yields the defaults byte-for-byte,
  sha256 `ea59a732051f16d90fc6be9592a41045d12fd8786ba1a215acefb9fbd6c94533`
  -- the #6337 default image).
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
(`include/rocksdb/options.h`, `options/options.cc`), confirms the
packet's shape:

- `include/rocksdb/options.h` declares `struct DBOptions` (:447) with
  only `DBOptions();` (:967) and `explicit DBOptions(const Options&
  options);` (:969), and `struct Options : public DBOptions, public
  ColumnFamilyOptions` (:1399) -- `DBOptions` is the first base, so
  the subobject is at `Options+0x00`, which is why the binary reads
  the source at the `DBOptions` offsets.
- `options/options.cc:128-130` defines this ctor as a delegation to
  the copy ctor (`DBOptions(const Options& options) :
  DBOptions(*static_cast<const DBOptions*>(&options)) {}`), but the
  binary contains NO call to the copy ctor 0x5d38750 -- the compiler
  inlined the implicit copy ctor's memberwise body into this FDE
  (same TU, `options.o`), with the shared_ptr, vector and string
  helpers inlined as well. The copy ctor's own 3 callers
  (SanitizeOptions, `DBOptionsConfigurable` x2) do not include this
  ctor, confirming the delegation was inlined rather than called.

Binary-vs-source observations, recorded not hidden:

- The source delegates to the copy ctor, but the binary inlines the
  whole memberwise copy (see above) -- the observable behaviour is
  the same memberwise copy the copy ctor performs; only the code
  shape differs.
- The census labels 0x5d35cb0 (the vector destructor used in the pads)
  `vector<TableReader::Anchor>::~vector`; the element loop strides
  0x28, frees a heap string at +0x0 (SSO buffer +0x10) and skips the
  u64 at +0x20, which is exactly `DbPath`'s layout -- the two
  instantiations share the folded address. The packet pins the
  binary behavior, not the template name.
- The census labels 0x5d46140 (the listeners vector destructor)
  `vector<shared_ptr<const SnapshotImpl>>::~vector`; the element loop
  strides 0x10 and releases each element's ctrl at +0x8, which is
  exactly `vector<shared_ptr<EventListener>>`'s layout -- the two
  instantiations share the folded address.
- The refcount guard byte lives behind the GOT slot at 0x64ed290,
  which is statically zero (a load-time relocation), so the guard
  flag's identity is NOT pinned statically -- recorded as an open
  unknown. Both paths increment the refcount at ctrl+0x8 by exactly
  1; that is what the model pins.
- The `db_paths` / `listeners` copies allocate exactly the byte size
  (cap == end, no slack) -- a vector copy constructor, not a
  `reserve` + `push_back` loop.
- The `.cold` catch pad disposes the constructed `DbPath` prefix
  walking FORWARD 0x28 at a time from the buffer start; the copy
  ctor's `__do_uninit_copy` pad walked backward. The disposed set is
  the same either way.
- Padding bytes the ctor never writes are modelled as zero; the
  binary leaves them uninitialized.

## Open unknowns (not claimed)

- The type-table entry the action-1 (catch) record names was not
  resolved statically; the pad body calls `__cxa_begin_catch` with no
  type test and rethrows, and `_M_create` can only throw
  `std::bad_alloc`, so the modelled behaviour does not depend on it.
- `Env::Default()`'s return and every `shared_ptr` control block are
  modelled as deterministic ids, not real pointers; the copy shares
  them (refcount +1) rather than deep-copying.
- Heap addresses of strings and vector buffers are modelled as
  deterministic ids, not real pointers; src and dst are modelled at
  the same slot address (`THIS_BASE`), so their SSO pointers coincide
  -- what the copy pins is the values, not the addresses.
- The next natural follow-ups: `DBImpl::Open` 0x5e62c50..0x5e65462 /
  `DBImpl::SwitchMemtable` 0x5e8a890..0x5e8c518, the two callers of
  `CreateWAL` found by the #6222 census (both census-bound, 10258 B
  and 7304 B -- large, and they need a live DB for an engine check).

## Environment limits (stated honestly)

No cargo/rustc/git-lfs/Ghidra on this VM. The binary is read statically
(`work/hl-node-115.bin`); nothing is executed. Heap addresses are
modelled as deterministic ids, not real pointers; padding bytes are
modelled as zero (the binary leaves them uninitialized). `make verify` /
`test` / `catalogue-check` in a tooled environment is still owed upstream.
