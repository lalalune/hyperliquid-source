# RE-002: reconstruct node #115 `rocksdb::DBOptions::DBOptions(const DBOptions&)`

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `DBOptions::DBOptions(const DBOptions&)` -- the implicit
memberwise copy constructor that every caller that needs its own
`DBOptions` runs (SanitizeOptions copies the caller's options before
sanitizing; `DBOptionsConfigurable`'s ctor stores its own copy of the
base options) to duplicate a whole 0x290-byte `DBOptions` (93 data
members). 2,400 byte-checked cases; 31 tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). One FDE, census-bound:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::DBOptions::DBOptions(const DBOptions&)` | `0x5d38750..0x5d38da5` | 1621 B | `a39ee28a2d76a9f88d79e079da0d8fe380dc289c8bc4141021550668ea162113` | `25dac13516458d4d-c.o`, `_ZN7rocksdb9DBOptionsC1ERKS0_` |

The source hash reproduces exactly by zeroing the census
relocations (31, kinds 2/4, no kind-42, no relaxation):
`f913228d9666811e62d1b98b250436337dd5175476b594bbd3a6cff6ccf35397`.
This is the direct follow-up to the default-ctor packet (open PR
#6337, 0x60b2db0) and the BuildDBOptions packet (open PR #6297,
0x60c2e20): the default ctor builds the 93 defaults, this copy ctor
duplicates a whole `DBOptions`, and BuildDBOptions then overwrites 91
of the fields from the immutable + mutable halves.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `DBOptions::DBOptions(const DBOptions&)` -- this in `rdi`
(= `rbx`), source in `rsi` (= `rbp`); `rsi`/`rdi` are bumped by +0x18
at the prologue, so the first stores use `-0x18(%rsi)`/`-0x18(%rdi)`.
No stack canary in this FDE (no `%fs:0x28` reference -- the throw
paths resume unwinding, they do not check a canary). In binary order:

1. Leading bools + env: the 7 bools at +0x00..0x06 are copied as one
   u32 (+0x00), one u16 (+0x04) and one u8 (+0x06); `env` (+0x08)
   and the `rate_limiter` ptr word (+0x10) arrive together in one
   `movdqu` (+0x08..+0x17); the `rate_limiter` ctrl (+0x18) is copied
   by the shared_ptr copy helper 0x5d35c00 (`__shared_count` copy
   ctor: bumps the refcount, never throws, no LSDA entry).
2. Shared pointers, each as ptr word (plain `mov`) + ctrl word (call
   0x5d35c00): `sst_file_manager` (+0x20/+0x28), `info_log`
   (+0x30/+0x38), `statistics` (+0x58/+0x60),
   `write_buffer_manager` (+0x158/+0x160), `row_cache`
   (+0x1f8/+0x200), `file_checksum_gen_factory` (+0x228/+0x230),
   `compaction_service` (+0x278/+0x280). Nine 0x5d35c00 calls in
   total -- one per shared_ptr field (eight) plus the per-element
   call in the listeners loop. The copy SHARES each control block
   (refcount +1); it never deep-copies the pointed-to object. A null
   source stays null.
3. Scalars: every scalar field is copied verbatim by plain `mov` /
   `movdqu` / `movups` at the same offset: `info_log_level`,
   `max_open_files`, `max_file_opening_threads`,
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
4. `db_paths` vector (+0x70, 0x5d387ed..0x5d38853): byte size = src
   end - src begin; the dst vector is zeroed first (begin = end =
   cap = 0); if size == 0 it stays zeroed. Else the size is
   bounds-checked against 0x7ffffffffffffff8 (else
   `__throw_bad_array_new_length`, PLT 0x63f0ec0); `operator new(size)`
   (PLT 0x63f0dd0) allocates the dst buffer; begin = end = the new
   buffer, cap = begin + size; then `__do_uninit_copy` (0x5d386a0,
   census-bound, same member c.o) copy-constructs each `DbPath`
   (0x28 = 40 bytes: `std::string` path at +0x0 via `_M_construct`,
   `uint64_t target_size` at +0x20) and returns the new end, stored
   to dst +0x78. The copy allocates EXACTLY size bytes (cap == end,
   no slack).
5. Strings `db_log_dir` (+0x88), `wal_dir` (+0xa8), `db_host_id`
   (+0x250): each built by `basic_string::_M_construct` (0x5d2e540,
   this in `rdi`, first in `rsi`, last in `rdx` = first + size) after
   the dst string's ptr word is preset to its own SSO buffer (lea
   this+0x98 / +0xb8 / +0x260). `_M_construct`
   (0x5d2e540..0x5d2e5e3, NO LSDA -- nothing to clean on a throw):
   len = last - first; len <= 15 stays in the SSO buffer (size stored,
   NUL at buf[len]); len > 15 goes through `_M_create` + `memcpy`
   (heap, capacity = len); len == 1 has a single-byte fast path;
   len == 0 skips the `memcpy`. The `db_log_dir` this-pointer is
   saved at 0x8(%rsp) and the `wal_dir` this-pointer in `r15` for the
   landing pads.
6. `listeners` vector (+0x1a8, 0x5d389cd..0x5d38aa3): byte size = src
   end - src begin; dst zeroed first; if size == 0 it stays zeroed.
   Else bounds-checked against 0x7ffffffffffffff0 (else
   `__throw_bad_array_new_length`); `operator new(size)`; begin =
   end = new buffer, cap = begin + size; then the inline loop copies
   each `shared_ptr<EventListener>` element (0x10 = 16 bytes: ptr word
   by `mov`, ctrl word by call 0x5d35c00 -- refcount +1 per element,
   the listeners are SHARED, not deep-copied) and stores the new end
   to dst +0x1b0.
7. Epilogue (0x5d38c1d..0x5d38c2b): `add $0x18,%rsp`; pop
   `rbx`/`rbp`/`r12`/`r13`/`r14`/`r15`; `ret`. The result is the fully
   copied object; no field is left at its default unless the source
   had the default there.

The landing pads live INSIDE the main FDE (0x5d38c55..0x5d38da5);
there is no separate `.cold` FDE. The LSDA call-site table was
decoded from `.gcc_except_table` (LSDA at 0x407084, 57 bytes, header
`ff ff 01 35`, all actions 0 = cleanup only, no type filter). Nine
entries; the nine `__shared_count` copy calls have NO entry
(noexcept):

- FDE+0xd7..+0xdc: `operator new`, db_paths (0x5d38827) -> pad
  0x5d38d45 (chain only: statistics, info_log, sst_file_manager,
  rate_limiter).
- FDE+0xfe..+0x103: `__do_uninit_copy`, db_paths (0x5d3884e) -> pad
  0x5d38c55 (raw `delete[]` of the db_paths buffer, then the chain --
  the constructed `DbPath` prefix was already disposed inside
  `__do_uninit_copy`'s own pad 0x5d38711, which `__cxa_begin_catch`es,
  `_M_dispose`s each constructed element's string walking back 0x28 at
  a time, and rethrows).
- FDE+0x132..+0x137: `_M_construct`, db_log_dir (0x5d38882) -> pad
  0x5d38c5e (db_paths vector dtor 0x5d35cb0, then the chain).
- FDE+0x160..+0x165: `_M_construct`, wal_dir (0x5d388b0) -> pad
  0x5d38d5a (db_log_dir `_M_dispose`, db_paths dtor, then the chain).
- FDE+0x2f5..+0x2fa: `operator new`, listeners (0x5d38a45) -> pad
  0x5d38d63 (write_buffer_manager ctrl release, wal_dir dispose,
  db_log_dir dispose, db_paths dtor, then the chain).
- FDE+0x48b..+0x490: `_M_construct`, db_host_id (0x5d38bdb) -> pad
  0x5d38d4e (file_checksum_gen_factory ctrl, row_cache ctrl, listeners
  per-element ctrl releases + buffer `delete[]`,
  write_buffer_manager ctrl, wal_dir dispose, db_log_dir dispose,
  db_paths dtor, then the chain).
- FDE+0x4fb..+0x500: `__throw_bad_array_new_length`, db_paths
  (0x5d38c4b) -> pad 0x5d38d45 (chain only).
- FDE+0x500..+0x505: `__throw_bad_array_new_length`, listeners
  (0x5d38c50) -> pad 0x5d38d63.
- FDE+0x5f0..+0x5f5: `_Unwind_Resume` (0x5d38d40) -> NO pad (already
  inside the cleanup).

The chain (0x5d38d05..0x5d38d40) releases, in order, the statistics
ctrl (+0x60), info_log ctrl (+0x38), sst_file_manager ctrl (+0x28)
and rate_limiter ctrl (+0x18) -- each via
`_Sp_counted_base::_M_release` (0x5d350c0) only if non-null -- then
resumes unwinding. No pad ever touches the strings whose
`_M_construct` threw (still SSO: `_M_create` throws before the heap
pointer is installed, so `_M_dispose` would be a no-op) or
`compaction_service` (+0x278, copied after the guarded region). The
output is never returned half-built.

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **3 direct calls** to `DBOptions::DBOptions(const DBOptions&)`,
0 tail jumps, 0 LEA refs:

| site | caller FDE | caller |
|---|---|---|
| 0x5e5cfa6 | 0x5e5cf70 | `rocksdb::SanitizeOptions` (census-bound, `db_impl_open.o`) |
| 0x60a4980 | 0x60a47f0 | `rocksdb::DBOptionsConfigurable::DBOptionsConfigurable` (census-bound, `db_options.o`) |
| 0x60a5248 | 0x60a47f0 | `rocksdb::DBOptionsConfigurable::DBOptionsConfigurable` (census-bound, `db_options.o`) |

## Evidence

- `tools/db_options_copy_ctor115.py` -- the DBOptions copy-ctor model
  (93-field table, 656-byte image renderer with src/dst heap-id
  namespaces, live check with a copy-map re-parse of the objdump).
- `tests/test_db_options_copy_ctor115.py` -- 31 tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 fields + 600
  containers + 600 throw + 600 bindings), 0 mismatches on replay
  (`python3 tools/db_options_copy_ctor115.py --verify`).
- Live check (`--live`): all 8 legs pass -- FDE body/source hashes,
  the 57-byte LSDA, the 3-site caller census, the engine-call counts
  (9x `__shared_count` copy, 3x `_M_construct`, 2x `operator new`, 1x
  `__do_uninit_copy`, 2x `__throw_bad_array_new_length`), the copy-map
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

- `include/rocksdb/options.h` declares NO explicit copy constructor
  for `DBOptions` -- only `DBOptions();` (:967) and `explicit
  DBOptions(const Options& options);` (:969) under `struct DBOptions`
  (:447) -- so the binary's `_ZN7rocksdb9DBOptionsC1ERKS0_` is the
  implicitly-defined memberwise copy constructor.
- `options/options.cc:128-130` confirms the shape:
  `DBOptions::DBOptions() {}` is empty (the 93 defaults come from
  in-class member initializers, as the #6337 packet pins), and
  `DBOptions::DBOptions(const Options& options)` delegates to the copy
  ctor (`DBOptions(*static_cast<const DBOptions*>(&options))`).
- The binary's memberwise copy (shared_ptrs shared, vectors/strings
  deep-copied, scalars verbatim) is exactly the implicit copy ctor's
  semantics. `DBOptions(const Options&)` exists only to delegate;
  the work is done here.

Binary-vs-source observations, recorded not hidden:

- The copy ctor is the implicit copy ctor, instantiated in the C API
  translation unit (vendor-census member `25dac13516458d4d-c.o`) --
  not in `options.o` like the default ctor. It is the only
  `DBOptions` ctor the C API's `rocksdb_options_create` path needs
  besides the default ctor.
- The census labels 0x5d35cb0 (the vector destructor used in pad B)
  `vector<TableReader::Anchor>::~vector`; the element loop strides
  0x28, frees a heap string at +0x0 (SSO buffer +0x10) and skips the
  u64 at +0x20, which is exactly `DbPath`'s layout -- the two
  instantiations share the folded address. The packet pins the
  binary behavior, not the template name.
- `basic_string::_M_construct` (0x5d2e540) is NOT in the vendor
  census (a libstdc++ routine); its identity is pinned by its body
  (len = last - first, SSO <= 15, `_M_create` + `memcpy` above, NUL
  at buf[len], stack canary, no LSDA).
- The `db_paths` / `listeners` copies allocate exactly the byte size
  (cap == end, no slack) -- a vector copy constructor, not a
  `reserve` + `push_back` loop.
- Padding bytes the ctor never writes are modelled as zero; the
  binary leaves them uninitialized.

## Open unknowns (not claimed)

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
