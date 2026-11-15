# RE-002 · Node #115 RocksDB WritableFileWriter::Sync

Component: storage / file writer / sync. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does a `WritableFileWriter` sync its file -- what does
`rocksdb::WritableFileWriter::Sync(bool use_fsync)` do when the writer has already
seen an error, when the flush fails, when the file uses direct I/O or has nothing
pending, and when the sync itself fails, and who calls it? Both FDEs are
census-bound (body hashes match the vendor census `target_body_sha256` exactly;
source hashes reproduced by zeroing the census relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::WritableFileWriter::Sync` | 0x6052800..0x60529ee | 494 | `6de1b149335b8aaa0377bd4d0f9a72fe688304c740725e6e4490fea4308fd9d9` |
| `...SyncEb.cold` | 0x60527a6..0x60527fd | 87 | `0f2e32ed5e4030a260198ce167722a997238f3b40fda5d19aae8cc13c3980f7e` |

The full hashes are in `functions.tsv` and `records.json`.

## Answer (pinned)

**Signature.** `IOStatus Sync(bool use_fsync)`; sret out in `rdi`, `this` in `rsi`,
`use_fsync` in `edx` (kept in `r12d`). A `0x30` stack frame, canary stored at
`rsp+0x28` and checked before every return (failure calls `__stack_chk_fail` at
`0x60529d1`). The `.eh_frame` record at section offset `0x7598bc` has length `0x34`,
range `0x1ee`, `aug_len` 4 (LSDA pointer at `0x41ea39` in `.gcc_except_table`); the
`.cold` FDE record at `0x7598f4` has length `0x1c`, range `0x57`, `aug_len` 4 (LSDA at
`0x41ea4d`).

**Decision.** If `seen_error_` (`this+0x89`, `std::atomic<bool>`) is set, return
`AssertFalseAndGetStatusForPrevError()` -- `IOStatus::IOError("Writer has previous
error.", 26 chars, code 5)` -- built fresh at `0x605282a`. Else call `Flush(IO_TOTAL)`
-- the public `Flush` at `0x6051a20` (FDE `0x6051a20..0x605257c`, open PR #6057), the
default argument (`file/writable_file_writer.h:244`) inlined as the constant 4 -- into
the stack-local status at `rsp`; if its code is non-zero, `set_seen_error()`
(`this+0x89 = 1`) and return the copy. Else resolve the file through
`FSWritableFilePtr::get()` inlined: `io_tracer_` is the `shared_ptr` at `this+0x20`,
`fs_tracer_` the `unique_ptr` at `this+0x30`; if `io_tracer_` is non-null and its
`tracing_enabled` byte at `+0x68` is set, the effective file is the tracing wrapper
itself; otherwise it is `fs_tracer_->target()`, the wrapped file at `wrapper+0x28`
(`FSWritableFileWrapper::target_`, after the `FSWritableFile` base: vtable + two `u64` +
two `int` + `bool` + pad = `0x28`). Call `use_direct_io()` on the effective file
(vtable slot 12, `*0x60(%rax)`): the default returns `false`
(`include/rocksdb/file_system.h:1052`), and the tracing wrapper forwards to its target
(`:1685`); `WritableFileWriter`'s own `use_direct_io()` is
`file/writable_file_writer.h:273`. If it returns true, skip the sync: clear
`pending_sync_` (`this+0x88`) and return OK. Else if `pending_sync_` is clear, return
OK the same way. Else call `SyncInternal(use_fsync)` at `0x604c900` (FDE
`0x604c900..0x604d4a7`, `.cold` `0x604c828..0x604c8f5`) into a second stack `IOStatus`
at `rsp+0x10`, move-assign it into the local status at `rsp` (code/subcode, bytes
`+3..+5` and `state_` move over; the destination's severity byte is never written, so
it stays 0 from the OK `Flush` result), then if its code is non-zero,
`set_seen_error()` and return the copy; else clear `pending_sync_` and return OK. The
OK return frees the local status's `state_` buffer (the `SyncInternal` message, when
any) and leaves out a fresh OK; the `Flush`/`SyncInternal` failure copies return the
copy of the local status with severity reset to `kNoError` by the `IOStatus` copy ctor
(`include/rocksdb/io_status.h:171`), so the returned status always has `sev_` 0.

**Status byte layout** (`Status` ctor init order, `include/rocksdb/status.h`): code `u8`
`+0x0`, subcode `u8` `+0x1`, sev `u8` `+0x2`, retryable `bool` `+0x3`, data_loss `bool`
`+0x4`, scope `u8` `+0x5`, padding `+0x6..+0x7` (never written), `state_` `unique_ptr`
`+0x8`. The fresh-error builder writes the code, zeroes the rest, then `new char[len+1]`
and copies the 26-char message in two `movdqa` chunks (bytes 0..9 from `0x451480`,
bytes 10..25 from `0x452bf0` -- the same chunks as `SyncWithoutFlush`).

**Throws.** Main LSDA at `0x41ea39`: 3 call-site entries, all cleanup, action 0 -- `[0]`
start `0x43` len 5 pad `0x1d6` (the prev-error `new[]` -> stub `0x60529d6` -> `.cold`
`0x60527a6`), `[1]` start `0xa6` len 5 no pad (the `Flush` call), `[2]` start `0xd3`
len `0x21` pad `0x1e2` (the `use_direct_io` call at `0xd3` and the `SyncInternal` call
at `0xef`, sharing the stub `0x60529e2` -> `.cold` `0x60527cc`). Cold LSDA at
`0x41ea4d`: 1 entry, start `0x21` len `0x2c`, no pad. A throw from `Flush` therefore
propagates with no cleanup of this function (`out` untouched, `seen_error_`
unchanged); a throw from `use_direct_io` or from `SyncInternal` lands in the `.cold`
cleanup at `0x60527cc`, which deletes the local status's `state_` (null after the OK
`Flush`), checks the canary, and calls `_Unwind_Resume`; a failed `new[]` lands in
the `.cold` cleanup at `0x60527a6`, which deletes the out `state_` (null at that
point), checks the canary, and calls `_Unwind_Resume` -- a bad canary in either block
calls `__stack_chk_fail` instead of resuming. The 116 main instructions and 20 cold
instructions are verified verbatim by `--live`.

**Callers.** Exactly 11 direct calls, 0 tail jumps, 0 LEA refs (whole-`.text` E8/E9/LEA
scan, Capstone-validated): `rocksdb::DBImpl::SyncClosedLogs` (site `0x5ddd278`, FDE
`0x5ddd080..0x5ddd673`, census-bound, `db_impl_compaction_flush.o`),
`rocksdb::CompactionOutputs::WriterSyncClose` (site `0x5e1881a`, FDE
`0x5e183f0..0x5e18b3b`, census-bound, `compaction_outputs.o`), `rocksdb::BuildTable`
(site `0x5e1eed6`, FDE `0x5e1b9c0..0x5e20481`; the main FDE has no census record, its
`.cold` is census-bound as `BuildTable`, `builder.o`), `rocksdb::BlobLogWriter::Sync`
(site `0x5e261ac`, FDE `0x5e26110..0x5e262c4`, census-bound, `blob_log_writer.o`),
`rocksdb::DBImpl::Open` (sites `0x5e63cce` and `0x5e650c7`, FDE `0x5e62c50..0x5e65462`,
census-bound, `db_impl_open.o`), `rocksdb::DBImpl::WriteToWAL` (site `0x5e8a1d2`, FDE
`0x5e89c90..0x5e8a4a9`, census-bound, `db_impl_write.o`), `rocksdb::CreateFile` (site
`0x603a9aa`, FDE `0x603a5a0..0x603ad3e`, census-bound, `file_util.o`),
`rocksdb::CopyFile` (site `0x603bcda`, FDE `0x603ae70..0x603bfd6`, census-bound,
`file_util.o`), `rocksdb::SyncManifest` (site `0x603fb3d`, FDE `0x603fa00..0x603ff25`,
census-bound, `filename.o`), `rocksdb::PersistRocksDBOptions` (site `0x60d43ff`, FDE
`0x60d2820..0x60d49d3`, census-bound, `options_parser.o`) -- the file-sync callers
upstream uses: `DBImpl::Open` syncs the WAL and manifest, `WriteToWAL` syncs after a
write batch, `SyncManifest` and the options persist path sync their files, and the
compaction-output and table-builder paths sync on close.

**Upstream cross-check.** RocksDB v8.1.1 (`meta/rocksdb`, read live this cycle) defines
this helper exactly as the binary behaves -- `file/writable_file_writer.cc:432-453`
(`seen_error()` -> `AssertFalseAndGetStatusForPrevError`; `s = Flush()`; on failure
`set_seen_error()` and return `s`; `if (!use_direct_io() && pending_sync_) { s =
SyncInternal(use_fsync); if (!s.ok()) { set_seen_error(); return s; } }`;
`pending_sync_ = false`; return `IOStatus::OK()`) -- `file/writable_file_writer.h:244`
declares `Flush` with the default `Env::IO_TOTAL`, `:273` defines `use_direct_io()` as
`writable_file_->use_direct_io()`, `:286-294` defines `seen_error()` /
`set_seen_error()`, and `env/file_system_tracer.h:345-383` defines `FSWritableFilePtr`
and its `get()`. The vendored `WritableFileWriter` layout differs from a stock v8.1.1
compile (`checksum_generator_` at `+0xc8`, `seen_error_` at `+0x89`); the model follows
the binary offsets, pinned by the two binary anchors.

## Cases

300 deterministic cases (`cases.tsv`, generated by `tools/sync115.py`):

- 100 checks: 50 combos (tracer state x direct-I/O x `pending_sync` x `Flush` result x
  `SyncInternal` result x `use_fsync`) x 2 `seen_error` states.
- 100 edge: 10 base combos x 10 conditions (normal, `Flush` throws, `use_direct_io`
  throws, `SyncInternal` throws, `new[]` fails in the `IOError` path, bad canary on
  return, `Flush` throw with bad canary, `SyncInternal` throw with bad canary, `new[]`
  failure with bad canary, empty sync message), pinning that the `Flush` throw has no
  landing pad, that the `use_direct_io`/`SyncInternal` throws share the `.cold`
  cleanup, that a failed `new[]` lands in `.cold`, and that a bad canary becomes
  `StackCheckFailed`.
- 100 bindings: 25 (writer, `use_fsync`) pairs x 4 recorded invariants (`body_sha256`,
  `source_sha256`, `fde_record`, `caller_census`) — each row records the invariant's
  expected value and replay compares it.

0 mismatches on replay (`--verify-cases`). 16 tests pass (`tests/test_sync115.py`).
Live check (`--live`, 33 legs) passes: artifact digest, both body hashes, both source
hashes (11 + 6 census relocations), both FDE records (lengths `0x34`/`0x1c`, ranges
`0x1ee`/`0x57`, `aug_len` 4, LSDA pointers `0x41ea39`/`0x41ea4d`), both LSDA call-site
tables (3 + 1 entries), the 116 + 20 verbatim instructions, the 8-call shape (7 direct
+ 1 indirect, `Flush` at `0x6051a20`, `SyncInternal` at `0x604c900`, 1 `new[]`, 3
`delete[]`, vtable slot 12), the 26-char message byte reconstruction, the 11-call
caller census, and the model end-to-end legs (prev-error / flush-fail / direct-io skip
/ `pending_sync` clear / ok / `seen_error` set / severity reset / wrapper-vs-target /
throws / bad-alloc / bad-canary).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never executed. The tool
models the helper in Python from its whole-FDE disassembly; `Flush` (open PR #6057)
and `SyncInternal` are oracles whose results are inputs to the model.
`make verify/test/catalogue-check` in a tooled environment is still owed upstream.
