# RE-002 · Node #115 RocksDB WritableFileWriter::SyncWithoutFlush

Component: storage / file writer / sync. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does a `WritableFileWriter` sync its file without flushing its buffer -- what does
`rocksdb::WritableFileWriter::SyncWithoutFlush(bool use_fsync)` do when the writer has
already seen an error, when the underlying file is not sync-thread-safe, and when the
sync itself fails, and who calls it? Both FDEs are census-bound (body hashes match the
vendor census `target_body_sha256` exactly; source hashes reproduced by zeroing the
census relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::WritableFileWriter::SyncWithoutFlush` | 0x604d500..0x604d6bd | 445 | `6904e218743d50b49106216aa2edf1b408c832b9e228319c8fc2d7615385b3df` |
| `...SyncWithoutFlushEb.cold` | 0x604d4a8..0x604d4fe | 86 | `88100ca53220c63d8ba9c7e6f02b925acfa2fed83a3236f8b78ed067ba719b10` |

The full hashes are in `functions.tsv` and `records.json`.

## Answer (pinned)

**Signature.** `IOStatus SyncWithoutFlush(bool use_fsync)`; sret out in `rdi`, `this` in
`rsi`, `use_fsync` in `edx` (kept in `r12d`). A `0x20` stack frame, canary stored at
`rsp+0x18` and checked before every return (failure calls `__stack_chk_fail` at
`0x604d6a0`). The `.eh_frame` record at section offset `0x759550` has length `0x34`,
range `0x1bd`, `aug_len` 4 (LSDA pointer at `0x41e76e` in `.gcc_except_table`); the
`.cold` FDE record at `0x759588` has length `0x1c`, range `0x56`, `aug_len` 4 (LSDA at
`0x41e786`).

**Decision.** If `seen_error_` (`this+0x89`, `std::atomic<bool>`) is set, return
`AssertFalseAndGetStatusForPrevError()` -- `IOStatus::IOError("Writer has previous
error.", 26 chars, code 5)` -- built fresh at `0x604d640` (the NDEBUG assert on
`sync_without_flush_called_` is compiled out). Else resolve the file through
`FSWritableFilePtr::get()` inlined: `io_tracer_` is the `shared_ptr` at `this+0x20`,
`fs_tracer_` the `unique_ptr` at `this+0x30`; if `io_tracer_` is non-null and its
`tracing_enabled` byte at `+0x68` is set, the effective file is the tracing wrapper
itself; otherwise it is `fs_tracer_->target()`, the wrapped file at `wrapper+0x28`
(`FSWritableFileWrapper::target_`, after the `FSWritableFile` base: vtable + two `u64` +
two `int` + `bool` + pad = `0x28`). Call `IsSyncThreadSafe()` on the effective file
(vtable slot 11, `*0x58(%rax)`): the default returns `false`
(`include/rocksdb/file_system.h:1048`), and the tracing wrapper forwards to its target
(`:1683`). If false, return `IOStatus::NotSupported` with the 94-char message `"Can't
WritableFileWriter::SyncWithoutFlush() because WritableFile::IsSyncThreadSafe() is
false"` (code 3). Else call `SyncInternal(use_fsync)` at `0x604c900` (FDE
`0x604c900..0x604d4a7`, `.cold` `0x604c828..0x604c8f5`) into a stack `IOStatus`; if its
code is non-zero, `set_seen_error()` (`this+0x89 = 1`); return the copy of that status
-- the `IOStatus` copy ctor (`include/rocksdb/io_status.h:171`) resets severity to
`kNoError`, so the returned status always has `sev_` 0, with code/subcode/retryable/
data_loss/scope/`state_` copied.

**Status byte layout** (`Status` ctor init order, `include/rocksdb/status.h`): code `u8`
`+0x0`, subcode `u8` `+0x1`, sev `u8` `+0x2`, retryable `bool` `+0x3`, data_loss `bool`
`+0x4`, scope `u8` `+0x5`, padding `+0x6..+0x7` (never written), `state_` `unique_ptr`
`+0x8`. The fresh-error builders write the code, zero the rest, then `new char[len+1]`
and copy the message in 16-byte `movdqa` chunks (the 94-char message's last chunk starts
at buffer `+0x4e`, overlapping the previous chunk by 2 bytes; the 26-char message's
second chunk starts at `+0xa`).

**Throws.** Main LSDA at `0x41e76e`: 4 call-site entries, all cleanup, action 0 -- `[0]`
start `0x4e` len 3 no pad (the `IsSyncThreadSafe` call), `[1]` start `0x72` len 5 pad
`0x1b1` (the `NotSupported` `new[]` -> stub `0x604d6b1` -> `.cold` `0x604d4ce`), `[2]`
start `0x102` len 5 no pad (the `SyncInternal` call), `[3]` start `0x159` len 5 pad
`0x1a5` (the `IOError` `new[]` -> stub `0x604d6a5` -> `.cold` `0x604d4a8`). Cold LSDA
at `0x41e786`: 1 entry, start `0x21` len `0x2b`, no pad. A throw from `IsSyncThreadSafe`
or from `SyncInternal` therefore propagates with no cleanup of this function (`out`
untouched, `seen_error_` unchanged); a failed `new[]` lands in the `.cold` cleanup,
which deletes the out `state_` (null at that point), checks the canary, and calls
`_Unwind_Resume` -- a bad canary there calls `__stack_chk_fail` instead of resuming.
The two `.cold` cleanup blocks are identical in effect and are reached from the two
different landing-pad stubs. The 105 main instructions and 20 cold instructions are
verified verbatim by `--live`.

**Callers.** Exactly 1 direct call, 0 tail jumps, 0 LEA refs (whole-`.text` E8/E9/LEA
scan, Capstone-validated): `rocksdb::DBImpl::SyncWAL` (site `0x5d7f657`, FDE
`0x5d7f3b0..0x5d7fb40`, census-bound, `db_impl.o`) -- the WAL-sync path, the same
caller upstream `db_impl.cc` uses.

**Upstream cross-check.** RocksDB v8.1.1 (`meta/rocksdb`, read live this cycle) defines
this helper exactly as the binary behaves -- `file/writable_file_writer.cc:455-474`
(`seen_error()` -> `AssertFalseAndGetStatusForPrevError`; `!writable_file_->
IsSyncThreadSafe()` -> `NotSupported` with the 94-char message; `SyncInternal
(use_fsync)`; on failure `set_seen_error()`; return `s`) -- `file/writable_file_writer.h:
296-301` defines `AssertFalseAndGetStatusForPrevError` as `IOStatus::IOError("Writer
has previous error.")`, `:286-294` defines `seen_error()` / `set_seen_error()`, and
`env/file_system_tracer.h:345-383` defines `FSWritableFilePtr` and its `get()`. The
vendored `WritableFileWriter` layout differs from a stock v8.1.1 compile
(`checksum_generator_` at `+0xc8`, `seen_error_` at `+0x89`); the model follows the
binary offsets, pinned by the two binary anchors.

## Cases

300 deterministic cases (`cases.tsv`, generated by `tools/sync_without_flush115.py`):

- 100 checks: 50 combos (tracer state x thread-safety x `use_fsync` x `SyncInternal`
  result: OK / IOError / NotSupported / NotFound, some with subcode, retryable,
  data_loss or scope) x 2 `seen_error` states.
- 100 edge: 10 base combos x 10 conditions (normal, `IsSyncThreadSafe` throws,
  `SyncInternal` throws, `new[]` fails in the `NotSupported` path, `new[]` fails in
  the `IOError` path, bad canary on return, throw with bad canary, `new[]` failure
  with bad canary, empty sync message), pinning that the two virtual/engine throws
  have no landing pad, that a failed `new[]` lands in `.cold`, and that a bad canary
  becomes `StackCheckFailed`.
- 100 bindings: 25 (writer, `use_fsync`) pairs x 4 recorded invariants (`body_sha256`,
  `source_sha256`, `fde_record`, `caller_census`) — each row records the invariant's
  expected value and replay compares it.

0 mismatches on replay (`--verify-cases`). 14 tests pass
(`tests/test_sync_without_flush115.py`). Live check (`--live`, 32 legs) passes:
artifact digest, both body hashes, both source hashes (15 + 6 census relocations),
both FDE records (lengths `0x34`/`0x1c`, ranges `0x1bd`/`0x56`, `aug_len` 4, LSDA
pointers `0x41e76e`/`0x41e786`), both LSDA call-site tables (4 + 1 entries), the
105 + 20 verbatim instructions, the 6-call shape (5 direct + 1 indirect, `SyncInternal`
at `0x604c900`, 2 `new[]`, vtable slot 11), the two message byte reconstructions,
the 1-call caller census, and the model end-to-end legs (prev-error / not-supported /
ok / `seen_error` set / severity reset / wrapper-vs-target / throws / bad-alloc /
bad-canary).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never executed. The tool
models the helper in Python from its whole-FDE disassembly; `SyncInternal` is an oracle
whose result is an input to the model. `make verify/test/catalogue-check` in a tooled
environment is still owed upstream.
