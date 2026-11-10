# RE-002 · Node #115 RocksDB WritableFileWriter::WriteBuffered

Component: storage / SST file writer. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 write buffered data to the underlying file -- how are the
writes chunked through the rate limiter, what does each chunk cost in
listener events and timer guards, when is a checksum handed off, and what
happens when a chunk's file Append fails? Both functions are pinned to the
binary; the main body has NO vendor census record (body hash only, per the
#5992 no-census convention) and the `.cold` IS census-bound (body hash
matches the vendor census `target_body_sha256` exactly; source hash
reproduced by zeroing the 14 recorded relocations, kinds 2/4; no kind-42
relocation, so no GOTPCRELX restoration applies):

| function | FDE | size | body SHA-256 |
|---|---|---|---:|
| `rocksdb::WritableFileWriter::WriteBuffered` | 0x604e140..0x604ef0d | 3533 | `06a1e5e0e8db73e3e78c70a40c074f7fd0a13ec28aa2773f2e711e25418bb520` |
| `rocksdb::WritableFileWriter::WriteBuffered.cold` | 0x604e01c..0x604e139 | 285 | `bf9ad78f14064a86e0b5e76320c974950347600d2fa20a4c40af1d0e598c8c8d` |

Scope note: open PR #6057 (WritableFileWriter::Flush) took WriteBuffered as
an input oracle and left it as the direct follow-up; open PR #6041
(WritableFileWriter::Append) takes it as its engine callee (two call sites
in its write loop); open PR #6070 (WritableFileWriter::Pad) reaches it
through Flush. This packet supersedes those oracle notes with the full body
model. `WriteBufferedWithChecksum`, `WriteDirect`, `WriteDirectWithChecksum`,
the `RangeSync` member, `UpdateFileChecksum` and `DecideRateLimiterPriority`
are input oracles here, not reconstructed; their bodies are open follow-ups.

## Answer (pinned)

**Signature.** `IOStatus WriteBuffered(const char* data, size_t size,
Env::IOPriority priority)` returns by value, so `rdi` is the hidden 16-byte
sret out-pointer, `rsi` is the `Writer*`, `rdx` the data, `rcx` the size,
`r8d` the priority.

**1. Seen-error gate (0x604e17a).** Byte `this+0x89` (`seen_error_`) is read
first. If set, the routine returns at once: sret = code 5 (`kIOError`),
27-byte heap state_ `"Writer has previous error."`, the old sret state_
`delete[]`'d first -- exactly upstream
`AssertFalseAndGetStatusForPrevError()` (`file/writable_file_writer.h:555-563`).
No other member is touched: no file call, no buffer change.

**2. IOOptions + file priority (0x604e18d..0x604e26b).** The file's
`GetIOPriority` (vtable slot 16, devirtualized when the slot equals the
RELATIVE reloc at 0x64ecf30, else the virtual call at 0x604ee59) feeds
`DecideRateLimiterPriority` (0x604c800, census-bound, pure) with the op
priority; a 0x58-byte `IOOptions` is built on the stack with the exact
defaults (timeout 0, prio `kIOLow` 0, `rate_limiter_priority` the Decide
result, type `kUnknown` 7, `property_bag` an empty unordered_map,
`force_dir_fsync` 0, `do_not_recurse` 0).

**3. Zero-size short-circuit (0x604e26b -> 0x604ee85).** When `size` is 0 the
routine returns OK at once (code 0, empty state_) -- but `buf_.cursize_` is
STILL cleared to 0 and `buffered_data_crc32c_checksum_` reset to 0
(0x604e7cd). Upstream has no separate zero-size branch (see the cross-check
below): the `while (left > 0)` loop is simply skipped and the epilogue does
the same clearing, so the observable behaviour is identical.

**4. Chunk loop (0x604e2b0 back-edge, while remaining > 0).**

- **(a) Rate-limiter grant.** When `rate_limiter_` (`this+0xa0`) is non-null
  AND the decided priority != `IO_TOTAL` (4), `granted =
  rate_limiter_->RequestToken(remaining, alignment 0, decided priority,
  stats_ (this+0xa8), OpType kWrite = 1)` -- vtable slot 6, base impl
  0x61c43f0; otherwise `granted = remaining` (0x604e850). A decided
  `IO_TOTAL` priority skips the limiter entirely even when one exists.
- **(b) Sync-point gates + timer-guard halves.** Four sync-point gates per
  successful chunk (0x604e2ec, 0x604e414, 0x604e767, 0x604e78f), all through
  the helper 0x606d9f0 when the sync-point global `*0x64ed5d0` is non-null.
  The string names are not pinned from the binary -- the literals are
  stripped (verified absent from the node #115 binary); upstream v8.1.1
  names the loop's `TEST_SYNC_POINT`
  `"WritableFileWriter::Flush:BeforeAppend"` and the success-path kill point
  `"WritableFileWriter::WriteBuffered:0"` (`TEST_KILL_RANDOM`). The nanos
  guard is armed iff `perf_level > 2` (clock = `*SystemClock::Default()`,
  0x5fe2680, dereferenced once; start = `NowNanos`, slot 20; stop adds the
  elapsed time to the TLS counter at `fs-0x3f8+0x28`); the CPU guard is armed
  iff `perf_level > 3` (clock = `this->clock_` or `Default()` when null;
  start = the CPU-time accessor, slot 22; stop adds to the TLS counter at
  `fs-0x3f8+0x58`). The stops are INLINE in the main FDE (CPU 0x604ea60
  before the listener events; nanos 0x604eaa0 on the success path, 0x604e9fd
  on the failure path after the sret build); the shared destructor 0x604c6b6
  runs only from `.cold` (unwind).
- **(c) `file->GetFileSize(io_options, nullptr)` (0x604e3c5, vtable slot 18).**
  The uint64 return is DISCARDED by the caller (stored to a stack slot the
  listener-event path overwrites with `next_write_offset_` before any read);
  the method is identified by its signature plus the
  `FSWritableFileTracingWrapper::GetFileSize` symbol (0x600a770), but why
  upstream calls it here is an open unknown.
- **(d) Listener start times (0x604e3d0).** Only when `listeners_`
  (`this+0xb0`) is non-empty, `steady_clock::now()` + `system_clock::now()`;
  `next_write_offset_` is saved for the event.
- **(e) perf_level save (0x604e40f).** The TLS `perf_level` byte is read
  (0x606ddd0) and restored after the Append (0x604e5d0, 0x606ddb0) -- the file
  Append may clobber it, so the caller's level is preserved across the call.
- **(f) Checksum dispatch (0x604e4c0).** When `perform_data_verification_`
  (`this+0xd1`) is set, the chunk CRC is computed by the 19-byte helper at
  0x604c7e0 -- `crc = crc32c::Extend(0, data, granted)` through the
  0x61c25f0 dispatch thunk, written to a 4-byte stack buffer -- and
  `file->Append(Slice{data, granted}, io_options, Slice{&crc, 4}, nullptr)`
  is called (vtable slot 3, 0x604e999); otherwise
  `file->Append(Slice{data, granted}, io_options, nullptr)` (vtable slot 2,
  0x604e520). The checksum is a fresh `crc32c::Value` per chunk, not a
  running checksum.
- **(g) On a non-OK Append status (0x604e5b9).** `buf_.cursize_` is cleared to
  0 and `buffered_data_crc32c_checksum_` reset to 0 at once; the failure is
  reported after the listener events (below).
- **(h) Listener events (0x604e5de..0x604e740, 0x604eae8..).** Only when
  `listeners_` is non-empty. Finish event (always): `{FileOperationType
  type = 1 (kWrite), WritableFileWriter* this, bool [this+0xd9], uint64
  offset = next_write_offset_, uint64 length = granted, uint64
  elapsed_nanos, TimePoint* &start_times, Status status (CopyState deep
  copy at 0x61cf610)}` through vtable slot 34 (0x110), skipping the base
  no-op 0x604c660. Failure event (only when the Append status is not OK):
  `{Status status (CopyState deep copy), FileOperationType type = 8
  (kAppend), std::string file_name_, uint64 granted, uint64
  next_write_offset_}` through vtable slot 47 (0x178), skipping the base
  no-op 0x6042c20. The type 8 is `kAppend` (v8.1.1
  `include/rocksdb/listener.h:236-248`, implicit 0-based: kRead 0, kWrite 1,
  kTruncate 2, kClose 3, kFlush 4, kSync 5, kFsync 6, kRangeSync 7, kAppend 8)
  -- exactly upstream `NotifyOnIOError(s, FileOperationType::kAppend,
  file_name(), allowed, old_size)`; the trailing u64s are the (allowed,
  old_size) arguments. This resolves the open unknown the prior draft
  recorded.
- **(i) Failure return (0x604e9b0).** When the Append status is not OK (after
  the notifications), `seen_error_` = 1 and the status is returned (byte 2
  forced to 0). No retry, no further chunks; `flushed_size_` is NOT advanced
  for the failed chunk (earlier successful chunks keep their advance).
- **(j) Success path.** Nanos-guard stop (0x604eaa0, elapsed -> the TLS
  counter at `fs-0x3f8+0x28`), then a third `TEST_SYNC_POINT` (0x604e767),
  then -- when the TLS flag at `fs-0x3f8+0x98` is clear -- a fourth
  `TEST_SYNC_POINT` (0x604e78f) and the TLS counter at `fs-0x3f8+0x8`
  advances by the granted bytes (the flag's identity is an open unknown). On
  the failure path the nanos guard stops instead at 0x604e9fd, after the
  sret build, and there is no bytes add.
- **(k) Advance (0x604e7b2..0x604e7c7).** `data += granted`, `flushed_size_`
  (`this+0x78`) += granted, `remaining -= granted`; loop while `remaining !=
  0`.

**5. Epilogue (0x604e7cd).** `buf_.cursize_` = 0,
`buffered_data_crc32c_checksum_` = 0, the working status is copied into the
sret (byte 2 forced to 0), the `IOOptions` `property_bag` is destroyed
(0x5d36110), the stack canary is checked and `__stack_chk_fail` fires on
mismatch.

**The `.cold` landing pad (0x604e01c, 285 B, census-bound).** A single tail
jump at 0x604eeae (one of the ten `endbr64` stubs at the main FDE tail,
0x604eea7..0x604ef07) enters it: `delete[]` the sret state_ when non-null,
destroy the failure-event strings, stop both timer guards through the shared
destructor 0x604c6b6, destroy the `IOOptions` `property_bag`, check the stack
canary, then `_Unwind_Resume` (or `__stack_chk_fail`). It is unwind-only; no
case exercises it.

**DecideRateLimiterPriority (0x604c800, 39 B, census-bound, verified
instruction by instruction in the Flush packet):** both `IO_TOTAL` (4) ->
`IO_TOTAL`; file `IO_TOTAL` -> op priority; op `IO_TOTAL` -> file priority;
else op priority. Exactly upstream `writable_file_writer.cc:1859-1885`.
Used by the `IOOptions` build here and by the Flush oracle.

**Writer layout** (node #115, from the field accesses, confirmed against
upstream `file/writable_file_writer.h` and the Append #6041 / Flush #6057
packets): `file_name_` +0x00 (std::string, 32), `writable_file_` +0x20
(`FSWritableFilePtr`: `io_tracer_` +0x20/+0x28, `fs_tracer_` +0x30),
`clock_` +0x38, `buf_` +0x40 (`AlignedBuffer`: `alignment_` +0x40, `buf_`
+0x48, `capacity_` +0x50, `cursize_` +0x58, `bufstart_` +0x60),
`max_buffer_size_` +0x68, `filesize_` +0x70, `flushed_size_` +0x78,
`next_write_offset_` +0x80, `pending_sync_` +0x88, `seen_error_` +0x89,
`last_sync_size_` +0x90, `bytes_per_sync_` +0x98, `rate_limiter_` +0xa0,
`stats_` +0xa8, `listeners_` +0xb0 (vector, 24), `checksum_generator_` +0xc8
(unique_ptr), `checksum_finalized_` +0xd0, `perform_data_verification_`
+0xd1, `buffered_data_crc32c_checksum_` +0xd4 (uint32),
`buffered_data_with_checksum_` +0xd8, unnamed bool +0xd9 (read into the
finish event, open unknown), `temperature_` +0xdc; total 0xe0.

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **2 direct calls** to WriteBuffered, 0 tail jumps, 0 LEA refs; the
`.cold` pad has exactly 1 tail jump from 0x604eeae. The callers:

| site | caller FDE | caller |
|---|---|---|
| 0x6051cc5 | 0x6051a20..0x605257c | `rocksdb::WritableFileWriter::Flush` |
| 0x6054d23 | 0x6054680..0x605518b | `rocksdb::WritableFileWriter::Append` |

WriteBuffered itself never calls Flush, Pad or RangeSync; the file's
Flush/RangeSync and WriteDirect are not reached from here. It calls
`file->Append` (vtable slots 2/3) and `file->GetFileSize` (vtable slot 18)
through the file pointer, not by direct call -- so no direct call sites for
those appear in the scan; the slot numbers are pinned by the disassembly and
the bindings group.

## Evidence

- `tools/writable_file_writer_writebuffered115.py` -- the WriteBuffered model
  (plus the Flush oracle at #6057 fidelity and the Append oracle at #6041
  fidelity, used for the live check).
- `tests/test_writable_file_writer_writebuffered115.py` -- 34 tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 gate + 600 grant_loop + 600
  checksum + 600 bindings), 0 mismatches on replay
  (`python3 tools/writable_file_writer_writebuffered115.py --verify`).
- Live engine check (`--live`): all 8 legs pass -- the model drove a real
  file through a 5000-byte grant loop, a per-chunk checksum split (grants
  [5, 6] over "hello world" give `Value("hello")` and `Value(" world")`),
  the seen-error gate, a zero-size clear, a mid-loop Append failure (first
  chunk keeps its advance, second chunk does not, `seen_error_` set, buffer
  cleared, checksum reset), listeners + both guards armed (perf 5, finish
  event type 1, offset = `next_write_offset_`, both guard counters advance),
  an `IO_TOTAL` priority skipping the limiter, and a failure event carrying
  type 8 = `kAppend` with trailing (granted, `next_write_offset_`); the
  model file image equalled the real file bytes after every WriteBuffered.
- `records.json` -- semantic records only (never a per-instruction mnemonic
  list); `functions.tsv`, `callers.tsv`, `census.json` -- the census above.
- `MANIFEST.sha256` verifies clean; `tools/verify_packets.py` flags only the
  pre-existing mismatch in unrelated packet RE-001-adjacent-last-115 (present
  on clean upstream main, untouched).
- Excerpts are whole-FDE and verbatim (`.hex` + `.objdump.txt` per function),
  with the repo-relative binary path `work/hl-node-115.bin` (no absolute
  home paths).

## Upstream cross-check

`facebook/rocksdb` v8.1.1, read live this cycle
(`file/writable_file_writer.cc`, `WriteBuffered`, lines 544-636), confirms the
packet step for step: the seen-error gate
(`AssertFalseAndGetStatusForPrevError`), the `IOOptions` build with
`DecideRateLimiterPriority`, the rate-limiter grant loop (`RequestToken`
with alignment 0, decided priority, `stats_`, `OpType::kWrite`), the
`TEST_SYNC_POINT` gate, the `IOSTATS_TIMER_GUARD` halves (`write_nanos` /
`cpu_write_nanos`), the `GetFileSize` call, the listener start times and the
perf-level save/restore, the checksum dispatch (`Crc32cHandoffChecksumCalculation`
+ `Append(..., v_info, nullptr)` vs plain `Append`), the failure path (buf
clear, checksum reset, `seen_error_` set after the notifications), and the
epilogue (`buf_.Size(0)`, checksum reset, return `s`).

CORRECTION: the prior draft cited lines 124-196 -- that range is inside
`Append`; `WriteBuffered` is 544-636 (verified against the GitHub symbol list
and line numbers this cycle).

RESOLVED this cycle: the failure event type 8 is `FileOperationType::kAppend`
(`include/rocksdb/listener.h:236-248`, implicit 0-based: kRead 0, kWrite 1,
kTruncate 2, kClose 3, kFlush 4, kSync 5, kFsync 6, kRangeSync 7, kAppend 8,
kPositionedAppend 9, kOpen 10) -- exactly upstream `NotifyOnIOError(s,
FileOperationType::kAppend, file_name(), allowed, old_size)` in
`WriteBuffered` (lines 613-615). It follows the sibling pattern exactly:
Flush's failure event carries its own op (4 = kFlush) and RangeSync's carries
7 = kRangeSync.

Binary-vs-source observations, recorded not hidden:

- The `GetFileSize` return is discarded by the caller even though the call
  is made every chunk: upstream stores it in `old_size` and then overwrites
  `old_size` with `next_write_offset_` when listeners exist (lines 575-580);
  when no listeners exist `old_size` keeps the file size but is never read.
  The binary stores it to a stack slot the listener-event path overwrites
  before any read -- same effect.
- The binary has a separate zero-size branch (0x604e26b -> 0x604ee85) while
  upstream has none: the `while (left > 0)` loop is simply skipped and the
  epilogue clears `buf_` and resets the checksum -- same observable
  behaviour.
- Upstream's post-loop `if (!s.ok()) set_seen_error()` is unreachable in
  practice (failures return early in-loop) and has no counterpart in the
  binary epilogue.
- Upstream's `assert(!use_direct_io())` is compiled out in the release
  binary; the model does not enforce it.
- Upstream names the loop's `TEST_SYNC_POINT`
  `"WritableFileWriter::Flush:BeforeAppend"` (a verbatim copy-paste name,
  despite being in `WriteBuffered`) and the success-path kill point
  `"WritableFileWriter::WriteBuffered:0"` (`TEST_KILL_RANDOM`), while the
  binary's string literals are stripped (verified absent from the node #115
  binary), so per-site names are not pinned from the binary. The binary
  calls the sync-point helper 0x606d9f0 from four sites per chunk
  (0x604e2ec, 0x604e414, 0x604e767, 0x604e78f) while upstream shows two named
  points per iteration -- the extra two sites are an open mapping question.
- The two timer-guard halves stop asymmetrically: the CPU guard stops at
  0x604ea60 BEFORE the listener events on both paths, while the nanos guard
  stops AFTER the events -- at 0x604eaa0 on the success path and at 0x604e9fd
  (after the sret build) on the failure path. The shared destructor
  0x604c6b6 runs only from `.cold` (unwind); the main-FDE stops are inline
  calls to the clock methods.
- The checksum is a fresh `crc32c::Value` per chunk, not a running checksum:
  the helper at 0x604c7e0 computes `Extend(0, data, granted)` for each chunk
  independently, so a multi-chunk write with verification on produces one
  Value per chunk. The live check pins this.

## Open unknowns (not claimed)

- `file->GetFileSize` (slot 18) per chunk: the return is discarded, so its
  purpose in `WriteBuffered` is open. It is called with the same `IOOptions`
  as the Append and with a null debug context; the tracing wrapper's
  `GetFileSize` (0x600a770) is the only symbol that matches the signature.
- The TLS flag byte at `fs-0x3f8+0x98` gating the IOStats bytes counter
  (+0x8) add: its identity is open. Modelled as `iostats_bytes_flag`
  (default clear = count).
- The 0x61cf610 helper's symbol: the census labels it `Status::CopyState`
  (one arg) but the call sites pass (dst, src). Recorded as an open unknown;
  the deep-copy behaviour is pinned.
- The four sync-point sites vs upstream's two named points per iteration
  (see the cross-check): the extra two sites are an open mapping question.
- Vtable slot 22 (0xb0) is the CPU-time accessor: inferred from the
  timer-guard destructor dispatching on the guard's cpu-flag byte (0 ->
  `NowNanos` slot 20, 1 -> slot 22). `NowNanos` is slot 20 per the Flush
  packet.
- The listener method name for vtable slot 47: the slot is the binary's
  observed position; no name is asserted.
- The bool at `this+0xd9`, read into the finish event: it is not named by
  the Append packet's writer layout and no upstream header in the 2019
  mirror has a member at that offset. Modelled as `flag_d9` and listed here
  as an open unknown (shared with the Flush packet).
- `Flush`, `Append`, `WriteBufferedWithChecksum`, `WriteDirect`,
  `WriteDirectWithChecksum` and the `RangeSync` member are input oracles
  here; their full reconstruction is a follow-up. The next natural
  follow-ups: `WriteBufferedWithChecksum` 0x604f080 (3351 B),
  `WriteDirect` 0x604fe80 (3338 B), `WriteDirectWithChecksum` 0x6050c80
  (3255 B) -- the three remaining engine callees Flush dispatches to; or
  `DBImpl::CreateWAL` 0x5e5c270..0x5e5c9a3 (caller of
  `AddCompressionTypeRecord`); or the unidentified FDE 0x60d4cf0
  (`SequentialFileReader::Read` caller, open unknown from #5992).

## Environment limits (stated honestly)

No cargo/rustc/git-lfs/Ghidra on this VM. The binary is read statically
(`work/hl-node-115.bin`); nothing is executed. `Flush`, `Append`,
`WriteBufferedWithChecksum`, `WriteDirect`, `WriteDirectWithChecksum`,
`RangeSync` and the file's `Flush`/`RangeSync`/`Append`/`GetFileSize` are
input oracles with the contracts from open PRs #6057 (Flush) and #6041
(Append); their bodies are not reconstructed here. `make verify` / `test` /
`catalogue-check` in a tooled environment is still owed upstream.
