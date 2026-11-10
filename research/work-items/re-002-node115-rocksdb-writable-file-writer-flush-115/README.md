# RE-002 · Node #115 RocksDB WritableFileWriter::Flush

Component: storage / WAL / SST file writer. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 flush a `WritableFileWriter` -- what does `Flush` do with a
non-empty buffer under buffered vs direct I/O, when does it call the file's
`Flush`, what listener events does it fire, and when does it `RangeSync`?
All three functions are pinned to the binary; the first two are census-bound
(body hash matches the vendor census `target_body_sha256` exactly; source
hash reproduced by zeroing the recorded relocations, with the GOTPCRELX
mov-lea opcode restored at Flush's two relaxed sites, offsets 1194 and 2383):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::WritableFileWriter::Flush` | 0x6051a20..0x605257c | 2908 | `fc5f4ed6a546b13e6ffeccdf9629bd4f9c1c704c8e8a0e9eaeb0013c679d2bc6` |
| `rocksdb::WritableFileWriter::Flush.cold` | 0x6051938..0x6051a1c | 228 | `be6981880b6cb3112ea941ebda10eb684990c24149069b682b361513e85c2588` |
| `rocksdb::WritableFileWriter::RangeSync` | 0x604d7b0..0x604e01b | 2155 | `ea8c92fe81c54b3e73dfcdf644de23fc169290efcab403030c3c95d101627013` |

The RangeSync member has NO vendor census record: body hash only, per the
#5992 no-census convention.

Scope note: open PR #6041 (WritableFileWriter::Append) took Flush as an
input oracle and left it as the direct follow-up; this packet supersedes
that oracle with the full body model. CORRECTION: the Append packet's
engine-callee note said Flush is "3452 B" -- the FDE is
0x6051a20..0x605257c, 2908 B, plus the 228 B `.cold`. The merged
AddCompressionTypeRecord packet (#5976) likewise noted Flush's body as
"census-bound but not modelled"; this packet models it. The write
routines Flush dispatches to -- `WriteBuffered` 0x604e140,
`WriteBufferedWithChecksum` 0x604f080, `WriteDirect` 0x604fe80,
`WriteDirectWithChecksum` 0x6050c80 -- are input oracles here, not
reconstructed; their bodies are open follow-ups.

## Answer (pinned)

**Signature.** `IOStatus Flush(Env::IOPriority priority)` returns by value,
so `rdi` is the hidden 16-byte sret out-pointer, `rsi` is the `Writer*`,
`edx` the priority.

**1. Seen-error gate (0x6051a4b).** Byte `this+0x89` (`seen_error_`) is read
first. If set, the routine returns at once: sret = code 5 (`kIOError`),
27-byte heap state_ `"Writer has previous error."`, the old sret state_
`delete[]`'d first -- exactly upstream
`AssertFalseAndGetStatusForPrevError()` (`file/writable_file_writer.h:555-563`).
No other member is touched: no write, no file Flush, no RangeSync.

**2. Write step (0x6051a5a..0x6051d26).** Only when `buf_.cursize_`
(`this+0x58`) != 0. The data Slice is `{buf_.bufstart_ (this+0x60),
buf_.cursize_}` and the priority is the Flush argument.

- `use_direct_io()` (vtable slot 12) true: only when `pending_sync_`
  (`this+0x88`) is set does it write -- `WriteDirect(priority)` at
  0x604fe80, or `WriteDirectWithChecksum(priority)` at 0x6050c80 when
  `perform_data_verification_` (`this+0xd1`) AND
  `buffered_data_with_checksum_` (`this+0xd8`) are both set. When
  `pending_sync_` is clear the write is skipped entirely and the status
  stays OK.
- `use_direct_io()` false: `WriteBuffered(Slice, priority)` at 0x604e140,
  or `WriteBufferedWithChecksum(Slice, priority)` at 0x604f080 under the
  same two flags.
- If the write status is not OK: `seen_error_` = 1 and return `s` at once.
  No file Flush, no RangeSync.

`WriteBuffered[WithChecksum]` / `WriteDirect[WithChecksum]` contracts (see
`tools/writable_file_writer_flush115.py`): they write the data straight to
the file in rate-limiter-sized chunks (the model writes it in one oracle
step and records the token grants), clear `buf_` and reset
`buffered_data_crc32c_checksum_` to 0, and advance `flushed_size_`;
`WriteDirect` page-pads the buffer, writes it positionally at
`next_write_offset_`, refits the tail, advances `next_write_offset_` by
the file advance and `flushed_size_` by the padded size. On a scripted
file-Append failure they clear `buf_` and reset the checksum anyway, set
`seen_error_` and return the error.

**3. Listener start times (0x6051a71..0x6051aa6).** Only when `listeners_`
(`this+0xb0`) is non-empty, the binary takes `steady_clock::now()` and
`system_clock::now()` and stores the pair. When the listener list is empty
both timestamps are skipped. There is NO `IOSTATS_TIMER_GUARD` in Flush
itself -- the timestamps exist solely for the listener event below.

**4. IOOptions block (0x6051aa6..0x6051b75).** A 0x58-byte `IOOptions` is
built on the stack with the exact default constants -- timeout 0, prio
`kIOLow` (0), `rate_limiter_priority` `IO_TOTAL` (4), type `kUnknown` (7),
`property_bag` an empty unordered_map (single-bucket self-pointer,
bucket_count 1, max_load_factor 1.0f), `force_dir_fsync` 0,
`do_not_recurse` 0 -- then `rate_limiter_priority` is overwritten with
`DecideRateLimiterPriority(file_priority, priority)` (0x604c800,
census-bound, pure). The file's priority comes from `GetIOPriority`,
vtable slot 16, devirtualized when the slot equals the base implementation
0x5df6e90; otherwise the virtual call runs at 0x60523a8.

**5. File selection + file_->Flush (0x6051b39..0x6051d66).** The file is
selected by `FSWritableFilePtr::operator->()` (`io_tracer_` null OR its
+0x68 enabled byte clear -> the raw file at wrapper+0x28; otherwise the
tracing wrapper at this+0x30). The Flush call itself is devirtualized
through the wrapper layers: the binary peels `[file+0x28]` targets while
vtable slot 8 (0x40) equals the RELATIVE relocation at 0x64ecf70, then
calls slot 8 as `file->Flush(sret, file, io_options, nullptr)` -- i.e.
`FSWritableFile::Flush(const IOOptions&, IODebugContext*)`. The returned
status is move-assigned into the working status (bytes copied out of the
sret, source zeroed, old state_ `delete[]`'d when non-null).

**6. Listener notifications (0x6051dd5..0x6052425).** Only when `listeners_`
is non-empty.

- **Finish event** (always, success or failure): elapsed =
  `steady_clock::now()` - start_steady; an event is built -- `{FileOperationType
  type = 4 (kFlush), WritableFileWriter* this, bool [this+0xd9], uint64 offset
  (NOT written by Flush), uint64 length (NOT written), uint64 elapsed_nanos,
  TimePoint* &start_times, Status status (CopyState deep copy)}` -- and every
  listener is called through vtable slot 35 (0x118), skipping the base no-op
  0x604c670. The slot is the OnFileFlushFinish position; the event struct
  itself is pinned from the binary, not from upstream text.
- **Failure event** (only when the file Flush status is not OK): a second
  event is built -- `{Status status (CopyState deep copy), FileOperationType
  type = 4 (kFlush), std::string file_name_}` -- and every listener is called
  through vtable slot 47 (0x178), skipping the base no-op 0x6042c20. The
  method at slot 47 is an open unknown (see below).

Then the IOOptions `property_bag` is destroyed (call 0x5d36110).

**7. Failure return (0x60521c6..0x60521d3).** When the file Flush status is
not OK (after the notifications): `seen_error_` = 1, sret byte 2 = 0, return
the status. No RangeSync.

**8. RangeSync arm (0x6051f28..0x60521ab).** Only when `!use_direct_io()` AND
`bytes_per_sync_` (`this+0x98`) != 0.

- `filesize_` (`this+0x70`) <= 0x100000 (1 MiB): skip.
- `offset_sync_to = (filesize_ - 0x100000) & ~0xfff` (4 KiB align down);
  `offset_sync_to == 0`: skip.
- `offset_sync_to - last_sync_size_` (`this+0x90`) < `bytes_per_sync_`: skip.
- Else `s = RangeSync(last_sync_size_, offset_sync_to - last_sync_size_)`
  -- the MEMBER RangeSync at 0x604d7b0 (2155 B, no census record; modelled
  as a sub-model below, not a plain oracle) -- and `last_sync_size_` =
  `offset_sync_to` UNCONDITIONALLY afterwards, even when the RangeSync
  status is not OK. On a non-OK status `seen_error_` = 1 as well.

The constants and the shape match upstream Flush
(`writable_file_writer.cc:749-785`) exactly, including the "avoid sync to
the last 1MB" rationale.

**9. Epilogue (0x6051f5b..0x6051fc5).** The working status is copied into the
sret (byte 2 forced to 0), the stack canary is checked and `__stack_chk_fail`
fires on mismatch (0x6052505).

**The `.cold` landing pad (0x6051938, 228 B, census-bound).** Ten endbr64
stubs at the tail of the main FDE (0x605250a..0x6052577) save the exception
object in `rbx` and jump into it at 0x605194a, 0x6051968, 0x605197a,
0x605197f, 0x6051991, 0x60519a3, 0x60519be, 0x60519d4, 0x60519e8 and
0x6051a12. The pad destroys the RangeSync-event strings, destroys the
IOOptions `property_bag` (call 0x5d36110), checks the stack canary, then
`_Unwind_Resume` (or `__stack_chk_fail`). It is unwind-only; no case
exercises it.

## RangeSync member (0x604d7b0..0x604e01b, 2155 B, body hash only)

Signature: `IOStatus RangeSync(uint64_t offset, uint64_t nbytes)` -- sret
`rdi`, this `rsi`, offset `rdx`, nbytes `rcx`. Steps, in binary order:

1. **Seen-error gate (0x604d7e4):** same 27-byte `"Writer has previous
   error."` return as Flush step 1. (Unreachable from Flush -- Flush only
   calls it with `seen_error_` clear -- but part of the member's own
   contract.)
2. **TEST_SYNC_POINT gate (0x604d7f3):** if the sync-point global
   (`*0x64ed5d0`) is non-null, call 0x606d9f0. Upstream:
   `TEST_SYNC_POINT("WritableFileWriter::RangeSync:0")`.
3. **IOSTATS_TIMER_GUARD(range_sync_nanos) (0x604d805..0x604d876, stop at
   0x604dca8..0x604dced):** armed iff `perf_level > 2` (TLS
   `_ZTHN7rocksdb10perf_levelE`); start = `SystemClock::Default()->NowNanos()`
   (vtable slot 20; `SystemClock::Default` at 0x5fe2680, census-bound); the
   elapsed time is added to the TLS `range_sync_nanos` counter at stop. The
   CPU-timer half is DEAD: flag, id and object are zeroed and never set.
4. **Listener start times (0x604d87a..0x604d8af):** only when `listeners_` is
   non-empty, `steady_clock::now()` + `system_clock::now()`.
5. **Own IOOptions (0x604d8af..0x604d975):** a fresh 0x58-byte IOOptions is
   built with the same defaults -- but `rate_limiter_priority` is the FILE's
   `GetIOPriority` directly (no `DecideRateLimiterPriority` call: RangeSync
   takes no op priority). The passed-in IOOptions from Flush is NOT reused
   (its `property_bag` was already destroyed by Flush before the call).
6. **file->RangeSync (0x604d984..0x604d9a6):** file selected the same way;
   virtual slot 23 (0xb8) as `file->RangeSync(sret, file, offset, nbytes,
   io_options, nullptr)` -- i.e. `FSWritableFile::RangeSync(uint64_t,
   uint64_t, const IOOptions&, IODebugContext*)`.
7. **Listener notifications (0x604d9b1..0x604de96):** only when `listeners_`
   is non-empty.
   - Finish event: elapsed = steady now - start steady; event --
     `{FileOperationType type = 7 (kRangeSync), WritableFileWriter* this,
     bool [this+0xd9], uint64 offset, uint64 nbytes, uint64 elapsed_nanos,
     TimePoint* &start_times, Status status (CopyState deep copy)}` -- every
     listener through vtable slot 37 (0x128), skipping the base no-op
     0x604c690. The slot is the OnFileRangeSyncFinish position.
   - Failure event (only when the file RangeSync status is not OK): event --
     `{Status status (CopyState deep copy), FileOperationType type = 7
     (kRangeSync), std::string file_name_}` -- every listener through vtable
     slot 47 (0x178), skipping the base no-op 0x6042c20 (the same slot as
     Flush's failure event).
   Then the IOOptions `property_bag` is destroyed (call 0x5d36110).
8. **Failure bookkeeping (0x604dc90):** when the file RangeSync status is
   not OK, `seen_error_` = 1 (before the notifications run). The member then
   returns the file's status unchanged.
9. **Epilogue:** the status is copied into the sret (byte 2 forced to 0),
   canary checked, return.

**DecideRateLimiterPriority (0x604c800, 39 B, census-bound, verified
instruction by instruction):** both `IO_TOTAL` (4) -> `IO_TOTAL`; file
`IO_TOTAL` -> op priority; op `IO_TOTAL` -> file priority; else op priority.
Exactly upstream `writable_file_writer.cc:1859-1885`.

**Writer layout** (node #115, from the field accesses, confirmed against
upstream `file/writable_file_writer.h`): `file_name_` +0x00 (std::string, 32),
`writable_file_` +0x20 (`FSWritableFilePtr`: `io_tracer_` shared_ptr +0x20/+0x28,
`fs_tracer_` unique_ptr +0x30), `clock_` +0x38, `buf_` +0x40 (`AlignedBuffer`:
`alignment_` +0x40, `buf_` +0x48, `capacity_` +0x50, `cursize_` +0x58,
`bufstart_` +0x60), `max_buffer_size_` +0x68, `filesize_` +0x70 (atomic u64),
`flushed_size_` +0x78, `next_write_offset_` +0x80, `pending_sync_` +0x88,
`seen_error_` +0x89 (atomic bool), `last_sync_size_` +0x90,
`bytes_per_sync_` +0x98, `rate_limiter_` +0xa0, `stats_` +0xa8,
`listeners_` +0xb0 (vector, 24), `checksum_generator_` +0xc8 (unique_ptr),
`checksum_finalized_` +0xd0, `perform_data_verification_` +0xd1,
`buffered_data_crc32c_checksum_` +0xd4 (uint32),
`buffered_data_with_checksum_` +0xd8, `temperature_` +0xdc; total 0xe0.

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **13 direct calls** to Flush, 0 tail jumps, 0 LEA refs; the `.cold`
pad has exactly 1 tail jump from 0x6052523. Call sites:

| site | caller FDE | caller |
|---|---|---|
| 0x5e2641b | 0x5e26300..0x5e26498 | `BlobLogWriter::WriteHeader` |
| 0x5e26987 | 0x5e265c0..0x5e26a03 | `BlobLogWriter::EmitPhysicalRecord` |
| 0x5f03b25 | 0x5f03a90..0x5f03b3d | `log::Writer::WriteBuffer` |
| 0x5f04105 | 0x5f03d60..0x5f0418f | `log::Writer::AddRecord` |
| 0x5f04394 | 0x5f041d0..0x5f0441c | `log::Writer::AddCompressionTypeRecord` |
| 0x5fce232 | 0x5fce130..0x5fce27d | (uncatalogued FDE) |
| 0x5fce6b8 | 0x5fce280..0x5fce766 | (uncatalogued FDE) |
| 0x605269a | 0x60525b0..0x60527a5 | `WritableFileWriter::Pad` |
| 0x60528a6 | 0x6052800..0x60529ee | `WritableFileWriter::Sync` |
| 0x6052e6c | 0x6052b80..0x6054600 | `WritableFileWriter::Close` |
| 0x6054b5d | 0x6054680..0x605518b | `WritableFileWriter::Append` (flush-if-needed arm) |
| 0x6054ef4 | 0x6054680..0x605518b | `WritableFileWriter::Append` (write loop) |
| 0x6054fa1 | 0x6054680..0x605518b | `WritableFileWriter::Append` (write loop) |

Caller names are the vendor-census symbols for each enclosing FDE
(`RE-002-node115-vendor-census`); the two `0x5fce...` FDEs have no census
symbol and stay uncatalogued.

## Evidence

- `tools/writable_file_writer_flush115.py` -- the Flush + RangeSync model.
- `tests/test_writable_file_writer_flush115.py` -- 28 tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 gate + 600 write_paths +
  600 rangesync + 600 bindings), 0 mismatches on replay
  (`python3 tools/writable_file_writer_flush115.py --verify`).
- Live engine check (`--live`): all 4 legs pass -- the model drove a real
  file through a buffered flush (11 B), a direct-I/O flush with a page-aligned
  buffer and leftover tail (5000 logical bytes -> 8192 B physical file), the
  seen-error gate, and the RangeSync arm on a >1 MiB file (last_sync_size_
  1 MiB, real file unchanged by the sync); the model file image equalled the
  real file bytes after every Flush.
- `records.json` -- semantic records only (never a per-instruction mnemonic
  list); `functions.tsv`, `callers.tsv`, `census.json` -- the census above.
- `MANIFEST.sha256` verifies clean; `tools/verify_packets.py` flags only the
  pre-existing mismatch in unrelated packet RE-001-adjacent-last-115 (present
  on clean upstream main, untouched).
- Excerpts are whole-FDE and verbatim (`.hex` + `.objdump.txt` per function),
  with the repo-relative binary path `work/hl-node-115.bin`.

## Upstream cross-check

A 2019 RocksDB mirror (GitLab cracking_rocksdb, commit 876c2dbf) confirms
the Flush skeleton step for step -- the buf_-non-empty write dispatch with
the `pending_sync_` gate on the direct arm, the plain `file_->Flush()` call,
and the `bytes_per_sync` block with the 1 MiB not-synced range, the 4 KiB
align-down, and `RangeSync(last_sync_size_, offset_sync_to - last_sync_size_)`
plus `last_sync_size_ = offset_sync_to`. The mirror PREDATES the binary's
version: it has no IOOptions, no priority arguments, no `seen_error_` /
checksum members, no listener notifications inside Flush, and a 3-line
RangeSync wrapper -- so the binary's seen-error gates, IOOptions builds,
`DecideRateLimiterPriority`, listener events, timer guard and member-RangeSync
body are pinned from the binary alone, NOT from that mirror; the mirror is
evidence for the skeleton only, and the version gap is recorded, not hidden.
The `FileOperationType` values (`kFlush` = 4, `kRangeSync` = 7) are confirmed
by the RocksDB 8.11 changelog ("Added another enumerator kVerify to enum
class FileOperationType in listener.h") and the rocksdbjni 9.0.0 EventListener
docs (`onFileFlushFinish` / `onFileRangeSyncFinish` take FileOperationInfo).

## Open unknowns (not claimed)

- One member the binary reads but the layout above does not name: a bool at
  `this+0xd9`, copied into both finish events (Flush 0x6051df3, RangeSync
  0x604d9cf) -- recorded in the model as `flag_d9`.
- The listener method name for vtable slot 47 (the failure event): the slot
  is the binary's observed position and the `FileOperationType` values (4/7)
  plus the rocksdbjni 9.0.0 docs support OnFileFlushFinish / OnFileRangeSyncFinish
  for slots 35/37, but slot 47's method name is not established, and the slot
  numbers do not line up with the 2019 `listener.h` declaration order
  (ReadFinish is slot 33 per the open #5992 packet, implying ~19 more virtuals
  before it than the 2019 order has). Recorded as open; no name is asserted.
- The exact identity of the +0x18/+0x20 fields in Flush's finish event
  (offset/length, left unwritten by Flush -- likely zero/garbage from the
  uninitialized stack slot).
- `WriteBuffered`, `WriteBufferedWithChecksum`, `WriteDirect`,
  `WriteDirectWithChecksum` bodies are input oracles here; their full
  reconstruction is a follow-up. `WritableFileWriter::Pad` 0x60525b0..0x60527a5
  (501 B, census-bound, a Flush caller) is a follow-up.

## Environment limits (stated honestly)

No cargo/rustc/git-lfs/Ghidra on this VM. The binary is read statically
(`work/hl-node-115.bin`); nothing is executed. `WriteBuffered`,
`WriteBufferedWithChecksum`, `WriteDirect`, `WriteDirectWithChecksum` and
`file_->Flush` / `file->RangeSync` are input oracles with the contracts
above; their bodies are not reconstructed here. `make verify` / `test` /
`catalogue-check` in a tooled environment is still owed upstream.
