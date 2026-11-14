# RE-002 · Node #115 RocksDB WritableFileWriter::WriteBufferedWithChecksum

Component: storage / SST file writer. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 flush a buffered write with its checksum -- how does the
rate limiter drain before the single file Append, what checksum is handed
off, what does each step cost in listener events and timer guards, and what
happens when the Append fails? Both functions are pinned to the binary; the
main body has NO vendor census record (body hash only, per the #5992
no-census convention) and the `.cold` IS census-bound (body hash matches the
vendor census `target_body_sha256` exactly; source hash reproduced by zeroing
the 14 recorded relocations, kinds 2/4; no kind-42 relocation, so no
GOTPCRELX restoration applies):

| function | FDE | size | body SHA-256 |
|---|---|---|---:|
| `rocksdb::WritableFileWriter::WriteBufferedWithChecksum` | 0x604f080..0x604fd97 | 3351 | `fc3c41a26936962546b56e0fc736a889923b776a48b864edb6038e6a2bda1d4c` |
| `rocksdb::WritableFileWriter::WriteBufferedWithChecksum.cold` | 0x604ef0e..0x604f079 | 363 | `b8f141f440ff4f95813e455e5a3fe3ef6e30c0450897655934fd46899b7bee48` |

Scope note: open PR #6088 (WritableFileWriter::WriteBuffered) took
WriteBufferedWithChecksum as an input oracle and left it as the direct
follow-up; open PR #6057 (WritableFileWriter::Flush) calls it at 0x6052490;
open PR #6041 (WritableFileWriter::Append) calls it at 0x6054ed9 and
0x605507b (its two verification arms). This packet supersedes those oracle
notes with the full body model. `WriteBuffered`, `WriteDirect`,
`WriteDirectWithChecksum`, the `RangeSync` member, `UpdateFileChecksum` and
`DecideRateLimiterPriority` are input oracles here, not reconstructed; their
bodies are open follow-ups.

## Answer (pinned)

**Signature.** `IOStatus WriteBufferedWithChecksum(const char* data, size_t
size, Env::IOPriority priority)` returns by value, so `rdi` is the hidden
16-byte sret out-pointer, `rsi` is the `Writer*`, `rdx` the data, `rcx` the
size, `r8d` the priority.

**1. Seen-error gate (0x604f0ae).** Byte `this+0x89` (`seen_error_`) is read
first. If set, the routine returns at once: sret = code 5 (`kIOError`),
27-byte heap state_ `"Writer has previous error."`, the old sret state_
`delete[]`'d first -- exactly upstream
`AssertFalseAndGetStatusForPrevError()` (`file/writable_file_writer.h:555-563`).
No other member is touched: no file call, no buffer change.

**2. IOOptions + file priority (0x604f0bd..0x604f1a1).** The file's
`GetIOPriority` (vtable slot 16, devirtualized when the slot equals the
RELATIVE reloc at 0x64ecf30, else the virtual call at 0x604f948) feeds
`DecideRateLimiterPriority` (0x604c800, census-bound, pure) with the op
priority; a 0x58-byte `IOOptions` is built on the stack with the exact
defaults (timeout 0, prio `kIOLow` 0, `rate_limiter_priority` the Decide
result, type `kUnknown` 7, `property_bag` an empty unordered_map,
`force_dir_fsync` 0, `do_not_recurse` 0).

**3. Rate-limiter DRAIN loop (0x604f1a2..0x604f1e7), NOT a chunk loop.** When
`rate_limiter_` (`this+0xa0`) is non-null AND the decided priority !=
`IO_TOTAL` (4) AND `size` != 0, while `data_size > 0`: `granted =
rate_limiter_->RequestToken(data_size, buf_.Alignment() (this+0x40), decided
priority, stats_ (this+0xa8), OpType kWrite = 1)` -- vtable slot 6, base impl
0x61c43f0; `data_size -= granted`. The grants are DISCARDED -- no write
happens in the loop; exactly ONE file Append follows (upstream TODO: "need to
be improved since it sort of defeats the purpose of the rate limiter").
PINNED DIFFERENCE from WriteBuffered, which passes alignment 0
(`xor edx,edx` at 0x604e2d8): here the alignment is `buf_.Alignment()`
(`mov 0x40(%rbx),%rdx` at 0x604f1ca). A decided `IO_TOTAL` priority skips the
limiter entirely even when one exists.

**4. Sync-point gate + timer-guard halves.** Four sync-point gates per call
(0x604f1e9, 0x604f315, 0x604f5f9, 0x604f621), all through the helper 0x606d9f0
when the sync-point global `*0x64ed5d0` is non-null. The string names are not
pinned from the binary -- the literals are stripped (verified absent from the
node #115 binary); upstream v8.1.1 names the loop's `TEST_SYNC_POINT`
`"WritableFileWriter::Flush:BeforeAppend"` and the success-path kill point
`"WritableFileWriter::WriteBuffered:0"` (`TEST_KILL_RANDOM`). The nanos guard
is armed iff `perf_level > 2` (clock = `*SystemClock::Default()`, 0x5fe2680,
dereferenced once; start = `NowNanos`, slot 20; stop adds the elapsed time
to the TLS counter at `fs-0x3f8+0x28`); the CPU guard is armed iff
`perf_level > 3` (clock = `this->clock_` or `Default()` when null; start =
the CPU-time accessor, slot 22; stop adds to the TLS counter at
`fs-0x3f8+0x58`). The stops are INLINE in the main FDE (CPU 0x604f8b8 before
the listener events; nanos 0x604f900 on the success path, 0x604f849..0x604f8ad
on the failure path after the sret build); the shared destructor 0x604c6b6
runs only from `.cold` (unwind).

**5. `file->GetFileSize(io_options, nullptr)` (0x604f2c9, vtable slot 18).**
The uint64 return is DISCARDED by the caller (stored to a stack slot the
listener-event path overwrites with `next_write_offset_` before any read);
the method is identified by its signature plus the
`FSWritableFileTracingWrapper::GetFileSize` symbol (0x600a770), but why
upstream calls it here is an open unknown.

**6. Listener start times (0x604f2d4).** Only when `listeners_`
(`this+0xb0`) is non-empty, `steady_clock::now()` + `system_clock::now()`;
`next_write_offset_` is saved for the event.

**7. perf_level save (0x604f310).** The TLS `perf_level` byte is read
(0x606ddd0) and restored after the Append (0x604f475, 0x606ddb0) -- the file
Append may clobber it, so the caller's level is preserved across the call.

**8. Checksum handoff (0x604f3cd..0x604f3ef).**
`EncodeFixed32(checksum_buf, buffered_data_crc32c_checksum_ (this+0xd4))` --
the checksum handed to the file is the writer's ACCUMULATED buffered value,
NOT a fresh `crc32c::Extend` over the data (that is WriteBuffered's per-chunk
dispatch). There is NO verification gate in the binary (the upstream asserts
are compiled out), so the checksum arm is always taken.

**9. Single `file->Append` (0x604f432, vtable slot 3).**
`writable_file_->Append(Slice{data, size}, io_options, DataVerificationInfo{
Slice{&crc, 4}}, nullptr)`. No loop and NO zero-size short-circuit (unlike
WriteBuffered): size 0 still runs one zero-length Append carrying the buffered
checksum, then the success epilogue. The result is written to a 16-byte stack
`IOStatus` at `rsp+0x70` and then copied (bytes 0-1, 3-4, 5, 8-15; byte 2
forced to 0 in the epilogue).

**10. Listener events (0x604f483..0x604f5cc, 0x604f960..).** Only when
`listeners_` is non-empty. Finish event (always): `{FileOperationType type =
1 (kWrite), WritableFileWriter* this, bool [this+0xd9], uint64 offset =
next_write_offset_, uint64 length = size, uint64 elapsed_nanos, TimePoint*
&start_times, Status status (CopyState deep copy at 0x61cf610)}` through
vtable slot 34 (0x110), skipping the base no-op 0x604c660. Failure event
(only when the Append status is not OK): `{Status status (CopyState deep
copy), FileOperationType type = 8 (kAppend), std::string file_name_, uint64
left = size, uint64 old_size}` through vtable slot 47 (0x178), skipping the
base no-op 0x6042c20. The type 8 is `kAppend` (v8.1.1
`include/rocksdb/listener.h:236-248`, implicit 0-based: kRead 0, kWrite 1,
kTruncate 2, kClose 3, kFlush 4, kSync 5, kFsync 6, kRangeSync 7, kAppend 8)
-- exactly upstream `NotifyOnIOError(s, kAppend, file_name(), left,
old_size)`; the trailing u64s are the (allowed, old_size) arguments. PINNED
DIFFERENCE from WriteBuffered: its failure event trails (granted,
`next_write_offset_`).

**11. Failure return (0x604f7fb).** When the Append status is not OK,
`buf_.cursize_` is cleared to 0 and `buffered_data_crc32c_checksum_` reset to
0 in the failure epilogue -- AFTER the notifications (pinned difference from
WriteBuffered, which clears immediately after the failed Append, before the
events); `seen_error_` = 1 AFTER the notifications; the sret is built (byte
2 forced to 0); the nanos guard stops at 0x604f849..0x604f8ad; no retry;
`flushed_size_` is NOT advanced.

**12. Success path.** Nanos-guard stop (0x604f900, elapsed -> the TLS counter
at `fs-0x3f8+0x28`), `TEST_SYNC_POINT` #3 (0x604f5f9, the `TEST_KILL_RANDOM`
`"WritableFileWriter::WriteBuffered:0"` site), then -- when the TLS flag at
`fs-0x3f8+0x98` is clear -- `TEST_SYNC_POINT` #4 (0x604f62b) and the TLS
counter at `fs-0x3f8+0x8` advances by the size (the flag's identity is an
open unknown).

**13. Epilogue (0x604f644..0x604f699).** `buf_.Size(0)`,
`buffered_data_crc32c_checksum_` = 0, `flushed_size_` (`this+0x78`) += size,
the working status is copied into the sret (byte 2 forced to 0), the
`IOOptions` `property_bag` is destroyed (0x5d36110), the stack canary is
checked and `__stack_chk_fail` fires on mismatch.

**The `.cold` landing pad (0x604ef0e, 363 B, census-bound).** Four tail jumps
at 0x604fca8, 0x604fd2c, 0x604fd38 and 0x604fd44 (four of the twenty-one
`endbr64` stubs at the main FDE tail, 0x604fca1..0x604fd95) enter it:
`delete[]` the sret state_ when non-null, destroy the failure-event strings,
stop both timer guards through the shared destructor 0x604c6b6, destroy the
`IOOptions` `property_bag`, check the stack canary, then `_Unwind_Resume`
(or `__stack_chk_fail`). It is unwind-only; no case exercises it.

**DecideRateLimiterPriority (0x604c800, 39 B, census-bound, verified
instruction by instruction in the Flush packet):** both `IO_TOTAL` (4) ->
`IO_TOTAL`; file `IO_TOTAL` -> op priority; op `IO_TOTAL` -> file priority;
else op priority. Exactly upstream `writable_file_writer.cc:1859-1885`.
Used by the `IOOptions` build here and by the Flush oracle.

**Writer layout** (node #115, from the field accesses, confirmed against
upstream `file/writable_file_writer.h` and the Append #6041 / Flush #6057 /
WriteBuffered #6088 packets): `file_name_` +0x00 (std::string, 32),
`writable_file_` +0x20 (`FSWritableFilePtr`: `io_tracer_` +0x20/+0x28,
`fs_tracer_` +0x30), `clock_` +0x38, `buf_` +0x40 (`AlignedBuffer`:
`alignment_` +0x40, `buf_` +0x48, `capacity_` +0x50, `cursize_` +0x58,
`bufstart_` +0x60), `max_buffer_size_` +0x68, `filesize_` +0x70,
`flushed_size_` +0x78, `next_write_offset_` +0x80, `pending_sync_` +0x88,
`seen_error_` +0x89, `last_sync_size_` +0x90, `bytes_per_sync_` +0x98,
`rate_limiter_` +0xa0, `stats_` +0xa8, `listeners_` +0xb0 (vector, 24),
`checksum_generator_` +0xc8 (unique_ptr), `checksum_finalized_` +0xd0,
`perform_data_verification_` +0xd1, `buffered_data_crc32c_checksum_` +0xd4
(uint32), `buffered_data_with_checksum_` +0xd8, unnamed bool +0xd9 (read
into the finish event, open unknown), `temperature_` +0xdc; total 0xe0.

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **3 direct calls** to WriteBufferedWithChecksum, 0 tail jumps, 0 LEA
refs; the `.cold` pad has exactly 4 tail jumps from 0x604fca8, 0x604fd2c,
0x604fd38 and 0x604fd44. The callers:

| site | caller FDE | caller |
|---|---|---|
| 0x6052490 | 0x6051a20..0x605257c | `rocksdb::WritableFileWriter::Flush` |
| 0x6054ed9 | 0x6054680..0x605518b | `rocksdb::WritableFileWriter::Append` |
| 0x605507b | 0x6054680..0x605518b | `rocksdb::WritableFileWriter::Append` |

WriteBufferedWithChecksum itself never calls Flush, Pad, RangeSync,
WriteBuffered or WriteDirect; the file's Flush/RangeSync and WriteDirect are
not reached from here. It calls `file->Append` (vtable slot 3, with
checksum) and `file->GetFileSize` (vtable slot 18) through the file pointer,
not by direct call -- so no direct call sites for those appear in the scan;
the slot numbers are pinned by the disassembly and the bindings group.

## Evidence

- `tools/writable_file_writer_writebufferedwithchecksum115.py` -- the
  WriteBufferedWithChecksum model (plus the Flush oracle at #6057 fidelity
  and the Append oracle at #6041 fidelity, used for the live check).
- `tests/test_writable_file_writer_writebufferedwithchecksum115.py` -- 32
  tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 gate + 600 grant_loop + 600
  checksum + 600 bindings), 0 mismatches on replay
  (`python3 tools/writable_file_writer_writebufferedwithchecksum115.py
  --verify`).
- Live engine check (`--live`): all 8 legs pass -- the model drove a real
  file through a 5000-byte drain loop (grants [2000, 2000, 1000] drain
  exactly, then one Append of 5000 B), a handoff checksum pin (the
  file_append events carry the entry buffered value 0x12345678 for every
  size), the seen-error gate, a zero-size run that still makes one
  zero-length Append, a single-Append failure (no `flushed_size_` advance,
  `seen_error_` set after the notifications, buf_ cleared, checksum reset),
  listeners + both guards armed (perf 5, finish event type 1, offset =
  `next_write_offset_`, both guard counters advance), an `IO_TOTAL` priority
  skipping the limiter, and a failure event carrying type 8 = `kAppend`
  with trailing (left = 10, old_size = 777); the model file image equalled
  the real file bytes after every WriteBufferedWithChecksum.
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
(`file/writable_file_writer.cc`, `WriteBufferedWithChecksum`, lines
1220-1395), confirms the packet step for step: the seen-error gate
(`AssertFalseAndGetStatusForPrevError`), the `IOOptions` build with
`DecideRateLimiterPriority`, the rate-limiter DRAIN loop (`RequestToken`
with `buf_.Alignment()`, decided priority, `stats_`, `OpType::kWrite`, and
the upstream TODO that it "sort of defeats the purpose of the rate
limiter"), the `TEST_SYNC_POINT` gate, the `IOSTATS_TIMER_GUARD` halves
(`write_nanos` / `cpu_write_nanos`), the `GetFileSize` call, the listener
start times and the perf-level save/restore, the checksum handoff
(`EncodeFixed32(checksum_buf, buffered_data_crc32c_checksum_)` then a single
`writable_file_->Append(Slice(src, left), io_options, v_info, nullptr)`),
the failure path (buf clear, checksum reset, `seen_error_` set after the
notifications), and the success epilogue (`IOSTATS_ADD(bytes_written,
left)`, `TEST_KILL_RANDOM`, `buf_.Size(0)`, checksum reset, `flushed_size_ +=
left`).

CORRECTION (found this cycle while cross-checking): the #6088 packet cites
`WriteBuffered` as upstream lines 544-636, but the raw v8.1.1 file
`writable_file_writer.cc` puts `WriteBuffered` at lines 1040-1217 (its
544-636 range is inside Close/Flush); the line citation in #6088 is wrong
and is fixed in-PR separately. The binary model in #6088 is unaffected.

RESOLVED this cycle: the failure event type 8 is `FileOperationType::kAppend`
(`include/rocksdb/listener.h:236-248`, implicit 0-based: kRead 0, kWrite 1,
kTruncate 2, kClose 3, kFlush 4, kSync 5, kFsync 6, kRangeSync 7, kAppend 8,
kPositionedAppend 9, kOpen 10) -- exactly upstream `NotifyOnIOError(s,
kAppend, file_name(), left, old_size)` in `WriteBufferedWithChecksum`
(lines 1390-1393). It follows the sibling pattern exactly: Flush's failure
event carries its own op (4 = kFlush) and RangeSync's carries 7 = kRangeSync.

Binary-vs-source observations, recorded not hidden:

- The `GetFileSize` return is discarded by the caller even though the call
  is made once: upstream stores it in `old_size` and then overwrites
  `old_size` with `next_write_offset_` when listeners exist; when no
  listeners exist `old_size` keeps the file size but is never read. The
  binary stores it to a stack slot the listener-event path overwrites
  before any read -- same effect.
- The binary has NO zero-size branch -- size 0 still runs one zero-length
  Append (upstream has no zero-size branch either, the same observable
  behaviour).
- The binary runs the `TEST_KILL_RANDOM` sync point BEFORE the
  `IOSTATS_ADD(bytes_written)` while upstream lists the bytes add first
  (line 1369 vs 1371) -- same observable behaviour, a scheduling difference.
- Upstream's post-epilogue `if (!s.ok()) set_seen_error()` is unreachable in
  practice (failures return early) and has no counterpart in the binary
  epilogue.
- Upstream's asserts (`assert(!use_direct_io())`,
  `assert(perform_data_verification_ && buffered_data_with_checksum_)`) are
  compiled out in the release binary; the model does not enforce them, and
  the checksum arm is always taken.
- Upstream names the loop's `TEST_SYNC_POINT`
  `"WritableFileWriter::Flush:BeforeAppend"` (a verbatim copy-paste name,
  despite being in `WriteBufferedWithChecksum`) and the success-path kill
  point `"WritableFileWriter::WriteBuffered:0"` (`TEST_KILL_RANDOM`), while
  the binary's string literals are stripped (verified absent from the node
  #115 binary), so per-site names are not pinned from the binary. The binary
  calls the sync-point helper 0x606d9f0 from four sites (0x604f1e9, 0x604f315,
  0x604f5f9, 0x604f621) while upstream shows two named points -- the extra
  two sites are an open mapping question.
- The two timer-guard halves stop asymmetrically: the CPU guard stops at
  0x604f8b8 BEFORE the listener events on both paths, while the nanos guard
  stops AFTER the events -- at 0x604f900 on the success path and at
  0x604f849..0x604f8ad (after the sret build) on the failure path. The shared
  destructor 0x604c6b6 runs only from `.cold` (unwind); the main-FDE stops
  are inline calls to the clock methods.
- The checksum is a HANDOFF, not a fresh computation: the binary
  `EncodeFixed32`'s the writer's accumulated
  `buffered_data_crc32c_checksum_` into the 4-byte v_info slice and never
  calls the `crc32c::Value` helper (0x604c7e0) -- WriteBuffered's per-chunk
  `crc32c::Extend` dispatch is absent here. The live check pins this.

## Open unknowns (not claimed)

- `file->GetFileSize` (slot 18) once: the return is discarded, so its
  purpose in `WriteBufferedWithChecksum` is open. It is called with the same
  `IOOptions` as the Append and with a null debug context; the tracing
  wrapper's `GetFileSize` (0x600a770) is the only symbol that matches the
  signature.
- The TLS flag byte at `fs-0x3f8+0x98` gating the IOStats bytes counter
  (+0x8) add: its identity is open. Modelled as `iostats_bytes_flag`
  (default clear = count).
- The 0x61cf610 helper's symbol: the census labels it `Status::CopyState`
  (one arg) but the call sites pass (dst, src). Recorded as an open unknown;
  the deep-copy behaviour is pinned.
- The four sync-point sites vs upstream's two named points (see the
  cross-check): the extra two sites are an open mapping question.
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
- `Flush`, `Append`, `WriteBuffered`, `WriteDirect`,
  `WriteDirectWithChecksum` and the `RangeSync` member are input oracles
  here; their full reconstruction is a follow-up. The next natural
  follow-ups: `WriteDirect` 0x604fe80 (3338 B),
  `WriteDirectWithChecksum` 0x6050c80 (3255 B) -- the two remaining engine
  callees Flush dispatches to; or `DBImpl::CreateWAL` 0x5e5c270..0x5e5c9a3
  (caller of `AddCompressionTypeRecord`); or the unidentified FDE 0x60d4cf0
  (`SequentialFileReader::Read` caller, open unknown from #5992).

## Environment limits (stated honestly)

No cargo/rustc/git-lfs/Ghidra on this VM. The binary is read statically
(`work/hl-node-115.bin`); nothing is executed. `Flush`, `Append`,
`WriteBuffered`, `WriteDirect`, `WriteDirectWithChecksum`, `RangeSync` and
the file's `Flush`/`RangeSync`/`Append`/`GetFileSize` are input oracles with
the contracts from open PRs #6057 (Flush), #6041 (Append) and #6088
(WriteBuffered); their bodies are not reconstructed here. `make verify` /
`test` / `catalogue-check` in a tooled environment is still owed upstream.
