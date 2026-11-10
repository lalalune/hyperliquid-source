# RE-002: reconstruct node #115 `rocksdb::WritableFileWriter::WriteDirectWithChecksum`

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `WritableFileWriter::WriteDirectWithChecksum(Env::IOPriority
priority)` -- the direct-I/O write step Flush uses when
`pending_sync_` is set and the buffer carries a checksum: pad the
buffer to the alignment, recompute the buffered checksum over the pad,
drain the rate limiter (grants discarded), then ONE `PositionedAppend`
of the whole padded buffer carrying the recomputed checksum. 2,400
byte-checked cases; 34 tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). Two FDEs, both pinned by recomputation:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::WritableFileWriter::WriteDirectWithChecksum` | `0x6050c80..0x6051937` | 3255 B | `cc22775ea5d3906acc8f401a09272eb2d6942514ae9c922067e756bf5d139de8` | none (body-hash-only, per the #5992 no-census convention) |
| `...::WriteDirectWithChecksum.cold` | `0x6050b8a..0x6050c7d` | 243 B | `eb4e08d3e3f13c068bc367c21fc7a9ecbfe27db362d7d04a2d6a35111930637c` | `node115-vendor-6050b8a`, 12 relocations (kinds 2/4, no kind-42), source hash `20e5f8ed80fc0035ad0c006fc8cefc9b641a7526d03f21e4c861c9ab99fd1721` (recomputed) |

Symbol (from the `.cold` census record):
`_ZN7rocksdb18WritableFileWriter23WriteDirectWithChecksumENS_3Env10IOPriorityE.cold`,
member `a895f7517936a0f7-writable_file_writer.o`, librocksdb-sys
0.11.0+8.1.1. The main FDE has no census record -- the same split as
Flush (#6057), Append (#6041), WriteBufferedWithChecksum (#6094) and
WriteDirect (#6204), whose mains are also body-hash-only.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `IOStatus WriteDirectWithChecksum(Env::IOPriority priority)`;
sret `rdi`, `this` `rsi`, priority `rdx`. The buffer IS the input (no
separate `Slice` argument -- the data to write is `buf_`, the writer's
own buffer).

**1. Seen-error gate (0x6050cb0).** If `seen_error_` is set, return
inline: code 5, with a 27-byte heap `state_` copy of `"Writer has
previous error."`. No file write, no limiter, no listener event.

**2. Page pad.** `pad = Roundup(cursize, alignment) - cursize` (division
at 0x6050d4f); `memset` at 0x6051488 when `pad != 0`. `file_advance` /
`leftover_tail` are computed LAZILY at the success epilogue
(0x60513e0..0x6051402) from the saved entry cursize_ (`r13`) and
alignment (`-0x210`), not up front: the pad step only rounds cursize_
up, and the single `PositionedAppend` writes the whole padded buffer.
The failure path restores cursize_ from the same two saved values
(`file_advance + leftover_tail = entry cursize_`).

**3. Checksum recompute over the pad (0x6050d61..0x6050d95),
UNCONDITIONAL.** `buffered = Crc32cCombine(old, Extend(0, bufstart_ +
entry_cursize_, pad), pad)` via the dispatch thunks 0x61c25f0
(`Extend`) / 0x61c2600 (`Combine`). There is NO
`perform_data_verification_` / `buffered_data_with_checksum_` gate
anywhere in the FDE -- the recompute runs on every call. `pad == 0`
gives the degenerate combine `Combine(old, 0, 0) = old` (no `len2 == 0`
early return). The live check pins this (the `positioned_append`
event carries `Combine(0x12345678, Value(501 zero bytes), 501)`,
never the entry buffered value alone and never a fresh per-chunk
`Extend`). PINNED DIFFERENCE from WriteDirect (fresh per-chunk
`Extend`, gated ONLY on `perform_data_verification_`) and from
WriteBufferedWithChecksum (handoff of the buffered value as-is, no
pad recompute).

**4. `IOOptions` + file priority (0x6050d82..0x6050e79).** No `GetFileSize`
call, no `perf_level` save/restore. `GetIOPriority` slot 16,
devirtualized vs the RELATIVE reloc 0x64ecf30, else virtual call
0x6051740; `DecideRateLimiterPriority` 0x604c800 (39 B, census-bound,
verified instruction by instruction in the Flush packet): both
`IO_TOTAL` (4) -> `IO_TOTAL`; file `IO_TOTAL` -> op priority; op
`IO_TOTAL` -> file priority; else op priority. Exactly upstream
`writable_file_writer.cc:1859-1885`.

**5. Rate-limiter DRAIN (0x6050e80..0x6050ecf).** `RequestToken(remaining,
alignment, decided, stats, kWrite=1)` slot 6 (base 0x61c43f0); the
grants are DISCARDED -- the drain loops until the remainder is 0,
then ONE `PositionedAppend` of the whole padded buffer follows. The
grants change nothing about the write, only whether the drain runs at
all: limiter non-null AND `decided != IO_TOTAL` AND `left != 0`. The
live check pins this (grants `[4096, 4096]` drain, one 8192-byte
append).

**6. Sync-point gate (0x6050ed1).** Through the helper 0x606d9f0 when
the sync-point global `*0x64ed5d0` is non-null. Three
`TEST_SYNC_POINT` gates fire PER CALL (0x6050ed1 drain-head, 0x6051398
success-path, 0x60513c0 bytes-add); the bytes-add gate fires only
when the IOStats-bytes flag is clear -- it sits between the flag check
and the bytes add. The string names are not asserted (the binary's
literals are stripped); the model records the site addresses.

**7. Timer guard.** Nanos armed iff `perf_level > 2` (clock
`*SystemClock::Default()` 0x5fe2680, `NowNanos` slot 20, TLS counter
`fs-0x3f8+0x28`). The CPU half is DEAD: the flag byte at `-0x18f` is
written 0 at 0x6050eff and never set, the second clock slot at
`-0x170` is never filled, and no clock-or-default helper is called,
so the slot-22 stop at 0x6051331 is unreachable and the stop always
takes the `NowNanos` branch (0x6051768). The model records
`wdwc_cpu_nanos = 0` at every perf level, and the bindings group pins
`timer_guard_cpu_armed = False` for perf levels 0..5. This is a
pinned difference from both siblings, whose CPU halves are armed iff
`perf_level > 3`.

**8. Listener start times (0x6050f7e..0x6050fb0).** Only when
`listeners_` is non-empty.

**9. Checksum handoff (0x6050fb7..0x6050fd3), UNCONDITIONAL.**
`v_info.checksum = Slice(checksum_buf, 4)` with the post-recompute
buffered value; `PositionedAppend` ALWAYS via slot 5 (0x605101b).

**10. Single `PositionedAppend` (0x6050fda..0x6051043).** Size = `left`
(the padded cursize); it runs even when `left == 0` -- the
entry-empty path makes a ZERO-LENGTH `PositionedAppend` (pinned
difference from WriteDirect, which skips its loop). The live check
pins this (`empty_buffer_zero_length_append`).

**11. Listener events.** Finish event always type 1 (`kWrite`), slot 34
(0x110), base no-op 0x604c660. Failure event only when the
`PositionedAppend` status is not OK, type 9 (`kPositionedAppend`),
slot 47 (0x178), base no-op 0x6042c20, trailing u64s (size,
write_offset) where size is the PADDED size. Type 9 is
`kPositionedAppend` (v8.1.1 `include/rocksdb/listener.h:449-473`,
implicit 0-based: kRead 0, kWrite 1, kTruncate 2, kClose 3, kFlush 4,
kSync 5, kFsync 6, kRangeSync 7, kAppend 8, kPositionedAppend 9,
kOpen 10) -- exactly upstream `NotifyOnIOError(s, kPositionedAppend,
file_name(), size, write_offset)`. PINNED DIFFERENCE from
WriteBufferedWithChecksum, whose failure event trails (left, old_size)
with type 8.

**12. Failure return (0x60512ad..0x6051377).** `cursize_` = ENTRY
cursize_; the buffered checksum is recomputed FRESH as `Extend(0,
bufstart_, entry_cursize)` (seed 0, NOT Combine); `seen_error_` = 1
AFTER the notifications; the nanos stop runs after the sret build;
`flushed_size_` is NOT advanced. PINNED DIFFERENCE from
WriteBufferedWithChecksum (which clears `buf_` and resets the checksum
to 0 after the events) and from WriteBuffered (which clears
immediately after the failed Append, before the events).

**13. Success path (0x6051380..0x6051480).** Nanos stop 0x60516f0 if
armed; sync-point 0x6051398; TLS flag clear -> sync-point 0x60513c0 +
TLS bytes counter += `left`; `flushed_size_ += left`; `leftover != 0`
-> `memmove` tail (0x6051750); `cursize_ = leftover`; the buffered
checksum is recomputed FRESH as `Extend(0, bufstart_, leftover)` AFTER
the `RefitTail` memmove -- so the `Extend` reads the tail bytes at
their new position (the buffer start), not their old one; an
entry-empty success (leftover 0) RESETS it to 0; `next_write_offset_
+= file_advance`. `filesize_` is NEVER advanced. The live check pins
the success checksum (the buffered checksum after the 5000-byte write
equals `Value` of the 904-byte tail).

**The `.cold` landing pad (0x6050b8a, 243 B, census-bound).** One tail
jump at 0x60518de (one of the fourteen `endbr64` stubs at the main FDE
tail, 0x6051895..0x6051932; thirteen jump into `.cold` -- one to the
entry, twelve interior -- and one jumps to another stub) enters it:
destroy the `file_name_` string copy, `delete[]` the saved sret
state_ when non-null, stop the timer guard through the shared
destructor 0x604c6b6, destroy the `IOOptions` `property_bag`, check the
stack canary, then `_Unwind_Resume` (or `__stack_chk_fail`). It is
unwind-only; no case exercises it.

**Writer layout** (node #115, from the field accesses, confirmed against
upstream `file/writable_file_writer.h` and the Append #6041 / Flush
#6057 / WriteBuffered #6088 / WriteBufferedWithChecksum #6094 /
WriteDirect #6204 packets): `file_name_` +0x00 (std::string, 32),
`writable_file_` +0x20 (`FSWritableFilePtr`: `io_tracer_` +0x20/+0x28,
`fs_tracer_` +0x30), `clock_` +0x38, `buf_` +0x40 (`AlignedBuffer`:
`alignment_` +0x40, `buf_` +0x48, `capacity_` +0x50, `cursize_` +0x58,
`bufstart_` +0x60), `max_buffer_size_` +0x68, `filesize_` +0x70 (never
read or written here), `flushed_size_` +0x78, `next_write_offset_`
+0x80, `pending_sync_` +0x88, `seen_error_` +0x89, `last_sync_size_`
+0x90, `bytes_per_sync_` +0x98, `rate_limiter_` +0xa0, `stats_` +0xa8,
`listeners_` +0xb0 (vector, 24), `checksum_generator_` +0xc8
(unique_ptr), `checksum_finalized_` +0xd0,
`perform_data_verification_` +0xd1 (READ here: gates nothing -- the
pad recompute is unconditional), `buffered_data_crc32c_checksum_`
+0xd4 (uint32, READ: the recompute's base), `buffered_data_with_checksum_`
+0xd8 (NOT consulted), unnamed bool +0xd9 (read into the finish event,
open unknown), `temperature_` +0xdc; total 0xe0.

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **1 direct call** to WriteDirectWithChecksum, 0 tail jumps, 0
LEA refs; the `.cold` pad has exactly 1 tail jump from 0x60518de. The
caller:

| site | caller FDE | caller |
|---|---|---|
| 0x60523b1 | 0x6051a20..0x605257c | `rocksdb::WritableFileWriter::Flush` |

WriteDirectWithChecksum itself never calls Flush, Pad, RangeSync,
WriteBuffered or WriteDirect; the file's Flush/RangeSync and WriteDirect
are not reached from here. It calls `file->PositionedAppend` (vtable
slot 5, with checksum) through the file pointer, not by direct call --
so no direct call sites for those appear in the scan; the slot number
is pinned by the disassembly and the bindings group.

## Evidence

- `tools/writable_file_writer_writedirectwithchecksum115.py` -- the
  WriteDirectWithChecksum model (plus the Flush oracle at #6057
  fidelity and the WriteDirect oracle at #6204 fidelity, used for the
  live check).
- `tests/test_writable_file_writer_writedirectwithchecksum115.py` -- 34
  tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 gate + 600 drain + 600
  checksum + 600 bindings), 0 mismatches on replay
  (`python3 tools/writable_file_writer_writedirectwithchecksum115.py --verify`).
- Live engine check (`--live`): all 8 legs pass -- the model drove a
  real file through a page-pad + positional write (5000 B, alignment
  4096, grants [4096, 4096]: the file holds the 5000 data bytes + 3192
  zeros, `flushed_size_` 8192, `next_write_offset_` 4096, the 904-byte
  tail refit), a checksum-handoff pin (the `positioned_append` event
  carries `Combine(0x12345678, Value(501 zero bytes), 501)`, never the
  entry buffered value alone and never a fresh per-chunk `Extend`),
  the seen-error gate, an entry-empty run that makes ONE zero-length
  `PositionedAppend` (a zero-length pwrite leaves the file length
  untouched even at a nonzero offset), a failure on the single
  `PositionedAppend` (`cursize_` restored to the entry 5000,
  `seen_error_` set, `flushed_size_` keeps 0), listeners + the nanos
  guard armed (perf 5, finish event type 1, offset =
  `next_write_offset_`, nbytes = the padded 4096, elapsed 700 ns,
  `wdwc_nanos` 2100, `wdwc_cpu_nanos` 0), an `IO_TOTAL` priority
  skipping the limiter, and a failure event carrying type 9 =
  `kPositionedAppend` with trailing (size = 4, write_offset = 777);
  the model file image equalled the real file bytes after every
  WriteDirectWithChecksum.
- `records.json` -- semantic records only (never a per-instruction
  mnemonic list); `functions.tsv`, `callers.tsv`, `census.json` -- the
  census above.
- `MANIFEST.sha256` verifies clean; `tools/verify_packets.py` flags
  only the pre-existing mismatch in unrelated packet
  RE-001-adjacent-last-115 (present on clean upstream main, untouched).
- Excerpts are whole-FDE and verbatim (`.hex` + `.objdump.txt` per
  function), with the repo-relative binary path `work/hl-node-115.bin`
  (no absolute home paths).

## Upstream cross-check

`facebook/rocksdb` v8.1.1, read live this cycle
(`file/writable_file_writer.cc`, `WriteDirectWithChecksum`, lines
1645-1857), confirms the packet step for step: the seen-error gate
(`AssertFalseAndGetStatusForPrevError`), the page pad
(`PadToAlignmentWith(0)`), the checksum recompute over the pad
(`buffered_data_crc32c_checksum_ = crc32c::Crc32cCombine(buffered,
crc32c::Value(padded_start, padded_size), padded_size)`), the
`IOOptions` build with `DecideRateLimiterPriority`, the rate-limiter
drain (`RequestToken` until the remainder is 0, grants discarded), the
single `PositionedAppend` carrying the recomputed buffered checksum,
the listener events (`NotifyOnWriteCompleted` / `NotifyOnIOError` with
`kPositionedAppend`), the failure path (`buf_.Size(file_advance +
leftover_tail)`, the buffered checksum recomputed as `Value` of the
remaining buffer, `set_seen_error()` after the events, return `s`),
and the success epilogue (`RefitTail`, `next_write_offset_ +=
file_advance`, `cursize_ = leftover_tail`, the buffered checksum
recomputed as `Value` of the tail). `WriteDirect` (lines 1449-1642)
is the sibling this packet is templated on. `util/aligned_buffer.h`
pins the `AlignedBuffer` layout and `file/writable_file_writer.h`
pins the writer layout. `Flush` (lines 641-643) confirms the dispatch:
`perform_data_verification_ && buffered_data_with_checksum_` ->
`WriteDirectWithChecksum`, else `WriteDirect` -- only when
`pending_sync_` is set.

RESOLVED this cycle: the failure event type 9 is
`FileOperationType::kPositionedAppend`
(`include/rocksdb/listener.h:449-473`, implicit 0-based: kRead 0,
kWrite 1, kTruncate 2, kClose 3, kFlush 4, kSync 5, kFsync 6,
kRangeSync 7, kAppend 8, kPositionedAppend 9, kOpen 10) -- exactly
upstream `NotifyOnIOError(s, kPositionedAppend, file_name(), size,
write_offset)` in `WriteDirectWithChecksum` (lines 1783-1785). It
follows the sibling pattern exactly: Flush's failure event carries
its own op (4 = kFlush) and RangeSync's carries 7 = kRangeSync.

Binary-vs-source observations, recorded not hidden:

- The binary has NO `GetFileSize` call and NO `perf_level` save/restore,
  while WriteBufferedWithChecksum has both (and upstream's
  WriteDirectWithChecksum has neither -- the same observable behaviour).
- The binary's CPU timer-guard half is DEAD (upstream's
  `IOSTATS_TIMER_GUARD` has both halves, but the binary never arms the
  CPU side here: the flag byte is written 0 and never set, the second
  clock slot is never filled, no clock-or-default helper is called).
  The model records `wdwc_cpu_nanos` = 0 at every perf level.
- The binary computes `file_advance` / `leftover_tail` lazily at the
  epilogue from the saved entry `cursize_`, while upstream computes
  them up front (`TruncateToPageBoundary` / `CurrentSize() -
  file_advance`) -- same observable behaviour, a scheduling difference.
- The binary runs the success-path sync point (0x6051398) BEFORE the
  `IOSTATS_ADD(bytes_written)` while upstream lists the bytes add first
  -- same observable behaviour, a scheduling difference.
- Upstream's post-epilogue `if (!s.ok()) set_seen_error()` is
  unreachable in practice (failures return early) and has no
  counterpart in the binary epilogue.
- Upstream names the loop's `TEST_SYNC_POINT`
  `"WritableFileWriter::Flush:BeforeAppend"` (a verbatim copy-paste
  name, despite being in `WriteDirectWithChecksum`), while the binary's
  string literals are stripped (verified absent from the node #115
  binary), so per-site names are not pinned from the binary. The binary
  calls the sync-point helper 0x606d9f0 from three sites (0x6050ed1,
  0x6051398, 0x60513c0) -- three per call -- while upstream shows one
  named point.
- The binary recomputes the buffered checksum over the pad
  UNCONDITIONALLY (upstream's `WriteDirectWithChecksum` asserts
  `perform_data_verification_` and `buffered_data_with_checksum_` --
  the asserts are compiled out, so the binary takes the checksum path
  for every call). Upstream computes the pad checksum with
  `crc32c::Value` (which is `Extend(0, ...)`); the binary calls the
  `Extend` dispatch thunk directly -- the same computation.
- The entry-empty path makes ONE zero-length `PositionedAppend` in
  both the binary and upstream: upstream has no `CurrentSize() == 0`
  early return, and the single `PositionedAppend(Slice(src, left), ...)`
  runs with `left == 0`. PINNED DIFFERENCE from WriteDirect, which
  skips its loop entirely on that path.
- The 16-byte `IOStatus` copy drops byte 2 on every return path (the
  code bytes spill at `-0x1d1..-0x1d5`, byte 2 never stored); the model
  reproduces it via `Status.out_bytes()`.

## Open unknowns (not claimed)

- The TLS flag byte at `fs-0x3f8+0x98` gating the IOStats bytes counter
  (+0x8) add: its identity is open. Modelled as `iostats_bytes_flag`
  (default clear = count).
- The three sync-point sites vs upstream's one named point (see the
  cross-check): the per-site names are not pinned from the binary
  (literals stripped); upstream names only
  `"WritableFileWriter::Flush:BeforeAppend"`.
- The bool at `this+0xd9`, read into the finish event: it is not named
  by the Append packet's writer layout and no upstream header in the
  2019 mirror has a member at that offset. Modelled as `flag_d9` and
  listed here as an open unknown (shared with the Flush packet).
- The initial `v_info` checksum-pointer lea at 0x6050db4 (`lea
  0x4376fd` into `-0x1c0(%rbp)`): it is overwritten with the
  `checksum_buf` address at 0x6050fd3 before the `PositionedAppend`,
  so the initial value is never read by the call; its target (a static
  address in `.rodata`) is not named here.
- Why the CPU timer-guard half is dead in this FDE (the flag byte is
  written 0 and never set): open. Modelled as `wdwc_cpu_nanos = 0` at
  every perf level.
- `Flush`, `Append`, `WriteBuffered`, `WriteBufferedWithChecksum`,
  `WriteDirect` and the `RangeSync` member are input oracles here;
  their full reconstruction is a follow-up. The next natural
  follow-ups: `DBImpl::CreateWAL` 0x5e5c270..0x5e5c9a3 (caller of
  `AddCompressionTypeRecord`); or the unidentified FDE 0x60d4cf0
  (`SequentialFileReader::Read` caller, open unknown from #5992).

## Environment limits (stated honestly)

No cargo/rustc/git-lfs/Ghidra on this VM. The binary is read statically
(`work/hl-node-115.bin`); nothing is executed. `Flush`, `Append`,
`WriteBuffered`, `WriteBufferedWithChecksum`, `WriteDirect`,
`RangeSync` and the file's `PositionedAppend` are input oracles with
the contracts from open PRs #6057 (Flush), #6041 (Append), #6088
(WriteBuffered), #6094 (WriteBufferedWithChecksum) and #6204
(WriteDirect); their bodies are not reconstructed here. `make verify`
/ `test` / `catalogue-check` in a tooled environment is still owed
upstream.
