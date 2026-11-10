# RE-002 · Node #115 RocksDB WritableFileWriter::WriteDirect

Component: storage / SST file writer. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 flush a buffered write through direct I/O -- how is the
buffer page-padded, how does the rate limiter grant per chunk, what checksum
is computed per chunk, what does each step cost in listener events and timer
guards, and what happens when a PositionedAppend fails? Both functions are
pinned to the binary; the main body has NO vendor census record (body hash
only, per the #5992 no-census convention) and the `.cold` IS census-bound
(body hash matches the vendor census `target_body_sha256` exactly; source
hash reproduced by zeroing the 13 recorded relocations, kinds 2/4; no
kind-42 relocation, so no GOTPCRELX restoration applies):

| function | FDE | size | body SHA-256 |
|---|---|---|---:|
| `rocksdb::WritableFileWriter::WriteDirect` | 0x604fe80..0x6050b8a | 3338 | `990fb8c23cd3fc1a1c983b8cfe438fb13f80d50e75f0cdc7a454da5caab10172` |
| `rocksdb::WritableFileWriter::WriteDirect.cold` | 0x604fd98..0x604fe7b | 227 | `18cb660154157e236c748aba25349341aaa39da33334ece098f0574e597f42bf` |

Scope note: open PR #6057 (WritableFileWriter::Flush) calls WriteDirect at
0x60520b9 -- the ONLY caller in the whole `.text` -- and took it as an input
oracle, leaving it as the direct follow-up. Open PR #6041
(WritableFileWriter::Append) pins the writer layout. Open PR #6094
(WritableFileWriter::WriteBufferedWithChecksum) is the direct template for
this packet's tool and packet scaffolding. This packet supersedes those
oracle notes with the full body model. `WriteBuffered`,
`WriteBufferedWithChecksum`, `WriteDirectWithChecksum`, the `RangeSync`
member, `UpdateFileChecksum` and `DecideRateLimiterPriority` are input
oracles here, not reconstructed; their bodies are open follow-ups.

## Answer (pinned)

**Signature.** `IOStatus WriteDirect(Env::IOPriority priority)` returns by
value, so `rdi` is the hidden 16-byte sret out-pointer, `rsi` is the
`Writer*`, `rdx` the priority. There is no data/size argument: the buffer
(`buf_`, `this+0x40`) IS the input.

**1. Seen-error gate (0x604feb5).** Byte `this+0x89` (`seen_error_`) is read
first. If set, the routine returns at once: sret = code 5 (`kIOError`),
27-byte heap state_ `"Writer has previous error."`, the old sret state_
`delete[]`'d first -- exactly upstream
`AssertFalseAndGetStatusForPrevError()` (`file/writable_file_writer.h:555-563`).
No other member is touched: no file call, no buffer change. The gate return
is INLINE in the main FDE (0x604fec6..0x604ff3c); `.cold` is unwind-only.

**2. Page pad (0x604ff40..0x604ff78 + 0x6050a97).** `pad =
Roundup(cursize_, alignment_) - cursize_` via the div at 0x604ff65; if `pad
!= 0`, `memset(bufstart_ + cursize_, 0, pad)` and `cursize_ += pad`
(`PadToAlignmentWith(0)`). `file_advance =
TruncateToPageBoundary(alignment_, ENTRY cursize_)` and `leftover_tail =
entry cursize_ - file_advance` are computed LAZILY at the success epilogue
(0x6050803..0x605081a) from the saved entry `cursize_` (-0x218) and
alignment (-0x220) -- not up front.

**3. IOOptions + file priority (0x604ff7e..0x605007d).** The file's
`GetIOPriority` (vtable slot 16, devirtualized when the slot equals the
RELATIVE reloc at 0x64ecf30, else the virtual call at 0x6050ac6) feeds
`DecideRateLimiterPriority` (0x604c800, census-bound, pure) with the op
priority; a 0x58-byte `IOOptions` is built on the stack with the exact
defaults (timeout 0, prio `kIOLow` 0, `rate_limiter_priority` the Decide
result, type `kUnknown` 7, `property_bag` an empty unordered_map,
`force_dir_fsync` 0, `do_not_recurse` 0). There is NO `GetFileSize` call and
NO `perf_level` save/restore -- both pinned differences from
WriteBufferedWithChecksum. If the padded cursize (`left`) == 0, the loop is
skipped (`je` 0x6050b06) and the success epilogue runs with `file_advance`
= 0, `leftover` = 0. QUIRK: on that entry-empty path the sret subcode byte
is read from -0x1d2, which no instruction on that path writes (a stale
stack slot); the model emits 0. The path is unreachable from Flush, which
only calls WriteDirect with `cursize_ > 0`.

**4. Write loop (0x60500b0..0x60507fd), while `left > 0`.** `size = left`,
or `granted = rate_limiter_->RequestToken(left, buf_.Alignment()
(this+0x40), decided priority, stats_ (this+0xa8), OpType kWrite = 1)` --
vtable slot 6, base impl 0x61c43f0 -- when `rate_limiter_` (`this+0xa0`) is
non-null AND the decided priority != `IO_TOTAL` (4). A decided `IO_TOTAL`
priority skips the limiter entirely even when one exists.

**5. Sync-point gate + timer-guard halves (per chunk).** Three sync-point
gates fire per chunk (0x6050108 loop-head, 0x6050795 success-tail, 0x60507bd
bytes-add), all through the helper 0x606d9f0 when the sync-point global
`*0x64ed5d0` is non-null. The string names are not pinned from the binary --
the literals are stripped (verified absent from the node #115 binary);
upstream v8.1.1 names the loop's `TEST_SYNC_POINT`
`"WritableFileWriter::Flush:BeforeAppend"`. The nanos guard is armed iff
`perf_level > 2` (clock = `*SystemClock::Default()`, 0x5fe2680, dereferenced
once; start = `NowNanos`, slot 20; stop adds the elapsed time to the TLS
counter at `fs-0x3f8+0x28`). The CPU half is DEAD in this FDE: the flag byte
at -0x18f is written 0 at 0x605012c and never set, the second clock slot at
-0x170 is never filled, and no clock-or-default helper is called, so the
slot-22 stop at 0x605071b is unreachable and the stop always takes the
`NowNanos` branch (0x6050af8). The stops are INLINE in the main FDE (nanos
0x60509a0 on the success path per chunk, 0x6050704..0x6050759 on the failure
path after the sret build); the shared destructor 0x604c6b6 runs only from
`.cold` (unwind).

**6. Listener start times (0x60501b1).** Only when `listeners_`
(`this+0xb0`) is non-empty, `steady_clock::now()` + `system_clock::now()`.

**7. Verification arm (0x60501ea), ONLY when `perform_data_verification_`
(`this+0xd1`) is set.** `checksum = crc32c::Extend(0, src, size)` per chunk
through the 19-byte helper 0x604c7e0, `EncodeFixed32` into `checksum_buf`,
`v_info.checksum = Slice(checksum_buf, 4)`, then
`file->PositionedAppend(Slice{src, size}, write_offset, io_options, v_info,
nullptr)` through vtable slot 5 (0x6050976). `buffered_data_with_checksum_`
(`this+0xd8`) is NOT consulted -- pinned difference from
WriteDirectWithChecksum -- and `buffered_data_crc32c_checksum_` (`this+0xd4`)
is never read: the checksum is a FRESH per-chunk computation, not a handoff.
Otherwise the plain `file->PositionedAppend` through vtable slot 4
(0x605024f). The result is saved to a 16-byte stack `IOStatus` at
-0x160(%rbp), then copied as bytes 0-1, 3-4, 5, 8-15 with byte 2 forced to 0.

**8. Listener events.** Only when `listeners_` is non-empty. Finish event
(always): `{FileOperationType type = 1 (kWrite), WritableFileWriter* this,
bool [this+0xd9], uint64 offset = write_offset, uint64 length = size, uint64
elapsed_nanos, TimePoint* &start_times, Status status (CopyState deep copy
at 0x61cf610)}` through vtable slot 34 (0x110), skipping the base no-op
0x604c660. Failure event (only when the PositionedAppend status is not OK):
`{Status status (CopyState deep copy), FileOperationType type = 9
(kPositionedAppend), std::string file_name_, uint64 size, uint64
write_offset}` through vtable slot 47 (0x178), skipping the base no-op
0x6042c20. The type 9 is `kPositionedAppend` (v8.1.1
`include/rocksdb/listener.h:236-248`, implicit 0-based: kRead 0, kWrite 1,
kTruncate 2, kClose 3, kFlush 4, kSync 5, kFsync 6, kRangeSync 7, kAppend 8,
kPositionedAppend 9, kOpen 10) -- exactly upstream `NotifyOnIOError(s,
kPositionedAppend, file_name(), size, write_offset)`; the trailing u64s are
the (allowed, old_size) arguments. PINNED DIFFERENCE from
WriteBufferedWithChecksum: its failure event trails (left, old_size) with
type 8.

**9. Failure return.** When a PositionedAppend status is not OK,
`buf_.Size(file_advance + leftover_tail)` = `cursize_` restored to the ENTRY
cursize_ (0x6050693..0x60506a5); `seen_error_` = 1 AFTER the notifications;
the sret is built (byte 2 forced to 0); the nanos guard stops at
0x6050704..0x6050759 after the sret build; the `IOOptions` `property_bag`
is destroyed (0x5d36110); no retry; `flushed_size_` is NOT advanced for the
failed chunk. PINNED DIFFERENCE from WriteBufferedWithChecksum (which clears
`buf_` and resets the checksum after the events) and from WriteBuffered
(which clears immediately after the failed Append, before the events).

**10. Success tail (per chunk).** Nanos-guard stop (0x60509a0, elapsed ->
the TLS counter at `fs-0x3f8+0x28`), `TEST_SYNC_POINT` at 0x6050795, then --
when the TLS flag at `fs-0x3f8+0x98` is clear -- a third `TEST_SYNC_POINT`
at 0x60507bd and the TLS counter at `fs-0x3f8+0x8` advances by the size (the
flag's identity is an open unknown); `src += size`, `write_offset += size`,
`flushed_size_ += size`, `left -= size`.

**11. Success epilogue (0x6050803..0x6050878).** If `leftover_tail != 0`,
`buf_.RefitTail(file_advance, leftover_tail)` (`memmove` at 0x6050ad7);
`next_write_offset_ += file_advance`; `cursize_ = leftover_tail`; the sret
copy (byte 0 forced to 0 -- the status is OK -- byte 2 forced to 0); the
`property_bag` is destroyed; the stack canary is checked and
`__stack_chk_fail` fires on mismatch. `filesize_` is NEVER advanced here.

**The `.cold` landing pad (0x604fd98, 227 B, census-bound).** One tail jump
at 0x6050b37 (one of the eight `endbr64` stubs at the main FDE tail,
0x6050b30..0x6050b85; the other seven jump to interior `.cold` addresses)
enters it: destroy the `file_name_` string copy, `delete[]` the saved sret
state_ when non-null, stop the timer guard through the shared destructor
0x604c6b6, destroy the `IOOptions` `property_bag`, check the stack canary,
then `_Unwind_Resume` (or `__stack_chk_fail`). It is unwind-only; no case
exercises it.

**DecideRateLimiterPriority (0x604c800, 39 B, census-bound, verified
instruction by instruction in the Flush packet):** both `IO_TOTAL` (4) ->
`IO_TOTAL`; file `IO_TOTAL` -> op priority; op `IO_TOTAL` -> file priority;
else op priority. Exactly upstream `writable_file_writer.cc:1859-1885`.
Used by the `IOOptions` build here and by the Flush oracle.

**Writer layout** (node #115, from the field accesses, confirmed against
upstream `file/writable_file_writer.h` and the Append #6041 / Flush #6057 /
WriteBuffered #6088 / WriteBufferedWithChecksum #6094 packets): `file_name_`
+0x00 (std::string, 32), `writable_file_` +0x20 (`FSWritableFilePtr`:
`io_tracer_` +0x20/+0x28, `fs_tracer_` +0x30), `clock_` +0x38, `buf_` +0x40
(`AlignedBuffer`: `alignment_` +0x40, `buf_` +0x48, `capacity_` +0x50,
`cursize_` +0x58, `bufstart_` +0x60), `max_buffer_size_` +0x68,
`filesize_` +0x70 (never read or written here), `flushed_size_` +0x78,
`next_write_offset_` +0x80, `pending_sync_` +0x88, `seen_error_` +0x89,
`last_sync_size_` +0x90, `bytes_per_sync_` +0x98, `rate_limiter_` +0xa0,
`stats_` +0xa8, `listeners_` +0xb0 (vector, 24), `checksum_generator_` +0xc8
(unique_ptr), `checksum_finalized_` +0xd0, `perform_data_verification_`
+0xd1 (READ: gates the per-chunk checksum arm), `buffered_data_crc32c_checksum_`
+0xd4 (uint32, NOT read here), `buffered_data_with_checksum_` +0xd8 (NOT
consulted), unnamed bool +0xd9 (read into the finish event, open unknown),
`temperature_` +0xdc; total 0xe0.

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **1 direct call** to WriteDirect, 0 tail jumps, 0 LEA refs; the
`.cold` pad has exactly 1 tail jump from 0x6050b37. The caller:

| site | caller FDE | caller |
|---|---|---|
| 0x60520b9 | 0x6051a20..0x605257c | `rocksdb::WritableFileWriter::Flush` |

WriteDirect itself never calls Flush, Pad, RangeSync, WriteBuffered or
WriteDirectWithChecksum; the file's Flush/RangeSync and WriteDirect are not
reached from here. It calls `file->PositionedAppend` (vtable slots 4 plain /
5 with checksum) through the file pointer, not by direct call -- so no
direct call sites for those appear in the scan; the slot numbers are pinned
by the disassembly and the bindings group.

## Evidence

- `tools/writable_file_writer_writedirect115.py` -- the WriteDirect model
  (plus the Flush oracle at #6057 fidelity and the Append oracle at #6041
  fidelity, used for the live check).
- `tests/test_writable_file_writer_writedirect115.py` -- 32 tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 gate + 600 write_loop + 600
  verification + 600 bindings), 0 mismatches on replay
  (`python3 tools/writable_file_writer_writedirect115.py --verify`).
- Live engine check (`--live`): all 8 legs pass -- the model drove a real
  file through a page-pad + positional write (5000 B, alignment 4096, grants
  [4096, 4096]: the file holds the 5000 data bytes + 3192 zeros,
  `flushed_size_` 8192, `next_write_offset_` 4096, the 904-byte tail refit),
  a per-chunk verification pin (the positioned_append events carry
  `crc32c::Value(b"hello")`, `Value(b" world")` and `Value(501 zero bytes)`,
  never the buffered 0x12345678), the seen-error gate, an entry-empty run
  that writes nothing at all, a failure on the second PositionedAppend
  (`cursize_` restored to the entry 5000, `seen_error_` set,
  `flushed_size_` keeps the first chunk's 4096), listeners + the nanos guard
  armed (perf 5, finish event type 1, offset = `next_write_offset_`, nbytes =
  the padded 4096, elapsed 700 ns, `wd_nanos` 2100, `wd_cpu_nanos` 0), an
  `IO_TOTAL` priority skipping the limiter, and a failure event carrying
  type 9 = `kPositionedAppend` with trailing (size = 4, write_offset = 777);
  the model file image equalled the real file bytes after every WriteDirect.
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
(`file/writable_file_writer.cc`, `WriteDirect`, lines 1449-1642), confirms
the packet step for step: the seen-error gate
(`AssertFalseAndGetStatusForPrevError`), the page pad
(`PadToAlignmentWith(0)`), the `IOOptions` build with
`DecideRateLimiterPriority`, the write loop (`RequestToken` with `left`,
`buf_.Alignment()`, decided priority, `stats_`, `OpType::kWrite`, then a
`PositionedAppend` per chunk, with the per-chunk `crc32c::Value` when data
verification is enabled), the listener events
(`NotifyOnWriteCompleted` / `NotifyOnIOError` with `kPositionedAppend`), the
failure path (`buf_.Size(file_advance + leftover_tail)`, `set_seen_error()`
after the events, return `s`), and the success epilogue (`RefitTail`,
`next_write_offset_ += file_advance`, `cursize_ = leftover_tail`).
`WriteDirectWithChecksum` (lines 1645-1857) is the direct follow-up: the
same shape with the buffered checksum recomputed as Value of the remaining
buffer. `util/aligned_buffer.h` pins the `AlignedBuffer` layout and
`file/writable_file_writer.h` pins the writer layout.

RESOLVED this cycle: the failure event type 9 is
`FileOperationType::kPositionedAppend`
(`include/rocksdb/listener.h:236-248`, implicit 0-based: kRead 0, kWrite 1,
kTruncate 2, kClose 3, kFlush 4, kSync 5, kFsync 6, kRangeSync 7, kAppend 8,
kPositionedAppend 9, kOpen 10) -- exactly upstream `NotifyOnIOError(s,
kPositionedAppend, file_name(), size, write_offset)` in `WriteDirect`
(lines 1576-1580). It follows the sibling pattern exactly: Flush's failure
event carries its own op (4 = kFlush) and RangeSync's carries 7 = kRangeSync.

Binary-vs-source observations, recorded not hidden:

- The binary has NO `GetFileSize` call and NO `perf_level` save/restore,
  while WriteBufferedWithChecksum has both (and upstream's WriteDirect has
  neither -- the same observable behaviour).
- The binary's CPU timer-guard half is DEAD (upstream's
  `IOSTATS_TIMER_GUARD` has both halves, but the binary never arms the CPU
  side here: the flag byte is written 0 and never set, the second clock slot
  is never filled, no clock-or-default helper is called). The model records
  `wd_cpu_nanos` = 0 at every perf level.
- The binary computes `file_advance` / `leftover_tail` lazily at the
  epilogue from the saved entry `cursize_`, while upstream computes them up
  front -- same observable behaviour, a scheduling difference.
- The binary runs the success-tail sync point BEFORE the
  `IOSTATS_ADD(bytes_written)` while upstream lists the bytes add first --
  same observable behaviour, a scheduling difference.
- Upstream's post-epilogue `if (!s.ok()) set_seen_error()` is unreachable in
  practice (failures return early) and has no counterpart in the binary
  epilogue.
- Upstream names the loop's `TEST_SYNC_POINT`
  `"WritableFileWriter::Flush:BeforeAppend"` (a verbatim copy-paste name,
  despite being in `WriteDirect`), while the binary's string literals are
  stripped (verified absent from the node #115 binary), so per-site names are
  not pinned from the binary. The binary calls the sync-point helper
  0x606d9f0 from three sites (0x6050108, 0x6050795, 0x60507bd) -- one per
  chunk, three per chunk -- while upstream shows one named point.
- The checksum is a FRESH per-chunk computation: the binary calls the
  `crc32c::Extend` helper (0x604c7e0) with (0, src, size) for every chunk
  when `perform_data_verification_` is set, and never reads the buffered
  checksum. The live check pins this.
- There is NO PositionedAppend on the entry-empty path: cursize 0 skips the
  loop entirely and returns OK. QUIRK: on that path the sret subcode byte is
  read from a stale stack slot (-0x1d2); the model emits 0. The path is
  unreachable from Flush (cursize_ > 0), so the byte is unobservable through
  the only caller.
- The 16-byte `IOStatus` copy drops byte 2 on every return path (the code
  bytes spill at -0x1d1..-0x1d5, byte 2 never stored); the model reproduces
  it via `Status.out_bytes()`.

## Open unknowns (not claimed)

- The TLS flag byte at `fs-0x3f8+0x98` gating the IOStats bytes counter
  (+0x8) add: its identity is open. Modelled as `iostats_bytes_flag`
  (default clear = count).
- The 0x61cf610 helper's symbol: the census labels it `Status::CopyState`
  (one arg) but the call sites pass (dst, src). Recorded as an open unknown;
  the deep-copy behaviour is pinned.
- The three sync-point sites vs upstream's one named point (see the
  cross-check): the per-site names are not pinned from the binary (literals
  stripped); upstream names only `"WritableFileWriter::Flush:BeforeAppend"`.
- The bool at `this+0xd9`, read into the finish event: it is not named by
  the Append packet's writer layout and no upstream header in the 2019
  mirror has a member at that offset. Modelled as `flag_d9` and listed here
  as an open unknown (shared with the Flush packet).
- The stale subcode byte on the entry-empty path (see the cross-check): the
  model emits 0; the actual byte in a live run would be whatever the stack
  slot held. Unobservable through the only caller.
- `Flush`, `Append`, `WriteBuffered`, `WriteBufferedWithChecksum`,
  `WriteDirectWithChecksum` and the `RangeSync` member are input oracles
  here; their full reconstruction is a follow-up. The next natural
  follow-ups: `WriteDirectWithChecksum` 0x6050c80 (3255 B) -- the direct
  follow-up, same shape with the buffered checksum recomputed; or
  `DBImpl::CreateWAL` 0x5e5c270..0x5e5c9a3 (caller of
  `AddCompressionTypeRecord`); or the unidentified FDE 0x60d4cf0
  (`SequentialFileReader::Read` caller, open unknown from #5992).

## Environment limits (stated honestly)

No cargo/rustc/git-lfs/Ghidra on this VM. The binary is read statically
(`work/hl-node-115.bin`); nothing is executed. `Flush`, `Append`,
`WriteBuffered`, `WriteBufferedWithChecksum`, `WriteDirectWithChecksum`,
`RangeSync` and the file's `PositionedAppend` are input oracles with the
contracts from open PRs #6057 (Flush), #6041 (Append), #6088
(WriteBuffered) and #6094 (WriteBufferedWithChecksum); their bodies are not
reconstructed here. `make verify` / `test` / `catalogue-check` in a tooled
environment is still owed upstream.
