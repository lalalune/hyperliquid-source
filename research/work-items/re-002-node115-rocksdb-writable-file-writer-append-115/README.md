# RE-002 · Node #115 RocksDB WritableFileWriter::Append

Component: storage / WAL. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 write bytes through a `WritableFileWriter` --
what does `WritableFileWriter::Append` check first, how does it
grow and flush its buffer, how does it pick the file, what checksum
does it fold in, and who calls it? The main function has NO vendor
census record (body hash only, per the #5992 no-census convention);
the `.cold` pad is census-bound (body hash matches the vendor census
`target_body_sha256` exactly; source hash reproduced by zeroing the
8 recorded relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::WritableFileWriter::Append` | 0x6054680..0x605518b | 2827 | `f796b02fe4615a8144a11d474f52be53aa2f2e08605c09a46d895a86c0b006da` |
| `rocksdb::WritableFileWriter::Append.cold` | 0x6054600..0x605467c | 124 | `a8869d110687c35e137ab978008411040c8dd2416f0333650e9372e56bd199b2` |

Scope note: the merged `log::Writer::EmitPhysicalRecord` packet
(PR #6012) calls this routine twice (header Append at 0x5f03c2a
with crc arg 0, payload Append at 0x5f03cae with crc arg
`payload_crc`) and took its body as an input oracle only, naming it
in its entry as the natural follow-up. This packet supersedes that
input with the full body model, 2,400 cases and the upstream
cross-check. The callees are cited, not re-claimed:
`WritableFileWriter::Flush` 0x6051a20 (census-bound oracle),
`WriteBuffered` 0x604e140 and `WriteBufferedWithChecksum` 0x604f080
(oracles), `UpdateFileChecksum` 0x604c7b0,
`DecideRateLimiterPriority` 0x604c800 (census-bound, 39 B),
`crc32c::Extend` thunk 0x61c25f0 and `crc32c::Crc32cCombine`
0x61c2600 (both fully reconstructed in merged
RE-002-node115-crc32c-extend-combine-115).

## Answer (pinned)

**Signature.** `IOStatus Append(const Slice& data, uint32_t
crc32c_checksum, Env::IOPriority priority)` returns by value, so
`rdi` is the hidden 16-byte sret out-pointer, `rsi` is the
`WritableFileWriter*`, `rdx` is `&data`, `rcx` is the crc, `r8d` is
the priority. It is the single choke point for file writes: every
write the node makes through a `WritableFileWriter` goes through one
of its 39 call sites.

**Writer layout** (node #115, from the field accesses, confirmed
against upstream `file/writable_file_writer.h`): `file_name_` +0x00,
`writable_file_` +0x20 (`FSWritableFilePtr`: `io_tracer_` +0x20/+0x28,
`fs_tracer_` +0x30), `clock_` +0x38, `buf_` +0x40 (`AlignedBuffer`:
`alignment_` +0x40, `buf_` +0x48, `capacity_` +0x50, `cursize_`
+0x58, `bufstart_` +0x60), `max_buffer_size_` +0x68, `filesize_`
+0x70, `flushed_size_` +0x78, `next_write_offset_` +0x80,
`pending_sync_` +0x88, `seen_error_` +0x89, `last_sync_size_` +0x90,
`bytes_per_sync_` +0x98, `rate_limiter_` +0xa0, `stats_` +0xa8,
`listeners_` +0xb0 (24 B), `checksum_generator_` +0xc8,
`checksum_finalized_` +0xd0, `perform_data_verification_` +0xd1,
`buffered_data_crc32c_checksum_` +0xd4,
`buffered_data_with_checksum_` +0xd8, `temperature_` +0xdc; total
0xe0.

**Seen-error gate.** The first thing the body does: byte
this+0x89 set -> return `IOStatus` code 5 with the 27-byte heap
state_ "Writer has previous error." (rodata 0x451480 "Writer has
previ" + 0x452bf0 " previous error."), the old sret state_
`delete[]`'d first, and nothing else touched. Upstream
`file/writable_file_writer.h:555-563`
(`AssertFalseAndGetStatusForPrevError`) returns exactly
`IOStatus::IOError("Writer has previous error.")`.

**Checksum update and IOOptions.** `pending_sync_` (this+0x88) = 1.
`UpdateFileChecksum(data)` at 0x604c7b0 runs when
`checksum_generator_` (this+0xc8) is set (tail-jump to vtable slot 2
= `Update`). An `IOOptions` of 0x58 B is built on the stack at
rsp+0x70 with exact defaults: timeout 0, prio 0 (`kIOLow`),
`rate_limiter_priority` `IO_TOTAL` 4 then overwritten at +0x0c with
the `DecideRateLimiterPriority` result, type 7 (`kUnknown`), an
empty `property_bag` with a self-pointer bucket at rsp+0xb8 (count
1, max_load 1.0f), `force_dir_fsync` 0, `do_not_recurse` 0. It is
destroyed via the `_Hashtable` dtor at 0x5d36110 after
`PrepareWrite`.

**Priority decision.** `DecideRateLimiterPriority` (0x604c800, 39 B,
census-bound): both `IO_TOTAL` -> `IO_TOTAL`; file `TOTAL` -> op;
op `TOTAL` -> file; else op. Verified instruction by instruction
against upstream `writable_file_writer.cc:1859-1885`.

**Sync point and timer guard.** A `TEST_SYNC_POINT` gate (global
`*0x64ed5d0`, RELATIVE reloc to 0x606d9f0, TLS marker helper) guards
`PrepareWrite`. The perf level comes from TLS
(`_ZTHN7rocksdb10perf_levelE`, GLOB_DAT at 0x64ed2b0); the
`IOSTATS_TIMER_GUARD(prepare_write_nanos)` is armed iff perf_level
> 2, with start = `SystemClock::Default()->NowNanos()` (vtable slot
20; `SystemClock::Default` 0x5fe2680) and the elapsed time added to
the TLS counter (iostats+0x48). The CPU-timer half is DEAD: flag
(rsp+0x41), id (rsp+0x44), object (rsp+0x60) are zeroed and never
set. The out-of-line guard dtor 0x604c6b6 does the same work and is
called from `.cold` only.

**File selection and PrepareWrite.** `PrepareWrite` is void, vtable
slot 24 (0xc0), called with `(filesize_, left, io_options,
nullptr)`. The file is selected by `FSWritableFilePtr::operator->`
(tracer null or its +0x68 byte clear -> the raw file at
wrapper+0x28, else the wrapper at this+0x30). `GetIOPriority` is
devirtualized: the guard compares vtable slot 16 against the
RELATIVE reloc at 0x64ecf30 (addend 0x5df6e90); 0x5df6e90 is `mov
0x18(%rdi),%eax; ret` = base `FSWritableFile::GetIOPriority`, so
when equal the binary reads file+0x18 directly, else it makes the
virtual call at 0x6054e90.

**Buffer growth.** If `capacity - cursize < left`, then for
`cap = capacity; cap < max; cap *= 2`: `desired = min(cap*2, max)`;
if `desired - cursize >= left` OR (`use_direct_io()` AND
`desired == max`): `AllocateNewBuffer(desired, copy_data=true)`;
break. `AllocateNewBuffer` (inlined at 0x6054e04): skip if
`copy_data` and `desired < cursize`; `new_capacity =
Roundup(desired, alignment)`; `new char[new_capacity + alignment]`;
memcpy old bytes; cursize unchanged.

**Flush-if-needed.** If `!use_direct_io()` AND `remaining < left`
AND `cursize > 0`: `s = Flush(priority)` at 0x6051a20; if `!ok`:
set seen_error, return `s`.

**Main write, four arms.** (a) Verification gate
(`perform_data_verification_` +0xd1 AND
`buffered_data_with_checksum_` +0xd8 AND `crc != 0`): remaining >=
left -> `buf_.Append` + `Crc32cCombine(old, crc, left)` at 0x61c2600
(the single append uses Combine, NOT Extend); direct-io +
remaining < left -> loop appending `min(remaining, left)` +
`Extend(old, src, appended)` via thunk 0x61c25f0 + Flush on left >
0; !direct + remaining < left ->
`buffered_data_crc32c_checksum_ = crc`, then
`WriteBufferedWithChecksum(src, left, priority)` at 0x604f080. (b)
Plain arm: direct-io OR capacity >= left -> loop (append +
conditional Extend + Flush); else direct-write path: verification +
checksum -> `checksum = Value(src, left)` then
`WriteBufferedWithChecksum`; else `WriteBuffered(src, left,
priority)` at 0x604e140.

**Epilogue.** If `s.ok()`: `filesize_ += data.size()` (this+0x70);
else set seen_error. The sret is returned; the stack canary is
checked, `__stack_chk_fail` on mismatch.

**The .cold landing pad** (0x6054600, entered from the six `endbr64`
stubs at the main FDE tail 0x6055143..0x605518b, which jump here at
0x6054600, 0x6054612, 0x605461f, 0x605463f and 0x605464e; only the
jump at 0x605514a is the census-validated site): `delete[]`s the
sret status's `state_` when non-null, runs the out-of-line
timer-guard dtor 0x604c6b6, checks the stack canary, then
`_Unwind_Resume` or `__stack_chk_fail`. It is unwind-only; no case
exercises it.

**Findings (verified against the binary + upstream v8.1.1).**

- *Combine, not Extend, on the single append:* the verification
  single-append arm folds the crc with `Crc32cCombine(old, crc,
  left)`; the direct-io loop arm and the plain arm use `Extend`.
  The same crc argument is folded three different ways depending on
  the arm -- pinned by the gate/write_paths cases.
- *Degenerate Combine is live:* appending 0 bytes with verification
  on still changes `buffered_data_crc32c_checksum_` to `old ^ crc`,
  because the binary calls Combine unconditionally with
  `length = left` (no early return for len2 == 0).
- *The AllocateNewBuffer skip guard is unreachable from Append:*
  `desired >= cap >= capacity >= cursize`, so `desired < cursize`
  can never hold in the growth loop. It is pinned by direct
  `AlignedBuffer` unit rows instead.
- *The CPU-timer half is dead:* the flag, id and object slots are
  zeroed and never set; only the wall-clock half runs, and only when
  perf_level > 2.
- *WriteDirect pads to the page:* flushing a 904 B buffered tail
  with direct I/O writes 4096 B positionally, so the physical file
  is 8192 B for 5000 logical bytes. Pinned by the direct-io test.
- *The IOOptions property_bag is built empty with a self-pointer
  bucket:* the binary stores rsp+0xb8 at rsp+0xb8 itself (bucket
  count 1, max_load 1.0f) and destroys it via the `_Hashtable` dtor
  at 0x5d36110 after `PrepareWrite`.
- *Live engine check:* the model drove a real file through three
  legs -- buffered appends (5032 B), direct-I/O appends (8292 B),
  and the seen-error gate -- and the model's file image equalled the
  real file bytes after every Append.

**Caller census** (whole-.text E8/E9/LEA scan, Capstone-validated,
`census.py`): exactly 39 direct calls, 0 tail jumps, 0 LEA refs.
Callers: `BlobLogWriter::WriteHeader` (1), `EmitPhysicalRecord` (3),
`AppendFooter` (1); `log::Writer::EmitPhysicalRecord` x2 (0x5f03c2a
header, 0x5f03cae payload); `log::Writer::AddRecord` (1);
uncatalogued FDE 0x5fce280 (1); `CreateFile` (1); `CopyFile` (1);
`PersistRocksDBOptions` (8); `BlockBasedTableBuilder::
WriteMaybeCompressedBlock` (2), `WriteFooter` (1);
`CuckooTableBuilder::Finish` (6); `PlainTableBuilder::Finish` (5),
`Add` (2); `PlainTableKeyEncoder::AppendKey` (4). The `.cold` has
exactly 1 tail jump, from 0x605514a inside the main FDE.

**Engine callees.** `DecideRateLimiterPriority` 0x604c800 and
`Flush` 0x6051a20 are census-bound; `WriteBuffered` 0x604e140,
`WriteBufferedWithChecksum` 0x604f080 and `UpdateFileChecksum`
0x604c7b0 are taken as oracles (no census record);
`crc32c::Extend` thunk 0x61c25f0 and `crc32c::Crc32cCombine`
0x61c2600 are census-bound (reconstructed in merged
RE-002-node115-crc32c-extend-combine-115); `SystemClock::Default`
0x5fe2680 is census-bound; the PLT stubs (`__stack_chk_fail`,
`operator delete[]`) are pinned by their relocation displacements
(see `records.json`).

## Cases

2,400 deterministic cases in `cases.tsv`, generated by
`tools/writable_file_writer_append115.py` (`--gen-cases`)
and replayed by
`tests/test_writable_file_writer_append115.py` (36 tests pass):

- 600 gate (seen-error, checksum generator, verification flags,
  crc zero/nonzero, priorities 0..4, tracer selection, perf level
  0..5, sync point, small data 0..64 B) -- the gate, the checksum
  update, the file selection, the timer guard, and the epilogue.
- 600 growth (alignment 512/4096, capacity/cursize/max combinations
  pinning the doubling loop, the max cap and the direct-io max arm)
  -- the growth loop and the AllocateNewBuffer contract.
- 600 write_paths (buffered/direct x verification x crc x
  remaining/left x Flush/WriteBuffered scripted outcomes x rate
  limiter x listeners, incl. the RangeSync arm with filesize > 1
  MiB) -- the four write arms, the Flush oracle, and the failure
  paths.
- 600 bindings (body/source hashes, 40 caller-census sites, vtable
  slots 12/16/24, 29 writer-layout offsets, IOOptions defaults,
  25-cell priority matrix, CRC vectors incl. check vector
  "123456789" -> 0xE3069283, Combine identities, AlignedBuffer unit
  rows, timer-guard thresholds, file-selection matrix).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool models the routine in Python; the callees
`WriteBuffered`, `WriteBufferedWithChecksum`, `Flush` and
`UpdateFileChecksum` are taken as scripted oracles, and the live
engine check drives the model against a real file and asserts the
model's file image equals the real file bytes after every Append.
`make verify/test/catalogue-check` in a tooled environment is still
owed upstream.

## Unknowns

- `WriteBuffered`, `WriteBufferedWithChecksum`, `Flush` and
  `UpdateFileChecksum` are taken as oracles here (their bodies are
  separate FDEs: `Flush` 0x6051a20 is census-bound, the others have
  no census record). Their internal steps are modelled from upstream
  source, not from their own binary bodies; reconstructing them is
  the natural follow-up.
- Whether the returned status's bytes 6-7 (padding, never written by
  the Append callee's error path) ever matter to a caller: the 39
  callers move the 16-byte status in their frames right after the
  call; whether bytes 6-7 are read was not traced.
- The exact `.cold` entry-point selection (which exception region
  uses which of the six stubs at 0x6055143..0x605518b): the stubs and
  the pad are pinned, but the LSDA region mapping was not decoded.
