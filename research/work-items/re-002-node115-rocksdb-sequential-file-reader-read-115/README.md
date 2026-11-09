# RE-002 · Node #115 RocksDB SequentialFileReader::Read

Component: storage / file reading. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 read through a `SequentialFileReader` -- how does
`SequentialFileReader::Read` choose between the raw file and the
tracing wrapper, decide between the buffered and direct-IO paths, and
what exactly does each path write to the reader state, the result
slice and the out-params? The main FDE has NO vendor census record
(like `Comparator::CreateFromString` in #5969): only its body hash
is claimed. The `.cold` landing pads ARE census-bound (body hash
matches the vendor census `target_body_sha256` exactly; source hash
reproduced by zeroing the 10 recorded kind-4 relocations), and their
symbol names the routine:

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::SequentialFileReader::Read` | 0x6048e00..0x60497fd | 2557 | `95a9f1f1e426f0f8fac5cb1cc8076c5cada53ace93a9f59506ddbe9b9027c3ea` |
| `rocksdb::SequentialFileReader::Read` (.cold) | 0x6048d68..0x6048df2 | 138 | `a9bc64e39b97b3441ad2400bda9e561fcd87f31e613fa5dee3badce60863e867` |

Scope note: this is the engine callee that the merged #5986 packet
(`log::Reader::ReadMore` 0x5f018d0, call site 0x5f01997) takes as an
input, and the follow-up its README left open. It closes the two
open unknowns that packet left behind: the Read body is now
modelled, and the `scratch[0]++` paranoid bump IS present in the
binary (0x6049784: `add BYTE PTR [rax],0x1`). The
`FragmentBufferedReader::TryReadMore` routine and
`ReadaheadSequentialFile` (the adjacent FDE 0x6048c30..0x6048d67)
are separate functions and are not modelled here.

## Answer (pinned)

**Signature.** `IOStatus Read(size_t n, Slice* result, char* scratch,
Env::IOPriority rate_limiter_priority)` -- `rdi` is the sret
`IOStatus*` (r15), `rsi` the reader (r14), `rdx` n, `rcx` result,
`r8` scratch, `r9d` the priority. It returns the 16-byte `IOStatus`
by sret and writes the read bytes into `*result` as
`Slice(scratch, bytes read)`.

**Reader layout** (node #115; the pinned fields from the field
accesses, the rest derived from the member order in upstream
`file/sequence_file_reader.h:98-106` with natural alignment):
`file_name_` +0x00 (std::string, 32), `file_` +0x20
(`FSSequentialFilePtr`, 96) with `io_tracer_` +0x20 (shared_ptr,
16) and `fs_tracer_` +0x30 (`FSSequentialFileTracingWrapper`, 80:
vptr +0x30, `target_` +0x38, `target_owned_` +0x40, `io_tracer_`
+0x48, `clock_` +0x58, `file_name_` +0x60), `offset_`
(atomic<size_t>) +0x80, `listeners_` +0x88 (vector, 24),
`rate_limiter_` +0xa0 (RateLimiter*, 8); total 0xa8.

**Prologue.** The sret `IOStatus` is initialised to OK -- bytes 0-3
zero, bytes 4-5 zero, bytes 8-15 (`state_`) zero. Bytes 6-7 are
NEVER written by this FDE: they keep whatever the caller left on
its stack (0 in practice, e.g. `ReadMore` zeroes its slot first).

**File selection** (0x6048e55, repeated before every file call at
0x6048fdd and 0x6049438): exactly
`FSSequentialFilePtr::operator->()` inlined
(`env/file_system_tracer.h:304-361`): if `io_tracer_` is null ->
the raw file at +0x38; else if the byte at `[io_tracer_+0x68]`
(the inlined `is_tracing_enabled()`,
`trace_replay/io_tracer.h:313-335`) is non-zero -> the wrapper at
+0x30; else -> the raw file at +0x38.

**Head.** Call vtable slot 4 on the selected file --
`FSSequentialFile::use_direct_io()`
(`include/rocksdb/file_system.h:1358`; the vtable order is dtor,
dtor, Read, Skip, use_direct_io, GetRequiredBufferAlignment,
InvalidateCache, PositionedRead, GetTemperature). Non-zero takes
the direct-IO path; zero takes the buffered path.

**Buffered path, paranoid bump** (0x6049784): if scratch is
non-null and n != 0, `scratch[0]++` (upstream
`file/sequence_file_reader.cc:196-200`). If scratch is null or n
== 0, no bump. The bump runs before the first file read, so a
successful read overwrites the bumped byte with the file's first
byte; it is observable only when the read returns 0 bytes (a
stale block then fails checksum) or in the event trace.

**Buffered path, n == 0** (0x6048ea0): `*result = Slice(scratch,
0)`; `IOSTATS_ADD(bytes_read, 0)`; return OK. No file read, no
rate-limiter call, no listener notification.

**Buffered path, loop** (head 0x6048f43, body 0x6048f80, exit
0x6049256-0x6049293): `read = 0; while (read < n)`:
- `allowed`: if priority != IO_TOTAL (4) and `rate_limiter_`
  (+0xa0) is non-null, `allowed = rate_limiter_->RequestToken(n -
  read, 0, priority, nullptr, kRead)` -- vtable slot 6 of
  `RateLimiter` (`include/rocksdb/rate_limiter.h:152-156`). Else
  `allowed = n` (the upstream else branch really is `allowed =
  n`, not `n - read`).
- If `listeners_` (+0x88/+0x90) is non-empty, `start_ts =
  FileOperationInfo::StartTimePoint::StartNow()` (steady clock,
  then system clock).
- `io_s = file_->Read(allowed, IOOptions(), &tmp, scratch + read,
  nullptr)` -- vtable slot 2, sret at rsp-0xa0; the `IOOptions`
  is built fresh on the stack each iteration (timeout 0, prio
  kIOLow 0, rate_limiter_priority IO_TOTAL 4, type kUnknown 7,
  property_bag an empty unordered_map, force_dir_fsync false,
  do_not_recurse false) and its property_bag is destroyed right
  after the call (0x60490fe: `_Hashtable` dtor 0x5d36110). The
  returned `IOStatus` is MOVED into the sret field by field: code
  (2 bytes @+0), bytes +3..+4, byte +5, `state_` (+8); the subcode
  byte (+2) and the scope byte (+6) are NOT moved, so the returned
  status always has subcode 0 and an unwritten scope byte. The
  previous iteration's sret `state_` is `delete[]`'d before being
  overwritten.
- If listeners_ is non-empty: `finish_ts =
  steady_clock::now()`; `offset = offset_.fetch_add(tmp.size())`
  (the atomic at +0x80 -- note this advance happens ONLY when
  listeners exist); build `FileOperationInfo(kRead, file_name_,
  offset, tmp.size(), finish - start, start_ts, io_s)` -- the
  info.status is a copy of io_s with its `state_` deep-copied via
  `Status::CopyState` 0x61cf610 -- and call
  `listener->OnFileReadFinish(info)` (vtable slot 33) for every
  listener whose slot-33 entry is NOT the empty base
  implementation at 0x6042c10 (endbr64; ret); base no-op listeners
  are skipped by the compiler's devirtualisation guard. Then the
  info.status `state_` copy is `delete[]`'d.
- `read += tmp.size()`; break unless io_s is ok AND `tmp.size()
  == allowed`. When `read >= n` the loop exits to the return
  (0x6048ea8): `*result = Slice(scratch, read)`;
  `IOSTATS_ADD(bytes_read, read)`; return io_s.

**Direct-IO path** (0x60492c0-0x604975e):
- `offset = offset_.fetch_add(n)` (0x60492c7) -- the offset
  advances by the FULL n up front, before any read.
- `alignment = file_->GetRequiredBufferAlignment()` (vtable slot
  5, 0x60492f1); `aligned_offset = offset & ~(alignment - 1)`;
  `offset_advance = offset - aligned_offset`; `size =
  Roundup(offset + n, alignment) - aligned_offset`; `capacity =
  Roundup(size, alignment)`; a raw buffer of `capacity +
  alignment` bytes is `new[]`'d (0x6049360) and the aligned start
  is `(raw + alignment - 1) & ~(alignment - 1)`.
- Loop while `read < size` (0x6049382 head): `allowed` is
  `RequestToken(capacity - read, alignment, priority, nullptr,
  kRead)` when the limiter applies, else `size`;
  `io_s = file_->PositionedRead(aligned_offset + read, allowed,
  IOOptions(), &tmp, aligned_buf + read, nullptr)` (vtable slot 7,
  0x60494f3); the listener notification is the same shape as the
  buffered path (including the second `offset_.fetch_add(tmp.size())`
  -- so with listeners the direct path advances offset_ by n AND
  by every chunk read); `read += tmp.size()`; break unless io_s
  is ok AND `tmp.size() == allowed`.
- Tail: `r = 0`; if io_s is ok and `offset_advance < read`, `r =
  min(read - offset_advance, n)` and `memcpy(scratch, aligned_buf
  + offset_advance, r)` (0x604970e-0x6049722). `*result =
  Slice(scratch, r)`; the raw buffer is `delete[]`'d (0x604977a);
  `IOSTATS_ADD(bytes_read, r)`; return io_s. Note the tail runs
  even when the loop broke on a short read with an ok status
  (0x6049758 -> 0x60496dc), but NOT when io_s is non-ok (r stays
  0).

**Epilogue** (0x6048ebd-0x6048f34, shared by all paths):
`IOSTATS_ADD(bytes_read, result->size())` -- the thread-local
iostats_context, gated on its enabled byte (0x606d9f0 is the TLS
accessor; the counter sits at +0x10 of the TLS object, the enabled
byte at +0x98); then the stack canary is checked and the frame is
popped.

**Exception landing pads** (.cold, 0x6048d68..0x6048df2): eight
pads that `delete[]` the in-flight info.status `state_` copy and
the sret `state_` when non-null, check the stack canary, and
resume unwinding (`_Unwind_Resume`). Recorded, not modelled: the
model never throws.

**Findings (verified against the binary + upstream v8.1.1).**

- *The bump is real:* `scratch[0]++` is present at 0x6049784,
  closing the open unknown the #5986 `ReadMore` packet left
  behind.
- *Buffered offset_ moves only with listeners:* the single `lock
  xadd` at 0x6049127 lives inside the notify block; without
  listeners offset_ never moves on the buffered path.
- *Direct offset_ double-counts with listeners:* the direct path
  advances offset_ by the full n up front (0x60492c7) and then
  again by every chunk's `tmp.size()` through the notify
  fetch_add.
- *The sret move drops subcode and scope:* the returned status
  always has subcode 0 and an unwritten scope byte.
- *The IOOptions else branches are `allowed = n` / `allowed =
  size`:* confirmed by the binary's jumps (`cmp $0x4,%ecx; je`
  to the bypass) and by the upstream source -- not `n - read` or
  `capacity - read`.
- *The listener guard devirtualises the empty base:* each
  listener's slot-33 entry is compared against 0x6042c10 and the
  call is skipped on a match.
- *The tail runs on a short ok read but not on an error:* an
  error after a good chunk leaves r = 0 even though bytes were
  read into the aligned buffer.
- *One unidentified caller:* the FDE 0x60d4cf0..0x60d4f62 (site
  0x60d4dc7, n 0x2000, priority forwarded) has no vendor census
  record; its enclosing function is unidentified.

**Caller census** (whole-.text E8/E9/LEA scan, Capstone-validated,
`census.py`, reproduced byte-identically by re-running it):
exactly 5 direct calls, 0 tail jumps, 0 LEA refs --
`log::Reader::UnmarkEOFInternal` 0x5f016a0 (site 0x5f0172d),
`log::Reader::ReadMore` 0x5f018d0 (site 0x5f01997, n 0x8000),
`FragmentBufferedReader::TryReadMore` 0x5f02980 (site 0x5f02a87,
n 0x8000), `rocksdb::CopyFile` 0x603ae70 (site 0x603b843, n =
min(remaining, 0x1000)), and one unidentified FDE 0x60d4cf0
(site 0x60d4dc7, n 0x2000, priority forwarded from its caller).
All four identified callers pass IO_TOTAL (4); the fifth forwards
its caller's priority.

## Cases

2,400 deterministic cases generated by
`tools/sequential_file_reader_read115.py` (`gen-cases`), 2,396
rows in `cases.tsv` (the 4 direct-path full-block rows over the
cap live only in `cases.json`, by the 100 MB rule from #5986),
replayed by `tests/test_sequential_file_reader_read115.py` (34
tests pass):

- 600 buffered_path (full/short/error reads, the paranoid bump,
  n == 0, scratch-null, multi-chunk reads via a rate limiter,
  error on the third chunk, a status `state_` on the second chunk
  (previous sret `state_` freed), rate-limiter gating incl.
  IO_TOTAL bypass, tracer selection, listeners incl. the base
  no-op skip and the error-status copy, IOSTATS on/off,
  script exhaustion mid-loop, pseudo-random fill) -- the bump,
  the loop, the sret move, the notify block, and the offset
  discipline.
- 600 direct_path (alignment/offset/n sweeps, full-window reads,
  multi-chunk positioned reads via a limiter, short reads incl.
  the r = 0 below-offset_advance case, error reads incl. error
  after a good chunk, rate limiter, listeners incl. the double
  offset advance, tracer selection, scratch-null, IOSTATS,
  pseudo-random fill) -- the alignment math, the memcpy tail, and
  the up-front offset advance.
- 600 sequences (buffered accumulation with/without listeners,
  short-read drain, error then success with no sticky state,
  direct accumulation, mixed priorities, varying n, a direct
  short read in the middle, pseudo-random fill) -- the state
  machine across calls.
- 600 bindings (function bytes, caller census, layout pins,
  constants, upstream anchors, case invariants, one 256-byte
  window row and per-byte rows over the main FDE start) -- every
  pinned byte replay-checked against the binary.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool models the routine in Python; the
`FSSequentialFile` (raw or tracing wrapper), the `RateLimiter`, the
`EventListener`s and the `IOTracer` are taken as inputs, and the
live check reads a real file through the same Read/PositionedRead
contract. `make verify/test/catalogue-check` in a tooled
environment is still owed upstream.

## Unknowns

- The exact declared widths of the `IOOptions` fields: the merged
  immediates pin the byte values (0x400000000 at +0x08, 7 at
  +0x10) but not the fields' exact declared widths; the 88-byte
  total follows the v8.1.1 header.
- The `tracing_enabled` byte derivation (+0x68 in `IOTracer`):
  the binary reads `[io_tracer_+0x68]` as the
  `is_tracing_enabled()` result, but which `IOTracer` member that
  byte is has not been independently derived.
- Whether the `Reader`'s other members (the 0xa8-byte total, the
  `FSSequentialFileTracingWrapper` interior at +0x40/+0x48/+0x58/
  +0x60) are exactly as derived: only the pinned fields
  (+0x20/+0x30/+0x38/+0x80/+0x88/+0x90/+0xa0) are observed in this
  FDE; the rest follows the header order with natural alignment.
- The `ReadaheadSequentialFile` wrapper
  (`NewReadaheadSequentialFile` 0x6048c30..0x6048d67, the adjacent
  FDE) is NOT modelled here: only its existence as the readahead
  path is recorded.
- The unidentified caller FDE 0x60d4cf0..0x60d4f62: its enclosing
  function is unidentified (no census record) -- a follow-up
  packet can pin it.
- `make verify/test/catalogue-check` in a tooled environment is
  still owed upstream (no cargo/rustc/git-lfs/Ghidra on this VM).
