# RE-002 · Node #115 RocksDB log::Reader::ReadMore

Component: storage / WAL / log reading. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 refill a WAL reader's buffer -- how does
`log::Reader::ReadMore` decide between reading a fresh block and
draining a truncated header, and what exactly does each path write
to the reader state and the out-params? The function is
census-bound (body hash matches the vendor census
`target_body_sha256` exactly; source hash reproduced by zeroing the
recorded relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::log::Reader::ReadMore` | 0x5f018d0..0x5f01a30 | 352 | `bb83379f1674d6eb1b4574cd9fd27e3424428e3a5c55d8588b7bfe22cdb3c55d` |

Scope note: this is the reader-side follow-up to open PR #5982
(`ReadPhysicalRecord` 0x5f01a30, the routine's only caller -- the
loop-head call at 0x5f01aab) and open PR #5979 (`InitCompression`
0x5f01e80). It closes the open unknown the #5982 packet left
behind ("`ReadMore`'s body ... is NOT modelled here"). The
`FragmentBufferedReader::TryReadMore` routine is a separate
function with its own read; it does not call this one.

## Answer (pinned)

**Signature.** `bool ReadMore(size_t* drop_size, int* error)` --
`rdi` is the `Reader*` (rbx), `rsi` carries `drop_size*` directly to
the drain store at 0x5f0190c, and `rdx` carries `error*` (preserved
in r12 at 0x5f018d8). It returns true when a fresh
block was read, false otherwise, and writes the failure code into
`*error` (kEof 10 or kBadHeader 12; `db/log_reader.h:286-316`).

**Reader layout** (node #115; the pinned fields from the field
accesses, the rest derived from the member order in upstream
`db/log_reader.h` with natural alignment): `vptr` +0x00, `info_log_`
+0x08 (16), `file_` +0x18, `reporter_` +0x20, `checksum_` +0x28,
`backing_store_` +0x30, `buffer_` (Slice) +0x38 (16), `eof_` +0x48,
`read_error_` +0x49, `eof_offset_` +0x50, `last_record_offset_`
+0x58, `end_of_buffer_offset_` +0x60, `log_number_` +0x68,
`recycled_` +0x70, `first_record_read_` +0x71,
`compression_type_` +0x72, `compression_type_record_read_` +0x73,
`uncompress_` +0x78, `uncompressed_buffer_` +0x80,
`uncompressed_record_` (std::string) +0x88 (32), `hash_state_`
+0xa8, `uncompress_hash_state_` +0xb0, `recorded_cf_to_ts_sz_`
+0xb8 (56); total 0xf0.

**Gate -- read vs drain.** The read path runs only when `!eof_ &&
!read_error_` (`cmpb $0,0x48(%rdi); jne drain` then `movzbl
0x49(%rdi),%ebp; test %bpl,%bpl; je read`). Either flag set takes
the drain path. No other state is consulted.

**Read path.** `buffer_.clear()` first (size 0 at +0x40, data =
0x4376fd, the empty-string literal) -- the stale block is dropped
before the fresh read, so a failed read never leaves the old
block behind. Then `SequentialFileReader::Read(kBlockSize,
&buffer_, backing_store_, Env::IO_TOTAL)` (0x6048e00; sret
Status* at rsp+0x10, file_ +0x18, n 0x8000, result &buffer_,
scratch backing_store_ +0x30, priority 4 = IO_TOTAL). The
16-byte Status is copied to the local at rsp+0x00.

**Offset advance before the status check.**
`end_of_buffer_offset_ += buffer_.size()` runs before the Status
code is tested, so a failed read still advances the offset by the
bytes actually read (a partial block still counts). The `addq` at
0x5f019bb stores a 64-bit result, so this addition wraps modulo
2^64, including on failed reads. A boundary regression checks
`u64::MAX + 2 -> 1` on both success and failure paths.

**Error arm.** If the Status code byte is non-zero:
`buffer_.clear()` again, `ReportDrop(kBlockSize, status)` -- the
0x5f01570 thunk, which calls `reporter_->Corruption(bytes,
reason)` when reporter_ (+0x20) is non-null -- then
`read_error_ = true` (+0x49), `*error = kEof` (10), return
false. The local Status is destroyed on the way out: its
`state_` pointer (rsp+0x08) is `delete[]`'d when non-null
(`_ZdaPv` PLT 0x63f0dc0).

**Short-read arm.** If the Status is ok and `buffer_.size() <
kBlockSize` (`cmp $0x7fff; ja` skips the arm, so 0x7fff sets it
and 0x8000 does not): `eof_ = true`, `eof_offset_ =
buffer_.size()` (+0x50). Return true. The Status `state_` is
`delete[]`'d here too when non-null.

**Drain path.** The buffer holds a truncated header (or nothing)
at the end of the file. If `buffer_.size() > 0`: `*drop_size =
buffer_.size()`, `buffer_.clear()`, `*error = kBadHeader` (12),
return false. If the buffer is empty: `buffer_.clear()` (data
0x4376fd; size already 0, so no size write), `*error = kEof`
(10), return false. No file read and no `ReportDrop` on this
path -- the truncated header is dropped silently as far as the
reporter is concerned (the caller, `ReadPhysicalRecord`, reports
it as "truncated header" only in the strict recovery modes).

**Exception landing pad.** On an exception during the read, the
pad at 0x5f01a24 jumps to the shared pad at 0x5f0189a, which
frees the local Status `state_` (`delete[]` when non-null),
checks the stack canary, and resumes unwinding
(`_Unwind_Resume`). It is recorded, not modelled: the model
never throws.

**Engine callees.** `SequentialFileReader::Read` 0x6048e00 (FDE
0x6048e00..0x60497fd, 2557 B; not census-bound) is taken as an
input: reads up to n bytes, `*result = Slice(scratch, bytes
read)`, returns the Status. Its identity is pinned by the
call-site signature match (upstream
`file_->Read(kBlockSize, &buffer_, backing_store_,
Env::IO_TOTAL)`, `sequence_file_reader.h:190-192`), the sret
Status prologue (Status has a non-trivial destructor, so it is
returned in memory), and the rate-limiter bypass branch
(`cmp $0x4,%ecx; je` skips `RequestToken` when the priority is
IO_TOTAL = 4, `env.h:809`). Its internals (the head's selection
between two read sources on a bool-returning vtable slot-4 call,
the prefetch/readahead selection, the exact `SequentialFileReader`
member offsets) are open unknowns, not modelled. `ReportDrop` 0x5f01570 is a 25-byte thunk:
`reporter_ = [this+0x20]`; null-check; tail-jump to the
reporter's vtable slot 2 (`Corruption`). Upstream
`ReportDrop` (`log_reader.cc:719-727`) has no other guard, so
the thunk is the whole body.

**Findings (verified against the binary + upstream v8.1.1).**

- *Offset advances on failure:* a failed read still adds the
  partially-read bytes to `end_of_buffer_offset_` -- the offset
  is the file position after the read attempt, not after a
  successful one.
- *Clear-before-read:* the stale buffer is cleared before the
  fresh read, so a failed read leaves an empty buffer, never the
  old block.
- *kBadHeader is the truncated-header code:* the drain path is
  the only place `*error = 12` is written, and only when the
  buffer is non-empty; the empty drain writes kEof. This is why
  `ReadPhysicalRecord` can return kBadHeader only through
  `ReadMore`.
- *The eof boundary is exact:* `size < 0x8000` sets eof_, so a
  0x7fff-byte read is EOF and a full 0x8000-byte read is not.
- *read_error_ sticks:* once set, every later call drains (the
  gate never re-enters the read path), so a WAL read error is
  terminal for the reader.
- *Status state_ is freed on both exits:* the local Status
  destructor runs on the success and the error path alike.
- *One call site, two paths:* `ReadPhysicalRecord` calls
  `ReadMore` from a single loop-head site (0x5f01aab); the
  short-buffer and recyclable-short-header arms both `continue`
  back to it.

**Caller census** (whole-.text E8/E9/LEA scan, Capstone-validated,
`census.py`, cross-checked by a second raw scan): exactly 1 direct
call, 0 tail jumps, 0 LEA refs -- the loop-head call at 0x5f01aab
inside `rocksdb::log::Reader::ReadPhysicalRecord`
0x5f01a30..0x5f01e7d. Upstream shows one `ReadMore` call per
`ReadPhysicalRecord` loop iteration; the binary has exactly one
site. `FragmentBufferedReader::TryReadMore` is a separate routine
and does not call this one.

## Cases

2,400 deterministic cases in `cases.tsv`, generated by
`tools/log_reader_read_more115.py` (`gen-cases`) and replayed by
`tests/test_log_reader_read_more115.py` (24 tests pass, including the review-added offset-wrap regression):

- 600 read_path (8 full-block reads; the short-read sweep
  0/1/2/7/100/1000/0x7ffe/0x7fff plus a 0..0x1000 stride-997
  sweep and mid-range sizes 0x2000/0x4000/0x6000; 8 rows each
  side of the 0x7fff/0x8000 boundary; failed reads with partial
  byte counts 0/1/100/0x7fff and with/without a Status state_;
  stale-buffer replacement; success-path state_ free;
  pseudo-random fill) -- the gate, the clear-before-read, the
  offset advance, the eof boundary, the error arm, and the
  state_ free. Full-block rows are capped so cases.tsv stays
  under GitHub's 100 MB file limit; the boundary is still pinned
  by 8 rows each side plus the sweep.
- 600 drain_path (eof_ set and read_error_ set, buffer sizes
  0..11 + 100/1000/0x7fff/0x8000; both flags set; the drain never
  consumes the read script and never calls ReportDrop; eof_offset_
  and end_of_buffer_offset_ unmoved; pseudo-random fill) -- the
  kBadHeader/kEof split, the drop_size discipline, and the
  no-read/no-report guarantee.
- 600 sequences (two full reads then a short read; full read
  then short read then drain; short read then drain then drain;
  error then drain then drain; error with a partial read; empty
  read then drain; four full reads; script exhaustion
  mid-sequence; pseudo-random sequences) -- the state machine
  across calls: eof_ setting, read_error_ sticking, offset
  accumulation.
- 600 bindings (body/source hashes, 8 relocation displacements,
  1 caller site, 24 Reader layout fields, 10 constants, 8
  upstream anchors, 200 stride-1 16-byte windows, 200 8-byte
  windows, 100 4-byte windows, 47 single-byte rows over the
  first 200 bytes of the 352-byte FDE).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool models the routine in Python;
`SequentialFileReader::Read` and `Reporter::Corruption` are taken
as inputs, and the live check reads a real file through the same
Read contract the engine callee implements (plus the
empty-literal byte check against the binary). `make
verify/test/catalogue-check` in a tooled environment is still owed
upstream.

## Unknowns

- `SequentialFileReader::Read`'s body (0x6048e00, 2557 B, not
  census-bound) is NOT modelled here -- only its boundary
  contract (reads up to n bytes, `*result = Slice(scratch, bytes
  read)`, Status ok/error) is an input. Its internals -- the
  head's selection between two read sources on a bool-returning
  vtable slot-4 call, the prefetch/readahead selection, the exact
  `SequentialFileReader` member offsets (rate_limiter_ is read at
  +0xa0, which does not match the v8.1.1 header layout) -- are
  open: a follow-up packet can reconstruct it.
- Whether the `scratch[0]++` paranoid bump in the engine callee's
  buffered path (`sequence_file_reader.cc:196-200`) is present in
  the binary: it is overwritten by the fresh bytes the read
  writes, so it is not observable through `ReadMore`'s result.
- Whether the `Reader`'s other members (the `0xf0`-byte total,
  the `UnorderedMap` at +0xb8) are exactly as derived: only the
  eight pinned fields (+0x18/+0x20/+0x30/+0x38/+0x48/+0x49/
  +0x50/+0x60) are observed in this FDE; the rest follows the
  header order with natural alignment.
- `make verify/test/catalogue-check` in a tooled environment is
  still owed upstream (no cargo/rustc/git-lfs/Ghidra on this VM).
