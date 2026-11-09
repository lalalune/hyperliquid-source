# RE-002 · Node #115 RocksDB log::FragmentBufferedReader::TryReadMore

Component: storage / WAL / log reading. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 refill a WAL fragment reader's buffer -- how does
`log::FragmentBufferedReader::TryReadMore` decide between reading a fresh
block, refilling the rest of the current block after EOF, and draining a
truncated header, and what exactly does each path write to the reader
state and the out-params? The function is census-bound (body hash
matches the vendor census `target_body_sha256` exactly; source hash
reproduced by zeroing the recorded relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::log::FragmentBufferedReader::TryReadMore` | 0x5f02980..0x5f02b32 | 434 | `ffed6babe23f74644c61ef2493500b66ed42afb9fe7e53292b436e55f9d6890b` |
| `rocksdb::log::Reader::UnmarkEOFInternal` | 0x5f016a0..0x5f01848 | 424 | `98b700cf3d8a6f09bfd130d3bb423c29262db4f70c9b2a255c8869a6a4f4f84e` |
| `rocksdb::log::FragmentBufferedReader::UnmarkEOF` | 0x5f01880..0x5f01899 | 25 | `8a1ca59cb21900b38395c79e57a23d76a7a4fc9e19ae309f8523d8ae3069e14b` |

Scope note: this is the reader-side follow-up to open PR #5994
(`TryReadFragment` 0x5f02b40, the routine's only caller -- the three
refill loops at 0x5f02bab, 0x5f02c57 and 0x5f02cb6) and the direct twin
of merged PR #5986 (`Reader::ReadMore` 0x5f018d0). It closes the open
unknown the #5994 packet left behind ("`TryReadMore`'s body ... is
NOT modelled here"). Note: #5994's entry gives TryReadMore's size as
401 B; the FDE is 0x5f02980..0x5f02b32 = 434 B, verified against the
census record.

## Answer (pinned)

**Signature.** `bool TryReadMore(size_t* drop_size, int* error)` --
`rdi` is the `FragmentBufferedReader*` (rbx), `rsi` carries
`drop_size*` (r13), `rdx` carries `error*` (rbp). It returns true
when the caller should keep going, false when it should stop, and
writes the failure code into `*error` (kEof 10 or kBadHeader 12;
`db/log_reader.h:286-316`).

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
+0xa8, `uncompress_hash_state_` +0xb0, `fragments_` +0xb8 (32,
caller-observed), `in_fragmented_record_` +0xd8 (caller-observed);
total 0xd9 observed. The Reader tail past +0xb0 is an open unknown
(see below).

**Gate -- read vs eof vs drain.** `eof_` set with `read_error_`
clear takes the eof path (step 3). `read_error_` set takes the
drain (step 4) from either gate. Otherwise (`!eof_ &&
!read_error_`) the read path runs. No other state is consulted.

**Read path.** `buffer_.clear()` first (size 0 at +0x40, data =
0x4376fd, the empty-string literal) -- the stale block is dropped
before the fresh read, so a failed read never leaves the old
block behind. Then `SequentialFileReader::Read(kBlockSize,
&buffer_, backing_store_, Env::IO_TOTAL)` (0x6048e00; sret
Status; n = 0x8000, priority 4). `end_of_buffer_offset_ +=
buffer_.size()` BEFORE the status check (a failed read still
advances the offset by the partial bytes). On status error:
`buffer_.clear()`, `ReportDrop(kBlockSize, status)` via the
0x5f01570 thunk, `read_error_ = true`, `*error = kEof` (10),
return false (no `*drop_size` write). On success: size <=
0x7fff (i.e. size < kBlockSize) sets `eof_ = true` and
`eof_offset_ = size`; a full 0x8000-byte read leaves both alone.
Return true. The Status `state_` is `delete[]`'d on both exits
when non-null.

**Eof path.** `read_error_` set takes the drain. Otherwise the
virtual `UnmarkEOF()` (vtable slot 3, +0x18) is invoked -- the
binary devirtualizes it: it compares the slot against 0x5f01880
(`FragmentBufferedReader::UnmarkEOF`) and, when equal, inlines
that override (`eof_ = false`, then call `UnmarkEOFInternal`
0x5f016a0); otherwise it calls the slot virtually with (this,
drop_size, error) still in the registers. The callee's return
value is DISCARDED; after the call, `read_error_` still clear
returns true (the original `eof_` value 1 in r12d), `read_error_`
set takes the drain.

**Drain.** `*error = kEof` (10) first, `*drop_size =
buffer_.size()` written UNCONDITIONALLY -- even 0, unlike
`Reader::ReadMore`, whose drain only writes `*drop_size` when
the buffer is non-empty -- then if the buffer is non-empty
`*error = kBadHeader` (12); `buffer_.clear()`; return false. No
file read, no ReportDrop.

**FragmentBufferedReader::UnmarkEOF (0x5f01880, 25 B).** If
`read_error_` return at once (the return value is whatever `al`
holds -- unobservable, the caller ignores it); else `eof_ =
false` and tail-jump to `UnmarkEOFInternal`. NOTE: it has NO
`eof_offset_ == 0` early return, unlike the base
`Reader::UnmarkEOF` (upstream `log_reader.cc:633-651`), which
returns early when `eof_offset_ == 0` without refilling.

**Reader::UnmarkEOFInternal (0x5f016a0, 424 B, void).** Refills
the rest of the current block, preserving the unconsumed tail:
`consumed_bytes = eof_offset_ - buffer_.size()`; `remaining =
kBlockSize - eof_offset_`. If `buffer_.data() != backing_store_
+ consumed_bytes`, `memmove(backing_store_ + consumed_bytes,
buffer_.data(), buffer_.size())`. Then `Slice read_buffer`;
`Status status = file_->Read(remaining, &read_buffer,
backing_store_ + eof_offset_, Env::IO_TOTAL)`; `added =
read_buffer.size()`; `end_of_buffer_offset_ += added`. On status
error: if `added > 0`, `ReportDrop(added, status)`; `read_error_
= true`; return (`buffer_` untouched -- the partial bytes sit in
`backing_store_` but are not covered by `buffer_`). On success:
if `read_buffer.data() != backing_store_ + eof_offset_`,
`memmove` the added bytes there; `buffer_ =
Slice(backing_store_ + consumed_bytes, eof_offset_ + added -
consumed_bytes)` (the old tail plus the fresh bytes); if `added
< remaining`, `eof_ = true` and `eof_offset_ += added`; else
`eof_offset_ = 0`. The Status `state_` is `delete[]`'d on every
exit when non-null. Its return value is never used by any caller.

## Caller census

Whole-.text E8/E9/LEA scan, Capstone-validated from enclosing FDE
starts (`census.py`): exactly 3 direct calls, 0 tail jumps, 0 LEA
refs -- all inside `rocksdb::log::FragmentBufferedReader::
TryReadFragment` 0x5f02b40..0x5f02ee6, at 0x5f02bab (header loop),
0x5f02c57 (recyclable loop) and 0x5f02cb6 (body loop), each with
the local code preset to kEof (10) and `drop_size` passed through.

## Cases

2,400 deterministic cases in `cases.tsv` (600 per group):
`read_path` (file-size sweep 0..0x8001 incl. capped full-block
rows, error injection with 0/partial/near-full bytes, out-param
non-write sweeps, `end_of_buffer_offset_` accounting, stale-buffer
clearing, pseudo-random small files), `eof_unmark` (`eof_offset`
x tail x growth matrix, empty-EOF growth, full vs short refill,
both memmove guards, refill errors with 0 vs >0 bytes,
foreign-vtable noop/internal/set_read_error arms, pseudo-random
eof states), `drain` ((eof, read_error) matrix x buffer size x
incoming out-params, drain via failed foreign UnmarkEOF, drain
after a failed refill, reporter-absent rows, pseudo-random
drains), `bindings` (5 hashes, 17 relocation displacements, 3
caller sites, 24 layout fields, 8 constants, 14 upstream anchors,
282 byte windows over TryReadMore, 247 over UnmarkEOFInternal).
Replayed by `tests/test_fragment_buffered_reader_try_read_more115.py`
(32 tests pass).

## Live engine check

`tools/fragment_buffered_reader_try_read_more115.py
live-engine-check` (all three legs pass): a real 2-block +
100-byte file reads full, full, short (`eof_`, `eof_offset_`
100, `end_of_buffer_offset_` 2*0x8000+100), then the UnmarkEOF
path re-reads 0 bytes and returns True with the 100-byte tail
still buffered (the no-progress case the caller detects, not
this routine); a refill error (40 bytes + error status) reports
`ReportDrop(40)`, sets `read_error_`, and drains with kBadHeader
and drop_size 100, and the next call drains empty with kEof and
drop_size 0; appending a full block after EOF refills through
UnmarkEOFInternal (tail preserved, `eof_offset_` 0,
`end_of_buffer_offset_` 3*0x8000); the byte at the empty-string
literal 0x4376fd is 0x00.

## Upstream anchors

Read live this cycle (mirror newer than v8.1.1):
`db/log_reader.cc` TryReadMore (lines 1510-1586), UnmarkEOF
(1495-1507), `Reader::UnmarkEOF` (633-651), UnmarkEOFInternal
(654-759), `Reader::ReadMore` (780-858); `db/log_reader.h`
(kEof 10, kBadHeader 12); `db/log_format.h` (kBlockSize 32768);
`file/sequence_file_reader.h` (Read signature, IO_TOTAL = 4).
The mirror confirms the packet step for step, including the
drain's unconditional `*drop_size` write and the fragment
UnmarkEOF's missing `eof_offset_ == 0` early return.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM; the target binary is
never executed; the tool models the routines in Python;
`SequentialFileReader::Read` is taken as an input, driven by a
real file in the live check. `make verify/test/catalogue-check`
in a tooled environment is still owed upstream.

## Open unknowns

- `FragmentBufferedReader::ReadRecord` (0x5f02f20..0x5f034f2,
  1490 B, census-bound) is NOT modelled here -- only its three
  TryReadMore call sites and its single TryReadFragment call site
  are pinned. It is the natural follow-up: it assembles fragments
  into logical records.
- Whether `FragmentBufferedReader` inherits `Reader` or duplicates
  its prefix, and where the Reader tail lives in this build: #5982
  derives `recorded_cf_to_ts_sz_` at +0xb8 (total 0xf0) for a plain
  Reader, but this class carries `fragments_` (std::string) at
  +0xb8 and `in_fragmented_record_` (bool) at +0xd8 in its sole
  caller. Only the seven fields these FDEs touch plus the two
  caller-observed fields are pinned here; the tail past +0xb0 is
  recorded as an open unknown, not as a correction to #5982.
- Whether a foreign UnmarkEOF override exists in any live subclass:
  the binary keeps the virtual call for dynamic types other than
  `FragmentBufferedReader`, but no such subclass is observed in
  this binary (the only vtable slot-3 entry found is 0x5f01880).
  The foreign arms are modelled with a scripted stand-in, not a
  real subclass.
- Whether `Reader::UnmarkEOF` (with the `eof_offset_ == 0` early
  return) is inlined at its call sites or identical-code-folded
  away: it has no standalone FDE in node #115, so its exact binary
  form is not pinned here.
