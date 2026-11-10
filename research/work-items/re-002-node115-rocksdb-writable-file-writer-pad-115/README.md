# RE-002 · Node #115 RocksDB WritableFileWriter::Pad

Component: storage / SST file writer. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 pad a `WritableFileWriter` -- how are the pad bytes
zero-filled, when does it flush the buffer mid-pad, what happens when that
flush fails, and what does the verification checksum cover? Both functions
are pinned to the binary; both are census-bound (body hash matches the
vendor census `target_body_sha256` exactly; source hash reproduced by
zeroing the recorded relocations -- Pad: 10 relocations, kinds 2/4; .cold:
3 relocations, kind 4; neither has a kind-42 relocation, so no GOTPCRELX
restoration applies):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::WritableFileWriter::Pad` | 0x60525b0..0x60527a5 | 501 | `6f8cee586bf154c1348c2458f5925fb69943ee01e05c24d95bcdc8348ae55f0b` |
| `rocksdb::WritableFileWriter::Pad.cold` | 0x605257c..0x60525a8 | 44 | `41b351719351e161fb7ae9bafede7ce7b4f7dad768c2f61b4092fc047b789191` |

Scope note: open PR #6057 (WritableFileWriter::Flush) took Pad as a caller
(one call site, 0x605269a) and left it as the direct follow-up; this packet
supersedes that oracle note with the full body model. The Flush it calls,
the `WriteBuffered[WithChecksum]` / `WriteDirect[WithChecksum]` routines
Flush dispatches to, and the `RangeSync` member Flush's arm calls are input
oracles here, not reconstructed; their bodies are open follow-ups.

## Answer (pinned)

**Signature.** `IOStatus Pad(uint64_t size, Env::IOPriority priority)`
returns by value, so `rdi` is the hidden 16-byte sret out-pointer, `rsi` is
the `Writer*`, `rdx` the size, `ecx` the priority.

**1. Seen-error gate (0x60525d5).** Byte `this+0x89` (`seen_error_`) is read
first. If set, the routine returns at once: sret = code 5 (`kIOError`),
27-byte heap state_ `"Writer has previous error."`, the old sret state_
`delete[]`'d first -- exactly upstream
`AssertFalseAndGetStatusForPrevError()` (`file/writable_file_writer.h:555-563`).
No other member is touched: no zero-fill, no Flush, `pending_sync_` NOT set,
`filesize_` unchanged.

**2. Zero-fill loop (0x60525e4..0x60526c4).** The entry `cursize_`
(`this+0x58`) is saved at `rsp+0x8` -- it is the pad start -- and the
remaining size is filled in chunks of `min(buf_.capacity_ (this+0x50) -
buf_.cursize_, remaining)`: `memset(buf_.bufstart_ (this+0x60) +
buf_.cursize_, 0, chunk)` via the PLT `memset` at 0x63f0a90, `cursize_ +=
chunk`, `remaining -= chunk`. When `remaining` is still non-zero the buffer
is full, so the routine calls `Flush(priority)` at 0x6051a20 (call site
0x605269a) with a 16-byte sret at `rsp+0x10`; on a non-OK Flush status (code
byte at `0x10(%rsp)` != 0) it sets `seen_error_` = 1 and returns that status
at once (0x6052758, move-assigned into the out sret with byte 2 forced to 0
-- `pending_sync_` NOT set, `filesize_` NOT advanced). On success it
`delete[]`s the Flush sret state_ when non-null, reloads `cursize_` /
`capacity_` and loops. A zero-size Pad skips the loop entirely (0x60525fa).
A full buffer at entry flushes first: chunk 0, Flush, then the pad.

**3. Epilogue (0x605262e).** `pending_sync_` (`this+0x88`) = 1; `filesize_`
(`this+0x70`) += `size`.

**4. Verification arm (0x6052641..0x605274f).** Only when
`perform_data_verification_` (`this+0xd1`) is set,
`buffered_data_crc32c_checksum_` (`this+0xd4`) =
`crc32c::Extend(checksum, buf_.bufstart_ + ENTRY cursize_, size)` through
the 0x61c25f0 dispatch thunk -- the pointer is the SAVED entry cursize, not
the final one. When no Flush intervened the span is exactly the zeros just
written; when a Flush DID intervene (size exceeded the free space at entry)
the span runs past the buffer's capacity -- the binary reads heap bytes past
the allocation, so the resulting checksum is NOT pinned by this model
(recorded as null with the pointer/length). `buffered_data_with_checksum_`
(`this+0xd8`) is NOT consulted here (unlike Flush's `WriteDirectWithChecksum`
selection, which requires both flags).

**5. OK return (0x605264f).** sret = `{code 0, state_ null}`.

**Direct I/O note.** Pad's binary has no `use_direct_io()` check (upstream
asserts `!use_direct_io()` only in the sense that `Pad` is written for the
buffered path -- see the cross-check below). With direct I/O and
`pending_sync_` clear, Flush skips the write, the buffer stays full and the
loop makes no progress -- the binary does not terminate for `size` > free
space in that configuration. The model raises instead of hanging (see
`pad()`); no generated case uses direct I/O.

**The `.cold` landing pad (0x605257c, 44 B, census-bound).** A single tail
jump at 0x60527a0 (the FDE's exception landing-pad tail: `endbr64; mov %rax,
%rbx; jmp 0x605257c`) enters it: `delete[]` the sret state_ when non-null,
check the stack canary, then `_Unwind_Resume` (or `__stack_chk_fail`). It is
unwind-only; no case exercises it.

**DecideRateLimiterPriority (0x604c800, 39 B, census-bound, verified
instruction by instruction in the Flush packet):** both `IO_TOTAL` (4) ->
`IO_TOTAL`; file `IO_TOTAL` -> op priority; op `IO_TOTAL` -> file priority;
else op priority. Exactly upstream `writable_file_writer.cc:1859-1885`.
Used by the Flush oracle's IOOptions build.

**Writer layout** (node #115, from the field accesses, confirmed against
upstream `file/writable_file_writer.h` and the Append #6041 / Flush #6057
packets): `file_name_` +0x00 (std::string, 32), `writable_file_` +0x20
(`FSWritableFilePtr`: `io_tracer_` shared_ptr +0x20/+0x28, `fs_tracer_`
unique_ptr +0x30), `clock_` +0x38, `buf_` +0x40 (`AlignedBuffer`:
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
exactly **1 direct call** to Pad, 0 tail jumps, 0 LEA refs; the `.cold`
pad has exactly 1 tail jump from 0x60527a0. The sole caller:

| site | caller FDE | caller |
|---|---|---|
| 0x60e7649 | 0x60e7200..0x60e7844 | `rocksdb::BlockBasedTableBuilder::WriteMaybeCompressedBlock` |

The caller (census-bound) computes the pad size at 0x60e7618..0x60e7649 as
`(block_size - ((offset + 5) % block_size)) % block_size` -- the SST
block-alignment pad (block trailer: 1 type byte + 4 CRC bytes), with priority
`IO_TOTAL` (4) -- so the next block starts aligned. Pad itself never
computes an alignment; the caller does. The alignment math is pinned in the
bindings group (`caller_pad_size` rows) for block sizes 4096..65536.

Pad calls `Flush` (0x6051a20) at exactly one site, 0x605269a, inside its
zero-fill loop, and the `crc32c::Extend` dispatch thunk 0x61c25f0 at
0x6052743. Pad calls no other `WritableFileWriter` member: no `Append` call
exists in the FDE.

## Evidence

- `tools/writable_file_writer_pad115.py` -- the Pad model (plus the Flush
  oracle at #6057 fidelity, used for the mid-loop Flush).
- `tests/test_writable_file_writer_pad115.py` -- 28 tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 gate + 600 pad_paths + 600
  verification + 600 bindings), 0 mismatches on replay
  (`python3 tools/writable_file_writer_pad115.py --verify`).
- Live engine check (`--live`): all 6 legs pass -- the model drove a real
  file through a 5000-byte pad with a mid-loop flush (4096 B flushed, 904 B
  tail, then a final Flush: 5000 zero bytes total), a verification-on pad
  with no flush (checksum pinned: `Extend(entry, zeros)`), the seen-error
  gate, a zero-size pad, a flush-intervened verification pad (file bytes
  exact, checksum null -- unpinned by design), and a mid-loop Flush failure
  (`seen_error_` set, `filesize_` NOT advanced, buffer cleared by the
  failed `WriteBuffered`); the model file image equalled the real file bytes
  after every Pad.
- `records.json` -- semantic records only (never a per-instruction mnemonic
  list); `functions.tsv`, `callers.tsv`, `census.json` -- the census above.
- `MANIFEST.sha256` verifies clean; `tools/verify_packets.py` flags only the
  pre-existing mismatch in unrelated packet RE-001-adjacent-last-115 (present
  on clean upstream main, untouched).
- Excerpts are whole-FDE and verbatim (`.hex` + `.objdump.txt` per function),
  with the repo-relative binary path `work/hl-node-115.bin` (no absolute
  home paths).

## Upstream cross-check

`facebook/rocksdb` v8.1.1, read live this cycle (`file/writable_file_writer.cc`,
`Pad`, lines 342-411), confirms the packet step for step:

```cpp
IOStatus WritableFileWriter::Pad(const size_t pad_bytes,
                                 Env::IOPriority op_rate_limiter_priority) {
  if (seen_error()) {
    return AssertFalseAndGetStatusForPrevError();
  }
  assert(pad_bytes < kDefaultPageSize);
  size_t left = pad_bytes;
  size_t cap = buf_.Capacity() - buf_.CurrentSize();
  size_t pad_start = buf_.CurrentSize();
  // Assume pad_bytes is small compared to buf_ capacity. ...
  while (left) {
    size_t append_bytes = std::min(cap, left);
    buf_.PadWith(append_bytes, 0);
    left -= append_bytes;
    if (left > 0) {
      IOStatus s = Flush(op_rate_limiter_priority);
      if (!s.ok()) {
        set_seen_error();
        return s;
      }
    }
    cap = buf_.Capacity() - buf_.CurrentSize();
  }
  pending_sync_ = true;
  uint64_t cur_size = filesize_.load(std::memory_order_acquire);
  filesize_.store(cur_size + pad_bytes, std::memory_order_release);
  if (perform_data_verification_) {
    buffered_data_crc32c_checksum_ =
        crc32c::Extend(buffered_data_crc32c_checksum_,
                       buf_.BufferStart() + pad_start, pad_bytes);
  }
  return IOStatus::OK();
}
```

Every step matches: the seen-error gate, the saved `pad_start`, the
`min(cap, left)` chunking with `PadWith(append_bytes, 0)` (inlined as
`memset` in the binary), the Flush-when-left-remains with the failure
return, the `cap` recompute, `pending_sync_ = true`, `filesize_ +=
pad_bytes`, and the verification `Extend` over `BufferStart() + pad_start`
with length `pad_bytes` gated on `perform_data_verification_` alone. Two
binary-vs-source observations, recorded not hidden:

- The `assert(pad_bytes < kDefaultPageSize)` is compiled out in the release
  binary: the FDE contains no comparison of `size` against 4096 (only the
  zero check at 0x60525fa), so the model does not enforce it.
- The over-read quirk is upstream code, not a model artifact: the Extend
  pointer is `BufferStart() + pad_start` with length `pad_bytes`, and the
  source comment says "Assume pad_bytes is small compared to buf_
  capacity". When that assumption fails (pad size exceeds the free space,
  so a Flush intervened), the Extend reads past the buffer -- the binary
  does exactly what the source says, and the model records the checksum as
  unpinned in that case rather than asserting heap contents.

## Open unknowns (not claimed)

- One member the binary reads but the layout above does not name: a bool at
  `this+0xd9`, copied into both finish events by the Flush oracle -- recorded
  in the model as `flag_d9` (shared with the Flush packet).
- The listener method name for vtable slot 47 (the failure event): the slot
  is the binary's observed position and the `FileOperationType` values (4/7)
  plus the rocksdbjni 9.0.0 docs support OnFileFlushFinish / OnFileRangeSyncFinish
  for slots 35/37, but slot 47's method name is not established, and the slot
  numbers do not line up with the 2019 `listener.h` declaration order
  (ReadFinish is slot 33 per the open #5992 packet, implying ~19 more virtuals
  before it than the 2019 order has). Recorded as open; no name is asserted.
- The heap bytes the verification Extend reads when a Flush intervened (past
  the buffer capacity): unpinned by design -- the model records the
  pointer/length and nulls the checksum rather than asserting heap contents.
- Direct-I/O Pad behaviour beyond the no-progress observation: the binary's
  Flush handles the direct arm (`WriteDirect` when `pending_sync_` is set),
  but upstream writes Pad for the buffered path, so the direct path is
  implemented in the Flush oracle but no Pad case uses it; the
  `pending_sync_`-clear non-termination is documented, not exercised as a
  case.
- `Flush`, `WriteBuffered`, `WriteBufferedWithChecksum`, `WriteDirect`,
  `WriteDirectWithChecksum` and the `RangeSync` member are input oracles
  here; their full reconstruction is a follow-up. The next natural
  follow-ups: `WriteBuffered` 0x604e140 (3533 B), `WriteBufferedWithChecksum`
  0x604f080 (3351 B), `WriteDirect` 0x604fe80 (3338 B),
  `WriteDirectWithChecksum` 0x6050c80 (3255 B) -- the four engine callees
  Flush dispatches to; or `DBImpl::CreateWAL` 0x5e5c270..0x5e5c9a3 (caller of
  `AddCompressionTypeRecord`); or the unidentified FDE 0x60d4cf0
  (`SequentialFileReader::Read` caller, open unknown from #5992).

## Environment limits (stated honestly)

No cargo/rustc/git-lfs/Ghidra on this VM. The binary is read statically
(`work/hl-node-115.bin`); nothing is executed. `Flush`,
`WriteBuffered`, `WriteBufferedWithChecksum`, `WriteDirect`,
`WriteDirectWithChecksum` and `file_->Flush` / `file->RangeSync` are input
oracles with the contracts from open PRs #6057 (Flush) and #6041 (Append);
their bodies are not reconstructed here. `make verify` / `test` /
`catalogue-check` in a tooled environment is still owed upstream.
