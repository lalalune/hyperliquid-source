# RE-002 · Node #115 RocksDB log::FragmentBufferedReader::TryReadFragment

Component: storage / WAL / log reading. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 turn the bytes in a fragment-buffered WAL reader's
buffer into one fragment -- how does
`log::FragmentBufferedReader::TryReadFragment` refill the buffer,
parse the header, decide recyclable vs plain, check the CRC, and when
does it decompress instead of returning the raw slice? The function is
census-bound (body hash matches the vendor census
`target_body_sha256` exactly; source hash reproduced by zeroing the
recorded relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::log::FragmentBufferedReader::TryReadFragment` | 0x5f02b40..0x5f02ee6 | 934 | `e7cefc65de0773da8a7779b9e3f67387702971ce9969dba96511ee470387cf01` |

Scope note: this is the reader-side continuation of open PR #5982
(`ReadPhysicalRecord` 0x5f01a30, the sibling routine with its own
inline copy of this parse) and open PR #5986 (`ReadMore` 0x5f018d0,
the twin of this packet's input `TryReadMore` 0x5f02980). The single
caller is `FragmentBufferedReader::ReadRecord` 0x5f02f20..0x5f034f2.
`TryReadMore` (0x5f02980) and the ZSTD streaming `Uncompress` engine
(#5972) are inputs to the model, not re-claimed.

## Answer (pinned)

**Signature.** `bool TryReadFragment(Slice* fragment, size_t*
drop_size, unsigned int* fragment_type_or_err)` -- `rdi` is the
`FragmentBufferedReader*` (rbx), `rsi` the fragment Slice* (saved
`[rsp+0x8]`), `rdx` the drop_size* (rbp), `rcx` the
fragment_type_or_err* (r13). It returns `true` when the caller should
process `*fragment_type_or_err` (a record type 0..9 on success, or a
special code: kEof 10, kBadRecord 11, kBadHeader 12 (only via
`TryReadMore`), kOldRecord 13, kBadRecordChecksum 15 -- there is no
kBadRecordLen arm here) and `false` only when `TryReadMore` fails or
makes no progress.

**FragmentBufferedReader layout** (node #115; the eight pinned fields
from the field accesses, the rest derived from the member order in
upstream `db/log_reader.h` with natural alignment -- same prefix as
#5982, plus the two fields the sole caller observes): `vptr` +0x00,
`info_log_` +0x08 (16), `file_` +0x18, `reporter_` +0x20, `checksum_`
+0x28, `backing_store_` +0x30, `buffer_` (Slice) +0x38 (16), `eof_`
+0x48, `read_error_` +0x49, `eof_offset_` +0x50,
`last_record_offset_` +0x58, `end_of_buffer_offset_` +0x60,
`log_number_` +0x68, `recycled_` +0x70, `first_record_read_` +0x71,
`compression_type_` +0x72, `compression_type_record_read_` +0x73,
`uncompress_` +0x78, `uncompressed_buffer_` +0x80,
`uncompressed_record_` (std::string) +0x88 (32), `hash_state_`
+0xa8, `uncompress_hash_state_` +0xb0, `fragments_` (std::string)
+0xb8 (32, caller-observed), `in_fragmented_record_` +0xd8 (1,
caller-observed). Highest observed offset + size is 0xd9; the full
object size past that is not pinned by this FDE (see the open
unknowns).

**Refill loops -- TryReadMore.** There are three of them, all the
same shape with different thresholds: header (`buffer_.size() <= 6`,
below `kHeaderSize` 7), recyclable header (`<= 10`, below
`kRecyclableHeaderSize` 11), and body (`header_size + length >
buffer_.size()`). Each presets the local code to `kEof` (10) and
calls `TryReadMore` (0x5f02980); on false, `*fragment_type_or_err`
is set to that code and the routine returns `false`. On true with
`buffer_.size()` unchanged (no progress), it returns `false` with
`*fragment_type_or_err` UNTOUCHED -- the caller then returns 0 (see
the caller disassembly at 0x5f03430). Otherwise it re-loops.

**Header parse.** Type is the sign-extended byte `header[6]`
(`movsx eax`); length is the LE16 `header[4:6]` (`movzx ecx,
word`). Recyclable iff `(uint32_t)(type - 5) <= 3`, i.e. the signed
type is in 5..8 (`kRecyclableFullType`..`kRecyclableLastType`).

**Recyclable arm.** If `end_of_buffer_offset_ - buffer_.size() == 0`
(`cmp [rbx+0x60], buffer size`), `recycled_ = true` at this+0x70.
The header grows to 11 (`kRecyclableHeaderSize`); a buffer of 10 or
fewer bytes goes back to `TryReadMore`. `log_num = DecodeFixed32(header
+ 7)`; a mismatch against `log_number_` (+0x68) sets
`*fragment_type_or_err = kOldRecord` (13) and returns `true` -- the
buffer is NOT cleared and no `drop_size` is written -- and this gate
fires *before* the CRC check.

**Body loop and zero check.** Unlike `ReadPhysicalRecord`, a short
body does NOT return `kBadRecordLen`: the body loop just keeps
refilling through `TryReadMore` until the whole record fits, so a
record longer than one block can still complete if the refills
deliver it. If type == 0 and length == 0: `buffer_.clear()`, return
`true` with `*fragment_type_or_err = kBadRecord` (11) -- with no
`drop_size` write and `*fragment` untouched.

**CRC check.** When `checksum_` (+0x28) is set: `expected =
crc32c::Unmask(DecodeFixed32(header))` -- the binary computes
`(stored - kMaskDelta) rol 15` (`add eax, 0x5d7d1528; rol eax, 0xf`;
0x5d7d1528 is `-0xa282ead8` mod 2^32); `actual =
crc32c::Value(header + 6, length + header_size - 6)`, inlined as
`Extend(0, header + 6, length + header_size - 6)` through the
dispatch thunk at 0x61c25f0 (see below). On mismatch: `*drop_size =
buffer_.size()`, `buffer_.clear()`, `*fragment_type_or_err =
kBadRecordChecksum` (15), return `true`. The covered range is the
type byte, the recyclable log_num, and the payload -- not the stored
CRC or the length.

**The CRC dispatch.** 0x61c25f0 is a 16-byte `endbr64; jmp
[rip+0x34630e]` stub whose target slot 0x6508908 (.bss) is written
once by the tiny init stub at 0x61c26d0 (`lea rax, 0x61c21d0; mov
[0x6508908], rax; ret`). 0x61c21d0 is census-bound as
`rocksdb::crc32c::ExtendImpl<Slow_CRC32>` -- the slow table
implementation the slot holds in this binary.

**Raw result.** `buffer_.remove_prefix(header_size + length)`, then
if `!uncompress_` (+0x78) or type == `kSetCompressionType` (9):
`*fragment = Slice(header + header_size, length)`;
`*fragment_type_or_err = type` (the sign-extended byte as u32 -- a
type byte >= 0x80 returns sign-extended, e.g. 0xFFFFFF80 for 0x80);
return `true`. Only type 9 bypasses decompression in this binary: a
newer upstream `log_reader.cc` also bypasses
`kUserDefinedTimestampSizeType` and
`kRecyclableUserDefinedTimestampSizeType`, but this FDE contains no
comparison against those type values at all, so types 10/11 go
through decompression when `uncompress_` is set -- the binary is
the authority and the packet pins that.

**Decompress loop.** Otherwise: `uncompressed_record_.clear()` (size
0 at +0x90, data[0] = 0). The `do-while` loop calls
`uncompress_->Uncompress(input, length, uncompressed_buffer_.get(),
&uncompressed_size)` through vtable slot 2 (`[rax+0x10]`): the input
is the payload on the first call and null afterwards, while the
length is passed unchanged on every call (the null-input resume rule
from #5972). `remaining < 0`: `buffer_.clear()`,
`*fragment_type_or_err = kBadRecord` (11), return `true` --
`*fragment` is NOT written on this arm (the partial
`uncompressed_record_` stays in the reader). Produced bytes > 0:
the `std::string` length check (produced > max_size - current size
throws `length_error "basic_string::append"`, 0x4474d2) and
`_M_append`. The loop runs while `remaining != 0` or `produced ==
kBlockSize` (0x8000) -- a full 0x8000-byte output forces another
call even with nothing left. Then `*fragment =
Slice(uncompressed_record_)`; `*fragment_type_or_err = type`;
return `true`. There is no XXH3 fragment-checksum handling here
(unlike #5982): no hash state is created, reset, or digested.

**Findings (verified against the binary + upstream).**

- *Three refill loops, two false exits:* every loop presets the
  code to `kEof` (10) before calling `TryReadMore`; a false return
  writes that code out, while a true return with no buffer growth
  returns `false` without writing the out-param at all -- the only
  path that leaves it untouched.
- *No kBadRecordLen arm:* a short body refills instead of failing,
  so `kBadRecordLen` (14) is in the enum but unreachable from this
  routine.
- *Signed-type classification:* the recyclable test and the zero
  check both run on the sign-extended type byte, so a type byte
  >= 0x80 takes the plain arm and returns sign-extended.
- *Log_num gate before CRC:* a corrupted log_num byte returns
  `kOldRecord`, not `kBadRecordChecksum`, even though bytes 7..10
  are inside the CRC coverage -- so the CRC coverage of the log_num
  field is not separately observable through the return code.
- *CRC coverage is type + log_num + payload:* the stored CRC and the
  length are outside the covered range; the stored value is masked
  and the binary unmasks with `(stored - 0xa282ead8) rol 15`.
- *Dispatch thunk, not a direct call:* the CRC engine is reached
  through the 16-byte thunk at 0x61c25f0 and the .bss slot 0x6508908,
  filled once at startup with `ExtendImpl<Slow_CRC32>` (0x61c21d0,
  census-bound).
- *Length passed unchanged:* every `Uncompress` call receives the
  original length in `rdx` while the input goes null after the
  first call -- the holder keeps the unconsumed input internally
  (the #5972 resume rule).
- *Types 10/11 are decompressed:* the binary has no bypass for the
  user-defined-timestamp types; the newer upstream bypass is absent
  here, which the packet records as a binary-vs-newer-source
  difference, not a model error.
- *Drop-size discipline:* only the `kBadRecordChecksum` path writes
  `*drop_size` (the zero-record and decompress-error paths clear the
  buffer without touching it); `TryReadMore`'s own `kBadHeader`
  failure is the only way `*drop_size` is set on the refill paths.
- *Live engine check:* pure-Python CRC32C reproduces the standard
  `0xE3069283` vector for `"123456789"` and Mask/Unmask round-trip;
  a real ZSTD frame wrapped in a real WAL record (type 1, correct
  masked CRC) runs through the model with the real `Uncompress`
  shim and returns `True` with fragment type 1 and the original
  payload; the same frame with `uncompress_` absent returns the
  frame bytes untouched; the same frame as a recyclable type-5
  record with a matching log_num returns `True` with fragment type
  5, the original payload, and `recycled_` set.

**Caller census** (whole-.text E8/E9/LEA scan, Capstone-validated,
`census.py`): exactly 1 direct call, 0 tail jumps, 0 LEA refs --
inside `rocksdb::log::FragmentBufferedReader::ReadRecord`
0x5f02f20..0x5f034f2 (at 0x5f02fdc; the call sets `rcx =
&fragment_type_or_err` [rsp+0x24], `rdx = &drop_size` [rsp+0x28],
`rsi = &fragment` [rsp+0x30], then dispatches on
`*fragment_type_or_err` through a jump table at 0x970768 when the
call returns true, and returns 0 when it returns false).
`TryReadMore` is called three times from inside this routine (the
three refill loops) but is an input, not a caller;
`ReadPhysicalRecord` is a sibling with its own inline copy of the
parse, not a caller.

**Engine callees.** `TryReadMore` 0x5f02980 is census-confirmed (the
model takes its outcome as an input); `crc32c::Extend` is reached
through the 0x61c25f0 dispatch thunk to `ExtendImpl<Slow_CRC32>`
0x61c21d0 (census-confirmed); the PLT stubs (`_M_append`,
`__stack_chk_fail`, `__throw_length_error`) are pinned by their
relocation displacements (see `records.json`).

## Cases

2,400 deterministic cases in `cases.tsv`, generated by
`tools/fragment_buffered_reader_try_read_fragment115.py`
(`gen-cases`) and replayed by
`tests/test_fragment_buffered_reader_try_read_fragment115.py` (36
tests pass):

- 600 header_parse (all 256 type bytes, length sweep 0..32761,
  impossible lengths 32762/40000/65535, zero-type arm, recyclable
  log_num match/mismatch, recycled flag set/unset, TryReadMore
  refill/fail/no-progress paths in all three loops incl.
  two-refill sequences, trailing bytes, two records back to back)
  -- the header parse, the recyclable gate, the body loop, and the
  three refill loops.
- 600 crc (288 correct masked CRCs across types 1/2/4/5/8/9,
  lengths 0..1000 and payload patterns; 288 corrupted stored-CRC /
  payload / type bytes; 12 log_num-gate-before-CRC rows; 12
  CRC-skipped-when-off rows) -- the masked-CRC check and its
  failure arm.
- 600 decompress (single-shot, multi-chunk, zero-produce steps,
  engine error on first/second call, type-9 bypass, types 10/11
  decompressed, type bytes >= 0x80, recyclable types, checksum-on
  decompress, one exact-kBlockSize continuation, pseudo-random
  fill) -- the do-while decompress loop and its error arms.
- 600 bindings (body/source hashes, 11 relocation displacements, 1
  caller site, 24 layout fields, 10 constants, 14 upstream
  anchors, 256 type-classification rows, 100 stride-1 16-byte
  windows, 100 8-byte windows, 50 4-byte windows, 32 single-byte
  rows over the first 100 bytes of the 934-byte FDE) -- the
  binary-level pins.

## Files

- `MANIFEST.sha256` -- SHA-256 of every file in this packet.
- `README.md` -- this file.
- `functions.tsv` -- the function, its FDE range, body/source
  hashes (generated by `gen_records.py` from the binary + census,
  never hand-transcribed).
- `records.json` -- the semantic records (model, layout, caller
  census, engine callees, observations, unknowns).
- `census.py` / `census.json` / `callers.tsv` -- the caller census
  (whole-.text E8/E9/LEA scan, Capstone-validated).
- `export_excerpts.py` -- regenerates the verbatim excerpts below.
- `try-read-fragment-5f02b40.hex` -- the raw 934 bytes of the FDE.
- `try-read-fragment-5f02b40.objdump.txt` -- the whole FDE,
  verbatim objdump (`-M intel`).
- `cases.tsv` -- the 2,400-case ledger.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM; the target binary is never
executed. The tool models the routine in Python; `TryReadMore` and
`StreamingUncompress::Uncompress` are taken as inputs, and the
CRC32C/ZSTD engines are driven for real in the live check
(pure-Python CRC32C validated against the standard `"123456789"`
vector, system libzstd.so.1 (1.5.5) via ctypes for the decompress
round trip). `make verify` / `make test` / `make catalogue-check` in
a tooled environment is still owed upstream.

## Open unknowns

- `TryReadMore`'s body (0x5f02980, 401 B, census-bound) is NOT
  modelled here -- only its true/false outcome, its code/drop_size
  writes, and its wholesale buffer replacement are inputs. A
  follow-up packet can reconstruct it (it is the fragment reader's
  own `ReadMore`, the direct twin of #5986).
- `FragmentBufferedReader::ReadRecord` (0x5f02f20..0x5f034f2, 1490 B,
  census-bound) is NOT modelled here -- only its single
  `TryReadFragment` call site and its jump-table dispatch are
  pinned. It is the natural follow-up: it assembles fragments into
  logical records.
- Whether `FragmentBufferedReader` inherits `Reader` or duplicates
  its prefix, and where the `Reader` tail lives in this build: #5982
  derives `recorded_cf_to_ts_sz_` at +0xb8 (total 0xf0) for a plain
  `Reader`, but this class carries `fragments_` (std::string) at
  +0xb8 and `in_fragmented_record_` (bool) at +0xd8 in its sole
  caller. Only the eight fields this FDE touches plus the two
  caller-observed fields are pinned here; the tail past +0xb0 is
  recorded as an open unknown, not as a correction to #5982.
- Whether `IsFastCrc32Supported` (0x61c2400) would select a
  different `Extend` implementation on another CPU: this packet
  pins the slow implementation the dispatch slot holds in this
  binary; the selection itself is not modelled.
