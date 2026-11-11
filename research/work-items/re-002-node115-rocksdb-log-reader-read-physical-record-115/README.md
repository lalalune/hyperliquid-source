# RE-002 · Node #115 RocksDB log::Reader::ReadPhysicalRecord

Component: storage / WAL / log reading. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 turn the bytes in a WAL reader's buffer into one
physical record -- how does `log::Reader::ReadPhysicalRecord` parse the
header, decide recyclable vs plain, check the CRC, and when does it
decompress instead of returning the raw slice? The function is
census-bound (body hash matches the vendor census
`target_body_sha256` exactly; source hash reproduced by zeroing the
recorded relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::log::Reader::ReadPhysicalRecord` | 0x5f01a30..0x5f01e7d | 1101 | `9c5b6dcbcbc0f4017ab39d2a4c19d2132e1bdede3cb4c874ace33b9eb39787bd` |

Scope note: this is the reader-side continuation of open PR #5979
(`InitCompression` 0x5f01e80, the routine this one feeds) and open PR
#5976 (the writer twin, `AddCompressionTypeRecord` 0x5f041d0, which
emits the type-9 record this routine returns raw). The two callers
are both inside `Reader::ReadRecord`; `FragmentBufferedReader::
TryReadFragment` carries its own inline copy of the parse and is a
sibling, not a caller. `ReadMore` (0x5f018d0) and the ZSTD streaming
`Uncompress` engine (#5972) are inputs to the model, not re-claimed.

## Answer (pinned)

**Signature.** `unsigned int ReadPhysicalRecord(Slice* result, size_t*
drop_size, uint64_t* fragment_checksum)` -- `rdi` is the `Reader*`
(rbx), `rsi` the result Slice* (r12), `rdx` the drop_size* (rbp),
`rcx` the fragment_checksum* (r13). It returns a record type (0..9)
or a special code: kEof 10, kBadRecord 11, kBadHeader 12 (only via
`ReadMore`), kOldRecord 13, kBadRecordLen 14, kBadRecordChecksum 15
(`db/log_reader.h:286-316`).

**Reader layout** (node #115; the ten pinned fields from the field
accesses, the rest derived from the member order in upstream
`db/log_reader.h` with natural alignment): `vptr` +0x00, `info_log_`
+0x08 (16), `file_` +0x18, `reporter_` +0x20, `checksum_` +0x28,
`backing_store_` +0x30, `buffer_` (Slice) +0x38 (16), `eof_` +0x48,
`read_error_` +0x49, `eof_offset_` +0x50, `last_record_offset_` +0x58,
`end_of_buffer_offset_` +0x60, `log_number_` +0x68, `recycled_` +0x70,
`first_record_read_` +0x71, `compression_type_` +0x72,
`compression_type_record_read_` +0x73, `uncompress_` +0x78,
`uncompressed_buffer_` +0x80, `uncompressed_record_` (std::string)
+0x88 (32), `hash_state_` +0xa8, `uncompress_hash_state_` +0xb0,
`recorded_cf_to_ts_sz_` +0xb8 (56); total 0xf0.

**Loop head -- ReadMore.** If `buffer_.size() <= 6` (below
`kHeaderSize` 7), the routine presets `r = kEof` (10) and calls
`ReadMore` (0x5f018d0); on true it re-loops, on false it returns `r`.
`ReadMore` replaces `buffer_` wholesale (it clears the buffer before
reading a fresh block), so a truncated header is dropped, not kept.

**Header parse.** Type is the sign-extended byte `header[6]`
(`movsx r15d`); length is the LE16 `header[4:6]` (`movzx esi,
word`). Recyclable iff `(uint32_t)(type - 5) <= 3`, i.e. the signed
type is in 5..8 (`kRecyclableFullType`..`kRecyclableLastType`).

**Recyclable arm.** If `end_of_buffer_offset_ - buffer_.size() == 0`
(`cmp [rbx+0x60], buffer size`), `recycled_ = true` at this+0x70.
The header grows to 11 (`kRecyclableHeaderSize`); a buffer of 10 or
fewer bytes goes back to `ReadMore`. `log_num = DecodeFixed32(header
+ 7)`; a mismatch against `log_number_` (+0x68) returns `kOldRecord`
(13) -- and this gate fires *before* the CRC check.

**Length and zero checks.** If `header_size + length >
buffer_.size()`: `*drop_size = buffer_.size()`, `buffer_.clear()`
(data = 0x4376fd, the empty-string literal, size 0), return
`kBadRecordLen` (14). If type == 0 and length == 0: `buffer_.clear()`,
return `kBadRecord` (11) -- with no `drop_size` write. A record
longer than one block (header + length > 32768) can therefore never
fit and always takes the `kBadRecordLen` arm.

**CRC check.** When `checksum_` (+0x28) is set: `expected =
crc32c::Unmask(DecodeFixed32(header))` -- the binary computes
`(stored - kMaskDelta) rol 15` (`lea r14d,[rax+0x5d7d1528]; rol
r14d,0xf`; 0x5d7d1528 is `-0xa282ead8` mod 2^32); `actual =
crc32c::Value(header + 6, length + header_size - 6)`, inlined as
`Extend(0, header + 6, length + header_size - 6)` through the
dispatch thunk at 0x61c25f0 (see below). On mismatch: `*drop_size =
buffer_.size()`, `buffer_.clear()`, return `kBadRecordChecksum` (15).
The covered range is the type byte, the recyclable log_num, and the
payload -- not the stored CRC or the length.

**The CRC dispatch.** 0x61c25f0 is a 16-byte `endbr64; jmp
[rip+0x34630e]` stub whose target slot 0x6508908 (.bss) is written
once by the tiny init stub at 0x61c26d0 (`lea rax, 0x61c21d0; mov
[0x6508908], rax; ret`). 0x61c21d0 is census-bound as
`rocksdb::crc32c::ExtendImpl<Slow_CRC32>` -- the slow table
implementation the slot holds in this binary.

**Raw result.** `buffer_.remove_prefix(header_size + length)`, then
if `!uncompress_` (+0x78) or type == `kSetCompressionType` (9):
`*result = Slice(header + header_size, length)`; return the type
(`r15d`, zero-extended -- a type byte >= 0x80 returns
sign-extended, e.g. 0xFFFFFF80 for 0x80). Type 9 is therefore never
decompressed: the caller needs the raw record to decode it.

**Decompress loop.** Otherwise: `uncompressed_record_.clear()` (size
0 at +0x90, data[0] = 0). If `fragment_checksum != nullptr`,
`uncompress_hash_state_` (+0xb0) is created lazily via
`XXH3_createState` (0x61dc410) when null, then `XXH3_64bits_reset`
(0x61dc480) runs every time. The `do-while` loop calls
`uncompress_->Uncompress(input, length, uncompressed_buffer_.get(),
&uncompressed_size)` through vtable slot 2 (`[rax+0x10]`): the input
is the payload on the first call and null afterwards, while the
length is passed unchanged on every call (the null-input resume rule
from #5972). `remaining < 0`: `buffer_.clear()`, return `kBadRecord`
(11). Produced bytes > 0: `XXH3_64bits_update` (0x61dc500) when
checksumming, then the `std::string` length check (produced >
max_size - current size throws `length_error
"basic_string::append"`, 0x4474d2) and `_M_append`. The loop runs
while `remaining != 0` or `produced == kBlockSize` (0x8000) -- a
full 0x8000-byte output forces another call even with nothing left.

**Digest check.** If `fragment_checksum != nullptr`:
`*fragment_checksum = XXH3_64bits_digest(state)` (0x61de260);
`actual = XXH3_64bits(uncompressed_record_.data(), size)` (0x61db650);
a mismatch returns `kBadRecord` (11) -- unreachable by construction,
since both digests cover exactly the appended bytes; the branch is
modelled and recorded. `*result = Slice(uncompressed_record_)`;
return the type.

**Findings (verified against the binary + upstream v8.1.1).**

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
- *Digest check is defensive:* the streamed digest and the
  recomputed `XXH3_64bits` cover exactly the same bytes, so the
  mismatch arm cannot fire in correct operation.
- *Drop-size discipline:* only the `kBadRecordLen` and
  `kBadRecordChecksum` paths write `*drop_size`; the zero-record and
  decompress-error paths clear the buffer without touching it.
- *Live engine check:* pure-Python CRC32C reproduces the standard
  `0xE3069283` vector for `"123456789"` and Mask/Unmask round-trip;
  libxxhash digests the empty input to the known
  `0x2d06800538d394c2`; a real ZSTD frame wrapped in a real WAL
  record (type 1, correct masked CRC) runs through the model with
  the real `Uncompress` shim and returns `kFullType` with the
  original payload and `fragment_checksum ==
  XXH3_64bits(payload)`.

**Caller census** (whole-.text E8/E9/LEA scan, Capstone-validated,
`census.py`): exactly 2 direct calls, 0 tail jumps, 0 LEA refs --
both inside `rocksdb::log::Reader::ReadRecord` 0x5f01f10..0x5f0294c
(at 0x5f01ff6 and 0x5f024f9; the compiler duplicated the loop body --
two jump tables at 0x9706e8 and 0x970728 dispatch on the return code;
both sites set `drop_size = 0`, pass the fragment Slice, `drop_size`
and `record_checksum`, and compute `physical_record_offset =
end_of_buffer_offset_ - buffer_.size()` first). Upstream shows one
`ReadPhysicalRecord` call per `ReadRecord` loop iteration; the
binary duplicates the loop body.

**Engine callees.** `ReadMore` 0x5f018d0 is census-confirmed (the
model takes its outcome as an input); `crc32c::Extend` is reached
through the 0x61c25f0 dispatch thunk to `ExtendImpl<Slow_CRC32>`
0x61c21d0 (census-confirmed); the XXH3 callees are census-confirmed
(`XXH3_createState` 0x61dc410, `XXH3_64bits_reset` 0x61dc480,
`XXH3_64bits_update` 0x61dc500, `XXH3_64bits_digest` 0x61de260,
`XXH3_64bits` 0x61db650); the PLT stubs (`_M_append`,
`__stack_chk_fail`, `__throw_length_error`) are pinned by their
relocation displacements (see `records.json`).

## Cases

2,400 deterministic cases in `cases.tsv`, generated by
`tools/log_reader_read_physical_record115.py` (`gen-cases`) and
replayed by `tests/test_log_reader_read_physical_record115.py` (36
tests pass):

- 600 header_parse (all 256 type bytes, length sweep 0..32761,
  impossible lengths 32762/40000/65535, zero-type arm, recyclable
  log_num match/mismatch, recycled flag set/unset, ReadMore refill
  and fail paths incl. two-refill sequences, trailing bytes) --
  the header parse, the recyclable gate, the length/zero arms, and
  the ReadMore loop.
- 600 crc (300 correct masked CRCs across types 1/2/4/5/8/9,
  lengths 0..1000 and payload patterns; 300 corrupted stored-CRC /
  payload / type bytes) -- the masked-CRC check and its failure
  arm.
- 600 decompress (single-shot, multi-chunk with remaining > 0,
  zero-produce steps, empty record, engine error on the first and
  second call, type-9 bypass, hash-state create/reuse, checksum-on
  decompress, recyclable types, one exact-kBlockSize continuation
  with a 0x8000-byte produce, pseudo-random fill) -- the decompress
  loop, the hash streaming, and the digest check.
- 600 bindings (body/source hashes, 16 relocation displacements,
  2 caller sites, 24 Reader layout fields, 10 constants, 8 upstream
  anchors, 256 type-classification rows, 100 stride-1 16-byte
  windows, 100 8-byte windows, 50 4-byte windows, 32 single-byte
  rows over the first 100 bytes of the 1101-byte FDE).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool models the routine in Python; `ReadMore` and
`StreamingUncompress::Uncompress` are taken as inputs, and the live
engine check drives the real engines only through the system
libxxhash.so.0 and libzstd.so.1 (1.5.5) via ctypes (plus a
pure-Python CRC32C validated against the standard vector).
`make verify/test/catalogue-check` in a tooled environment is still
owed upstream.

## Unknowns

- `ReadMore`'s body (0x5f018d0, 352 B, census-bound) is NOT modelled
  here -- only its true/false outcome and its `r`/`drop_size`
  writes are inputs. A follow-up packet can reconstruct it (it is
  the next reader-side routine).
- Why the compiler duplicated the `ReadRecord` loop body (two
  identical `ReadPhysicalRecord` call sites at 0x5f01ff6 and
  0x5f024f9 with two jump tables): both sites are pinned, but the
  dispatch reason was not traced.
- Whether the `Reader`'s other members (the `0xf0`-byte total, the
  `UnorderedMap` at +0xb8) are exactly as derived: only the ten
  pinned fields (+0x28/+0x38/+0x60/+0x68/+0x70/+0x78/+0x80/+0x88/
  +0x90/+0xb0) are observed in this FDE; the rest follows the header
  order with natural alignment.
- Whether `IsFastCrc32Supported` (0x61c2400) would select a different
  `Extend` implementation on another CPU: this packet pins the slow
  implementation the dispatch slot holds in this binary; the
  selection itself is not modelled.
