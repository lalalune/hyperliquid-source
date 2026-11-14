# RE-002 · Node #115 RocksDB log::FragmentBufferedReader::ReadRecord

Component: storage / WAL / log reading. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 turn the fragments its fragment-buffered WAL
reader fetches into one logical record -- how does
`log::FragmentBufferedReader::ReadRecord` loop over `TryReadFragment`,
dispatch the fragment code through its jump table, reassemble
fragmented records, handle the `SetCompressionType` record, and when
does it return false? The function is census-bound (body hash matches
the vendor census `target_body_sha256` exactly; source hash reproduced
by zeroing the recorded relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::log::FragmentBufferedReader::ReadRecord` | 0x5f02f20..0x5f034f2 | 1490 | `851bfd41f5a00fd7bd4cc448bcc678c2c15604f16c6c639169bb6688fffde7c1` |

Scope note: this is the caller of `TryReadFragment` (PR #5994,
0x5f02b40, the only routine this packet's target calls to fetch
fragments -- the call at 0x5f02fdc) and of `InitCompression` (PR
#5979, 0x5f01e80, called at 0x5f033ac). `TryReadMore` (PR #5995,
0x5f02980) and the ZSTD streaming `Uncompress` engine (#5972) are
inputs to the model, not re-claimed. ReadRecord itself has no direct
call site in the binary: it is virtual, reached only through the
Reader vtable.

## Answer (pinned)

**Signature.** `bool ReadRecord(Slice* record, std::string* scratch,
WALRecoveryMode /*unused*/, uint64_t* /* checksum */)` -- `rdi` is
the `FragmentBufferedReader*` (rbx), `rsi` the record Slice*, `rdx`
the scratch string*. The 3rd (`rcx`) and 4th (`r8`) parameters are
present but UNREFERENCED: neither is saved in the prologue nor read
anywhere in the 1490-byte body. Upstream names them
`WALRecoveryMode /*unused*/` and `uint64_t* /* checksum */`
(`db/log_reader.cc:1092-1094`); the base `Reader::ReadRecord`
(0x5f01f10, lines 128-570) uses them, this override does not.

**Prologue.** `*record = Slice{0x4376fd, 0}` (the empty-string
literal at 0x4376fd, verified 0x00); `scratch->clear()`; if
`uncompress_` (+0x78) is non-null, `uncompress_->Reset()` (vtable
slot 3, at 0x5f02f7f) once; `physical_record_offset =
end_of_buffer_offset_ - buffer_.size()` computed ONCE from entry-time
state; `drop_size = 0`, `fragment_type_or_err = 0`, `fragment` = empty
Slice, `saved_first_offset = 0`.

**Loop.** `TryReadFragment(&fragment, &drop_size,
&fragment_type_or_err)` (0x5f02b40, at 0x5f02fdc) once per iteration;
a false return ends the call at once with `false` and no report.
Otherwise the code dispatches through the jump table at 0x970768
(unsigned compare, `> 15` goes to the default handler):

- **Codes 1, 5 -- kFullType** (0x5f03140): if
  `in_fragmented_record_` AND `fragments_` is non-empty,
  `ReportCorruption(fragments_.size(), "partial record without
  end(1)")`; `fragments_.clear()` unconditionally; `*record =
  fragment`; `first_record_read_ = true`; `in_fragmented_record_ =
  false`; `last_record_offset_ = physical_record_offset`; return
  `true`.
- **Codes 2, 6 -- kFirstType** (0x5f030f0): if
  `in_fragmented_record_` OR `fragments_` is non-empty,
  `ReportCorruption(fragments_.size(), "partial record without
  end(2)")`; `fragments_.replace(0, fragments_.size(), fragment)`;
  `in_fragmented_record_ = true`; `saved_first_offset =
  physical_record_offset`; loop.
- **Codes 3, 7 -- kMiddleType** (0x5f030a0): if not in a fragmented
  record, `ReportCorruption(fragment.size(), "missing start of
  fragmented record(1)")` and loop; else the length check
  (`fragment.size() > 0x3fffffffffffffff - fragments_.size()`
  throws `std::length_error` "basic_string::append"),
  `fragments_.append(fragment)`, loop.
- **Codes 4, 8 -- kLastType** (0x5f03070): if not in a fragmented
  record, `ReportCorruption(fragment.size(), "missing start of
  fragmented record(2)")` and loop; else the same length check,
  append, `scratch->replace(0, scratch->size(), fragments_.data(),
  fragments_.size())`, `*record = Slice(scratch)`,
  `fragments_.clear()`, `physical_record_offset =
  saved_first_offset`, `last_record_offset_ =
  physical_record_offset`, `first_record_read_ = true`,
  `in_fragmented_record_ = false`, return `true`.
- **Code 9 -- kSetCompressionType** (0x5f031b8): if
  `compression_type_record_read_` (+0x73),
  `ReportCorruption(fragment.size(), "read multiple
  SetCompressionType records")` and continue; if
  `first_record_read_`, `ReportCorruption(fragment.size(),
  "SetCompressionType not the first record")` and continue;
  `fragments_.clear()`; `last_record_offset_ =
  physical_record_offset`; `in_fragmented_record_ = false`; type
  byte = 0. If `fragment.size() <= 3`: `Status(Corruption,
  "CompressionTypeRecord: Error decoding WAL compression type")`
  via the 5-arg Status ctor 0x61cf670 (code 2, subcode 0, severity
  0) -> `ReportCorruption(fragment.size(), "could not decode
  SetCompressionType record")`, delete the status state_,
  `saved_first_offset = physical`, loop. Else read the LE32 at
  `fragment.data()` as the type and strip 4 bytes (the rest is
  ignored); type 0 or 7 (LOW byte only) -> status OK,
  `InitCompression(type)` (0x5f01e80; #5979), `saved_first_offset
  = physical`, loop; any other type -> `Status(Corruption,
  "CompressionTypeRecord: WAL compression type not supported")` ->
  `ReportCorruption(fragment.size()` AFTER the 4-byte strip,
  `"could not decode SetCompressionType record")`, delete the
  state_, `saved_first_offset = physical`, loop. The `"code == 0"`
  branch after the Status ctor is dead in practice: the ctor always
  writes code 2.
- **Codes 10, 11, 12, 13 -- kEof / kBadRecord / kBadHeader /
  kOldRecord** (shared entry 0x5f0302e): if in a fragmented record,
  `ReportCorruption(fragments_.size(), "error in middle of
  record")`, `fragments_.clear()`, `in_fragmented_record_ =
  false`, loop; else loop with no report.
- **Code 15 -- kBadRecordChecksum** (0x5f03010): if `recycled_`
  (+0x70), `fragments_.clear()` and return `false` --
  `in_fragmented_record_` is NOT cleared on this path; else
  `ReportCorruption(drop_size, "checksum mismatch")`, then the
  same handling as the 10-13 group.
- **Codes 0, 14, and any > 15 -- default** (0x5f032f0):
  `snprintf` `"unknown record type %u"` (0x441a65) into a 40-byte
  stack buffer, `ReportCorruption(fragment.size() +
  (in_fragmented_record_ ? fragments_.size() : 0), buf)`,
  `fragments_.clear()` unconditionally, `in_fragmented_record_ =
  false`, loop.

The landing pad at 0x5f034e6 (`endbr64; mov %rax,%rbx; jmp
0x5f02ee6`) is shared exception cleanup with TryReadFragment's FDE
end.

## Layout (pinned)

`FragmentBufferedReader` (node #115; the Reader base ends at +0xb8
in this v8.1.1-based build -- there is NO `recorded_cf_to_ts_sz_`
member, so `fragments_` is the first FragmentBufferedReader member):
`vptr` +0x00, `info_log_` +0x08 (16), `file_` +0x18, `reporter_`
+0x20, `checksum_` +0x28, `backing_store_` +0x30, `buffer_` (Slice)
+0x38 (16), `eof_` +0x48, `read_error_` +0x49, `eof_offset_` +0x50,
`last_record_offset_` +0x58, `end_of_buffer_offset_` +0x60,
`log_number_` +0x68, `recycled_` +0x70, `first_record_read_` +0x71,
`compression_type_` +0x72, `compression_type_record_read_` +0x73,
`uncompress_` (StreamingUncompress*) +0x78, `uncompressed_buffer_`
+0x80, `uncompressed_record_` (std::string) +0x88 (32),
`hash_state_` +0xa8, `uncompress_hash_state_` +0xb0, `fragments_`
(std::string) +0xb8 (32), `in_fragmented_record_` +0xd8 (1). Total
0xe0 (0xd9 rounded up to the 8-byte alignment).

**Layout correction.** PR #5982 put `recorded_cf_to_ts_sz_` at
+0xb8 (total 0xf0); that member comes from a NEWER `log_reader.h`
member order and does NOT apply here (`db/log_reader.h:205-231` in
v8.1.1 has no such field). This packet corrects #5982 and resolves
#5994's open unknown ("where fragments_ lives") by the inheritance
argument: the base `Reader::ReadRecord` FDE (0x5f01f10) never touches
+0xb8/+0xd8 (it keeps assembly state in stack locals), consistent
with `fragments_`/`in_fragmented_record_` being
FragmentBufferedReader-only members.

## Quirks worth knowing

- `last_record_offset_` is the ENTRY-time offset. Because
  `physical_record_offset` is computed once before the loop, a
  `SetCompressionType` record that precedes the returned record in
  the same call leaves `last_record_offset_` pointing at the
  `SetCompressionType` record, not at the returned record.
  Upstream `log_reader.cc:1115` computes it the same way, once.
- The recycled checksum arm is asymmetric: `recycled_` returns
  `false` with `fragments_` cleared but `in_fragmented_record_`
  left set -- the flag survives into the next call. The
  non-recycled arm reports and takes the eof-group handling, which
  DOES clear the flag.
- The `compression_type_record_read_` flag is set ONLY inside
  `InitCompression`: a failed `SetCompressionType` record (short
  fragment or unsupported type) does not mark it, so a later valid
  record is still accepted with no "multiple" report. The
  "multiple" and "not the first record" reports do NOT stop the
  record from being processed -- both paths fall through to the
  decode and `InitCompression`.
- The compression-type gate reads only the LOW byte
  (`CompressionType` is `enum : unsigned char`): a u32 of 0x100
  installs type 0, 0x107 installs type 7.
- The report size on a decode error is the fragment size AFTER the
  4-byte strip for an unsupported type, but the fragment's own size
  for a short fragment (the strip at 0x5f03225-0x5f0322f writes the
  post-strip size back before the report; the short-fragment path
  branches before the strip).

## Upstream confirmation

Read live this cycle from facebook/rocksdb v8.1.1:
`db/log_reader.cc:1092-1344` (FragmentBufferedReader::ReadRecord,
step for step), `db/log_reader.h:205-404` (member order; no
`recorded_cf_to_ts_sz_`), `db/log_reader.h:284-316` (RecordType
enum), `util/compression.h:3117-3146` (DecodeFrom), `util/
compression.h:1007-1027` (StreamingCompressionTypeSupported: only 0
and 7), `include/rocksdb/compression_type.h:27` (the unsigned-char
enum), `db/log_format.h:34-84` (RecordType enum, kBlockSize 32768,
kHeaderSize 7, kRecyclableHeaderSize 11). Wording-level differences
only: upstream uses `assign` where the binary uses `_M_replace`
(kFirstType/kLastType -- same bytes); the Status ctor is inlined in
the binary as the 5-arg ctor call 0x61cf670.

## Verification

- `python3 tools/fragment_buffered_reader_read_record115.py gen-cases`
  -- 2,400 cases in `cases.tsv` (600 dispatch / 600 assembly / 600
  compression / 600 bindings; 0 UNKNOWN reloc targets).
- `python3 -m pytest
  tests/test_fragment_buffered_reader_read_record115.py` -- 37 tests
  (replay of all 2,400 cases plus direct behaviour tests).
- `python3 tools/fragment_buffered_reader_read_record115.py
  live-engine-check` -- a real WAL file (SetCompressionType type 0,
  a full record, a fragmented first/middle/last record, a
  corrupt-CRC record, a padding record filling block 1 to exactly
  0x8000 bytes, and a final full record in block 2) read through the
  model: four ReadRecord calls return the full record, the
  reassembled fragmented record, the record after the corrupt one
  (with a checksum-mismatch report on the way), and False at EOF.
  The padding matters: a CRC failure clears the whole buffered
  block (TryReadFragment, #5994), so the record after the corrupt
  one must live in a later block to survive.
- `python3 tools/verify_packets.py` -- only the pre-existing
  mismatch in the unrelated packet RE-001-adjacent-last-115
  (present on clean upstream main, untouched by this change).

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM. The
target binary is never executed. `make verify/test/catalogue-check`
in a tooled environment is still owed upstream.

## Open unknowns

- `ReportCorruption` 0x5f015c0: the exact reporter null-guard and
  vtable slot for the `reporter_->Corruption(bytes, status)` call
  are not pinned (only the `Status(kCorruption)` construction from
  the reason string is decoded).
- The exact vtable slot of `ReadRecord` itself is not pinned -- the
  caller census found no static call site, and the vtable layout is
  not recovered in this packet.
- The `length_error` throw in the middle/last arms: the guard and
  the "basic_string::append" message are pinned, but the throw's
  runtime target is not.
- The `uncompress_->Reset()` vtable call (slot 3): the callee is
  whichever streaming uncompress product `InitCompression`
  installed; its body is not modelled here.

## Files

| file | contents |
|---|---|
| `read-record-5f02f20.hex` | raw FDE bytes (1490 B, one lowercase hex line) |
| `read-record-5f02f20.objdump.txt` | whole FDE, verbatim objdump (Intel syntax) |
| `functions.tsv` | function row: body/source hashes, 37 relocations, census id |
| `records.json` | semantic records (model, layout, dispatch, census, cases, callees, observations, unknowns) |
| `cases.tsv` | 2,400 cases |
| `census.py` / `census.json` / `callers.tsv` | caller census (0 direct calls, 0 jumps, 0 LEA refs) |
| `gen_records.py` | regenerates `functions.tsv` from the binary + census |
| `gen_records_json.py` | regenerates `records.json` from `functions.tsv` + `cases.tsv` |
| `export_excerpts.py` | regenerates the `.hex` / `.objdump.txt` from the binary |
| `MANIFEST.sha256` | SHA-256 of every file in this packet |
