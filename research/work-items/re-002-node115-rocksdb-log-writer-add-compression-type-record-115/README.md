# RE-002 · Node #115 RocksDB log::Writer::AddCompressionTypeRecord

Component: storage / WAL / compression. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 arm a fresh WAL writer for compression -- what does
`log::Writer::AddCompressionTypeRecord` emit as the first record, when
does it skip the work, how does it build the streaming compressor and
its output buffer, and who calls it? Both functions are census-bound
(body hash matches the vendor census `target_body_sha256` exactly;
source hash reproduced by zeroing the recorded relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::log::Writer::AddCompressionTypeRecord` | 0x5f041d0..0x5f0441c | 588 | `4908b432baec467a497cda1dae218bbe3633b974594d5b42296f7c5429cd9d45` |
| `rocksdb::log::Writer::AddCompressionTypeRecord.cold` | 0x5f04190..0x5f041c4 | 52 | `714b44cdc044d0beb9a7d788b23de3f75749941fd991e26448e7bf276edc8bb4` |

Scope note: merged RE-001-zstd-compress-cache-115 first pinned this
routine at census level as its "refresh" record (547/588 bytes, the
objdump excerpt, the one caller) but modelled neither the body nor the
Flush path, the status-copy byte rules, the .cold pad, or the old-value
handling. This packet supersedes that record with the full body model,
2,400 cases and the upstream cross-check, and corrects two of its
claims (see below). The three callees are cited, not re-claimed:
`EmitPhysicalRecord` 0x5f03b80, `WritableFileWriter::Flush` 0x6051a20
and `StreamingCompress::Create` 0x61c1c10 (fully reconstructed in the
merged cache packet).

## Answer (pinned)

**Signature.** `IOStatus AddCompressionTypeRecord()` returns by value,
so `rdi` is the hidden 16-byte sret out-pointer and `rsi` is the
`Writer*`. It is the first record a fresh WAL writer emits, called
once by `DBImpl::CreateWAL` right after the Writer is constructed.

**Writer layout** (node #115, from the field accesses, confirmed
against upstream `db/log_writer.h`): `dest_` +0x00,
`block_offset_` +0x08, `log_number_` +0x10, `recycle_log_files_`
+0x18, `type_crc_[10]` +0x1c..+0x44, `manual_flush_` +0x44,
`compression_type_` +0x45, `compress_` +0x48,
`compressed_buffer_` +0x50; total 0x58.

**Gate (type == 0).** If `compression_type_` (this+0x45) is
`kNoCompression` (0), the routine zeroes 16 bytes at the
out-pointer (bytes 0-3, 4-5, 8-15; bytes 6-7 are NOT written) and
returns at once. No record is emitted, no compressor is installed.

**Encode.** `CompressionTypeRecord(compression_type_)` is appended to
an empty SSO `std::string` `encode` as 4 little-endian bytes
(`PutFixed32`, upstream `util/compression.h:3108-3114`).

**Emit.** `EmitPhysicalRecord(type 9 = kSetCompressionType,
encode.data(), 4, IO_TOTAL = 4)` at 0x5f04294. On emit failure
(status code != 0) `compression_type_` is cleared to 0 and the emit
status is returned; nothing is installed.

**Flush.** On emit OK with `manual_flush_` (this+0x44) == 0,
`dest_->Flush()` (`WritableFileWriter::Flush`, 0x6051a20) runs and its
status moves into `s` (the old emit status's heap `state_` is
`delete[]`'d when non-null). With `manual_flush_` != 0 the Flush is
skipped.

**Install -- regardless of the Flush result.** The binary does not
re-check the status after the Flush: it builds the 48-byte default
`CompressionOptions` template and calls `StreamingCompress::Create
(type, template, version 2, max_len)` at 0x61c1c10, where `max_len`
is `0x8000 - header` = 0x7ff9 (legacy, `recycle` == 0) or 0x7ff5
(recyclable, `recycle` == 1). The product is installed at this+0x48
(`compress_`); a fresh buffer of `max_len` bytes is `new[]`'d and
stored at this+0x50 (`compressed_buffer_`), `delete[]`ing the
previous buffer when non-null. A previous `compress_` is overwritten
without a delete (a leak on re-entry; the routine is designed to run
once, on a fresh Writer).

**Return.** The final 16-byte status is copied into the out-pointer:
bytes 0-1, 3-4, 5, 8-15 copied, byte 2 forced to 0, bytes 6-7 NOT
written. The `encode` string is destroyed (sized delete of the heap
buffer when it is not the SSO buffer), the stack canary is checked,
and the out-pointer is returned.

**The 48-byte template** (upstream default `CompressionOptions`,
`advanced_options.h:366-384`): `window_bits` -14, `level` 32767
(`kDefaultCompressionLevel`), `strategy` 0, `max_dict_bytes` 0,
`zstd_max_train_bytes` 0, `parallel_threads` 1, `enabled` false,
`max_dict_buffer_bytes` 0, `use_zstd_dict_trainer` true. As qwords:
+0x00 = `0x00007ffffffffff2` (one load from the .rodata pair at
0x459aa0), +0x08 = 0, +0x10 = `0x100000000`, +0x18 = 0, +0x20 = 0,
byte +0x28 = 1. The tail padding +0x29..+0x2f is NEVER written.

**The .cold landing pad** (0x5f04190, entered from the two `endbr64`
stubs at 0x5f04404 / 0x5f04410): entry 0x5f04190 `delete[]`s the
status `state_` at [rsp+8] when non-null, then disposes the `encode`
string; entry 0x5f0419f disposes the string only. Both check the
canary and `_Unwind_Resume` with the exception object saved in `rbx`.

**Findings (verified against the binary + upstream v8.1.1).**

- *Flush-failure-still-installs:* after `dest_->Flush()` the binary
  jumps straight to the Create section without re-checking the
  status code. Upstream checks `s.ok()` once, before the Flush, and
  the init block runs unconditionally inside it -- so a failed Flush
  still installs the compressor and the buffer, and the returned
  status is the Flush error.
- *Status byte rules, explained:* the returned status is `IOStatus`
  (`Status` layout code@0, subcode@1, `sev_`@2, `retryable`@3,
  `data_loss`@4, `scope`@5, `state_`@8). The final copy zeroes byte 2
  because `IOStatus`'s copy-ctor builds from `Status(code, subcode)`,
  which initializes `sev_` to `kNoError` (`io_status.h:311`,
  `status.h:866-878`). The Flush move does not touch byte 2 because
  `IOStatus`'s move-assignment does not mention `sev_`
  (`io_status.h:371-405`); its source resets (bytes 0-1 to
  `kOk`/`kNone`, byte 5 to `kIOErrorScopeFileSystem` = 0, bytes 8-15
  moved) match the binary's move instruction for instruction. Bytes
  6-7 are padding, never written by this routine.
- *State_ transfer:* the return copy moves the `state_` pointer with
  a plain 8-byte move (no `CopyState` call in the body); the stack
  slot's `state_` is not freed afterwards in this function.
- *Two corrections to the merged packet:* the template's first qword
  is (-14, 32767), not (-14, INT_MAX) -- the high int32 is
  `0x00007fff` = 32767 = `kDefaultCompressionLevel`; and 0x6051a20 is
  `WritableFileWriter::Flush` (census-confirmed, 2908 B), not a
  "shared 4-byte copy helper".
- *No block_offset_ check:* the binary never reads this+0x08, so the
  upstream `assert(block_offset_ == 0)` is compiled out -- a caller
  could invoke the routine mid-block and it would still emit the
  type-9 record.
- *Live engine check:* a real CCtx created through the system
  libzstd takes parameter 201 -> 1 (the checksum flag the factory
  sets) and resets with directive 1; `ZSTD_CCtx_setParameter`
  echoes the set value (1) on success, which is not an error.

**Caller census** (whole-.text E8/E9/LEA scan, Capstone-validated,
`census.py`): exactly 1 direct call at 0x5e5c5a3 inside
`rocksdb::DBImpl::CreateWAL` 0x5e5c270..0x5e5c9a3, and exactly 1 tail
jump to the .cold block at 0x5f0440b. No tail jumps or LEA refs to
0x5f041d0.

**Engine callees.** `EmitPhysicalRecord` 0x5f03b80 and
`WritableFileWriter::Flush` 0x6051a20 and
`StreamingCompress::Create` 0x61c1c10 are census-confirmed; the PLT
stubs (`_M_append`, `operator new[]`/`delete[]`/sized delete,
`_M_dispose`, `_Unwind_Resume`, `__stack_chk_fail`) are pinned by
their relocation displacements (see `records.json`).

## Cases

2,400 deterministic cases in `cases.tsv`, generated by
`tools/log_writer_add_compression_type_record115.py` (`gen-cases`)
and replayed by
`tests/test_log_writer_add_compression_type_record115.py` (18 tests pass):

- 600 gate+encode (all 256 type bytes twice with manual/recycle
  variation, plus the 10 named `CompressionType` values) -- the gate,
  the 4-byte `PutFixed32` encode, and gate independence from the
  other Writer flags.
- 600 emit+flush (emit codes 0/1/2/3/5/13 x manual_flush 0/1 x
  recycle 0/1 x flush codes 0/1/2/4, with subcode/flag/state
  variation) -- the emit-failure path, the Flush skip/call, the
  status move, and the flush-failure-still-installs rule.
- 600 create+install (10 named types x manual/recycle x old buffer
  null/present x old compress_ null/present) -- the kind-7-only
  Create gate, the 0x7ff5/0x7ff9 buffer sizes, the old-buffer delete
  and the old-compress_ leak.
- 600 bindings (body/source hashes, 17 relocation displacements,
  template qwords/bytes, 10 Writer layout fields, 3 caller sites, 2
  max_output_len values, 8 upstream anchors, 549 stride-1 16-byte
  windows over both FDEs).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool models the routine in Python; the three external
calls are taken as inputs, and the live engine check drives the real
ZSTD engine only through the system libzstd.so.1 (1.5.5) via ctypes.
`make verify/test/catalogue-check` in a tooled environment is still
owed upstream.

## Unknowns

- `EmitPhysicalRecord`'s body (0x5f03b80) and `WritableFileWriter::
  Flush`'s body (0x6051a20, 2908 B) are census-bound but not modelled
  here -- only their status results are inputs to the model.
- Whether any caller other than `DBImpl::CreateWAL` can reach this
  routine with a non-fresh Writer (re-entry with a live compress_/
  buffer): the census finds exactly one caller, so the leak/delete
  branches are modelled but not observed live.
- Whether the returned status's bytes 6-7 (padding) ever matter to a
  caller: the one caller moves a 16-byte status in its frame right
  after the call (sequence at 0x5e5c5a8); the exact slot and whether
  bytes 6-7 are read were not fully traced.
- The exact .cold entry-point selection (which exception region uses
  stub 1 at 0x5f04404 vs stub 2 at 0x5f04410): both stubs and both
  entries are pinned, but the LSDA region mapping was not decoded.
