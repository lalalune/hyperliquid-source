# RE-002 · Node #115 RocksDB log::Writer::EmitPhysicalRecord

Component: storage / WAL. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 write one physical WAL record -- what header does
`log::Writer::EmitPhysicalRecord` build, how is the CRC computed, what
does it hand to the file writer, and who calls it? Both functions are
census-bound (body hash matches the vendor census
`target_body_sha256` exactly; source hash reproduced by zeroing the
recorded relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::log::Writer::EmitPhysicalRecord` | 0x5f03b80..0x5f03d26 | 422 | `f82927be6afb1e677d0cd26f44020f7973672cc1f5f05b92495fa9469a41bcc5` |
| `rocksdb::log::Writer::EmitPhysicalRecord.cold` | 0x5f03b50..0x5f03b7b | 43 | `60c6dbfbbdb2a6e95a79122d5de806e56274ef09cb06fe810147da0a406f20cf` |

Scope note: merged RE-001-zstd-compress-cache-115 first pinned this
routine at census level as a caller entry (catalogue
`EmitPhysicalRecord`, 394/422 non-relocation bytes) and the merged
AddCompressionTypeRecord packet (PR #5976) takes its status as the
emit result, but neither modelled the body. This packet supersedes
both records with the full body model, 2,400 cases and the upstream
cross-check. The callees are cited, not re-claimed:
`crc32c::Extend` (thunk 0x61c25f0), `crc32c::Crc32cCombine` 0x61c2600
(both fully reconstructed in merged
RE-002-node115-crc32c-extend-combine-115) and
`WritableFileWriter::Append` 0x6054680 (input oracle here; its body
is the natural follow-up).

## Answer (pinned)

**Signature.** `IOStatus EmitPhysicalRecord(RecordType type, const
char* ptr, size_t length, IOPriority io_priority)` returns by value,
so `rdi` is the hidden 16-byte sret out-pointer, `rsi` is the
`Writer*`, `edx` the type, `rcx` the payload pointer, `r8` the
length, `r9d` the priority. It is the single choke point for
physical-record emission: every physical record the node writes goes
through one of its two call sites.

**Writer layout** (node #115, from the field accesses, confirmed
against upstream `db/log_writer.h`): `dest_` +0x00,
`block_offset_` +0x08, `log_number_` +0x10, `recycle_log_files_`
+0x18, `type_crc_[10]` +0x1c..+0x44, `manual_flush_` +0x44,
`compression_type_` +0x45, `compress_` +0x48,
`compressed_buffer_` +0x50; total 0x58. `type_crc_[i]` is
`crc32c::Value` of the single byte `i` (ctor, upstream
`log_writer.cc:59-65`).

**Seed, then gate.** `type_crc_[type]` (this+0x1c +
4\*sign_extend(type)) is loaded BEFORE the gate. The gate is legacy
iff `(int32)type <= 4` OR `type == 9` (`kSetCompressionType`);
otherwise recyclable. Upstream `db/log_writer.cc` (v8.1.1):
`if (t < kRecyclableFullType || t == kSetCompressionType)` -- the
same gate, since `kRecyclableFullType` is 5.

**Recyclable arm.** `header_size` is 11 (`kRecyclableHeaderSize`);
the low 32 bits of `log_number_` (this+0x10) are stored at `buf+7`
and the seed becomes `Extend(seed, buf+7, 4)` via the 16-byte Extend
thunk at 0x61c25f0. Legacy arm: `header_size` is 7
(`kHeaderSize`), no log number.

**CRC chain.** `payload_crc = Extend(0, ptr, length)` (i.e.
`crc32c::Value`) via the same thunk, then `crc =
Crc32cCombine(seed, payload_crc, length)` at 0x61c2600. By the
combine identity this equals the CRC of (type byte [+ log_number
LE32] + payload). Then `masked = ror(crc, 15) + 0xa282ead8`
(`crc32c::Mask`; the binary does `ror $0xf` then `sub $0x5d7d1528`,
and `0x5d7d1528 == -0xa282ead8 mod 2^32`).

**Header.** `[masked CRC LE32][length LE16][type byte][log_number
LE32 if recyclable]`, built at `rsp+0x3d`. The length is stored
truncated to 16 bits (`mov %r8w`); the `n <= 0xffff` assert from
upstream is compiled out.

**Header Append.** `dest_->Append(Slice(buf, header_size), 0,
priority)` at 0x5f03c2a -- `dest_` is this+0x00
(`unique_ptr<WritableFileWriter>`), the callee is
`WritableFileWriter::Append(const Slice&, uint32_t crc32c_checksum,
IOPriority)` at 0x6054680. The result is written DIRECTLY into the
caller's sret slot (`rbp`). The crc argument is 0 for the header.

**Failure arm.** If the header Append failed (status byte 0 != 0),
the payload Append is skipped entirely; `block_offset_ +=
header_size + length` anyway (0x5f03c35) and the header status is
returned.

**Payload Append.** On header success,
`dest_->Append(Slice(ptr, length), payload_crc, priority)` at
0x5f03cae, result into a 16-byte stack slot at `rsp+0x20`; then a
move-assign copies that slot into the sret: bytes 0-1, 3-4, 5 and
8-15 are copied, byte 2 (`sev_`) and bytes 6-7 (padding) are NOT
copied (they keep the header status's values), and the header
status's heap `state_` is `delete[]`'d when non-null. The payload
Append passes the payload CRC as its checksum argument -- the writer
checksums the payload, not the header.

**Return.** `block_offset_` (this+0x08) `+= header_size + length`
UNCONDITIONALLY (both Append arms join at 0x5f03c35), and the sret
pointer is returned. No Flush is called here (upstream
`log_writer.cc:443-457` agrees: the Flush lives in `AddRecord` /
`AddCompressionTypeRecord`, not in `EmitPhysicalRecord`).
`TEST_SYNC_POINT_CALLBACK` (upstream `log_writer.cc:436-438`) is
compiled out: no call sits between the Mask and the header store.

**The .cold landing pad** (0x5f03b50, entered from the `endbr64`
stub at 0x5f03d1a, which the FDE's LSDA reaches on unwind and which
saves the exception object in `rbx` first): `delete[]`s the sret
status's `state_` at [rbp+8] when non-null, checks the stack canary,
then `_Unwind_Resume` with `rbx`, or `__stack_chk_fail`. It is
unwind-only; no case exercises it.

**Findings (verified against the binary + upstream v8.1.1).**

- *Value + Combine, not a single Extend:* the payload CRC is
  computed separately (`Extend(0, ptr, n)`) and then combined with
  the type seed. All 600 `crc_combine` cases pin the equality with a
  direct Extend over the concatenated bytes, and the 100
  combine-identity binding rows re-verify it.
- *Length truncation:* the upstream `assert(n <= 0xffff)` is
  compiled out, so the header stores only the low 16 bits of the
  length while the CRC covers the full payload. Pinned by the two
  0x10000/0x10001 `header_build` rows (header length 0/1, CRC over
  the full 64 KiB payload). `AddRecord` never passes more than
  0x7ff9, so this is a latent quirk, not a live path.
- *Log-number truncation:* only the low 32 bits of the 64-bit
  `log_number_` are stored, so two log numbers 2^32 apart produce
  identical recyclable headers. Pinned by the 0x100000000 /
  0x123456789 log-number rows.
- *Append checksum args:* the header Append passes crc arg 0 and
  the payload Append passes `payload_crc` -- the writer checksums
  the payload, not the header. This matches upstream
  `log_writer.cc:445-451` exactly, including the `0 /*
  crc32c_checksum */` comment on the header call.
- *Status move byte rules:* the second Append's result is
  move-assigned into the sret, copying bytes 0-1, 3-4, 5, 8-15 and
  preserving byte 2 (`sev_`, `status.h:841-857`) and bytes 6-7
  (padding) from the header status. The old header `state_` is
  `delete[]`'d when non-null. The second `delete[]` in the epilogue
  (0x5f03d0b) is dead code -- its slot (`rsp+0x28`) was just zeroed
  by the move.
- *First Append writes into the sret directly:* that is why the move
  preserves byte 2 / bytes 6-7 -- they are the first Append's bytes,
  and the Append callee's error path writes bytes 0-3, 4-5, 8-15 but
  never bytes 6-7.
- *Live engine check:* the model wrote a real WAL file (legacy full
  record, recyclable full record with log_number 0x12345678, type-9
  record) and parsed it back independently -- all three stored CRCs
  verify and all 56 bytes are consumed; `block_offset_` ends at 56.

**Caller census** (whole-.text E8/E9/LEA scan, Capstone-validated,
`census.py`): exactly 2 direct calls -- `AddRecord` 0x5f03ee3
(FDE 0x5f03d60..0x5f0418f, the fragment loop) and
`AddCompressionTypeRecord` 0x5f04294 (FDE 0x5f041d0..0x5f0441c);
0 jumps, 0 LEA refs. The .cold has exactly 1 tail jump, from
0x5f03d21 inside the main FDE.

**Engine callees.** `crc32c::Extend` thunk 0x61c25f0 and
`crc32c::Crc32cCombine` 0x61c2600 are census-bound (reconstructed in
merged RE-002-node115-crc32c-extend-combine-115);
`WritableFileWriter::Append` 0x6054680 is FDE-pinned (its .cold at
0x6054600..0x605467c is census-bound and pins the symbol); the PLT
stubs (`_Unwind_Resume`, `__stack_chk_fail`, `operator delete[]`)
are pinned by their relocation displacements (see `records.json`).

## Cases

2,400 deterministic cases in `cases.tsv`, generated by
`tools/log_writer_emit_physical_record115.py` (`--gen-cases`)
and replayed by
`tests/test_log_writer_emit_physical_record115.py` (25 tests pass):

- 600 header_build (types 0..9 x 8 log_numbers x 10 lengths incl.
  0x7ff9/0x8000/0xffff, plus two length-truncation rows at
  0x10000/0x10001) -- the header layout, the gate, the log-number
  truncation, and the unconditional `block_offset_` advance.
- 600 crc_combine (check vector "123456789" -> 0xE3069283, mask
  round-trips, Value+Combine+Mask chains across types/log_numbers/
  payloads 0..32 B, each cross-checked against a direct Extend over
  the concatenated bytes) -- the CRC chain and the combine identity.
- 600 append_flow (header codes 0/1/2/5/13 x payload codes 0/1/2/5 x
  priorities 0..4 x subcode/flag/b2/b67/state variation) -- the
  skip-payload-on-header-failure rule, the crc-arg values (0 vs
  payload_crc), the status-move byte rules, and the old-state free.
- 600 bindings (body/source hashes, 12 relocation displacements, 3
  call/jump sites, caller census, gate decisions for types 0..15,
  10 `type_crc_` seeds, 10 Mask values, 8 Writer offsets, 4 FDE
  ranges, 100 combine-identity rows, header-layout rows to 600).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool models the routine in Python; the two Append
calls are taken as inputs through a scripted oracle, and the live
engine check writes a real WAL file with the model and parses it
back with independent header/CRC verification.
`make verify/test/catalogue-check` in a tooled environment is still
owed upstream.

## Unknowns

- `WritableFileWriter::Append`'s body (0x6054680..0x605518b, 2827 B)
  is not reconstructed here -- only its contract is an input. Its
  buffering, rate-limiter interaction, checksum-generator update,
  IOOptions handling and the exact meaning of the byte at this+0x89
  (previous-error flag) are unpinned. Its full body is the natural
  follow-up packet.
- Types outside 0..9 (10..15, negatives): the binary takes the
  recyclable arm and loads `type_crc_[type]` past the 10-entry array,
  reading `manual_flush_`/`compression_type_`/`compress_` bytes as
  the CRC seed. The gate decision is pinned (bindings rows for types
  0..15); the out-of-range seed value is NOT modelled -- cases use
  types 0..9 only.
- Whether the returned status's bytes 6-7 (padding, never written by
  the Append callee's error path) ever matter to a caller: both
  callers move the 16-byte status in their frames right after the
  call; whether bytes 6-7 are read was not traced.
- The exact .cold entry-point selection (which exception region uses
  the stub at 0x5f03d1a): the stub and the pad are pinned, but the
  LSDA region mapping was not decoded.
