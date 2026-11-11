# RE-002 · Node #115 RocksDB Tracer::Write

Component: storage / tracing. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115's `rocksdb::Tracer::Write` (0x61b1af0, 808 bytes)
record a `WriteBatch` — the gate it consults, the timestamp it
stamps, the payload it builds from the batch, and the Status it
returns? The body hash matches the vendor census exactly; the
source hash is reproduced by zeroing the census relocation fields
(see `functions.tsv`). This is the first of the five recording
methods (Write, Get, IteratorSeek, IteratorSeekForPrev, MultiGet);
the other four are NOT reconstructed here.

## Answer (pinned)

**Call shape.** `Status Tracer::Write(WriteBatch* batch)`:
`rdi` is the hidden sret `Status*` (the function returns Status by
value), `rsi` is `this` (Tracer*), `rdx` is the batch. The seven
steps below are the whole function (0x61b1af0..0x61b1e18); the
exception landing pads (the `.cold` part at 0x61b1ac6..0x61b1aeb
and the separate 37-byte FDE at 0x61b1e18..0x61b1e3d) run only on
the exception path and are not modelled.

**1. Type.** The Trace's type byte is set to 3 (`kTraceWrite`,
immediate at 0x61b1b23).

**2. Gate.** `ShouldSkipTrace(this, type)` (0x61b1930, call at
0x61b1b28; modelled in the header/footer packet, open PR #5870):
if it returns true, Write returns `Status::OK()` at once — the
clock is never consulted and nothing is written. The Write flag
bit is `0x02` (jump table at `.rodata 0x97c5f4`); a set bit skips
without advancing the sampling counter, and the file-size gate
(`GetFileSize() > max_trace_file_size`, strictly greater) and the
sampling counter apply first as in that packet.

**3. Timestamp.** `ts = clock_->NowMicros()` through the same
13-layer `SystemClockWrapper::NowMicros` (0x5d4d490) fast path as
WriteHeader/WriteFooter: each layer's vtable slot 19 (+0x98) is
compared against 0x5d4d490 (the expected function as an immediate
at 0x61b1b9f) and followed through `+0x20`; the first layer whose
slot differs calls that slot's function directly (0x61b1cb0). The
observable result is the innermost clock's `NowMicros()`.

**4. Payload map.** `TracerHelper::SetPayloadMap(trace.payload_map,
1)` (0x61b18b0, call at 0x61b1cd4): `bts` bit 1 —
`kWriteBatchData` — so the in-memory `payload_map` becomes 2 (it
starts at 0). The map value is never serialized by `EncodeTrace`;
it is visible only as the first 8 payload bytes below.

**5. PutFixed64.** The 8 little-endian bytes of the payload map
(`02 00 00 00 00 00 00 00`) are appended to the payload string
(with the std::string length guard: `length_error` when
`0x3fffffffffffffff - size <= 8`).

**6. PutLengthPrefixedSlice.** The batch's serialized bytes are
appended length-prefixed: `EncodeVarint32(char*, uint32_t)`
(0x61bd410, its own FDE 0x61bd410..0x61bd4e9, not in the vendor
census) writes the LEB128 varint of the LOW 32 BITS of the size
(`mov esi, r13d`) into a 5-byte stack buffer, then the bytes are
appended (again with the length guard). Note the split: the varint
encodes `(uint32_t)size` while the append copies the full `size_t`
— a >4 GiB batch would prefix the truncated length. That is read
from the disassembly (`mov esi, r13d` at 0x61b1d23 vs the full
`r13` used as the append length at 0x61b1d68); it is untestable at
that scale and is not covered by a case.

**The batch's bytes.** `WriteBatch::Data()` is `Slice(rep_)`, and
`rep_` is the std::string at batch+0x40: the data pointer is
`[batch+0x40]`, the size is `[batch+0x48]`. Confirmed
independently by `WriteBatch::Clear` (0x5fb7220), which loads
`[rdi+0x40]` as the string data pointer, stores 0 at `[rdi+0x48]`
(the size) and calls `resize(12, 0)` on the string at `+0x40`
(the 12-byte rep header: 8-byte sequence + 4-byte count). The members before `rep_` are confirmed by the upstream source
(`include/rocksdb/write_batch.h`): `save_points_` (unique_ptr,
+0x08), `wal_term_point_` (SavePoint, +0x10..0x20), three bools
(+0x20..0x23), `content_flags_` (atomic u32, +0x24), `max_bytes_`
(+0x28), `prot_info_` (unique_ptr, +0x30), `default_cf_ts_sz_`
(+0x38) — so `rep_` starts exactly at +0x40. The `Clear`
disassembly agrees field by field (`[rbx+0x24]=0` is
`content_flags_`, `[rbx+0x30]` is `prot_info_`, `[rbx+0x38]=0` is
`default_cf_ts_sz_`).

**7. Return.** `WriteTrace(trace)` (0x61b1a10, call at 0x61b1d88):
`EncodeTrace` (timestamp u64 LE, type byte, payload length u32 LE,
payload) + `TraceWriter::Write` (slot 2); the returned Status is
forwarded unchanged — writer errors propagate to the caller. The
payload string is freed only when its pointer differs from the
SSO buffer at `rsp+0x48` (standard string destruction).

**Golden record.** Clock 0, empty batch: `00`*8 (ts) + `03`
(type) + `09 00 00 00` (payload length 9) + `02 00 00 00 00 00
00 00` (PutFixed64(2)) + `00` (varint(0)) — 22 bytes. A fresh
WriteBatch rep (12 zero bytes) gives a 34-byte record.

## Cases

2,400 deterministic cases (`cases.tsv`, seeded generator in
`tools/tracer_write115.py`): 1,200 `write` (200 Write-flag skips,
200 file-size-gate skips, 200 six-call sampling sequences for
periods 0/1/2/3/5/10, 50 writer-error rows, 550 full records over
boundary clocks and batch sizes 0/1/12/127/128/256/1000/16383/
16384 — including a realistic empty rep and a realistic 1-put
rep), 600 `write_payload` (the payload bytes for batch sizes
0/1/12/127/128/256/1000/16383/16384), 600 `encode_varint32`
(boundary values 0/1/127/128/16383/16384/2097151/2097152/
268435455/268435456/2^32-1 plus random u32s). 18 tests pass
(`tests/test_tracer_write115.py`), including the golden-record
test, the flag/file-size/sampling gate tests, the varint
boundary tests and the full 2,400-row replay.

## Caller census

Whole-`.text` scan for E8 calls, E9 tail jumps and RIP-relative LEA
references landing on the target, validated by decoding forward from
the enclosing FDE start with Capstone (`census.py`). 7 validated
sites, all direct calls, all in DBImpl write paths — each passes
`(Status* sret, Tracer*, WriteBatch*)` with the batch taken from
the write group (`[writer]` / `[writer+0x0]`, the list advancing
via `[writer+0xf8]`; verified at 0x5e8f565, 0x5e90e06 and
0x5e922ca):

- `DBImpl::PipelinedWriteImpl` (FDE 0x5e8ef90..0x5e904bd): 0x5e8f565, 0x5e8f5a4
- `DBImpl::WriteImplWALOnly` (FDE 0x5e909d0..0x5e91cd2): 0x5e90e06, 0x5e90e42
- `DBImpl::WriteImpl` (FDE 0x5e91ed0..0x5e9406a): 0x5e922ca, 0x5e92ebe, 0x5e92efa

The enclosing functions are identified by the `.cold` FDE of the
same function immediately preceding each main FDE (vendor-census
symbols `DBImpl::PipelinedWriteImpl.cold`,
`DBImpl::WriteImplWALOnly.cold`, `DBImpl::WriteImpl.cold`). No E9
tail jump or LEA reference to 0x61b1af0 exists in `.text`.

## Unknowns (kept separate from observations)

- Upstream source: the RocksDB v8.1.1 read arrived before
  submission and CONFIRMS the packet — `Tracer::Write`
  (`trace_replay/trace_replay.cc:355–368`; the files live at
  top-level `trace_replay/`, not `utilities/trace_replay/`)
  matches the binary step for step, and the `WriteBatch` member
  layout above pins `rep_` at +0x40. It also gives the next
  methods' payload shapes (Get: `kGetCFID`+`kGetKey`,
  PutFixed32(cf id), length-prefixed key; IteratorSeek/ForPrev:
  `kIterCFID`+`kIterKey` plus conditional `kIterLowerBound` /
  `kIterUpperBound`; MultiGet: `kMultiGetSize`+`kMultiGetCFIDs`+
  `kMultiGetKeys`, size as PutFixed32, CF-id/key lists as
  length-prefixed strings) — still to be verified per-function
  against the binary.
- The caller-side gate at the call sites (e.g. the
  `[tracer+0x20]` byte checked in `PipelinedWriteImpl` before the
  first call): caller logic, outside Write's body, not modelled.
- The other four recording methods (Get 0x61b1e40, IteratorSeek
  0x61b21f0, IteratorSeekForPrev 0x61b2760, MultiGet 0x61b2cf0)
  are the natural continuation; their payload encodings (cf id /
  key slices, their `TracePayloadType` bits) are NOT reconstructed
  here and must each be verified against the binary.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool is a behavioural Python model of the one
function only. `make verify` / `make test` / `make catalogue-check`
in a tooled environment is still owed upstream. Object dump format:
GNU objdump 2.42, Intel syntax. Upstream base: RocksDB v8.1.1
(librocksdb-sys 0.11.0+8.1.1 per the vendor census).
