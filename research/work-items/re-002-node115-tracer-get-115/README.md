# RE-002 · Node #115 RocksDB Tracer::Get

Component: storage / tracing. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115's `rocksdb::Tracer::Get` (0x61b1e40, 906 bytes)
record a `Get` — the gate it consults, the timestamp it stamps,
the payload it builds from the column-family id and the key, and
the Status it returns? The body hash matches the vendor census
exactly; the source hash is reproduced by zeroing the census
relocation fields (see `functions.tsv`). This is the second of the
five recording methods (Write, Get, IteratorSeek,
IteratorSeekForPrev, MultiGet); the other three are NOT
reconstructed here.

## Answer (pinned)

**Call shape.** `Status Tracer::Get(ColumnFamilyHandle* cf, const
Slice& key)`: `rdi` is the hidden sret `Status*` (the function
returns Status by value), `rsi` is `this` (Tracer*), `rdx` is the
column-family handle, `rcx` is the key Slice pointer (`{data
+0x00, size +0x08}`). The eight steps below are the whole
function (0x61b1e40..0x61b21ca); the exception landing pad at
0x61b21be..0x61b21c5 jumps to the shared pad at 0x61b1e18..0x61b1e3d
(`_M_dispose` + `_Unwind_Resume`) and runs only on the exception
path, so it is not modelled.

**1. Type.** The Trace's type byte is set to 4 (`kTraceGet`,
immediate at 0x61b1e76). The type byte lives in its own stack
slot (`rsp+0x13`) and is passed by address to ShouldSkipTrace
(`lea 0x13(%rsp),%rsi` at 0x61b1e71); it is copied into
`trace.type` (`rsp+0x28`) only after the gate passes (`movzbl
0x13(%rsp),%eax` at 0x61b200c, store at 0x61b201b). The source
explains the separate slot: `Get` declares a local `TraceType
trace_type = kTraceGet;` and passes it to `ShouldSkipTrace`
(`trace_replay.cc:371–372`), and `ShouldSkipTrace` takes it as
`const TraceType&` (`trace_replay.h:175`) — a const reference,
which the ABI passes as a pointer, exactly as the binary does.

**2. Gate.** `ShouldSkipTrace(this, type)` (0x61b1930, call at
0x61b1e7b; modelled in the header/footer packet, open PR #5870):
if it returns true, Get returns `Status::OK()` at once — the
clock is never consulted and nothing is written. The Get flag
bit is `0x01` (jump table at `.rodata 0x97c5f4`); a set bit skips
without advancing the sampling counter, and the file-size gate
(`GetFileSize() > max_trace_file_size`, strictly greater) and the
sampling counter apply first as in that packet.

**3. Timestamp.** `ts = clock_->NowMicros()` through the same
13-layer `SystemClockWrapper::NowMicros` (0x5d4d490) fast path as
WriteHeader/WriteFooter/Write: each layer's vtable slot 19 (+0x98)
is compared against 0x5d4d490 (the expected function as an
immediate, `lea` at 0x61b1eef — the single kind-42 relocation
site, offset 178) and followed through `+0x20`; the first layer
whose slot differs calls that slot's function directly
(0x61b2000). The observable result is the innermost clock's
`NowMicros()`.

**4. Payload map.** `TracerHelper::SetPayloadMap(trace.payload_map,
2)` (0x61b18b0, call at 0x61b202c) then
`SetPayloadMap(trace.payload_map, 3)` (call at 0x61b203b): `bts`
bits 2 (`kGetCFID`) and 3 (`kGetKey`) — so the in-memory
`payload_map` becomes 12 (it starts at 0). The map value is
never serialized by `EncodeTrace`; it is visible only as the
first 8 payload bytes below.

**5. PutFixed64.** The 8 little-endian bytes of the payload map
(`0c 00 00 00 00 00 00 00`) are appended to the payload string
(the map word is first copied to `rsp+0x18` at 0x61b2040–0x61b2045,
then appended with the std::string length guard:
`length_error` when `0x3fffffffffffffff - size <= 8`).

**6. PutFixed32.** The column-family id is read through the
`ColumnFamilyHandle` vtable slot 3 (`0x18`) — `GetID()`, call at
0x61b2081 — and its 4 little-endian bytes are appended (again
with the length guard: `length_error` when
`0x3fffffffffffffff - size <= 4`).

**7. PutLengthPrefixedSlice.** The key bytes are appended
length-prefixed: `EncodeVarint32(char*, uint32_t)` (0x61bd410,
its own FDE 0x61bd410..0x61bd4e9, not in the vendor census)
writes the LEB128 varint of the LOW 32 BITS of the key size
(`mov 0x8(%r12),%esi` — a 32-bit load — at 0x61b20b8) into a
5-byte stack buffer at `rsp+0x63`, then the varint bytes and the
key bytes are appended (each with the length guard). Note the
split: the varint encodes `(uint32_t)size` while the append
copies the full `size_t` — a >4 GiB key would prefix the
truncated length. That is read from the disassembly (`mov
0x8(%r12),%esi` at 0x61b20b8 vs the full `r12` used as the
append length at 0x61b20ee); it is untestable at that scale and
is not covered by a case.

**8. Return.** `WriteTrace(trace)` (0x61b1a10, call at 0x61b211e):
`EncodeTrace` (timestamp u64 LE, type byte, payload length u32 LE,
payload) + `TraceWriter::Write` (slot 2); the returned Status is
forwarded unchanged — writer errors propagate to the caller. The
payload string is freed only when its pointer differs from the
SSO buffer at `rsp+0x48` (standard string destruction).

**Golden record.** Clock 0, CF 0, empty key: `00`*8 (ts) + `04`
(type) + `0d 00 00 00` (payload length 13) + `0c 00 00 00 00 00
00 00` (PutFixed64(12)) + `00 00 00 00` (PutFixed32(0)) + `00`
(varint(0)) — 26 bytes. CF 0, key `"key"` gives a 30-byte record
(payload 16 bytes).

## Cases

2,400 deterministic cases (`cases.tsv`, seeded generator in
`tools/tracer_get115.py`): 1,200 `get` (200 Get-flag skips,
200 file-size-gate skips, 200 six-call sampling sequences for
periods 0/1/2/3/5/10, 50 writer-error rows, 550 full records over
boundary clocks and CF ids 0/1/2/3/2^32-1 and key sizes
0/1/3/127/128/256/1000/16383/16384 — including a realistic CF 0 /
`"key"` get), 600 `get_payload` (the payload bytes for CF ids
0/1/2/3/2^32-1 and key sizes 0/1/3/127/128/256/1000/16383/
16384), 600 `encode_varint32` (boundary values 0/1/127/128/
16383/16384/2097151/2097152/268435455/268435456/2^32-1 plus
random u32s). 20 tests pass (`tests/test_tracer_get115.py`),
including the golden-record test, the flag/file-size/sampling
gate tests, the varint boundary tests and the full 2,400-row
replay.

## Caller census

Whole-`.text` scan for E8 calls, E9 tail jumps and RIP-relative LEA
references landing on the target, validated by decoding forward from
the enclosing FDE start with Capstone (`census.py`). 3 validated
sites, all direct calls, all in DBImpl Get paths — each passes
`(Status* sret, Tracer*, ColumnFamilyHandle*, const Slice&)` with
the tracer taken from the DB member at `+0x650` after a null check
(`mov 0x650(%reg),%rsi; test %rsi,%rsi; je <skip>` at each site;
the call at 0x606ca40 just before is the same lock helper at all
three sites):

- `rocksdb::DBImpl::GetImpl` (FDE 0x5d60fa0..0x5d623e0): 0x5d61261
- `rocksdb::DBImplReadOnly::Get` (FDE 0x5e704c0..0x5e7151e): 0x5e706b9
- `rocksdb::DBImplSecondary::GetImpl` (FDE 0x5e7ca80..0x5e7d919): 0x5e7cd24

The enclosing functions are identified by the `.cold` FDE of the
same function immediately preceding each main FDE (vendor-census
symbols `DBImpl::GetImpl.cold`,
`DBImplReadOnly::Get.cold`, `DBImplSecondary::GetImpl.cold`). No E9
tail jump or LEA reference to 0x61b1e40 exists in `.text`.

## Unknowns (kept separate from observations)

- Upstream source: the RocksDB v8.1.1 read arrived before
  submission and CONFIRMS the packet — `Tracer::Get`
  (`trace_replay/trace_replay.cc:370–387`) matches the binary step
  for step (local `TraceType trace_type = kTraceGet`, gate before
  the clock, `SetPayloadMap(kGetCFID)` then `SetPayloadMap(kGetKey)`,
  `PutFixed64(payload_map)`, `PutFixed32(column_family->GetID())`,
  `PutLengthPrefixedSlice(key)`, `return WriteTrace(trace)`).
  `ShouldSkipTrace` is `bool ShouldSkipTrace(const TraceType&
  type)` (`trace_replay.h:175`, defined at `trace_replay.cc:531`)
  — a const reference, which is why the binary passes the type
  byte's address. `ColumnFamilyHandle::GetID()` is `virtual
  uint32_t GetID() const = 0` (`include/rocksdb/db.h:83`), the
  third declared virtual after the destructor and `GetName` —
  consistent with the binary's vtable slot 3 (`0x18`).
  `kTraceGet = 4` (`include/rocksdb/trace_record.h:28`).
  `SetPayloadMap` is `payload_map |= (1 << payload_type)`
  (`trace_replay.cc:121–127`), so the map is 12, and the
  `kTraceGet` decoder reads the same order back
  (`GetFixed64`, `GetFixed32`, `GetLengthPrefixedSlice`).
- The `+0x650` DB member holding the tracer pointer (loaded and
  null-checked at each call site): its member name is not pinned
  here — caller logic, outside Get's body, not modelled.
- The other three recording methods (IteratorSeek 0x61b21f0,
  IteratorSeekForPrev 0x61b2760, MultiGet 0x61b2cf0) are the
  natural continuation; their payload encodings are NOT
  reconstructed here and must each be verified against the
  binary.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool is a behavioural Python model of the one
function only. `make verify` / `make test` / `make catalogue-check`
in a tooled environment is still owed upstream. Object dump format:
GNU objdump 2.42, Intel syntax. Upstream base: RocksDB v8.1.1
(librocksdb-sys 0.11.0+8.1.1 per the vendor census).
