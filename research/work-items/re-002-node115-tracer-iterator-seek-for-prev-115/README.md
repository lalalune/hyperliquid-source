# RE-002 · Node #115 RocksDB Tracer::IteratorSeekForPrev

Component: storage / tracing. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115's `rocksdb::Tracer::IteratorSeekForPrev` (0x61b2760,
1352 bytes) record an `IteratorSeekForPrev` — the gate it consults, the
timestamp it stamps, the payload it builds from the column-family
id, the key and the two bounds, and the Status it returns? The body
hash matches the vendor census exactly; the source hash is
reproduced by zeroing the census relocation fields (see
`functions.tsv`). This is the fourth of the five recording methods
(Write, Get, IteratorSeek, IteratorSeekForPrev, MultiGet); the
other one (MultiGet) is NOT reconstructed here.

## Answer (pinned)

**Call shape.** `Status Tracer::IteratorSeekForPrev(const uint32_t& cf_id,
const Slice& key, const Slice& lower_bound, const Slice
upper_bound)`: `rdi` is the hidden sret `Status*` (the function
returns Status by value), `rsi` is `this` (Tracer*), `rdx` is the
CF id by reference (`const uint32_t*`), `rcx` is the key Slice
pointer (`{data +0x00, size +0x08}`), `r8` is the lower-bound Slice
pointer, and the upper-bound Slice arrives **by value** on the
stack (data at `[rsp+0x08]`, size at `[rsp+0x10]` on entry; the
prologue copies the data pointer to `[rsp+0x10]` and the size into
`r15`). The ten steps below are the whole function
(0x61b2760..0x61b2ca8); the exception landing pad at
0x61b2c9c..0x61b2ca7 jumps to 0x61b2738 and runs only on the
exception path, so it is not modelled.

**1. Type.** The Trace's type byte is set to 6
(`kTraceIteratorSeekForPrev`, immediate at 0x61b27b2). The type byte
lives in its own stack slot (`rsp+0x23`) and is passed by address
to ShouldSkipTrace (`lea 0x23(%rsp),%rsi` at 0x61b2790); it is
copied into `trace.type` (`rsp+0x38`) only after the gate passes
(`movzbl 0x23(%rsp),%eax` at 0x61b293c, store at 0x61b294b). The
source explains the separate slot: `IteratorSeekForPrev` declares a local
`TraceType trace_type = kTraceIteratorSeekForPrev;` and passes it to
`ShouldSkipTrace` (`trace_replay.cc:424–425`), and
`ShouldSkipTrace` takes it as `const TraceType&`
(`trace_replay.h:175`) — a const reference, which the ABI passes
as a pointer, exactly as the binary does.

**2. Gate.** `ShouldSkipTrace(this, type)` (0x61b1930, call at
0x61b27b7; modelled in the header/footer packet, open PR #5870):
if it returns true, IteratorSeekForPrev returns `Status::OK()` at once —
the clock is never consulted and nothing is written. The
IteratorSeekForPrev flag bit is `0x08` (jump table at `.rodata 0x97c5f4`);
a set bit skips without advancing the sampling counter, and the
file-size gate (`GetFileSize() > max_trace_file_size`, strictly
greater) and the sampling counter apply first as in that packet.

**3. Timestamp.** `ts = clock_->NowMicros()` through the same
13-layer `SystemClockWrapper::NowMicros` (0x5d4d490) fast path as
WriteHeader/WriteFooter/Write/Get: each layer's vtable slot 19
(+0x98) is compared against 0x5d4d490 (the expected function as an
immediate, `lea` at 0x61b2834 — the single kind-42 relocation
site, offset 215) and followed through `+0x20`; the first layer
whose slot differs calls that slot's function directly
(0x61b2930). The observable result is the innermost clock's
`NowMicros()`.

**4. Payload map.** `TracerHelper::SetPayloadMap(trace.payload_map,
4)` (0x61b18b0, call at 0x61b295c) then
`SetPayloadMap(trace.payload_map, 5)` (call at 0x61b296b): `bts`
bits 4 (`kIterCFID`) and 5 (`kIterKey`) — so the in-memory
`payload_map` becomes 48 (it starts at 0). Then, only when the
lower bound is non-empty (`cmp [r14+0x8],0` at 0x61b2970),
`SetPayloadMap(map, 6)` (`kIterLowerBound`, call at 0x61b2b2f);
and only when the upper bound is non-empty (`test r15,r15` at
0x61b297b), `SetPayloadMap(map, 7)` (`kIterUpperBound`, call at
0x61b298f). With both bounds present the map is 240. The map value
is never serialized by `EncodeTrace`; it is visible only as the
first 8 payload bytes below.

**5. PutFixed64.** The 8 little-endian bytes of the payload map
are appended to the payload string (the map word is first copied
to `rsp+0x28` at 0x61b2999, then appended with the std::string
length guard: `length_error` when `0x3fffffffffffffff - size <=
8`).

**6. PutFixed32.** The CF id is loaded from the reference the
caller passed (`mov 0x0(%rax),%eax` — a 32-bit load — at
0x61b29d2) and its 4 little-endian bytes are appended (again with
the length guard: `length_error` when `0x3fffffffffffffff - size
<= 4`). Unlike Get, there is no `ColumnFamilyHandle` vtable call
here — the caller already resolved the id.

**7. PutLengthPrefixedSlice (key).** The key bytes are appended
length-prefixed: `EncodeVarint32(char*, uint32_t)` (0x61bd410,
its own FDE 0x61bd410..0x61bd4e9, not in the vendor census)
writes the LEB128 varint of the LOW 32 BITS of the key size
(`mov 0x8(%r13),%esi` — a 32-bit load — at 0x61b2a08) into a
5-byte stack buffer at `rsp+0x69`, then the varint bytes and the
key bytes are appended (each with the length guard). Note the
split: the varint encodes `(uint32_t)size` while the append
copies the full `size_t` — a >4 GiB key would prefix the
truncated length. That is read from the disassembly; it is
untestable at that scale and is not covered by a case.

**8. PutLengthPrefixedSlice (lower bound), only when non-empty.**
The size test is at 0x61b2a71 (`test %rsi,%rsi` on the lower
bound's size, branch to 0x61b2b40): the varint of
`(uint32_t)lower_size` (the size passes through `rsi`/`esi` at
0x61b2a6d) is written into a 5-byte stack buffer at `rsp+0x6e`,
then the varint bytes and the bound bytes are appended. An empty
lower bound contributes nothing — no varint, no bytes, and no
map bit (step 4).

**9. PutLengthPrefixedSlice (upper bound), only when non-empty.**
The size test is at 0x61b2a7a (`test r15,r15`, branch to 0x61b2ae0
when empty): the varint of `(uint32_t)upper_size` (`mov
r15d,%esi` at 0x61b2a84) is written into a 5-byte stack buffer at
`rsp+0x73`, then the varint bytes and the bound bytes are
appended (data from `[rsp+0x10]`, size from `r15`).

**10. Return.** `WriteTrace(trace)` (0x61b1a10, call at 0x61b2aeb):
`EncodeTrace` (timestamp u64 LE, type byte, payload length u32 LE,
payload) + `TraceWriter::Write` (slot 2); the returned Status is
forwarded unchanged — writer errors propagate to the caller. The
payload string is freed only when its pointer differs from the
SSO buffer at `rsp+0x58` (standard string destruction).

**Golden record.** Clock 0, CF 0, empty key and bounds: `00`*8
(ts) + `06` (type) + `0d 00 00 00` (payload length 13) + `30 00
00 00 00 00 00 00` (PutFixed64(48)) + `00 00 00 00`
(PutFixed32(0)) + `00` (varint(0)) — 26 bytes. CF 0, key `"key"`,
lower `"lo"`, upper `"hi"` gives a 35-byte record (payload 22
bytes, map 240).

## Cases

2,400 deterministic cases (`cases.tsv`, seeded generator in
`tools/tracer_iterator_seek_for_prev_for_prev115.py`): 1,200 `iterator_seek_for_prev` (200
IteratorSeekForPrev-flag skips, 200 file-size-gate skips, 200 six-call
sampling sequences for periods 0/1/2/3/5/10, 50 writer-error rows,
550 full records over boundary clocks and CF ids 0/1/2/3/2^32-1
and key/lower/upper sizes 0/1/3/127/128/256/1000/16383/16384 —
including a realistic CF 0 / `"key"` / `"lo"` / `"hi"` seek —
cycling the four bound-presence combos), 600
`iterator_seek_for_prev_for_prev_payload` (the payload bytes for CF ids
0/1/2/3/2^32-1 and key/lower/upper sizes 0/1/3/127/128/256/1000/
16383/16384), 600 `encode_varint32` (boundary values
0/1/127/128/16383/16384/2097151/2097152/268435455/268435456/2^32-1
plus random u32s). 24 tests pass
(`tests/test_tracer_iterator_seek_for_prev_for_prev115.py`), including the
golden-record tests, the bound-combination map tests, the
flag/file-size/sampling gate tests, the varint boundary tests and
the full 2,400-row replay.

## Caller census

Whole-`.text` scan for E8 calls, E9 tail jumps and RIP-relative
LEA references landing on the target, validated by decoding
forward from the enclosing FDE start with Capstone (`census.py`).
1 validated site, one direct call, in a DBImpl seek path:

- `rocksdb::DBImpl::TraceIteratorSeek` (FDE 0x5d55520..0x5d55644,
  the second copy): 0x5d555b1

It passes `(Status* sret, Tracer*, const uint32_t* cf_id, const
Slice* key, const Slice* lower_bound, Slice upper_bound by value
on the stack)` with the tracer taken from the DB member at
`+0x650` after a null check (`mov 0x650(%rsi),%rsi; test
%rsi,%rsi; je <skip>` at 0x5d5558b–0x5d55595; the call at
0x606ca40 just before is the same lock helper as in the Get
callers, entered with the mutex at `+0x658`); the upper bound's
two words are copied onto the stack with `movdqu`/`movups` at
0x5d55597–0x5d555ad. The Status is zeroed at entry (`movl $0x0,
(%rdi)` at 0x5d5554a).

No E9 tail jump or LEA reference to 0x61b2760 exists in `.text`.

Note: the first, nominally identical copy of
`DBImpl::TraceIteratorSeek` (FDE 0x5d553c0..0x5d554e4) does NOT
call IteratorSeekForPrev — it calls `IteratorSeek` (0x61b21f0)
at 0x5d55451. The two copies diverge by seek direction; that
call is observed in the first copy's disassembly, not part of
this packet's validated census.

## Unknowns (kept separate from observations)

- Upstream source: the RocksDB v8.1.1 read arrived before
  submission and CONFIRMS the packet — `Tracer::IteratorSeekForPrev`
  (`trace_replay/trace_replay.cc:424–458`) matches the binary step
  for step (local `TraceType trace_type = kTraceIteratorSeekForPrev`,
  gate before the clock, `SetPayloadMap(kIterCFID)` then
  `SetPayloadMap(kIterKey)`, conditional `SetPayloadMap`
  (kIterLowerBound/kIterUpperBound) on `size() > 0`,
  `PutFixed64(payload_map)`, `PutFixed32(cf_id)`,
  `PutLengthPrefixedSlice(key)`, conditional
  `PutLengthPrefixedSlice(lower_bound)` /
  `PutLengthPrefixedSlice(upper_bound)`, `return
  WriteTrace(trace)`). It is identical to `IteratorSeek`
  (`trace_replay.cc:389–422`) except `trace_type =
  kTraceIteratorSeekForPrev` — and the binary confirms this
  directly: the two 1352-byte FDEs differ in exactly one semantic
  byte, the `movb $0x6` at 0x61b27b2 versus `movb $0x5` at
  0x61b2242 (all other differing bytes are relative-displacement
  encodings of the same absolute targets). `TracePayloadType` is
  `enum : char` in `trace_replay/trace_replay.h:71–85` (not in
  `trace_record.h`): `kIterCFID = 4`, `kIterKey = 5`,
  `kIterLowerBound = 6`, `kIterUpperBound = 7`;
  `kTraceIteratorSeekForPrev = 6` (`trace_record.h:29`).
  `ShouldSkipTrace` is `bool ShouldSkipTrace(const TraceType&
  type)` (`trace_replay.h:175`, defined at
  `trace_replay.cc:531`) — a const reference, which is why the
  binary passes the type byte's address. The
  kTraceIteratorSeek/kTraceIteratorSeekForPrev decoder
  (`DecodeTraceRecord`, `trace_replay.cc:214–270`) reads the
  payload_map bits in ascending order — kIterCFID
  (`GetFixed32`), kIterKey, kIterLowerBound, kIterUpperBound
  (each `GetLengthPrefixedSlice`) — the same order the binary
  encodes.
- The `+0x650` DB member holding the tracer pointer (loaded and
  null-checked at the call site): its member name is not pinned
  here — caller logic, outside IteratorSeekForPrev's body, not modelled.
- The last recording method, MultiGet (0x61b2cf0, 2214 bytes), is
  the natural continuation; its payload encoding is NOT
  reconstructed here and must be verified against the binary.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool is a behavioural Python model of the one
function only. `make verify` / `make test` / `make catalogue-check`
in a tooled environment is still owed upstream. Object dump format:
GNU objdump 2.42, Intel syntax. Upstream base: RocksDB v8.1.1
(librocksdb-sys 0.11.0+8.1.1 per the vendor census).
