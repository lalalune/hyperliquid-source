# RE-002 · Node #115 RocksDB Tracer::MultiGet

Component: storage / tracing. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115's `rocksdb::Tracer::MultiGet` (0x61b2cf0, 2214
bytes) record a `MultiGet` — the size check it runs before the
gate, the gate it consults, the timestamp it stamps, the two blobs
it builds from the column-family handles and the keys, the payload
it assembles from them, and the Status it returns? The body hash
matches the vendor census exactly; the source hash is reproduced
by zeroing the census relocation fields (see `functions.tsv`).
This is the fifth and last of the five recording methods (Write,
Get, IteratorSeek, IteratorSeekForPrev, MultiGet); the other four
are reconstructed in their own packets, not here.

## Answer (pinned)

**Call shape.** `Status Tracer::MultiGet(const
std::vector<ColumnFamilyHandle*>& column_families, const
std::vector<Slice>& keys)`: `rdi` is the hidden sret `Status*`
(the function returns Status by value), `rsi` is `this`
(Tracer*), `rdx` is the column-families vector pointer
(`{begin +0x00, end +0x08}` of 8-byte `ColumnFamilyHandle*`
elements), `rcx` is the keys vector pointer (`{begin +0x00,
end +0x08}` of 16-byte Slice elements). The eleven steps below
are the whole function (0x61b2cf0..0x61b3596); the exception
landing pads at 0x61b3576..0x61b3595 jump to the shared cleanup
fragment at 0x61b2ca8..0x61b2cd5 and run only on the exception
path, so they are not modelled.

**1. Size check.** `n_keys = (keys.end - keys.begin) >> 4` and
`n_cf = (column_families.end - column_families.begin) >> 3`
(0x61b2d08..0x61b2d3c; arithmetic shifts, but `end >= begin`
for a valid vector, so the shift is exact). When they differ,
MultiGet returns at once (0x61b2d41..0x61b2db1) with
`Status::Corruption("the CFs size and keys size does not
match!")` — the 42-byte message at `.rodata 0x966820`, built by
the `Status(code, subcode, msg, msg2)` constructor at 0x61cf670
with code 2 (`kCorruption`), subcode 0 and an empty second
message (the Slice at `rsp+0x70` has data 0x4376fd and size 0),
so the state is the message alone. The gate and the clock are
never consulted on this path and the sampling counter is
untouched. This check runs BEFORE the gate — a mismatched
multiget returns Corruption even when the MultiGet flag is set
or the trace file is over the limit. The source states the same
check first (`trace_replay.cc:947–951`).

**2. Type.** The Trace's type byte is set to 13
(`kTraceMultiGet`, immediate at 0x61b2dc0). The type byte lives
in its own stack slot (`rsp+0x5b`) and is passed by address to
ShouldSkipTrace (`lea 0x5b(%rsp),%rsi` at 0x61b2dbb); it is
copied into `trace.type` (`rsp+0xc8`) only after the gate passes
(`movzbl 0x5b(%rsp),%eax` at 0x61b2f2a, store at 0x61b2f3f).
The source explains the separate slot: `MultiGet` declares a
local `TraceType trace_type = kTraceMultiGet;` and passes it to
`ShouldSkipTrace` (`trace_replay.cc:953–955`), and
`ShouldSkipTrace` takes it as `const TraceType&`
(`trace_replay.h:175`) — a const reference, which the ABI passes
as a pointer, exactly as the binary does.

**3. Gate.** `ShouldSkipTrace(this, type)` (0x61b1930, call at
0x61b2dc8; modelled in the header/footer packet, open PR #5870):
if it returns true, MultiGet returns `Status::OK()` at once —
the clock is never consulted and nothing is written. The
MultiGet flag bit is `0x10` (jump table at `.rodata 0x97c5f4`);
a set bit skips without advancing the sampling counter, and the
file-size gate (`GetFileSize() > max_trace_file_size`, strictly
greater) and the sampling counter apply first as in that packet.

**4. Timestamp.** `ts = clock_->NowMicros()` through the
`SystemClockWrapper::NowMicros` (0x5d4d490) fast path as in
WriteHeader/WriteFooter/Write/Get/IteratorSeek/
IteratorSeekForPrev, here unrolled over 10 layers (9 compared
layers, the 10th called directly): each compared layer's vtable
slot 19 (+0x98) is compared against 0x5d4d490 (the expected
function as an immediate, `lea` at 0x61b2e2e — the single
kind-42 relocation site, offset 321) and followed through
`+0x20`; the first layer whose slot differs calls that slot's
function directly (0x61b2f20); the 10th layer's slot is called
directly at 0x61b2eed without a comparison. The observable
result is the innermost clock's `NowMicros()`. The unroll depth
is a code-generation artifact — IteratorSeekForPrev unrolls 12
layers — not a semantic difference.

**5. Payload map.** `TracerHelper::SetPayloadMap(trace.payload_map,
8)` (0x61b18b0, call at 0x61b2f46), `SetPayloadMap(map, 9)`
(call at 0x61b2f53), `SetPayloadMap(map, 10)` (call at
0x61b2f60): `bts` bits 8 (`kMultiGetSize`), 9 (`kMultiGetCFIDs`)
and 10 (`kMultiGetKeys`) — so the in-memory `payload_map`
becomes 0x700 (1792). It starts at 0, and the three calls are
unconditional: the map is 0x700 even for the empty multiget.
The map value is never serialized by `EncodeTrace`; it is
visible only as the first 8 payload bytes below.

**6. The two blobs.** Two `std::string` locals are built first
(cfids at `rsp+0x80`, SSO buffer at `rsp+0x90`; keys at
`rsp+0xa0`, SSO buffer at `rsp+0xb0`). For each `i` in
`0..multiget_size-1` — `multiget_size` is the LOW 32 bits of
`keys.size()` (the loop bound is the zero-extended u32 at
0x61b2fc4; the byte offset `r15` steps by 8 while `r15 <
multiget_size * 8`, and `r14 = keys.begin + r15 * 2`):
  - cfids blob: `PutFixed32(column_families[i]->GetID())` —
    the CF id via the `ColumnFamilyHandle` vtable slot 3
    (`+0x18`, call at 0x61b3000), its 4 little-endian bytes
    appended (the id is held at `rsp+0x5c` first, with the
    std::string length guard).
  - keys blob: `PutLengthPrefixedSlice(keys[i])` —
    `EncodeVarint32(char*, uint32_t)` (0x61bd410, its own FDE
    0x61bd410..0x61bd4e9, not in the vendor census) writes the
    LEB128 varint of the LOW 32 BITS of the key size (`mov
    0x8(%r14),%esi` — a 32-bit load — at 0x61b3062) into a 5-byte
    stack buffer at `rsp+0xf9`, then the varint bytes and the
    key bytes are appended (each with the length guard). Note
    the split: the varint encodes `(uint32_t)size` while the
    append copies the full `size_t` — a >4 GiB key would prefix
    the truncated length. That is read from the disassembly; it
    is untestable at that scale and is not covered by a case.
  When `multiget_size` is 0 the loop is skipped and both blobs
  stay empty.

**7. PutFixed64.** The 8 little-endian bytes of the payload map
are appended to the payload string (the map word is first
copied to `rsp+0x70` at 0x61b30f8, then appended with the
std::string length guard: `length_error` when
`0x3fffffffffffffff - size <= 8`).

**8. PutFixed32.** The key count is appended as 4 little-endian
bytes (`mov 0x30(%rsp),%eax` — a 32-bit load of the low 32 bits
of `keys.size()` — at 0x61b3150, held at `rsp+0x60`; again with
the length guard). This is `multiget_size`, the same truncated
u32 the loop bound uses — a `keys.size()` above 2^32 would
encode and loop over the truncated count (disassembly-only
observation, untestable at that scale).

**9. PutLengthPrefixedSlice (cfids blob).** The varint of
`(uint32_t)cfids_size` (`mov r12d,%esi` at 0x61b31c3) is written
into a 5-byte stack buffer at `rsp+0xfe`, then the varint bytes
and the cfids bytes are appended.

**10. PutLengthPrefixedSlice (keys blob).** The varint of
`(uint32_t)keys_size` (`mov r12d,%esi` at 0x61b3272) is written
into a 5-byte stack buffer at `rsp+0x103`, then the varint
bytes and the keys bytes are appended.

**11. Return.** `WriteTrace(trace)` (0x61b1a10, call at
0x61b3318): `EncodeTrace` (timestamp u64 LE, type byte, payload
length u32 LE, payload) + `TraceWriter::Write` (slot 2); the
returned Status is forwarded unchanged — writer errors
propagate to the caller. The three strings are freed only when
their pointers differ from their SSO buffers (standard string
destruction, 0x61b331d..0x61b3385).

**Golden records.** Clock 0, no CFs, no keys: `00`*8 (ts) +
`0d` (type) + `0e 00 00 00` (payload length 14) + `00 07 00 00
00 00 00 00` (PutFixed64(0x700)) + `00 00 00 00`
(PutFixed32(0)) + `00` (varint(0), cfids blob) + `00`
(varint(0), keys blob) — 27 bytes. Clock 0, CF 0, key `""`:
payload 19 bytes, record 32 bytes. Clock 0, CFs 0 and 1, keys
`"key1"`/`"key2"`: payload 32 bytes (cfids blob 8 bytes,
keys blob 10 bytes), record 45 bytes.

## Cases

2,400 deterministic cases (`cases.tsv`, seeded generator in
`tools/tracer_multiget115.py`): 1,200 `multiget` (200 MultiGet-flag
skips, 200 file-size-gate skips, 200 six-call sampling sequences
for periods 0/1/2/3/5/10, 50 writer-error rows, 100 size-mismatch
rows — half of them also setting the MultiGet flag or an oversized
file, to pin that the mismatch check precedes the gate — 450 full
records over boundary clocks and CF ids 0/1/2/3/2^32-1 and key
sizes 0/1/3/127/128/256/1000/16383/16384, including the empty
multiget and a realistic CF 0/1 / `"key1"` / `"key2"` multiget),
600 `multiget_payload` (the payload bytes for 0–6 keys, CF ids
0/1/2/3/2^32-1, key sizes 0/1/3/127/128/256/1000/16383/16384),
600 `encode_varint32` (boundary values
0/1/127/128/16383/16384/2097151/2097152/268435455/268435456/2^32-1
plus random u32s). 26 tests pass
(`tests/test_tracer_multiget115.py`), including the golden-record
tests, the mismatch-before-gate tests, the flag/file-size/sampling
gate tests, the varint boundary tests and the full 2,400-row
replay.

## Caller census

Whole-`.text` scan for E8 calls, E9 tail jumps and RIP-relative
LEA references landing on the target, validated by decoding
forward from the enclosing FDE start with Capstone (`census.py`).
3 validated sites, all direct calls:

- `rocksdb::DBImpl::TraceMultiGet` (FDE 0x5d78b40..0x5d7a806):
  0x5d79107. It passes `(Status* sret, Tracer*, const
  std::vector<ColumnFamilyHandle*>*, const std::vector<Slice>*)`
  with the tracer in `rsi`, null-checked (`test %rsi,%rsi; je
  <skip>` at 0x5d790ea, skipping the call when null).
- `rocksdb::Tracer::MultiGet(size_t, ColumnFamilyHandle**,
  const Slice*)` (FDE 0x61b4440..0x61b45d9): 0x61b456a. The
  array overload: its copy loop loads each CF pointer from the
  input array (`mov (%r12,%rax),%rdx` at 0x61b4540) and each key
  with `movdqu`/`movups`, then delegates to the vector overload.
  It returns `Status::OK()` at once when `num_keys == 0`
  (`test %rdx,%rdx` at the FDE start, per the upstream source).
- `rocksdb::Tracer::MultiGet(size_t, ColumnFamilyHandle*,
  const Slice*)` (FDE 0x61b4610..0x61b47a1): 0x61b4739. The
  single-CF array overload: its copy loop stores the same CF
  pointer into every vector slot (`mov (%rdx),%r12` at
  0x61b4717) while copying each key, then delegates. It also
  returns `Status::OK()` at once when `num_keys == 0`.

No E9 tail jump or LEA reference to 0x61b2cf0 exists in `.text`.

## Unknowns (kept separate from observations)

- Upstream source: the RocksDB v8.1.1 read arrived before
  submission and CONFIRMS the packet — `Tracer::MultiGet`
  (`trace_replay/trace_replay.cc:943–1015`) matches the binary
  step for step (size check first with the exact 42-byte message,
  local `TraceType trace_type = kTraceMultiGet`, gate before the
  clock, `SetPayloadMap(kMultiGetSize)` then
  `SetPayloadMap(kMultiGetCFIDs)` then
  `SetPayloadMap(kMultiGetKeys)`, the per-key loop with
  `PutFixed32(column_families[i]->GetID())` and
  `PutLengthPrefixedSlice(keys[i])`, `PutFixed64(payload_map)`,
  `PutFixed32(multiget_size)`,
  `PutLengthPrefixedSlice(cfids_payload)`,
  `PutLengthPrefixedSlice(keys_payload)`, `return
  WriteTrace(trace)`). `TracePayloadType` is `enum : char` in
  `trace_replay/trace_replay.h:71–85`: `kMultiGetSize = 8`,
  `kMultiGetCFIDs = 9`, `kMultiGetKeys = 10`;
  `kTraceMultiGet = 13` (`trace_record.h:30`). The
  kTraceMultiGet decoder (`DecodeTraceRecord`,
  `trace_replay.cc:519–640`) reads the payload_map bits in
  ascending order — kMultiGetSize (`GetFixed32`), kMultiGetCFIDs,
  kMultiGetKeys (each `GetLengthPrefixedSlice`) — the same order
  the binary encodes, then splits the blobs back into per-key
  CF ids and keys. The two array overloads
  (`trace_replay.cc:879–909` and `912–940`) build the vectors
  and delegate, returning `Status::OK()` at once when
  `num_keys == 0` — matching the two in-binary delegate callers
  and their early returns.
- The earlier RE-001 tag-13 packet
  (`RE-001-tag13-query-2cf0-115`, merged) describes the same
  FDE in generic terms (count-mismatch prologue, two-string
  build, record loop, three callers) without naming the function
  or its payload encoding; this packet is the named RE-002
  reconstruction of that body, the same precedent as the
  tag-3/tag-4 RE-001 packets versus the Tracer::Write/Get
  reconstructions.
- The `+0x650` DB member holding the tracer pointer (null-checked
  at the DBImpl call site): its member name is not pinned here —
  caller logic, outside MultiGet's body, not modelled.
- The FDE order of the two array overloads is as observed in the
  binary (the `ColumnFamilyHandle**` overload at 0x61b4440, the
  single-`ColumnFamilyHandle*` overload at 0x61b4610); the
  upstream file lists them in the same order.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool is a behavioural Python model of the one
function only. `make verify` / `make test` / `make catalogue-check`
in a tooled environment is still owed upstream. Object dump format:
GNU objdump 2.42, Intel syntax. Upstream base: RocksDB v8.1.1
(librocksdb-sys 0.11.0+8.1.1 per the vendor census).
