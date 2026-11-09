# RE-002 · Node #115 RocksDB Tracer header/footer + write gate

Component: storage / tracing. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115's `rocksdb::Tracer` decide whether to trace an
operation, write one trace record, and frame a trace file — the four
functions `ShouldSkipTrace` (0x61b1930, 183 bytes), `WriteTrace`
(0x61b1a10, 182 bytes), `WriteFooter` (0x61b35c0, 349 bytes) and
`WriteHeader` (0x61b3860, 1491 bytes)? All four body hashes match the
vendor census exactly; the source hashes are reproduced by zeroing
the census relocation fields (see `functions.tsv`). The file-size
helper at 0x61b1910 (its own FDE, not in the census) is modelled as
part of `ShouldSkipTrace`.

## Answer (pinned)

**Tracer layout (56 bytes).** `+0x00` SystemClock\* (the timestamp
source); `+0x08..0x28` the 32-byte TraceOptions copied wholesale by
the constructor (0x61b3e60): word 0 is `max_trace_file_size`, word 1
the sampling period, word 2 the per-type skip flags, word 3 of
unknown role; `+0x28` `unique_ptr<TraceWriter>`; `+0x30` the sampling
counter (starts at 0). The size is pinned by `DBImpl::EndTrace`'s
`operator delete` with size `0x38` after destroying the Tracer.
Tracer is not polymorphic: there is no vtable at `+0x00`, and `~Tracer`
(D1, 0x61b18d0) destroys only the writer.

**ShouldSkipTrace.** Three gates, in order. (1) The file-size gate:
`trace_writer_->GetFileSize()` (TraceWriter vtable slot 4) is
compared strictly-greater with `max_trace_file_size`; a file exactly
at the limit still traces. (2) The per-type flag test: the type byte
minus 3 indexes a jump table (`.rodata 0x97c5f4`) — `kTraceWrite` (3)
tests bit `0x02`, `kTraceGet` (4) `0x01`, `kTraceIteratorSeek` (5)
`0x04`, `kTraceIteratorSeekForPrev` (6) `0x08`, `kTraceMultiGet`
(13) `0x10`. A set bit skips at once without advancing the counter;
types 0, 1, 2, 7–12 and ≥ 14 skip the flag test entirely and go
straight to (3). (3) The sampling counter: `counter += 1` (u64,
wrapping); while `counter < period` the trace is skipped; once the
counter reaches the period it resets to 0 and the trace is recorded.
Period 0 or 1 records everything that reaches the counter. The
counter is shared across all operation types.

**WriteTrace.** Encodes the Trace with `TracerHelper::EncodeTrace`
(0x61b1260, model copied from open PR #5863): timestamp u64 LE, type
byte, payload length u32 LE (low 32 bits of the size), payload bytes.
The encoded record is handed to `trace_writer_->Write(Slice)`
(TraceWriter vtable slot 2) and that Status is returned unchanged
(the writer's Status lands directly in the caller's out slot via the
passed-through sret pointer).

**WriteHeader.** Streams the 90-byte payload into a stack
`std::ostringstream`: magic `feedcafedeadbeef` + TAB +
`"Trace Version: "` + `0` + `"."` + `2` + TAB +
`"RocksDB Version: "` + `8` + `"."` + `1` + TAB +
`"Format: Timestamp OpType Payload\n"`. The version ints are
immediates in the binary (trace version "0.2", RocksDB version
"8.1"). The header Trace is `{ts = clock_->NowMicros(), type = 1
(kTraceBegin), payload_map = 0, payload}` and is returned via
`WriteTrace`. The payload round-trips through `ParseTraceHeader`
(0x61b4840, open PR #5866): field[1][15:] = `"0.2"` parses to 2,
field[2][17:] = `"8.1"` parses to 81.

**WriteFooter.** The footer Trace is `{ts = clock_->NowMicros(),
type = 2 (kTraceEnd), payload_map = 0, payload = ""}` (the binary
assigns the empty string via `_M_replace(0, 0, "", 0)` — a literal
no-op on the already-empty SSO string) and is returned via
`WriteTrace`.

**Timestamps.** Both header and footer stamp `ts` from the
SystemClock at Tracer+0x00 through a devirtualized wrapper chain:
each `SystemClockWrapper::NowMicros` (0x5d4d490) forwards to the
wrapped clock's `NowMicros` (vtable slot 19, 0x98), and the binary
unrolls the forwarding checks (WriteHeader: 13 layers, expected
function as an immediate; WriteFooter: fewer layers, expected
function from the GOT slot at 0x64ecf80). The observable result is
the innermost clock's `NowMicros()`.

## Cases

2,400 deterministic cases (`cases.tsv`, seeded generator in
`tools/tracer_header_footer115.py`): 600 `should_skip` (200 type
sweep with the file-size gate cycled below/equal/above the limit,
200 flag sweep for the five flag-tested types, 200 six-call sampling
sequences for periods 0/1/2/3/5/10), 600 `write_trace` (550 encoded
records over boundary timestamps/types/payloads plus 50 writer-error
rows), 600 `write_header` and 600 `write_footer` (the full encoded
record for 600 clock values each). 21 tests pass
(`tests/test_tracer_header_footer115.py`).

## Caller census

Whole-`.text` scan for E8 calls, E9 tail jumps and RIP-relative LEA
references landing on the targets, validated by decoding forward from
the enclosing FDE start with Capstone (`census.py`). 14 validated
sites: `ShouldSkipTrace` 5 (one per recording method — Write, Get,
IteratorSeek, IteratorSeekForPrev, MultiGet), `WriteTrace` 7 (the
same five plus WriteFooter and WriteHeader), `WriteFooter` 1 (the
unnamed 63-byte forwarder at 0x61b3720, called by
`DBImpl::EndTrace`), `WriteHeader` 1 (the Tracer constructor).

## Unknowns (kept separate from observations)

- The upstream `TraceOptions` field names: the four u64 words at
  Tracer+0x08..0x28 are copied wholesale from the TraceOptions
  argument; only word 0's role (`max_trace_file_size`) is pinned by
  use, words 1–2 by their roles in `ShouldSkipTrace`, and word 3 not
  at all. An upstream-source read was requested; if it has not
  landed, these names stay open.
- The upstream spelling of the version constants (separate ints 0/2
  and 8/1 in the binary vs. a version string or named constants in
  source) and of the skip-flags option.
- The identity of the 63-byte forwarder at 0x61b3720 (no
  vendor-census record, no symbol): it tail-calls `WriteFooter` and
  is called only by `DBImpl::EndTrace`.
- Whether the TraceOptions word at Tracer+0x20 is read by any other
  Tracer method. The five recording methods (Write/Get/IteratorSeek/
  IteratorSeekForPrev/MultiGet) are the natural next read, and are
  NOT reconstructed in this packet.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool is a behavioural Python model of the four
functions only. `make verify` / `make test` / `make catalogue-check`
in a tooled environment is still owed upstream. Object dump format:
GNU objdump 2.42, Intel syntax. Upstream base: RocksDB v8.1.1
(librocksdb-sys 0.11.0+8.1.1 per the vendor census).
