# RE-002 · Node #115 RocksDB TracerHelper codec

Component: storage / tracing. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How do node #115's `rocksdb::TracerHelper` codec functions work:
`ParseVersionStr`, `EncodeTrace`, `DecodeTrace` and `DecodeHeader`?
Four functions, `0x61b10f0..0x61b18a5`, all with vendor-census records
and all body hashes matching exactly (see `functions.tsv`); all four
source hashes are reproduced by relocation zeroing (DecodeHeader needs
the kind-42 mov restoration at offset 179).

## Answer (pinned)

**Trace layout.** A `Trace` is 48 bytes: `timestamp` (u64) at `+0x00`,
a `type` byte at `+0x08`, and a `std::string payload` at `+0x18`
(ptr `+0x18`, size `+0x20`, capacity `+0x28`). The encoded record is
`timestamp` (8 bytes LE) | `type` (1 byte) | payload length (u32 LE) |
payload bytes — 13 bytes of header plus the payload.

**ParseVersionStr** (`0x61b10f0`, 355 B) takes a version string and an
`int*`. It requires at least two `'.'` characters: no dot at all returns
`kCorruption` with `Corrupted trace file. Incorrect version format.`
(47 bytes, `.rodata 0x96b278`); exactly one dot returns `kCorruption`
with the same text *without* the trailing period (46 bytes, `.rodata
0x95df68`). Otherwise it walks the whole string: `'.'` bytes are
skipped, digit bytes accumulate `value = value * 10 + digit` in 32 bits
(wrapping), and any other byte returns `kCorruption` with the 46-byte
message. The value is the decimal concatenation of *every* digit in the
string — `b"1.0.0"` gives 100, `b"1.2.3.4"` gives 1234 — not a tuple.
`b"42949672.9.5"` (digits 4294967295) wraps to −1 as a signed int, and
`b".."` parses to 0 and returns OK. Its only caller is
`TracerHelper::ParseTraceHeader` (`0x61b4840`), which calls it twice.

**EncodeTrace** (`0x61b1260`, 323 B) appends to the output string, in
order: the 8 timestamp bytes, the type byte, the payload size as a u32
(the low 32 bits of the `std::string` size — a payload of 2³² bytes or
more would truncate the field; modeled, untestable by construction),
then the payload bytes. Each append carries the `std::string` capacity
guard (`0x3fffffffffffffff − size <= chunk` throws `length_error`),
modeled in the tool. Five direct callers: `Tracer::WriteTrace`
(`0x61b1a57`), `BlockCacheTraceWriterImpl::WriteHeader` (`0x61bb28f`)
and `::WriteBlockAccess` (`0x61bba0e`), `IOTraceWriter::WriteIOOp`
(`0x61bc790`) and `::WriteHeader` (`0x61bcc0e`).

**DecodeTrace** (`0x61b13b0`, 652 B) decodes a record into a `Trace`.
An input of 7 bytes or fewer returns `kIncomplete` with `Decode trace
string failed` (26 bytes, `.rodata 0x44a5c5`) and leaves the trace
untouched. Otherwise the timestamp is read first — and an input of
8–12 bytes then fails with the same `kIncomplete` *after* the timestamp
has been written, with type and payload untouched. On success the type
byte comes from byte 8 and the payload is the whole remainder from byte
13. The 4-byte length field at bytes 9–13 is skipped and **never read
or validated**: a record whose declared length disagrees with the
actual trailing bytes still decodes (verified: declared 0 and declared
`0xffffffff` both return the full remainder as the payload). Callers:
`DecodeHeader` itself (`0x61b1699`) and `ReplayerImpl::ReadTrace`
(`0x61fe5e2`).

**DecodeHeader** (`0x61b1670`, 565 B) first decodes the record with
`DecodeTrace` (status kept in a temporary), then requires the trace
type to be exactly 1 — otherwise `kCorruption` with `Corrupted trace
file. Incorrect header.` (39 bytes, `.rodata 0x96b2a8`), discarding the
decode status — and requires the payload to be at least 16 bytes long
and start with the magic `feedcafedeadbeef`, otherwise `kCorruption`
with `Corrupted trace file. Incorrect magic.` (38 bytes, `.rodata
0x9617a8`). The magic is the global `std::string` at `0x6508800`,
built by the static initializer at `0x61b7068` from 16 bytes at
`.rodata 0x452c50`. Anything after the 16 magic bytes is unchecked
here; the version text after the magic is parsed by the caller
(`ParseTraceHeader`). When both checks pass, the `DecodeTrace` status
is returned as-is — including its `kIncomplete` error when the decode
failed but the incoming trace already had type 1 and a magic payload.
Both live callers zero the type byte first (`ReplayerImpl::ReadHeader`
stores 0 at the type byte before the call at `0x61fe266`, the only
direct caller), so in the live path a truncated record reports the
header error, not the decode error.

## Cases

2,400 deterministic cases (`cases.tsv`, seeded generator in
`tools/tracer_helper115.py`): 600 `parse_version_str` (digit
concatenation, both error messages, 32-bit wrap, bad-byte rejection),
600 `encode_trace` (exact byte layout, round-trip through decode),
600 `decode_trace` (lying length fields, truncation at every length
0–12 with the partial-mutation rule, empty payload), 600
`decode_header` (type/magic gates, both error messages, the
`kIncomplete`-survives edge). 16 tests pass
(`tests/test_tracer_helper115.py`).

## Caller census

Whole-`.text` scan for E8 calls, E9 tail jumps and RIP-relative LEA
references landing on each target, validated by decoding forward from
the enclosing FDE start with Capstone (`census.py`). 10 validated
sites: ParseVersionStr 2, EncodeTrace 5, DecodeTrace 2, DecodeHeader 1;
no tail jumps or LEA references to any of the four.

## Unknowns (kept separate from observations)

- The upstream `TraceType` enumerator names for the type-byte values
  (in particular which name value 1 carries). The binary only shows the
  numeric check `type == 1`; the names are not recoverable from the
  binary alone. An upstream-source read was requested; if it has not
  landed, this stays open.
- The default-constructed `Trace`'s type byte. Both live callers zero
  it explicitly, so the live initial value is 0; whether the in-class
  default differs is not pinned.
- `TracerHelper::ParseTraceHeader` (`0x61b4840`) — the only caller of
  `ParseVersionStr` — is not reconstructed here; how the parsed version
  int is consumed is the natural follow-up.
- The payload-length u32 truncation for payloads ≥ 2³² bytes is modeled
  from the `mov` instruction but untestable by construction.
- The `Tracer` methods that call `EncodeTrace` and the replayer methods
  that call `DecodeTrace`/`DecodeHeader` are separate FDEs and are not
  reconstructed in this packet.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool is a behavioural Python model of the four functions
only. `make verify` / `make test` / `make catalogue-check` in a tooled
environment is still owed upstream. Object dump format: GNU objdump
2.42, Intel syntax. Upstream base: RocksDB v8.1.1
(librocksdb-sys 0.11.0+8.1.1 per the vendor census).
