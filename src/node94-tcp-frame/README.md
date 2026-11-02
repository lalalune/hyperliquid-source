# Node #94 TCP frame codec

This standalone Rust crate reconstructs the bounded, offline TCP frame format
established for Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It is independently authored from retained static evidence and does not contain
socket code, peer networking, a production transport client, or captured-target
execution.

The initial public contract is the verified five-byte header:

```text
+0..+4  payload length, big-endian u32
+4      compression flag; exactly 1 means LZ4, every other value means raw
```

`Header::decode` requires all five bytes and reports an explicit header EOF.
`Header::encode` preserves the original flag byte. `Header::from_payload_len`
rejects lengths that cannot be represented by the wire u32.

`FrameLimits` applies the reader's inclusive `declared <= max_len` admission
and the same inclusive gate to an LZ4 uncompressed-size prefix. `ChunkPlan`
implements the verified decimal 4,000,000-byte cap without allocating a list;
readers apply it to the payload and writers apply it to the complete frame.
No target-wide numeric maximum was established, so the crate does not invent
one: callers must provide a bounded `FrameLimits` value appropriate for their
offline input and memory budget.

The writer compression policy is also exposed without I/O: compress at lengths
at least 1,025 unless `(stream_field & !1) == 3998`, which excludes observed
u16 values 3998 and 3999. Separate NodePort evidence contains those two port
values, but the meaning of the stream field at every writer call remains an
inference. Checked sizing helpers preserve the observed
`len * 110 / 100 + 20` output window, `+24` allocation, 65,535-byte hash-table
switch, and truncating little-endian u32 size prefix.

## Asynchronous stream I/O

Enable `stream` to read and write frames through caller-owned
`tokio::io::AsyncRead` / `AsyncWrite` values. It pins Tokio 1.44.2, the version
identified by the target's read-buffer evidence. The default build remains an
offline codec without Tokio.

```rust,ignore
use node94_tcp_frame::{FrameLimits, stream};

// `io` is an already-established, caller-owned async byte stream.
stream::write_frame(&mut io, b"payload", stream_field).await?;
let frame = stream::read_frame(&mut io, FrameLimits::new(max_payload)).await?;
```

The reader fills the five-byte header before admitting or allocating its
payload, consumes payload chunks of at most 4,000,000 bytes, and leaves the
next frame untouched. Only flag 1 selects decompression. An empty or truncated
stream returns `UnexpectedEof`; a zero-progress write returns `WriteZero`.
Partial reads/writes and `Pending` preserve progress within the same future.
The writer chunks the entire frame including its header; it does not flush or
close the caller's stream.

These operations are **not cancellation safe**. After a cancelled or failed
operation, discard the connection unless its frame boundary can independently
be restored. This layer does not implement statistics, peer discovery,
handshake, reconnect logic or message protocol. The `stream` functions are
untimed; deadline-aware operations are available separately below.

The [stream evidence packet](../../research/work-items/RE-012-tcp-stream-94/README.md)
records the selected read/write loops and the tested boundary. This component's
new lockfile is a real build lock, not a recovered node dependency graph;
in particular its `bytes` and `pin-project-lite` versions are not claimed to
match the target.

Run `cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features`
to include the stream and deadline controls. They use deterministic scripted
I/O, not public network connections or captured-node execution.

## Header and chunk deadlines

Enable `timed-stream` to use `deadlines::read_frame` and
`deadlines::write_frame`. This also enables `stream` and Tokio's time feature.
An active Tokio runtime with its time driver enabled is required.

```rust,ignore
use node94_tcp_frame::{FrameLimits, deadlines};

// The header flag and write override are explicit caller decisions.
deadlines::write_frame(&mut io, b"payload", stream_field, None).await?;
let frame = deadlines::read_frame(&mut io, FrameLimits::new(max_payload), true).await?;
```

With header timing enabled, the five-byte header has 40 seconds. Disabling
that flag leaves only the header untimed. Every payload chunk has a fresh
20-second deadline. Writes use a fresh 20-second deadline per complete-frame
chunk unless the caller supplies a `Duration` override; the observed
60-second override is tested. Partial I/O within a chunk does not reset its
deadline. Completed I/O, including an I/O error, wins over an elapsed timer on
the same poll, matching the selected target branches and Tokio 1.44.2.

`DeadlineError::Elapsed` reports the header or chunk and configured limit.
This is a new Rust API, not the target's error ABI. Caller defaults for the
header flag, arbitrary floating-point duration conversion, timer-driver
internals, target cleanup and logging remain unqualified. Timeout can leave a
partially consumed or transmitted frame; the cancellation rule above still
applies. These operations do not constitute a network-compatible transport.

The [deadline evidence packet](../../research/work-items/RE-012-frame-deadlines-94/README.md)
records the conditional header path, chunk reset, timer relocation and poll
ordering, with instruction corruptions and compiled negative controls.

## Initial greeting frame exchange

With `timed-stream` enabled, `greeting::exchange_frame` sends the initial
post-connect request and receives its reply frame over a caller-owned stream:

```rust,ignore
use node94_tcp_frame::greeting::{self, Request};

let reply = greeting::exchange_frame(&mut io, Request {
    first: first_greeting_byte,
    second: second_greeting_byte,
    time_header: time_reply_header,
}).await?;
// Validate reply.payload with the peer protocol decoder before accepting it.
```

The request is exactly `00 00 00 03 00 first second 00`. Both supplied bytes
are preserved. A separate flag controls the reply header's 40-second timeout;
it is not the third transmitted byte. The write uses 20 seconds. Reply payloads
and LZ4 output have the observed inclusive limit of 1,000 bytes when `first`
is zero, otherwise 3,000,000,000 bytes. This is the target caller's limit;
callers must account for the potentially large allocation in their resource
policy. No protocol meaning or valid configuration range is assigned to either
request byte here.

`exchange_frame` leaves the reply payload uninterpreted. `greeting::exchange`
also runs the mode-1 wire decoder and returns `greeting::reply::Decoded`.
Neither operation authenticates or accepts a peer. Caller retry and acceptance
policy remain separate work. Send, receive and decode failures are distinguished;
cancellation retains the partial-I/O limitations above.
The [greeting exchange evidence](../../research/work-items/RE-012-greeting-frame-exchange-94/README.md)
binds this specific caller and records its frame-only scope.

## Greeting reply decoding

`greeting::reply::decode(payload, logical_limit)` handles all six outer wire
variants, including all three nested hash variants:

| Wire selector | Decoded fields |
| --- | --- |
| Outer 0 | Byte vector, u64, nested hash variant |
| Outer 1 | Three u64 values in wire order |
| Outer 2–5 | Unit variants |
| Nested 0 | 32 raw bytes and one map |
| Nested 1 | 32 raw bytes and two maps |
| Nested 2 | Three records, each containing two variable-width integers and 2,048 raw bytes |

Map keys are 20 raw bytes. Values contain eight variable-width u64s and one
raw byte. Maps return keys in lexicographic order and keep the last value for
a repeated key. The decoder tracks the target's logical charge independently
of byte consumption, including count reservations, per-row refunds and fixed
field charges. A short field or rejected integer retains the reached cursor
and charge. Nonminimal integer encodings and trailing bytes are accepted.

`Decoded` reports consumed bytes, remaining bytes and logical charge. `Failure`
reports the actual cursor and charge, rather than the target wrapper's separate
zero consumed-count diagnostic on error. Field names describe wire positions;
the original Rust types, enum layout, B-tree nodes, allocation behavior and
error text are not reproduced. The parser reuses this repository's independent
`hl-bincode-varint` component. The default codec build still enables neither
that dependency nor Tokio.

The [reply evidence packet](../../research/work-items/RE-012-greeting-reply-94/README.md)
retains native bindings, independent frozen-fixture comparisons and compiled
negative controls. Valid decoding supplies data for future peer checks; it does
not establish current-network compatibility or a runnable node.

## LZ4 correspondence and limits

The decoder pins the MIT-licensed crate `lz4_flex = 0.11.6` in both
`Cargo.toml` and `Cargo.lock`. The downloaded crates.io archive has SHA-256
`373f5eceeeab7925e0c1098212f2fbc4d416adec9d35051a6ab251e824c1854a`,
matching the archive identified by the static evidence. The component calls
that version's `block::uncompressed_size` and `block::decompress`, preserving:

- a little-endian u32 size prefix and `ExpectedAnotherByte` for 0–3 bytes;
- the inclusive configured decoded-size limit before output allocation;
- the five observed error classes (`OutputTooSmall`, `LiteralOutOfBounds`,
  `ExpectedAnotherByte`, `OffsetZero`, `OffsetOutOfBounds`);
- truncation to the produced length without requiring it to equal the prefix.

This version pin is source/API correspondence, not a claim that this crate's
compressed bytes, allocator behavior, optimized copy paths, panic formatting,
or generated machine code are binary-identical to node #94. The target's full
Cargo feature set, compiler flags, allocator, compressor bodies, and every
decoder fast path remain unverified. Default `lz4_flex` 0.11.6 features are
locked here; only the block API behavior above is claimed.

`encode_frame` emits a complete offline frame. It uses flag 0 with an exact raw
copy below the threshold or for the excluded stream-field values; otherwise it
calls the pinned crate's `block::compress_prepend_size` and emits flag 1. The
final wire payload must fit a u32, and `EncodedFrame::chunks` plans decimal
4,000,000-byte writes over the header plus payload. Allocation failure and the
target's precise panic or error construction for impossible oversized writer
inputs are not claimed.

The integration tests roundtrip complete frames at 0/1 bytes, on both sides of
the 1,025-byte compression threshold, on both sides of the 65,535-byte table
switch, and on both sides of the 4,000,000-byte reader/writer chunk boundaries.
Independent negative controls mutate header lengths, compression flags, prefix
endianness, match offsets, and every truncation point of raw and compressed
frames. A bounded deterministic mutation corpus also checks that arbitrary
short inputs never panic and that repeated decoding is stable.

Build from the repository root with the pinned toolchain:

```sh
cargo build --locked --manifest-path src/node94-tcp-frame/Cargo.toml
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml
cargo clippy --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node94-tcp-frame/Cargo.toml -- --check
```

This component is a partial transport reconstruction. Passing its offline tests
does not establish TCP runtime compatibility, target binary identity, complete
transport recovery, or a repository progress gate.

The initial caller routing is available as `Request::route_reply` and
`greeting::exchange_routed`. It distinguishes continuation of the existing
stream, a data reply requiring further state validation, and four named peer
rejections. The first request byte is kept raw: data replies test bit zero,
while the empty-success reply requires the whole byte to be zero. The routed
exchange preserves decoded metadata. Dispose of the borrowed stream on any
error; these routes do not establish peer authentication or state validity.
See [the routing evidence](../../research/work-items/RE-012-greeting-policy-94/README.md).

`evm_kvs::decode` (with `timed-stream`) decodes the subsequent EVM KVS message
payloads: ordered raw byte-array pairs or the unit message. It preserves row
order, duplicate keys, logical charging, cursor errors and suffix metadata.
It does not write a database or validate received state. The binary evidence
and checkpoint context are in
[RE-012 EVM KVS messages](../../research/work-items/RE-012-evm-kvs-message-94/README.md).

The separate `evm_kvs::TransferSize` guard counts cumulative raw row bytes and
rejects a transfer at 100,000,000,000 bytes. It preserves the updated count on
rejection. Call it before applying a decoded batch, and abandon the transfer
on error; it does not write to a database.
