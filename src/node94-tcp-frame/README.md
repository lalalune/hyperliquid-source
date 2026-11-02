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
be restored. This layer does not implement the target's timer wrapper,
statistics, peer discovery, handshake, reconnect logic or message protocol.
The target's 20/40-second reader and selected 20/60-second writer timing
behavior remains separate work; an untimed frame stream is not a finished
node transport.

The [stream evidence packet](../../research/work-items/RE-012-tcp-stream-94/README.md)
records the selected read/write loops and the tested boundary. This component's
new lockfile is a real build lock, not a recovered node dependency graph;
in particular its `bytes` and `pin-project-lite` versions are not claimed to
match the target.

Run `cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features`
to include the stream controls. They use deterministic scripted
I/O, not public network connections or captured-node execution.

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
