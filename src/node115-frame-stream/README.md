# Node 115 offline frame stream

This crate composes the existing `node115-tcp-frame-plan` and
`node115-lz4-decode` reconstructions into an owned, one-frame byte-stream
adapter. It advances issue #3911; it does not close that issue or claim the
complete TCP component.

`FrameReader::feed` accepts fragments and reports how many bytes it consumed.
An empty fragment means no progress, not EOF. `eof` explicitly signals end of
input. A completed or failed reader is terminal; callers create a new reader
for a subsequent frame. This is a local API policy, not a claim about how a
native connection recovers after an error. Extra input remains with the caller.

The selected node 115 evidence shows a five-byte header, an inclusive wire
length limit, flag 1 selecting the LZ4 path, bounded body reads and the same
limit passed to the transform. The adapter uses the existing reconstructions
for these policies. It does not model native reactor scheduling, timeouts,
socket error payloads, allocator ABI, concurrent connections or complete
connection recovery. `Allocation` reports failure of the initial wire-buffer
reservation; the LZ4 dependency retains its own error and allocation behavior.

Run offline with an already installed Rust 1.95 toolchain:

```sh
cargo +1.95.0 test --locked --offline --manifest-path src/node115-frame-stream/Cargo.toml
```
