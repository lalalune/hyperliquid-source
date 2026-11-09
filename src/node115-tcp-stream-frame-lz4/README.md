# node115 TCP stream frame and LZ4 adapter

An offline Rust `Read` adapter that composes the separately target-bound
five-byte TCP frame policy with the node #115 size-prefixed LZ4 decoder. It
handles short reads, enforces the inclusive wire-size limit, requests payload
intervals no larger than 4,000,000 bytes, and decodes only when the captured
flag equals one.

```sh
cargo +1.95.0 test --locked --offline --manifest-path src/node115-tcp-stream-frame-lz4/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-tcp-stream-frame-lz4/Cargo.toml
```

This new API uses `std::io::Read`, two explicit caller limits and ordinary
`Vec` allocation. It is not the captured async future, does not open a socket,
and does not claim the original I/O error, allocation, cancellation or
connection lifecycle. `FrameError::disposition` describes this adapter's
consumption state: a full compressed payload leaves the stream at the next
frame boundary even when decompression fails; an incomplete or undrained frame
must be discarded. See the [target evidence and limits](../../research/work-items/RE-012-tcp-stream-frame-lz4-115/README.md).
