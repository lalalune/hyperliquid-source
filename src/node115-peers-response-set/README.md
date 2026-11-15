# node115-peers-response-set

Offline Rust path from the bytes of one TCP frame to the normalized peer set that node #115's
selected Peers response wrapper (`0x2dd2980`) builds. Target SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. New code is MIT.

```rust
use node115_peers_response_set::decode_frame;
let (decoded, rest) = decode_frame(&frame_bytes)?;   // 5-byte header, optional LZ4, rows, normalize
decoded.set.peers();     // rows ordered by the four key bytes, one row per key
decoded.set.storage();   // Small (<= 64 kept rows) or Tree (> 64)
decoded.set.source_index(i); // which wire row was kept for peers()[i]
```

Frame reading, LZ4 and row decoding are the existing crates `node115-tcp-stream-frame-lz4`,
`node115-gossip-response-composed` and what they depend on, used through path dependencies and not
modified. The request limit 10,000 is passed to all three places that take it. The new code is
`normalize`: sort by the key bytes, keep the last row of every repeated key, choose small set or
tree. Which row survives for a repeated key at any input length is argued in
[TIES.md](../../research/work-items/RE-012-node115-peers-response-set/TIES.md); the rest of the
evidence, credits and limits are in the
[packet README](../../research/work-items/RE-012-node115-peers-response-set/README.md).

Not claimed: the native async ABI, allocation or unwind behaviour, what the key, flag and scalar
mean (no addresses or ports are read out of them), peer identity or signatures, any network
behaviour, or that the node itself rejects the other response kinds for a Peers request (that
rejection is this API's policy). Bytes after the vector are reported, not rejected.

```sh
cargo test --offline --locked --manifest-path src/node115-peers-response-set/Cargo.toml
```

This test is not run by `make test`, which does not discover Rust crates. The repository's pinned
toolchain is 1.95.0; the results in the packet were obtained with the `cargo` on this machine
(1.99.1).
