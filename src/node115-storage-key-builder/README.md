# Node115 storage-key builder

An independently authored, allocation-using `no_std` implementation of the
bounded node115 relation at `0x3d47d20..0x3d47ebb`. It produces the selected
52-byte storage-key suffix from a 20-byte address and four source-order qwords.
The optional full-key helper prepends a caller-supplied prefix.

This is not the original Rust ABI, the complete `eth_getStorageAt` adapter, a
runtime prefix claim or a whole-node implementation. See the evidence packet at
[`research/work-items/RE-011-node115-storage-key-suffix`](../../research/work-items/RE-011-node115-storage-key-suffix/README.md)
and its pre-implementation contract.

The selector conversion that creates the four source-order qwords remains a
separate boundary. Allocation failure, pointer aliasing, the slow synchronization
paths and the complete JSON-RPC response path are excluded.

```sh
cargo test --offline --locked
cargo test --offline --locked --release
cargo fmt --all --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --release --lib
```

The tests consume all 258 committed vectors from the existing RE-011 storage-read
evidence packet. That comparison validates a static mathematical relation; it
does not execute the captured node.
