# Node 115 wide byte selection

This dependency-free `no_std` crate models the complete normal-return
computation of the leaf at `0x43352f0`, based on the authenticated static
packet [`RE-001-node115-wide-byte-select`](../../research/work-items/RE-001-node115-wide-byte-select/README.md).
The target is Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The model uses 32-byte little-endian slots. It checks the entire 256-bit index,
selects byte `31-index` for indices below 32, clears the result slot's upper
bytes, decrements depth, and preserves all other slots. Underflow preserves
upper RAX and memory while replacing AL with `0x2c`. `ScratchEffect` records
the 24-byte red-zone zeroing on normal paths. A too-short Rust slice is a
host-side input guard, not a target outcome.

The crate does not infer the source type, opcode identity, dispatch-table
consumer, original ABI, or protocol meaning. It is not a full-node
reconstruction or binary-equivalence claim. No captured executable was run
or emulated.

```sh
cargo test --offline --locked
cargo test --offline --locked --release
cargo fmt --all --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --release --lib --target x86_64-unknown-linux-gnu
```
