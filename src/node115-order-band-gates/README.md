# Node 115 order-band and spot admission gates

This dependency-free `no_std` model ports the bounded decision rules from the
authenticated static packet
[`RE-004-order-band-gates-115`](../../research/work-items/RE-004-order-band-gates-115/README.md).
The target is Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The crate models the shared binary64 order-price band, its scaled refusal
payload, the perp exemption's low-byte test, spot-chain short-circuit order,
and the final spot price cap. It accepts the exemption and map/tree probe
outcomes as explicit inputs because those callees are stubs in the evidence
packet; it does not recreate their data structures or infer their key meaning.

This is not the original ABI, a complete order admission subsystem, or a
binary-equivalence result. The comparisons do not establish how `price`,
`reference`, or `distance` are produced by surrounding callers. No captured
executable was run or emulated.

```sh
cargo test --offline --locked
cargo test --offline --locked --release
cargo fmt --all --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --release --lib --target x86_64-unknown-linux-gnu
```
