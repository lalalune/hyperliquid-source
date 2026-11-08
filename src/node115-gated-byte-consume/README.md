# Node 115 gated byte consume

This dependency-free `no_std` crate models the normal-return behavior of the
leaf at `0x232b1b0`, using the authenticated static packet
[`RE-001-node115-gated-byte-consume`](../../research/work-items/RE-001-node115-gated-byte-consume/README.md).
The target is Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The model preserves the mode-1 counter overflow and old-count limit test,
including the stored increment on limit rejection; the empty-input result and
additional-byte value; and the one-byte cursor transition and raw success tag.
`Option` fields distinguish output bytes left untouched from writes of zero.
It does not assign source names or types, infer domain meaning, or claim the
surrounding subsystem is reconstructed.

This safe API assumes readable nonoverlapping memory on the byte-consume path.
It is not the original pointer ABI, a full decoder, a binary-equivalence
claim, or a component gate. No captured executable was run or emulated.

```sh
cargo test --offline --locked
cargo test --offline --locked --release
cargo fmt --all --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --release --lib --target x86_64-unknown-linux-gnu
```
