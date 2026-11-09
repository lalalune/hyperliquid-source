# Node 115 byte-prefix step projection

This `no_std` crate models the normal-return behavior of the bounded leaf at
`0x5434bb0`, based on the authenticated static packet
[`RE-001-node115-byte-prefix-step`](../../research/work-items/RE-001-node115-byte-prefix-step/README.md).
The packet binds the complete 127-byte FDE and 49 decoded instructions for
Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The model preserves the empty-input register-derived output bytes, the
nonempty cursor update, each observed byte-class pair, the `0xc0` special
tag-only write, and the relocated descriptor pointer as an opaque runtime
address. `Option` fields distinguish bytes left untouched from writes of zero.
It does not infer the descriptor's meaning, the prefix values' semantic names,
caller behavior, a wire format, or an original ABI. It is not a complete codec,
binary-equivalence result, or component gate.

The caller supplies the next byte and descriptor runtime address as inputs;
the empty-input path ignores the byte. Inputs are assumed valid and readable
as specified by the packet. No captured executable was run or emulated.

```sh
cargo test --offline --locked
cargo test --offline --locked --release
cargo fmt --all --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --release --lib --target x86_64-unknown-linux-gnu
```
