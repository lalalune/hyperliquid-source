# Node 115 twenty-byte sequence equality

This dependency-free `no_std` crate provides a safe Rust model of the leaf at
`0x5436860`, based on the authenticated static packet
[`RE-001-node115-slice20-equal`](../../research/work-items/RE-001-node115-slice20-equal/README.md).
The packet binds the complete 86-byte function body, its 28 instructions and
the two caller sites in the raw-signature-tracker source context. The target is
Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The model returns false for unequal record counts, true for equal empty
sequences, and otherwise compares every byte of each corresponding 20-byte
record, stopping at the first mismatch. The function meaning and record type
are unknown, so the API keeps the records opaque. It does not claim the
original pointer/count ABI, fault behavior, constant-time comparison,
caller-level policy, binary equivalence, or component completion.

The slice API models safely constructible sequences; it does not emulate
arbitrary u64 pointer/count pairs or invalid memory. The packet's large-count
loop claim is algebraic under its stated valid-memory premise, not established
by allocating huge test fixtures. No captured executable was run or emulated.

```sh
cargo test --offline --locked
cargo test --offline --locked --release
cargo fmt --all --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --release --lib --target x86_64-unknown-linux-gnu
```
