# Node #115 HIP-3 disabled-state enum codec

This crate independently models the four `disabled_state` enum tags and their
exact name mapping, along with the observed JSON unit-variant output. It is a
bounded Rust implementation for evidence packet RE-007, not a full HIP-3 DEX
registry implementation.

The target is Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The
packet at `research/work-items/RE-007-hip3-disabled-state-codec-115/` records
14 function bodies, jump tables, name pools and target-interpreted vectors.
Observed tag/name pairs are `0/Na`, `1/UserDisabled`,
`2/ValidatorDisabled`, and `3/m`. The tagged visitor success word is
`0x09 | (tag << 8)`.

The crate covers exact name lookup, tag lookup, tagged success-word formation
and appending the quoted JSON variant text. Its tests check all four pairs and
reject a case-folded or prefix match.

It does not implement unknown-variant error formatting, lossy UTF-8 ownership,
JSON buffer capacity behavior, the enclosing MessagePack record, callee
serialization, or state transitions. In particular, the record writer's
MessagePack callees remain stubs in the evidence packet, so no record bytes are
claimed here.

Run the focused checks from the repository root:

```sh
cargo test --offline --manifest-path src/node115-hip3-disabled-state-codec/Cargo.toml
cargo fmt --manifest-path src/node115-hip3-disabled-state-codec/Cargo.toml -- --check
cargo clippy --offline --manifest-path src/node115-hip3-disabled-state-codec/Cargo.toml -- -D warnings
```
