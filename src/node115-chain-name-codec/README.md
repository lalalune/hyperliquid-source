# Node #115 chain-name codec

This crate independently models the four observed chain-name tags and exact
wire spellings, their visitor success words, and MessagePack fixstr output.
Evidence is in `research/work-items/RE-015-chain-codec-115/`, bound to Linux
x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The target packet establishes `0=Local`, `1=Sandbox`, `2=Testnet`, and
`3=Mainnet`. The serializer writes `0xa5` plus `Local`, or `0xa7` plus one of
the three seven-byte names. Tag lookup returns `None` outside the enum domain;
the native serializer's unchecked jump table is only defined for valid enum
tags.

Unknown-variant error construction and the vector growth callee bodies remain
outside the packet's reconstruction. This crate therefore does not claim exact
serde error values, reserve calls, allocation behavior, caller ownership, or
which configuration fields use the enum.

Run from the repository root:

```sh
cargo test --offline --manifest-path src/node115-chain-name-codec/Cargo.toml
cargo fmt --manifest-path src/node115-chain-name-codec/Cargo.toml -- --check
cargo clippy --offline --manifest-path src/node115-chain-name-codec/Cargo.toml -- -D warnings
```
