# Node #115 Spot/Mark/ExternalPerp codec

This crate models the exact `Spot`, `Mark`, and `ExternalPerp` names, their
tagged visitor success words, and MessagePack fixstr output from
`research/work-items/RE-015-spot-mark-codec-115/`. The evidence packet is bound
to Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The target serializer maps raw tag 0 to `Spot`, tag 1 to `Mark`, and every
other byte value to `ExternalPerp`. The exact-name visitor accepts only the
three complete, case-sensitive spellings. The crate does not model the
unknown-variant error payload or the vector reserve/growth callees.

Run from the repository root:

```sh
cargo test --offline --manifest-path src/node115-spot-mark-codec/Cargo.toml
cargo fmt --manifest-path src/node115-spot-mark-codec/Cargo.toml -- --check
cargo clippy --offline --manifest-path src/node115-spot-mark-codec/Cargo.toml -- -D warnings
```
