# Node #115 margin-mode codec

This crate models the exact `normal`, `noCross`, and `strictIsolated` names,
their visitor success words, and MessagePack fixstr output from
`research/work-items/RE-007-margin-mode-codec-115/`. Evidence is bound to
Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The packet observes serializer tags 0 and 1 selecting `normal` and `noCross`;
all other raw bytes select `strictIsolated`. Exact-name visitors accept only
the three complete, case-sensitive spellings. Unknown-variant error objects,
lossy UTF-8 allocation/free internals, and vector reserve/growth callees are
not modeled.

Run from the repository root:

```sh
cargo test --offline --manifest-path src/node115-margin-mode-codec/Cargo.toml
cargo fmt --manifest-path src/node115-margin-mode-codec/Cargo.toml -- --check
cargo clippy --offline --manifest-path src/node115-margin-mode-codec/Cargo.toml -- -D warnings
```
