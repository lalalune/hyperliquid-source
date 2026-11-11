# Node115 MessagePack Action marker dispatch

This crate expresses the bounded marker-dispatch path documented in
[RE-010](../../research/work-items/RE-010-action-msgpack-identifier-115/README.md),
bound to node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
It covers marker normalization, scalar/string/binary/map/array/extension routes,
length and payload EOF cursor behavior, the binary caller flag, nesting-depth
handling, invalid UTF-8 fallback and zero-length container requirement.

The `Visitors` trait is an independently authored adapter boundary, not the
node's private ABI. Scalar decoding, map/sequence/ext payload semantics,
callee-owned errors and cleanup landing pads remain outside this component.
The caller flag's meaning and the complete `Action` value are not inferred.
No captured code is executed or emulated by the Rust crate.

Run with Rust 1.95.0 or newer:

```sh
cargo test --offline --locked --manifest-path src/node115-action-msgpack-identifier/Cargo.toml
```
