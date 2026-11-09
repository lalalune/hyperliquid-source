# Node #115 EVM read-precompile outcome names

This crate implements the exact name-to-tag visitor for
`ReadPrecompileResult`, using evidence from
`research/work-items/evm-call-outcome-codec-115/`. The packet is bound to Linux
x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The observed spellings and tags are `Ok` (0), `OutOfGas` (1), `Error` (2),
and `UnexpectedError` (3). Both visitor copies write tagged success word
`0x09 | (tag << 8)`. Matching is exact, case-sensitive, and full-length.

This crate models only variant-name recognition. `Ok`'s `(gas_used, bytes)`
payload, the enclosing MessagePack serializer, unknown-variant error payloads,
lossy UTF-8 allocation/free behavior, and caller ownership are not implemented.

Run from the repository root:

```sh
cargo test --offline --manifest-path src/node115-evm-precompile-outcome-names/Cargo.toml
cargo fmt --manifest-path src/node115-evm-precompile-outcome-names/Cargo.toml -- --check
cargo clippy --offline --manifest-path src/node115-evm-precompile-outcome-names/Cargo.toml -- -D warnings
```
