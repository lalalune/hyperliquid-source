# node115-hpack

Encoder-only HPACK reconstruction for Linux x86-64 node #115
(`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

This is an independent crate. It is not wired into `src/net-utils`, and it does
not change `research/progress.json`, `research/components.json`, or any
component gate.

## Scope

Implemented from the PR #5981 evidence:

- HPACK Huffman bit packing (`0x179d760`), including all-ones padding.
- Length-prefixed Huffman string literals (`0x17acf90`).
- Literal headers with an indexed name (`0x17ad380`).

Excluded: the decoder, dynamic-table functions (`0x17aca30`, `0x17acc80`,
`0x17ac730`), the header-block encoder (`0x17ad510`), HTTP/2 I/O, and live
target execution. This crate makes no binary-equivalence claim.

## Inputs

- PR #5981: `research/work-items/transport-hpack-encode-115/` (encoder evidence,
  Huffman table, and frozen sampled cases).
- PR #5998: `research/work-items/transport-hpack-decode-115/` (decoder context
  only; decoder behavior is not implemented here).
- `research/work-items/RE-002-node115-rust-h2-hpack-references/` (static
  references; no runtime implementation).

## Tests

The frozen test reads the sampled cases from
`research/work-items/transport-hpack-encode-115/cases-sample.tsv` and checks
append-only output, destination-prefix preservation, and all 3,932 sampled
encoder cases.

```sh
cargo test --offline --manifest-path src/node115-hpack/Cargo.toml
```
