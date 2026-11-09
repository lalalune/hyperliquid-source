# Node #115 IndexedArtifactContentSerde variant visitor

This crate independently models the exact string-to-index visitor for
`IndexedArtifactContentSerde`, using
`research/work-items/RE-009-indexed-artifact-content-codec-115/` as its target
evidence. The packet is bound to Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The observed names in index order are `NodeMetadata`, `VisorMetadata`,
`HotfixMetadata`, `NodeArtifact`, and `PublisherBinaryMetadata`. Matching is
exact, case-sensitive, and full-length.

This crate covers only the `&str` visitor's successful name/index result and
unknown-name rejection. It does not implement the enum seed, JSON object/map
access, struct payload bodies, output layouts, allocator behavior, or serde
error payloads; the evidence packet explicitly stubs those areas.

Run from the repository root:

```sh
cargo test --offline --manifest-path src/node115-indexed-artifact-variant/Cargo.toml
cargo fmt --manifest-path src/node115-indexed-artifact-variant/Cargo.toml -- --check
cargo clippy --offline --manifest-path src/node115-indexed-artifact-variant/Cargo.toml -- -D warnings
```
