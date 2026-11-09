# Node115 digest-reference handoff

Dependency-free owned logical projection of selected tracker extraction, current-registry member remapping, stable queue draining, and the replay comparison prefix.

The target-bound contract, prior-art credit, static evidence, 15 hand-derived test expectations and explicit unclosed dependencies are in [`RE-017-node115-digest-reference-handoff`](../../research/work-items/RE-017-node115-digest-reference-handoff/README.md).

This crate starts from existing logical tracker/registry state. It does not determine quorum, authenticate signatures, choose timer-eligible heights, implement native layouts, or claim full replay equivalence. Its membership set is an observation, not a vote count. The whole sink batch precedes the comparison prefix; a first mismatch stops only the modeled comparisons.

```sh
cargo test --offline --manifest-path src/node115-digest-reference-handoff/Cargo.toml
cargo test --offline --release --manifest-path src/node115-digest-reference-handoff/Cargo.toml
cargo clippy --offline --manifest-path src/node115-digest-reference-handoff/Cargo.toml --all-targets -- -D warnings
```
