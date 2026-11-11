# Node #115 selected RNG refill fallback

This independently authored, dependency-free `no_std` Rust library computes
the four-block, six-double-round fallback relation mapped in PR #4230 for node
#115. `refill(&mut State) -> [u32; 64]` accepts eight key words and four tail
words; the first two tail words form a little-endian 64-bit block counter. It
returns four blocks in order, increments that counter by four with wrapping,
and preserves the key and the other two tail words.

This is an owned numerical API. Correspondence assumes valid, non-overlapping
native input/output memory, normal return, the six-double-round caller and the
fallback path being selected. It does not choose CPU features, obtain entropy,
reseed, reproduce accelerated paths or establish native runtime or binary
identity. No captured target code, networking or chain action is run.

The [evidence packet](../../research/work-items/RE-001-node115-rng-refill-rust/README.md)
credits and rechecks the target-bound prior mapping and records independent
synthetic source-comparison results. Component gates remain unchanged.

```sh
cargo +1.95.0 test --offline --manifest-path src/node115-rng-refill/Cargo.toml
cargo +1.95.0 test --offline --release --manifest-path src/node115-rng-refill/Cargo.toml
cargo +1.95.0 clippy --offline --manifest-path src/node115-rng-refill/Cargo.toml --all-targets -- -D warnings
```
