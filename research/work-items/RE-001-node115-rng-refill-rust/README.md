# Node #115 selected RNG refill fallback in Rust

This independently authored source is bounded progress for
[issue #3906](https://github.com/lalalune/hyperliquid-source/issues/3906).
It implements the four-block fallback described in open PR #4230 and does not
claim a new native mapping. Node #115 target SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Basis and scope

PR #2799 established the selected buffer/cursor caller; #4230 connects its
`0x150139d..0x1501409` window to `0x5bba800..0x5bbb030`, derives the
six-double-round fallback and independently checks block-major output, the
64-bit counter wrap, and preserved state words. The retained `records.json`,
`verify.py` and `verification.json` are the same credited prior evidence,
rechecked here for a self-contained input binding. Their 2 selected windows,
2,204 bytes / 456 instructions, 54 facts and 13 corruption controls describe
static evidence, not new native ownership or compiled-byte coverage.

The new source implements that specific relation using scalar word operations.
It does not implement CPU dispatch, alternatives, entropy, reseeding, allocator
or native ABI. A comparison of source with another source implementation is
not a target differential run; native correspondence remains conditional on the
prior static interpretation, valid inputs and normal return.

## Validation

The source crate has no dependencies. Its three tests pass on Rust 1.95.0 in
debug and release; Clippy passes with `-D warnings`. They cover a known
independent all-zero block, counter wrap/preserved words and shifted successive
blocks.

The separate `reference/` harness compares against already available
`rand_chacha` 0.3.1 and `rand_core` 0.6.4 (MIT OR Apache-2.0). Its lockfile pins
all test-only packages; none is a dependency of the library. It compares 288
synthetic seed/counter/stream cases, 18,432 words and updated state. Four
altered references (20 rounds, next counter, changed stream, changed key)
differed on 288/288 cases each. These are reference-comparison controls, not
mutations of target instructions. The installed `rand_chacha` source hashes
were Cargo.toml `e2ef45f3c9d6f013da266b76ca1e1f664ad5fa1d526b46580a77fb311c659fd8`,
`src/chacha.rs` `dfd79ed4762e8267148d1776381c71b898808014a4069cfafbc78177247d5fe9`,
and `src/guts.rs` `898fd129897fb44d15053044227307ee2bf416970adb8e63b4f5eabb7431aa1e`.
The optional harness needs these locked packages already cached; no package was
installed or downloaded for this run.

```sh
python3 research/work-items/RE-001-node115-rng-refill-rust/verify.py
cargo +1.95.0 test --offline --manifest-path src/node115-rng-refill/Cargo.toml
cargo +1.95.0 test --offline --release --manifest-path src/node115-rng-refill/Cargo.toml
cargo +1.95.0 clippy --offline --manifest-path src/node115-rng-refill/Cargo.toml --all-targets -- -D warnings
cargo +1.95.0 run --offline --locked --release --manifest-path research/work-items/RE-001-node115-rng-refill-rust/reference/Cargo.toml
```

The native verifier requires the hydrated pinned target and Capstone 5.0.7.
No captured instructions were executed or emulated. Full component completion,
full native equivalence and the behavior of other refill implementations are
not claimed. All component gates remain false.
