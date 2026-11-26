# RE-001: compose the node #115 refill fallback with buffered policy

Partial progress for [issue #3906](https://github.com/lalalune/hyperliquid-source/issues/3906). This closes the selected fallback boundary between the existing buffered-u32 policy and the independently reconstructed four-block refill. It removes the supplied post-refill output premise for this one branch.

## Authenticated basis

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- [RE-012 RNG buffer selection](../RE-012-rng-buffer-selection-115/README.md) binds the selected caller's 48-byte mutable state, native refill argument `6`, 256-byte output buffer, and post-return cursor reset/word-zero read.
- [RE-001 refill contract](../RE-001-node115-rng-refill-contract/README.md) authenticates the direct refill target, its 48-byte key/tail words, four output blocks, and fallback counter advance by four. Its instruction evidence covers the caller and complete selected refill FDE, 2,204 bytes / 456 instructions / 54 facts, with 13 semantic corruption controls rejected.
- [RE-001 Rust fallback](../RE-001-node115-rng-refill-rust/README.md) independently compiled the fallback against MIT/Apache-2.0 `rand_chacha` ChaCha12 across 288 cases / 18,432 words.

## Composition

`RefillRequest::complete_four_block_fallback` interprets the policy's 48 state bytes as eight little-endian key words and four little-endian tail words, calls the existing `node115-rng-refill` implementation, serializes its advanced state back to the same 48-byte form, and completes the original request with the 64-word output. `RefillRequest::complete(RefillOutput)` remains available for genuinely external results.

The API name and docs require the caller to establish that native CPU dispatch selected the four-block fallback. The composition does not select or reproduce accelerated alternatives. Its tests check budget and cursor transitions plus the 48-byte state projection. The independent reference harness compares the composed path, not only the leaf refill, against ChaCha12 for 288 seed/counter/stream cases and 18,432 words; four altered references each differ on all 288 cases.

## Reproduction

From the repository root, with Rust 1.95, the pinned node artifact, Python 3.14 and Capstone 5.0.7:

```sh
python3 research/work-items/RE-001-node115-rng-fallback-compose/verify.py
cargo +1.95.0 test --locked --offline --manifest-path src/node115-rng-buffer-selection/Cargo.toml
```

The verifier reruns the parent target-bound contract verifier and the locked offline independent comparison harness. Captured target code is never executed or emulated.

## Limits

Entropy acquisition, reseed policy and its provider, error-box allocation failure, CPU feature detection and accelerated implementations, TLS/reference lifetime, allocation behavior, native layout/ABI and concurrency remain outside this composition. The source-built result is conditional on the established fallback branch and normal return; it does not close the full Foundation component or issue #3906.
