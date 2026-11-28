# Derive offline timer drain from the pending checkpoint entries

The integrated tracker previously needed a caller-supplied list of eligible heights. The new offline entry point accepts pending insertion times on the same normalized nanosecond clock as the drain time. It derives primary maturity and the secondary eviction budget, then passes primary heights through the existing ordered extraction and quorum sink.

The native finalizer reads the pending descriptor's count at `0x5afa048`, snapshots its saturated difference from 1,000 and supplies a separate initially zero secondary counter. The normal primary comparison enters extraction through `0x515259e → 0x5377df0`. In the normal secondary path, the second threshold loads 60.0 seconds at `0x515233b`, and the comparison at `0x51524a8` admits only entries that fit the secondary budget. The accepted branch increments that counter and reaches the pending entry removal tail without a primary digest extraction. [PR #6626](https://github.com/lalalune/hyperliquid-source/pull/6626) and the [counter-identity packet](../RE-017-node115-replay-budget-map-identity/README.md) recover the native counter sources. [PR #7456](https://github.com/lalalune/hyperliquid-source/pull/7456) supplies the duration input from an offline checkpoint image.

The adapter models ordinarily returning timer callbacks with caller-supplied, normalized timestamps and the existing logical tracker. It does not decode the native packed clock, model its fallback tuple, verify signatures, inspect a live tracker, or treat a locally produced quorum line as a native raw-state reference.

The Rust test stages 1,002 synthetic pending entries and supplies three equal-edge secondary candidates. It verifies that only two consume the secondary budget, and that a separate exactly mature primary entry is still delivered. A missing timestamp on the same fixture leaves the pending set and queue intact.

## Reproduce

Target Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-017-node115-offline-timer-budget/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-abci/Cargo.toml --test timed_drain
```

The [offline log](offline-log.txt) preserves the static results and actual Rust tests. The verifier reads the captured ELF as data.
