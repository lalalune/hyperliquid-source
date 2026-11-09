# Node #115 consensus timer seconds conversion

This crate independently implements the established seconds/nanoseconds portion of the consensus timer function attributed to `node/src/consensus/timer.rs:17:30`.

The target-bound packet `research/work-items/RE-001-node115-consensus-timer-conversion` records the exact exponent regimes, ties-to-even fractional rounding, billion-nanosecond carry, negative-input rejection, and upper range rejection. The state constructor passes the two exact inputs `0.3` and the binary64 value `0x3fb9999999999999`; tests preserve both.

## Boundaries

`convert_seconds` returns only the proved `(seconds, nanoseconds)` pair. Its error variants distinguish the two observed nonreturning branches, but do not reproduce panic formatting. This crate does not build the native `0x70`-byte payload, allocate or copy that payload, name the output record, or integrate a consensus timer/state machine. Those are explicit open dependencies in the evidence packet. No component gate is advanced.

## Validation

```sh
cargo +1.95.0 test --locked --offline --manifest-path src/node115-consensus-timer-conversion/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-consensus-timer-conversion/Cargo.toml
```

The focused crate run passes all 5 unit tests and doctests; formatting passes. Repository checks on base `0781ce04826eeefd89fe336cb8ea073be0c1de30`: `make doctor` and `make verify` pass with GNU binutils available. `make catalogue-check` reports the pre-existing stale generated `research/catalogue/components.json`. `make test` was started but interrupted after 68/1,130 files: two pytest-style files fail because the environment has no `pytest` module, and the complete inventory therefore remains unverified.

Tests cover both recorded caller inputs, each exponent regime, nearest-even ties, fractional carry, signed zero, negative subnormal/infinity, NaNs, and the `u64` boundary. They validate this independent arithmetic slice; they do not execute or emulate the captured node.
