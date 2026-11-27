# `clearinghouse` — Integrated Node #115 Clearinghouses & Risk Library

Target binary: Linux x86-64 `hl-node` #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Integrates all 19 Cargo-packaged node #115 `risk` / clearinghouse micro-crates
(margin tables & modes, leverage aggregate, notional collector, position
transitions, oracle lifecycle/keys/admission, borrow-lend codecs, and outcome
projections) with independently authored Rust reconstructions of the
binary-verified #115 clearinghouse risk routines:

- `position_risk`:
  - `risk-position-family-115` (`0x3bebd70` account position fold, `0x447e810`
    isolated-position check, `0x469b990` margin test — 12,535 cases, 0 mismatches)
  - `risk-position-ratio-115` (`0x446b840` position ratio — 16,024 cases, 0 mismatches)
  - `risk-asset-decimal-scale-115` (`10^(high - low)` asset decimal scaler)

## Test

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 \
  CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --offline --locked --manifest-path src/clearinghouse/Cargo.toml
```
