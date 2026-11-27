# `l1-shared` — Integrated Node #115 L1 Shared State Helpers

Target binary: Linux x86-64 `hl-node` #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Integrates `node115-agent-erase-state` with independently authored Rust
reconstructions of the binary-verified #115 L1 shared helpers:

- `agent_erase`: `src/node115-agent-erase-state` (`l1/src/agent_tracker.rs`)
- `decimal_scaler`:
  - `l1-shared-decimal-amount-scaler-115` (`0x421e9d0` + 5 decimal helpers — 10,300 cases)
  - `l1-shared-amount-wrappers-115` (`0x46aa250`, `0x274b760`, `0x2891af0`, `0x3be28a0`, `0x3c42660` — 24,000 cases)
  - `l1-shared-f64-to-decimal-115` (`0x5c43c60`, `0x43099f0` — 13,310 cases)
- `nonce_set`:
  - `action-wire-nonce-admission-115` (`0x4228080`, `0x4228310`, 19 expanded-window addresses — 29,600 cases, `l1/src/nonce_set.rs`)
- `hyperliquidity`:
  - `exchange-hyperliquidity-ladder-115` (`0x3be2a50`, `0x38bddf0`, `0x38bcb80` — 12,000 cases)
  - `exchange-hyperliquidity-seed-115` (`0x38bc000`, `0x38bcaa0` — 12,000 cases, `l1/src/hyperliquidity.rs:360`)

## Scope and limitations

- Pure standard-library Rust (`#![forbid(unsafe_code)]`), no external crates.io dependencies.
- Reconstructs established static and byte-executed semantics only; does not claim
  full-node binary identity or component gate completion.

## Test

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 \
  CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --manifest-path src/l1-shared/Cargo.toml
```
