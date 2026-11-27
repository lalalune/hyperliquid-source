# `exchange` — Integrated Node #115 Exchange Orchestration Library

Target binary: Linux x86-64 `hl-node` #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Top-level L1 exchange orchestrator joining all Stream E2 integrated crates
(`action-wire`, `action-dispatch`, `clearinghouse`, `dex-registry`, `vaults`,
`l1-shared`), Stream E1 integrated crates (`node115-assets`, `node115-fees`,
`node115-orderbook`), and all 8 Cargo-packaged `exchange` micro-crates
(`node115-bole-{record-bound,reserve-reply,user-reply}`,
`node115-funding-{premium,rate,read-reset,settlement-user}`,
`node115-modify-window-admission`), plus independently authored Rust
reconstructions of:

- `token_scaling`: `exchange-token-decimal-scaling-115` (`0x434f660` scaled
  multiply with token-0 shortcut & divide-first fallback, `0x434f790` 128-bit
  percent divide with `2^64/100` bound, `0x434f910` signed-exponent 256-bit
  scaler with `2^63/10` bound — 12,000 cases, 0 mismatches)
- `spot_deploy`: `exchange-spot-deploy-charge-115` (`0x2c57090` / `0x55cbcc0` /
  `0x55cc610` perp-to-spot charge path, `0x44811d0` rate scaler, `ceil(fee/100)`,
  and ledger row update — 42,000 cases, 0 mismatches)
- `orchestrator`: cohesive `Exchange` state & block/action execution shell
  ready to wire directly into `node115-abci` (`storage-abci`)

## Test

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 \
  CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --offline --locked --manifest-path src/exchange/Cargo.toml
```
