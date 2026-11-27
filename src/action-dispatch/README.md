# `action-dispatch` — Integrated Node #115 Action Router & Handlers

Target binary: Linux x86-64 `hl-node` #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Integrates all seven `action-dispatch` handler micro-crates with `action-wire`
and the independently authored Rust reconstruction of node #115's central
92-arm action router `0x2bda7c0` (`research/work-items/action-dispatch-router-115`):

- `router`: complete 92-arm dispatch table (`0x609f00`), tag-to-index niche
  mapping (`< 0x86 => VoteGlobal (20)`), trading-action feature-flag 50 gate
  bitmask `0x501d` (`noop`, `batchModify`, `cancel`, `cancelByCloid`, `modify`,
  `order`), latency timer sentinel `0x3b9aca00` (`1_000_000_000`), and exact
  argument shapes (`None`, `TagPointer`, `TagPointerPlus8`, `PayloadLoads`)
- Re-exported handler micro-crates:
  - `node115-action-admission-binding`
  - `node115-display-name-decision` & `node115-display-name-state`
  - `node115-builder-approval` (`0x3c1a510`)
  - `node115-claim-rewards`
  - `node115-referral-code` (`0x285c730`, `0x3c193d0`)
  - `node115-set-referrer` (`0x3c17590`)

## Test

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 \
  CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --offline --locked --manifest-path src/action-dispatch/Cargo.toml
```
