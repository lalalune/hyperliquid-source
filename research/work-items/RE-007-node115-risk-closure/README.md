# RE-007: Node #115 Complete `risk` (`l1/src/clearinghouse/*`, `l1/src/spot_clearinghouse/*`) Full-Scope Closure

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `risk` (`l1/clearinghouse/*`, `l1/spot_clearinghouse/*` — Stream E2 / `RE-007`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** observed `risk` source file (**14/14**: 10 `l1/src/clearinghouse/*.rs` files + 4 `l1/src/spot_clearinghouse/*.rs` files), **every** `.data.rel.ro` `Location` struct (**82/82**), **every** `.text` FDE referencing those `Location` structs (**117/117 unique FDEs = 384,117 bytes**), and **7 disjoint core clearinghouse & spot-clearinghouse business FDEs** (`10,365 bytes`, **124 unique FDEs / 394,482 bytes** combined).

## Complete 14-File `risk` Implementation Map

- `l1/src/clearinghouse/cl_trait.rs` (`3` Locations / `7` FDEs): `src/node115-position-transition`, `src/clearinghouse/src/position_risk.rs`.
- `l1/src/clearinghouse/clearinghouse.rs` (`18` Locations / `12` FDEs): `src/clearinghouse/src/liquidation.rs` (`0x44dcf80` backstop pro-rata allocation, `"Liquidator must use cross margin for asset "`), `src/node115-clearinghouse-ntl-ratio`, `src/node115-open-interest-cap`, `src/node115-notional-collector`, `src/node115-leverage-aggregate`, `src/node115-portfolio-split-entries`.
- `l1/src/clearinghouse/impl_first_dex.rs` (`2` Locations / `1` FDE `0x4482950`): `src/clearinghouse` + `src/node115-open-interest-cap`.
- `l1/src/clearinghouse/margin_table.rs` (`2` Locations / `7` FDEs + `0x3c43150`): `src/clearinghouse/src/margin_user_state.rs` (`0x38b4e20` `first_tier`, `0x38b54b0` `maintenance_margin`, `0x38b5300` exact 2/3 `backstop_margin`, `0x3c43150` `id < 50` vs custom `MarginTableStore`), `src/node115-margin-{flat-compose,mode-codec,mode-identifier,range,row,tree-range}`.
- `l1/src/clearinghouse/oracle/oracle.rs` (`33` Locations / `77` FDEs): `src/node115-oracle-{entry-lifecycle,nested-keys,outcome-kind}`, `src/node115-price-list-retain`.
- `l1/src/clearinghouse/oracle/oracle_kind.rs` (`2` Locations / `1` FDE `0x3db4e40`): `src/clearinghouse/src/reference_oracle.rs` (3-variant `OracleKind`).
- `l1/src/clearinghouse/oracle/reference_oracle.rs` (`1` Location / `1` FDE `0x366f900`): `src/clearinghouse/src/reference_oracle.rs` (`ReferenceOracle::evaluate`, `-1.0` `0x458dc8`, `1e9` `0x458d50`, severity `8` alert `0x366fbc5`).
- `l1/src/clearinghouse/position.rs` (`1` Location / `5` FDEs): `src/clearinghouse/src/position_risk.rs` (`0x3bebd70`, `0x446b840`, `0x447e810`, `0x469b990`) + `src/clearinghouse/src/margin_user_state.rs` (`0x448b800` 5-arm `Position::margin_summary`).
- `l1/src/clearinghouse/position_map.rs` (`1` Location / `1` FDE `0x4205370`): `src/clearinghouse/src/position_risk.rs` + `src/node115-position-transition`.
- `l1/src/clearinghouse/user_state.rs` (`1` Location / `1` FDE `0x3beb700`): `src/clearinghouse/src/margin_user_state.rs` (`available_margin_isolated`, `available_margin_cross`).
- `l1/src/spot_clearinghouse/cl_trait.rs` (`15` Locations / `9` FDEs): `src/clearinghouse/src/spot_clearinghouse.rs` (`SpotFillDeltaAccumulator::record_fill` `0x3d4e560`).
- `l1/src/spot_clearinghouse/impl_outcome.rs` (`1` Location / `1` FDE `0x3bf2be0`): `src/node115-outcome-{payload,record-msgpack}`, `src/node115-oracle-outcome-kind`.
- `l1/src/spot_clearinghouse/spot_clearinghouse.rs` (`1` Location / `1` FDE `0x3d5e540` + 6 business FDEs `0x3bf5120`, `0x3bfa400`, `0x3bfa810`, `0x3bfb650`, `0x3bfd020`, `0x3bfd3c0`): `src/clearinghouse/src/spot_clearinghouse.rs` (`100M` lots min, `1%` Hyperliquidity `[0xff; 20]` / `"HYPE"` exemption, `<= 1000` blacklist cap, `1e-6` dust / `0.01` clawback / `1.01` ratio cap pro-rata distribution).
- `l1/src/spot_clearinghouse/types.rs` (`1` Location / `7` FDEs): `src/clearinghouse/src/spot_clearinghouse.rs` (`SpotBalance::apply_delta` `0x3bfa910`, `0x028f5c28f5c28f5c` `entry_ntl` proportional scale guard).

## Complete `risk` Acceptance Inventory

- **Mapped**: 14/14 `risk` source files, 82/82 `Location` structs, 117/117 Location-referencing FDEs (`384,117 B`) + 7/7 disjoint core business FDEs (`10,365 B`) = **124 unique FDEs (`394,482 B`)** verified against `work/index/node-115-fde.tsv` and raw ELF bytes.
- **Built & Behavior**: Integrated `src/clearinghouse` (`#![forbid(unsafe_code)]`, 0 external deps, wired into `src/exchange` and `src/hl-node`) plus all 23 registered `risk` sibling crates in `research/components.json` build and pass tests cleanly (with `src/clearinghouse` passing debug, `--release`, and `clippy --all-targets -- -D warnings`).
- **Compiled-Byte Identity (honest status)**: `identity` remains `false`; compiled-byte proofs currently cover `RE-007-node115-stream-e2-logic-byte-matches` (business-logic FDEs), `RE-007-node115-stream-e2-debug-byte-matches` (`8w / 2,050 B` `risk` `Debug::fmt` FDEs), and `RE-007-node115-stream-e2-byte-matches` (`risk` visitor FDEs).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-007-node115-risk-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_risk_closure_115 -v
(cd research/work-items/RE-007-node115-risk-closure && sha256sum -c MANIFEST.sha256)
```
