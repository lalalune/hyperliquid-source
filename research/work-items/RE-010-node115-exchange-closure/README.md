# RE-010: Node #115 Complete `exchange` (`l1/src/exchange/*`) Full-Scope Closure

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `exchange` (`l1/exchange/*` — Stream E2 / `RE-010`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** observed `exchange` source file (**15/15** `l1/src/exchange/*.rs` files), **every** `.data.rel.ro` `Location` struct (**70/70**), **every** `.text` FDE referencing those `Location` structs (**102/102 unique FDEs = 611,186 bytes**), and **17 disjoint core `exchange` business-logic FDEs** (`9,479 bytes`, **119 unique FDEs / 620,665 bytes** combined).

## Complete 15-File `exchange` Implementation Map

- `l1/src/exchange/begin_block.rs` (`10` Locations): `src/exchange/src/orchestrator.rs`, `src/exchange/src/bole_liquidation.rs` (`0x2bdf8f0` 7-phase periodic schedule), `src/node115-funding-{premium,rate,read-reset,settlement-user}`.
- `l1/src/exchange/end_block.rs` (`2` Locations): `src/exchange/src/orchestrator.rs`, `src/exchange/src/bole_liquidation.rs` (`0x2c71250`).
- `l1/src/exchange/exchange.rs` (`3` Locations): `src/exchange/src/orchestrator.rs` (`Exchange` state container), `src/node115-exchange-freeze-prelude`, `src/node115-user-admission-prefix`, `src/node115-symbol-prefix`.
- `l1/src/exchange/impl_abstraction.rs` (`3` Locations): `src/node115-abstraction-kind-decoder`.
- `l1/src/exchange/impl_bole.rs` (`4` Locations): `src/exchange/src/bole_liquidation.rs` (`0x2c80670`, `[0xbb; 20]` liquidator sentinel `0x60e1c7`), `src/exchange/src/bole_reserve.rs` (`0x369ff10..0x36a1327` 8 `Reserve` fixed-point FDEs + `0x36939f0` `$100` leg guard, `10^14` scale `0x5af3107a4000`, `31_557_600_000 ms` Julian year), `src/node115-bole-{entry-prefix,record-bound}`.
- `l1/src/exchange/impl_global.rs` (`7` Locations): `src/exchange/src/orchestrator.rs` + `src/action-dispatch` (`governance-vote-state`).
- `l1/src/exchange/impl_ledger.rs` (`1` Location): `src/exchange/src/orchestrator.rs` + `src/node115-fees`.
- `l1/src/exchange/impl_outcome.rs` (`2` Locations) & `l1/src/exchange/impl_outcome_deploy.rs` (`4` Locations): `src/node115-outcome-{account-projection,fraction-scale}`, `src/exchange/src/stake_requirement.rs` (`0x420e470` `"not an outcome deployer"` / `"not an active outcome deployer"`).
- `l1/src/exchange/impl_spot_deploy.rs` (`6` Locations): `src/exchange/src/spot_deploy.rs` (`0x2c57090`/`0x55cbcc0`/`0x55cc610`/`0x44811d0`, `"could not convert perp usdc to spot"`), `src/exchange/src/token_scaling.rs` (`0x434f660`/`0x434f790`/`0x434f910`).
- `l1/src/exchange/impl_trading.rs` (`6` Locations): `src/exchange/src/orchestrator.rs` + `src/node115-modify-window-admission` + `src/node115-orderbook`.
- `l1/src/exchange/impl_user.rs` (`2` Locations): `src/exchange/src/orchestrator.rs` (`0x2c77640`), `src/node115-user-admission-prefix`.
- `l1/src/exchange/impl_vault.rs` (`6` Locations): `src/exchange/src/orchestrator.rs` + `src/vaults`.
- `l1/src/exchange/simulate_portfolio_margin.rs` (`10` Locations): `src/exchange` + `src/clearinghouse` (`node115-portfolio-split-entries`).
- `l1/src/exchange/stake_requirement.rs` (`4` Locations): `src/exchange/src/stake_requirement.rs` (`0x235a050`, `0x294ceb0`, `0x2c58c70`, `0x292deb0`, `0x2c59360`, `0x420e470`, `0x2c59480`, 4×4 `.rodata` stake tables `0x457b00`/`0x457d00`/`0x457f00`, 183-day `0xf14280` s cooldown, tags `0xc5`/`0x118`/`0x119`/`0x11a`/`0x1a2`), `src/node115-stake-cursor`.

## Complete `exchange` Acceptance Inventory

- **Mapped**: 15/15 `exchange` source files, 70/70 `Location` structs, 102/102 Location-referencing FDEs (`611,186 B`) + 17/17 disjoint business FDEs (`9,479 B`) = **119 unique FDEs (`620,665 B`)** verified against `work/index/node-115-fde.tsv` and raw ELF bytes.
- **Built & Behavior**: Integrated `src/exchange` (`#![forbid(unsafe_code)]`, 0 external deps, wired into `src/hl-node`) plus all 14 registered `exchange` sibling crates in `research/components.json` build and pass tests cleanly (`src/exchange` passing debug, `--release`, and `clippy --all-targets -- -D warnings`, `src/hl-node` 10/10 OK).
- **Compiled-Byte Identity (honest status)**: `identity` remains `false`; compiled-byte proofs currently cover `RE-007-node115-stream-e2-logic-byte-matches` (incl. `BoleReserve::utilization_bps` `0x36a08b0` & `utilization_f64` `0x36a09f0`), `RE-007-node115-stream-e2-debug-byte-matches` (`3w / 584 B` `exchange` `Debug::fmt` FDEs), and `RE-007-node115-stream-e2-byte-matches` (`exchange` visitor FDEs).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-010-node115-exchange-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_exchange_closure_115 -v
(cd research/work-items/RE-010-node115-exchange-closure && sha256sum -c MANIFEST.sha256)
```
