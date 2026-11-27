# RE-010: Node #115 Borrow-Lend (`bole`) Reserve Fixed-Point Interest, Utilization, Solvency & Liquidity Bounds

## Target Binary
- **Path**: `artifacts/node/115/hl-node` (Linux x86-64 ELF)
- **SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Source crate**: `src/exchange/src/bole_reserve.rs` (`#![forbid(unsafe_code)]`, 0 external deps)

## Direct Observations (Binary-Backed)
All 9 FDEs below are exact `.eh_frame` entries in `work/index/node-115-fde.tsv` (FDEs #53062..#53069 + #53017; **5,553 B** of pure fixed-point `l1/src/bole` math):

| VA Range | Size | FDE # | Anchored Semantics |
|---|---:|---:|---|
| `0x369ff10..0x36a003e` | 302 B | 53062 | `Reserve::utilization_scaled`: `borrow_wei = ceil([0x40]*[0x58]/1e14)`, `supply_wei = floor([0x60]*[0x78]/1e14)`, returns `0` if `supply_wei == 0`, else `min((borrow_wei * 1e14) / supply_wei, 1e14)`. |
| `0x36a0040..0x36a01f9` | 441 B | 53063 | `Reserve::protocol_equity_and_solvency_check`: computes `assets = [0x18] + borrow_wei`, `liabilities = [0x28] + supply_wei`, returns `Err(0x10)` if `assets < liabilities`, else `[0x20] + [0x28] + (assets - liabilities)`. |
| `0x36a0200..0x36a08ad` | 1,709 B | 53064 | `Reserve::accrue_interest`: evaluates kinked piecewise-linear rate curve (`[0x80]=base`, `[0x88]=max`, `[0x90]=kink_rate`, `[0x98]=optimal_util`), rejects `dt_ms > 0x758fac300` (`31_557_600_000` ms = `365.25 * 86_400 * 1_000` Julian year), updates `borrow_index` (`[0x58]`) and `supply_index` (`[0x78]`), accrues protocol fee into `[0x28]`, and sweeps `min([0x18], [0x28])` into `[0x20]`. |
| `0x36a08b0..0x36a09e8` | 312 B | 53065 | `Reserve::utilization_bps`: `utilization_scaled / 10^10` via magic `0x6df37f675ef7 >> 80`. |
| `0x36a09f0..0x36a0b25` | 309 B | 53066 | `Reserve::utilization_f64`: `utilization_scaled as f64 / 1e14` (`.rodata 0x459378`). |
| `0x36a0b30..0x36a0d72` | 578 B | 53067 | `Reserve::yearly_borrow_rate_bps`: kinked curve evaluated at `utilization_scaled().unwrap_or(0)`, divided by `10^10` via magic `0xdbe6fecebdedd5bf >> 97`. |
| `0x36a0d80..0x36a0fd6` | 598 B | 53068 | `Reserve::yearly_borrow_rate_f64`: kinked curve divided by `1e14` (`.rodata 0x459378`). |
| `0x36a0fe0..0x36a1327` | 839 B | 53069 | `Reserve::max_delta_wei_for_target_utilization(is_borrow, target_util)`: floor-share path for max additional borrowable wei (`is_borrow=true`), ceil-share path for max withdrawable supply wei (`is_borrow=false`, `Err(0x06)` if `target_util == 0` or `index == 0`). |
| `0x36939f0..0x3693bc1` | 465 B | 53017 | `UserState::check_min_leg_notional`: converts user shares with `ceil` for borrow / `floor` for supply, allows `0`, rejects non-zero `< min_wei` (converted from `$100` = `0x5f5e100` via `0x4217e60`) with tag `0x07`. |

## Inferences & Remaining Unknowns
- **Inferences**: The `0xb0`-byte struct passed to FDEs #53062..#53069 is `bole::Reserve`, with field pairs `([0x40], [0x58]) = (total_borrow_shares, borrow_index)` and `([0x60], [0x78]) = (total_supply_shares, supply_index)`, cash/fee fields `[0x18]=pool_cash_wei`, `[0x20]=realized_protocol_fee_wei`, `[0x28]=pending_protocol_fee_wei`, rate curve `[0x80..0xa0]`, and 12-byte `Time` at `[0xa0..0xac]`.
- **Unknowns**: Higher-level multi-asset portfolio-margin LTV / health-factor aggregation across `0x36961e0` (11,506 B) and `0x369a480` (3,805 B) remains un-reconstructed in Rust.
