# RE-004: Node #115 Complete `fees` (`l1/src/fees/*`, `raw_vlm.rs`, `scaled_vlm.rs`) Full-Scope Closure

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `fees` (`l1/src/fees/*`, `l1/src/raw_vlm.rs`, `l1/src/scaled_vlm.rs` — Stream E1 / `RE-004`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** observed `fees` source file (**4/4**: `l1/src/fees/compute.rs`, `l1/src/fees/fees.rs`, `l1/src/raw_vlm.rs`, `l1/src/scaled_vlm.rs`), **every** `.data.rel.ro` `Location` struct (**4/4**), **every** `.text` FDE referencing those `Location` structs (**17/17 unique FDEs = 32,890 bytes**), and **every** `FeeTracker` business-logic FDE in `0x3c154d0..0x3c1b378` (**15/15 unique FDEs = 24,123 bytes**, **32 unique FDEs / 57,013 bytes** combined).

## Final `FeeTracker` Business Routines Closed Here

1. **Zero-fee system addresses & `active_staking_discount` (`0x3c154d0..0x3c15802`, `818 B`)**:
   - Checks both zero-fee system addresses via SIMD `pcmpeqb` (`0x3c154ee`: `[0xff; 20]` against `.rodata 0x453b70`; `0x3c1551a`: `[0xfe; 20]` against `.rodata 0x4543c0` / `0x455bb0`), treating both as `staked_bps = 0.0`, then scans `stake_discount_tiers` (`0x10`-byte stride).
2. **`referrer_reward_fraction` (`0x3c15810..0x3c15b93`, `899 B`)**:
   - Sums the referred user's cumulative `RawVlm` across token entries (saturating add), returning `0.0` once `(cum >> 11) > 0x2e90edc` (`cum >= 100_000_000_000` = `$1,000,000,000.00` in `$0.01` units).
   - For spot (`is_spot == true`), returns `fee_schedule.referrer_keep` (`[rbx+0x90]`).
   - For perp (`is_spot == false`), computes `max(0.0, user_fee_scale * (referrer_stake_discount - user_stake_discount))` (`0x3c15b82`: `subsd; mulsd; maxsd`).
3. **`user_fee_state` (`0x3c18260..0x3c18389`, `297 B`)**:
   - Returns all-zero rates and `fee_scale = 0.0` for `[0xff; 20]` and `[0xfe; 20]`; falls back to `fee_schedule` base rates with `fee_scale = 1.0` (`0x3ff0000000000000` at `0x3c18343`) for uninitialized users; otherwise returns the user's active fee/trial state.
4. **`register_referrer` (`0x3c193d0..0x3c1a24b`, `3,707 B`)**:
   - Enforces non-admin minimum cumulative `RawVlm >= 1_000_000` (`$10,000.00`, `0x3c1961a`: `cmp rbx, 0xf4240` -> `UserError 0xa9`), code length `<= 100` (`0x3c193fc`/`0x3c19636`: `cmp r12, 0x64` -> `0xa4`), user not already registered (`0xa8`), and code not already taken by another user (`0xa7`), with admin bypass of volume and re-registration checks.

## Complete `fees` Acceptance Inventory

- **Mapped**: 4/4 `fees` source files, 4/4 `Location` structs, 17/17 Location-referencing FDEs (`32,890 B`) + 15/15 `FeeTracker` business FDEs (`24,123 B`) = **32 unique FDEs (`57,013 B`)** verified against `work/index/node-115-fde.tsv` and raw ELF bytes.
- **Built & Behavior**: Integrated `src/node115-fees` (`#![forbid(unsafe_code)]`, 0 external deps, wired into `src/hl-node` and `src/node115-orderbook`/`src/exchange`) combines all 8 registered `fees` micro-crates (`node115-fee-point-classifier`, `node115-raw-threshold`, `node115-fee-window-scan`, `node115-fee-active-scaling`, `node115-fee-failure-selection`, `node115-fee-map-iteration`, `node115-fee-schedule-compose`, `node115-fee-trial`) with full implementations of `RawVlm`/`ScaledVlm` saturating arithmetic, open-order cap (`0x5495210`/`0x5495680`), schedule-cancel & subaccount volume gates (`0x5569580`/`0x56195a0`), 6-scale `5e-6` net-fee solvency (`0x36a58d0`), fill-fee scaling & ledger settlement (`0x46a6860`, `0x3c1a250`, `0x3c1a3f0`, `0x3c1ae50`), schedule validation & monotonicity (`0x36e1b10`, `0x3c18a80`), and complete `FeeTracker` referral/reward/trial/builder-cap/state lifecycle (`0x3c154d0..0x3c1ae41`).
- **Compiled-Byte Identity (honest status)**: `identity` remains `false`; compiled-byte proof currently covers `RE-006-node115-stream-e1-thinlto-byte-matches` (`2w / 474 B` non-visitor `fees` `Debug::fmt` FDEs) plus `RE-004-node115-stream-e1-byte-matches` leaf helpers (`fees` cluster).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-004-node115-fees-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_fees_closure_115 -v
(cd research/work-items/RE-004-node115-fees-closure && sha256sum -c MANIFEST.sha256)
```
