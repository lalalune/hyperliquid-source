# RE-004: Node #115 `FeeTracker` Trial, Referral, Reward-Claim, & Builder-Cap Lifecycle

## Target Binary
- Path: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`

## Scope (Observed in Node #115 `.text` & `.rodata`)
Closes 5 core `FeeTracker` lifecycle FDEs (**7,898 B total**) in `l1/src/fees/fees.rs` and ports them to `src/node115-fees/src/lifecycle.rs` (`#![forbid(unsafe_code)]`, 0 external deps):

| FDE | Size | Function | Binary-Backed Rules & Constants |
| --- | ---: | --- | --- |
| `0x3c17390..0x3c17590` | 512 B | `FeeTracker::active_referral_discount` | Requires referrer set (`[rax+0xc4] == 1`), saturating-sums per-token `cum_raw_vlm`, checks `(sum >> 8) <= 0x9502f8` (`sum < 2_500_000_000` = `$25,000,000.00` in `$0.01` RawVlm units) |
| `0x3c17590..0x3c17fb9` | 2,601 B | `FeeTracker::set_referrer` | Enforces code registered (`0xa6`), no self-referral (`0xa2`), referrer not already set (`0xa3`), bucket refresh via `now_millis / referral_bucket_millis` with quota `max(custom_limit, 1000)` (`0x3e9`/`0x3e8`), empty-bucket rejection (`0xa5`), success (`0x1a2`) |
| `0x3c17fc0..0x3c18252` | 658 B | `FeeTracker::claim_rewards` | Iterates per-token `0x38`-byte reward entries, enforces `$1.00` (`0x5f5e100 = 100_000_000` USDC wei) minimum per-token claim threshold via `0x4217e60`, distinguishes `0xaa` ("No rewards to claim") vs `0xab` ("Must have at least $1 of a reward token to claim"), saturating-adds claimed rewards |
| `0x3c18390..0x3c18a7e` | 1,774 B | `FeeTracker::start_fee_trial` | Enforces `trials_disabled` (`0x14d`), no active trial (`0x149`), VIP (`0x30` stride) or `(vip.cross, mm.add)` (`0x10` stride) rate membership (`0x14a`), 90-day cooldown (`0x5a` via `node115-daycount-date`, `0x14c`), 14-day duration (`0x0e`), staking discount on positive rates only, improvement check (`0x14b`), propagation across linked accounts |
| `0x3c1a510..0x3c1ae41` | 2,353 B | `FeeTracker::approve_builder_fee` | Enforces maximum 10 approved builders per user (`cmp rax, 0xa` -> `0x13c`, "Too many builders approved."), zero-rate removal (`0x1a2`) |

All 13 `UserError` `u16` discriminants are independently anchored in the master `UserError` jump table at `.rodata 0x7d8c1c` inside `0x46ef710..0x46f312f`.

## Verification Commands
```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_fee_trial_referral_rewards_115 -v
(cd research/work-items/RE-004-node115-fee-trial-referral-rewards && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=/home/shaw/Work/hyperliquid-source/work/target/assets-fees-book \
  cargo test --offline --locked --manifest-path src/node115-fees/Cargo.toml
```

## Gate Honesty
Documents behavioral/constant closure for these 5 `FeeTracker` FDEs; makes no `research/progress.json` gate claims.
