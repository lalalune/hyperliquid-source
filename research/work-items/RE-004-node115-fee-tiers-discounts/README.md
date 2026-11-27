# RE-004: node #115 fee schedule tiers (`FeeSchedule`, `FeeTiers`, `StakeDiscount`, referral/builder fee splits)

- Component ID: `fees` (`RE-004`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: observation for all `.rodata` struct/field/variant schemas and `node115-fee-schedule-compose` validation bounds; inference for Rust domain methods (`FeeSchedule::user_fee_rates`, `FeeSchedule::compute_trade_fee`, `BuilderFeeRegistry`). No full-component acceptance gate is claimed by this packet alone.
- Implementation path: `src/node115-fees/src/tiers.rs`.

## Evidence (node #115 `.rodata` observations)

| `.rodata` VA | Observed #115 schema |
| --- | --- |
| `0x5c92f9`, `0x5f67be` | `struct FeeSchedule` (8 elements): `rates`, `tiers`, `referral_discount`, `referrer_keep`, `destination`, `extra_destination_fractions`, `stake_discount_tiers`, `weigh_spot_volume_double` |
| `0x5c9053` | `struct FeeTiers` (2 elements): `vip`, `mm` |
| `0x641b7a`, `0x5e67c1` | Base & user rate fields: `perpCrossBaseRate`, `perpAddBaseRate`, `spotCrossBaseRate`, `spotAddBaseRate`, `ntlCutoff`, `cross`, `add`, `spotCross`, `spotAdd`, `userCrossRate`, `userAddRate`, `userSpotCrossRate`, `userSpotAddRate`, `activeReferralDiscount` |
| `0x5c94e6`, `0x5c97cc`, `0x5f70ab` | `struct StakeDiscount` (2 elements: `bps_of_max_supply_staked`, `discount`) & `struct StakeDiscountTiers` (1 element) |
| `0x5c967a`, `0x5e6ca4` | `struct FeeTracker` (10 elements: `total_fees_collected`, `total_spot_fees_collected`, `collected_builder_fees`, `trials_disabled`) and `struct ApproveBuilderFeeAction` (`maxFeeRate`) |

## Reproduce

```sh
python3 tools/artifacts.py verify
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_fee_tiers_discounts_115
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/assets-fees-book \
  cargo test --offline --locked --manifest-path src/node115-fees/Cargo.toml
(cd research/work-items/RE-004-node115-fee-tiers-discounts && sha256sum -c MANIFEST.sha256)
```
