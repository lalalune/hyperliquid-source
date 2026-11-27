# RE-008: Node #115 `CStaking` Reward Emission Curve, Staging, Commission Split & Asymmetric 0.99 Decay

## Target

- Binary: `artifacts/node/115/hl-node` (Linux x86-64 ELF, `105,896,032` bytes)
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`

## Direct Observations

1. **Per-step staking emission rate (`0x3c38360..0x3c3854e`, 494 B)**:
   - Looks up current epoch validator stakes via `0x3be6f50`; returns `None` if absent.
   - Returns `Some(0.0)` when rewards are disabled (`testb $0x1, %r15b`), `reference_supply == 0`, or active stake is absent.
   - Converts `reward_period_ms` (`[self + 0x2b8]`) to seconds by dividing by `1000.0` (`.rodata 0x459a60`), computes `steps_per_year = 31_557_600.0 / step_secs` (`.rodata 0x459058`; clamps `inf -> 0.0`).
   - Evaluates the exact inverse-square-root quadratic emission curve at `0x3c3850d..0x3c38539`:
     - `ratio = total_staked / reference_supply`
     - `denom = ratio.sqrt().max(0.015)` (`.rodata 0x4596b0`)
     - `x = 0.015 / denom`
     - `annual_rate = x + (-0.5) * x * x` (`.rodata 0x459420`)
     - `step_rate = annual_rate / steps_per_year`
2. **Ordered periodic bucket dispatcher (`0x3c3f780..0x3c403f7`, 3,191 B)**:
   - Evaluates 3 monotonic `time_ms / period_ms > last_bucket` guards in order:
     1. `c_staking_stage_reward` (`.rodata 0x7bbe59`, len `0x16`): period `[self+0x2b8]`, last `[self+0x2c0]` -> calls `0x422c320`.
     2. `c_staking_distribute_staged_rewards` (`.rodata 0x7bbe6f`, len `0x23`): period `[self+0x2c8]`, last `[self+0x2d0]` -> calls `0x422abf0`.
     3. `decay_staking` (`.rodata 0x7bbee3`, len `0x0d`): period `[self+0x2a8]`, last `[self+0x2b0]` -> calls `0x422a630`.
3. **Reserve-capped reward staging (`0x422c320..0x422c95f`, 1,599 B + `0x3d66500..0x3d66a5d`, 1,373 B)**:
   - `0x422c320` calls `0x3c38360` at `0x422c371` and iterates active unjailed validators through `0x3bcb810 -> 0x3dce3c0 -> 0x3d66500`.
   - `0x3d66916..0x3d66a5b` converts finite positive `validator_stake * step_rate` to `u64`, caps the transfer against the reward reserve (`remaining = reserve.saturating_sub(reward); actual = reserve - remaining`), updates reserve, and saturating-adds `actual` to the validator's staged reward balance.
4. **Commission & pro-rata delegator distribution (`0x422abf0..0x422c320`, 5,936 B)**:
   - Commission fraction (`0x422b0d0..0x422b0e6`): `(commission_bps as f64) * 0.0001` (`.rodata 0x459b50`), guarded by `<= 1.01` (`.rodata 0x4590b8`, else `0`), subtracted from staged reward with saturating guard at `0x422b1cb..0x422b1e7`.
   - Per-delegator share (`0x422b747..0x422b76b`): `delegator_stake / total_validator_stake`, guarded by `0.0 <= share <= 1.01`, multiplied by remaining delegator pool and clamped to `u64`.
5. **Asymmetric 0.99 staking decay (`0x422a630..0x422abe5`, 1,461 B)**:
   - Loop at `0x422a7a0..0x422a804`: for each `(decayed_wei, raw_wei)` pair, if `raw_wei < decayed_wei` (`jb 0x422a790`), immediately sets `decayed_wei = raw_wei`; otherwise adds `clamp_u64(((raw_wei - decayed_wei) as f64) * 0.99)` (`.rodata 0x459208`), preserving `decayed_wei` on `u64` addition overflow (`0x422a78e -> 0x422a801`).

## Inferences

- Implemented in `src/node115-staking/src/rewards.rs` (exported from `src/node115-staking/src/lib.rs`) as pure, `#![forbid(unsafe_code)]`, zero-external-dep Rust.
- `0x3c38360`'s `x - 0.5 * x^2` with `x = 0.015 / max(0.015, sqrt(staked / supply))` matches Hyperliquid's inverse-square-root staking emission schedule (capped at 50% APR at the `0.015` floor, yielding ~2.47% APR at 36% staked).

## Unknowns / Limits

- Exact outer-caller provenance of `reference_supply_wei` (passed in `%r14` from `Exchange::end_block` into `0x3c3f780` -> `0x422c320` -> `0x3c38360`, e.g. fixed genesis total supply vs circulating supply minus burned/non-circulating) is not proven inside this 6-FDE packet.
- These 6 stateful FDEs are behaviorally reconstructed and byte-anchored, not yet compiled to byte-identical machine code; no acceptance gate in `research/progress.json` is flipped.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-staking-rewards-and-decay/verify.py --self-test
(cd research/work-items/RE-008-node115-staking-rewards-and-decay && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_node115_staking_rewards_and_decay.py
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/consensus-staking cargo test --offline --locked --manifest-path src/node115-staking/Cargo.toml
```
