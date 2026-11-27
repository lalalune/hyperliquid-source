//! Independently authored Rust reconstruction of node #115's
//! `l1/src/exchange/stake_requirement.rs` (all 7 FDEs: `0x294ceb0`, `0x235a050`,
//! `0x2c58c70`, `0x543ef80`, `0x543ffc0`, `0x5b7a610`, `0x5b9c890`) and
//! `l1/src/staking.rs:325` per-validator stake rollup (`0x3dd9480..0x3dd99d3`
//! calling `0x4351de0..0x4351f56`).

use std::collections::BTreeMap;

use crate::delegation::StakingChain;
use crate::snapshot::ValidatorKey;

/// Exact native `UserError` tag returned on `u64` multiplication overflow in
/// `0x294cf61..0x294cf9b` (`mulq (%rsi,%rcx,8); jo -> 0xc5`, `"Mul result error"`).
pub const TAG_MUL_RESULT_ERROR: u16 = 0xc5;

/// Number of stake-requirement categories indexed through `.rodata` jump/offset
/// tables `0x602d1c` (unit stakes) and `0x60aeec` (category counters in `0x2c58c70`).
pub const STAKE_REQUIREMENT_CATEGORY_COUNT: usize = 4;

/// Exact 4-category x 4-chain (`[Local, Sandbox, Testnet, Mainnet]`) unit-stake
/// table anchored in node #115 `.rodata` via `0x602d1c`:
/// - Category 0 (`0x457d00`): `[100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000]`
/// - Category 1 (`0x457b00`): `[50_000, 20_000_000_000_000, 5_000_000_000, 20_000_000_000_000]`
/// - Category 2 (`0x457f00`): `[200_000, 50_000_000_000_000, 10_000_000_000, 50_000_000_000_000]`
/// - Category 3 (`0x457d00`, shared row): `[100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000]`
pub const STAKE_REQUIREMENT_UNIT_TABLE: [[u64; 4]; STAKE_REQUIREMENT_CATEGORY_COUNT] = [
    [100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000],
    [50_000, 20_000_000_000_000, 5_000_000_000, 20_000_000_000_000],
    [200_000, 50_000_000_000_000, 10_000_000_000, 50_000_000_000_000],
    [100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000],
];

/// Four stake-requirement categories dispatched at `0x60aeec` (`0x2c58c70`) and
/// priced through `0x602d1c` (`0x294ceb0`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StakeRequirementCategory {
    Category0 = 0,
    Category1 = 1,
    Category2 = 2,
    Category3 = 3,
}

impl StakeRequirementCategory {
    pub const ALL: [Self; STAKE_REQUIREMENT_CATEGORY_COUNT] = [
        Self::Category0,
        Self::Category1,
        Self::Category2,
        Self::Category3,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Overflow error returned by `0x294ceb0` (`TAG_MUL_RESULT_ERROR = 0xc5`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StakeRequirementError {
    MulOverflow {
        category: StakeRequirementCategory,
        effective_count: u64,
        unit_stake: u64,
    },
    SumOverflow,
}

impl StakeRequirementError {
    pub const fn native_tag(self) -> u16 {
        match self {
            Self::MulOverflow { .. } => TAG_MUL_RESULT_ERROR,
            Self::SumOverflow => crate::delegation::TAG_ADD_RESULT_ERROR,
        }
    }
}

/// Looks up the exact per-unit stake requirement from `0x602d1c` for `(category, chain)`.
pub const fn unit_stake_requirement(
    category: StakeRequirementCategory,
    chain: StakingChain,
) -> u64 {
    STAKE_REQUIREMENT_UNIT_TABLE[category.index()][chain as usize]
}

/// Evaluates `0x294ceb0..0x294cfbe` for a single category:
/// `effective = existing_count.saturating_add(u64::from(category == target_category))`
/// followed by `effective.checked_mul(unit_stake).ok_or(MulOverflow)` (`0xc5`).
pub const fn category_required_stake(
    chain: StakingChain,
    category: StakeRequirementCategory,
    existing_count: u64,
    target_category: Option<StakeRequirementCategory>,
) -> Result<u64, StakeRequirementError> {
    let bump = match target_category {
        Some(t) if t as u8 == category as u8 => 1u64,
        _ => 0u64,
    };
    let effective_count = existing_count.saturating_add(bump);
    let unit_stake = unit_stake_requirement(category, chain);
    match effective_count.checked_mul(unit_stake) {
        Some(v) => Ok(v),
        None => Err(StakeRequirementError::MulOverflow {
            category,
            effective_count,
            unit_stake,
        }),
    }
}

/// Computes the 4-category required-stake vector (matching `0x235a050` /
/// `0x5b7a610` / `0x5b9c890` collecting the 4 category values) and its checked
/// total sum.
pub fn compute_stake_requirements(
    chain: StakingChain,
    existing_counts: [u64; STAKE_REQUIREMENT_CATEGORY_COUNT],
    target_category: Option<StakeRequirementCategory>,
) -> Result<([u64; STAKE_REQUIREMENT_CATEGORY_COUNT], u64), StakeRequirementError> {
    let mut per_cat = [0u64; STAKE_REQUIREMENT_CATEGORY_COUNT];
    let mut total = 0u64;
    for cat in StakeRequirementCategory::ALL {
        let idx = cat.index();
        let req = category_required_stake(chain, cat, existing_counts[idx], target_category)?;
        per_cat[idx] = req;
        total = total
            .checked_add(req)
            .ok_or(StakeRequirementError::SumOverflow)?;
    }
    Ok((per_cat, total))
}

/// Reconstructs `l1/src/staking.rs:325` (`0x3dd9480..0x3dd99d3`) and its
/// saturating sum helper (`0x4351de0..0x4351f56`): maps each validator's
/// delegator-stake map to `(validator, saturating_sum(stakes))`.
pub fn rollup_validator_stakes<K>(
    stakes_by_validator: &BTreeMap<ValidatorKey, BTreeMap<K, u64>>,
) -> Vec<(ValidatorKey, u64)> {
    stakes_by_validator
        .iter()
        .map(|(&validator, delegators)| {
            let sum = delegators
                .values()
                .copied()
                .fold(0u64, u64::saturating_add);
            (validator, sum)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_table_matches_node115_rodata_constants() {
        assert_eq!(
            unit_stake_requirement(StakeRequirementCategory::Category0, StakingChain::Mainnet),
            50_000_000_000_000
        );
        assert_eq!(
            unit_stake_requirement(StakeRequirementCategory::Category1, StakingChain::Mainnet),
            20_000_000_000_000
        );
        assert_eq!(
            unit_stake_requirement(StakeRequirementCategory::Category1, StakingChain::Testnet),
            5_000_000_000
        );
        assert_eq!(
            unit_stake_requirement(StakeRequirementCategory::Category2, StakingChain::Local),
            200_000
        );
        assert_eq!(
            unit_stake_requirement(StakeRequirementCategory::Category3, StakingChain::Mainnet),
            unit_stake_requirement(StakeRequirementCategory::Category0, StakingChain::Mainnet)
        );
    }

    #[test]
    fn compute_requirements_bumps_target_and_detects_mul_overflow() {
        let (per_cat, total) = compute_stake_requirements(
            StakingChain::Mainnet,
            [1, 0, 0, 0],
            Some(StakeRequirementCategory::Category1),
        )
        .unwrap();
        assert_eq!(
            per_cat,
            [50_000_000_000_000, 20_000_000_000_000, 0, 0]
        );
        assert_eq!(total, 70_000_000_000_000);

        let err = category_required_stake(
            StakingChain::Mainnet,
            StakeRequirementCategory::Category0,
            u64::MAX,
            Some(StakeRequirementCategory::Category0),
        )
        .unwrap_err();
        assert_eq!(err.native_tag(), TAG_MUL_RESULT_ERROR);
    }

    #[test]
    fn rollup_validator_stakes_uses_saturating_sum() {
        let mut map: BTreeMap<ValidatorKey, BTreeMap<u32, u64>> = BTreeMap::new();
        let mut v1 = BTreeMap::new();
        v1.insert(1, u64::MAX - 10);
        v1.insert(2, 25);
        map.insert([0x11; 32], v1);

        let mut v2 = BTreeMap::new();
        v2.insert(1, 300);
        v2.insert(2, 700);
        map.insert([0x22; 32], v2);

        let rolled = rollup_validator_stakes(&map);
        assert_eq!(rolled, vec![([0x11; 32], u64::MAX), ([0x22; 32], 1_000)]);
    }
}
