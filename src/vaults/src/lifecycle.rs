//! Binary-verified node #115 vault lifecycle helpers from `l1/src/vault/mod.rs`:
//! - `Vault::vault_equity` (`0x44aad40..0x44ab017`, 727 B)
//! - `Vault::max_withdrawable` (`0x44abfb0..0x44ac60e`, 1,630 B)
//! - `Vault::new` (`0x44ae320..0x44ae805`, 1,253 B)
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

use crate::{sat_add_i64, sat_sub_i64, sat_trunc_i64, Address};

/// Maximum accepted initial USD value (`0x44ae34b`: `0x0ccc_cccc_cccc_cccc`).
pub const MAX_INITIAL_USD: u64 = 0x0ccc_cccc_cccc_cccc;

/// Minimum initial deposit to create a vault (`0x44ae35a`: `> 0x5f5e0ff` -> `100_000_000` = $100).
pub const MIN_INITIAL_USD: u64 = 100_000_000;

/// Outer vault name/description byte-length limits (`0x44ae3c0`, `0x44ae429`).
pub const VAULT_NAME_OUTER_LIMIT: usize = 100;
pub const VAULT_NAME_MIN_LEN: usize = 3;
pub const VAULT_NAME_MAX_LEN: usize = 50;
pub const VAULT_DESC_MIN_LEN: usize = 10;
pub const VAULT_DESC_MAX_LEN: usize = 250;

/// Chain lockup durations from `.rodata` table at `0x454110` (`[20.0, 86400.0]`).
pub const LOCKUP_SECONDS_NON_MAINNET: f64 = 20.0;
pub const LOCKUP_SECONDS_MAINNET: f64 = 86_400.0;

/// Default leader profit-share commission (`0x4593e0`: `0.1` = 10%).
pub const DEFAULT_LEADER_COMMISSION: f64 = 0.1;

/// Leader minimum remaining share ratio multiplier `0.05 / 0.95` (`0x459240`).
pub const LEADER_MIN_KEEP_RATIO_OF_FOLLOWERS: f64 = 0.052_631_578_947_368_425;

/// Leader minimum remaining equity in `0x44abfb0` (`0x44ac4bf`: `0x5f5e100` = $100).
pub const LEADER_MIN_REMAINING_USD: i64 = 100_000_000;

/// Node #115 `Vault::new` error tags observed in `0x44ae320..0x44ae805`.
pub const TAG_ERR_INITIAL_DEPOSIT_TOO_SMALL: u16 = 0x01;
pub const TAG_ERR_NAME_TOO_SHORT: u16 = 0x03;
pub const TAG_ERR_NAME_TOO_LONG: u16 = 0x04;
pub const TAG_ERR_DESC_TOO_SHORT: u16 = 0x05;
pub const TAG_ERR_INVALID_USD_AMOUNT: u16 = 0x154;
pub const TAG_ERR_STRING_TOO_LONG: u16 = 0x158;

/// Validation error returned by [`validate_new_vault`] (`0x44ae320`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewVaultError {
    InvalidUsdAmount { amount: u64 },
    InitialDepositTooSmall,
    NameOuterTooLong { len: usize },
    NameTooShort,
    NameTooLong,
    DescriptionOuterTooLong { len: usize },
    DescriptionTooShort,
}

impl NewVaultError {
    pub const fn tag(self) -> u16 {
        match self {
            Self::InvalidUsdAmount { .. } => TAG_ERR_INVALID_USD_AMOUNT,
            Self::InitialDepositTooSmall => TAG_ERR_INITIAL_DEPOSIT_TOO_SMALL,
            Self::NameOuterTooLong { .. } | Self::DescriptionOuterTooLong { .. } => {
                TAG_ERR_STRING_TOO_LONG
            }
            Self::NameTooShort => TAG_ERR_NAME_TOO_SHORT,
            Self::NameTooLong => TAG_ERR_NAME_TOO_LONG,
            Self::DescriptionTooShort => TAG_ERR_DESC_TOO_SHORT,
        }
    }
}

/// Admitted vault configuration produced by [`validate_new_vault`] (`0x44ae320`).
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedVaultConfig {
    pub initial_usd: u64,
    pub lockup_seconds: f64,
    pub leader_commission: f64,
}

/// Reconstructs the ordered validation and defaults of `Vault::new` (`0x44ae320..0x44ae805`).
///
/// `chain_id == 3` corresponds to Mainnet (`86400.0` s lockup); all other chain
/// IDs select `20.0` s (`0x44ae4aa..0x44ae4b8`). When `zero_commission` is true,
/// `leader_commission` is `0.0`, otherwise `0.1` (`0x4593e0`).
pub fn validate_new_vault(
    initial_usd: u64,
    name: &str,
    description: &str,
    chain_id: u8,
    zero_commission: bool,
) -> Result<ValidatedVaultConfig, NewVaultError> {
    if initial_usd >= MAX_INITIAL_USD {
        return Err(NewVaultError::InvalidUsdAmount {
            amount: initial_usd,
        });
    }
    if initial_usd < MIN_INITIAL_USD {
        return Err(NewVaultError::InitialDepositTooSmall);
    }
    let name_len = name.len();
    if name_len > VAULT_NAME_OUTER_LIMIT {
        return Err(NewVaultError::NameOuterTooLong { len: name_len });
    }
    if name_len < VAULT_NAME_MIN_LEN {
        return Err(NewVaultError::NameTooShort);
    }
    if name_len > VAULT_NAME_MAX_LEN {
        return Err(NewVaultError::NameTooLong);
    }
    let desc_len = description.len();
    if desc_len > VAULT_DESC_MAX_LEN {
        return Err(NewVaultError::DescriptionOuterTooLong { len: desc_len });
    }
    if desc_len < VAULT_DESC_MIN_LEN {
        return Err(NewVaultError::DescriptionTooShort);
    }
    let lockup_seconds = if chain_id == 3 {
        LOCKUP_SECONDS_MAINNET
    } else {
        LOCKUP_SECONDS_NON_MAINNET
    };
    let leader_commission = if zero_commission {
        0.0
    } else {
        DEFAULT_LEADER_COMMISSION
    };
    Ok(ValidatedVaultConfig {
        initial_usd,
        lockup_seconds,
        leader_commission,
    })
}

/// Reconstructs `Vault::vault_equity` (`0x44aad40..0x44ab017`).
///
/// Sums the vault's own equity (`0x44a9430`) and, when `vault_tag == 2`
/// (parent vault relationship), saturating-adds every child vault's equity.
pub fn aggregate_vault_equity<E>(
    vault: Address,
    vault_tag: u32,
    child_vaults: &[Address],
    mut equity_of: E,
) -> (i64, usize)
where
    E: FnMut(Address) -> i64,
{
    let mut total = equity_of(vault);
    let mut overflows = 0usize;
    if vault_tag == 2 {
        for &child in child_vaults {
            let (next, ovf) = sat_add_i64(total, equity_of(child));
            if ovf {
                overflows += 1;
            }
            total = next;
        }
    }
    (total, overflows)
}

/// Reconstructs the leader/follower cap of `Vault::max_withdrawable` (`0x44abfb0..0x44ac60e`).
///
/// - Computes `user_equity = sat_trunc_i64(share_fraction * (total_equity as f64))`.
/// - For a non-leader follower, returns `user_equity.max(0) as u64`.
/// - For the vault leader, reserves at least `max(LEADER_MIN_REMAINING_USD, sat_trunc_i64(follower_equity * (0.05 / 0.95)))`
///   matching `0x44ac458..0x44ac4d5` (`0x459240` = `0.052631578947368425`, `0x5f5e100` = `$100`).
pub fn max_withdrawable_for_user(
    total_equity: i64,
    share_fraction: f64,
    is_leader: bool,
) -> u64 {
    if total_equity <= 0 || !share_fraction.is_finite() || share_fraction <= 0.0 {
        return 0;
    }
    let user_equity = sat_trunc_i64(share_fraction * (total_equity as f64));
    if user_equity <= 0 {
        return 0;
    }
    if !is_leader {
        return user_equity as u64;
    }
    let (follower_equity, _) = sat_sub_i64(total_equity, user_equity);
    let ratio_keep = if follower_equity > 0 {
        sat_trunc_i64((follower_equity as f64) * LEADER_MIN_KEEP_RATIO_OF_FOLLOWERS)
    } else {
        0
    };
    let min_keep = ratio_keep.max(LEADER_MIN_REMAINING_USD);
    let (withdrawable, _) = sat_sub_i64(user_equity, min_keep);
    withdrawable.max(0) as u64
}
