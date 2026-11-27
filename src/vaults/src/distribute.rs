//! Binary-verified node #115 vault distribution routine (`0x44a97b0`, `l1/src/vault/mod.rs:517,525,526`).
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
//!
//! Static observations in `0x44a97b0..0x44aad40` (5,520 B):
//! - Minimum explicit distribution amount: `$10.00 USDC` (`cmpq $0x989680, %r15` at `0x44a9ad7`) -> error tag `0x13`.
//! - Exceeding max distributable or non-positive/non-finite fraction -> error tag `0x12`.
//! - Close-all distribution (`usd == None`) requires `vault_equity == withdrawable_balance`, else tag `0x14`.
//! - Vault withdrawable balance `< usd` (or `< residual`) -> error tag `0x34`.
//! - Per-follower profit-share math (`0x44aa0c4..0x44aa430`):
//!   - `ledger_change = finite_clamp_i64(weight_fraction * (usd as f64))`
//!   - `basis_change = sat_nonneg_i64((vault_entry_usd as f64) * (usd / vault_equity))`
//!   - `commission_usd = finite_clamp_i64(((ledger_change - basis_change) as f64) * leader_commission).max(0)`
//!   - `user_ledger_change = ledger_change - commission_usd` (logs `0x7d2afa` if `<= 0`)
//! - Residual `usd - sum(ledger_change)` is settled between vault and leader (`0x44aa86c..0x44aab23`), returning `0x1a2`.

use crate::{finite_clamp_i64, Address};

/// Minimum explicit vault distribution amount (`0x989680` = $10.00 in 1e6 USDC).
pub const VAULT_DISTRIBUTE_MIN_USD: u64 = 0x0098_9680;

/// Error and success status tags observed in `0x44a97b0`.
pub const TAG_INVALID_DISTRIBUTE_AMOUNT: u16 = 0x12;
pub const TAG_BELOW_MIN_DISTRIBUTE_USD: u16 = 0x13;
pub const TAG_CLOSE_BALANCE_MISMATCH: u16 = 0x14;
pub const TAG_INSUFFICIENT_VAULT_BALANCE: u16 = 0x34;
pub const TAG_OK: u16 = 0x1a2;

/// Follower state consumed and updated by `Vault::distribute` (`0x44a97b0`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VaultFollowerDistributeState {
    pub user: Address,
    /// Follower's normalized share fraction (`weight / total_weight`).
    pub weight_fraction: f64,
    /// Follower's cost basis (`vault_entry_usd`, must be `>= 0`).
    pub vault_entry_usd: i64,
    /// Follower's cumulative net deposit / ledger balance (`+0x10` in follower struct).
    pub net_deposit: i64,
}

/// Per-follower distribution payout emitted by `distribute_vault` (`0x44aa0c4..0x44aa430`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FollowerDistributionPayout {
    pub user: Address,
    pub ledger_change: i64,
    pub basis_change: i64,
    pub commission_usd: i64,
    pub user_ledger_change: i64,
    pub transfer_to_user: i64,
    pub non_positive_warning: bool,
}

/// Full result of `distribute_vault` (`0x44a97b0`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultDistributeOutcome {
    Ok {
        tag: u16,
        distributed_usd: u64,
        total_follower_ledger_change: i64,
        total_commission_usd: i64,
        leader_residual: i64,
        payouts: Vec<FollowerDistributionPayout>,
    },
    Rejected {
        tag: u16,
    },
}

/// Non-negative saturating `f64 -> i64` matching `0x44aa15c..0x44aa19c` (`+inf -> 0`, `NaN -> 0`, `> i64::MAX -> i64::MAX`).
#[inline]
fn sat_nonneg_basis_i64(x: f64) -> i64 {
    if x.is_nan() || x == f64::INFINITY || x <= 0.0 {
        0
    } else if x >= (i64::MAX as f64) {
        i64::MAX
    } else {
        x as i64
    }
}

/// Reconstructs `Vault::distribute` (`0x44a97b0`, `l1/src/vault/mod.rs:517,525,526`).
pub fn distribute_vault(
    requested_usd: Option<u64>,
    vault_equity: i64,
    max_distributable: u64,
    vault_withdrawable: u64,
    leader_commission: f64,
    followers: &mut [VaultFollowerDistributeState],
) -> VaultDistributeOutcome {
    let usd = match requested_usd {
        Some(amount) => {
            if amount < VAULT_DISTRIBUTE_MIN_USD {
                return VaultDistributeOutcome::Rejected {
                    tag: TAG_BELOW_MIN_DISTRIBUTE_USD,
                };
            }
            if amount > max_distributable {
                return VaultDistributeOutcome::Rejected {
                    tag: TAG_INVALID_DISTRIBUTE_AMOUNT,
                };
            }
            if vault_equity <= 0 {
                return VaultDistributeOutcome::Rejected {
                    tag: TAG_INVALID_DISTRIBUTE_AMOUNT,
                };
            }
            amount
        }
        None => {
            if vault_equity < 0 || (vault_equity as u64) != vault_withdrawable {
                return VaultDistributeOutcome::Rejected {
                    tag: TAG_CLOSE_BALANCE_MISMATCH,
                };
            }
            if vault_equity == 0 {
                return VaultDistributeOutcome::Rejected {
                    tag: TAG_INVALID_DISTRIBUTE_AMOUNT,
                };
            }
            vault_equity as u64
        }
    };

    let usd_f = usd as f64;
    let fraction = usd_f / (vault_equity as f64);
    if !fraction.is_finite() {
        return VaultDistributeOutcome::Rejected {
            tag: TAG_INVALID_DISTRIBUTE_AMOUNT,
        };
    }

    if vault_withdrawable < usd {
        return VaultDistributeOutcome::Rejected {
            tag: TAG_INSUFFICIENT_VAULT_BALANCE,
        };
    }

    let mut payouts = Vec::with_capacity(followers.len());
    let mut total_ledger_change = 0i64;
    let mut total_commission = 0i64;

    for f in followers.iter_mut() {
        let ledger_change = finite_clamp_i64(f.weight_fraction * usd_f);
        let entry_f = f.vault_entry_usd.max(0) as f64;
        let basis_change = sat_nonneg_basis_i64(entry_f * fraction);
        let profit = ledger_change.saturating_sub(basis_change);
        let commission_usd = finite_clamp_i64((profit as f64) * leader_commission).max(0);
        let user_ledger_change = ledger_change.saturating_sub(commission_usd);
        let non_positive_warning = user_ledger_change <= 0;

        f.net_deposit = f.net_deposit.saturating_sub(user_ledger_change);
        f.vault_entry_usd = f.vault_entry_usd.saturating_sub(basis_change.max(0));

        total_ledger_change = total_ledger_change.saturating_add(ledger_change);
        total_commission = total_commission.saturating_add(commission_usd);

        payouts.push(FollowerDistributionPayout {
            user: f.user,
            ledger_change,
            basis_change,
            commission_usd,
            user_ledger_change,
            transfer_to_user: user_ledger_change.max(0),
            non_positive_warning,
        });
    }

    let usd_i64 = i64::try_from(usd).unwrap_or(i64::MAX);
    let leader_residual = usd_i64.saturating_sub(total_ledger_change);

    VaultDistributeOutcome::Ok {
        tag: TAG_OK,
        distributed_usd: usd,
        total_follower_ledger_change: total_ledger_change,
        total_commission_usd: total_commission,
        leader_residual,
        payouts,
    }
}
