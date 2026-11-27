//! Vault share-split & profit-commission settlement body (`0x44af2f0`).
//!
//! Anchored to node #115 evidence packet `research/work-items/vaults-split-body-115`.

use std::collections::BTreeMap;

use crate::{
    checked_ratio, sat_add_i64, sat_sub_i64, sat_trunc_i64, Address, TINY_EPS, USD_SCALE,
};

/// Depositor record subset read and updated by `0x44af2f0`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SplitEntry {
    /// Share fraction `v` (`f64`).
    pub share_fraction: f64,
    /// Cost-basis units (`i64`, subtracted unsigned-saturating on withdrawal).
    pub basis_units: i64,
    /// Cumulative net withdrawal / PnL slot 3 (`i64`).
    pub net_slot: i64,
}

/// Request inputs to [`execute_vault_split`] (`0x44af2f0`).
#[derive(Clone, Debug)]
pub struct SplitRequest {
    pub vault_tag: u64,
    pub vault: Address,
    pub leader: Address,
    pub depositor: Address,
    pub child_vaults: Vec<Address>,
    pub ratio: f64,
    pub commission_rate: f64,
    pub limit: i64,
    /// Liquid balance read before the split check, and re-read before debit.
    pub first_balance: i64,
    pub second_balance: i64,
}

/// Mutable state mutated by [`execute_vault_split`].
#[derive(Clone, Debug)]
pub struct SplitState {
    pub counter: i64,
    pub entries: BTreeMap<Address, SplitEntry>,
}

/// Settlement receipt returned on successful split (`0x44af2f0`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SplitReceipt {
    pub limit_usd: f64,
    pub leader_commission_usd: f64,
    pub closing_gap_usd: f64,
    pub basis_units_usd: f64,
    pub depositor_keep_usd: f64,
    pub vault: Address,
    pub depositor: Address,
    pub depositor_keep_raw: i64,
    pub leader_payout_raw: i64,
    pub leader_recipient: Option<Address>,
    pub debit_spend: i64,
    pub apply_negative_delta: i64,
}

/// Outcome of [`execute_vault_split`] (`0x44af2f0`).
#[derive(Clone, Debug, PartialEq)]
pub enum SplitOutcome {
    None,
    InsufficientLiquidBalance,
    NegativeUnitsPanic,
    MissingAfterApplyPanic,
    Settled(SplitReceipt),
}

/// Executes node #115's vault share-split body `0x44af2f0`.
///
/// - `equity_of(addr)` supplies each vault's signed equity from `0x44a9430`.
/// - `apply_reweight(&mut state, depositor, negative_delta, total)` models
///   the inner `0x44ad9e0` weight-rebalance call between the debit and re-lookup.
pub fn execute_vault_split<E, A>(
    req: &SplitRequest,
    state: &mut SplitState,
    mut equity_of: E,
    mut apply_reweight: A,
) -> SplitOutcome
where
    E: FnMut(Address) -> i64,
    A: FnMut(&mut SplitState, Address, i64, i64),
{
    let mut total = equity_of(req.vault);
    if req.vault_tag == 2 && !req.child_vaults.is_empty() {
        for &child in &req.child_vaults {
            let (sum, _) = sat_add_i64(total, equity_of(child));
            total = sum;
        }
    }

    let cut = sat_trunc_i64(req.ratio * (total as f64));
    let (rest, _) = sat_sub_i64(total, cut);
    let (base, _) = sat_sub_i64(total, rest);

    let Some(&entry_before) = state.entries.get(&req.depositor) else {
        return SplitOutcome::None;
    };
    let v = entry_before.share_fraction;
    let units_before = entry_before.basis_units;

    let balance = req.first_balance;
    let exact = (base as i128) - (balance as i128);
    let (diff, _) = sat_sub_i64(base, balance);
    let gap = diff.max(0);

    let (held, g) = if exact <= 0 {
        if req.ratio > v {
            return SplitOutcome::None;
        }
        (base, req.ratio)
    } else {
        let low = ((base as u64) as f64) / USD_SCALE;
        let high = ((balance as u64) as f64) / USD_SCALE;
        if TINY_EPS > low {
            return SplitOutcome::None;
        }
        let quotient = high / low;
        let scaled = req.ratio * quotient;
        if scaled > v {
            return SplitOutcome::None;
        }
        (balance, scaled)
    };

    if units_before < 0 {
        return SplitOutcome::NegativeUnitsPanic;
    }

    let Some(q) = checked_ratio(g, v) else {
        return SplitOutcome::None;
    };
    let units = sat_trunc_i64(q * (units_before as f64));
    if units < 0 {
        return SplitOutcome::None;
    }

    if held > req.second_balance {
        return SplitOutcome::InsufficientLiquidBalance;
    }

    let spend = held.max(0);
    let (c1, _) = sat_sub_i64(state.counter, spend);
    state.counter = c1;

    let raw_apply = sat_trunc_i64(g * (total as f64));
    let negative_delta = if raw_apply == i64::MIN {
        i64::MAX
    } else {
        -raw_apply
    };

    apply_reweight(state, req.depositor, negative_delta, total);

    let Some(entry_now) = state.entries.get_mut(&req.depositor) else {
        return SplitOutcome::MissingAfterApplyPanic;
    };
    let now_u64 = entry_now.basis_units as u64;
    let units_u64 = units as u64;
    entry_now.basis_units = if now_u64 < units_u64 {
        0
    } else {
        (now_u64 - units_u64) as i64
    };

    let (left, _) = sat_sub_i64(held, units);
    let raw_commission = sat_trunc_i64((left as f64) * req.commission_rate);
    let leader_payout = raw_commission.max(0);
    if raw_commission > 0 {
        let (c2, _) = sat_add_i64(state.counter, leader_payout);
        state.counter = c2;
    }

    let (keep, _) = sat_sub_i64(held, leader_payout);
    let paid = keep.max(0);
    let (c3, _) = sat_add_i64(state.counter, paid);
    state.counter = c3;

    let (slot3, _) = sat_sub_i64(entry_now.net_slot, keep);
    entry_now.net_slot = slot3;

    let (gap_a, _) = sat_sub_i64(req.limit, held);
    let (gap_b, _) = sat_sub_i64(gap_a, gap);

    SplitOutcome::Settled(SplitReceipt {
        limit_usd: (req.limit as f64) / USD_SCALE,
        leader_commission_usd: (leader_payout as f64) / USD_SCALE,
        closing_gap_usd: (gap_b as f64) / USD_SCALE,
        basis_units_usd: (units as f64) / USD_SCALE,
        depositor_keep_usd: (keep as f64) / USD_SCALE,
        vault: req.vault,
        depositor: req.depositor,
        depositor_keep_raw: keep,
        leader_payout_raw: leader_payout,
        leader_recipient: if raw_commission > 0 {
            Some(req.leader)
        } else {
            None
        },
        debit_spend: spend,
        apply_negative_delta: negative_delta,
    })
}
