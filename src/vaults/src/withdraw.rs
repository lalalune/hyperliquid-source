//! Vault withdrawal admission gate (`0x44ab4a0`).
//!
//! Anchored to node #115 evidence packet `research/work-items/vaults-withdraw-gate-115`.

use std::collections::BTreeMap;

use crate::{sat_add_i64, sat_sub_i64, sat_trunc_i64, Address, TINY_EPS, USD_SCALE};

/// Minimum allowed withdrawal fraction ratio (`0x459b00`: `1e-8`).
pub const MIN_WITHDRAW_RATIO: f64 = 1e-8;

/// Dust/excess threshold when leaving remaining equity (`5_000_000` = $5.00 in 1e6).
pub const EXCESS_DUST_THRESHOLD: i64 = 5_000_000;

/// Leader self-withdrawal slack factor (`0x459038`: `0.05` = 5%).
pub const SELF_SLACK_FACTOR: f64 = 0.05;

/// Leader minimum remaining equity in 1e6 units (`100_000_000` = $100.00).
pub const LEADER_MIN_REMAINING_EQUITY: i64 = 100_000_000;

/// Minimum displayed close ratio when `taken > locked` (`0x4592d8`: `0.2` = 20%).
pub const KIND_RATIO_FLOOR: f64 = 0.2;

/// Observed withdrawal rejection tags from `0x44ab4a0`.
pub const ERR_NONPOSITIVE_VAULT_EQUITY: u16 = 0x0A;
pub const ERR_MISSING_DEPOSITOR: u16 = 0x0B;
pub const ERR_LOCKUP_NOT_EXPIRED: u16 = 0x0C;
pub const ERR_EXCEEDS_AVAILABLE: u16 = 0x0D;
pub const ERR_RATIO_OUT_OF_RANGE: u16 = 0x0E;
pub const ERR_LEADER_SLACK_VIOLATION: u16 = 0x0F;
pub const ERR_LEADER_MIN_REMAINING: u16 = 0x10;
pub const ERR_REMAINING_BELOW_DUST: u16 = 0x2A;
pub const ERR_VAULT_BELOW_MIN_REMAINING: u16 = 0x11F;

/// Comparable `(date_days, seconds_of_day, nanos)` timestamp triple observed in `0x44ab4a0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GateDateTime {
    pub date_days: i32,
    pub seconds: u32,
    pub nanos: u32,
}

/// Depositor entry subset inspected by `0x44ab4a0`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WithdrawDepositor {
    pub share_fraction: f64,
    pub unlock_time: GateDateTime,
}

/// Inputs to [`evaluate_withdraw_gate`] (`0x44ab4a0`).
#[derive(Clone, Debug)]
pub struct WithdrawGateRequest {
    pub vault_tag: u64,
    pub vault_leader_key: Address,
    pub self_leader_key: Address,
    pub depositor: Address,
    pub child_vaults: Vec<Address>,
    pub request_time: GateDateTime,
    /// `mode == 1`: withdraw explicit `requested_amount`; otherwise withdraw full `available`.
    pub mode: u64,
    pub requested_amount: u64,
    pub available_amount: u64,
    /// `mode2 == 1`: enforce `base - taken >= min_remaining_vault`.
    pub enforce_min_remaining: bool,
    pub min_remaining_vault: i64,
    pub locked_amount: i64,
    pub kind_flag: bool,
}

/// Terminal outcome of [`evaluate_withdraw_gate`] (`0x44ab4a0`).
#[derive(Clone, Debug, PartialEq)]
pub enum WithdrawGateOutcome {
    Rejected {
        code: u16,
    },
    RatioInvalidPanic,
    BaseInvalidPanic,
    Admitted {
        kind: u8,
        shown_ratio: Option<f64>,
        taken: i64,
        ratio: f64,
        vault_equity: i64,
        sum_overflows: usize,
    },
}

/// Evaluates node #115's vault withdrawal admission gate `0x44ab4a0`.
///
/// `depositor.unlock_time` is the already-computed `deposit_time + lock_duration`
/// unlock threshold (matching `date_gate` in `vaults-withdraw-gate-115`).
pub fn evaluate_withdraw_gate<E>(
    req: &WithdrawGateRequest,
    depositors: &BTreeMap<Address, WithdrawDepositor>,
    mut equity_of: E,
) -> WithdrawGateOutcome
where
    E: FnMut(Address) -> i64,
{
    let mut total = equity_of(req.vault_leader_key);
    let mut sum_overflows = 0usize;

    if req.vault_tag == 2 && !req.child_vaults.is_empty() {
        for &child in &req.child_vaults {
            let part = equity_of(child);
            let (grown, ovf) = sat_add_i64(total, part);
            if ovf {
                sum_overflows += 1;
            }
            total = grown;
        }
    }

    if total <= 0 {
        return WithdrawGateOutcome::Rejected {
            code: ERR_NONPOSITIVE_VAULT_EQUITY,
        };
    }
    let base = total;

    let Some(entry) = depositors.get(&req.depositor) else {
        return WithdrawGateOutcome::Rejected {
            code: ERR_MISSING_DEPOSITOR,
        };
    };

    if req.vault_tag != 1 && req.request_time < entry.unlock_time {
        return WithdrawGateOutcome::Rejected {
            code: ERR_LOCKUP_NOT_EXPIRED,
        };
    }

    let explicit_amount = req.mode == 1;
    let amount = if explicit_amount {
        req.requested_amount
    } else {
        req.available_amount
    };

    let frac = entry.share_fraction;
    let base_f = base as f64;
    let lo = (amount as f64) / USD_SCALE;
    let hi = base_f / USD_SCALE;
    let ratio = lo / hi;
    if !ratio.is_finite() || hi < TINY_EPS {
        return if explicit_amount {
            WithdrawGateOutcome::RatioInvalidPanic
        } else {
            WithdrawGateOutcome::BaseInvalidPanic
        };
    }

    if ratio > frac || MIN_WITHDRAW_RATIO > ratio {
        return WithdrawGateOutcome::Rejected {
            code: ERR_RATIO_OUT_OF_RANGE,
        };
    }

    let limit = sat_trunc_i64(frac * base_f);
    if limit > 0 && (limit as u64) > amount {
        let diff = (limit as i128) - (amount as i128);
        if diff < EXCESS_DUST_THRESHOLD as i128 {
            return WithdrawGateOutcome::Rejected {
                code: ERR_REMAINING_BELOW_DUST,
            };
        }
    }

    if amount > req.available_amount {
        return WithdrawGateOutcome::Rejected {
            code: ERR_EXCEEDS_AVAILABLE,
        };
    }

    if req.depositor == req.self_leader_key {
        let diff = frac - ratio;
        let slack = (1.0 - ratio) * SELF_SLACK_FACTOR;
        if slack > MIN_WITHDRAW_RATIO + diff {
            return WithdrawGateOutcome::Rejected {
                code: ERR_LEADER_SLACK_VIOLATION,
            };
        }
        if sat_trunc_i64(diff * base_f) < LEADER_MIN_REMAINING_EQUITY {
            return WithdrawGateOutcome::Rejected {
                code: ERR_LEADER_MIN_REMAINING,
            };
        }
    }

    let product = base_f * ratio;
    let taken = sat_trunc_i64(product);

    if req.enforce_min_remaining {
        let (left, _) = sat_sub_i64(base, taken);
        if left < req.min_remaining_vault {
            return WithdrawGateOutcome::Rejected {
                code: ERR_VAULT_BELOW_MIN_REMAINING,
            };
        }
    }

    if req.vault_tag == 1 {
        return WithdrawGateOutcome::Admitted {
            kind: 0,
            shown_ratio: Some(product),
            taken,
            ratio,
            vault_equity: base,
            sum_overflows,
        };
    }

    if taken <= req.locked_amount {
        if req.kind_flag {
            WithdrawGateOutcome::Admitted {
                kind: 1,
                shown_ratio: Some(ratio),
                taken,
                ratio,
                vault_equity: base,
                sum_overflows,
            }
        } else {
            WithdrawGateOutcome::Admitted {
                kind: 0,
                shown_ratio: None,
                taken,
                ratio,
                vault_equity: base,
                sum_overflows,
            }
        }
    } else {
        let shown = if ratio > KIND_RATIO_FLOOR {
            ratio
        } else {
            KIND_RATIO_FLOOR
        };
        WithdrawGateOutcome::Admitted {
            kind: 1,
            shown_ratio: Some(shown),
            taken,
            ratio,
            vault_equity: base,
            sum_overflows,
        }
    }
}
