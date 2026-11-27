//! Vault deposit / move core (`0x44ae810`) and protocol vault allowlists.
//!
//! Anchored to node #115 evidence packet `research/work-items/vaults-move-core-115`
//! and micro-crate `src/node115-vault-identity-guards`.

use std::collections::BTreeMap;

use node115_vault_identity_guards::{evaluate_prelude, PreludeResult};

use crate::{
    checked_ratio, finite_clamp_i64, sat_add_i64, sat_add_u64, sat_sub_i64, Address, USD_SCALE,
};

/// Minimum leader-position value in USD (`0x459920`: `1e-7`).
pub const LEADER_SHARE_FLOOR: f64 = 1e-7;

/// Minimum leader share ratio required for non-leader deposits (`0x459038`: `0.05` = 5%).
pub const LEADER_MIN_SHARE_RATIO: f64 = 0.05;

/// Error tag when vault equity is negative and vault is outside [`PROTECTED_VAULT_SET_A`].
pub const ERR_NEGATIVE_VAULT_EQUITY: u16 = 0x09;

/// Error tag when leader entry is missing, below `1e-7`, or leader share `< 5%`.
pub const ERR_LEADER_SHARE_TOO_LOW: u16 = 0x02;

/// Error tag when depositor's available balance is less than the transfer amount.
pub const ERR_INSUFFICIENT_BALANCE: u16 = 0x2d;

/// Hardcoded 8-address protected vault set A at node #115 `0x421a3c0`
/// (exempt from negative-equity rejection `0x09`).
pub const PROTECTED_VAULT_SET_A: [Address; 8] = [
    [
        0x2e, 0x3d, 0x94, 0xf0, 0x56, 0x27, 0x03, 0xb2, 0x5c, 0x83, 0x30, 0x8a, 0x05, 0x04, 0x6d,
        0xda, 0xf9, 0xa8, 0xdd, 0x14,
    ],
    [
        0xb0, 0xa5, 0x5f, 0x13, 0xd2, 0x2f, 0x66, 0xe6, 0xd4, 0x95, 0xac, 0x98, 0x11, 0x38, 0x41,
        0xb2, 0x32, 0x6e, 0x95, 0x40,
    ],
    [
        0x5e, 0x17, 0x7e, 0x5e, 0x39, 0xc0, 0xf4, 0xe4, 0x21, 0xf5, 0x86, 0x5a, 0x6d, 0x8b, 0xee,
        0xd8, 0xd9, 0x21, 0xcb, 0x70,
    ],
    [
        0x2e, 0xd5, 0xc4, 0x48, 0x4e, 0xa3, 0xff, 0x8b, 0x57, 0xd5, 0xf2, 0xfb, 0x15, 0x2a, 0x40,
        0xd9, 0xf2, 0xb6, 0x83, 0x08,
    ],
    [
        0x6a, 0x87, 0x50, 0xa4, 0xcc, 0xcf, 0xfd, 0xb3, 0x94, 0xa7, 0xbb, 0xe9, 0xd4, 0xd0, 0xdc,
        0xef, 0x23, 0xfb, 0x14, 0x17,
    ],
    [
        0xd0, 0x76, 0x1c, 0x28, 0x19, 0x45, 0xec, 0x08, 0x4d, 0x32, 0x44, 0x15, 0xbb, 0x06, 0x06,
        0xbe, 0x2c, 0x8d, 0xf3, 0x82,
    ],
    [
        0xcb, 0xf4, 0xdf, 0xba, 0x8c, 0xdf, 0x95, 0x58, 0xe8, 0x15, 0x53, 0xb0, 0x8f, 0x0d, 0x7c,
        0x91, 0x0b, 0x8c, 0x4e, 0x90,
    ],
    [
        0x4f, 0xbe, 0x63, 0x4d, 0x33, 0x28, 0xb1, 0xd5, 0x6f, 0x10, 0x5b, 0x88, 0x7e, 0xd2, 0x5d,
        0xcb, 0x2c, 0x71, 0xb8, 0x8d,
    ],
];

/// Hardcoded 8-address protected vault set B at node #115 `0x421a520`
/// (exempt from the 5% leader-share check `0x02`).
pub const PROTECTED_VAULT_SET_B: [Address; 8] = [
    [
        0x01, 0x04, 0x61, 0xc1, 0x4e, 0x14, 0x6a, 0xc3, 0x5f, 0xe4, 0x22, 0x71, 0xbd, 0xc1, 0x13,
        0x4e, 0xe3, 0x1c, 0x70, 0x3a,
    ],
    [
        0x31, 0xca, 0x83, 0x95, 0xcf, 0x83, 0x7d, 0xe0, 0x8b, 0x24, 0xda, 0x3f, 0x66, 0x0e, 0x77,
        0x76, 0x1d, 0xfb, 0x97, 0x4b,
    ],
    [
        0x76, 0x84, 0x84, 0xf7, 0xe2, 0xeb, 0xb6, 0x75, 0xc5, 0x78, 0x38, 0x36, 0x6c, 0x02, 0xae,
        0x99, 0xba, 0x2a, 0x9b, 0x08,
    ],
    [
        0xc6, 0x4c, 0xc0, 0x0b, 0x46, 0x10, 0x1b, 0xd4, 0x0a, 0xa1, 0xc3, 0x12, 0x11, 0x95, 0xe8,
        0x5c, 0x0b, 0x09, 0x18, 0xd8,
    ],
    [
        0x07, 0xbe, 0xd5, 0xc0, 0x83, 0x06, 0xe0, 0x26, 0x79, 0x7e, 0x5e, 0xa9, 0x3c, 0x29, 0x3a,
        0xbc, 0x56, 0x73, 0xc2, 0xad,
    ],
    [
        0x93, 0xe2, 0x55, 0x1d, 0x82, 0x1d, 0xda, 0x10, 0x80, 0xa3, 0x72, 0xf0, 0xb0, 0x4b, 0x86,
        0x46, 0x83, 0x20, 0x33, 0x3d,
    ],
    [
        0xa1, 0x50, 0x99, 0xa3, 0x0b, 0xbf, 0x2e, 0x68, 0x94, 0x2d, 0x6f, 0x4c, 0x43, 0xd7, 0x0d,
        0x04, 0xfa, 0xea, 0xb0, 0xa0,
    ],
    [
        0xdf, 0xc2, 0x4b, 0x07, 0x7b, 0xc1, 0x42, 0x5a, 0xd1, 0xde, 0xa7, 0x5b, 0xcb, 0x6f, 0x81,
        0x58, 0xe1, 0x0d, 0xf3, 0x03,
    ],
];

/// Depositor record layout observed in `0x44ae810` (48 bytes total).
#[derive(Clone, Debug, PartialEq)]
pub struct DepositorRecord {
    /// `+0x00`: share weight (`f64`).
    pub weight: f64,
    /// `+0x08`: cumulative unsigned deposited units (`u64`).
    pub deposited_u64: u64,
    /// `+0x10`: signed net deposited / basis units (`i64`).
    pub net_i64: i64,
    /// `+0x18..+0x24`: opaque middle bytes preserved across move updates.
    pub mid: [u8; 12],
    /// `+0x24..+0x30`: 12-byte timestamp / lockup metadata written on deposit.
    pub timestamp_aux: [u8; 12],
}

/// Overflow sites recorded during `0x44ae810`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveOverflow {
    VaultSum,
    LeaderTotal,
    BalanceSub,
    BalanceAdd,
    EntryU64,
    EntryI64,
}

/// Parameters for [`vault_move_core`] (`0x44ae810`).
#[derive(Clone, Debug)]
pub struct MoveRequest {
    pub depositor: Address,
    pub leader: Address,
    pub vault: Address,
    pub raw_mode: u64,
    pub policy_byte: u8,
    pub bypass_leader_check: bool,
    pub amount: i64,
    pub depositor_available: u64,
    pub child_vaults: Vec<Address>,
    pub timestamp_aux: [u8; 12],
}

/// Mutable state updated by [`vault_move_core`].
#[derive(Clone, Debug)]
pub struct MoveState {
    pub global_balance: i64,
    pub entries: BTreeMap<Address, DepositorRecord>,
}

/// Terminal outcome of [`vault_move_core`] (`0x44ae810`).
#[derive(Clone, Debug, PartialEq)]
pub enum MoveOutcome {
    Rejected {
        reason: u16,
    },
    NegativeAmountPanic,
    MissingDepositorAfterSettlePanic,
    Accepted {
        amount_usd: f64,
        vault: Address,
        vault_equity_before: i64,
        overflows: Vec<MoveOverflow>,
    },
}

/// Leader-position USD value computed by `0x44ae810`:
/// `finite_clamp_i64(vault_equity as f64 * leader_weight) as f64 / 1_000_000.0`.
pub fn leader_share_usd(vault_equity: i64, leader_weight: f64) -> f64 {
    let scaled = (vault_equity as f64) * leader_weight;
    let truncated = finite_clamp_i64(scaled);
    (truncated as f64) / USD_SCALE
}

/// Reconstructs the full deposit/move core at node #115 VA `0x44ae810`.
///
/// - `equity_of(addr)` supplies the vault equity value returned by `0x44a9430`.
/// - `settle_fn(&mut state, depositor, amount, vault_equity_before, aux)`
///   represents the `0x44ad9e0` weight-rebalance / depositor-insertion step.
pub fn vault_move_core<E, S>(
    req: &MoveRequest,
    state: &mut MoveState,
    mut equity_of: E,
    mut settle_fn: S,
) -> MoveOutcome
where
    E: FnMut(Address) -> i64,
    S: FnMut(&mut MoveState, Address, i64, i64, [u8; 12]),
{
    if let PreludeResult::Reject { reason, .. } = evaluate_prelude(
        req.raw_mode,
        req.policy_byte,
        &req.depositor,
        &req.leader,
    ) {
        return MoveOutcome::Rejected { reason };
    }

    let mut overflows = Vec::new();
    let mut vault_equity = equity_of(req.vault);

    if (req.raw_mode as u32) == 2 && !req.child_vaults.is_empty() {
        let mut sorted = req.child_vaults.clone();
        sorted.sort();
        for child in sorted {
            let v = equity_of(child);
            let (sum, ovf) = sat_add_i64(vault_equity, v);
            if ovf {
                overflows.push(MoveOverflow::VaultSum);
            }
            vault_equity = sum;
        }
    }

    if vault_equity < 0 && !PROTECTED_VAULT_SET_A.contains(&req.vault) {
        return MoveOutcome::Rejected {
            reason: ERR_NEGATIVE_VAULT_EQUITY,
        };
    }

    let is_leader = req.depositor == req.leader;
    let skip_leader_check = req.bypass_leader_check
        || (req.raw_mode as u32) == 1
        || is_leader
        || PROTECTED_VAULT_SET_B.contains(&req.vault);

    if !skip_leader_check {
        let Some(leader_rec) = state.entries.get(&req.leader) else {
            return MoveOutcome::Rejected {
                reason: ERR_LEADER_SHARE_TOO_LOW,
            };
        };
        let lead_usd = leader_share_usd(vault_equity, leader_rec.weight);
        let base_nonneg = vault_equity.max(0) as u64;
        let (total_u64, ovf) = sat_add_u64(base_nonneg, req.amount as u64);
        if ovf {
            overflows.push(MoveOverflow::LeaderTotal);
        }
        if LEADER_SHARE_FLOOR > lead_usd {
            return MoveOutcome::Rejected {
                reason: ERR_LEADER_SHARE_TOO_LOW,
            };
        }
        let Some(ratio) = checked_ratio(lead_usd, (total_u64 as f64) / USD_SCALE) else {
            return MoveOutcome::Rejected {
                reason: ERR_LEADER_SHARE_TOO_LOW,
            };
        };
        if LEADER_MIN_SHARE_RATIO > ratio {
            return MoveOutcome::Rejected {
                reason: ERR_LEADER_SHARE_TOO_LOW,
            };
        }
    }

    if req.amount < 0 {
        return MoveOutcome::NegativeAmountPanic;
    }
    let amount_u64 = req.amount as u64;
    if req.depositor_available < amount_u64 {
        return MoveOutcome::Rejected {
            reason: ERR_INSUFFICIENT_BALANCE,
        };
    }

    let (b1, ovf_sub) = sat_sub_i64(state.global_balance, req.amount);
    if ovf_sub {
        overflows.push(MoveOverflow::BalanceSub);
    }
    let (b2, ovf_add) = sat_add_i64(b1, req.amount);
    if ovf_add {
        overflows.push(MoveOverflow::BalanceAdd);
    }
    state.global_balance = b2;

    settle_fn(state, req.depositor, req.amount, vault_equity, req.timestamp_aux);

    let Some(entry) = state.entries.get_mut(&req.depositor) else {
        return MoveOutcome::MissingDepositorAfterSettlePanic;
    };
    let (uu, ovf_u) = sat_add_u64(entry.deposited_u64, amount_u64);
    if ovf_u {
        overflows.push(MoveOverflow::EntryU64);
    }
    let (ii, ovf_i) = sat_add_i64(entry.net_i64, req.amount);
    if ovf_i {
        overflows.push(MoveOverflow::EntryI64);
    }
    entry.deposited_u64 = uu;
    entry.net_i64 = ii;
    entry.timestamp_aux = req.timestamp_aux;

    MoveOutcome::Accepted {
        amount_usd: (req.amount as f64) / USD_SCALE,
        vault: req.vault,
        vault_equity_before: vault_equity,
        overflows,
    }
}
