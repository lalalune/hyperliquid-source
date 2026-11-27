//! Shared handler admission wrapper (`action-dispatch-prior-key-wrapper-115`,
//! `action-dispatch-shared-admission-115`), timed action router special guards
//! (`0x55f99b0`), and action tag classifier (`0x36c30f0`) for node #115.
//!
//! Anchored to node #115 evidence packets:
//! - `research/work-items/action-dispatch-prior-key-wrapper-115` (10 clones × 1,087 B, 11,000 cases)
//! - `research/work-items/action-dispatch-shared-admission-115` (92/92 handlers verified)
//! - `research/work-items/action-dispatch-timed-router-115` (`0x55f99b0`, 10,260 cases)
//! - `research/work-items/action-dispatch-tag-tables-115` (`0x2bdb5b0`, `0x36c30f0`, 12,000 cases)

use std::collections::BTreeSet;

use action_wire::{
    error_display::ACTION_SUCCESS_TAG,
    rmp_signable::{ENVELOPE_ERR_BYTE, ENVELOPE_OK_BYTE},
    variants::tag_to_index,
    Address,
};

/// Result error word stored at `[out + 0x10]` when key or alias hits the prior-key B-tree set (`0x120`).
pub const PRIOR_KEY_REJECT_CODE: u16 = 0x120;

/// Maximum allowed `CWithdraw` payload word in timed router `0x55f99b0` arm 61 (`< 0x0ccc_cccc_cccc_cccc`).
pub const TIMED_ROUTER_MAX_CWITHDRAW_WORD: u64 = 0x0ccc_cccc_cccc_cccc;

/// Error code emitted by timed router `0x55f99b0` arm 61 when `[tag + 0x28] >= 0x0ccc_cccc_cccc_cccc`.
pub const TIMED_ROUTER_ARM61_OVERFLOW_CODE: u16 = 0x154;

/// Context selector value (`ctx[0xb9a] == 3`) rejected with code `0x91` in timed router arms 63 & 64.
pub const TIMED_ROUTER_CTX_B9A_REJECT_VALUE: u8 = 3;
pub const TIMED_ROUTER_CTX_B9A_REJECT_CODE: u16 = 0x91;

/// Error code emitted by timed router `0x55f99b0` arm 75 when `ctx[0x42ad] == 0`.
pub const TIMED_ROUTER_ARM75_DISABLED_CODE: u16 = 0x92;

/// Router arm index for nested `MultiSig` re-entry (`0xba` -> index `52`).
pub const MULTISIG_ARM_INDEX: usize = 52;

/// Exact 10 router indices whose handlers are identical 1,087-byte prior-key wrapper clones
/// (`action-dispatch-prior-key-wrapper-115` + `action-dispatch-shared-admission-115`).
pub const PRIOR_KEY_CLONE_INDICES: [usize; 10] = [1, 6, 8, 21, 25, 27, 45, 55, 80, 84];

/// Exact 4 router indices whose handler FDEs omit a literal `movw $0x120` store
/// (`cancel`, `cancelByCloid`, `scheduleCancel`, `twapCancel`).
pub const NO_0X120_HANDLER_INDICES: [usize; 4] = [3, 4, 18, 35];

/// Outcome of the 10-clone prior-key handler wrapper (`action-dispatch-prior-key-wrapper-115`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PriorKeyWrapperOutcome<R> {
    /// Original key or resolved alias was present in the prior-key B-tree set (`0xf` / `0x120`).
    PriorKeyRejected { tag_byte: u8, code: u16 },
    /// First shared admission check (`0x2c202b0`) returned a non-`0x1a2` error tag.
    FirstCheckFailed {
        tag_byte: u8,
        error_tag: u16,
        payload: [u8; 0x70],
    },
    /// Second shared admission check (`0x2c206b0`) returned a non-`0x1a2` error tag.
    SecondCheckFailed {
        tag_byte: u8,
        error_tag: u16,
        payload: [u8; 0x70],
    },
    /// Alias probe index exceeded alias table length (bounds panic path in native code).
    AliasIndexOutOfBounds,
    /// All checks passed and the per-clone sink executed with `(effective_key, original_key)`.
    Dispatched {
        effective_key: Address,
        output: R,
    },
}

/// Reconstructs the 5-step prior-key handler wrapper template (`10 × 1,087 B` clones):
/// 1. Consult alias override (`0x2a8ab70`); if present, bypasses alias table and B-tree check (step 4).
/// 2. Otherwise resolve alias in `alias_table` (`count == 1` direct compare, `count > 1` lookup).
/// 3. Walk `prior_keys` B-tree for `original_key` and effective `v`; any hit rejects with `0xf` / `0x120`.
/// 4. Run shared checks `0x2c202b0` then `0x2c206b0` (each succeeds iff `[slot..2] == 0x1a2`).
/// 5. Tail-call sink on success.
pub fn run_prior_key_wrapper<F1, F2, S, R>(
    original_key: Address,
    override_key: Option<Address>,
    alias_table: &[(Address, Address)],
    prior_keys: &BTreeSet<Address>,
    check1: F1,
    check2: F2,
    sink: S,
) -> PriorKeyWrapperOutcome<R>
where
    F1: FnOnce(Address) -> [u8; 0x70],
    F2: FnOnce(Address) -> [u8; 0x70],
    S: FnOnce(Address) -> R,
{
    let effective = if let Some(ov) = override_key {
        ov
    } else {
        let mut resolved = original_key;
        if alias_table.len() == 1 {
            if alias_table[0].0 == original_key {
                resolved = alias_table[0].1;
            }
        } else if alias_table.len() > 1 {
            if let Some((_, target)) = alias_table.iter().find(|(k, _)| *k == original_key) {
                resolved = *target;
            }
        }
        if prior_keys.contains(&original_key) || prior_keys.contains(&resolved) {
            return PriorKeyWrapperOutcome::PriorKeyRejected {
                tag_byte: ENVELOPE_ERR_BYTE,
                code: PRIOR_KEY_REJECT_CODE,
            };
        }
        resolved
    };

    let slot1 = check1(effective);
    let tag1 = u16::from_le_bytes([slot1[0], slot1[1]]);
    if tag1 != ACTION_SUCCESS_TAG {
        return PriorKeyWrapperOutcome::FirstCheckFailed {
            tag_byte: ENVELOPE_ERR_BYTE,
            error_tag: tag1,
            payload: slot1,
        };
    }

    let slot2 = check2(effective);
    let tag2 = u16::from_le_bytes([slot2[0], slot2[1]]);
    if tag2 != ACTION_SUCCESS_TAG {
        return PriorKeyWrapperOutcome::SecondCheckFailed {
            tag_byte: ENVELOPE_ERR_BYTE,
            error_tag: tag2,
            payload: slot2,
        };
    }

    PriorKeyWrapperOutcome::Dispatched {
        effective_key: effective,
        output: sink(original_key),
    }
}

/// Special inline guard result from timed router `0x55f99b0` (`action-dispatch-timed-router-115`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimedRouterGuardOutcome {
    /// Arm 0 (`Noop`): immediately returns ok byte `0x0e`.
    ImmediateOk { tag_byte: u8 },
    /// Arm rejected inline before calling handler (`0x0f` + 16-bit error word).
    InlineError { tag_byte: u8, code: u16 },
    /// Arm 52 (`MultiSig`): re-enters timed router with `force_gate = false`.
    RecurseMultiSig,
    /// Proceed to arm handler.
    DispatchHandler,
}

/// Evaluates the exact inline special-arm guards of timed router `0x55f99b0`
/// (arms 0, 52, 61, 63, 64, 75).
pub const fn check_timed_router_arm_guard(
    index: usize,
    ctx_b9a: u8,
    ctx_42ad: u8,
    arm61_word: u64,
) -> TimedRouterGuardOutcome {
    match index {
        0 => TimedRouterGuardOutcome::ImmediateOk {
            tag_byte: ENVELOPE_OK_BYTE,
        },
        MULTISIG_ARM_INDEX => TimedRouterGuardOutcome::RecurseMultiSig,
        61 if arm61_word >= TIMED_ROUTER_MAX_CWITHDRAW_WORD => {
            TimedRouterGuardOutcome::InlineError {
                tag_byte: ENVELOPE_ERR_BYTE,
                code: TIMED_ROUTER_ARM61_OVERFLOW_CODE,
            }
        }
        63 | 64 if ctx_b9a == TIMED_ROUTER_CTX_B9A_REJECT_VALUE => {
            TimedRouterGuardOutcome::InlineError {
                tag_byte: ENVELOPE_ERR_BYTE,
                code: TIMED_ROUTER_CTX_B9A_REJECT_CODE,
            }
        }
        75 if ctx_42ad == 0 => TimedRouterGuardOutcome::InlineError {
            tag_byte: ENVELOPE_ERR_BYTE,
            code: TIMED_ROUTER_ARM75_DISABLED_CODE,
        },
        _ => TimedRouterGuardOutcome::DispatchHandler,
    }
}

/// Input view for the 92-arm action tag classifier `0x36c30f0` (`action-dispatch-tag-tables-115`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClassifierAction<'a> {
    /// Standard leaf action tag word (`0x86..=0xe1` or niche `< 0x86`), with optional
    /// per-arm flag byte (arms 12/36), batch-modify predicate (arm 2), or order-element flags (arm 14).
    Leaf {
        tag: u64,
        flag_byte: bool,
        order_flags: &'a [bool],
    },
    /// Nested `MultiSig` action (index 52, tag `0xba`) forwarding to its inner action.
    MultiSig(&'a ClassifierAction<'a>),
}

/// Reconstructs the exact 92-arm classifier `0x36c30f0` (`table 0x79afb0`, 7 distinct targets):
/// - indices `3, 4, 18, 35` -> `true`
/// - index `2` (`BatchModify`) -> `flag_byte` (via GOT slot `0x64e8e28`)
/// - indices `12, 36` (`Modify`, `TwapOrder`) -> `flag_byte` (`+0x56` / `+0x55`)
/// - index `14` (`Order`) -> `true` iff every element flag is non-zero (`true` for empty slice)
/// - index `52` (`MultiSig`) -> recursively classifies inner action
/// - all other valid indices -> `false`
pub fn classify_action_tag(action: &ClassifierAction<'_>) -> Option<bool> {
    match action {
        ClassifierAction::MultiSig(inner) => classify_action_tag(inner),
        ClassifierAction::Leaf {
            tag,
            flag_byte,
            order_flags,
        } => {
            let idx = tag_to_index(*tag)?;
            Some(match idx {
                3 | 4 | 18 | 35 => true,
                2 | 12 | 36 => *flag_byte,
                14 => order_flags.iter().all(|&f| f),
                _ => false,
            })
        }
    }
}
