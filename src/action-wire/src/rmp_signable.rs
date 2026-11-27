//! L1 `rmp_signable` connection-ID preimage/hash, 128-byte action-wrapper result fold,
//! `user_outcome` admission guards, and `ActionDelayer` metadata for node #115.
//!
//! Anchored to node #115 `.data.rel.ro` `Location`s and `.text` FDEs:
//! - `l1/src/action/rmp_signable.rs:14:55` (`0x36aa9a0`, `0x3c267e0`, `0x421bb70`)
//! - `l1/src/action/vault_transfer.rs:27:18` (`0x283c6b0`, `0x532f980`, `0x532fa40`)
//! - `l1/src/action/withdraw3.rs:17:22` (`0x246cd10`, `0x59da3e0`, `0x59da4a0`)
//! - `l1/src/action/user_outcome.rs:55:56, 59:26` (`0x283b5b0`, `0x567c830`, `0x567d220`)
//! - `l1/src/action/vote_global.rs:1504:40` (`0x28cd7a0`, `0x538cd30`, `0x5397b50`)
//! - `l1/src/action_delayer.rs` (`.rodata 0x5c9a34` `struct ActionDelayer with 6 elements`)

use crate::{error_display::ACTION_SUCCESS_TAG, keccak256, Address};

/// Result envelope discriminant for `Ok` in 128-byte action wrappers (`0x283c708`, `0x246cd68`).
pub const ENVELOPE_OK_BYTE: u8 = 0x0e;

/// Result envelope discriminant for `Err` in 128-byte action wrappers (`0x283c758`, `0x246cdb8`).
pub const ENVELOPE_ERR_BYTE: u8 = 0x0f;

/// `user_outcome` refusal tag when outcome feature flag `[ctx + 0x2a9] == 0` (`0x283b5d3`).
pub const USER_OUTCOME_DISABLED_TAG: u16 = 0x92;

/// `user_outcome` refusal tag when `[ctx + 0x2a8] != 0` (`0x283b5c5`, sub-code `7`).
pub const USER_OUTCOME_BLOCKED_TAG: u16 = 0x193;
pub const USER_OUTCOME_BLOCKED_SUBCODE: u8 = 7;

/// `user_outcome` refusal tag when account is absent (`0x283b65e`).
pub const USER_OUTCOME_UNKNOWN_USER_TAG: u16 = 0x15;

/// Number of serialized fields in `ActionDelayer` (`.rodata 0x5c9a34`: `struct ActionDelayer with 6 elements`).
pub const ACTION_DELAYER_FIELD_COUNT: usize = 6;

/// Builds the exact byte preimage hashed by `l1/src/action/rmp_signable.rs:14:55` (`0x36aa9a0`):
/// `msgpack_action || nonce.to_be_bytes() || (0x00 | 0x01 || vault_address) || (optional 0x00 || expires_after.to_be_bytes())`.
pub fn connection_id_preimage(
    msgpack_action: &[u8],
    nonce: u64,
    vault_address: Option<Address>,
    expires_after: Option<u64>,
) -> Vec<u8> {
    let extra = 8
        + if vault_address.is_some() { 21 } else { 1 }
        + if expires_after.is_some() { 9 } else { 0 };
    let mut buf = Vec::with_capacity(msgpack_action.len() + extra);
    buf.extend_from_slice(msgpack_action);
    buf.extend_from_slice(&nonce.to_be_bytes());
    match vault_address {
        Some(addr) => {
            buf.push(0x01);
            buf.extend_from_slice(&addr);
        }
        None => buf.push(0x00),
    }
    if let Some(exp) = expires_after {
        buf.push(0x00);
        buf.extend_from_slice(&exp.to_be_bytes());
    }
    buf
}

/// Computes the 32-byte L1 action connection ID (`keccak256(connection_id_preimage(...))`)
/// matching `0x36aa9a0..0x36aabde` (`l1/src/action/rmp_signable.rs:14:55`).
pub fn connection_id(
    msgpack_action: &[u8],
    nonce: u64,
    vault_address: Option<Address>,
    expires_after: Option<u64>,
) -> [u8; 32] {
    let preimage = connection_id_preimage(msgpack_action, nonce, vault_address, expires_after);
    keccak256(&preimage)
}

/// Folded 128-byte action wrapper result matching `vault_transfer` (`0x283c6b0`)
/// and `withdraw3` (`0x246cd10`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionEnvelopeFold {
    /// Inner tag word equaled `0x1a2` -> outer tag byte `0x0e`.
    Ok { tag_byte: u8 },
    /// Inner tag word != `0x1a2` -> outer tag byte `0x0f` + `0x70`-byte error payload copy.
    Err {
        tag_byte: u8,
        error_tag: u16,
        payload: [u8; 0x70],
    },
}

/// Reconstructs the 184-byte result-folding wrapper shared by `vault_transfer.rs:27:18`
/// (`0x283c6b0`) and `withdraw3.rs:17:22` (`0x246cd10`).
pub fn fold_action_result(inner_slot: &[u8; 0x70]) -> ActionEnvelopeFold {
    let inner_tag = u16::from_le_bytes([inner_slot[0], inner_slot[1]]);
    if inner_tag == ACTION_SUCCESS_TAG {
        ActionEnvelopeFold::Ok {
            tag_byte: ENVELOPE_OK_BYTE,
        }
    } else {
        ActionEnvelopeFold::Err {
            tag_byte: ENVELOPE_ERR_BYTE,
            error_tag: inner_tag,
            payload: *inner_slot,
        }
    }
}

/// Refusal outcome from `l1/src/action/user_outcome.rs` entry checks (`0x283b5b0..0x283b694`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserOutcomeEntryReject {
    /// Feature flag `[ctx + 0x2a9] == 0` -> tag `0x92`.
    Disabled { tag: u16 },
    /// Blocked flag `[ctx + 0x2a8] != 0` -> tag `0x193`, sub-code `7`.
    Blocked { tag: u16, subcode: u8 },
    /// Sender absent from user set -> tag `0x15`.
    UnknownUser { tag: u16 },
}

/// Evaluates the exact ordered entry guards of `l1/src/action/user_outcome.rs` (`0x283b5b0`).
pub const fn check_user_outcome_entry(
    outcomes_enabled: bool,
    outcomes_blocked: bool,
    user_exists: bool,
) -> Result<(), UserOutcomeEntryReject> {
    if !outcomes_enabled {
        return Err(UserOutcomeEntryReject::Disabled {
            tag: USER_OUTCOME_DISABLED_TAG,
        });
    }
    if outcomes_blocked {
        return Err(UserOutcomeEntryReject::Blocked {
            tag: USER_OUTCOME_BLOCKED_TAG,
            subcode: USER_OUTCOME_BLOCKED_SUBCODE,
        });
    }
    if !user_exists {
        return Err(UserOutcomeEntryReject::UnknownUser {
            tag: USER_OUTCOME_UNKNOWN_USER_TAG,
        });
    }
    Ok(())
}

/// Delayed action envelope metadata matching `.rodata 0x5c9a46` (`ActionDelayer` / `DelayedAction`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelayedActionRecord {
    pub id: u64,
    pub action_index: usize,
    pub is_frontend: bool,
    pub expires_after: Option<u64>,
    pub delay_scale: u64,
}
