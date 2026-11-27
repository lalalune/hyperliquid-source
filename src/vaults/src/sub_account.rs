//! Sub-account creation admission (`0x366a620`, `l1/src/sub_account.rs:75`)
//! and label guard (`0x366b350`).
//!
//! Anchored to node #115 evidence packets:
//! - `research/work-items/RE-001-node115-subaccount-admission-append`
//! - `research/work-items/RE-012-subaccount-label-guard-115`

use crate::Address;

/// Minimum raw volume required to create a sub-account (`0x366a63a`: `0x989680` = `10_000_000`).
pub const MIN_VOLUME_RAW: u64 = 10_000_000;

/// Divisor applied when formatting the volume error payload (`0x459498`: `100.0`).
pub const VOLUME_DISPLAY_DIVISOR: f64 = 100.0;

/// Reciprocal volume step per additional sub-account (`0x366a688`: `floor(v / 10_000_000_000)`).
pub const VOLUME_PER_EXTRA_SUB_ACCOUNT: u64 = 10_000_000_000;

/// Base sub-account allowance (`0x366a6a9`: `+ 10`).
pub const BASE_SUB_ACCOUNT_CAP: u64 = 10;

/// Maximum bonus sub-accounts above base (`0x366a69c`: `min(quot, 70)` -> max total 80).
pub const MAX_EXTRA_SUB_ACCOUNTS: u64 = 70;

/// Maximum byte length admitted by the outer caller before `0x366b350` (`len < 101`).
pub const OUTER_NAME_LEN_LIMIT: usize = 100;

/// Byte length range admitted by the inner label guard `0x366b350` (`1..=16`).
pub const LABEL_MIN_BYTES: usize = 1;
pub const LABEL_MAX_BYTES: usize = 16;

/// Observed node #115 result tags in `0x366a620` and `0x366b350`.
pub const TAG_SUCCESS: u16 = 0x1a2;
pub const TAG_ERR_LIMIT_REACHED: u16 = 0xe5;
pub const TAG_ERR_DUPLICATE_LABEL: u16 = 0xe6;
pub const TAG_ERR_DUPLICATE_ADDRESS: u16 = 0xe7;
pub const TAG_ERR_INVALID_LABEL_LEN: u16 = 0xe8;
pub const TAG_ERR_VOLUME_TOO_LOW: u16 = 0xec;
pub const TAG_ERR_NAME_TOO_LONG: u16 = 0x158;

/// Rejection reason from sub-account admission (`0x366a620` / `0x366b350`).
#[derive(Clone, Debug, PartialEq)]
pub enum SubAccountReject {
    /// Raw volume below [`MIN_VOLUME_RAW`] (tag `0xec`, payload `volume as f64 / 100.0`).
    VolumeTooLow { volume_scaled: f64 },
    /// Existing sub-account count `>= max_sub_accounts_for_volume(volume)` (tag `0xe5`).
    LimitReached { current: usize, max: u64 },
    /// Derived sub-account address already exists (tag `0xe7`).
    DuplicateAddress,
    /// Raw name byte length `>= 101` before calling `0x366b350` (tag `0x158`).
    NameTooLong { len: usize },
    /// Raw label byte length outside `1..=16` in `0x366b350` (tag `0xe8`).
    InvalidLabelLength { len: usize },
    /// Case-folded label duplicates an existing sub-account label in `0x366b350` (tag `0xe6`).
    DuplicateLabel,
}

impl SubAccountReject {
    pub const fn tag(&self) -> u16 {
        match self {
            Self::VolumeTooLow { .. } => TAG_ERR_VOLUME_TOO_LOW,
            Self::LimitReached { .. } => TAG_ERR_LIMIT_REACHED,
            Self::DuplicateAddress => TAG_ERR_DUPLICATE_ADDRESS,
            Self::NameTooLong { .. } => TAG_ERR_NAME_TOO_LONG,
            Self::InvalidLabelLength { .. } => TAG_ERR_INVALID_LABEL_LEN,
            Self::DuplicateLabel => TAG_ERR_DUPLICATE_LABEL,
        }
    }
}

/// Computes the exact capped sub-account allowance from `0x366a688..0x366a6ad`.
///
/// Uses the same unsigned division (`mul 0xDBE6FECEBDEDD5BF; shr 33`, exact for
/// all `u64` as `floor(volume / 10_000_000_000)`), clamped to `70` and `+ 10`.
pub fn max_sub_accounts_for_volume(volume_raw: u64) -> u64 {
    let quot = volume_raw / VOLUME_PER_EXTRA_SUB_ACCOUNT;
    quot.min(MAX_EXTRA_SUB_ACCOUNTS) + BASE_SUB_ACCOUNT_CAP
}

/// Reconstructs the byte-length and transformed-duplicate guard at `0x366b350`.
///
/// Note: `0x366b350` checks `1 <= label.len() <= 16` on raw UTF-8 byte length
/// before transforming through `str::to_lowercase` (`0x141cc40`).
pub fn validate_sub_account_label(
    label: &str,
    existing_labels: &[&str],
) -> Result<(), SubAccountReject> {
    let len = label.len();
    if !(LABEL_MIN_BYTES..=LABEL_MAX_BYTES).contains(&len) {
        return Err(SubAccountReject::InvalidLabelLength { len });
    }
    let candidate = label.to_lowercase();
    for existing in existing_labels {
        if existing.to_lowercase() == candidate {
            return Err(SubAccountReject::DuplicateLabel);
        }
    }
    Ok(())
}

/// Existing sub-account record tracked for a master account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExistingSubAccount {
    pub address: Address,
    pub label: String,
}

/// Evaluates the ordered admission checks of `0x366a620` (`l1/src/sub_account.rs:75`)
/// up to record append, returning the admitted sub-account record on success.
pub fn admit_sub_account(
    volume_raw: u64,
    derived_address: Address,
    label: &str,
    existing_for_master: &[ExistingSubAccount],
    address_already_registered: bool,
) -> Result<ExistingSubAccount, SubAccountReject> {
    if volume_raw < MIN_VOLUME_RAW {
        return Err(SubAccountReject::VolumeTooLow {
            volume_scaled: (volume_raw as f64) / VOLUME_DISPLAY_DIVISOR,
        });
    }

    if !existing_for_master.is_empty() {
        let max = max_sub_accounts_for_volume(volume_raw);
        if (existing_for_master.len() as u64) >= max {
            return Err(SubAccountReject::LimitReached {
                current: existing_for_master.len(),
                max,
            });
        }
    }

    if address_already_registered {
        return Err(SubAccountReject::DuplicateAddress);
    }

    if label.len() > OUTER_NAME_LEN_LIMIT {
        return Err(SubAccountReject::NameTooLong { len: label.len() });
    }

    let existing_labels: Vec<&str> = existing_for_master
        .iter()
        .map(|s| s.label.as_str())
        .collect();
    validate_sub_account_label(label, &existing_labels)?;

    Ok(ExistingSubAccount {
        address: derived_address,
        label: label.to_string(),
    })
}
