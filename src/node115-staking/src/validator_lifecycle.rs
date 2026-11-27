//! Independently authored Rust reconstruction of node #115's validator
//! registration, profile/commission validation, signer/IP cooldowns, and
//! unregister rules:
//! - `0x2c77640..0x2c77ba5` (`CValidatorAction` front end)
//! - `0x3c3d480..0x3c3f412` (`c_staking_validator_lifecycle`, slot `0x64e7f10`)
//! - `0x3c3a700..0x3c3adf5` (`c_staking_validate_profile`)
//! - `0x469b540..0x469b725` (`ValidatorProfile::validate`, slot `0x64e9650`)
//! - `0x4225b80..0x4225c74` (`register_active_validator`)
//!
//! Backed by `research/work-items/RE-008-node115-staking-crate-map`.

use std::collections::{BTreeMap, BTreeSet};

use crate::delegation::{StakingChain, add_secs_saturating};
use crate::jailing::{Address, JailingTime};

/// Verified native error / success tags from `0x2c77640`, `0x3c3d480`, `0x469b540`, `0x4225b80`.
pub const TAG_ACTION_DISABLED_ON_CHAIN: u16 = 0x092; // 146
pub const TAG_TOO_MANY_VALIDATORS: u16 = 0x096; // 150
pub const TAG_VALIDATOR_ALREADY_REGISTERED: u16 = 0x097; // 151
pub const TAG_INVALID_VALIDATOR: u16 = 0x098; // 152
pub const TAG_VALIDATOR_IP_NOT_GLOBAL: u16 = 0x12f; // 303
pub const TAG_VALIDATOR_NAME_LEN: u16 = 0x130; // 304
pub const TAG_VALIDATOR_DESC_LEN: u16 = 0x131; // 305
pub const TAG_VALIDATOR_COMMISSION_INVALID: u16 = 0x132; // 306
pub const TAG_VALIDATOR_RECENT_SIGNER_OR_IP_CHANGE: u16 = 0x135; // 309
pub const TAG_OTHER_VALIDATOR_RECENT_SIGNER_OR_IP_CHANGE: u16 = 0x136; // 310
pub const TAG_CANNOT_UNREGISTER_WITH_DELEGATIONS: u16 = 0x144; // 324
pub const TAG_INVALID_INPUT_NUMBER: u16 = 0x154; // 340
pub const TAG_INVALID_INPUT: u16 = 0x155; // 341

/// Verified bounds from `0x2c778a2`, `0x3c3d5d3`, and `0x469b5ee..0x469b64b`.
pub const MAX_REGISTERED_VALIDATORS: usize = 1_000; // cmp [rsi+0xe8], 0x3e7; jbe
pub const MAX_INITIAL_WEI: u64 = 0x0ccc_cccc_cccc_cccb; // < 0xccccccccccccccc
pub const VALIDATOR_NAME_MIN_LEN: usize = 1;
pub const VALIDATOR_NAME_MAX_LEN: usize = 50; // 0x32
pub const VALIDATOR_DESC_MIN_LEN: usize = 1;
pub const VALIDATOR_DESC_MAX_LEN: usize = 1_000; // 0x3e8
pub const MAX_COMMISSION_BPS: u64 = 10_000; // 0x2710 (100%)
pub const MAX_COMMISSION_INCREASE_BPS: u64 = 100; // < 0x65 (1%)

/// Errors emitted by `0x2c77640`, `0x3c3d480`, `0x469b540`, and `0x4225b80`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorLifecycleError {
    ActionDisabledOnChain,
    UnknownValidator,
    TooManyValidators,
    ValidatorAlreadyRegistered,
    InvalidValidator,
    NativeTokenMissing,
    InsufficientBalanceToDelegate,
    DelegationsDisabled,
    SelfDelegationInsufficient,
    InvalidInputNumber,
    InvalidInput,
    IpAddressNotGlobal,
    NameLengthOutOfRange { len: usize },
    DescriptionLengthOutOfRange { len: usize },
    CommissionInvalid { commission_bps: u64 },
    ValidatorSignerOrIpChangedRecently,
    OtherValidatorSignerOrIpChangedRecently,
    CannotUnregisterWithDelegations { total_delegated: u64 },
}

impl ValidatorLifecycleError {
    pub const fn native_tag(self) -> u16 {
        match self {
            Self::ActionDisabledOnChain => TAG_ACTION_DISABLED_ON_CHAIN,
            Self::UnknownValidator => crate::delegation::TAG_UNKNOWN_VALIDATOR,
            Self::TooManyValidators => TAG_TOO_MANY_VALIDATORS,
            Self::ValidatorAlreadyRegistered => TAG_VALIDATOR_ALREADY_REGISTERED,
            Self::InvalidValidator => TAG_INVALID_VALIDATOR,
            Self::NativeTokenMissing => crate::delegation::TAG_NATIVE_TOKEN_MISSING,
            Self::InsufficientBalanceToDelegate => {
                crate::delegation::TAG_INSUFFICIENT_BALANCE_DELEGATE
            }
            Self::DelegationsDisabled => crate::delegation::TAG_DELEGATIONS_DISABLED,
            Self::SelfDelegationInsufficient => {
                crate::delegation::TAG_SELF_DELEGATION_INSUFFICIENT
            }
            Self::InvalidInputNumber => TAG_INVALID_INPUT_NUMBER,
            Self::InvalidInput => TAG_INVALID_INPUT,
            Self::IpAddressNotGlobal => TAG_VALIDATOR_IP_NOT_GLOBAL,
            Self::NameLengthOutOfRange { .. } => TAG_VALIDATOR_NAME_LEN,
            Self::DescriptionLengthOutOfRange { .. } => TAG_VALIDATOR_DESC_LEN,
            Self::CommissionInvalid { .. } => TAG_VALIDATOR_COMMISSION_INVALID,
            Self::ValidatorSignerOrIpChangedRecently => TAG_VALIDATOR_RECENT_SIGNER_OR_IP_CHANGE,
            Self::OtherValidatorSignerOrIpChangedRecently => {
                TAG_OTHER_VALIDATOR_RECENT_SIGNER_OR_IP_CHANGE
            }
            Self::CannotUnregisterWithDelegations { .. } => TAG_CANNOT_UNREGISTER_WITH_DELEGATIONS,
        }
    }
}

/// Exact IPv4 global-address predicate matching `0x469b54a..0x469b5e8` and `0x469b694..0x469b6e8`.
pub const fn is_global_ipv4(octets: [u8; 4]) -> bool {
    let [a, b, c, d] = octets;
    if a == 0 || a == 10 || a == 127 {
        return false;
    }
    if a == 169 && b == 254 {
        return false;
    }
    if a == 172 && (b & 0xf0) == 16 {
        return false;
    }
    if a == 192 && b == 168 {
        return false;
    }
    if a == 192 && b == 0 && c == 0 {
        return d == 9 || d == 10;
    }
    if a == 192 && b == 0 && c == 2 {
        return false;
    }
    if a == 198 && b == 51 && c == 100 {
        return false;
    }
    if a == 203 && b == 0 && c == 113 {
        return false;
    }
    if a == 255 && b == 255 && c == 255 && d == 255 {
        return false;
    }
    true
}

/// Validator profile fields checked by `0x469b540`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorProfileInput {
    pub node_ip: [u8; 4],
    pub name: String,
    pub description: String,
    pub commission_bps: u64,
    pub disable_delegations: bool,
    pub signer: Address,
}

/// Reconstructs `0x469b540..0x469b725` (`ValidatorProfile::validate`, slot `0x64e9650`).
pub fn validate_validator_profile(
    profile: &ValidatorProfileInput,
    allow_private_ip: bool,
    previous_commission_bps: Option<u64>,
) -> Result<(), ValidatorLifecycleError> {
    if !allow_private_ip && !is_global_ipv4(profile.node_ip) {
        return Err(ValidatorLifecycleError::IpAddressNotGlobal);
    }
    let name_len = profile.name.len();
    if !(VALIDATOR_NAME_MIN_LEN..=VALIDATOR_NAME_MAX_LEN).contains(&name_len) {
        return Err(ValidatorLifecycleError::NameLengthOutOfRange { len: name_len });
    }
    let desc_len = profile.description.len();
    if !(VALIDATOR_DESC_MIN_LEN..=VALIDATOR_DESC_MAX_LEN).contains(&desc_len) {
        return Err(ValidatorLifecycleError::DescriptionLengthOutOfRange { len: desc_len });
    }
    if profile.commission_bps > MAX_COMMISSION_BPS {
        return Err(ValidatorLifecycleError::CommissionInvalid {
            commission_bps: profile.commission_bps,
        });
    }
    let prev = previous_commission_bps.unwrap_or(MAX_COMMISSION_BPS);
    if profile.commission_bps > prev && profile.commission_bps > MAX_COMMISSION_INCREASE_BPS {
        return Err(ValidatorLifecycleError::CommissionInvalid {
            commission_bps: profile.commission_bps,
        });
    }
    Ok(())
}

/// Stored validator record for [`ValidatorLifecycleState`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredValidator {
    pub profile: ValidatorProfileInput,
    pub last_signer_or_ip_change: JailingTime,
    pub total_delegated: u64,
}

/// Stateful model of `0x2c77640` + `0x3c3d480` + `0x469b540` + `0x4225b80`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorLifecycleState {
    pub permissionless: bool,
    pub allowlist: BTreeSet<Address>,
    pub private_ip_exempt: BTreeSet<Address>,
    pub native_token_exists: bool,
    pub self_delegation_requirement: u64,
    pub per_validator_change_cooldown_secs: u64,
    pub global_change_cooldown_secs: u64,
    pub last_global_signer_or_ip_change: Option<JailingTime>,
    pub validators: BTreeMap<Address, RegisteredValidator>,
}

impl ValidatorLifecycleState {
    /// Reconstructs `CValidatorAction::Register` (`0x2c77890..0x2c779e4` -> `0x3c3d480` -> `0x469b540` -> `0x4225b80`).
    #[allow(clippy::too_many_arguments)]
    pub fn register_validator(
        &mut self,
        chain: StakingChain,
        now: JailingTime,
        validator: Address,
        profile: ValidatorProfileInput,
        initial_wei: u64,
        available_balance: u64,
    ) -> Result<(), ValidatorLifecycleError> {
        if !self.permissionless && !self.allowlist.contains(&validator) {
            return Err(ValidatorLifecycleError::InvalidValidator);
        }
        if chain == StakingChain::Local {
            return Err(ValidatorLifecycleError::ActionDisabledOnChain);
        }
        if initial_wei > MAX_INITIAL_WEI {
            return Err(ValidatorLifecycleError::InvalidInputNumber);
        }
        if initial_wei != 0 || self.self_delegation_requirement != 0 {
            if profile.disable_delegations {
                return Err(ValidatorLifecycleError::DelegationsDisabled);
            }
            if !self.native_token_exists {
                return Err(ValidatorLifecycleError::NativeTokenMissing);
            }
            if initial_wei < self.self_delegation_requirement {
                return Err(ValidatorLifecycleError::SelfDelegationInsufficient);
            }
            if available_balance < initial_wei {
                return Err(ValidatorLifecycleError::InsufficientBalanceToDelegate);
            }
        }
        if self.validators.len() >= MAX_REGISTERED_VALIDATORS {
            return Err(ValidatorLifecycleError::TooManyValidators);
        }
        if self.validators.contains_key(&validator) {
            return Err(ValidatorLifecycleError::ValidatorAlreadyRegistered);
        }
        let allow_private_ip = self.private_ip_exempt.contains(&validator);
        validate_validator_profile(&profile, allow_private_ip, None)?;

        self.validators.insert(
            validator,
            RegisteredValidator {
                profile,
                last_signer_or_ip_change: now,
                total_delegated: initial_wei,
            },
        );
        Ok(())
    }

    /// Reconstructs `CValidatorAction::ChangeProfile` (`0x2c776c3` -> `0x3c3d480` -> `0x469b540` + cooldowns `0x135`/`0x136`).
    pub fn change_profile(
        &mut self,
        now: JailingTime,
        validator: Address,
        new_profile: ValidatorProfileInput,
    ) -> Result<(), ValidatorLifecycleError> {
        if !self.permissionless && !self.allowlist.contains(&validator) {
            return Err(ValidatorLifecycleError::InvalidValidator);
        }
        let existing = self
            .validators
            .get(&validator)
            .ok_or(ValidatorLifecycleError::UnknownValidator)?;
        let prev_commission = existing.profile.commission_bps;
        let signer_or_ip_changed = existing.profile.signer != new_profile.signer
            || existing.profile.node_ip != new_profile.node_ip;
        let last_val_change = existing.last_signer_or_ip_change;

        let allow_private_ip = self.private_ip_exempt.contains(&validator);
        validate_validator_profile(&new_profile, allow_private_ip, Some(prev_commission))?;

        if signer_or_ip_changed {
            let val_unlock =
                add_secs_saturating(last_val_change, self.per_validator_change_cooldown_secs);
            if val_unlock > now {
                return Err(ValidatorLifecycleError::ValidatorSignerOrIpChangedRecently);
            }
            if let Some(last_global) = self.last_global_signer_or_ip_change {
                let global_unlock =
                    add_secs_saturating(last_global, self.global_change_cooldown_secs);
                if global_unlock > now {
                    return Err(ValidatorLifecycleError::OtherValidatorSignerOrIpChangedRecently);
                }
            }
            self.last_global_signer_or_ip_change = Some(now);
        }

        if let Some(entry) = self.validators.get_mut(&validator) {
            entry.profile = new_profile;
            if signer_or_ip_changed {
                entry.last_signer_or_ip_change = now;
            }
        }
        Ok(())
    }

    /// Reconstructs `0x3c3dacd..0x3c3dadc` unregister zero-delegation check (`0x144`).
    pub fn unregister_validator(&mut self, validator: Address) -> Result<(), ValidatorLifecycleError> {
        let entry = self
            .validators
            .get(&validator)
            .ok_or(ValidatorLifecycleError::UnknownValidator)?;
        if entry.total_delegated != 0 {
            return Err(ValidatorLifecycleError::CannotUnregisterWithDelegations {
                total_delegated: entry.total_delegated,
            });
        }
        self.validators.remove(&validator);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    fn t(days: i32, secs: u32) -> JailingTime {
        JailingTime {
            major: days,
            seconds: secs,
            nanos: 0,
        }
    }

    fn good_profile(commission_bps: u64) -> ValidatorProfileInput {
        ValidatorProfileInput {
            node_ip: [8, 8, 8, 8],
            name: "AlphaVal".to_string(),
            description: "High-availability validator".to_string(),
            commission_bps,
            disable_delegations: false,
            signer: addr(0x11),
        }
    }

    #[test]
    fn ipv4_global_and_commission_rules_match_0x469b540() {
        assert!(is_global_ipv4([8, 8, 8, 8]));
        assert!(is_global_ipv4([192, 0, 0, 9]));
        assert!(is_global_ipv4([192, 0, 0, 10]));
        assert!(!is_global_ipv4([192, 0, 0, 8]));
        assert!(!is_global_ipv4([10, 0, 0, 1]));
        assert!(!is_global_ipv4([127, 0, 0, 1]));
        assert!(!is_global_ipv4([172, 16, 0, 1]));
        assert!(!is_global_ipv4([192, 168, 1, 1]));
        assert!(!is_global_ipv4([198, 51, 100, 1]));
        assert!(!is_global_ipv4([255, 255, 255, 255]));

        // Initial registration may set commission up to 10_000 bps (100%)
        validate_validator_profile(&good_profile(500), false, None).unwrap();
        assert_eq!(
            validate_validator_profile(&good_profile(10_001), false, None),
            Err(ValidatorLifecycleError::CommissionInvalid {
                commission_bps: 10_001,
            })
        );
        // Decreasing from 500 -> 200 is allowed
        validate_validator_profile(&good_profile(200), false, Some(500)).unwrap();
        // Increasing from 50 -> 100 (<= 1%) is allowed
        validate_validator_profile(&good_profile(100), false, Some(50)).unwrap();
        // Increasing from 50 -> 101 (> 1%) is rejected with 0x132
        assert_eq!(
            validate_validator_profile(&good_profile(101), false, Some(50)),
            Err(ValidatorLifecycleError::CommissionInvalid {
                commission_bps: 101,
            })
        );
    }

    #[test]
    fn register_cooldown_and_unregister_enforce_native_tags() {
        let mut st = ValidatorLifecycleState {
            permissionless: true,
            native_token_exists: true,
            self_delegation_requirement: 1_000,
            per_validator_change_cooldown_secs: 600,
            global_change_cooldown_secs: 120,
            ..Default::default()
        };

        // Local chain disabled (0x92)
        assert_eq!(
            st.register_validator(StakingChain::Local, t(1, 0), addr(1), good_profile(100), 1_000, 2_000),
            Err(ValidatorLifecycleError::ActionDisabledOnChain)
        );
        // Initial wei below min_self (0x145)
        assert_eq!(
            st.register_validator(StakingChain::Mainnet, t(1, 0), addr(1), good_profile(100), 999, 2_000),
            Err(ValidatorLifecycleError::SelfDelegationInsufficient)
        );
        // Register succeeds
        st.register_validator(StakingChain::Mainnet, t(1, 0), addr(1), good_profile(100), 1_000, 2_000)
            .unwrap();
        // Duplicate fails (0x97)
        assert_eq!(
            st.register_validator(StakingChain::Mainnet, t(1, 0), addr(1), good_profile(100), 1_000, 2_000),
            Err(ValidatorLifecycleError::ValidatorAlreadyRegistered)
        );
        // Unregister with active delegations fails (0x144)
        assert_eq!(
            st.unregister_validator(addr(1)),
            Err(ValidatorLifecycleError::CannotUnregisterWithDelegations {
                total_delegated: 1_000,
            })
        );

        // Changing IP before 600s cooldown fails with 0x135
        let mut moved = good_profile(100);
        moved.node_ip = [1, 1, 1, 1];
        assert_eq!(
            st.change_profile(t(1, 300), addr(1), moved.clone()),
            Err(ValidatorLifecycleError::ValidatorSignerOrIpChangedRecently)
        );
        // After 600s succeeds and records global change timestamp
        st.change_profile(t(1, 600), addr(1), moved).unwrap();

        // Second validator changing IP within 120s of validator 1's change fails with 0x136
        st.register_validator(StakingChain::Mainnet, t(0, 0), addr(2), good_profile(100), 1_000, 2_000)
            .unwrap();
        let mut moved2 = good_profile(100);
        moved2.node_ip = [9, 9, 9, 9];
        assert_eq!(
            st.change_profile(t(1, 650), addr(2), moved2),
            Err(ValidatorLifecycleError::OtherValidatorSignerOrIpChangedRecently)
        );

        // Clearing delegations permits unregister
        st.validators.get_mut(&addr(1)).unwrap().total_delegated = 0;
        st.unregister_validator(addr(1)).unwrap();
        assert!(!st.validators.contains_key(&addr(1)));
    }
}
