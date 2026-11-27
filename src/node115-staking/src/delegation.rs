//! Independently authored Rust reconstruction of node #115's staking
//! delegation, undelegation, lockup, and self-delegation lifecycle:
//! - `0x2c68bb0..0x2c68e80` (`TokenDelegate` action front end)
//! - `0x3c34fd0..0x3c35a0e` (`c_staking::delegate_or_undelegate`, slot `0x64e7e70`)
//! - `0x4221f40..0x4222753` (`delegate_core`)
//! - `0x4221510..0x4221a8e` (`undelegate_core`)
//! - `0x42258d0..0x4225a2c` (`sub_active_stake`)
//! - `0x4225a30..0x4225b7f` (`add_active_stake`)
//!
//! Backed by `research/work-items/RE-008-node115-staking-delegation`.

use std::collections::{BTreeMap, BTreeSet};

use crate::jailing::{Address, JailingTime};

/// Native action-error / success tags verified in `0x2c68bb0`, `0x3c34fd0`,
/// `0x4221f40`, `0x4221510`, and `0x4225a30`.
pub const TAG_DELEGATE_ZERO_AMOUNT: u16 = 0x033; // 51
pub const TAG_UNKNOWN_VALIDATOR: u16 = 0x095; // 149
pub const TAG_MISSING_EPOCH_STATE: u16 = 0x09b; // 155
pub const TAG_ADD_RESULT_ERROR: u16 = 0x0c3; // 195
pub const TAG_NATIVE_TOKEN_MISSING: u16 = 0x10a; // 266
pub const TAG_INSUFFICIENT_BALANCE_DELEGATE: u16 = 0x10b; // 267
pub const TAG_DELEGATIONS_DISABLED: u16 = 0x10c; // 268
pub const TAG_INSUFFICIENT_BALANCE_UNDELEGATE: u16 = 0x10d; // 269
pub const TAG_LOCKUP_ACTIVE: u16 = 0x10e; // 270
pub const TAG_SELF_DELEGATION_INSUFFICIENT: u16 = 0x145; // 325
pub const TAG_ACTION_OK: u16 = 0x1a2; // 418

/// Exact IEEE-754 `f64` bit patterns at `.rodata 0x4578a0..0x4578c0` indexed by
/// `StakingChain as usize` (`0..=3`), used in `0x4222005..0x4222012`.
pub const DELEGATION_LOCKUP_SECS_BITS: [u64; 4] = [
    0x4122_7500_0000_0000, // Local:   604,800.0 s (7 days)
    0x405e_0000_0000_0000, // Sandbox:     120.0 s (2 minutes)
    0x405e_0000_0000_0000, // Testnet:     120.0 s (2 minutes)
    0x40f5_1800_0000_0000, // Mainnet:  86,400.0 s (1 day)
];

/// Exact 1-Julian-year (`365.25 * 86400 = 31,557,600.0` s) self-delegation lock
/// duration loaded from `.rodata 0x459058` at `0x2c68e38`.
pub const SELF_DELEGATION_LOCK_SECS_BITS: u64 = 0x417e_187e_0000_0000;

/// Chain discriminant order matching `node115-chain-name-codec` and `0x46f40b0`
/// (`cmp dil, 3` for Mainnet).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StakingChain {
    Local = 0,
    Sandbox = 1,
    Testnet = 2,
    Mainnet = 3,
}

impl StakingChain {
    /// Delegation lockup duration in seconds from `.rodata 0x4578a0`.
    pub const fn delegation_lockup_secs(self) -> u64 {
        match self {
            Self::Local => 604_800,
            Self::Sandbox | Self::Testnet => 120,
            Self::Mainnet => 86_400,
        }
    }

    /// Exact raw IEEE-754 `f64` bits from `.rodata 0x4578a0[chain * 8]`.
    pub const fn delegation_lockup_bits(self) -> u64 {
        DELEGATION_LOCKUP_SECS_BITS[self as usize]
    }
}

/// Exact `mode` discriminant passed at `[rdx + 0x00]` to `0x3c34fd0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegationMode {
    /// `mode = 0`: normal undelegate enforcing lockup (`0x10e`) and `min_self_delegation` (`0x145`).
    Undelegate { min_self_delegation: u64 },
    /// `mode = 1`: unchecked undelegate bypassing lockup and `min_self_delegation`.
    UncheckedUndelegate,
    /// `mode = 2`: delegate; `no_lockup` (bit 0 at `[rdx+0x08]`) bypasses disabled checks and lockup extension.
    Delegate { no_lockup: bool },
}

/// Errors emitted by `0x2c68bb0`, `0x3c34fd0`, `0x4221f40`, `0x4221510`, and `0x4225a30`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegationError {
    NativeTokenMissing,
    ZeroAmount,
    UnknownValidator,
    MissingEpochState,
    ValidatorDelegationsDisabled,
    InsufficientBalanceToDelegate,
    InsufficientBalanceToUndelegate,
    LockupActive { locked_until: JailingTime },
    SelfDelegationInsufficient { remaining: u64, required: u64 },
}

impl DelegationError {
    pub const fn native_tag(self) -> u16 {
        match self {
            Self::NativeTokenMissing => TAG_NATIVE_TOKEN_MISSING,
            Self::ZeroAmount => TAG_DELEGATE_ZERO_AMOUNT,
            Self::UnknownValidator => TAG_UNKNOWN_VALIDATOR,
            Self::MissingEpochState => TAG_MISSING_EPOCH_STATE,
            Self::ValidatorDelegationsDisabled => TAG_DELEGATIONS_DISABLED,
            Self::InsufficientBalanceToDelegate => TAG_INSUFFICIENT_BALANCE_DELEGATE,
            Self::InsufficientBalanceToUndelegate => TAG_INSUFFICIENT_BALANCE_UNDELEGATE,
            Self::LockupActive { .. } => TAG_LOCKUP_ACTIVE,
            Self::SelfDelegationInsufficient { .. } => TAG_SELF_DELEGATION_INSUFFICIENT,
        }
    }
}

/// Per-`(user, validator)` delegation record matching the 24-byte value in `[state+0xf0]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserDelegation {
    pub amount: u64,
    pub locked_until: JailingTime,
}

/// Per-`(validator, delegator)` epoch-minimum stake tracker matching `[rbx+0..0x18]`
/// in `0x4221f40` / `0x4221510`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochMinStake {
    pub current: u64,
    pub epoch_min: u64,
    pub last_epoch: u64,
}

/// Active validator stake record matching `[r15+0..0x10]` in `0x42258d0` / `0x4225a30`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveValidatorStake {
    pub epoch_min_stake: u64,
    pub current_stake: u64,
}

/// Validator metadata tracked by `0x3c34fd0` & `0x2c68bb0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatorDelegationInfo {
    /// Profile-level disable flag (`[state+0xd0]` entry `+0x50`).
    pub profile_disabled: bool,
    /// Runtime validator-state disable flag (`[state+0x288]` entry `+0x18`).
    pub delegations_disabled: bool,
    /// Validator registration timestamp queried via slot `0x64e7e78 -> 0x3c3a0b0`.
    pub registered_at: JailingTime,
}

/// Pure-Rust state model covering the fields mutated by `0x2c68bb0`, `0x3c34fd0`,
/// `0x4221f40`, `0x4221510`, `0x42258d0`, and `0x4225a30`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DelegationState {
    pub native_token_exists: bool,
    pub current_epoch: Option<u64>,
    /// Minimum self-delegation required during the 1-year lock (`[exchange+0x1090]`).
    pub self_delegation_requirement: u64,
    /// Minimum self-delegation below which `0x3c35862..0x3c3586f` auto-disables delegations (`[state+0x308]`).
    pub min_self_delegation_for_delegations: u64,
    /// Validators exempt from the 1-year expiration (always enforcing `self_delegation_requirement`, `0x64e7e80`).
    pub permanent_self_delegation_validators: BTreeSet<Address>,
    /// Active validator stakes (`[state+0x10]`).
    pub active_stakes: BTreeMap<Address, ActiveValidatorStake>,
    /// Validator delegation flags & registration timestamps (`[state+0xd0]` / `[state+0x288]`).
    pub validators: BTreeMap<Address, ValidatorDelegationInfo>,
    /// User liquid staking balances (`[state+0x228]`).
    pub user_balances: BTreeMap<Address, u64>,
    /// User pending withdrawal amounts subtracted before delegation (`[state+0x268]`).
    pub pending_withdrawals: BTreeMap<Address, u64>,
    /// User -> Validator -> Delegation (`[state+0xf0]`).
    pub user_delegations: BTreeMap<Address, BTreeMap<Address, UserDelegation>>,
    /// Validator -> total delegated stake (`[val+0x20]`).
    pub validator_total_delegated: BTreeMap<Address, u64>,
    /// Validator -> User -> EpochMinStake (`[state+0x110]`).
    pub validator_delegators: BTreeMap<Address, BTreeMap<Address, EpochMinStake>>,
    /// Count of `0xc3` active-stake addition overflows observed (`0x4225b6c`).
    pub add_overflow_alerts: u64,
}

/// Adds whole seconds to `JailingTime`, clamping on overflow.
pub fn add_secs_saturating(t: JailingTime, secs: u64) -> JailingTime {
    let total_secs = u64::from(t.seconds).saturating_add(secs);
    let add_days = total_secs / 86_400;
    let rem_secs = (total_secs % 86_400) as u32;
    let new_days = i64::from(t.major).saturating_add(add_days.min(i64::MAX as u64) as i64);
    if new_days > i64::from(i32::MAX) {
        JailingTime {
            major: i32::MAX,
            seconds: 86_399,
            nanos: 999_999_999,
        }
    } else {
        JailingTime {
            major: new_days as i32,
            seconds: rem_secs,
            nanos: t.nanos,
        }
    }
}

impl DelegationState {
    /// Available delegatable balance for `user` (`0x3c35889..0x3c3588e`: saturating subtraction).
    pub fn available_to_delegate(&self, user: &Address) -> u64 {
        let balance = self.user_balances.get(user).copied().unwrap_or(0);
        let pending = self.pending_withdrawals.get(user).copied().unwrap_or(0);
        balance.saturating_sub(pending)
    }

    /// Total delegated stake held by `user` across all validators.
    pub fn user_total_delegated(&self, user: &Address) -> u64 {
        self.user_delegations
            .get(user)
            .map(|m| m.values().fold(0u64, |acc, d| acc.saturating_add(d.amount)))
            .unwrap_or(0)
    }

    /// Reconstructs `0x2c68bb0` (`TokenDelegate` action front end):
    /// `is_undelegate_raw == 0` -> Delegate, `1` -> Undelegate (with 1-year self-delegation rule),
    /// `> 1` -> UncheckedUndelegate.
    pub fn handle_token_delegate(
        &mut self,
        chain: StakingChain,
        now: JailingTime,
        user: Address,
        validator: Address,
        amount: u64,
        is_undelegate_raw: u8,
    ) -> Result<(), DelegationError> {
        if !self.native_token_exists {
            return Err(DelegationError::NativeTokenMissing);
        }
        if amount == 0 {
            return Err(DelegationError::ZeroAmount);
        }

        let mode = match is_undelegate_raw {
            0 => DelegationMode::Delegate { no_lockup: false },
            1 => {
                let min_self = if user == validator {
                    let info = self
                        .validators
                        .get(&validator)
                        .ok_or(DelegationError::UnknownValidator)?;
                    if self.permanent_self_delegation_validators.contains(&validator) {
                        self.self_delegation_requirement
                    } else {
                        let unlock_at = add_secs_saturating(info.registered_at, 31_557_600);
                        if unlock_at < now {
                            0
                        } else {
                            self.self_delegation_requirement
                        }
                    }
                } else {
                    0
                };
                DelegationMode::Undelegate {
                    min_self_delegation: min_self,
                }
            }
            _ => DelegationMode::UncheckedUndelegate,
        };

        self.delegate_or_undelegate(chain, now, user, validator, amount, mode)
    }

    /// Reconstructs `0x3c34fd0` (`c_staking::delegate_or_undelegate`) + `0x4221f40` / `0x4221510`
    /// + `0x4225a30` / `0x42258d0`.
    pub fn delegate_or_undelegate(
        &mut self,
        chain: StakingChain,
        now: JailingTime,
        user: Address,
        validator: Address,
        amount: u64,
        mode: DelegationMode,
    ) -> Result<(), DelegationError> {
        if !self.active_stakes.contains_key(&validator) {
            return Err(DelegationError::UnknownValidator);
        }
        let current_epoch = self
            .current_epoch
            .ok_or(DelegationError::MissingEpochState)?;

        match mode {
            DelegationMode::Delegate { no_lockup } => {
                if !no_lockup {
                    let info = self
                        .validators
                        .get(&validator)
                        .ok_or(DelegationError::UnknownValidator)?;
                    if info.profile_disabled || info.delegations_disabled {
                        return Err(DelegationError::ValidatorDelegationsDisabled);
                    }
                }
                let available = self.available_to_delegate(&user);
                self.delegate_core(
                    chain,
                    now,
                    current_epoch,
                    user,
                    validator,
                    amount,
                    available,
                    no_lockup,
                )?;
                self.add_active_stake(&validator, amount);
                Ok(())
            }
            DelegationMode::Undelegate {
                min_self_delegation,
            } => {
                self.undelegate_core(
                    now,
                    current_epoch,
                    user,
                    validator,
                    amount,
                    Some(min_self_delegation),
                )?;
                self.sub_active_stake(&validator, amount);
                self.maybe_disable_after_self_undelegate(&user, &validator);
                Ok(())
            }
            DelegationMode::UncheckedUndelegate => {
                self.undelegate_core(now, current_epoch, user, validator, amount, None)?;
                self.sub_active_stake(&validator, amount);
                self.maybe_disable_after_self_undelegate(&user, &validator);
                Ok(())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn delegate_core(
        &mut self,
        chain: StakingChain,
        now: JailingTime,
        current_epoch: u64,
        user: Address,
        validator: Address,
        amount: u64,
        available: u64,
        no_lockup: bool,
    ) -> Result<(), DelegationError> {
        if available < amount {
            return Err(DelegationError::InsufficientBalanceToDelegate);
        }

        let bal = self.user_balances.entry(user).or_insert(0);
        *bal = bal.saturating_sub(amount);

        let lockup_secs = chain.delegation_lockup_secs();
        let user_map = self.user_delegations.entry(user).or_default();
        match user_map.get_mut(&validator) {
            Some(entry) => {
                entry.amount = entry.amount.saturating_add(amount);
                if !no_lockup {
                    entry.locked_until = add_secs_saturating(now, lockup_secs);
                }
            }
            None => {
                let locked_until = if no_lockup {
                    now
                } else {
                    add_secs_saturating(now, lockup_secs)
                };
                user_map.insert(
                    validator,
                    UserDelegation {
                        amount,
                        locked_until,
                    },
                );
            }
        }

        let total = self.validator_total_delegated.entry(validator).or_insert(0);
        *total = total.saturating_add(amount);

        let val_map = self.validator_delegators.entry(validator).or_default();
        match val_map.get_mut(&user) {
            Some(rec) => {
                if rec.last_epoch != current_epoch {
                    rec.last_epoch = current_epoch;
                    rec.epoch_min = rec.current;
                }
                rec.current = rec.current.saturating_add(amount);
            }
            None => {
                val_map.insert(
                    user,
                    EpochMinStake {
                        current: amount,
                        epoch_min: 0,
                        last_epoch: current_epoch,
                    },
                );
            }
        }

        Ok(())
    }

    fn undelegate_core(
        &mut self,
        now: JailingTime,
        current_epoch: u64,
        user: Address,
        validator: Address,
        amount: u64,
        checked_min_self_delegation: Option<u64>,
    ) -> Result<(), DelegationError> {
        let entry = self
            .user_delegations
            .get(&user)
            .and_then(|m| m.get(&validator))
            .copied()
            .ok_or(DelegationError::InsufficientBalanceToUndelegate)?;

        if entry.amount < amount {
            return Err(DelegationError::InsufficientBalanceToUndelegate);
        }

        if let Some(min_self) = checked_min_self_delegation {
            if entry.locked_until > now {
                return Err(DelegationError::LockupActive {
                    locked_until: entry.locked_until,
                });
            }
            let remaining = entry.amount.saturating_sub(amount);
            if remaining < min_self {
                return Err(DelegationError::SelfDelegationInsufficient {
                    remaining,
                    required: min_self,
                });
            }
        }

        let remaining = entry.amount.saturating_sub(amount);
        let credited = entry.amount - remaining;
        let bal = self.user_balances.entry(user).or_insert(0);
        *bal = bal.saturating_add(credited);

        if remaining == 0 {
            if let Some(m) = self.user_delegations.get_mut(&user) {
                m.remove(&validator);
                if m.is_empty() {
                    self.user_delegations.remove(&user);
                }
            }
        } else if let Some(m) = self.user_delegations.get_mut(&user)
            && let Some(slot) = m.get_mut(&validator)
        {
            slot.amount = remaining;
        }

        if let Some(total) = self.validator_total_delegated.get_mut(&validator) {
            *total = total.saturating_sub(amount);
        }

        if let Some(val_map) = self.validator_delegators.get_mut(&validator) {
            let mut remove_user = false;
            if let Some(rec) = val_map.get_mut(&user) {
                rec.current = rec.current.saturating_sub(amount);
                if rec.last_epoch == current_epoch {
                    rec.epoch_min = rec.epoch_min.min(rec.current);
                } else {
                    rec.last_epoch = current_epoch;
                    rec.epoch_min = rec.current;
                }
                if rec.current == 0 {
                    remove_user = true;
                }
            }
            if remove_user {
                val_map.remove(&user);
                if val_map.is_empty() {
                    self.validator_delegators.remove(&validator);
                }
            }
        }

        Ok(())
    }

    /// Reconstructs `0x4225a30..0x4225b7f` (`add_active_stake`).
    fn add_active_stake(&mut self, validator: &Address, amount: u64) {
        if let Some(active) = self.active_stakes.get_mut(validator) {
            match active.current_stake.checked_add(amount) {
                Some(sum) => active.current_stake = sum,
                None => self.add_overflow_alerts = self.add_overflow_alerts.saturating_add(1),
            }
        }
    }

    /// Reconstructs `0x42258d0..0x4225a2c` (`sub_active_stake`).
    fn sub_active_stake(&mut self, validator: &Address, amount: u64) {
        if let Some(active) = self.active_stakes.get_mut(validator) {
            active.current_stake = active.current_stake.saturating_sub(amount);
            active.epoch_min_stake = active.epoch_min_stake.min(active.current_stake);
        }
    }

    /// Reconstructs `0x3c35377..0x3c353df` and `0x3c3583b..0x3c35875`:
    /// after a validator undelegates from itself, if its remaining self-delegation
    /// is absent or strictly less than `[state+0x308]`, sets `delegations_disabled = true`.
    fn maybe_disable_after_self_undelegate(&mut self, user: &Address, validator: &Address) {
        if user != validator {
            return;
        }
        let self_delegated = self
            .user_delegations
            .get(user)
            .and_then(|m| m.get(validator))
            .map(|d| d.amount)
            .unwrap_or(0);
        if self_delegated < self.min_self_delegation_for_delegations
            && let Some(info) = self.validators.get_mut(validator)
        {
            info.delegations_disabled = true;
        }
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

    fn sample_state() -> DelegationState {
        let mut st = DelegationState {
            native_token_exists: true,
            current_epoch: Some(10),
            self_delegation_requirement: 1_000,
            min_self_delegation_for_delegations: 500,
            ..Default::default()
        };
        st.active_stakes.insert(
            addr(1),
            ActiveValidatorStake {
                epoch_min_stake: 2_000,
                current_stake: 2_000,
            },
        );
        st.validators.insert(
            addr(1),
            ValidatorDelegationInfo {
                profile_disabled: false,
                delegations_disabled: false,
                registered_at: t(100, 0),
            },
        );
        st.user_balances.insert(addr(2), 1_000);
        st.pending_withdrawals.insert(addr(2), 300);
        st
    }

    #[test]
    fn delegate_enforces_available_balance_lockup_and_epoch_min() {
        let mut st = sample_state();
        // Zero amount rejected with 0x33
        assert_eq!(
            st.handle_token_delegate(StakingChain::Mainnet, t(101, 0), addr(2), addr(1), 0, 0),
            Err(DelegationError::ZeroAmount)
        );
        // Balance 1000 - pending 300 = 700 available; delegating 701 fails with 0x10b
        assert_eq!(
            st.handle_token_delegate(StakingChain::Mainnet, t(101, 0), addr(2), addr(1), 701, 0),
            Err(DelegationError::InsufficientBalanceToDelegate)
        );
        // Delegating 500 succeeds, sets 1-day lockup on Mainnet, epoch_min = 0 for new delegator
        st.handle_token_delegate(StakingChain::Mainnet, t(101, 10), addr(2), addr(1), 500, 0)
            .unwrap();
        assert_eq!(st.user_balances[&addr(2)], 500);
        assert_eq!(st.active_stakes[&addr(1)].current_stake, 2_500);
        assert_eq!(
            st.user_delegations[&addr(2)][&addr(1)],
            UserDelegation {
                amount: 500,
                locked_until: t(102, 10),
            }
        );
        assert_eq!(
            st.validator_delegators[&addr(1)][&addr(2)],
            EpochMinStake {
                current: 500,
                epoch_min: 0,
                last_epoch: 10,
            }
        );

        // Undelegating during lockup fails with 0x10e
        assert_eq!(
            st.handle_token_delegate(StakingChain::Mainnet, t(102, 9), addr(2), addr(1), 100, 1),
            Err(DelegationError::LockupActive {
                locked_until: t(102, 10),
            })
        );

        // Epoch advances to 11; adding 100 snapshots prior current (500) into epoch_min
        st.current_epoch = Some(11);
        st.handle_token_delegate(StakingChain::Testnet, t(102, 10), addr(2), addr(1), 100, 0)
            .unwrap();
        assert_eq!(
            st.validator_delegators[&addr(1)][&addr(2)],
            EpochMinStake {
                current: 600,
                epoch_min: 500,
                last_epoch: 11,
            }
        );
        // Testnet lockup is 120s
        assert_eq!(
            st.user_delegations[&addr(2)][&addr(1)].locked_until,
            t(102, 130)
        );
        // Undelegating 400 after lockup lowers epoch_min to min(500, 200) = 200
        st.handle_token_delegate(StakingChain::Testnet, t(102, 130), addr(2), addr(1), 400, 1)
            .unwrap();
        assert_eq!(
            st.validator_delegators[&addr(1)][&addr(2)].epoch_min,
            200
        );
        assert_eq!(st.active_stakes[&addr(1)].current_stake, 2_200);
        assert_eq!(st.active_stakes[&addr(1)].epoch_min_stake, 2_000);
    }

    #[test]
    fn self_undelegation_enforces_1yr_lock_and_auto_disables_below_threshold() {
        let mut st = sample_state();
        st.user_balances.insert(addr(1), 1_500);
        // Validator self-delegates 1_200 at day 100
        st.handle_token_delegate(StakingChain::Testnet, t(100, 0), addr(1), addr(1), 1_200, 0)
            .unwrap();
        // Before 365.25 days (day 200), undelegating 300 leaves 900 < 1000 -> 0x145
        assert_eq!(
            st.handle_token_delegate(StakingChain::Testnet, t(200, 0), addr(1), addr(1), 300, 1),
            Err(DelegationError::SelfDelegationInsufficient {
                remaining: 900,
                required: 1_000,
            })
        );
        // After 365.25 days (day 466 > 100 + 365.25), self-delegation floor expires,
        // and undelegating 800 leaves 400 < 500 -> succeeds AND sets delegations_disabled = true!
        st.handle_token_delegate(StakingChain::Testnet, t(466, 0), addr(1), addr(1), 800, 1)
            .unwrap();
        assert!(st.validators[&addr(1)].delegations_disabled);
        // External delegate is now rejected with 0x10c
        assert_eq!(
            st.handle_token_delegate(StakingChain::Testnet, t(466, 10), addr(2), addr(1), 100, 0),
            Err(DelegationError::ValidatorDelegationsDisabled)
        );
    }

    #[test]
    fn lockup_bits_match_rodata_constants() {
        assert_eq!(
            f64::from_bits(StakingChain::Local.delegation_lockup_bits()),
            604_800.0
        );
        assert_eq!(
            f64::from_bits(StakingChain::Sandbox.delegation_lockup_bits()),
            120.0
        );
        assert_eq!(
            f64::from_bits(StakingChain::Testnet.delegation_lockup_bits()),
            120.0
        );
        assert_eq!(
            f64::from_bits(StakingChain::Mainnet.delegation_lockup_bits()),
            86_400.0
        );
        assert_eq!(f64::from_bits(SELF_DELEGATION_LOCK_SECS_BITS), 31_557_600.0);
    }
}
