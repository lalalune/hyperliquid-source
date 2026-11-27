//! Independently authored Rust reconstruction of node #115 validator jailing
//! and unjailing (`l1/src/c_staking/jailing.rs`: `0x3c3c260`, `0x3c35a10`,
//! `0x3c35fe0`; evidence packet `RE-008-node115-staking-jailing`).

use std::collections::{BTreeMap, BTreeSet};

use crate::error_text::{
    JAILED_UNTIL_DISCRIMINANT, MANUAL_UNJAIL_DISCRIMINANT, MANUAL_UNJAIL_INTERVAL_BITS,
};

pub type Address = [u8; 20];

/// Status discriminants observed in `0x3c3c260` (`jailing.rs:38`).
pub const STATUS_OK: u16 = 0x1a2;
pub const STATUS_DISABLED: u16 = 0x99;
pub const STATUS_MANUAL_UNJAIL_COOLDOWN: u16 = MANUAL_UNJAIL_DISCRIMINANT; // 0x9f (159)
pub const STATUS_JAILED_UNTIL: u16 = JAILED_UNTIL_DISCRIMINANT; // 0xa0 (160)

/// 300.0 seconds (`0x4072c00000000000` at `.rodata` `0x458f40`).
pub const MANUAL_UNJAIL_INTERVAL_SECS: u32 = 300;

/// 12-byte lexicographically compared timestamp observed in `0x3c3cdb6..0x3c3ce86`:
/// signed `i32` field (`setg`) followed by two unsigned `u32` fields (`seta`, `ja`).
/// Represents `(day_or_epoch_i32, sec_u32, subsec_nanos_u32)` or equivalent
/// monotonic triple with `add_seconds` on seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct JailingTime {
    pub major: i32,
    pub seconds: u32,
    pub nanos: u32,
}

impl JailingTime {
    pub const fn new(major: i32, seconds: u32, nanos: u32) -> Self {
        Self {
            major,
            seconds,
            nanos,
        }
    }

    /// Adds whole seconds with day rollover (86,400 s/day), preserving `nanos`.
    pub fn add_seconds(self, secs: u32) -> Self {
        const SECS_PER_DAY: u64 = 86_400;
        let total = u64::from(self.seconds) + u64::from(secs);
        let extra_days = (total / SECS_PER_DAY) as i32;
        let rem_secs = (total % SECS_PER_DAY) as u32;
        Self {
            major: self.major.saturating_add(extra_days),
            seconds: rem_secs,
            nanos: self.nanos,
        }
    }
}

/// Three action arms dispatched by `0x3c3c260` (`BYTE PTR [r12]` = `0`, `1`, `2`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JailingAction {
    /// Arm `0`: validator requests manual unjail at `now`.
    ManualUnjail,
    /// Arm `1`: validator self-jails (`jail_until = None`).
    SelfJail,
    /// Arm `2`: peer votes to jail `target` until `jail_until`.
    VoteToJail {
        target: Address,
        jail_until: JailingTime,
    },
}

/// Errors returned by `0x3c3c260` with exact node #115 discriminants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JailingError {
    /// Status `0x99`: validator is in `disabled_validators` (`state+0x1e8`).
    Disabled,
    /// Status `0xa0` (160): `jailed_until > now`.
    JailedUntil(JailingTime),
    /// Status `0x9f` (159): `last_manual_unjail + 300s > now`.
    ManualUnjailCooldown,
}

impl JailingError {
    pub const fn status_code(self) -> u16 {
        match self {
            JailingError::Disabled => STATUS_DISABLED,
            JailingError::JailedUntil(_) => STATUS_JAILED_UNTIL,
            JailingError::ManualUnjailCooldown => STATUS_MANUAL_UNJAIL_COOLDOWN,
        }
    }
}

/// Reconstructs the stake-weighted median loop at `0x3c3c8b7..0x3c3c94c`:
///
/// 1. Inputs are `(Option<JailingTime>, u64 weight)` sorted ascending (matching
///    Rust's `Option::Ord` where `None < Some(_)`).
/// 2. Computes `total_stake` with saturating `u64` addition.
/// 3. Walks entries accumulating `cum = cum.saturating_add(weight)`:
///    - If an entry is `None` (`DWORD PTR [r11] == 0`), stops immediately and
///      returns `None` (no jail).
///    - If `cum >= (1u64 << 63)` (`js`) OR `2 * cum >= total_stake` (`jb` false),
///      returns `Some(time)`.
///    - Empty input returns `None`.
pub fn weighted_median_jail_until(entries: &[(Option<JailingTime>, u64)]) -> Option<JailingTime> {
    if entries.is_empty() {
        return None;
    }
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|(t, _)| *t);

    let total_stake = sorted
        .iter()
        .fold(0u64, |acc, (_, w)| acc.saturating_add(*w));

    let mut cum = 0u64;
    for (opt_time, weight) in sorted {
        let time = opt_time?;
        cum = cum.saturating_add(weight);
        if (cum & (1u64 << 63)) != 0 || cum.wrapping_mul(2) >= total_stake {
            return Some(time);
        }
    }
    None
}

/// Value-level model of the node #115 jailing state mutated by `0x3c3c260`,
/// `0x3c35a10`, and `0x3c35fe0`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JailingState {
    /// Active validator stakes (`state+0xd0` projection).
    pub active_validators: BTreeMap<Address, u64>,
    /// Disabled validators that cannot manually unjail (`state+0x1e8`).
    pub disabled_validators: BTreeSet<Address>,
    /// Exempt/protected validators (`0x64e5be8` / `0x64fdb90`).
    pub exempt_validators: BTreeSet<Address>,
    /// Currently jailed validators (`state+0x180`).
    pub jailed_validators: BTreeSet<Address>,
    /// Per-validator minimum jail-until timestamps (`state+0x1a8`).
    pub jailed_until: BTreeMap<Address, JailingTime>,
    /// Last manual unjail timestamp per validator (`state+0x1c8`).
    pub last_manual_unjail: BTreeMap<Address, JailingTime>,
    /// Peer jail votes: `target -> (voter -> proposed_jail_until)` (`state+0x98`).
    pub jail_votes: BTreeMap<Address, BTreeMap<Address, JailingTime>>,
}

impl JailingState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies that the crate constant matches the binary `.rodata` bit pattern.
    pub fn manual_unjail_interval_f64() -> f64 {
        f64::from_bits(MANUAL_UNJAIL_INTERVAL_BITS)
    }

    /// Reconstructs `0x3c35a10` (`jail_validator`): protected/exempt validators
    /// are guarded against jailing when `guard_blocks_exempt` is true; otherwise
    /// inserts into `jailed_validators` and records `jailed_until` if `Some`.
    pub fn jail_validator(
        &mut self,
        validator: Address,
        until: Option<JailingTime>,
        guard_blocks_exempt: bool,
    ) -> bool {
        if guard_blocks_exempt && self.exempt_validators.contains(&validator) {
            return false;
        }
        self.jailed_validators.insert(validator);
        if let Some(t) = until {
            self.jailed_until.insert(validator, t);
        }
        true
    }

    /// Reconstructs `0x3c3c260` (`Jailing::apply_action`).
    pub fn apply_action(
        &mut self,
        signer: Address,
        now: JailingTime,
        action: JailingAction,
        guard_blocks_exempt: bool,
    ) -> Result<(), JailingError> {
        match action {
            JailingAction::ManualUnjail => {
                // 1. Disabled validator check (`state+0x1e8`) -> status 0x99.
                if self.disabled_validators.contains(&signer) {
                    return Err(JailingError::Disabled);
                }
                // 2. Not currently jailed (`state+0x180`) -> idempotent Ok (0x1a2).
                if !self.jailed_validators.contains(&signer) {
                    return Ok(());
                }
                // 3. Exempt validator bypasses jail_until and 300s cooldown (`0x3c3cd02 -> 0x3c3cee4`).
                if self.exempt_validators.contains(&signer) {
                    self.jailed_validators.remove(&signer);
                    return Ok(());
                }
                // 4. `jailed_until > now` -> status 0xa0 with payload Time.
                if let Some(&until) = self.jailed_until.get(&signer)
                    && until > now
                {
                    return Err(JailingError::JailedUntil(until));
                }
                // 5. `last_manual_unjail + 300s > now` -> status 0x9f.
                if let Some(&last) = self.last_manual_unjail.get(&signer) {
                    let next_allowed = last.add_seconds(MANUAL_UNJAIL_INTERVAL_SECS);
                    if next_allowed > now {
                        return Err(JailingError::ManualUnjailCooldown);
                    }
                }
                self.last_manual_unjail.insert(signer, now);
                self.jailed_validators.remove(&signer);
                Ok(())
            }
            JailingAction::SelfJail => {
                self.jail_validator(signer, None, guard_blocks_exempt);
                Ok(())
            }
            JailingAction::VoteToJail { target, jail_until } => {
                // Target must be an active validator and not already jailed.
                if !self.active_validators.contains_key(&target)
                    || self.jailed_validators.contains(&target)
                {
                    return Ok(());
                }
                self.jail_votes
                    .entry(target)
                    .or_default()
                    .insert(signer, jail_until);

                // Project votes over active validators: non-voting active validators
                // contribute `(None, stake)` (`0x3d6f520`).
                let target_votes = self.jail_votes.get(&target);
                let mut weighted = Vec::with_capacity(self.active_validators.len());
                for (&voter, &stake) in &self.active_validators {
                    let vote = target_votes.and_then(|m| m.get(&voter).copied());
                    weighted.push((vote, stake));
                }
                if let Some(median_until) = weighted_median_jail_until(&weighted) {
                    self.jail_validator(target, Some(median_until), guard_blocks_exempt);
                }
                Ok(())
            }
        }
    }

    /// Reconstructs `0x3c35fe0` (`jailing.rs:199`): prunes jail votes for
    /// inactive targets/voters and removes expired `jailed_until` entries.
    pub fn expire_and_prune(&mut self, now: JailingTime) {
        self.jail_votes
            .retain(|target, _| self.active_validators.contains_key(target));
        for votes in self.jail_votes.values_mut() {
            votes.retain(|voter, _| self.active_validators.contains_key(voter));
        }
        self.jailed_until.retain(|_, until| *until > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        let mut a = [0u8; 20];
        a[19] = b;
        a
    }

    #[test]
    fn weighted_median_matches_none_short_circuit_and_2x_threshold() {
        let t1 = JailingTime::new(100, 10, 0);
        let t2 = JailingTime::new(100, 20, 0);

        // Any None entry sorts first and stops without jailing (`0x3c3c90e`).
        assert_eq!(
            weighted_median_jail_until(&[(None, 10), (Some(t1), 100)]),
            None
        );

        // All Some entries: picks first time where 2 * cum >= total_stake.
        assert_eq!(
            weighted_median_jail_until(&[(Some(t1), 40), (Some(t2), 60)]),
            Some(t2)
        );
        assert_eq!(
            weighted_median_jail_until(&[(Some(t1), 50), (Some(t2), 50)]),
            Some(t1)
        );

        // Overflow guard (`cum >= 2^63` triggers immediately via `js`).
        assert_eq!(
            weighted_median_jail_until(&[(Some(t1), 1u64 << 63), (Some(t2), 1)]),
            Some(t1)
        );
    }

    #[test]
    fn manual_unjail_enforces_disabled_jail_until_cooldown_and_exempt_bypass() {
        assert_eq!(JailingState::manual_unjail_interval_f64(), 300.0);
        let mut st = JailingState::new();
        let v1 = addr(1);
        let v_disabled = addr(2);
        let v_exempt = addr(3);
        let t0 = JailingTime::new(20_000, 1_000, 0);
        let t_until = JailingTime::new(20_000, 1_200, 0);

        st.disabled_validators.insert(v_disabled);
        st.exempt_validators.insert(v_exempt);
        st.jailed_validators.insert(v1);
        st.jailed_until.insert(v1, t_until);

        // Disabled validator -> 0x99 even if not jailed.
        assert_eq!(
            st.apply_action(v_disabled, t0, JailingAction::ManualUnjail, false),
            Err(JailingError::Disabled)
        );
        assert_eq!(JailingError::Disabled.status_code(), 0x99);

        // Before jailed_until -> 0xa0 (160) with payload Time.
        assert_eq!(
            st.apply_action(v1, t0, JailingAction::ManualUnjail, false),
            Err(JailingError::JailedUntil(t_until))
        );
        assert_eq!(JailingError::JailedUntil(t_until).status_code(), 0xa0);

        // Exactly at jailed_until (`>` is strict) -> succeeds and records last_manual_unjail.
        assert_eq!(
            st.apply_action(v1, t_until, JailingAction::ManualUnjail, false),
            Ok(())
        );
        assert!(!st.jailed_validators.contains(&v1));

        // Self-jail immediately and attempt manual unjail at +299s -> 0x9f (159).
        assert_eq!(
            st.apply_action(v1, t_until.add_seconds(10), JailingAction::SelfJail, false),
            Ok(())
        );
        assert!(st.jailed_validators.contains(&v1));
        assert_eq!(
            st.apply_action(
                v1,
                t_until.add_seconds(299),
                JailingAction::ManualUnjail,
                false
            ),
            Err(JailingError::ManualUnjailCooldown)
        );
        assert_eq!(JailingError::ManualUnjailCooldown.status_code(), 0x9f);

        // At exactly +300s (`>` is strict) -> succeeds!
        assert_eq!(
            st.apply_action(
                v1,
                t_until.add_seconds(300),
                JailingAction::ManualUnjail,
                false
            ),
            Ok(())
        );
        assert!(!st.jailed_validators.contains(&v1));

        // Exempt validator bypasses both jailed_until and cooldown.
        st.jailed_validators.insert(v_exempt);
        st.jailed_until.insert(v_exempt, t_until.add_seconds(9999));
        assert_eq!(
            st.apply_action(v_exempt, t0, JailingAction::ManualUnjail, false),
            Ok(())
        );
        assert!(!st.jailed_validators.contains(&v_exempt));
    }

    #[test]
    fn peer_votes_jail_when_all_stake_votes_and_prune_removes_expired() {
        let mut st = JailingState::new();
        let v1 = addr(1);
        let v2 = addr(2);
        let t_now = JailingTime::new(100, 50, 0);
        let t_early = JailingTime::new(100, 200, 0);
        let t_late = JailingTime::new(100, 400, 0);
        st.active_validators.insert(v1, 40);
        st.active_validators.insert(v2, 60);

        // Only v1 voted -> v2 contributes None -> not jailed yet.
        st.apply_action(
            v1,
            t_now,
            JailingAction::VoteToJail {
                target: v1,
                jail_until: t_early,
            },
            true,
        )
        .unwrap();
        assert!(!st.jailed_validators.contains(&v1));

        // v2 votes with weight 60 -> weighted median selects t_late (40 < 50 <= 100).
        st.apply_action(
            v2,
            t_now,
            JailingAction::VoteToJail {
                target: v1,
                jail_until: t_late,
            },
            true,
        )
        .unwrap();
        assert!(st.jailed_validators.contains(&v1));
        assert_eq!(st.jailed_until.get(&v1), Some(&t_late));

        // Expire & prune at t_late removes expired jailed_until entry.
        st.expire_and_prune(t_late);
        assert!(!st.jailed_until.contains_key(&v1));
    }
}
