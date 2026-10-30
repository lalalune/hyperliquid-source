//! A deliberately narrow model of the node #94 timeout-to-round transition.
//!
//! Inputs are already-authenticated timeouts or already-acceptable timeout
//! certificates.  Signature parsing, cryptography, wire decoding, validator
//! snapshots, persistence, timers, queues, and notifications are outside this
//! model because the RE-008 packet does not recover their complete semantics.

use std::collections::{BTreeMap, BTreeSet};

/// The binary compares 20 bytes when intersecting timeout keys with stake keys.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ValidatorId(pub [u8; 20]);

pub type StakeTable = BTreeMap<ValidatorId, u64>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoundState {
    pub current_round: u64,
    /// One already-verified timeout per key for the current round.
    pub verified_timeouts: BTreeSet<ValidatorId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimeoutAdmission {
    RoundMismatch {
        current: u64,
        supplied: u64,
    },
    Duplicate,
    Stored {
        signed_weight: u64,
        total_weight: u64,
    },
    Transitioned {
        from: u64,
        to: u64,
        signed_weight: u64,
        total_weight: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateAdmission {
    Stale { current: u64, supplied: u64 },
    Transitioned { from: u64, supplied: u64, to: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    StakeOverflow,
}

impl RoundState {
    pub fn new(current_round: u64) -> Self {
        Self {
            current_round,
            verified_timeouts: BTreeSet::new(),
        }
    }

    /// Admit a timeout only after the caller has established the signature and
    /// snapshot preconditions that remain outside this model.
    pub fn admit_verified_timeout(
        &mut self,
        validator: ValidatorId,
        timeout_round: u64,
        stakes: &StakeTable,
    ) -> Result<TimeoutAdmission, ModelError> {
        if timeout_round != self.current_round {
            return Ok(TimeoutAdmission::RoundMismatch {
                current: self.current_round,
                supplied: timeout_round,
            });
        }
        if self.verified_timeouts.contains(&validator) {
            return Ok(TimeoutAdmission::Duplicate);
        }

        self.verified_timeouts.insert(validator);
        let total_weight = checked_sum(stakes.values().copied())?;
        let signed_weight = checked_sum(
            self.verified_timeouts
                .iter()
                .filter_map(|key| stakes.get(key).copied()),
        )?;

        if !has_strict_two_thirds(signed_weight, total_weight) {
            return Ok(TimeoutAdmission::Stored {
                signed_weight,
                total_weight,
            });
        }

        let from = self.current_round;
        let to = timeout_round.saturating_add(1);
        self.current_round = to;
        self.verified_timeouts.clear();
        Ok(TimeoutAdmission::Transitioned {
            from,
            to,
            signed_weight,
            total_weight,
        })
    }

    /// Apply only the round-field behavior after the binary's TC verifier and
    /// post-verifier helper have both returned their success representation.
    pub fn apply_acceptable_certificate(&mut self, certificate_round: u64) -> CertificateAdmission {
        if certificate_round < self.current_round {
            return CertificateAdmission::Stale {
                current: self.current_round,
                supplied: certificate_round,
            };
        }
        let from = self.current_round;
        let to = certificate_round.saturating_add(1);
        self.current_round = to;
        self.verified_timeouts.clear();
        CertificateAdmission::Transitioned {
            from,
            supplied: certificate_round,
            to,
        }
    }
}

/// Exact strict predicate seen on the transition path.  Wider arithmetic
/// expresses the binary's high-word multiply/compare without host overflow.
pub fn has_strict_two_thirds(signed_weight: u64, total_weight: u64) -> bool {
    2_u128 * u128::from(total_weight) < 3_u128 * u128::from(signed_weight)
}

fn checked_sum(values: impl IntoIterator<Item = u64>) -> Result<u64, ModelError> {
    values.into_iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(value).ok_or(ModelError::StakeOverflow)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> ValidatorId {
        ValidatorId([byte; 20])
    }

    fn stakes(entries: &[(u8, u64)]) -> StakeTable {
        entries
            .iter()
            .map(|(key, stake)| (id(*key), *stake))
            .collect()
    }

    #[test]
    fn wrong_round_rejects_without_mutation() {
        let table = stakes(&[(1, 70), (2, 30)]);
        for supplied in [6, 8] {
            let mut state = RoundState::new(7);
            let before = state.clone();
            assert_eq!(
                state.admit_verified_timeout(id(1), supplied, &table),
                Ok(TimeoutAdmission::RoundMismatch {
                    current: 7,
                    supplied
                })
            );
            assert_eq!(state, before);
        }
    }

    #[test]
    fn duplicate_rejects_without_second_mutation() {
        let table = stakes(&[(1, 40), (2, 60)]);
        let mut state = RoundState::new(9);
        assert_eq!(
            state.admit_verified_timeout(id(1), 9, &table),
            Ok(TimeoutAdmission::Stored {
                signed_weight: 40,
                total_weight: 100
            })
        );
        let before = state.clone();
        assert_eq!(
            state.admit_verified_timeout(id(1), 9, &table),
            Ok(TimeoutAdmission::Duplicate)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn insufficient_stake_is_retained_for_later_votes() {
        let table = stakes(&[(1, 40), (2, 30), (3, 30)]);
        let mut state = RoundState::new(11);
        assert_eq!(
            state.admit_verified_timeout(id(1), 11, &table),
            Ok(TimeoutAdmission::Stored {
                signed_weight: 40,
                total_weight: 100
            })
        );
        assert_eq!(state.current_round, 11);
        assert_eq!(state.verified_timeouts, BTreeSet::from([id(1)]));
    }

    #[test]
    fn exact_two_thirds_is_not_quorum() {
        assert!(!has_strict_two_thirds(2, 3));
        let table = stakes(&[(1, 1), (2, 1), (3, 1)]);
        let mut state = RoundState::new(12);
        assert!(matches!(
            state.admit_verified_timeout(id(1), 12, &table),
            Ok(TimeoutAdmission::Stored { .. })
        ));
        assert_eq!(
            state.admit_verified_timeout(id(2), 12, &table),
            Ok(TimeoutAdmission::Stored {
                signed_weight: 2,
                total_weight: 3
            })
        );
        assert_eq!(state.current_round, 12);
    }

    #[test]
    fn first_weight_above_two_thirds_transitions_and_clears_votes() {
        let table = stakes(&[(1, 40), (2, 30), (3, 30)]);
        let mut state = RoundState::new(14);
        state.admit_verified_timeout(id(1), 14, &table).unwrap();
        state.admit_verified_timeout(id(2), 14, &table).unwrap();
        assert_eq!(state.current_round, 15);
        assert!(state.verified_timeouts.is_empty());
    }

    #[test]
    fn unknown_validator_is_stored_but_contributes_zero_weight() {
        let table = stakes(&[(1, 70), (2, 30)]);
        let mut state = RoundState::new(20);
        assert_eq!(
            state.admit_verified_timeout(id(99), 20, &table),
            Ok(TimeoutAdmission::Stored {
                signed_weight: 0,
                total_weight: 100
            })
        );
        assert!(state.verified_timeouts.contains(&id(99)));
    }

    #[test]
    fn acceptable_certificate_can_advance_from_current_or_future_round() {
        let mut current = RoundState::new(30);
        assert_eq!(
            current.apply_acceptable_certificate(30),
            CertificateAdmission::Transitioned {
                from: 30,
                supplied: 30,
                to: 31
            }
        );
        let mut future = RoundState::new(30);
        assert_eq!(
            future.apply_acceptable_certificate(35),
            CertificateAdmission::Transitioned {
                from: 30,
                supplied: 35,
                to: 36
            }
        );
    }

    #[test]
    fn stale_certificate_is_side_effect_free() {
        let mut state = RoundState::new(30);
        state.verified_timeouts.insert(id(1));
        let before = state.clone();
        assert_eq!(
            state.apply_acceptable_certificate(29),
            CertificateAdmission::Stale {
                current: 30,
                supplied: 29
            }
        );
        assert_eq!(state, before);
    }

    #[test]
    fn max_round_saturates() {
        let mut state = RoundState::new(u64::MAX);
        assert_eq!(
            state.apply_acceptable_certificate(u64::MAX),
            CertificateAdmission::Transitioned {
                from: u64::MAX,
                supplied: u64::MAX,
                to: u64::MAX,
            }
        );
    }

    #[test]
    fn stake_overflow_is_reported() {
        let table = stakes(&[(1, u64::MAX), (2, 1)]);
        let mut state = RoundState::new(1);
        assert_eq!(
            state.admit_verified_timeout(id(1), 1, &table),
            Err(ModelError::StakeOverflow)
        );
    }
}
