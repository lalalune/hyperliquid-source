//! Independently authored Rust reconstruction of node #115 consensus round
//! progression, timeout quorum / 1/3 amplification, TC high-QC selection, and
//! jailed-validator history lookup (`RE-008-node115-round-progression`).
//!
//! Target binary anchors (Linux x86-64 node #115):
//! - `0x595c3a0..0x595c5f3` (`validator_set.rs:164`): jailed-validator lookup
//! - `0x5960010..0x5960381`: `TimeoutCertificate::from_timeouts`
//! - `0x2e112f0..0x2e11afb` (`state.rs:1193`, `validator_stakes.rs:26,30`):
//!   timeout quorum check, 1/3 amplification, TC assembly, round advance
//! - `0x2e154e0..0x2e157b2`: local timeout broadcast plan & flag transition
//! - `0x2e19920..0x2e1a118` (`timer.rs:23`): `advance_round`

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

pub type Address = [u8; 20];

/// Exact offset constants observed in `0x595c3a0` (`validator_set.rs:164`).
pub const HISTORY_FAST_WINDOW: u64 = 2_000;
pub const HISTORY_LOOKBACK: u64 = 200;

/// Error returned by `0x595c3a0` (tag `0x28` with the requested round).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JailedLookupError {
    pub requested_round: u64,
}

/// Outcome of `0x595c3a0` jailed-validator history lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JailedLookupOutcome<'a> {
    pub query_round: u64,
    pub warned_high_round: bool,
    pub jailed: &'a BTreeSet<Address>,
}

/// Computes the warning threshold and query round matching `0x595c3a0`:
/// - `limit = max(base_warn.saturating_add(2000), exec_round.saturating_add(200).saturating_add(1))`
/// - `warn = round >= limit`
/// - `query_round = if round < base_jailed.saturating_add(2000) { base_jailed } else { max(base_jailed, round.wrapping_sub(200)) }`
pub fn jailed_validators_query_round(
    base_warn: u64,
    exec_round: u64,
    base_jailed: u64,
    round: u64,
) -> (u64, bool) {
    let limit_a = base_warn.saturating_add(HISTORY_FAST_WINDOW);
    let limit_b = exec_round
        .saturating_add(HISTORY_LOOKBACK)
        .saturating_add(1);
    let limit = limit_a.max(limit_b);
    let warned = round >= limit;

    let fast_cutoff = base_jailed.saturating_add(HISTORY_FAST_WINDOW);
    let query_round = if round < fast_cutoff {
        base_jailed
    } else {
        base_jailed.max(round.wrapping_sub(HISTORY_LOOKBACK))
    };
    (query_round, warned)
}

/// Value model of the jailed-validator history table queried by `0x595c3a0`.
#[derive(Debug)]
pub struct JailedHistory {
    pub base_warn: u64,
    pub exec_round: u64,
    pub base_jailed: u64,
    pub high_round_warnings: AtomicU64,
    /// Sorted `(round, jailed_set)` history snapshots.
    snapshots: Vec<(u64, BTreeSet<Address>)>,
}

impl JailedHistory {
    pub fn new(base_warn: u64, exec_round: u64, base_jailed: u64) -> Self {
        Self {
            base_warn,
            exec_round,
            base_jailed,
            high_round_warnings: AtomicU64::new(0),
            snapshots: Vec::new(),
        }
    }

    pub fn insert_snapshot(&mut self, round: u64, jailed: BTreeSet<Address>) {
        match self.snapshots.binary_search_by_key(&round, |(r, _)| *r) {
            Ok(idx) => self.snapshots[idx].1 = jailed,
            Err(idx) => self.snapshots.insert(idx, (round, jailed)),
        }
    }

    /// Reconstructs `0x595c3a0`: updates warning counter when `round >= limit`
    /// (never rejecting on warning), computes `query_round`, and returns the
    /// greatest stored snapshot with `snapshot_round <= query_round`.
    pub fn lookup(&self, round: u64) -> Result<JailedLookupOutcome<'_>, JailedLookupError> {
        let (query_round, warned) =
            jailed_validators_query_round(self.base_warn, self.exec_round, self.base_jailed, round);
        if warned {
            self.high_round_warnings.fetch_add(1, Ordering::Relaxed);
        }
        let pos = self.snapshots.partition_point(|(r, _)| *r <= query_round);
        if pos == 0 {
            return Err(JailedLookupError {
                requested_round: round,
            });
        }
        Ok(JailedLookupOutcome {
            query_round,
            warned_high_round: warned,
            jailed: &self.snapshots[pos - 1].1,
        })
    }
}

/// A verified timeout message entry stored in `state+0x818` and passed into
/// `0x5960010` (`TimeoutCertificate::from_timeouts`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeoutEntry<Q = u64> {
    pub signer: Address,
    pub timeout_round: u64,
    /// Value at `TimeoutMsg+0x30` (`high_qc.round`).
    pub high_qc_round: u64,
    /// Value at `TimeoutMsg+0x40` (round used to query stakes in `0x2e115d3`).
    pub stake_lookup_round: u64,
    pub high_qc: Q,
    pub signature: [u8; 65],
}

/// Constructed timeout certificate matching `0x5960010`'s `0x90`-byte record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltTimeoutCertificate<Q = u64> {
    pub round: u64,
    pub high_qc_round: u64,
    pub high_qc: Q,
    pub signers: Vec<(Address, [u8; 65])>,
}

/// Reconstructs `0x5960010` (`TimeoutCertificate::from_timeouts`).
///
/// - Empty input returns `None` (native `0x8000000000000001` niche).
/// - Non-empty input selects the **last** element achieving the maximum
///   `high_qc_round` (`cmp cur, cand; cmova; cmovbe` at `0x59600de..0x596012a`).
pub fn select_highest_qc_timeout<Q: Clone>(
    round: u64,
    timeouts: &[TimeoutEntry<Q>],
) -> Option<BuiltTimeoutCertificate<Q>> {
    if timeouts.is_empty() {
        return None;
    }
    let mut best_idx = 0usize;
    let mut best_round = timeouts[0].high_qc_round;
    for (idx, item) in timeouts.iter().enumerate().skip(1) {
        if item.high_qc_round >= best_round {
            best_round = item.high_qc_round;
            best_idx = idx;
        }
    }
    let winner = &timeouts[best_idx];
    let signers = timeouts.iter().map(|t| (t.signer, t.signature)).collect();
    Some(BuiltTimeoutCertificate {
        round,
        high_qc_round: winner.high_qc_round,
        high_qc: winner.high_qc.clone(),
        signers,
    })
}

/// Reconstructs the `f+1` (1/3 stake) timeout-amplification predicate at
/// `0x2e118c5..0x2e118f2` and `0x2e11ac8..0x2e11ad8`:
///
/// - Suppressed when `already_timed_out` (`BYTE PTR [state+0x8d0] == 1`).
/// - Otherwise computes `signed_stake.saturating_mul(3) > total_stake`.
///   Crucially, on 64-bit multiplication overflow (`3 * signed >= 2^64`),
///   `0x2e11ac8` saturates `rax = u64::MAX` and compares `u64::MAX > total_stake`,
///   which is `false` when `total_stake == u64::MAX`.
pub fn should_amplify_timeout(
    already_timed_out: bool,
    signed_stake: u64,
    total_stake: u64,
) -> bool {
    if already_timed_out {
        return false;
    }
    signed_stake.saturating_mul(3) > total_stake
}

/// Outbound queue message tags emitted by `0x2e154e0` (`broadcast_local_timeout`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundMessageKind {
    /// Tag `0x8000000000000002` pushed unconditionally at `0x2e1569f`.
    LocalTimeout,
    /// Tag `0x8000000000000003` pushed at `0x2e15710` when `last_tc` is `Some`.
    LastTimeoutCertificate,
}

/// Reconstructs the flag transition and outbound message sequence of `0x2e154e0`.
pub fn local_timeout_broadcast_plan(has_last_tc: bool) -> Vec<OutboundMessageKind> {
    let mut out = Vec::with_capacity(2);
    out.push(OutboundMessageKind::LocalTimeout);
    if has_last_tc {
        out.push(OutboundMessageKind::LastTimeoutCertificate);
    }
    out
}

/// Telemetry metric code passed to slot `0x64e5b78` at `0x2e19b67..0x2e19b8c`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RoundMetricCode {
    /// `cert_round == cur_round && opt_tc.is_none()` (`1 ^ 7 = 6`)
    SameRoundQc = 6,
    /// `cert_round == cur_round && opt_tc.is_some()` (`0 ^ 7 = 7`)
    SameRoundTc = 7,
    /// `cert_round > cur_round` (`8`)
    SkippedRound = 8,
}

/// Transition classification written at `0x2e199d8..0x2e199f2` when `opt_tc.is_some()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdvanceTransitionKind {
    /// `cert_round == cur_round && last_voted_round != cur_round`
    SameRoundUnvoted = 0,
    /// `cert_round == cur_round && last_voted_round == cur_round`
    SameRoundVoted = 1,
    /// `cert_round > cur_round`
    SkippedRound = 2,
}

/// Provider boundary for slot `0x64e86f0` (`0x595cb30` proposer selection).
pub trait ProposerProvider {
    fn proposer_for_round(&self, round: u64) -> Option<Address>;
}

/// Provider boundary for `0x2e112f0`'s stake-set lookup + stake sums + quorum check.
pub trait TimeoutQuorumChecker {
    type Error: Clone + Eq + core::fmt::Debug;

    /// Queries stake set for `stake_lookup_round`, returning `(signed_stake, total_stake, has_quorum)`.
    fn evaluate_timeout_quorum(
        &self,
        stake_lookup_round: u64,
        signers: &[Address],
    ) -> Result<(u64, u64, bool), Self::Error>;
}

/// Consensus round state subset mutated by `0x2e112f0`, `0x2e154e0`, and `0x2e19920`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoundState<Q = u64> {
    /// `state+0xbc0..+0xbd4`
    pub self_address: Address,
    /// `state+0xae0`
    pub round: u64,
    /// `state+0xae8`
    pub last_voted_round: u64,
    /// `state+0x818`
    pub timeouts: Vec<TimeoutEntry<Q>>,
    /// `state+0x838` (`0x90`-byte `Option<TimeoutCertificate>`)
    pub last_tc: Option<BuiltTimeoutCertificate<Q>>,
    /// `state+0x8c8`
    pub timeout_counter: u64,
    /// `state+0x8d0` (low byte = `timed_out_this_round`, second byte = flag)
    pub timed_out_this_round: bool,
    pub secondary_timeout_flag: bool,
    /// `state+0xaa0`
    pub primary_timer_enabled: bool,
    /// `state+0xac0`
    pub leader_timer_enabled: bool,
    /// Outbound queue (`state+0x3c0`)
    pub outbound: Vec<OutboundMessageKind>,
}

impl<Q> RoundState<Q> {
    pub fn new(self_address: Address, round: u64) -> Self {
        Self {
            self_address,
            round,
            last_voted_round: 0,
            timeouts: Vec::new(),
            last_tc: None,
            timeout_counter: 0,
            timed_out_this_round: false,
            secondary_timeout_flag: false,
            primary_timer_enabled: false,
            leader_timer_enabled: false,
            outbound: Vec::new(),
        }
    }
}

/// Structured result of `advance_round` (`0x2e19920`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvanceRoundReport {
    pub advanced: bool,
    pub previous_round: u64,
    pub new_round: u64,
    pub metric_code: Option<RoundMetricCode>,
    pub transition_kind: Option<AdvanceTransitionKind>,
    pub primary_timer_reset: bool,
    pub leader_timer_reset: bool,
}

/// Reconstructs `0x2e19920` (`ConsensusState::advance_round`).
pub fn advance_round<Q, P: ProposerProvider>(
    state: &mut RoundState<Q>,
    cert_round: u64,
    opt_tc: Option<BuiltTimeoutCertificate<Q>>,
    proposers: &P,
) -> AdvanceRoundReport {
    let cur_round = state.round;
    if cert_round < cur_round {
        // Stale certificate: drop opt_tc and return false (`setae al` at 0x2e19fe0).
        drop(opt_tc);
        return AdvanceRoundReport {
            advanced: false,
            previous_round: cur_round,
            new_round: cur_round,
            metric_code: None,
            transition_kind: None,
            primary_timer_reset: false,
            leader_timer_reset: false,
        };
    }

    let new_round = cert_round.saturating_add(1);
    state.round = new_round;

    let has_tc = opt_tc.is_some();
    let transition_kind = if has_tc {
        // Native code queries proposers for cur_round and cur_round.saturating_add(1) for logging.
        let _ = proposers.proposer_for_round(cur_round);
        let _ = proposers.proposer_for_round(cur_round.saturating_add(1));
        Some(if cert_round != cur_round {
            AdvanceTransitionKind::SkippedRound
        } else if state.last_voted_round == cur_round {
            AdvanceTransitionKind::SameRoundVoted
        } else {
            AdvanceTransitionKind::SameRoundUnvoted
        })
    } else {
        None
    };

    let metric_code = if cert_round != cur_round {
        RoundMetricCode::SkippedRound
    } else if has_tc {
        RoundMetricCode::SameRoundTc
    } else {
        RoundMetricCode::SameRoundQc
    };

    // State reset (`0x2e19dad..0x2e19df7`).
    state.timeouts.clear();
    state.last_tc = opt_tc;
    state.timeout_counter = 0;
    state.timed_out_this_round = false;
    state.secondary_timeout_flag = false;

    // Primary timer unconditionally enabled (`0x2e19e63`).
    state.primary_timer_enabled = true;

    // Leader timer enabled iff proposer(new_round) == self_address (`0x2e19e6b..0x2e19f4d`).
    let is_next_proposer = proposers
        .proposer_for_round(new_round)
        .map(|p| p == state.self_address)
        .unwrap_or(false);
    if is_next_proposer {
        state.leader_timer_enabled = true;
    }

    AdvanceRoundReport {
        advanced: true,
        previous_round: cur_round,
        new_round,
        metric_code: Some(metric_code),
        transition_kind,
        primary_timer_reset: true,
        leader_timer_reset: is_next_proposer,
    }
}

/// Outcome of `check_timeout_quorum_and_advance` (`0x2e112f0`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeoutCheckOutcome {
    pub amplified_local_timeout: bool,
    pub quorum_reached: bool,
    pub advance_report: Option<AdvanceRoundReport>,
    pub should_try_propose: bool,
}

/// Reconstructs `0x2e112f0` (`state.rs:1193`): scans `state.timeouts` for the
/// last-wins max `high_qc_round` entry, evaluates stake sums and quorum for its
/// `stake_lookup_round`, performs 1/3 timeout amplification via `0x2e154e0` if
/// not yet timed out, and on 2/3 quorum constructs a TC (`0x5960010`), advances
/// the round (`0x2e19920`), and signals `try_propose` (`0x2e13ea0`).
pub fn check_timeout_quorum_and_advance<Q: Clone, C: TimeoutQuorumChecker, P: ProposerProvider>(
    state: &mut RoundState<Q>,
    checker: &C,
    proposers: &P,
) -> Result<TimeoutCheckOutcome, C::Error> {
    if state.timeouts.is_empty() {
        return Ok(TimeoutCheckOutcome {
            amplified_local_timeout: false,
            quorum_reached: false,
            advance_report: None,
            should_try_propose: false,
        });
    }

    // First pass (`0x2e11474..0x2e115d3`): last-wins max by `high_qc_round` (+0x30).
    let mut best_idx = 0usize;
    let mut best_high_qc_round = state.timeouts[0].high_qc_round;
    for (idx, item) in state.timeouts.iter().enumerate().skip(1) {
        if item.high_qc_round >= best_high_qc_round {
            best_high_qc_round = item.high_qc_round;
            best_idx = idx;
        }
    }
    let stake_lookup_round = state.timeouts[best_idx].stake_lookup_round;

    // Collect deduplicated signer addresses (`0x22bce50`) and check stake sums + quorum.
    let mut unique_signers = BTreeSet::new();
    for item in &state.timeouts {
        unique_signers.insert(item.signer);
    }
    let signers: Vec<Address> = unique_signers.into_iter().collect();
    let (signed_stake, total_stake, quorum_reached) =
        checker.evaluate_timeout_quorum(stake_lookup_round, &signers)?;

    // 1/3 stake timeout amplification (`0x2e118c5..0x2e118f2`).
    let mut amplified_local_timeout = false;
    if should_amplify_timeout(state.timed_out_this_round, signed_stake, total_stake) {
        amplified_local_timeout = true;
        state.timed_out_this_round = true;
        let msgs = local_timeout_broadcast_plan(state.last_tc.is_some());
        state.outbound.extend(msgs);
    }

    if !quorum_reached {
        return Ok(TimeoutCheckOutcome {
            amplified_local_timeout,
            quorum_reached: false,
            advance_report: None,
            should_try_propose: false,
        });
    }

    // Take timeouts, build TC for `state.round`, advance round, and trigger propose.
    let drained = core::mem::take(&mut state.timeouts);
    let tc_round = state.round;
    let opt_tc = select_highest_qc_timeout(tc_round, &drained);
    let Some(tc) = opt_tc else {
        return Ok(TimeoutCheckOutcome {
            amplified_local_timeout,
            quorum_reached: true,
            advance_report: None,
            should_try_propose: false,
        });
    };

    let cert_round = tc.round;
    let report = advance_round(state, cert_round, Some(tc), proposers);
    let should_try_propose = report.advanced;
    Ok(TimeoutCheckOutcome {
        amplified_local_timeout,
        quorum_reached: true,
        advance_report: Some(report),
        should_try_propose,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct FixedProposers(BTreeMap<u64, Address>);
    impl ProposerProvider for FixedProposers {
        fn proposer_for_round(&self, round: u64) -> Option<Address> {
            self.0.get(&round).copied()
        }
    }

    struct StubQuorum {
        stakes: BTreeMap<Address, u64>,
        min_count_fraction: f64,
        fail_round: Option<u64>,
    }

    impl TimeoutQuorumChecker for StubQuorum {
        type Error = u64;

        fn evaluate_timeout_quorum(
            &self,
            stake_lookup_round: u64,
            signers: &[Address],
        ) -> Result<(u64, u64, bool), Self::Error> {
            if self.fail_round == Some(stake_lookup_round) {
                return Err(stake_lookup_round);
            }
            let mut signed = 0u64;
            let mut total = 0u64;
            let mut count = 0u64;
            for v in self.stakes.values() {
                total = total.saturating_add(*v);
            }
            for s in signers {
                if let Some(w) = self.stakes.get(s) {
                    signed = signed.saturating_add(*w);
                    count += 1;
                }
            }
            // Exact #115 quorum rule (`0x595bc40` + `0x4d3e1a0`).
            let stake_ok = (signed as u128) * 3 > (total as u128) * 2;
            let count_ok = if !stake_ok {
                false
            } else {
                let f = if !self.min_count_fraction.is_finite() {
                    1.0
                } else {
                    self.min_count_fraction.clamp(0.0, 0.7)
                };
                if f == 0.0 {
                    true
                } else {
                    (count as f64) > f * (self.stakes.len() as f64)
                }
            };
            Ok((signed, total, stake_ok && count_ok))
        }
    }

    fn addr(b: u8) -> Address {
        let mut a = [0u8; 20];
        a[19] = b;
        a
    }

    #[test]
    fn jailed_query_round_matches_fast_window_and_saturation() {
        // Below base + 2000 -> base_jailed; no warning below limit.
        assert_eq!(jailed_validators_query_round(100, 50, 100, 150), (100, false));
        // Exactly at base_jailed + 2000 -> uses max(base_jailed, round - 200).
        assert_eq!(
            jailed_validators_query_round(100, 50, 100, 2100),
            (1900, true)
        );
        // Warning threshold uses max(base_warn + 2000, exec_round + 201).
        assert_eq!(
            jailed_validators_query_round(100, 5000, 100, 5200),
            (5000, false)
        );
        assert_eq!(
            jailed_validators_query_round(100, 5000, 100, 5201),
            (5001, true)
        );
        // Saturation at u64::MAX must not wrap.
        assert_eq!(
            jailed_validators_query_round(u64::MAX - 10, u64::MAX - 10, u64::MAX - 10, u64::MAX),
            (u64::MAX - 10, true)
        );
    }

    #[test]
    fn jailed_history_lookup_warns_without_rejecting_and_rejects_empty() {
        let mut h = JailedHistory::new(10, 10, 10);
        assert_eq!(h.lookup(15), Err(JailedLookupError { requested_round: 15 }));
        let mut s1 = BTreeSet::new();
        s1.insert(addr(7));
        h.insert_snapshot(10, s1.clone());
        let ok = h.lookup(2050).unwrap();
        assert_eq!(ok.query_round, 1850);
        assert!(ok.warned_high_round);
        assert_eq!(ok.jailed, &s1);
        assert_eq!(h.high_round_warnings.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn tc_builder_empty_returns_none_and_ties_prefer_last_element() {
        assert_eq!(select_highest_qc_timeout::<u32>(9, &[]), None);
        let entries = vec![
            TimeoutEntry {
                signer: addr(1),
                timeout_round: 9,
                high_qc_round: 5,
                stake_lookup_round: 5,
                high_qc: 101u32,
                signature: [1u8; 65],
            },
            TimeoutEntry {
                signer: addr(2),
                timeout_round: 9,
                high_qc_round: 7,
                stake_lookup_round: 7,
                high_qc: 202u32,
                signature: [2u8; 65],
            },
            TimeoutEntry {
                signer: addr(3),
                timeout_round: 9,
                high_qc_round: 7,
                stake_lookup_round: 7,
                high_qc: 303u32,
                signature: [3u8; 65],
            },
        ];
        let tc = select_highest_qc_timeout(9, &entries).unwrap();
        assert_eq!(tc.round, 9);
        assert_eq!(tc.high_qc_round, 7);
        assert_eq!(tc.high_qc, 303);
        assert_eq!(tc.signers.len(), 3);
    }

    #[test]
    fn amplify_timeout_matches_saturating_mul3_and_u64_max_boundary() {
        // Exact 1/3 does NOT amplify (`>` is strict).
        assert!(!should_amplify_timeout(false, 100, 300));
        assert!(should_amplify_timeout(false, 101, 300));
        // Already timed out suppresses amplification.
        assert!(!should_amplify_timeout(true, 200, 300));
        // Overflow saturates to u64::MAX: `u64::MAX > total` is true unless total == u64::MAX.
        assert!(should_amplify_timeout(false, u64::MAX / 2, u64::MAX - 1));
        assert!(!should_amplify_timeout(false, u64::MAX / 2, u64::MAX));
    }

    #[test]
    fn timeout_amplification_then_quorum_advances_round_and_enables_leader_timer() {
        let self_addr = addr(1);
        let mut state = RoundState::new(self_addr, 10);
        state.last_voted_round = 10;

        let mut stakes = BTreeMap::new();
        stakes.insert(addr(1), 100);
        stakes.insert(addr(2), 100);
        stakes.insert(addr(3), 100);
        let checker = StubQuorum {
            stakes,
            min_count_fraction: 0.0,
            fail_round: None,
        };
        let mut proposers_map = BTreeMap::new();
        proposers_map.insert(10, addr(2));
        proposers_map.insert(11, self_addr);
        let proposers = FixedProposers(proposers_map);

        // 1/3 stake (100 of 300): neither amplifies nor reaches quorum.
        state.timeouts.push(TimeoutEntry {
            signer: addr(2),
            timeout_round: 10,
            high_qc_round: 8,
            stake_lookup_round: 8,
            high_qc: 8u64,
            signature: [2u8; 65],
        });
        let r1 = check_timeout_quorum_and_advance(&mut state, &checker, &proposers).unwrap();
        assert!(!r1.amplified_local_timeout);
        assert!(!r1.quorum_reached);
        assert_eq!(state.round, 10);

        // Add signer 3 -> 200/300 (> 1/3, == 2/3 so NOT > 2/3): amplifies local timeout, no TC yet!
        state.timeouts.push(TimeoutEntry {
            signer: addr(3),
            timeout_round: 10,
            high_qc_round: 9,
            stake_lookup_round: 9,
            high_qc: 9u64,
            signature: [3u8; 65],
        });
        let r2 = check_timeout_quorum_and_advance(&mut state, &checker, &proposers).unwrap();
        assert!(r2.amplified_local_timeout);
        assert!(!r2.quorum_reached);
        assert!(state.timed_out_this_round);
        assert_eq!(state.outbound, vec![OutboundMessageKind::LocalTimeout]);

        // Add signer 1 -> 300/300 (> 2/3): builds TC, advances round 10 -> 11, resets state, enables leader timer.
        state.timeouts.push(TimeoutEntry {
            signer: addr(1),
            timeout_round: 10,
            high_qc_round: 9,
            stake_lookup_round: 9,
            high_qc: 99u64,
            signature: [1u8; 65],
        });
        let r3 = check_timeout_quorum_and_advance(&mut state, &checker, &proposers).unwrap();
        assert!(!r3.amplified_local_timeout); // already timed out
        assert!(r3.quorum_reached);
        assert!(r3.should_try_propose);
        assert_eq!(state.round, 11);
        assert!(state.timeouts.is_empty());
        assert!(!state.timed_out_this_round);
        assert!(state.primary_timer_enabled);
        assert!(state.leader_timer_enabled);
        let tc = state.last_tc.as_ref().unwrap();
        assert_eq!(tc.high_qc, 99u64); // last-wins tie breaker
        let rep = r3.advance_report.unwrap();
        assert_eq!(rep.metric_code, Some(RoundMetricCode::SameRoundTc));
        assert_eq!(rep.transition_kind, Some(AdvanceTransitionKind::SameRoundVoted));
    }

    #[test]
    fn advance_round_rejects_stale_and_saturates_at_u64_max() {
        let proposers = FixedProposers(BTreeMap::new());
        let mut state = RoundState::<u64>::new(addr(1), 50);
        let stale = advance_round(&mut state, 49, None, &proposers);
        assert!(!stale.advanced);
        assert_eq!(state.round, 50);

        let skip = advance_round(&mut state, 60, None, &proposers);
        assert!(skip.advanced);
        assert_eq!(state.round, 61);
        assert_eq!(skip.metric_code, Some(RoundMetricCode::SkippedRound));

        let mut max_state = RoundState::<u64>::new(addr(1), u64::MAX);
        let sat = advance_round(&mut max_state, u64::MAX, None, &proposers);
        assert!(sat.advanced);
        assert_eq!(max_state.round, u64::MAX);
        assert_eq!(sat.metric_code, Some(RoundMetricCode::SameRoundQc));
    }
}
