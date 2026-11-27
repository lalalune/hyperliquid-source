//! Node #115 deterministic proposer selection (`0x595cb30..0x595e5b8`,
//! slot `0x64e86f0`; anchored to `RE-008-proposer-selection-115` and
//! `RE-008-node115-consensus-crate-map`).
//!
//! Integrates the two-round history lookup (`query_round` selects snapshots,
//! `selected_round` indexes the materialized schedule), jailed-validator
//! exclusion, threshold adjustment, FMA3 event ordering, 3-at-a-time fallback
//! replacement, and implements both [`ProposerProvider`] and
//! [`BlockProposerProvider`] for downstream consensus callers.

use std::cmp::Ordering;

use crate::block_rules::BlockProposerProvider;
use crate::round_progression::{Address, ProposerProvider};

/// Native status tags emitted by `0x595cb30`.
pub const TAG_PROPOSER_MISSING_HISTORY: u8 = 0x28;
pub const TAG_PROPOSER_EMPTY_SCHEDULE: u8 = 0x0f;
pub const TAG_PROPOSER_SELECTED: u8 = 0x2e;

/// Failure reasons returned by [`ProposerScheduleHistory`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposerError {
    InvalidSnapshot,
    Capacity,
    MissingHistory,
    EmptySchedule,
}

impl ProposerError {
    pub const fn native_tag(self) -> Option<u8> {
        match self {
            Self::MissingHistory => Some(TAG_PROPOSER_MISSING_HISTORY),
            Self::EmptySchedule => Some(TAG_PROPOSER_EMPTY_SCHEDULE),
            Self::InvalidSnapshot | Self::Capacity => None,
        }
    }
}

/// One `(validator, stake_weight)` row in a stake-set snapshot.
pub type StakeRow = (Address, u64);

/// One scheduled event in `0x595cb30`'s weighted-event sort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduleEvent {
    pub bits: u64,
    pub key: Option<Address>,
}

/// Prepared intermediate weights produced before event expansion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedWeights {
    pub total: u64,
    pub threshold: u64,
    pub adjusted: Vec<StakeRow>,
    pub fallback: Vec<(u64, Address)>,
    pub members: Vec<Address>,
}

fn strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|w| w[0] < w[1])
}

/// History predecessor query matching `0x595c3a0` / `0x595cb30`:
/// `q = base` if `round < base.saturating_add(2000)` else `base.max(round.wrapping_sub(200))`.
pub fn history_query(base: u64, rounds: &[u64], round: u64) -> Result<(u64, Option<usize>), ProposerError> {
    if !strictly_sorted(rounds) {
        return Err(ProposerError::InvalidSnapshot);
    }
    let query = if round < base.saturating_add(2000) {
        base
    } else {
        base.max(round.wrapping_sub(200))
    };
    let index = rounds.partition_point(|&r| r <= query).checked_sub(1);
    Ok((query, index))
}

/// Warning threshold diagnostic matching `0x595c3a0`:
/// `limit = max(stake_base.saturating_add(2000), execution.saturating_add(201))`.
pub const fn history_warning_limit(stake_base: u64, execution: u64) -> u64 {
    let a = stake_base.saturating_add(2000);
    let b = execution.saturating_add(201);
    if a >= b { a } else { b }
}

/// Weight preparation stage of `0x595cb30`:
/// excludes `blocked`, forms `members = blocked U extra`, computes
/// `threshold = total.saturating_sub(1000) / members.len()`, subtracts
/// `threshold` from `members` weights and multiplies non-members by `3`.
pub fn prepare_weights(
    blocked: &[Address],
    extra: &[Address],
    rows: &[StakeRow],
) -> Result<PreparedWeights, ProposerError> {
    if !strictly_sorted(blocked)
        || !strictly_sorted(extra)
        || !rows.windows(2).all(|w| w[0].0 < w[1].0)
    {
        return Err(ProposerError::InvalidSnapshot);
    }
    let mut members = blocked.to_vec();
    members.extend_from_slice(extra);
    members.sort_unstable();
    members.dedup();

    let kept: Vec<StakeRow> = rows
        .iter()
        .copied()
        .filter(|(key, _)| blocked.binary_search(key).is_err())
        .collect();
    let total = kept
        .iter()
        .fold(0u64, |acc, &(_, w)| acc.saturating_add(w));
    let threshold = if members.is_empty() {
        0
    } else {
        total.saturating_sub(1000) / members.len() as u64
    };
    let adjusted: Vec<StakeRow> = kept
        .into_iter()
        .map(|(key, weight)| {
            let w = if members.binary_search(&key).is_ok() {
                weight.saturating_sub(threshold)
            } else {
                weight.saturating_mul(3)
            };
            (key, w)
        })
        .collect();
    let mut fallback: Vec<(u64, Address)> = adjusted
        .iter()
        .filter(|(key, _)| members.binary_search(key).is_ok())
        .map(|&(key, weight)| (weight.saturating_mul(3), key))
        .collect();
    fallback.sort_unstable_by(|a, b| b.cmp(a));
    Ok(PreparedWeights {
        total,
        threshold,
        adjusted,
        fallback,
        members,
    })
}

/// Exact `f64` event coordinate computation using `mul_add` matching `0x595cb30`.
pub fn event_point_bits(i: u64, n: u64, weight: u64, j: u64) -> Result<u64, ProposerError> {
    if n == 0 || weight == 0 || i >= n || i > i64::MAX as u64 || j >= weight {
        return Err(ProposerError::InvalidSnapshot);
    }
    let inverse = 1.0 / weight as f64;
    let base = (i as i64 as f64 * inverse) / n as f64;
    let point = inverse.mul_add(j as f64, base);
    Ok(point.to_bits())
}

pub fn event_order(a: &ScheduleEvent, b: &ScheduleEvent) -> Ordering {
    f64::from_bits(a.bits)
        .total_cmp(&f64::from_bits(b.bits))
        .then_with(|| a.key.cmp(&b.key))
}

/// Materializes the full proposer schedule keys for `(blocked, extra, rows)`.
pub fn build_schedule(
    blocked: &[Address],
    extra: &[Address],
    rows: &[StakeRow],
) -> Result<Vec<Address>, ProposerError> {
    let p = prepare_weights(blocked, extra, rows)?;
    let event_count = p.adjusted.iter().try_fold(0usize, |sum, &(_, w)| {
        usize::try_from(w)
            .ok()
            .and_then(|v| sum.checked_add(v))
            .ok_or(ProposerError::Capacity)
    })?;
    if event_count > (isize::MAX as usize - 7) / 32 {
        return Err(ProposerError::Capacity);
    }
    let mut events = Vec::new();
    events
        .try_reserve_exact(event_count)
        .map_err(|_| ProposerError::Capacity)?;

    let n = p.adjusted.len() as u64;
    for (index, &(key, weight)) in p.adjusted.iter().enumerate() {
        let payload = if p.members.binary_search(&key).is_ok() {
            None
        } else {
            Some(key)
        };
        for j in 0..weight {
            let bits = event_point_bits(index as u64, n, weight, j)?;
            events.push(ScheduleEvent { bits, key: payload });
        }
    }
    events.sort_by(event_order);

    let key_count = events.iter().try_fold(0usize, |sum, ev| {
        sum.checked_add(if ev.key.is_some() { 1 } else { 3 })
            .ok_or(ProposerError::Capacity)
    })?;
    if key_count > isize::MAX as usize / 20 {
        return Err(ProposerError::Capacity);
    }
    let mut keys = Vec::new();
    keys.try_reserve_exact(key_count)
        .map_err(|_| ProposerError::Capacity)?;
    let mut pool = p.fallback;
    for ev in &events {
        if let Some(key) = ev.key {
            keys.push(key);
        } else if !pool.is_empty() {
            for idx in [0, usize::from(pool.len() != 1), 2 % pool.len()] {
                keys.push(pool[idx].1);
                pool[idx].0 = pool[idx].0.saturating_sub(1);
            }
            pool.sort_unstable_by(|a, b| b.cmp(a));
            while pool.last().is_some_and(|x| x.0 == 0) {
                pool.pop();
            }
        }
    }
    Ok(keys)
}

/// Selects the proposer for `selected_round` from `(blocked, extra, rows)`.
pub fn select_proposer(
    blocked: &[Address],
    extra: &[Address],
    rows: &[StakeRow],
    selected_round: u64,
) -> Result<Address, ProposerError> {
    let keys = build_schedule(blocked, extra, rows)?;
    if keys.is_empty() {
        return Err(ProposerError::EmptySchedule);
    }
    Ok(keys[(selected_round % keys.len() as u64) as usize])
}

/// Two-history snapshot store wired directly to `ProposerProvider` and `BlockProposerProvider`.
#[derive(Clone, Debug, Default)]
pub struct ProposerScheduleHistory {
    pub jailed_base_round: u64,
    pub jailed_snapshots: Vec<(u64, Vec<Address>)>,
    pub stake_base_round: u64,
    pub stake_snapshots: Vec<(u64, Vec<StakeRow>)>,
    pub extra_members: Vec<Address>,
}

impl ProposerScheduleHistory {
    pub fn select_for_rounds(
        &self,
        selected_round: u64,
        query_round: u64,
    ) -> Result<Address, ProposerError> {
        let jailed_rounds: Vec<u64> = self.jailed_snapshots.iter().map(|(r, _)| *r).collect();
        let (_, jailed_idx) = history_query(self.jailed_base_round, &jailed_rounds, query_round)?;
        let Some(ji) = jailed_idx else {
            return Err(ProposerError::MissingHistory);
        };

        let stake_rounds: Vec<u64> = self.stake_snapshots.iter().map(|(r, _)| *r).collect();
        let (_, stake_idx) = history_query(self.stake_base_round, &stake_rounds, query_round)?;
        let Some(si) = stake_idx else {
            return Err(ProposerError::MissingHistory);
        };

        select_proposer(
            &self.jailed_snapshots[ji].1,
            &self.extra_members,
            &self.stake_snapshots[si].1,
            selected_round,
        )
    }
}

impl ProposerProvider for ProposerScheduleHistory {
    fn proposer_for_round(&self, round: u64) -> Option<Address> {
        self.select_for_rounds(round, round).ok()
    }
}

impl BlockProposerProvider for ProposerScheduleHistory {
    type Error = ProposerError;

    fn proposer_for_block(
        &self,
        block_round: u64,
        stake_lookup_round: u64,
    ) -> Result<Address, Self::Error> {
        self.select_for_rounds(block_round, stake_lookup_round)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    #[test]
    fn proposer_selection_excludes_jailed_and_wraps_by_schedule_len() {
        let history = ProposerScheduleHistory {
            jailed_base_round: 0,
            jailed_snapshots: vec![(0, vec![addr(1)])],
            stake_base_round: 0,
            stake_snapshots: vec![(0, vec![(addr(1), 50), (addr(2), 3), (addr(3), 1)])],
            extra_members: vec![],
        };
        // addr(1) is jailed -> excluded; addr(2) weight 3*3=9, addr(3) weight 1*3=3 -> 12 slots total
        let sched = build_schedule(
            &[addr(1)],
            &[],
            &[(addr(1), 50), (addr(2), 3), (addr(3), 1)],
        )
        .unwrap();
        assert_eq!(sched.len(), 12);
        assert!(!sched.contains(&addr(1)));
        assert_eq!(sched.iter().filter(|&&k| k == addr(2)).count(), 9);
        assert_eq!(sched.iter().filter(|&&k| k == addr(3)).count(), 3);
        assert_eq!(history.proposer_for_block(12, 0).unwrap(), sched[0]);
        assert_eq!(history.proposer_for_block(13, 0).unwrap(), sched[1]);
    }

    #[test]
    fn missing_history_and_empty_schedule_return_native_tags() {
        let empty = ProposerScheduleHistory::default();
        assert_eq!(
            empty.proposer_for_block(10, 10),
            Err(ProposerError::MissingHistory)
        );
        assert_eq!(ProposerError::MissingHistory.native_tag(), Some(0x28));

        let all_jailed = ProposerScheduleHistory {
            jailed_base_round: 0,
            jailed_snapshots: vec![(0, vec![addr(1)])],
            stake_base_round: 0,
            stake_snapshots: vec![(0, vec![(addr(1), 100)])],
            extra_members: vec![],
        };
        assert_eq!(
            all_jailed.proposer_for_block(5, 5),
            Err(ProposerError::EmptySchedule)
        );
        assert_eq!(ProposerError::EmptySchedule.native_tag(), Some(0x0f));
    }
}
