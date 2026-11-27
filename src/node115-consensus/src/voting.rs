//! Independently authored Rust reconstruction of node #115's HotStuff voting
//! decision (`0x2e07a00..0x2e08745`), QC processing & equivocation detection
//! (`0x2e08750..0x2e089f4` + `0x2e1fe30..0x2e20047`), and uncommitted ancestor
//! chain completeness check (`0x2e20b00..0x2e210ef`).
//!
//! Backed by `research/work-items/RE-008-node115-hotstuff-vote-and-qc`.

use std::collections::{BTreeMap, BTreeSet};

use crate::block_rules::BlockProposerProvider;
use crate::round_progression::{
    Address, AdvanceRoundReport, ProposerProvider, RoundState, advance_round,
};

/// Maximum cumulative tx-batch bytes per block enforced at `0x2e082e3` (`cmp rbp, 0x4c4b40`).
pub const MAX_BLOCK_TX_BYTES: u64 = 5_000_000;

/// Maximum future block timestamp drift (`block.time - now <= 3.5s`) at `.rodata 0x459518`.
pub const MAX_FUTURE_BLOCK_DRIFT_SECS_BITS: u64 = 0x400c_0000_0000_0000; // 3.5 s
pub const MAX_FUTURE_BLOCK_DRIFT_NANOS: u64 = 3_500_000_000;

/// Vote pacing delay (`0.05s` = 50 ms) at `.rodata 0x459038` when `[state+0xbd4] != 0`.
pub const VOTE_PACING_DELAY_SECS_BITS: u64 = 0x3fa9_9999_9999_999a; // 0.05 s
pub const VOTE_PACING_DELAY_NANOS: u64 = 50_000_000;

/// Zero 32-byte genesis parent hash checked at `0x2e07e2b` / `0x2e20bae`.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// Minimal consensus block header stored in `[state+0x2c0]` for ancestor & vote checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBlockHeader {
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub parent_round: u64,
    pub block_round: u64,
    pub validator_set_round: u64,
    pub timestamp_nanos: u64,
    pub tx_hashes: Vec<[u8; 32]>,
}

/// Quorum Certificate summary processed by `0x2e08750` (`process_qc`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QcSummary {
    pub round: u64,
    pub block_hash: [u8; 32],
}

/// Equivocation safety record emitted by `0x2e1fe30` when two distinct block hashes
/// carry QCs for the same round.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QcEquivocationAlert {
    pub round: u64,
    pub existing_hash: [u8; 32],
    pub conflicting_hash: [u8; 32],
}

/// Result of `0x2e08750` (`process_qc`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessQcOutcome {
    pub equivocation_alert: Option<QcEquivocationAlert>,
    pub updated_highest_qc: bool,
    pub advance: AdvanceRoundReport,
}

/// Result of `0x2e20b00` (`collect_uncommitted_ancestors`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AncestorChainOutcome {
    /// Tag `0`: unbroken chain back to `committed_round` (with collected uncommitted tx hashes).
    Complete { ancestor_tx_hashes: Vec<[u8; 32]> },
    /// Tag `1`: missing ancestor block or chain skipped past `committed_round`.
    MissingBlock([u8; 32]),
}

/// Outcome of `0x2e07a00` (`try_vote`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TryVoteOutcome<PE> {
    VoteEmitted {
        block_round: u64,
        block_hash: [u8; 32],
        next_leader_round: u64,
        recipient: Address,
        new_min_vote_time_nanos: u64,
    },
    VotePacingNotElapsed,
    AlreadyVotedOrCommitted,
    NoBlockForCurrentRound,
    MissingTxBatch([u8; 32]),
    MissingParentBlock([u8; 32]),
    NonIncreasingTimestamp,
    IncompleteAncestorChain([u8; 32]),
    BlockPayloadTooLarge { total_bytes: u64 },
    NotInActiveStakeSet,
    AlreadyTimedOutInRound,
    BlockTooFarInFuture { drift_nanos: u64 },
    NextLeaderLookupFailed(PE),
}

/// Stateful HotStuff voting + QC safety tracker modeling `0x2e07a00`, `0x2e08750`,
/// `0x2e1fe30`, and `0x2e20b00`.
#[derive(Clone, Debug, Default)]
pub struct HotStuffVoteState {
    pub committed_round: u64,
    pub last_voted_round: u64,
    pub min_vote_time_nanos: u64,
    pub vote_pacing_enabled: bool,
    pub highest_qc: Option<QcSummary>,
    pub certified_blocks: BTreeMap<u64, [u8; 32]>,
    pub pending_blocks: BTreeMap<[u8; 32], PendingBlockHeader>,
    pub local_tx_sizes: BTreeMap<[u8; 32], u64>,
}

impl HotStuffVoteState {
    /// Reconstructs `0x2e1fe30` (`record_qc_and_check_equivocation`).
    pub fn record_qc_and_check_equivocation(
        &mut self,
        qc: QcSummary,
    ) -> Option<QcEquivocationAlert> {
        if let Some(&existing) = self.certified_blocks.get(&qc.round) {
            if existing != qc.block_hash {
                return Some(QcEquivocationAlert {
                    round: qc.round,
                    existing_hash: existing,
                    conflicting_hash: qc.block_hash,
                });
            }
            None
        } else {
            self.certified_blocks.insert(qc.round, qc.block_hash);
            None
        }
    }

    /// Reconstructs `0x2e08750` (`process_qc`):
    /// 1. Records `(qc.round, qc.block_hash)` and detects 32-byte equivocation (`0x2e1fe30`).
    /// 2. Updates `highest_qc` when `qc.round > highest_qc.round`.
    /// 3. Advances consensus round via `advance_round(round_state, qc.round, None)` (`0x2e19920`).
    pub fn process_qc<P: ProposerProvider>(
        &mut self,
        round_state: &mut RoundState,
        proposers: &P,
        qc: QcSummary,
    ) -> ProcessQcOutcome {
        let equivocation_alert = self.record_qc_and_check_equivocation(qc);
        let updated_highest_qc = match self.highest_qc {
            Some(prev) if qc.round <= prev.round => false,
            _ => {
                self.highest_qc = Some(qc);
                true
            }
        };
        let advance = advance_round(round_state, qc.round, None, proposers);
        ProcessQcOutcome {
            equivocation_alert,
            updated_highest_qc,
            advance,
        }
    }

    /// Reconstructs `0x2e20b00` (`collect_uncommitted_ancestors`):
    /// walks `parent_hash` links down to `committed_round`.
    pub fn collect_uncommitted_ancestors(&self, start_parent_hash: [u8; 32]) -> AncestorChainOutcome {
        let mut cur_hash = start_parent_hash;
        let mut ancestor_tx_hashes = Vec::new();
        let mut visited = BTreeSet::new();

        loop {
            if cur_hash == GENESIS_HASH {
                if self.committed_round == 0 {
                    return AncestorChainOutcome::Complete { ancestor_tx_hashes };
                }
                return AncestorChainOutcome::MissingBlock(cur_hash);
            }
            if !visited.insert(cur_hash) {
                return AncestorChainOutcome::MissingBlock(cur_hash);
            }
            let Some(block) = self.pending_blocks.get(&cur_hash) else {
                return AncestorChainOutcome::MissingBlock(cur_hash);
            };
            if block.block_round <= self.committed_round {
                if block.block_round == self.committed_round {
                    return AncestorChainOutcome::Complete { ancestor_tx_hashes };
                }
                return AncestorChainOutcome::MissingBlock(cur_hash);
            }
            ancestor_tx_hashes.extend_from_slice(&block.tx_hashes);
            cur_hash = block.parent_hash;
        }
    }

    /// Reconstructs `0x2e07a00` (`try_vote`) in exact native predicate order.
    pub fn try_vote<P: BlockProposerProvider>(
        &mut self,
        round_state: &RoundState,
        now_nanos: u64,
        active_validators: &BTreeSet<Address>,
        proposers: &P,
    ) -> TryVoteOutcome<P::Error> {
        if now_nanos < self.min_vote_time_nanos {
            return TryVoteOutcome::VotePacingNotElapsed;
        }
        let cur_round = round_state.round;
        if cur_round <= self.last_voted_round || cur_round <= self.committed_round {
            return TryVoteOutcome::AlreadyVotedOrCommitted;
        }

        let Some(block) = self
            .pending_blocks
            .values()
            .find(|b| b.block_round == cur_round && b.block_round > self.committed_round)
            .cloned()
        else {
            return TryVoteOutcome::NoBlockForCurrentRound;
        };

        for tx_hash in &block.tx_hashes {
            if !self.local_tx_sizes.contains_key(tx_hash) {
                return TryVoteOutcome::MissingTxBatch(*tx_hash);
            }
        }

        if block.parent_hash == GENESIS_HASH {
            if block.timestamp_nanos == 0 {
                return TryVoteOutcome::NonIncreasingTimestamp;
            }
        } else {
            let Some(parent) = self.pending_blocks.get(&block.parent_hash) else {
                return TryVoteOutcome::MissingParentBlock(block.parent_hash);
            };
            if block.timestamp_nanos <= parent.timestamp_nanos {
                return TryVoteOutcome::NonIncreasingTimestamp;
            }
        }

        if let AncestorChainOutcome::MissingBlock(missing) =
            self.collect_uncommitted_ancestors(block.parent_hash)
        {
            return TryVoteOutcome::IncompleteAncestorChain(missing);
        }

        let mut total_bytes = 0u64;
        for tx_hash in &block.tx_hashes {
            let sz = self.local_tx_sizes.get(tx_hash).copied().unwrap_or(0);
            total_bytes = total_bytes.saturating_add(sz);
        }
        if total_bytes > MAX_BLOCK_TX_BYTES {
            return TryVoteOutcome::BlockPayloadTooLarge { total_bytes };
        }

        if !active_validators.contains(&round_state.self_address) {
            return TryVoteOutcome::NotInActiveStakeSet;
        }
        if round_state.timed_out_this_round {
            return TryVoteOutcome::AlreadyTimedOutInRound;
        }
        if let Some(drift_nanos) = block.timestamp_nanos.checked_sub(now_nanos)
            && drift_nanos > MAX_FUTURE_BLOCK_DRIFT_NANOS
        {
            return TryVoteOutcome::BlockTooFarInFuture { drift_nanos };
        }

        let next_leader_round = block.parent_round.saturating_add(2);
        let recipient = match proposers
            .proposer_for_block(next_leader_round, block.validator_set_round)
        {
            Ok(addr) => addr,
            Err(err) => return TryVoteOutcome::NextLeaderLookupFailed(err),
        };

        self.last_voted_round = block.block_round;
        let pacing = if self.vote_pacing_enabled {
            VOTE_PACING_DELAY_NANOS
        } else {
            0
        };
        self.min_vote_time_nanos = now_nanos.saturating_add(pacing);

        TryVoteOutcome::VoteEmitted {
            block_round: block.block_round,
            block_hash: block.block_hash,
            next_leader_round,
            recipient,
            new_min_vote_time_nanos: self.min_vote_time_nanos,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposer::ProposerScheduleHistory;

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    #[test]
    fn process_qc_detects_equivocation_and_advances_round() {
        let hist = ProposerScheduleHistory {
            jailed_base_round: 0,
            jailed_snapshots: vec![(0, vec![])],
            stake_base_round: 0,
            stake_snapshots: vec![(0, vec![(addr(1), 1)])],
            extra_members: vec![],
        };
        let mut rs = RoundState::new(addr(1), 5);
        let mut vs = HotStuffVoteState::default();

        let out1 = vs.process_qc(
            &mut rs,
            &hist,
            QcSummary {
                round: 5,
                block_hash: [0xaa; 32],
            },
        );
        assert!(out1.equivocation_alert.is_none());
        assert!(out1.updated_highest_qc);
        assert!(out1.advance.advanced);
        assert_eq!(rs.round, 6);

        // Conflicting QC for round 5 triggers equivocation alert and does not overwrite highest_qc
        let out2 = vs.process_qc(
            &mut rs,
            &hist,
            QcSummary {
                round: 5,
                block_hash: [0xbb; 32],
            },
        );
        assert_eq!(
            out2.equivocation_alert,
            Some(QcEquivocationAlert {
                round: 5,
                existing_hash: [0xaa; 32],
                conflicting_hash: [0xbb; 32],
            })
        );
        assert!(!out2.updated_highest_qc);
        assert!(!out2.advance.advanced);
    }

    #[test]
    fn try_vote_enforces_5mb_cap_timeout_excl_3_5s_drift_and_50ms_pacing() {
        let hist = ProposerScheduleHistory {
            jailed_base_round: 0,
            jailed_snapshots: vec![(0, vec![])],
            stake_base_round: 0,
            stake_snapshots: vec![(0, vec![(addr(1), 1)])],
            extra_members: vec![],
        };
        let mut active = BTreeSet::new();
        active.insert(addr(1));

        let mut rs = RoundState::new(addr(1), 1);
        let mut vs = HotStuffVoteState {
            committed_round: 0,
            vote_pacing_enabled: true,
            ..Default::default()
        };
        let tx_h = [0x11; 32];
        vs.local_tx_sizes.insert(tx_h, MAX_BLOCK_TX_BYTES + 1);
        vs.pending_blocks.insert(
            [0x22; 32],
            PendingBlockHeader {
                block_hash: [0x22; 32],
                parent_hash: GENESIS_HASH,
                parent_round: 0,
                block_round: 1,
                validator_set_round: 0,
                timestamp_nanos: 10_000_000_000,
                tx_hashes: vec![tx_h],
            },
        );

        // Exceeds 5MB cap
        assert_eq!(
            vs.try_vote(&rs, 10_000_000_000, &active, &hist),
            TryVoteOutcome::BlockPayloadTooLarge {
                total_bytes: MAX_BLOCK_TX_BYTES + 1,
            }
        );

        // Shrink tx to fit 5MB, but set now so drift is 3.5s + 1ns -> rejected
        vs.local_tx_sizes.insert(tx_h, MAX_BLOCK_TX_BYTES);
        assert_eq!(
            vs.try_vote(
                &rs,
                10_000_000_000 - MAX_FUTURE_BLOCK_DRIFT_NANOS - 1,
                &active,
                &hist
            ),
            TryVoteOutcome::BlockTooFarInFuture {
                drift_nanos: MAX_FUTURE_BLOCK_DRIFT_NANOS + 1,
            }
        );

        // Already timed out in round -> rejected
        rs.timed_out_this_round = true;
        assert_eq!(
            vs.try_vote(&rs, 10_000_000_000, &active, &hist),
            TryVoteOutcome::AlreadyTimedOutInRound
        );

        // Clear timeout -> emits vote routed to proposer(parent_round + 2 = 2) and sets +50ms pacing
        rs.timed_out_this_round = false;
        assert_eq!(
            vs.try_vote(&rs, 10_000_000_000, &active, &hist),
            TryVoteOutcome::VoteEmitted {
                block_round: 1,
                block_hash: [0x22; 32],
                next_leader_round: 2,
                recipient: addr(1),
                new_min_vote_time_nanos: 10_050_000_000,
            }
        );
        // Immediate retry rejected by pacing, after pacing rejected by anti-double-vote
        assert_eq!(
            vs.try_vote(&rs, 10_049_999_999, &active, &hist),
            TryVoteOutcome::VotePacingNotElapsed
        );
        assert_eq!(
            vs.try_vote(&rs, 10_050_000_000, &active, &hist),
            TryVoteOutcome::AlreadyVotedOrCommitted
        );
        assert_eq!(f64::from_bits(MAX_FUTURE_BLOCK_DRIFT_SECS_BITS), 3.5);
        assert_eq!(f64::from_bits(VOTE_PACING_DELAY_SECS_BITS), 0.05);
    }
}
