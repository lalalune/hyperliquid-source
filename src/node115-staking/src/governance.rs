//! Independently authored Rust reconstruction of node #115's staking governance
//! proposal creation (`0x3c348b0..0x3c34fca`, slot `0x64e5bd0`), governance
//! voting with 4x long-term lockup multiplier (`0x3c33f10..0x3c348ae`), and
//! expired-proposal pruning (`0x3c33520..0x3c33f07`).

use std::collections::BTreeMap;

use crate::delegation::{StakingChain, add_secs_saturating};
use crate::jailing::{Address, JailingTime};

/// Exact native error tags emitted by `0x3c348b0` (`gov_propose`) and
/// `0x3c33f10` (`gov_vote`), verified against node #115's `UserError` display
/// jump table at `0x7d8c1c`.
pub const TAG_PROPOSAL_TITLE_LEN: u16 = 0x10f; // 271: 1..=50
pub const TAG_PROPOSAL_DESC_LEN: u16 = 0x110; // 272: 1..=1000
pub const TAG_INSUFFICIENT_DELEGATIONS_TO_PROPOSE: u16 = 0x111; // 273: < 1_000_000_000
pub const TAG_PROPOSAL_ALREADY_EXISTS: u16 = 0x112; // 274
pub const TAG_TOO_MANY_ACTIVE_PROPOSALS: u16 = 0x113; // 275: existing > 2 (limit 3)
pub const TAG_PROPOSAL_DOES_NOT_EXIST: u16 = 0x114; // 276: "Proposal does not exist"
pub const TAG_ALREADY_VOTED: u16 = 0x115; // 277: "Already voted"
pub const TAG_INSUFFICIENT_DELEGATIONS_TO_VOTE: u16 = 0x116; // 278: "Insufficient delegations to vote"
pub const TAG_VOTING_ALREADY_ENDED: u16 = 0x117; // 279: "Voting on the proposal has already ended."
pub const TAG_GOV_OK: u16 = 0x1a2; // 418: Ok

/// Exact bit-shift guard for the 4x long-term lockup voting-weight boost in
/// `0x3c343cb..0x3c343dd` (`shr $0x3e, %rax; jne skip; shl $0x2, %rcx`).
pub const LONG_TERM_VOTE_BOOST_SHIFT: u32 = 2;
pub const LONG_TERM_VOTE_BOOST_OVERFLOW_SHIFT: u32 = 62;

/// 32-byte proposal identifier key in `CStaking.gov_proposals` (`[state+0x130]`).
pub type ProposalId = [u8; 32];

/// Verified constants from `0x3c3491e..0x3c3499b` and `0x3c34c26`.
pub const PROPOSAL_TITLE_MIN_LEN: usize = 1;
pub const PROPOSAL_TITLE_MAX_LEN: usize = 50; // 0x32
pub const PROPOSAL_DESC_MIN_LEN: usize = 1;
pub const PROPOSAL_DESC_MAX_LEN: usize = 1_000; // 0x3e8
pub const PROPOSAL_MIN_DELEGATED_STAKE: u64 = 1_000_000_000; // 0x3b9aca00
pub const MAX_ACTIVE_PROPOSALS_PER_USER: usize = 3; // rejects when existing > 2

/// Exact `.rodata` IEEE-754 `f64` voting duration constants at `0x3c34c73..0x3c34cb2`.
pub const PROPOSAL_DURATION_TEST_LONG_BITS: u64 = 0x4072_c000_0000_0000; // 300.0 s @ 0x455bc0
pub const PROPOSAL_DURATION_TEST_SHORT_BITS: u64 = 0x405e_0000_0000_0000; // 120.0 s @ 0x455bc8
pub const PROPOSAL_DURATION_MAIN_LONG_BITS: u64 = 0x411f_a400_0000_0000; // 518,400.0 s @ 0x459418
pub const PROPOSAL_DURATION_MAIN_SHORT_BITS: u64 = 0x40f5_1800_0000_0000; // 86,400.0 s @ 0x459ac0

/// Rejection reasons matching `0x3c348b0`'s exact check order and native tags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposeError {
    TitleLengthOutOfRange { len: usize },
    DescriptionLengthOutOfRange { len: usize },
    InsufficientDelegations { delegated: u64 },
    ProposalAlreadyExists,
    TooManyActiveProposals { existing_for_user: usize },
}

impl ProposeError {
    pub const fn native_tag(self) -> u16 {
        match self {
            Self::TitleLengthOutOfRange { .. } => TAG_PROPOSAL_TITLE_LEN,
            Self::DescriptionLengthOutOfRange { .. } => TAG_PROPOSAL_DESC_LEN,
            Self::InsufficientDelegations { .. } => TAG_INSUFFICIENT_DELEGATIONS_TO_PROPOSE,
            Self::ProposalAlreadyExists => TAG_PROPOSAL_ALREADY_EXISTS,
            Self::TooManyActiveProposals { .. } => TAG_TOO_MANY_ACTIVE_PROPOSALS,
        }
    }
}

/// Voting duration in seconds selected by `0x3c34c73..0x3c34cb2`.
pub const fn proposal_voting_duration_secs(chain: StakingChain, long_window: bool) -> u64 {
    match chain {
        StakingChain::Sandbox | StakingChain::Testnet => {
            if long_window {
                300
            } else {
                120
            }
        }
        StakingChain::Local | StakingChain::Mainnet => {
            if long_window {
                518_400
            } else {
                86_400
            }
        }
    }
}

/// Evaluates `0x3c348b0`'s admission predicates in exact native order and returns
/// the proposal voting deadline (`now + duration`).
#[allow(clippy::too_many_arguments)]
pub fn validate_proposal_creation(
    chain: StakingChain,
    now: JailingTime,
    title: &str,
    description: &str,
    proposer_delegated_stake: u64,
    proposal_id_exists: bool,
    existing_active_for_user: usize,
    long_window: bool,
) -> Result<JailingTime, ProposeError> {
    let title_len = title.len();
    if !(PROPOSAL_TITLE_MIN_LEN..=PROPOSAL_TITLE_MAX_LEN).contains(&title_len) {
        return Err(ProposeError::TitleLengthOutOfRange { len: title_len });
    }
    let desc_len = description.len();
    if !(PROPOSAL_DESC_MIN_LEN..=PROPOSAL_DESC_MAX_LEN).contains(&desc_len) {
        return Err(ProposeError::DescriptionLengthOutOfRange { len: desc_len });
    }
    if proposer_delegated_stake < PROPOSAL_MIN_DELEGATED_STAKE {
        return Err(ProposeError::InsufficientDelegations {
            delegated: proposer_delegated_stake,
        });
    }
    if proposal_id_exists {
        return Err(ProposeError::ProposalAlreadyExists);
    }
    if existing_active_for_user >= MAX_ACTIVE_PROPOSALS_PER_USER {
        return Err(ProposeError::TooManyActiveProposals {
            existing_for_user: existing_active_for_user,
        });
    }
    let duration = proposal_voting_duration_secs(chain, long_window);
    Ok(add_secs_saturating(now, duration))
}

/// Rejection reasons emitted by `CStaking::gov_vote` (`0x3c33f10..0x3c348ae`) in
/// exact native check order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteError {
    ProposalDoesNotExist,
    VotingEnded,
    AlreadyVoted,
    InsufficientDelegations,
}

impl VoteError {
    pub const fn native_tag(self) -> u16 {
        match self {
            Self::ProposalDoesNotExist => TAG_PROPOSAL_DOES_NOT_EXIST,
            Self::VotingEnded => TAG_VOTING_ALREADY_ENDED,
            Self::AlreadyVoted => TAG_ALREADY_VOTED,
            Self::InsufficientDelegations => TAG_INSUFFICIENT_DELEGATIONS_TO_VOTE,
        }
    }
}

/// Recorded vote entry in `Proposal.votes` (`0x3c34625..0x3c34636`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordedVote {
    pub weight: u64,
    pub choice: u8,
}

/// Active governance proposal stored in `CStaking.gov_proposals` (`[state+0x130]`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceProposal {
    pub proposer: Address,
    pub title: String,
    pub description: String,
    pub end_time: JailingTime,
    pub votes: BTreeMap<Address, RecordedVote>,
}

/// Outcome of a successful `gov_vote` call (`0x3c33f10`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovVoteOutcome {
    pub weight: u64,
    pub choice: u8,
    pub lockup_extended_to: JailingTime,
    pub long_term_boost_applied: bool,
    pub expired_lockup_cleared: bool,
}

/// Applies node #115's exact overflow-guarded 4x long-term vote weight boost
/// (`0x3c343cb..0x3c343dd`): `if (weight >> 62) == 0 { weight << 2 } else { weight }`.
pub const fn apply_long_term_vote_boost(base_weight: u64) -> u64 {
    if (base_weight >> LONG_TERM_VOTE_BOOST_OVERFLOW_SHIFT) == 0 {
        base_weight << LONG_TERM_VOTE_BOOST_SHIFT
    } else {
        base_weight
    }
}

/// Cohesive governance proposal store modeling `CStaking.gov_proposals`
/// (`[state+0x130]`), per-user long-term lockup timestamps (`[state+0x228]`),
/// and delegation lockup extensions (`0x4221ca0`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GovernanceState {
    pub proposals: BTreeMap<ProposalId, GovernanceProposal>,
    pub long_term_lockup_until: BTreeMap<Address, Option<JailingTime>>,
    pub delegation_lockup_until: BTreeMap<Address, JailingTime>,
}

impl GovernanceState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates and stores a proposal using `0x3c348b0`'s exact admission gate.
    #[allow(clippy::too_many_arguments)]
    pub fn propose(
        &mut self,
        chain: StakingChain,
        now: JailingTime,
        proposal_id: ProposalId,
        proposer: Address,
        title: String,
        description: String,
        proposer_delegated_stake: u64,
        long_window: bool,
    ) -> Result<JailingTime, ProposeError> {
        let existing_for_user = self
            .proposals
            .values()
            .filter(|p| p.proposer == proposer)
            .count();
        let end_time = validate_proposal_creation(
            chain,
            now,
            &title,
            &description,
            proposer_delegated_stake,
            self.proposals.contains_key(&proposal_id),
            existing_for_user,
            long_window,
        )?;
        self.proposals.insert(
            proposal_id,
            GovernanceProposal {
                proposer,
                title,
                description,
                end_time,
                votes: BTreeMap::new(),
            },
        );
        Ok(end_time)
    }

    /// Executes `CStaking::gov_vote` (`0x3c33f10..0x3c348ae`) in exact native
    /// check order:
    /// 1. Proposal lookup (`0x114` if missing).
    /// 2. Deadline check (`0x117` if strictly `now > end_time`; `now == end_time` succeeds).
    /// 3. Duplicate voter check (`0x115` if `voter` already voted).
    /// 4. Non-zero delegated stake check (`0x116` if `voter_delegated_stake == 0`).
    /// 5. Extend voter's delegation lockup to `max(existing, proposal.end_time)` (`0x4221ca0`).
    /// 6. Long-term lockup check (`[state+0x228]`): if `now < lockup_end_time`, apply
    ///    overflow-guarded 4x boost (`0x3c343cb..0x3c343dd`); if present and expired
    ///    (`now >= lockup_end_time`), clear lockup (`0x3c343be`).
    /// 7. Record `(voter -> RecordedVote { weight, choice })`.
    pub fn gov_vote(
        &mut self,
        now: JailingTime,
        proposal_id: ProposalId,
        voter: Address,
        choice: u8,
        voter_delegated_stake: u64,
    ) -> Result<GovVoteOutcome, VoteError> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(VoteError::ProposalDoesNotExist)?;

        // 0x3c340a0..0x3c340cf: rejects strictly when now > end_time.
        if now > proposal.end_time {
            return Err(VoteError::VotingEnded);
        }

        // 0x3c340de..0x3c341c5: rejects duplicate voter.
        if proposal.votes.contains_key(&voter) {
            return Err(VoteError::AlreadyVoted);
        }

        // 0x3c341ef..0x3c341f8: rejects zero delegated stake.
        if voter_delegated_stake == 0 {
            return Err(VoteError::InsufficientDelegations);
        }

        let end_time = proposal.end_time;
        // 0x3c3423d: extend voter's delegation lockup to proposal.end_time.
        self.delegation_lockup_until
            .entry(voter)
            .and_modify(|cur| {
                if end_time > *cur {
                    *cur = end_time;
                }
            })
            .or_insert(end_time);

        // 0x3c34242..0x3c343e2: check long-term staking lockup and apply 4x boost if active.
        let mut weight = voter_delegated_stake;
        let mut long_term_boost_applied = false;
        let mut expired_lockup_cleared = false;
        if let Some(slot) = self.long_term_lockup_until.get_mut(&voter) {
            match *slot {
                Some(lockup_end) if now < lockup_end => {
                    weight = apply_long_term_vote_boost(weight);
                    long_term_boost_applied = true;
                }
                Some(_) => {
                    *slot = None;
                    expired_lockup_cleared = true;
                }
                None => {}
            }
        }

        proposal
            .votes
            .insert(voter, RecordedVote { weight, choice });
        Ok(GovVoteOutcome {
            weight,
            choice,
            lockup_extended_to: end_time,
            long_term_boost_applied,
            expired_lockup_cleared,
        })
    }

    /// Executes `CStaking::prune_expired_proposals` (`0x3c33520..0x3c33f07`):
    /// collects and drains every proposal with `now >= proposal.end_time`
    /// (`0x3c336e8..0x3c33718`), returning the drained map keyed by `ProposalId`.
    pub fn prune_expired_proposals(
        &mut self,
        now: JailingTime,
    ) -> BTreeMap<ProposalId, GovernanceProposal> {
        let expired_ids: Vec<ProposalId> = self
            .proposals
            .iter()
            .filter_map(|(&id, p)| (now >= p.end_time).then_some(id))
            .collect();
        let mut drained = BTreeMap::new();
        for id in expired_ids {
            if let Some(p) = self.proposals.remove(&id) {
                drained.insert(id, p);
            }
        }
        drained
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(days: i32, secs: u32) -> JailingTime {
        JailingTime {
            major: days,
            seconds: secs,
            nanos: 0,
        }
    }

    #[test]
    fn proposal_gate_enforces_exact_order_bounds_and_durations() {
        let ok_title = "HIP-99";
        let ok_desc = "Enable governance parameter update";

        assert_eq!(
            validate_proposal_creation(StakingChain::Mainnet, t(10, 0), "", ok_desc, 0, true, 9, false),
            Err(ProposeError::TitleLengthOutOfRange { len: 0 })
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 0),
                &"a".repeat(51),
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                0,
                false,
            ),
            Err(ProposeError::TitleLengthOutOfRange { len: 51 })
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 0),
                ok_title,
                &"b".repeat(1001),
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                0,
                false,
            ),
            Err(ProposeError::DescriptionLengthOutOfRange { len: 1001 })
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 0),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE - 1,
                false,
                0,
                false,
            ),
            Err(ProposeError::InsufficientDelegations {
                delegated: PROPOSAL_MIN_DELEGATED_STAKE - 1,
            })
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 0),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                true,
                0,
                false,
            ),
            Err(ProposeError::ProposalAlreadyExists)
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 0),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                3,
                false,
            ),
            Err(ProposeError::TooManyActiveProposals {
                existing_for_user: 3,
            })
        );

        // Existing active == 2 is allowed (3rd proposal); Mainnet long window = 6 days (518,400s)
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 5),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                2,
                true,
            ),
            Ok(t(16, 5))
        );
        // Testnet short window = 120s, long window = 300s
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Testnet,
                t(10, 5),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                0,
                false,
            ),
            Ok(t(10, 125))
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Sandbox,
                t(10, 5),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                0,
                true,
            ),
            Ok(t(10, 305))
        );
    }
}
