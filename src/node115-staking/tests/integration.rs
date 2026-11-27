//! End-to-end integration tests for `node115-staking` covering governance
//! proposal creation (`0x3c348b0`), voting with 4x long-term lockup boost and
//! delegation lockup extension (`0x3c33f10`), expired-proposal pruning
//! (`0x3c33520`), 4-category stake requirements (`0x294ceb0`/`0x235a050`),
//! saturating validator stake rollup (`0x3dd9480`/`0x4351de0`), rewards,
//! jailing, and withdrawal queue interactions.

use std::collections::BTreeMap;

use node115_staking::{
    GovernanceState, JailingTime, PROPOSAL_MIN_DELEGATED_STAKE, StakeRequirementCategory,
    StakingChain, TAG_ALREADY_VOTED, TAG_INSUFFICIENT_DELEGATIONS_TO_VOTE, TAG_MUL_RESULT_ERROR,
    TAG_PROPOSAL_DOES_NOT_EXIST, TAG_VOTING_ALREADY_ENDED, VoteError, apply_long_term_vote_boost,
    compute_stake_requirements, rollup_validator_stakes,
};

fn t(days: i32, secs: u32, nanos: u32) -> JailingTime {
    JailingTime {
        major: days,
        seconds: secs,
        nanos,
    }
}

#[test]
fn gov_vote_order_lockup_boost_and_boundary_asymmetry_with_pruning() {
    let mut gov = GovernanceState::new();
    let proposer = [0x01; 20];
    let voter_boosted = [0x02; 20];
    let voter_expired_lockup = [0x03; 20];
    let voter_exact_deadline = [0x04; 20];
    let pid = [0xaa; 32];

    // Unknown proposal rejected first with 0x114.
    let err = gov
        .gov_vote(t(10, 0, 0), pid, voter_boosted, 1, 500)
        .unwrap_err();
    assert_eq!(err, VoteError::ProposalDoesNotExist);
    assert_eq!(err.native_tag(), TAG_PROPOSAL_DOES_NOT_EXIST);

    // Mainnet short window = 86,400 s (1 day).
    let end_time = gov
        .propose(
            StakingChain::Mainnet,
            t(10, 0, 0),
            pid,
            proposer,
            "HIP-115".to_string(),
            "Governance test".to_string(),
            PROPOSAL_MIN_DELEGATED_STAKE,
            false,
        )
        .unwrap();
    assert_eq!(end_time, t(11, 0, 0));

    // Zero delegated stake rejected with 0x116.
    let err = gov
        .gov_vote(t(10, 100, 0), pid, voter_boosted, 1, 0)
        .unwrap_err();
    assert_eq!(err, VoteError::InsufficientDelegations);
    assert_eq!(err.native_tag(), TAG_INSUFFICIENT_DELEGATIONS_TO_VOTE);

    // Active long-term lockup (now < lockup_end) grants 4x boost and extends delegation lockup.
    gov.long_term_lockup_until
        .insert(voter_boosted, Some(t(20, 0, 0)));
    let out = gov
        .gov_vote(t(10, 100, 0), pid, voter_boosted, 1, 2_500)
        .unwrap();
    assert_eq!(out.weight, 10_000);
    assert!(out.long_term_boost_applied);
    assert!(!out.expired_lockup_cleared);
    assert_eq!(out.lockup_extended_to, end_time);
    assert_eq!(gov.delegation_lockup_until.get(&voter_boosted), Some(&end_time));

    // Duplicate vote rejected with 0x115.
    let err = gov
        .gov_vote(t(10, 200, 0), pid, voter_boosted, 0, 2_500)
        .unwrap_err();
    assert_eq!(err, VoteError::AlreadyVoted);
    assert_eq!(err.native_tag(), TAG_ALREADY_VOTED);

    // Expired long-term lockup (now >= lockup_end) is cleared and receives 1x weight.
    gov.long_term_lockup_until
        .insert(voter_expired_lockup, Some(t(10, 300, 0)));
    let out = gov
        .gov_vote(t(10, 300, 0), pid, voter_expired_lockup, 0, 7_000)
        .unwrap();
    assert_eq!(out.weight, 7_000);
    assert!(!out.long_term_boost_applied);
    assert!(out.expired_lockup_cleared);
    assert_eq!(gov.long_term_lockup_until.get(&voter_expired_lockup), Some(&None));

    // Exact deadline now == end_time is STILL accepted by gov_vote (0x3c340a0..0x3c340cf).
    let out = gov
        .gov_vote(end_time, pid, voter_exact_deadline, 1, 1_000)
        .unwrap();
    assert_eq!(out.weight, 1_000);

    // 1 ns past end_time is rejected with 0x117 (checked before AlreadyVoted).
    let err = gov
        .gov_vote(t(11, 0, 1), pid, voter_boosted, 1, 2_500)
        .unwrap_err();
    assert_eq!(err, VoteError::VotingEnded);
    assert_eq!(err.native_tag(), TAG_VOTING_ALREADY_ENDED);

    // Overflow guard: values >= 2^62 stay unshifted (0x3c343d3 shr $0x3e).
    let huge = 1u64 << 62;
    assert_eq!(apply_long_term_vote_boost(huge - 1), (huge - 1) << 2);
    assert_eq!(apply_long_term_vote_boost(huge), huge);

    // Pruning before end_time keeps the proposal; pruning AT now == end_time drains it (0x3c336e8).
    assert!(gov.prune_expired_proposals(t(10, 86_399, 999_999_999)).is_empty());
    let drained = gov.prune_expired_proposals(end_time);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[&pid].votes.len(), 3);
    assert!(gov.proposals.is_empty());
}

#[test]
fn stake_requirements_and_validator_rollup_end_to_end() {
    let (per_cat, total) = compute_stake_requirements(
        StakingChain::Mainnet,
        [2, 1, 1, 0],
        Some(StakeRequirementCategory::Category3),
    )
    .unwrap();
    assert_eq!(
        per_cat,
        [
            100_000_000_000_000,
            20_000_000_000_000,
            50_000_000_000_000,
            50_000_000_000_000,
        ]
    );
    assert_eq!(total, 220_000_000_000_000);

    let err = compute_stake_requirements(
        StakingChain::Mainnet,
        [u64::MAX, 0, 0, 0],
        None,
    )
    .unwrap_err();
    assert_eq!(err.native_tag(), TAG_MUL_RESULT_ERROR);

    let mut stakes: BTreeMap<[u8; 32], BTreeMap<[u8; 20], u64>> = BTreeMap::new();
    stakes.insert(
        [0x01; 32],
        BTreeMap::from([([0xa1; 20], 40_000), ([0xa2; 20], 60_000)]),
    );
    stakes.insert(
        [0x02; 32],
        BTreeMap::from([([0xb1; 20], u64::MAX - 5), ([0xb2; 20], 99)]),
    );
    let rolled = rollup_validator_stakes(&stakes);
    assert_eq!(rolled, vec![([0x01; 32], 100_000), ([0x02; 32], u64::MAX)]);
}
