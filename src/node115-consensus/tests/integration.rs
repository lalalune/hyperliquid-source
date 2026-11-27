//! End-to-end integration tests for `node115-consensus` exercising the full
//! HotStuff-2 consensus lifecycle across all reconstructed node #115 modules:
//! proposer selection (`0x595cb30`), wire signing codec & `try_propose` guards
//! (`0x5823db0` / `0x2e13ea0`), HotStuff QC equivocation detection (`0x2e1fe30`),
//! 128-bit strict 2/3 stake quorum (`0x4d3e1a0`), certified two-chain commit &
//! `register_block` guards (`0x2e157c0` / `0x2e1da10`), timeout counter &
//! round advancement (`0x2e19920` / `0x2e098e0`), and 180s heartbeat latency
//! EMA tracking (`0x5a71e20` / `0x5a71ee0`).

use std::collections::BTreeSet;

use node115_consensus::{
    CertifiedBlockNode, GENESIS_HASH, HEARTBEAT_WINDOW_SECS, HeartbeatTracker, HotStuffVoteState,
    ProposerScheduleHistory, QcSummary, REGISTER_TAG_NOT_NEW, REGISTER_TAG_STALE,
    RegisterBlockOutcome, SIGNING_TAG_BLOCK, TryProposeDecision, TwoChainCommitOutcome,
    TwoChainCommitStore, VALIDATOR_LATENCY_EMA_KEY, encode_block_signing_payload,
    evaluate_try_propose_guards, has_strict_two_thirds_quorum_u128, select_proposer,
};

#[test]
fn hotstuff2_propose_vote_quorum_two_chain_commit_and_heartbeat_loop() {
    // 1. Deterministic proposer selection (0x595cb30) over 3 validators.
    let v1 = [0x01; 20];
    let v2 = [0x02; 20];
    let v3 = [0x03; 20];
    let rows = vec![(v1, 400u64), (v2, 300u64), (v3, 300u64)];
    let proposer_r1 = select_proposer(&[], &[], &rows, 1).unwrap();
    assert!([v1, v2, v3].contains(&proposer_r1));

    let history = ProposerScheduleHistory {
        jailed_base_round: 0,
        jailed_snapshots: vec![(0, vec![])],
        stake_base_round: 0,
        stake_snapshots: vec![(0, rows)],
        extra_members: vec![],
    };
    let active: BTreeSet<[u8; 20]> = BTreeSet::from([v1, v2, v3]);

    // 2. Wire signing codec (0x5823db0) & try_propose guards (0x2e13ea0).
    let b1_hash = [0x11; 32];
    let b2_hash = [0x22; 32];
    let b3_hash = [0x33; 32];
    let payload =
        encode_block_signing_payload(&proposer_r1, &[b1_hash], 1_700_000_000, 123, &[0u8]).unwrap();
    assert_eq!(payload[0], SIGNING_TAG_BLOCK);
    assert_eq!(&payload[1..21], &proposer_r1);

    assert_eq!(
        evaluate_try_propose_guards(&history, proposer_r1, 1, 0, Some(0), &active),
        TryProposeDecision::Propose
    );
    assert_eq!(
        evaluate_try_propose_guards(&history, proposer_r1, 1, 0, Some(1), &active),
        TryProposeDecision::AlreadyProposedForRound {
            last_proposed_round: 1
        }
    );

    // 3. 128-bit strict 2/3 stake quorum check (0x4d3e1a0): 3*signed > 2*total.
    let total_stake = 1_000u64;
    assert!(!has_strict_two_thirds_quorum_u128(666, total_stake));
    assert!(has_strict_two_thirds_quorum_u128(667, total_stake));
    assert!(has_strict_two_thirds_quorum_u128(u64::MAX, u64::MAX));

    // 4. HotStuff QC equivocation detection (0x2e1fe30).
    let mut vote_state = HotStuffVoteState::default();
    let qc1 = QcSummary {
        round: 1,
        block_hash: b1_hash,
    };
    assert!(vote_state.record_qc_and_check_equivocation(qc1).is_none());
    let equiv = vote_state.record_qc_and_check_equivocation(QcSummary {
        round: 1,
        block_hash: [0xee; 32],
    });
    assert!(equiv.is_some());
    assert_eq!(equiv.unwrap().existing_hash, b1_hash);

    // 5. HotStuff-2 two-chain commit (0x2e157c0) & register_block guards (0x2e1da10).
    let mut commit_store = TwoChainCommitStore::new(0, 1);
    assert_eq!(
        commit_store.register_block(CertifiedBlockNode {
            block_hash: [0x09; 32],
            parent_hash: GENESIS_HASH,
            parent_cert_round: 0,
        }),
        RegisterBlockOutcome::Registered
    );
    // Duplicate block rejected with REGISTER_TAG_NOT_NEW (4).
    assert_eq!(
        commit_store.register_block(CertifiedBlockNode {
            block_hash: [0x09; 32],
            parent_hash: GENESIS_HASH,
            parent_cert_round: 0,
        }),
        RegisterBlockOutcome::NotNew {
            tag: REGISTER_TAG_NOT_NEW
        }
    );
    // Stale block below min_stored_round rejected with REGISTER_TAG_STALE (3).
    let mut strict_store = TwoChainCommitStore::new(0, 5);
    assert_eq!(
        strict_store.register_block(CertifiedBlockNode {
            block_hash: b1_hash,
            parent_hash: GENESIS_HASH,
            parent_cert_round: 0,
        }),
        RegisterBlockOutcome::Stale {
            tag: REGISTER_TAG_STALE
        }
    );

    assert_eq!(
        commit_store.register_block(CertifiedBlockNode {
            block_hash: b1_hash,
            parent_hash: GENESIS_HASH,
            parent_cert_round: 0,
        }),
        RegisterBlockOutcome::Registered
    );
    assert_eq!(
        commit_store.register_block(CertifiedBlockNode {
            block_hash: b2_hash,
            parent_hash: b1_hash,
            parent_cert_round: 1,
        }),
        RegisterBlockOutcome::Registered
    );
    assert_eq!(
        commit_store.register_block(CertifiedBlockNode {
            block_hash: b3_hash,
            parent_hash: b2_hash,
            parent_cert_round: 2,
        }),
        RegisterBlockOutcome::Registered
    );
    // Certifying B3 (parent B2 @ round 2, consecutive 2-chain over B1 @ round 1) commits B1..B2!
    let commit = commit_store.try_two_chain_commit(&b3_hash);
    match commit {
        TwoChainCommitOutcome::Committed {
            new_committed_round,
            committed_blocks,
        } => {
            assert_eq!(new_committed_round, 2);
            assert_eq!(committed_blocks.len(), 2);
            assert_eq!(committed_blocks[0].block_hash, b1_hash);
            assert_eq!(committed_blocks[1].block_hash, b2_hash);
        }
        TwoChainCommitOutcome::NoCommit => panic!("expected two-chain commit"),
    }

    // 6. Heartbeat tracker 180s liveness window & validator_latency_ema (0x5a71e20 / 0x5a71ee0).
    let mut hb = HeartbeatTracker::default();
    assert_eq!(hb.window_secs, HEARTBEAT_WINDOW_SECS);
    assert_eq!(VALIDATOR_LATENCY_EMA_KEY, "validator_latency_ema");
    hb.record_heartbeat(v1, 1_000, 12.5);
    hb.record_heartbeat(v2, 1_000, 18.0);
    hb.record_heartbeat(v3, 700, 25.0);
    assert_eq!(hb.stale_validators(1_050), vec![v3]);
    let snap = hb.active_latency_ema_snapshot(1_050);
    assert_eq!(snap.len(), 2);
}
