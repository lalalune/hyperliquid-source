use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use node115_abci_checkpoint_replay_fixture::{
    ACTION_TAG_ABCI_DIGEST_VOTE, BlockAdmissionError, ExternalDigestVote, ReplayBlock,
    ReplayEngineFixture, RestoreError, RootProvenance, RootSelectorCell, SupportContext,
    VOTE_HEIGHT_EXCLUSIVE_LIMIT, VoteStepOutcome, restore_checkpoint, select_root_impl,
};
use node115_digest_reference_handoff::{Comparison, Registry};
use node115_digest_vote_admission::Admission;

fn temp_checkpoint_dir(tag: &str, height: u64, complete: bool) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "node115-qcp-fixture-{tag}-{}-{nanos}",
        std::process::id()
    ));
    let ckpt = root.join(height.to_string());
    fs::create_dir_all(&ckpt).unwrap();
    if complete {
        fs::write(ckpt.join("CHECKPOINT_COMPLETE"), b"").unwrap();
    }
    root
}

fn sample_support_and_registry() -> (SupportContext, Registry, u64) {
    let v32_a = [0x11u8; 32];
    let v32_b = [0x22u8; 32];
    let v32_c = [0x33u8; 32];
    let v20_a = [0xa1u8; 20];
    let v20_b = [0xb2u8; 20];
    let v20_c = [0xc3u8; 20];

    let weights_32 = BTreeMap::from([(v32_a, 40), (v32_b, 35), (v32_c, 25)]);
    let eligible_20 = BTreeSet::from([v20_a, v20_b, v20_c]);
    let support = SupportContext {
        weights_32,
        fraction_20: 0.5,
        eligible_20,
        stored_total_20: 3,
    };

    let ctx_id = 7u64;
    let reg_map = BTreeMap::from([(v32_a, v20_a), (v32_b, v20_b), (v32_c, v20_c)]);
    let registry = BTreeMap::from([(ctx_id, reg_map)]);
    (support, registry, ctx_id)
}

#[test]
fn end_to_end_restore_h_plus_1_and_external_quorum_match() {
    let h = 1_000_000u64;
    let r = 1_000_050u64;
    let seq = 9u64;
    let dir = temp_checkpoint_dir("e2e-match", h, true);
    let restored = restore_checkpoint(&dir, h, h, r, seq).unwrap();
    assert_eq!(restored.height, h);
    assert_eq!(restored.round, r);
    assert_eq!(restored.loader_seq, seq + 1);
    assert_eq!(restored.copied_round, r);
    assert_eq!(restored.replay_initializer.initial_height, h);
    assert_eq!(restored.replay_initializer.initial_round, r);

    let (support, registry, reg_ctx) = sample_support_and_registry();
    let mut engine = ReplayEngineFixture::from_restored(restored, 1, None);
    let root_h1 = [0x5au8; 32];

    // Block 1: restores H -> H+1 = 1_000_001, produces local root AFTER comparison.
    let block1 = ReplayBlock {
        prev_round: r,
        new_round: r + 1,
        expected_loader_seq: seq + 1,
        expected_copied_round: r,
        votes: vec![],
        timer_eligible_heights: vec![],
        synthetic_local_root: Some(root_h1),
    };
    let rep1 = engine
        .apply_block(&block1, &support, &registry, reg_ctx, |cell, _| {
            // Bit 19 and bit 25 set -> selector byte 4.
            let word = (1u64 << 19) | (1u64 << 25);
            cell.write_fallback(word, 0, 0)
        })
        .unwrap();
    assert_eq!(rep1.post_height, h + 1);
    assert_eq!(rep1.post_round, r + 1);
    assert!(rep1.handoff.sink_pairs.is_empty());
    let (local_prov, sel_trace) = rep1.local_root_recorded.unwrap();
    assert_eq!(sel_trace.selector_byte, 4);
    assert_eq!(sel_trace.fallback_invocations, 1);
    assert_eq!(
        local_prov,
        RootProvenance::LocalPostComparison {
            height: h + 1,
            selector_byte: 4,
            digest: root_h1,
        }
    );
    assert_eq!(engine.local_raw_history.get(&(h + 1)), Some(&root_h1));

    // Block 2: external 0xdd votes for H+1 arrive; first vote is below quorum (40/100, 1/3),
    // second vote crosses BOTH gates (75/100 > 2/3 AND 2 > 0.5*3), drains, and matches ctx+0x400[H+1]!
    let block2 = ReplayBlock {
        prev_round: r + 1,
        new_round: r + 2,
        expected_loader_seq: seq + 1,
        expected_copied_round: r,
        votes: vec![
            ExternalDigestVote {
                action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                height: h + 1,
                digest: root_h1,
                voter_32: Some(([0x11; 32], true)),
                voter_20: Some(([0xa1; 20], true)),
            },
            ExternalDigestVote {
                action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                height: h + 1,
                digest: root_h1,
                voter_32: Some(([0x22; 32], true)),
                voter_20: Some(([0xb2; 20], true)),
            },
        ],
        timer_eligible_heights: vec![h + 1],
        synthetic_local_root: None,
    };
    let rep2 = engine
        .apply_block(&block2, &support, &registry, reg_ctx, |_, _| {
            panic!("cell already populated")
        })
        .unwrap();
    assert_eq!(rep2.post_height, h + 2);
    assert_eq!(
        rep2.vote_outcomes[0],
        VoteStepOutcome::Processed {
            admissions: vec![
                Admission::AdmitNew { count: 0 },
                Admission::ExistingCandidate,
            ],
            selected_transition: false,
        }
    );
    assert_eq!(
        rep2.vote_outcomes[1],
        VoteStepOutcome::Processed {
            admissions: vec![Admission::ExistingCandidate, Admission::ExistingCandidate],
            selected_transition: true,
        }
    );
    assert_eq!(rep2.drained_provenance.len(), 1);
    assert_eq!(
        rep2.drained_provenance[0],
        RootProvenance::ExternalDigestVoteQuorum {
            action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
            height: h + 1,
            digest: root_h1,
            resolved_members: BTreeSet::from([[0xa1; 20], [0xb2; 20]]),
        }
    );
    assert_eq!(rep2.handoff.sink_pairs, vec![(h + 1, root_h1)]);
    assert_eq!(rep2.handoff.comparisons.len(), 1);
    assert_eq!(rep2.handoff.comparisons[0].comparison, Comparison::Equal);
    assert_eq!(rep2.handoff.comparisons[0].local, Some(root_h1));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn single_byte_mismatch_preserves_sink_before_comparison_and_stops_prefix() {
    let h = 2_000_000u64;
    let r = 2_000_010u64;
    let dir = temp_checkpoint_dir("mismatch", h, true);
    let restored = restore_checkpoint(&dir, h, h, r, 1).unwrap();
    let (support, registry, reg_ctx) = sample_support_and_registry();
    let mut engine = ReplayEngineFixture::from_restored(restored, 1, None);

    let local_h1 = [0x44u8; 32];
    let mut wrong_expected_h1 = local_h1;
    wrong_expected_h1[31] ^= 0x01;
    let local_h2 = [0x88u8; 32];

    // Produce local roots for H+1 and H+2.
    engine
        .apply_block(
            &ReplayBlock {
                prev_round: r,
                new_round: r + 1,
                expected_loader_seq: 2,
                expected_copied_round: r,
                votes: vec![],
                timer_eligible_heights: vec![],
                synthetic_local_root: Some(local_h1),
            },
            &support,
            &registry,
            reg_ctx,
            |c, _| c.write_fallback(1u64 << 15, 0, 0),
        )
        .unwrap();
    engine
        .apply_block(
            &ReplayBlock {
                prev_round: r + 1,
                new_round: r + 2,
                expected_loader_seq: 2,
                expected_copied_round: r,
                votes: vec![],
                timer_eligible_heights: vec![],
                synthetic_local_root: Some(local_h2),
            },
            &support,
            &registry,
            reg_ctx,
            |_, _| 0,
        )
        .unwrap();

    // Block 3 drains TWO heights: H+1 (mismatching) and H+2 (matching).
    // Native contract: BOTH reach the +0x280 sink first; comparison stops at H+1 mismatch!
    let rep3 = engine
        .apply_block(
            &ReplayBlock {
                prev_round: r + 2,
                new_round: r + 3,
                expected_loader_seq: 2,
                expected_copied_round: r,
                votes: vec![
                    ExternalDigestVote {
                        action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                        height: h + 1,
                        digest: wrong_expected_h1,
                        voter_32: Some(([0x11; 32], true)),
                        voter_20: Some(([0xa1; 20], true)),
                    },
                    ExternalDigestVote {
                        action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                        height: h + 1,
                        digest: wrong_expected_h1,
                        voter_32: Some(([0x22; 32], true)),
                        voter_20: Some(([0xb2; 20], true)),
                    },
                    ExternalDigestVote {
                        action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                        height: h + 2,
                        digest: local_h2,
                        voter_32: Some(([0x11; 32], true)),
                        voter_20: Some(([0xa1; 20], true)),
                    },
                    ExternalDigestVote {
                        action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                        height: h + 2,
                        digest: local_h2,
                        voter_32: Some(([0x22; 32], true)),
                        voter_20: Some(([0xb2; 20], true)),
                    },
                ],
                timer_eligible_heights: vec![h + 1, h + 2],
                synthetic_local_root: None,
            },
            &support,
            &registry,
            reg_ctx,
            |_, _| 0,
        )
        .unwrap();

    assert_eq!(
        rep3.handoff.sink_pairs,
        vec![(h + 1, wrong_expected_h1), (h + 2, local_h2)]
    );
    assert_eq!(rep3.handoff.comparisons.len(), 1);
    assert_eq!(rep3.handoff.comparisons[0].height, h + 1);
    assert_eq!(rep3.handoff.comparisons[0].comparison, Comparison::Mismatch);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn comparison_runs_before_end_root_selector_so_same_block_local_root_is_missing() {
    let h = 3_000_000u64;
    let r = 3_000_000u64;
    let dir = temp_checkpoint_dir("same-block-order", h, true);
    let restored = restore_checkpoint(&dir, h, h, r, 0).unwrap();
    let (support, registry, reg_ctx) = sample_support_and_registry();
    let mut engine = ReplayEngineFixture::from_restored(restored, 1, None);
    let root_h1 = [0x99u8; 32];

    let rep = engine
        .apply_block(
            &ReplayBlock {
                prev_round: r,
                new_round: r + 1,
                expected_loader_seq: 1,
                expected_copied_round: r,
                votes: vec![
                    ExternalDigestVote {
                        action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                        height: h + 1,
                        digest: root_h1,
                        voter_32: Some(([0x11; 32], true)),
                        voter_20: Some(([0xa1; 20], true)),
                    },
                    ExternalDigestVote {
                        action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                        height: h + 1,
                        digest: root_h1,
                        voter_32: Some(([0x22; 32], true)),
                        voter_20: Some(([0xb2; 20], true)),
                    },
                ],
                timer_eligible_heights: vec![h + 1],
                synthetic_local_root: Some(root_h1),
            },
            &support,
            &registry,
            reg_ctx,
            |c, _| c.write_fallback(0, 1u64 << 10, 0),
        )
        .unwrap();

    // Comparison ran BEFORE `0x5a07ec0` wrote `ctx+0x400[H+1]`, so it saw MissingLocal,
    // even though `local_raw_history` now contains `H+1` after the block ends!
    assert_eq!(rep.handoff.comparisons.len(), 1);
    assert_eq!(
        rep.handoff.comparisons[0].comparison,
        Comparison::MissingLocal
    );
    assert_eq!(engine.local_raw_history.get(&(h + 1)), Some(&root_h1));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn root_selector_all_four_arms_fallback_word_distinction_and_repeated_reads() {
    // 1. All 4 stable outputs: 1, 2, 3, 4
    let cases = [
        (0u64, 1u8),
        (1u64 << 10, 2u8),
        (1u64 << 15, 3u8),
        ((1u64 << 19) | (1u64 << 25), 4u8),
        // bit 19 set without bit 25 falls through to bit 15 / bit 10!
        ((1u64 << 19) | (1u64 << 15), 3u8),
        ((1u64 << 19) | (1u64 << 10), 2u8),
    ];
    for (word, expected_sel) in cases {
        let mut cell = RootSelectorCell::default();
        let trace = select_root_impl(&mut cell, |c, _| c.words[0], |c, _| {
            c.write_fallback(word, 0, 0)
        });
        assert_eq!(trace.selector_byte, expected_sel, "word=0x{word:x}");
    }

    // 2. Fallback return value (r13) differs from stored words[0] (r13 | rdi)!
    let mut cell = RootSelectorCell::default();
    let ret = cell.write_fallback(1u64 << 19, 1u64 << 25, 0xdead);
    assert_eq!(ret, 1u64 << 19);
    assert_eq!(cell.words[0], (1u64 << 19) | (1u64 << 25));
    assert_eq!(cell.words[1], 0xdead | (1u64 << 19));
    assert_eq!(cell.words[2], 0xdead | (1u64 << 25));

    // 3. Repeated-read sensitivity: w0 has bit 19, w1 lacks bit 25, w2 lacks bit 15, w3 has bit 10 -> 2!
    let mut cell2 = RootSelectorCell { words: [1, 0, 0] };
    let seq_words = [1u64 << 19, 0, 0, 1u64 << 10];
    let trace = select_root_impl(
        &mut cell2,
        |_, stage| seq_words[stage],
        |_, _| 0,
    );
    assert_eq!(trace.effective_reads, vec![1u64 << 19, 0, 0, 1u64 << 10]);
    assert_eq!(trace.fallback_invocations, 2);
    assert_eq!(trace.selector_byte, 2);
}

#[test]
fn negative_controls_restore_admission_height_limit_and_conflict() {
    let dir = temp_checkpoint_dir("neg-controls", 500, false);
    // Incomplete checkpoint (no CHECKPOINT_COMPLETE) is rejected by discovery.
    assert_eq!(
        restore_checkpoint(&dir, 500, 500, 10, 0),
        Err(RestoreError::CheckpointNotFound {
            requested_height: 500
        })
    );
    fs::write(dir.join("500").join("CHECKPOINT_COMPLETE"), b"").unwrap();
    assert_eq!(
        restore_checkpoint(&dir, 500, 501, 10, 0),
        Err(RestoreError::HeightMismatch {
            requested: 500,
            persisted: 501
        })
    );

    let restored = restore_checkpoint(&dir, 500, 500, 10, 0).unwrap();
    let (support, registry, reg_ctx) = sample_support_and_registry();
    let mut engine = ReplayEngineFixture::from_restored(restored, 1, None);

    // Non-advancing round rejected (`0x5a04eea`).
    let bad_round = ReplayBlock {
        prev_round: 10,
        new_round: 10,
        expected_loader_seq: 1,
        expected_copied_round: 10,
        votes: vec![],
        timer_eligible_heights: vec![],
        synthetic_local_root: None,
    };
    assert_eq!(
        engine.apply_block(&bad_round, &support, &registry, reg_ctx, |_, _| 0),
        Err(BlockAdmissionError::NonAdvancingRound {
            prev_round: 10,
            new_round: 10
        })
    );

    // Vote at height == 0xccccccccccccccc is rejected by height bound (`0x58694f9..0x5869506`).
    let rep = engine
        .apply_block(
            &ReplayBlock {
                prev_round: 10,
                new_round: 11,
                expected_loader_seq: 1,
                expected_copied_round: 10,
                votes: vec![ExternalDigestVote {
                    action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                    height: VOTE_HEIGHT_EXCLUSIVE_LIMIT,
                    digest: [0xaa; 32],
                    voter_32: Some(([0x11; 32], true)),
                    voter_20: Some(([0xa1; 20], true)),
                }],
                timer_eligible_heights: vec![],
                synthetic_local_root: None,
            },
            &support,
            &registry,
            reg_ctx,
            |_, _| 0,
        )
        .unwrap();
    assert_eq!(
        rep.vote_outcomes,
        vec![VoteStepOutcome::HeightAtOrAboveLimit {
            height: VOTE_HEIGHT_EXCLUSIVE_LIMIT
        }]
    );

    let _ = fs::remove_dir_all(&dir);
}
