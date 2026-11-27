use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use node115_abci::abci_hash::{
    ROOT_CAPTURE_SLOT_COUNT, ReductionNode, ReductionRow, blake3_hash, compute_reduction_tree_root,
    encode_reduction_tree,
};
use node115_abci::checkpoint_replay_fixture::{
    ACTION_TAG_ABCI_DIGEST_VOTE, ExternalDigestVote, SupportContext, restore_checkpoint,
};
use node115_abci::digest_reference_handoff::{Comparison, Registry};
use node115_abci::engine::{
    AbciEngine, EngineBlock, PRUNE_KEEP_EVM_CHECKPOINTS, TAR_COMPLETE_MARKER,
    build_daily_evm_tar_command, select_checkpoints_to_prune,
};
use node115_abci::hash_signature_tracker::{
    HashSignatureTracker, PRUNE_WINDOW_HEIGHTS, timer_is_mature,
};
use node115_abci::state::{AbciState, FreezeHeightError};

fn unique_tmp(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "node115-abci-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

fn sample_support_and_registry() -> (SupportContext, Registry, u64) {
    let v32_a = [0x11u8; 32];
    let v32_b = [0x22u8; 32];
    let v32_c = [0x33u8; 32];
    let v20_a = [0xa1u8; 20];
    let v20_b = [0xb2u8; 20];
    let v20_c = [0xc3u8; 20];
    let support = SupportContext {
        weights_32: BTreeMap::from([(v32_a, 40), (v32_b, 35), (v32_c, 25)]),
        fraction_20: 0.5,
        eligible_20: BTreeSet::from([v20_a, v20_b, v20_c]),
        stored_total_20: 3,
    };
    let registry = BTreeMap::from([(7u64, BTreeMap::from([(v32_a, v20_a), (v32_b, v20_b), (v32_c, v20_c)]))]);
    (support, registry, 7)
}

#[test]
fn reduction_tree_preimage_matches_re017_msgpack_vectors() {
    assert_eq!(ROOT_CAPTURE_SLOT_COUNT, 59);
    // Empty vector -> 0x90
    assert_eq!(encode_reduction_tree(&[]).unwrap(), vec![0x90]);

    // Single zero leaf at index 0 -> 91 92 00 d9 42 "0x" + 64*'0'
    let one = encode_reduction_tree(&[ReductionRow {
        index: 0,
        value: ReductionNode::Leaf([0u8; 32]),
    }])
    .unwrap();
    assert_eq!(&one[..7], &[0x91, 0x92, 0x00, 0xd9, 0x42, b'0', b'x']);
    assert_eq!(one.len(), 7 + 64);
    assert!(one[7..].iter().all(|&b| b == b'0'));

    // Sparse index 200 (0xcc 0xc8) and nested child
    let nested = encode_reduction_tree(&[ReductionRow {
        index: 200,
        value: ReductionNode::Nested(vec![ReductionRow {
            index: 1,
            value: ReductionNode::Leaf([0xab; 32]),
        }]),
    }])
    .unwrap();
    assert_eq!(&nested[..9], &[0x91, 0x92, 0xcc, 0xc8, 0x91, 0x92, 0x01, 0xd9, 0x42]);
    assert_eq!(&nested[9..13], b"0xab");
}

#[test]
fn tracker_watermark_seal_prune_window_and_recheck() {
    let (mut support, registry, reg_ctx) = sample_support_and_registry();
    let mut tracker = HashSignatureTracker::new();

    // First vote at height 100 (below quorum)
    let d100 = [0x10u8; 32];
    let r1 = tracker
        .record_vote(
            &ExternalDigestVote {
                action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                height: 100,
                digest: d100,
                voter_32: Some(([0x11; 32], true)),
                voter_20: Some(([0xa1; 20], true)),
            },
            &support,
            None,
        )
        .unwrap();
    assert!(!r1.selected_transition);

    // Recheck after raising v32_a weight to 70/100 and lowering fraction_20 to 0.25 promotes height 100!
    support.weights_32.insert([0x11; 32], 70);
    support.weights_32.insert([0x22; 32], 15);
    support.weights_32.insert([0x33; 32], 15);
    support.fraction_20 = 0.25;
    let promoted = tracker.recheck_candidates(&support);
    assert_eq!(promoted, vec![100]);
    assert_eq!(tracker.selected_digest(100), Some(d100));
    assert_eq!(tracker.max_watermark, 100);

    // Transition at height 60_000 sets seal_marker and prunes heights < 60_000 - 50_000 = 10_000!
    let h_high = 60_000u64;
    let d_high = [0x60u8; 32];
    let r2 = tracker
        .record_vote(
            &ExternalDigestVote {
                action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                height: h_high,
                digest: d_high,
                voter_32: Some(([0x11; 32], true)),
                voter_20: Some(([0xa1; 20], true)),
            },
            &support,
            Some(h_high),
        )
        .unwrap();
    assert!(r2.selected_transition);
    assert!(r2.sealed_now);
    assert!(tracker.seal_marker);
    assert_eq!(r2.prune_cutoff, Some(h_high - PRUNE_WINDOW_HEIGHTS));
    assert_eq!(tracker.selected_digest(100), None);
    assert_eq!(tracker.selected_digest(h_high), Some(d_high));

    let (rows, lines) = tracker.drain_eligible(&[h_high], &registry, reg_ctx);
    assert_eq!(rows.len(), 1);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("{\"height\":60000,\"d\":\"0x606060"));
    assert!(lines[0].ends_with("\"}\n"));
}

#[test]
fn engine_offline_replay_freeze_guard_and_checkpoint_maintenance() {
    let dir = unique_tmp("engine");
    let h = 9_999u64; // Next block is 10_000 (triggers % 10_000 == 0 root cadence!)
    let r = 500u64;
    fs::create_dir_all(dir.join(h.to_string())).unwrap();
    fs::write(dir.join(h.to_string()).join("CHECKPOINT_COMPLETE"), b"").unwrap();

    let restored = restore_checkpoint(&dir, h, h, r, 4).unwrap();
    let state = AbciState::new(restored, 0, None);
    assert_eq!(
        state.check_freeze_height(h - 1),
        Err(FreezeHeightError::FreezeHeightBelowCurrent {
            freeze_height: h - 1,
            current_height: h,
        })
    );
    assert!(state.check_freeze_height(h).is_ok());

    let (support, registry, reg_ctx) = sample_support_and_registry();
    let mut engine = AbciEngine::new(state);
    let root_10k = [0xfeu8; 32];

    // Block 1: height advances 9_999 -> 10_000, triggering default % 10_000 cadence.
    let rep1 = engine
        .apply_block(
            &EngineBlock {
                prev_round: r,
                new_round: r + 1,
                expected_loader_seq: 5,
                expected_copied_round: r,
                external_votes: vec![],
                timer_eligible_heights: vec![],
                synthetic_local_root: Some(root_10k),
            },
            &support,
            &registry,
            reg_ctx,
            |c, _| c.write_fallback(1u64 << 15, 0, 0),
        )
        .unwrap();
    assert_eq!(rep1.height, 10_000);
    assert_eq!(rep1.local_root.unwrap().1.selector_byte, 3);

    // Block 2: height 10_001 delivers external 0xdd votes for 10_000 -> quorum sink JSON + Equal!
    let rep2 = engine
        .apply_block(
            &EngineBlock {
                prev_round: r + 1,
                new_round: r + 2,
                expected_loader_seq: 5,
                expected_copied_round: r,
                external_votes: vec![
                    ExternalDigestVote {
                        action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                        height: 10_000,
                        digest: root_10k,
                        voter_32: Some(([0x11; 32], true)),
                        voter_20: Some(([0xa1; 20], true)),
                    },
                    ExternalDigestVote {
                        action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                        height: 10_000,
                        digest: root_10k,
                        voter_32: Some(([0x22; 32], true)),
                        voter_20: Some(([0xb2; 20], true)),
                    },
                ],
                timer_eligible_heights: vec![10_000],
                synthetic_local_root: None,
            },
            &support,
            &registry,
            reg_ctx,
            |_, _| 0,
        )
        .unwrap();
    assert_eq!(rep2.handoff.comparisons[0].comparison, Comparison::Equal);
    assert_eq!(rep2.quorum_sink_lines.len(), 1);
    assert_eq!(engine.quorum_sink_log.len(), 1);

    // EVM checkpoint prune (keep=100) and daily tar command (`TAR_COMPLETE` skip)
    let heights: Vec<u64> = (1..=105).collect();
    assert_eq!(
        select_checkpoints_to_prune(heights, PRUNE_KEEP_EVM_CHECKPOINTS),
        vec![1, 2, 3, 4, 5]
    );
    let tar_dir = dir.join("tar_out");
    fs::create_dir_all(&tar_dir).unwrap();
    let cmd = build_daily_evm_tar_command(&dir, "10000", &tar_dir.join("10000.tar"), &tar_dir);
    assert!(cmd.is_some());
    fs::write(tar_dir.join(TAR_COMPLETE_MARKER), b"").unwrap();
    assert!(
        build_daily_evm_tar_command(&dir, "10000", &tar_dir.join("10000.tar"), &tar_dir).is_none()
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn real_blake3_state_root_and_timer_maturity_end_to_end() {
    // Build a 59-slot reduction tree and compute its exact node #115 BLAKE3 state root!
    let rows: Vec<ReductionRow> = (0..ROOT_CAPTURE_SLOT_COUNT as u64)
        .map(|i| ReductionRow {
            index: i,
            value: ReductionNode::Leaf([i as u8; 32]),
        })
        .collect();
    let preimage = encode_reduction_tree(&rows).unwrap();
    let root = compute_reduction_tree_root(&rows).unwrap();
    assert_eq!(root, blake3_hash(&preimage));

    // Timer maturity boundary (`0x515218d..0x51522cd`): 10.5 seconds = 10_500_000_000 ns
    let t0 = 1_700_000_000_000_000_000u64;
    assert!(!timer_is_mature(t0, 10.5, t0 + 10_499_999_999));
    assert!(timer_is_mature(t0, 10.5, t0 + 10_500_000_000));
    assert!(!timer_is_mature(t0, f64::NAN, t0 + 99_999_999_999));
    assert!(!timer_is_mature(t0, -1.0, t0 + 99_999_999_999));
}
