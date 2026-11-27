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

#[test]
fn tracker_wire_schema_checkpoint_format_and_straggler_filter() {
    use node115_abci::engine::{
        EvmCheckpointFilterOutcome, MARKED_FOR_DELETION_MARKER, classify_evm_checkpoint_entry,
        daily_evm_checkpoint_tar_path,
    };
    use node115_abci::hash_signature_tracker::{
        HASH_SIGNATURE_TRACKER_WIRE_FIELDS, PENDING_CUTOFF_WINDOW, QRS_ENTRY_SIZE_BYTES,
        QuorumStatus,
    };
    use node115_abci::state::{
        CHECKPOINT_JSON_INDENT, CHECKPOINT_JSON_INITIAL_CAPACITY, CheckpointFormat,
        classify_checkpoint_path,
    };
    use std::path::Path;

    assert_eq!(
        HASH_SIGNATURE_TRACKER_WIRE_FIELDS,
        ["tracker", "qrs", "highest_quorum_height", "htm", "adu", "h"]
    );
    assert_eq!(QRS_ENTRY_SIZE_BYTES, 0x68);
    assert_eq!(QuorumStatus::NoQuorum.wire_tag(), "N");
    assert_eq!(QuorumStatus::Quorum([0xaa; 32]).wire_tag(), "Q");

    let mut tracker = HashSignatureTracker::new();
    tracker.pending_heights.insert(500);
    tracker.pending_heights.insert(1_500);
    assert_eq!(tracker.quorum_status(500), QuorumStatus::NoQuorum);
    assert_eq!(tracker.prune_pending_window(2_000), 2_000 - PENDING_CUTOFF_WINDOW);
    assert!(!tracker.pending_heights.contains(&500));
    assert!(tracker.pending_heights.contains(&1_500));

    // Checkpoint path dispatch (`0x26a2c80`)
    assert_eq!(
        classify_checkpoint_path(Path::new("/dev/null")),
        CheckpointFormat::SkipDevNull
    );
    assert_eq!(
        classify_checkpoint_path(Path::new("/var/hl/abci_state.rmp")),
        CheckpointFormat::MessagePackRmp
    );
    assert_eq!(
        classify_checkpoint_path(Path::new("/var/hl/abci_state.json")),
        CheckpointFormat::PrettyJson
    );
    assert_eq!(
        classify_checkpoint_path(Path::new("..")),
        CheckpointFormat::PrettyJson
    );
    assert_eq!(CHECKPOINT_JSON_INITIAL_CAPACITY, 0x80);
    assert_eq!(CHECKPOINT_JSON_INDENT, "  ");

    // Daily archive path (`0x38c4478`)
    assert_eq!(
        daily_evm_checkpoint_tar_path(Path::new("/home/hl"), "20260401", "evm", "10000"),
        Path::new("/home/hl/data/daily_evm_checkpoints/20260401/evm_10000.tar")
    );

    // Straggler filter (`0x3d5dca0`)
    let dir = unique_tmp("straggler");
    let marked = dir.join("100");
    let clean = dir.join("200");
    fs::create_dir_all(&marked).unwrap();
    fs::create_dir_all(&clean).unwrap();
    fs::write(marked.join(MARKED_FOR_DELETION_MARKER), b"").unwrap();

    assert_eq!(
        classify_evm_checkpoint_entry(&marked, 100, 150, 300, 250),
        EvmCheckpointFilterOutcome::SkippedMarkedForDeletion
    );
    assert_eq!(
        classify_evm_checkpoint_entry(&clean, 100, 150, 300, 250),
        EvmCheckpointFilterOutcome::DroppedStraggler
    );
    assert_eq!(
        classify_evm_checkpoint_entry(&clean, 200, 150, 300, 250),
        EvmCheckpointFilterOutcome::Retained
    );
    assert_eq!(
        classify_evm_checkpoint_entry(&clean, 251, 150, 300, 250),
        EvmCheckpointFilterOutcome::DroppedOutOfWindow
    );
    assert_eq!(
        classify_evm_checkpoint_entry(&clean, 300, 150, 300, 400),
        EvmCheckpointFilterOutcome::DroppedOutOfWindow
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn apply_block_six_ordered_guards_and_history_split_off_cutoff() {
    use node115_abci::state::{ApplyBlockPreconditionError, REQUIRED_FEATURE_VERSION};

    let dir = unique_tmp("guards");
    fs::create_dir_all(dir.join("100")).unwrap();
    fs::write(dir.join("100").join("CHECKPOINT_COMPLETE"), b"").unwrap();
    let restored = restore_checkpoint(&dir, 100, 100, 50, 1).unwrap();
    let _ = fs::remove_dir_all(&dir);

    // 1. Frozen state (hardfork_height == current_height)
    let frozen = AbciState::new(restored.clone(), 0, Some(100));
    assert!(frozen.is_frozen());
    assert_eq!(
        frozen.validate_apply_preconditions(50, 51, (1, 2), (1, 2), 4, 4, REQUIRED_FEATURE_VERSION),
        Err(ApplyBlockPreconditionError::StateFrozen { height: 100 })
    );

    // 2. Hardfork height below current height
    let past_hf = AbciState::new(restored.clone(), 0, Some(99));
    assert_eq!(
        past_hf.validate_apply_preconditions(50, 51, (1, 2), (1, 2), 4, 4, REQUIRED_FEATURE_VERSION),
        Err(ApplyBlockPreconditionError::HardforkHeightBelowCurrent {
            hardfork_height: 99,
            current_height: 100,
        })
    );

    // 3..6. Ordered round, parent_round, parent_time, action_count, feature_version guards
    let active = AbciState::new(restored, 0, Some(200));
    assert!(!active.is_frozen());
    assert_eq!(
        active.validate_apply_preconditions(50, 50, (1, 2), (1, 2), 4, 4, 3),
        Err(ApplyBlockPreconditionError::NonAdvancingRound {
            parent_round: 50,
            round: 50,
        })
    );
    assert_eq!(
        active.validate_apply_preconditions(49, 51, (1, 2), (1, 2), 4, 4, 3),
        Err(ApplyBlockPreconditionError::ParentRoundMismatch {
            state_round: 50,
            block_parent_round: 49,
        })
    );
    assert_eq!(
        active.validate_apply_preconditions(50, 51, (1, 2), (1, 3), 4, 4, 3),
        Err(ApplyBlockPreconditionError::ParentTimeMismatch {
            state_time: (1, 2),
            block_parent_time: (1, 3),
        })
    );
    assert_eq!(
        active.validate_apply_preconditions(50, 51, (1, 2), (1, 2), 4, 5, 3),
        Err(ApplyBlockPreconditionError::ActionCountMismatch {
            header_actions: 4,
            payload_actions: 5,
        })
    );
    assert_eq!(
        active.validate_apply_preconditions(50, 51, (1, 2), (1, 2), 4, 4, 2),
        Err(ApplyBlockPreconditionError::FeatureVersionMismatch {
            expected: 3,
            actual: 2,
        })
    );
    assert!(active.validate_apply_preconditions(50, 51, (1, 2), (1, 2), 4, 4, 3).is_ok());

    // Local raw-root history split_off(&(watermark.saturating_add(1))) (`0x5a05ea1..0x5a05fbd`)
    let mut engine = AbciEngine::new(active);
    engine.local_raw_history.insert(100, [0x10; 32]);
    engine.local_raw_history.insert(200, [0x20; 32]);
    engine.local_raw_history.insert(201, [0x21; 32]);
    assert_eq!(engine.prune_local_history_through(200), 2);
    assert_eq!(engine.local_raw_history.len(), 1);
    assert!(engine.local_raw_history.contains_key(&201));
}

#[test]
fn lthash_big_endian_homomorphic_arithmetic_and_hardfork_version_check() {
    use node115_abci::lt_hash::{
        LT_HASH_BYTES, LT_HASH_LANES, LT_HASH_REBUILD_BATCH_SIZE, LT_HASH_WIRE_FIELDS,
        LT_HASHES_WIRE_FIELDS, LtHash, LtHashes,
    };
    use node115_abci::state::{HardforkVersionError, validate_hardfork_version};

    assert_eq!(LT_HASH_BYTES, 2048);
    assert_eq!(LT_HASH_LANES, 1024);
    assert_eq!(LT_HASH_REBUILD_BATCH_SIZE, 1_000_000);
    assert_eq!(LT_HASH_WIRE_FIELDS, ["n_elements", "n_bytes", "hash"]);
    assert_eq!(
        LT_HASHES_WIRE_FIELDS,
        ["accounts_hash", "contracts_hash", "storage_hash"]
    );

    // Big-endian u16 lane wraparound (`0x3c289d0` / `0x3c27b10`):
    // BE 0x00ff + 0x0001 == 0x0100 ([0x01, 0x00]), NOT LE ([0x00, 0x00] or [0x01, 0x00])!
    let mut acc = [0u8; LT_HASH_BYTES];
    let mut delta = [0u8; LT_HASH_BYTES];
    acc[0] = 0x00;
    acc[1] = 0xff;
    delta[0] = 0x00;
    delta[1] = 0x01;
    LtHash::add_be_u16_lanes(&mut acc, &delta);
    assert_eq!((acc[0], acc[1]), (0x01, 0x00));
    LtHash::sub_be_u16_lanes(&mut acc, &delta);
    assert_eq!((acc[0], acc[1]), (0x00, 0xff));

    // Commutativity and exact invertibility of BLAKE3-XOF homomorphic mix_in / mix_out / replace
    let mut a = LtHash::new();
    let mut b = LtHash::new();
    a.mix_in(b"acct:alice:100");
    a.mix_in(b"acct:bob:200");
    b.mix_in(b"acct:bob:200");
    b.mix_in(b"acct:alice:100");
    assert_eq!(a, b);
    assert_eq!(a.n_elements, 2);
    assert_eq!(a.n_bytes, 26);
    assert_eq!(a.checksum(), blake3_hash(&a.hash));

    // In-place update matches direct construction
    a.replace(Some(b"acct:alice:100"), b"acct:alice:150");
    let mut direct = LtHash::new();
    direct.mix_in(b"acct:bob:200");
    direct.mix_in(b"acct:alice:150");
    assert_eq!(a, direct);

    // Full removal returns to zero identity
    a.mix_out(b"acct:bob:200");
    a.mix_out(b"acct:alice:150");
    assert_eq!(a, LtHash::new());

    // LtHashes triple checksums
    let mut hashes = LtHashes::new();
    hashes.accounts_hash.mix_in(b"acct0");
    hashes.contracts_hash.mix_in(b"code0");
    hashes.storage_hash.mix_in(b"slot0");
    let (c_acc, c_con, c_sto) = hashes.checksums();
    assert_ne!(c_acc, c_con);
    assert_ne!(c_con, c_sto);

    // Hardfork version validation (`0x595aff0..0x595b1a0`)
    assert!(validate_hardfork_version(115, 115).is_ok());
    assert_eq!(
        validate_hardfork_version(116, 115),
        Err(HardforkVersionError {
            state_version: 116,
            expected_version: 115,
        })
    );
}
