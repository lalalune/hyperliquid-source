use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use node115_abci_checkpoint_replay_fixture::{
    BlockAdmissionError, HardforkWords, LocalRestoreError, ReplayBlock, ReplayEngineFixture,
    RestoreError, SupportContext, restore_local_checkpoint,
};

struct Checkpoints(PathBuf);

impl Checkpoints {
    fn with_complete_height(height: u64) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "node115-local-restore-{}-{nonce}",
            std::process::id()
        ));
        let candidate = root.join(height.to_string());
        fs::create_dir_all(&candidate).unwrap();
        fs::write(candidate.join("CHECKPOINT_COMPLETE"), b"").unwrap();
        Self(root)
    }
}

impl Drop for Checkpoints {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn preserves_disk_pair_without_an_exact_freeze() {
    let checkpoints = Checkpoints::with_complete_height(10_000);
    let disk = HardforkWords {
        version: 109,
        round: 41,
    };
    for schedule in [None, Some(10_001)] {
        let restored =
            restore_local_checkpoint(&checkpoints.0, 10_000, 10_000, 57, disk, schedule).unwrap();
        assert_eq!(restored.startup_pair, disk);
        assert_eq!(restored.state.loader_seq, 109);
        assert_eq!(restored.state.copied_round, 41);
        assert_eq!(restored.state.replay_initializer.initial_height, 10_000);
        assert_eq!(restored.state.replay_initializer.initial_round, 57);
    }
}

#[test]
fn first_replay_reads_the_rewritten_pair_with_saturation() {
    let checkpoints = Checkpoints::with_complete_height(10_000);
    for (version, rewritten) in [(109, 110), (u64::MAX, u64::MAX)] {
        let disk = HardforkWords { version, round: 41 };
        let restored =
            restore_local_checkpoint(&checkpoints.0, 10_000, 10_000, 57, disk, Some(10_000))
                .unwrap();
        assert_eq!(restored.startup_pair, disk);
        assert_eq!(restored.state.loader_seq, rewritten);
        assert_eq!(restored.state.copied_round, 57);
        let mut engine = ReplayEngineFixture::from_restored(restored.state, 1_000, None);
        let support = SupportContext {
            weights_32: BTreeMap::new(),
            fraction_20: 0.0,
            eligible_20: Default::default(),
            stored_total_20: 0,
        };
        let registry = BTreeMap::new();
        let mut block = ReplayBlock {
            prev_round: 57,
            new_round: 58,
            expected_loader_seq: rewritten,
            expected_copied_round: disk.round,
            votes: vec![],
            timer_eligible_heights: vec![],
            synthetic_local_root: None,
        };
        assert!(matches!(
            engine.apply_block(&block, &support, &registry, 0, |_, _| 0),
            Err(BlockAdmissionError::CopiedRoundMismatch { .. }),
        ));
        block.expected_copied_round = 57;
        let result = engine
            .apply_block(&block, &support, &registry, 0, |_, _| 0)
            .unwrap();
        assert_eq!(result.post_height, 10_001);
        assert_eq!(result.post_round, 58);
    }
}

#[test]
fn rejects_past_freeze_and_mismatched_checkpoint_height() {
    let checkpoints = Checkpoints::with_complete_height(10_000);
    let disk = HardforkWords {
        version: 109,
        round: 41,
    };
    assert_eq!(
        restore_local_checkpoint(&checkpoints.0, 10_000, 10_000, 57, disk, Some(9_999)),
        Err(LocalRestoreError::PastFreeze {
            target: 9_999,
            height: 10_000
        }),
    );
    assert_eq!(
        restore_local_checkpoint(&checkpoints.0, 10_000, 10_001, 57, disk, None),
        Err(LocalRestoreError::Checkpoint(
            RestoreError::HeightMismatch {
                requested: 10_000,
                persisted: 10_001,
            }
        )),
    );
}
