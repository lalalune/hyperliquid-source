use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use node115_abci::checkpoint_replay_fixture::SupportContext;
use node115_abci::engine::{AbciEngine, EngineBlock};
use node115_abci::state::{AbciState, PostRestoreImageError, ReplayInitializer, RestoreError};

#[test]
fn pinned_post_restore_image_supplies_first_replay_state_without_rewriting_the_pair() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hl-node-restore-{}-{nanos}", std::process::id()));
    let checkpoint = dir.join("10000");
    fs::create_dir_all(&checkpoint).unwrap();
    let mut source = vec![0xa5; 0x42c8];
    for (offset, word) in [
        (0x18, 115_u64),
        (0x20, 41),
        (0x28, 10_000),
        (0x30, 93),
        (0x10f0, 11_000),
        (0x39c8, 73),
    ] {
        source[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
    }
    source[0x10e8..0x10ec].copy_from_slice(&1_u32.to_le_bytes());

    assert_eq!(
        AbciState::from_post_restore_image(&dir, 10_000, &source),
        Err(PostRestoreImageError::Checkpoint(
            RestoreError::CheckpointNotFound {
                requested_height: 10_000,
            }
        )),
    );
    fs::write(checkpoint.join("CHECKPOINT_COMPLETE"), b"").unwrap();
    let image_path = checkpoint.join("compact-state.bin");
    fs::write(&image_path, &source).unwrap();
    let image = fs::read(&image_path).unwrap();
    let state = AbciState::from_post_restore_image(&dir, 10_000, &image).unwrap();
    assert_eq!(state.inner.checkpoint_path, checkpoint);
    assert_eq!(
        state.inner.replay_initializer,
        ReplayInitializer {
            initial_height: 10_000,
            initial_round: 93,
        }
    );
    assert_eq!(state.hardfork_height, Some(11_000));

    assert_eq!(
        AbciState::from_post_restore_image(&dir, 10_001, &image),
        Err(PostRestoreImageError::Checkpoint(
            RestoreError::HeightMismatch {
                requested: 10_001,
                persisted: 10_000,
            }
        )),
    );
    assert_eq!(
        AbciState::from_post_restore_image(&dir, 10_000, &image[..8]),
        Err(PostRestoreImageError::WrongSize { actual: 8 }),
    );

    let mut invalid_tag_image = image.clone();
    invalid_tag_image[0x10e8..0x10ec].copy_from_slice(&2_u32.to_le_bytes());
    assert_eq!(
        AbciState::from_post_restore_image(&dir, 10_000, &invalid_tag_image),
        Err(PostRestoreImageError::InvalidFreezeTag { tag: 2 }),
    );

    let mut engine = AbciEngine::new(state);
    let support = SupportContext {
        weights_32: BTreeMap::new(),
        fraction_20: 0.0,
        eligible_20: BTreeSet::new(),
        stored_total_20: 0,
    };
    let block = EngineBlock {
        prev_round: 93,
        new_round: 94,
        expected_loader_seq: 115,
        expected_copied_round: 41,
        external_votes: Vec::new(),
        timer_eligible_heights: Vec::new(),
        synthetic_local_root: Some([0x82; 32]),
    };
    let report = engine
        .apply_block(&block, &support, &BTreeMap::new(), 0, |cell, _| {
            cell.write_fallback(1u64 << 15, 0, 0)
        })
        .unwrap();
    assert_eq!((report.height, report.round), (10_001, 94));
    assert_eq!(engine.local_raw_history[&10_001], [0x82; 32]);
    assert_eq!(fs::read(image_path).unwrap(), source);
    fs::remove_dir_all(dir).unwrap();
}
