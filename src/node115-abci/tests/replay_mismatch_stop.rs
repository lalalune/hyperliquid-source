use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use node115_abci::checkpoint_replay_fixture::{ReplayBlock, ReplayEngineFixture, SupportContext};
use node115_abci::digest_reference_handoff::{Comparison, ReferenceRow};
use node115_abci::engine::{AbciEngine, ApplyBlockPipelineInput, ApplyBlockStage, EngineBlock};
use node115_abci::state::{AbciState, REQUIRED_FEATURE_VERSION, ReplayInitializer, RestoredState};

#[test]
fn both_replay_paths_keep_history_and_skip_successor_root_after_mismatch() {
    let restored = RestoredState {
        checkpoint_path: PathBuf::from("9999"),
        height: 9_999,
        round: 500,
        loader_seq: 5,
        copied_round: 500,
        replay_initializer: ReplayInitializer {
            initial_height: 9_999,
            initial_round: 500,
        },
    };
    let reference_rows = vec![
        ReferenceRow {
            height: 9_999,
            digest: [0xbb; 32],
            members: BTreeSet::from([[0x01; 20]]),
        },
        ReferenceRow {
            height: 9_998,
            digest: [0xcc; 32],
            members: BTreeSet::from([[0x02; 20]]),
        },
    ];
    let history = BTreeMap::from([(9_998, [0xcc; 32]), (9_999, [0xaa; 32])]);
    let support = SupportContext {
        weights_32: BTreeMap::new(),
        fraction_20: 0.0,
        eligible_20: BTreeSet::new(),
        stored_total_20: 0,
    };
    let registry = BTreeMap::new();
    let mut integrated = AbciEngine::new(AbciState::new(restored.clone(), 10_000, None));
    integrated.local_raw_history = history.clone();
    integrated.tracker.handoff.ready = reference_rows.clone();
    let block = EngineBlock {
        prev_round: 500,
        new_round: 501,
        expected_loader_seq: 5,
        expected_copied_round: 500,
        external_votes: Vec::new(),
        timer_eligible_heights: Vec::new(),
        synthetic_local_root: Some([0xdd; 32]),
    };
    let report = integrated
        .apply_block_pipeline(
            &ApplyBlockPipelineInput {
                block: &block,
                state_time: (5, 500),
                block_parent_time: (5, 500),
                header_actions: 0,
                payload_actions: 0,
                feature_version: REQUIRED_FEATURE_VERSION,
                prune_watermark: Some(9_999),
            },
            &support,
            &registry,
            0,
            |_| (),
            |_| (),
            |_| (),
            |_, _| panic!("selector ran after mismatch"),
        )
        .unwrap();
    assert_eq!(
        report.stages.last(),
        Some(&ApplyBlockStage::VerifyStateRoot)
    );
    assert_eq!(report.pruned_history_entries, 0);
    assert_eq!(report.engine_report.handoff.sink_pairs.len(), 2);
    assert_eq!(report.engine_report.handoff.comparisons.len(), 1);
    assert_eq!(
        report.engine_report.handoff.comparisons[0].comparison,
        Comparison::Mismatch
    );
    assert!(report.engine_report.local_root.is_none());
    assert_eq!(integrated.local_raw_history, history);

    let mut lower = ReplayEngineFixture::from_restored(restored, 10_000, None);
    lower.local_raw_history = history.clone();
    lower.tracker_handoff.ready = reference_rows;
    let report = lower
        .apply_block_with_history_pruning(
            &ReplayBlock {
                prev_round: 500,
                new_round: 501,
                expected_loader_seq: 5,
                expected_copied_round: 500,
                votes: Vec::new(),
                timer_eligible_heights: Vec::new(),
                synthetic_local_root: Some([0xdd; 32]),
            },
            &support,
            &registry,
            0,
            Some(9_999),
            |_, _| panic!("standalone selector ran after mismatch"),
        )
        .unwrap();
    assert_eq!(report.handoff.sink_pairs.len(), 2);
    assert_eq!(report.handoff.comparisons.len(), 1);
    assert_eq!(
        report.handoff.comparisons[0].comparison,
        Comparison::Mismatch
    );
    assert!(report.local_root_recorded.is_none());
    assert_eq!(lower.local_raw_history, history);
}
