use std::collections::BTreeMap;

use node115_abci::checkpoint_replay_fixture::{ReplayInitializer, RestoredState, SupportContext};
use node115_abci::engine::{AbciEngine, ApplyBlockPipelineInput, EngineBlock};
use node115_abci::state::{AbciState, REQUIRED_FEATURE_VERSION};

const HEIGHT: u64 = 9_999;
const NEW_ROOT: [u8; 32] = [0x72; 32];

fn fixture() -> (AbciEngine, EngineBlock, SupportContext) {
    let state = RestoredState {
        checkpoint_path: "fixture/checkpoint/9999".into(),
        height: HEIGHT,
        round: 500,
        loader_seq: 5,
        copied_round: 500,
        replay_initializer: ReplayInitializer {
            initial_height: HEIGHT,
            initial_round: 500,
        },
    };
    let mut engine = AbciEngine::new(AbciState::new(state, 0, None));
    engine.local_raw_history = BTreeMap::from([(HEIGHT, [0x31; 32]), (u64::MAX, [0x63; 32])]);

    let block = EngineBlock {
        prev_round: 500,
        new_round: 501,
        expected_loader_seq: 5,
        expected_copied_round: 500,
        external_votes: vec![],
        timer_eligible_heights: vec![],
        synthetic_local_root: Some(NEW_ROOT),
    };
    let support = SupportContext {
        weights_32: BTreeMap::new(),
        fraction_20: 0.0,
        eligible_20: Default::default(),
        stored_total_20: 0,
    };
    (engine, block, support)
}

#[test]
fn pipeline_prunes_old_history_before_recording_the_eligible_successor_root() {
    let (mut engine, block, support) = fixture();
    let input = ApplyBlockPipelineInput {
        block: &block,
        state_time: (5, 500),
        block_parent_time: (5, 500),
        header_actions: 0,
        payload_actions: 0,
        feature_version: REQUIRED_FEATURE_VERSION,
        prune_watermark: Some(HEIGHT + 1),
    };
    let report = engine
        .apply_block_pipeline(
            &input,
            &support,
            &BTreeMap::new(),
            0,
            |_| {},
            |_| {},
            |_| {},
            |_, _| 0,
        )
        .unwrap();

    assert!(report.engine_report.local_root.is_some());
    assert_eq!(engine.local_raw_history.get(&(HEIGHT + 1)), Some(&NEW_ROOT));
    assert_eq!(report.pruned_history_entries, 1);
    assert_eq!(
        engine.local_raw_history,
        BTreeMap::from([(HEIGHT + 1, NEW_ROOT), (u64::MAX, [0x63; 32])])
    );
}

#[test]
fn direct_block_entry_keeps_the_existing_history() {
    let (mut engine, block, support) = fixture();
    let report = engine
        .apply_block(&block, &support, &BTreeMap::new(), 0, |_, _| 0)
        .unwrap();

    assert!(report.local_root.is_some());
    assert_eq!(
        engine.local_raw_history,
        BTreeMap::from([
            (HEIGHT, [0x31; 32]),
            (HEIGHT + 1, NEW_ROOT),
            (u64::MAX, [0x63; 32])
        ])
    );
}
