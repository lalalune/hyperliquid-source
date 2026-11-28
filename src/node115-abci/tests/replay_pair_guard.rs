use std::cell::Cell;
use std::collections::BTreeMap;

use node115_abci::checkpoint_replay_fixture::{
    BlockAdmissionError, ReplayInitializer, RestoredState, SupportContext,
};
use node115_abci::engine::{
    AbciEngine, ApplyBlockPipelineError, ApplyBlockPipelineInput, EngineBlock,
};
use node115_abci::state::{AbciState, REQUIRED_FEATURE_VERSION};

fn check_pair_guard(expected_seq: u64, expected_round: u64, expected_error: BlockAdmissionError) {
    let state = RestoredState {
        checkpoint_path: "fixture/41".into(),
        height: 41,
        round: 105,
        loader_seq: 8,
        copied_round: 99,
        replay_initializer: ReplayInitializer {
            initial_height: 41,
            initial_round: 105,
        },
    };
    let mut engine = AbciEngine::new(AbciState::new(state.clone(), 1000, None));
    let block = EngineBlock {
        prev_round: 105,
        new_round: 106,
        expected_loader_seq: expected_seq,
        expected_copied_round: expected_round,
        external_votes: vec![],
        timer_eligible_heights: vec![],
        synthetic_local_root: None,
    };
    let input = ApplyBlockPipelineInput {
        block: &block,
        state_time: (8, 99),
        block_parent_time: (8, 99),
        header_actions: 1,
        payload_actions: 1,
        feature_version: REQUIRED_FEATURE_VERSION,
        prune_watermark: None,
    };
    let support = SupportContext {
        weights_32: BTreeMap::new(),
        fraction_20: 0.0,
        eligible_20: Default::default(),
        stored_total_20: 0,
    };
    let callbacks = Cell::new(0);
    let result = engine.apply_block_pipeline(
        &input,
        &support,
        &BTreeMap::new(),
        0,
        |_| callbacks.set(callbacks.get() + 1),
        |_| callbacks.set(callbacks.get() + 1),
        |_| callbacks.set(callbacks.get() + 1),
        |_, _| 0,
    );

    assert_eq!(
        result,
        Err(ApplyBlockPipelineError::Admission(expected_error))
    );
    assert_eq!(
        callbacks.get(),
        0,
        "replay pair is checked before pipeline callbacks"
    );
    assert_eq!(engine.state.inner, state);
}

#[test]
fn first_pair_word_mismatch_precedes_begin_action_and_end() {
    check_pair_guard(
        7,
        99,
        BlockAdmissionError::LoaderSeqMismatch {
            state_seq: 8,
            block_seq: 7,
        },
    );
}

#[test]
fn second_pair_word_mismatch_precedes_begin_action_and_end() {
    check_pair_guard(
        8,
        98,
        BlockAdmissionError::CopiedRoundMismatch {
            state_copied: 99,
            block_copied: 98,
        },
    );
}
