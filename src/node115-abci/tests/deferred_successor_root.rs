use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use node115_abci::abci_hash::{
    ReductionNode, ReductionRow, blake3_hash, compute_reduction_tree_root,
};
use node115_abci::checkpoint_replay_fixture::{
    BlockAdmissionError, RootProvenance, SupportContext,
};
use node115_abci::engine::{AbciEngine, EngineBlock};
use node115_abci::state::{AbciState, ReplayInitializer, RestoredState};

fn engine_at(height: u64) -> AbciEngine {
    AbciEngine::new(AbciState::new(
        RestoredState {
            checkpoint_path: PathBuf::from(height.to_string()),
            height,
            round: 500,
            loader_seq: 12,
            copied_round: 91,
            replay_initializer: ReplayInitializer {
                initial_height: height,
                initial_round: 500,
            },
        },
        10_000,
        None,
    ))
}

#[test]
fn capture_happens_only_at_the_eligible_successor_after_state_advance() {
    let mut engine = engine_at(9_999);
    let support = SupportContext {
        weights_32: BTreeMap::new(),
        fraction_20: 0.0,
        eligible_20: BTreeSet::new(),
        stored_total_20: 0,
    };
    let registry = BTreeMap::new();
    let mut block = EngineBlock {
        prev_round: 500,
        new_round: 501,
        expected_loader_seq: 11,
        expected_copied_round: 91,
        external_votes: Vec::new(),
        timer_eligible_heights: Vec::new(),
        synthetic_local_root: None,
    };
    assert_eq!(
        engine.apply_block_with_root_source(
            &block,
            &support,
            &registry,
            0,
            |_| panic!("guard rejected block before root capture"),
            |_, _| panic!("guard rejected block before root selection"),
        ),
        Err(BlockAdmissionError::LoaderSeqMismatch {
            state_seq: 12,
            block_seq: 11
        }),
    );

    block.expected_loader_seq = 12;
    let expected = blake3_hash(
        b"\x91\x92\x01\xd9\x420x4444444444444444444444444444444444444444444444444444444444444444",
    );
    let report = engine
        .apply_block_with_root_source(
            &block,
            &support,
            &registry,
            0,
            |state| {
                assert_eq!((state.height(), state.round()), (10_000, 501));
                Some(
                    compute_reduction_tree_root(&[ReductionRow {
                        index: 1,
                        value: ReductionNode::Leaf([0x44; 32]),
                    }])
                    .unwrap(),
                )
            },
            |cell, _| cell.write_fallback(1 << 15, 0, 0),
        )
        .unwrap();
    assert_eq!(
        report.local_root.unwrap().0,
        RootProvenance::LocalPostComparison {
            height: 10_000,
            selector_byte: 3,
            digest: expected
        },
    );
    assert_eq!(engine.local_raw_history.get(&10_000), Some(&expected));

    block.prev_round = 501;
    block.new_round = 502;
    let report = engine
        .apply_block_with_root_source(
            &block,
            &support,
            &registry,
            0,
            |_| panic!("ineligible height cannot capture a root"),
            |_, _| panic!("ineligible height cannot select a root"),
        )
        .unwrap();
    assert_eq!(report.height, 10_001);
    assert!(report.local_root.is_none());
    assert!(!engine.local_raw_history.contains_key(&10_001));
}
