use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use node115_abci::abci_hash::{ReductionNode, ReductionRow, blake3_hash};
use node115_abci::checkpoint_replay_fixture::SupportContext;
use node115_abci::engine::{AbciEngine, EngineBlock, RestoredRootError};
use node115_abci::state::{AbciState, ReplayInitializer, RestoredState};

fn engine_at(height: u64, cadence: u64) -> AbciEngine {
    let restored = RestoredState {
        checkpoint_path: PathBuf::from(height.to_string()),
        height,
        round: 500,
        loader_seq: 7,
        copied_round: 500,
        replay_initializer: ReplayInitializer {
            initial_height: height,
            initial_round: 500,
        },
    };
    AbciEngine::new(AbciState::new(restored, cadence, None))
}

#[test]
fn restored_height_root_is_available_before_successor_root() {
    let mut engine = engine_at(10_000, 73);
    let rows = [ReductionRow {
        index: 0,
        value: ReductionNode::Leaf([0x11; 32]),
    }];
    let expected_h = blake3_hash(
        b"\x91\x92\x00\xd9\x420x1111111111111111111111111111111111111111111111111111111111111111",
    );
    let expected_h1 = blake3_hash(
        b"\x91\x92\x00\xd9\x420x2222222222222222222222222222222222222222222222222222222222222222",
    );
    let checkpoint = engine
        .record_restored_root(&rows, |cell, _| cell.write_fallback(1 << 15, 0, 0))
        .unwrap()
        .unwrap();
    assert_eq!(checkpoint.height, 10_000);
    assert_eq!(checkpoint.digest, expected_h);
    assert_eq!(checkpoint.selector.selector_byte, 3);
    assert_eq!(
        engine.local_raw_history,
        BTreeMap::from([(10_000, expected_h)])
    );
    assert_eq!(engine.state.round(), 500);

    let support = SupportContext {
        weights_32: BTreeMap::new(),
        fraction_20: 0.0,
        eligible_20: BTreeSet::new(),
        stored_total_20: 0,
    };
    let block = EngineBlock {
        prev_round: 500,
        new_round: 501,
        expected_loader_seq: 7,
        expected_copied_round: 500,
        external_votes: Vec::new(),
        timer_eligible_heights: Vec::new(),
        synthetic_local_root: Some(expected_h1),
    };
    let report = engine
        .apply_block(&block, &support, &BTreeMap::new(), 0, |_, _| {
            panic!("the previous selector call populated the cell")
        })
        .unwrap();
    assert_eq!((report.height, report.round), (10_001, 501));
    assert_eq!(
        engine.local_raw_history,
        BTreeMap::from([(10_000, expected_h), (10_001, expected_h1)])
    );
    assert_eq!(
        engine.record_restored_root(&rows, |_, _| panic!("replay already started")),
        Err(RestoredRootError::ReplayAlreadyStarted),
    );
}

#[test]
fn restored_root_outside_cadence_does_not_enter_selector() {
    let mut engine = engine_at(9_999, 73);
    assert_eq!(
        engine.record_restored_root(&[], |_, _| panic!("outside cadence")),
        Ok(None),
    );
    assert!(engine.local_raw_history.is_empty());
}
