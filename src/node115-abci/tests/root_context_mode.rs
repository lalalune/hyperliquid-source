use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use node115_abci::checkpoint_replay_fixture::SupportContext;
use node115_abci::engine::{AbciEngine, EngineBlock};
use node115_abci::state::{AbciState, ReplayInitializer, RestoredState};

#[test]
fn mode_two_finishes_successor_without_publishing_a_raw_root() {
    for (height, cadence) in [(9_999, 1000), (10_000, 73)] {
        let restored = RestoredState {
            checkpoint_path: PathBuf::from(height.to_string()),
            height,
            round: 500,
            loader_seq: 5,
            copied_round: 500,
            replay_initializer: ReplayInitializer {
                initial_height: height,
                initial_round: 500,
            },
        };
        let state = AbciState::new(restored, cadence, None);
        let mut standard = AbciEngine::new(state.clone());
        let mut mode_two = AbciEngine::new(state).with_root_context_mode(2);
        let support = SupportContext {
            weights_32: BTreeMap::new(),
            fraction_20: 0.0,
            eligible_20: BTreeSet::new(),
            stored_total_20: 0,
        };
        let registry = BTreeMap::new();
        let successor = EngineBlock {
            prev_round: 500,
            new_round: 501,
            expected_loader_seq: 5,
            expected_copied_round: 500,
            external_votes: Vec::new(),
            timer_eligible_heights: Vec::new(),
            synthetic_local_root: Some([0x11; 32]),
        };

        let normal_report = standard
            .apply_block(&successor, &support, &registry, 0, |cell, _| {
                cell.write_fallback(1u64 << 15, 0, 0)
            })
            .unwrap();
        assert!(normal_report.local_root.is_some());
        assert_eq!(standard.local_raw_history[&(height + 1)], [0x11; 32]);

        let report = mode_two
            .apply_block(&successor, &support, &registry, 0, |_, _| {
                panic!("the skipped mode must precede the selector")
            })
            .unwrap();
        assert_eq!(report.height, height + 1);
        assert_eq!(report.round, 501);
        assert_eq!(report.local_root, None);
        assert!(mode_two.local_raw_history.is_empty());
    }
}
