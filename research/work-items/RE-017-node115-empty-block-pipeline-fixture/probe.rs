use node115_abci::{
    checkpoint_replay_fixture::{SupportContext, restore_checkpoint},
    digest_reference_handoff::Registry,
    engine::{
        AbciEngine, ApplyBlockPipelineError, ApplyBlockPipelineInput, ApplyBlockStage, ChainName,
        EngineBlock,
    },
    state::{AbciState, ApplyBlockPreconditionError},
};
use node115_replay_completed_payload::{
    CompletedPayload, ReplayBlockCheck, ReplayPayload, decode_completed_payload,
};
use std::{cell::RefCell, env, fs, path::Path};

const H: u64 = 42;
const RESTORED_ROUND: u64 = 40;
const LOADER_SEQUENCE: u64 = 4;
const RESTORED_HARDFORK: [u64; 2] = [5, 40];
const INDEPENDENT_PREPARED_GROUPS: u64 = 0;

fn main() {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let wire = fs::read(&arguments[0]).unwrap();
    let checkpoints = Path::new(&arguments[1]);
    let restored = restore_checkpoint(checkpoints, H, H, RESTORED_ROUND, LOADER_SEQUENCE).unwrap();
    let decoded = decode_completed_payload(CompletedPayload::Plain(&wire)).unwrap();
    assert_eq!(decoded.consumed, wire.len());
    assert!(matches!(
        &decoded.result,
        Ok(ReplayPayload::Block {
            attachments: None,
            ..
        })
    ));
    let header = decoded.project_replica_header(RESTORED_ROUND).unwrap();
    assert_eq!(
        decoded.check_block_identity(RESTORED_HARDFORK),
        ReplayBlockCheck::Match {
            successor: header.round
        }
    );
    assert_eq!((header.parent_round, header.round), (40, 41));
    assert_eq!(header.hardfork, [5, 40]);
    let header_groups = arguments[2].to_str().unwrap().parse().unwrap();
    let block = EngineBlock {
        prev_round: header.parent_round,
        new_round: header.round,
        expected_loader_seq: LOADER_SEQUENCE + 1,
        expected_copied_round: RESTORED_ROUND,
        external_votes: Vec::new(),
        timer_eligible_heights: Vec::new(),
        synthetic_local_root: None,
    };
    let mut engine = AbciEngine::new(AbciState::new(restored, 0, None));
    let support = SupportContext {
        weights_32: Default::default(),
        fraction_20: 0.5,
        eligible_20: Default::default(),
        stored_total_20: 0,
    };
    let registry = Registry::new();
    let mut input = ApplyBlockPipelineInput {
        block: &block,
        state_time: RESTORED_HARDFORK.into(),
        block_parent_time: header.hardfork.into(),
        header_actions: header_groups,
        payload_actions: INDEPENDENT_PREPARED_GROUPS,
        feature_version: 0,
        prune_watermark: None,
    }
    .with_restored_chain(ChainName::Mainnet);
    let events = RefCell::new(Vec::new());

    // Alter only the staged hardfork input and verify that no callback runs.
    input.state_time.1 = 39;
    let rejected = engine.apply_block_pipeline(
        &input,
        &support,
        &registry,
        0,
        |height| events.borrow_mut().push(("begin", height)),
        |_| panic!("empty fixture cannot call an action callback"),
        |height| events.borrow_mut().push(("end", height)),
        |_, _| 0,
    );
    assert_eq!(
        rejected,
        Err(ApplyBlockPipelineError::Precondition(
            ApplyBlockPreconditionError::ParentTimeMismatch {
                state_time: (5, 39),
                block_parent_time: (5, 40),
            }
        ))
    );
    assert!(events.borrow().is_empty());
    assert_eq!(engine.state.height(), H);
    println!("mismatching restored hardfork pair stopped before begin at H={H}");

    input.state_time = RESTORED_HARDFORK.into();
    let advanced = engine
        .apply_block_pipeline(
            &input,
            &support,
            &registry,
            0,
            |height| events.borrow_mut().push(("begin", height)),
            |_| panic!("empty fixture cannot call an action callback"),
            |height| events.borrow_mut().push(("end", height)),
            |_, _| 0,
        )
        .unwrap();
    assert_eq!(
        advanced.stages,
        [
            ApplyBlockStage::PreGuards,
            ApplyBlockStage::BeginBlock,
            ApplyBlockStage::ExecuteActions,
            ApplyBlockStage::EndBlock,
            ApplyBlockStage::UpdateDigestQuorum,
            ApplyBlockStage::VerifyStateRoot,
            ApplyBlockStage::PruneHistory,
        ]
    );
    assert_eq!(*events.borrow(), [("begin", H + 1), ("end", H + 1)]);
    assert_eq!(
        (advanced.engine_report.height, advanced.engine_report.round),
        (H + 1, 41)
    );
    assert!(advanced.engine_report.local_root.is_none() && engine.local_raw_history.is_empty());
    println!(
        "consumed {} wire bytes, parent_round={}, hardfork={:?}",
        decoded.consumed, header.parent_round, header.hardfork
    );
    println!(
        "height/round {H}/{RESTORED_ROUND} -> {}/{}",
        advanced.engine_report.height, advanced.engine_report.round
    );
    println!("events={:?}, local_root=absent", events.borrow());
}
