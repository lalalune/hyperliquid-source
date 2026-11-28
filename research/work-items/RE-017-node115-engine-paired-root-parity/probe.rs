use node115_abci::{
    abci_hash::{
        CaptureSlot, ROOT_CAPTURE_SLOT_COUNT, ReductionNode, ReductionRow, blake3_hash,
        compute_reduction_tree_root, reduce_top_level_capture,
    },
    checkpoint_replay_fixture::SupportContext,
    engine::{AbciEngine, EngineBlock},
    state::{AbciState, restore_checkpoint},
};
use node115_client_block_success::{
    Parent, ReplayPayload, decode_replay_payload_prefix, replay_parent_projection,
};
use std::{collections::BTreeMap, env, fs, path::Path};

fn capture(state: &AbciState, aux: [u8; 32]) -> Vec<ReductionRow> {
    let height = ReductionNode::Leaf(blake3_hash(&state.height().to_le_bytes()));
    let round = ReductionNode::Leaf(blake3_hash(&state.round().to_le_bytes()));
    let context = ReductionNode::Nested(vec![
        ReductionRow {
            index: 2,
            value: height,
        },
        ReductionRow {
            index: 4,
            value: round,
        },
    ]);
    let exchange = ReductionNode::Nested(vec![ReductionRow {
        index: 0,
        value: context,
    }]);
    let mut slots: [CaptureSlot; ROOT_CAPTURE_SLOT_COUNT] =
        std::array::from_fn(|_| CaptureSlot::Empty);
    slots[0] = CaptureSlot::Value(exchange);
    slots[58] = CaptureSlot::Value(ReductionNode::Leaf(aux));
    reduce_top_level_capture(slots)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let mut args = env::args_os().skip(1);
    let wire = fs::read(args.next().expect("validated offline Block payload")).unwrap();
    let checkpoint_path = args.next().expect("temporary checkpoint marker fixture");
    let args_text = fs::read_to_string(args.next().expect("pinned fixture state")).unwrap();
    let mut parts = args_text.split_whitespace();
    let height: u64 = parts.next().unwrap().parse().unwrap();
    let round: u64 = parts.next().unwrap().parse().unwrap();
    let persisted_seq: u64 = parts.next().unwrap().parse().unwrap();
    let cadence: u64 = parts.next().unwrap().parse().unwrap();
    let hardfork_first: u64 = parts.next().unwrap().parse().unwrap();
    let hardfork_second: u64 = parts.next().unwrap().parse().unwrap();
    let aux_hex = parts.next().unwrap();
    assert_eq!(aux_hex.len(), 64);
    let aux = std::array::from_fn(|i| u8::from_str_radix(&aux_hex[i * 2..i * 2 + 2], 16).unwrap());
    assert!(parts.next().is_none());

    let decoded = decode_replay_payload_prefix(&wire, 10_000_000);
    assert!(decoded.remaining.is_empty());
    let ReplayPayload::Block { block, .. } = decoded.result.unwrap() else {
        panic!("Block required")
    };
    let Parent::QuorumCertificate(incoming_parent) = &block.header.parent else {
        panic!("expected the selected ordinary direct-quorum fixture");
    };
    assert_eq!(incoming_parent.fields[2], round);
    let projected = replay_parent_projection(&block.header.parent);
    assert_eq!(
        projected.comparison_words,
        [hardfork_first, hardfork_second]
    );
    let restored = restore_checkpoint(
        Path::new(&checkpoint_path),
        height,
        height,
        round,
        persisted_seq,
    )
    .unwrap();
    let block = EngineBlock {
        prev_round: round,
        new_round: projected.successor,
        expected_loader_seq: restored.loader_seq,
        expected_copied_round: restored.copied_round,
        external_votes: Vec::new(),
        timer_eligible_heights: Vec::new(),
        synthetic_local_root: None,
    };
    let mut engine = AbciEngine::new(AbciState::new(restored, cadence, None));
    let checkpoint_rows = capture(&engine.state, aux);
    let starting = engine
        .record_restored_root(&checkpoint_rows, |cell, _| {
            cell.write_fallback(1 << 15, 0, 0)
        })
        .unwrap()
        .expect("eligible starting root");
    assert_eq!(engine.local_raw_history.len(), 1);
    let support = SupportContext {
        weights_32: Default::default(),
        fraction_20: 0.0,
        eligible_20: Default::default(),
        stored_total_20: 0,
    };
    let successor = engine
        .apply_block_with_root_source(
            &block,
            &support,
            &BTreeMap::new(),
            0,
            |state| Some(compute_reduction_tree_root(&capture(state, aux)).unwrap()),
            |_, _| panic!("first root initialized the shared selector"),
        )
        .unwrap();
    let after = engine.local_raw_history[&successor.height];
    assert_eq!(engine.local_raw_history[&height], starting.digest);
    assert_eq!(engine.local_raw_history.len(), 2);
    println!(
        "{{\"height\":{},\"round\":{round},\"computed_h\":\"0x{}\",\"successor_height\":{},\"successor_round\":{},\"computed_h1\":\"0x{}\"}}",
        starting.height,
        hex(&starting.digest),
        successor.height,
        successor.round,
        hex(&after)
    );
}
