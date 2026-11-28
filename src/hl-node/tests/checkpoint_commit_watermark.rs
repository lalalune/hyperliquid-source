use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use global_constants::ChainName;
use hl_node::engine::{NodeBlock, NodeEngine};

#[test]
fn checkpoint_roundtrip_keeps_committed_and_applied_rounds_separate() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let data_dir = std::env::temp_dir().join(format!(
        "hl-node-commit-round-{}-{nanos}",
        std::process::id(),
    ));
    let mut engine = NodeEngine::open_or_restore(ChainName::Local, &data_dir).unwrap();
    let root = engine
        .apply_block(NodeBlock {
            height: 1,
            round: 7,
            proposer_id: 0,
            tx_payload: Vec::new(),
            evm_kvs_writes: Vec::new(),
        })
        .unwrap();
    assert_eq!(engine.committed_round(), 0);
    let checkpoint = engine.persist_checkpoint().unwrap();
    drop(engine);

    let restored = NodeEngine::open_or_restore(ChainName::Local, &data_dir).unwrap();
    let restored_committed = restored.committed_round();
    assert_eq!(restored.latest_round(), 7);
    assert_eq!(restored.abci_state_root(), root);
    drop(restored);

    let metadata = checkpoint.join("abci_state_meta.json");
    let saved = fs::read_to_string(&metadata).unwrap();
    assert!(saved.contains(",\"committed_round\":0"));
    fs::write(&metadata, saved.replace(",\"committed_round\":0", "")).unwrap();
    let legacy = NodeEngine::open_or_restore(ChainName::Local, &data_dir).unwrap();
    assert_eq!(legacy.committed_round(), 7);
    assert_eq!(legacy.abci_state_root(), root);
    drop(legacy);
    fs::remove_dir_all(&data_dir).unwrap();

    assert_eq!(restored_committed, 0, "restart replaced saved committed round");
}
