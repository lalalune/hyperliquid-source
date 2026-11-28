use global_constants::ChainName;
use hl_node::engine::{NodeBlock, NodeEngine};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn checkpoint_writer_stays_within_its_restore_byte_limit() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hl-bound-{}-{nanos}", std::process::id()));
    let mut engine = NodeEngine::open_or_restore(ChainName::Local, &dir).unwrap();
    let original_root = engine.abci_state_root();
    engine.persist_checkpoint().unwrap();

    engine
        .apply_block(NodeBlock {
            height: 1,
            round: 1,
            proposer_id: 0,
            tx_payload: vec![0; 16 * 1024 * 1024],
            evm_kvs_writes: Vec::new(),
        })
        .unwrap();
    let oversized = engine.persist_checkpoint();
    let new_dir_exists = engine.db_home().checkpoint_dir_for_height(1).exists();
    drop(engine);

    let reopened = NodeEngine::open_or_restore(ChainName::Local, &dir)
        .map(|restored| (restored.latest_height(), restored.abci_state_root()));
    fs::remove_dir_all(dir).unwrap();

    if let Err(error) = &reopened {
        eprintln!("restart outcome: {error}");
    }
    let error = oversized.expect_err("writer published a checkpoint its own reader rejects");
    assert!(
        error
            .to_string()
            .contains("checkpoint payload exceeds restore limit")
    );
    assert!(!new_dir_exists);
    assert_eq!(reopened.unwrap(), (0, original_root));
}
