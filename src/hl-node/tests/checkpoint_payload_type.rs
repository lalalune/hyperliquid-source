use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use global_constants::ChainName;
use hl_node::engine::NodeEngine;

#[test]
fn latest_local_restore_skips_directory_named_like_checkpoint_payload() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let data_dir = std::env::temp_dir().join(format!(
        "hl-node-checkpoint-payload-{}-{nanos}",
        std::process::id(),
    ));
    let engine = NodeEngine::open_or_restore(ChainName::Local, &data_dir).unwrap();
    let root = engine.abci_state_root();
    engine.persist_checkpoint().unwrap();
    let newer_path = engine.db_home().checkpoint_dir_for_height(1);
    fs::create_dir_all(newer_path.join("checkpoint.bin")).unwrap();
    fs::write(newer_path.join("CHECKPOINT_COMPLETE"), b"").unwrap();
    drop(engine);

    let result = NodeEngine::open_or_restore(ChainName::Local, &data_dir);
    let observed = result
        .as_ref()
        .map(|restored| {
            (
                restored.restored_from_checkpoint(),
                restored.abci_state_root(),
            )
        })
        .map_err(ToString::to_string);
    drop(result);
    fs::remove_dir_all(&data_dir).unwrap();

    assert_eq!(
        observed,
        Ok((Some(0), root)),
        "a directory is not a local checkpoint payload file",
    );
}
