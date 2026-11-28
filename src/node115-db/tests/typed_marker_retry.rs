use node115_db::rocks_db::{PersistentShardKvStore, RocksDbShard};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn checkpoint_retry_preserves_an_existing_typed_marker_file() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hl-markers-{}-{nanos}", std::process::id()));
    let shard = RocksDbShard::EvmState;
    let mut store = PersistentShardKvStore::open(&dir.join("local"), shard).unwrap();
    store
        .put(
            "EvmStateStorage",
            b"fixture-key".to_vec(),
            b"fixture-value".to_vec(),
        )
        .unwrap();
    let checkpoint = dir.join("checkpoint").join("42");
    let marker = shard.checkpoint_complete_marker_path(&checkpoint);
    store.create_checkpoint(&checkpoint).unwrap();
    assert_eq!(fs::read(&marker).unwrap(), b"");

    fs::write(&marker, b"existing offline marker").unwrap();
    store.create_checkpoint(&checkpoint).unwrap();
    let observed = fs::read(&marker).unwrap();
    let opened = PersistentShardKvStore::open(&checkpoint, shard).unwrap();
    assert_eq!(
        opened.get("EvmStateStorage", b"fixture-key").unwrap(),
        b"fixture-value"
    );
    assert!(checkpoint.join("CHECKPOINT_COMPLETE").is_file());
    drop(opened);
    drop(store);
    fs::remove_dir_all(dir).unwrap();

    assert_eq!(
        observed, b"existing offline marker",
        "retry replaced the existing typed marker"
    );
}
