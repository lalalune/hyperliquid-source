use node115_db::rocks_db::{PersistentShardKvStore, RocksDbShard};
use std::fs;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn shard_restore_requires_exactly_one_complete_column_family_record() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hl-kv-{}-{nanos}", std::process::id()));
    let home = dir.join("live");
    let checkpoint = dir.join("checkpoint").join("42");
    let shard = RocksDbShard::EvmState;
    let storage = "EvmStateStorage";
    let mut store = PersistentShardKvStore::open(&home, shard).unwrap();

    store
        .put(storage, b"local".to_vec(), b"first snapshot".to_vec())
        .unwrap();
    let cp = store.create_checkpoint(&checkpoint).unwrap();
    let path = cp.join("EvmStateStorage.kv");
    let first = fs::read(&path).unwrap();
    let loaded = PersistentShardKvStore::open(&checkpoint, shard).unwrap();
    assert_eq!(loaded.get(storage, b"local").unwrap(), b"first snapshot");
    drop(loaded);

    store
        .put(storage, b"local".to_vec(), b"second snapshot".to_vec())
        .unwrap();
    let second = fs::read(store.root_dir().join("EvmStateStorage.kv")).unwrap();
    fs::write(&path, [first, second].concat()).unwrap();
    let result = PersistentShardKvStore::open(&checkpoint, shard);

    drop(store);
    fs::remove_dir_all(dir).unwrap();
    let error = result.expect_err("restore accepted concatenated snapshots");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("trailing bytes"));
}
