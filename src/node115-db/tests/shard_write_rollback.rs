use node115_db::rocks_db::{PersistentShardKvStore, RocksDbShard};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn failed_single_writes_leave_live_and_reopened_shard_values_unchanged() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hl-rollback-{}-{nanos}", std::process::id()));
    let shard = RocksDbShard::EvmState;
    let column = "EvmStateStorage";
    let mut store = PersistentShardKvStore::open(&dir, shard).unwrap();
    store
        .put(column, b"existing".to_vec(), b"one".to_vec())
        .unwrap();
    store
        .put(column, b"other".to_vec(), b"two".to_vec())
        .unwrap();

    let blocked = store.root_dir().join("EvmStateStorage.tmp");
    fs::create_dir(&blocked).unwrap();
    assert!(
        store
            .put(column, b"existing".to_vec(), b"replacement".to_vec())
            .is_err()
    );
    assert!(
        store
            .put(column, b"new".to_vec(), b"insert".to_vec())
            .is_err()
    );
    assert!(store.delete(column, b"other").is_err());
    let live = [b"existing".as_slice(), b"other", b"new"]
        .map(|key| store.get(column, key).map(<[u8]>::to_vec));

    fs::remove_dir(blocked).unwrap();
    store
        .put(column, b"later".to_vec(), b"three".to_vec())
        .unwrap();
    drop(store);
    let reopened = PersistentShardKvStore::open(&dir, shard).unwrap();
    assert_eq!(reopened.get(column, b"later"), Some(b"three".as_slice()));
    let disk = [b"existing".as_slice(), b"other", b"new"]
        .map(|key| reopened.get(column, key).map(<[u8]>::to_vec));
    drop(reopened);
    fs::remove_dir_all(dir).unwrap();

    let expected = [Some(b"one".to_vec()), Some(b"two".to_vec()), None];
    assert_eq!(live, expected, "failed write changed the live shard");
    assert_eq!(
        disk, expected,
        "failed write appeared in the reopened shard"
    );
}
