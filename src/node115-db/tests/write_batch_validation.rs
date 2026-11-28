use node115_db::rocks_db::{DbWriteBatchOp, PersistentShardKvStore, RocksDbShard};
use std::fs;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn bad_column_family_leaves_earlier_batch_operations_unapplied() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hl-node-batch-{}-{nanos}", std::process::id()));
    let mut store = PersistentShardKvStore::open(&dir, RocksDbShard::EvmState).unwrap();
    let column = "EvmStateStorage";
    store
        .put(column, b"stable".to_vec(), b"original".to_vec())
        .unwrap();

    let result = store.write_batch(&[
        DbWriteBatchOp::Put {
            cf: column.into(),
            key: b"new".to_vec(),
            value: b"uncommitted".to_vec(),
        },
        DbWriteBatchOp::Delete {
            cf: column.into(),
            key: b"stable".to_vec(),
        },
        DbWriteBatchOp::Put {
            cf: "EvmStateStorageTypo".into(),
            key: b"local".to_vec(),
            value: Vec::new(),
        },
    ]);
    let immediate_new = store.get(column, b"new").map(<[u8]>::to_vec);
    let immediate_stable = store.get(column, b"stable").map(<[u8]>::to_vec);

    store
        .write_batch(&[DbWriteBatchOp::Put {
            cf: column.into(),
            key: b"later".to_vec(),
            value: b"committed".to_vec(),
        }])
        .unwrap();
    drop(store);

    let reopened = PersistentShardKvStore::open(&dir, RocksDbShard::EvmState).unwrap();
    assert_eq!(reopened.get(column, b"later").unwrap(), b"committed");
    let reopened_new = reopened.get(column, b"new").map(<[u8]>::to_vec);
    let reopened_stable = reopened.get(column, b"stable").map(<[u8]>::to_vec);
    drop(reopened);
    fs::remove_dir_all(dir).unwrap();

    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    assert_eq!(
        immediate_new, None,
        "bad family must prevent the earlier put"
    );
    assert_eq!(immediate_stable, Some(b"original".to_vec()));
    assert_eq!(reopened_new, None);
    assert_eq!(reopened_stable, Some(b"original".to_vec()));
}
