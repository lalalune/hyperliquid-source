use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use node115_db::block_reader::{BlockReadError, IndexedArtifactVariant, OfflineBlockReader};
use node115_db::db_home::{
    CHECKPOINT_SUBDIR, CheckpointMode, DbHome, DbHomeError, EXCHANGE_ROOT_CAPTURE_OFFSETS,
    LT_HASHES_FILENAME, checkpoint_plan, directory_end_height, validate_db_home_path,
};
use node115_db::db_hub::{
    ByteKeyLookup, ByteKeyNode, InvalidValue, OfflineDbHub, SnapshotOuterPath,
    SnapshotWorkerAdmission, SnapshotWrapperKind, byte_key_lookup, snapshot_outer_selection,
    snapshot_worker_admission,
};
use node115_db::owned_db_home::{
    OpenProfile, OwnedDbDirError, OwnedDbOpenConfig, SLOW_DEFAULT_CACHE_BUDGET, open_cache_budget,
    validate_owned_db_path,
};
use node115_db::rocks_db::{
    BLOCK_SIZE, BlockHandle, COMPANION_BYTES, DEFAULT_CACHE_BUDGET, ERROR_NICHE, OPTIONS_FLAG,
    encode, interpret_open_word,
};

fn unique_tmp(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("node115-db-{tag}-{}-{nanos}", std::process::id()))
}

#[test]
fn owned_db_home_checkpoint_guard_and_live_vs_slow_budgets() {
    assert!(validate_owned_db_path(Path::new("/var/hl/live_db")).is_ok());
    assert!(matches!(
        validate_owned_db_path(Path::new("/var/hl/checkpoints/1000")),
        Err(OwnedDbDirError::ContainsCheckpoint { .. })
    ));
    assert!(matches!(
        validate_owned_db_path(Path::new("checkpoint")),
        Err(OwnedDbDirError::ContainsCheckpoint { .. })
    ));
    // Exact 9-byte prefix is not 10-byte "checkpoint"
    assert!(validate_owned_db_path(Path::new("checkpoin")).is_ok());

    let live = OwnedDbOpenConfig::for_profile(OpenProfile::Live, 0, 999);
    assert_eq!(live.cache_budget_bytes, DEFAULT_CACHE_BUDGET);
    assert_eq!(live.cache_budget_bytes, 2 * 1024 * 1024 * 1024);
    assert_eq!(live.block_size, BLOCK_SIZE);
    assert_eq!(live.options_flag, OPTIONS_FLAG);
    assert_eq!(live.companion_bytes, COMPANION_BYTES);

    let slow = OwnedDbOpenConfig::for_profile(OpenProfile::Slow, 0, 999);
    assert_eq!(slow.cache_budget_bytes, SLOW_DEFAULT_CACHE_BUDGET);
    assert_eq!(slow.cache_budget_bytes, 16 * 1024 * 1024 * 1024);

    assert_eq!(open_cache_budget(OpenProfile::Slow, 1, 4), 4u64 << 30);
    assert_eq!(open_cache_budget(OpenProfile::Live, 1, 1u64 << 34), u64::MAX);
}

#[test]
fn db_home_guard_discovery_plan_restore_copy_and_replica_height() {
    assert!(validate_db_home_path(Path::new("/var/hl/db_home")).is_ok());
    assert!(matches!(
        validate_db_home_path(Path::new("/var/hl/db_bundle/state")),
        Err(DbHomeError::ContainsDbBundle { .. })
    ));

    let root = unique_tmp("home");
    let ckpt_dir = root.join("5000");
    fs::create_dir_all(ckpt_dir.join("EvmState")).unwrap();
    fs::write(ckpt_dir.join("CHECKPOINT_COMPLETE"), b"").unwrap();
    let live_dir = root.join("live");
    fs::create_dir_all(&live_dir).unwrap();

    let home = DbHome::new(&root).unwrap();
    let found = home.find_checkpoint_at(5000).unwrap();
    assert_eq!(found.height, 5000);
    assert_eq!(found.path, ckpt_dir);

    let plan = checkpoint_plan(true, false, true);
    assert_eq!(plan.mode, CheckpointMode::Checkpoint);
    assert_eq!(plan.source_copies, 2);
    assert!(plan.copy_checkpoint);
    assert!(plan.process_lt_hashes);

    let live_home = DbHome::new(&live_dir).unwrap();
    let cmd = live_home.prepare_evm_restore_command(&ckpt_dir).unwrap();
    assert_eq!(cmd.get_program(), "cp");
    let args: Vec<_> = cmd.get_args().collect();
    assert_eq!(args[0], "-al");
    assert!(args[1].to_string_lossy().ends_with("/EvmState"));

    // Replica end-height check
    let rep_root = root.join("replica");
    let date_dir = rep_root.join("20261127");
    fs::create_dir_all(&date_dir).unwrap();
    fs::write(date_dir.join("1000"), b"line1\nline2\nline3\n").unwrap();
    assert_eq!(directory_end_height(&rep_root).unwrap(), 1003);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn db_home_checkpoint_subdir_lt_hashes_and_74_slot_capture_offsets() {
    let home = DbHome::new(Path::new("/var/hl/db_home")).unwrap();
    assert_eq!(home.checkpoint_subdir(), Path::new("/var/hl/db_home").join(CHECKPOINT_SUBDIR));
    assert_eq!(
        home.checkpoint_dir_for_height(42),
        Path::new("/var/hl/db_home/checkpoint/42")
    );
    assert_eq!(
        home.lt_hashes_path(42),
        Path::new("/var/hl/db_home/checkpoint/42").join(LT_HASHES_FILENAME)
    );
    assert_eq!(EXCHANGE_ROOT_CAPTURE_OFFSETS.len(), 74);
    assert_eq!(EXCHANGE_ROOT_CAPTURE_OFFSETS[24], 0x3f08);
    assert_eq!(EXCHANGE_ROOT_CAPTURE_OFFSETS[25], 0x0d88);
    assert_eq!(EXCHANGE_ROOT_CAPTURE_OFFSETS[28], 0x10e8);
    assert_eq!(EXCHANGE_ROOT_CAPTURE_OFFSETS[71], 0x3d98);
    assert_eq!(EXCHANGE_ROOT_CAPTURE_OFFSETS[72], 0x3e50);
    assert_eq!(EXCHANGE_ROOT_CAPTURE_OFFSETS[73], 0x3908);
}

#[test]
fn db_hub_byte_key_storage_decode_and_snapshot_selectors() {
    let keys = [1u8, 4u8, 9u8];
    let vals: [&[u8]; 3] = [b"v1", b"v4", b"v9"];
    let children = [None, None, None, None];
    let node = ByteKeyNode::new(&keys, &vals, &children).unwrap();
    assert_eq!(
        byte_key_lookup(Some(&node), 0, 0x0504),
        ByteKeyLookup::Found {
            value: b"v4",
            value_index: 1,
            nodes_visited: 1,
        }
    );

    let mut hub = OfflineDbHub::new();
    // MessagePack bin8 (0xc4, len 32) encoding 32-byte big-endian u256 = 1
    let mut encoded = vec![0xc4u8, 32u8];
    encoded.extend_from_slice(&[0u8; 31]);
    encoded.push(1u8);
    hub.put(4, b"slot0".to_vec(), encoded);
    let decoded = hub.get_u256_limbs(4, b"slot0").unwrap().unwrap();
    assert_eq!(decoded.limbs, [1, 0, 0, 0]);
    assert_eq!(decoded.consumed, 34);

    // Valid UTF-8 str8 of length 32 must be rejected per node #115 decoder
    let mut valid_utf8_str = vec![0xd9u8, 32u8];
    valid_utf8_str.extend_from_slice(&[b'A'; 32]);
    hub.put(4, b"bad".to_vec(), valid_utf8_str);
    assert_eq!(hub.get_u256_limbs(4, b"bad").unwrap(), Err(InvalidValue));

    assert_eq!(
        snapshot_worker_admission(1u64 << 63, 200),
        SnapshotWorkerAdmission::AllCollection
    );
    assert_eq!(
        snapshot_worker_admission(5, 101),
        SnapshotWorkerAdmission::LimitExit
    );
    assert_eq!(
        snapshot_outer_selection(SnapshotWrapperKind::First, (1u64 << 63) + 1, 1, 7).path,
        SnapshotOuterPath::Special
    );
}

#[test]
fn rocks_db_niche_block_reader_and_indexed_artifact_variants() {
    assert_eq!(interpret_open_word(ERROR_NICHE), Err(ERROR_NICHE));
    assert_eq!(interpret_open_word(0x1234), Ok(0x1234));

    let backing = b"HEADER--PAYLOAD-BYTES--TRAILER";
    let reader = OfflineBlockReader::new(backing);
    let handle = BlockHandle {
        offset: 8,
        size: 13,
    };
    let wire = encode(handle);
    let (decoded_h, slice, rem) = reader.read_encoded_handle(&wire).unwrap();
    assert_eq!(decoded_h, handle);
    assert_eq!(slice, b"PAYLOAD-BYTES");
    assert!(rem.is_empty());

    // Out-of-bounds handle rejected
    let oob = encode(BlockHandle {
        offset: 25,
        size: 10,
    });
    assert!(matches!(
        reader.read_encoded_handle(&oob),
        Err(BlockReadError::OutOfBounds { .. })
    ));

    // IndexedArtifactVariant round-trip
    assert_eq!(
        IndexedArtifactVariant::from_name("NodeMetadata"),
        Some(IndexedArtifactVariant::NodeMetadata)
    );
    assert_eq!(IndexedArtifactVariant::from_name("nodeMetadata"), None);
}

#[test]
fn db_hub_29_kind_prefix_table_and_3_shard_routing() {
    use node115_db::db_hub::{
        DB_HUB_CORE_TIER_MAX_INDEX, DB_HUB_SHARD_0_MASK, DB_HUB_SHARD_1_MASK, DbKind,
    };

    assert_eq!(DB_HUB_SHARD_0_MASK & DB_HUB_SHARD_1_MASK, 0);
    assert_eq!(DbKind::ALL.len(), 29);

    let mut shard_counts = [0usize; 3];
    let mut core_count = 0usize;
    for kind in DbKind::ALL {
        shard_counts[kind.shard_id() as usize] += 1;
        if kind.is_core_l1_tier() {
            assert!((kind as u8) <= DB_HUB_CORE_TIER_MAX_INDEX);
            core_count += 1;
        }
    }
    assert_eq!(shard_counts, [22, 4, 3]);
    assert_eq!(core_count, 21);

    assert_eq!(DbKind::Candle.prefix_bytes(), b"cA");
    assert_eq!(DbKind::Candle.shard_id(), 0);
    assert_eq!(DbKind::ExplorerUserTxs.prefix_bytes(), b"et");
    assert_eq!(DbKind::ExplorerUserTxs.shard_id(), 1);
    assert_eq!(DbKind::EvmBlocks.prefix_bytes(), b"Eb");
    assert_eq!(DbKind::EvmBlocks.shard_id(), 1);
    assert_eq!(DbKind::EvmStateAccounts.prefix_bytes(), b"Ea");
    assert_eq!(DbKind::EvmStateAccounts.shard_id(), 2);
    assert_eq!(DbKind::EvmStateContracts.prefix_bytes(), b"Ec");
    assert_eq!(DbKind::EvmStateContracts.shard_id(), 2);
    assert_eq!(DbKind::EvmStateStorage.prefix_bytes(), b"Es");
    assert_eq!(DbKind::EvmStateStorage.shard_id(), 2);

    let mut hub = OfflineDbHub::new();
    hub.put_kind(DbKind::Candle, b"BTC:1m", b"ohlcv".to_vec());
    hub.put_kind(DbKind::EvmBlocks, b"42", b"blk".to_vec());
    hub.put_kind(DbKind::EvmStateStorage, b"slot7", b"val".to_vec());
    assert_eq!(hub.namespace_count(), 3);
    assert_eq!(hub.get_kind(DbKind::Candle, b"BTC:1m"), Some(b"ohlcv".as_slice()));
    assert_eq!(hub.get_kind(DbKind::EvmBlocks, b"42"), Some(b"blk".as_slice()));
    assert_eq!(hub.get_kind(DbKind::EvmStateStorage, b"slot7"), Some(b"val".as_slice()));
    assert_eq!(hub.get(2, b"Esslot7"), Some(b"val".as_slice()));
}

#[test]
fn indexed_block_reader_point_and_range_query_inclusive() {
    use node115_db::block_reader::IndexedBlockReader;

    let mut reader = IndexedBlockReader::new();
    reader.insert_block(10, b"b10".to_vec());
    reader.insert_block(12, b"b12".to_vec());
    reader.insert_block(15, b"b15".to_vec());

    assert_eq!(reader.block(10), Some(b"b10".as_slice()));
    assert_eq!(reader.block(11), None);
    assert_eq!(
        reader.range_query_inclusive(10, 12),
        vec![(10, b"b10".as_slice()), (12, b"b12".as_slice())]
    );
    assert!(reader.range_query_inclusive(20, 10).is_empty());
}

#[test]
fn rocksdb_3_shard_profiles_tcp_ceiling_and_persistent_checkpoint_roundtrip() {
    use node115_db::rocks_db::{
        CORE_BLOCK_SIZE, CORE_DEFAULT_CACHE_BYTES, DHS_SUBDIR_PREFIX, DbWriteBatchOp,
        DbWriteError, EVM_BLOCK_SIZE, EVM_DEFAULT_CACHE_BYTES, EVM_STATE_COLUMN_FAMILIES,
        PersistentShardKvStore, RocksDbShard, RocksDbTooLargeError, TCP_ROCKSDB_MAX_BYTES,
        WRITE_BUFFER_BYTES, validate_tcp_rocksdb_size,
    };

    // Core L1 vs EvmState profile contrast (`0x57c6530` vs `0x4524660`)
    let ex = RocksDbShard::Exchange.profile();
    let rpc = RocksDbShard::Rpc.profile();
    let evm = RocksDbShard::EvmState.profile();
    assert_eq!(ex.default_cache_bytes, CORE_DEFAULT_CACHE_BYTES);
    assert_eq!(ex.block_size_bytes, CORE_BLOCK_SIZE);
    assert_eq!(ex.write_buffer_bytes, WRITE_BUFFER_BYTES);
    assert!(!ex.multi_column_family);
    assert_eq!(rpc.default_cache_bytes, CORE_DEFAULT_CACHE_BYTES);
    assert_eq!(evm.default_cache_bytes, EVM_DEFAULT_CACHE_BYTES);
    assert_eq!(evm.block_size_bytes, EVM_BLOCK_SIZE);
    assert_eq!(evm.write_buffer_bytes, WRITE_BUFFER_BYTES);
    assert!(evm.multi_column_family);
    assert_eq!(RocksDbShard::EvmState.column_families(), &EVM_STATE_COLUMN_FAMILIES);
    assert_eq!(DHS_SUBDIR_PREFIX, "dhs/");

    // Exact 100 GB TCP RocksDB size ceiling (`0x5a69415..0x5a6941f`)
    assert!(validate_tcp_rocksdb_size(TCP_ROCKSDB_MAX_BYTES - 1).is_ok());
    assert_eq!(
        validate_tcp_rocksdb_size(TCP_ROCKSDB_MAX_BYTES),
        Err(RocksDbTooLargeError {
            size_bytes: TCP_ROCKSDB_MAX_BYTES,
            limit_bytes: TCP_ROCKSDB_MAX_BYTES,
        })
    );
    assert_ne!(
        DbWriteError::InvalidMarkerWrite("m".into()),
        DbWriteError::InvalidDataWrite("m".into())
    );

    // Persistent on-disk multi-CF EvmState KV store + batch + reload + atomic checkpoint
    let root = unique_tmp("rocks-kv");
    let live_home = root.join("live");
    let ckpt_dir = root.join("checkpoint").join("42000");
    {
        let mut store = PersistentShardKvStore::open(&live_home, RocksDbShard::EvmState).unwrap();
        store
            .put("EvmStateAccounts", b"0x01".to_vec(), b"bal=100".to_vec())
            .unwrap();
        store
            .write_batch(&[
                DbWriteBatchOp::Put {
                    cf: "EvmStateContracts".into(),
                    key: b"0x02".to_vec(),
                    value: b"bytecode".to_vec(),
                },
                DbWriteBatchOp::Put {
                    cf: "EvmStateStorage".into(),
                    key: b"slot0".to_vec(),
                    value: b"val0".to_vec(),
                },
                DbWriteBatchOp::Put {
                    cf: "EvmStateStorage".into(),
                    key: b"slot1".to_vec(),
                    value: b"val1".to_vec(),
                },
                DbWriteBatchOp::Delete {
                    cf: "EvmStateStorage".into(),
                    key: b"slot0".to_vec(),
                },
            ])
            .unwrap();
        assert_eq!(store.len_in_cf("EvmStateStorage"), 1);
        store.create_checkpoint(&ckpt_dir).unwrap();
    }

    assert!(ckpt_dir.join("CHECKPOINT_COMPLETE").is_file());
    assert!(ckpt_dir.join("CHECKPOINT_COMPLETE_evmstate").is_file());
    let reloaded = PersistentShardKvStore::open(&live_home, RocksDbShard::EvmState).unwrap();
    assert_eq!(reloaded.get("EvmStateAccounts", b"0x01"), Some(b"bal=100".as_slice()));
    assert_eq!(reloaded.get("EvmStateContracts", b"0x02"), Some(b"bytecode".as_slice()));
    assert_eq!(reloaded.get("EvmStateStorage", b"slot0"), None);
    assert_eq!(reloaded.get("EvmStateStorage", b"slot1"), Some(b"val1".as_slice()));

    let from_ckpt = PersistentShardKvStore::open(&ckpt_dir, RocksDbShard::EvmState).unwrap();
    assert_eq!(from_ckpt.get("EvmStateAccounts", b"0x01"), Some(b"bal=100".as_slice()));
    assert_eq!(from_ckpt.get("EvmStateStorage", b"slot1"), Some(b"val1".as_slice()));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn storage_db_closure_latest_checkpoint_loader_db_hub_path_and_single_run_block_query() {
    use node115_db::block_reader::{
        BlockingBlockQueryError, IndexedBlockReader, SingleRunBlockQuery,
    };
    use node115_db::db_home::LoadLatestCheckpointError;
    use node115_db::db_hub::{DEFAULT_DB_HUB_SUBDIR, default_db_hub_path};

    // db_hub.rs:25:38 (`0x4e33ef0`) default path & db_hub.rs:62/66/68 (`0x1692ca0`) marker write
    assert_eq!(DEFAULT_DB_HUB_SUBDIR, "hyperliquid_data/db_hub");
    assert_eq!(
        default_db_hub_path(Path::new("/home/hl")),
        Path::new("/home/hl/hyperliquid_data/db_hub")
    );

    let root = unique_tmp("closure");
    let home = DbHome::new(&root).unwrap();

    // 1. Missing outer `checkpoint` dir -> OuterDirDoesNotExist
    let e1 = home.load_latest_checkpoint(Some("EvmState")).unwrap_err();
    assert!(matches!(e1, LoadLatestCheckpointError::OuterDirDoesNotExist { .. }));
    assert!(e1.to_string().starts_with("checkpoint outer dir does not exist "));

    // 2. Empty `checkpoint` dir (or only signed/non-digit dirs like "+10", "-5", "tmp") -> NoCheckpointsToLoad
    let outer = home.checkpoint_subdir();
    fs::create_dir_all(outer.join("+10")).unwrap();
    fs::create_dir_all(outer.join("-5")).unwrap();
    fs::create_dir_all(outer.join("tmp")).unwrap();
    let e2 = home.load_latest_checkpoint(Some("EvmState")).unwrap_err();
    assert!(matches!(e2, LoadLatestCheckpointError::NoCheckpointsToLoad { .. }));
    assert!(e2.to_string().starts_with("no checkpoints to load: "));

    // 3. Numeric dir exists without CHECKPOINT_COMPLETE -> UnableToLoadAnyCurrentCheckpoint
    fs::create_dir_all(outer.join("100")).unwrap();
    let e3 = home.load_latest_checkpoint(Some("EvmState")).unwrap_err();
    assert!(matches!(
        e3,
        LoadLatestCheckpointError::UnableToLoadAnyCurrentCheckpoint { .. }
    ));
    assert!(
        e3.to_string()
            .starts_with("unable to load any current checkpoint from ")
    );

    // 4. Higher incomplete dir 200 skipped; valid dir 100 with CHECKPOINT_COMPLETE + EvmState selected
    fs::create_dir_all(outer.join("200")).unwrap();
    let hub = OfflineDbHub::new();
    hub.write_checkpoint_marker(&outer.join("100"), "EvmState", "CHECKPOINT_COMPLETE", b"")
        .unwrap();
    let latest = home.load_latest_checkpoint(Some("EvmState")).unwrap();
    assert_eq!(latest.height, 100);
    assert_eq!(latest.path, outer.join("100"));

    // 5. block_reader.rs:29:26 (`0x2b2be60`) single-run blocking query contract
    let mut reader = IndexedBlockReader::new();
    reader.insert_block(42, b"blk42".to_vec());
    let mut q = SingleRunBlockQuery::new(42);
    assert_eq!(q.run_once(&reader), Ok(Some(b"blk42".as_slice())));
    assert_eq!(q.run_once(&reader), Err(BlockingBlockQueryError::AlreadyPolled));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn rocks_db_per_shard_checkpoint_marker_and_owned_db_dir_guard() {
    use node115_db::rocks_db::{
        CHECKPOINT_COMPLETE_SHARD_PREFIX, OWNED_DB_DIR_FORBIDDEN_SUBSTR, OwnedDbDirInvalidError,
        RocksDbShard, validate_owned_db_dir,
    };

    assert_eq!(CHECKPOINT_COMPLETE_SHARD_PREFIX, "CHECKPOINT_COMPLETE_");
    assert_eq!(OWNED_DB_DIR_FORBIDDEN_SUBSTR, "checkpoint");

    let ckpt = Path::new("/var/hl/ckpt/42000");
    assert_eq!(
        RocksDbShard::Exchange.checkpoint_complete_marker_path(ckpt),
        Path::new("/var/hl/ckpt/42000/CHECKPOINT_COMPLETE_exchange")
    );
    assert_eq!(
        RocksDbShard::Rpc.checkpoint_complete_marker_path(ckpt),
        Path::new("/var/hl/ckpt/42000/CHECKPOINT_COMPLETE_rpc")
    );
    assert_eq!(
        RocksDbShard::EvmState.checkpoint_complete_marker_path(ckpt),
        Path::new("/var/hl/ckpt/42000/CHECKPOINT_COMPLETE_evmstate")
    );

    assert!(validate_owned_db_dir("/var/hl/live_db").is_ok());
    assert!(validate_owned_db_dir("/var/hl/checkpoin").is_ok());
    let err = validate_owned_db_dir("/var/hl/checkpoint/42000").unwrap_err();
    assert_eq!(
        err,
        OwnedDbDirInvalidError {
            dir: "/var/hl/checkpoint/42000".to_string()
        }
    );
    assert_eq!(
        err.to_string(),
        "OwnedDbDir invalid dir /var/hl/checkpoint/42000"
    );
}
