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
