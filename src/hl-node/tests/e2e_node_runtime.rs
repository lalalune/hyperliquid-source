use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use clearinghouse::liquidation::LiquidationAction;
use evm::system::{
    BIG_BLOCK_GAS_LIMIT, CORE_WRITER_VERSION_V1, CoreWriterFrameError, SMALL_BLOCK_GAS_LIMIT,
    encode_core_writer_frame,
};
use exchange::bole_liquidation::{BOLE_LIQUIDATOR_ADDRESS, BeginBlockPhase, SpotPairMeta};
use global_constants::ChainName;
use hl_node::engine::{
    BINARY_HARDFORK_VERSION, EngineError, NodeBlock, NodeEngine, format_hex_32,
};
use hl_node::http_server::{HttpServerConfig, LocalHttpServer, http_get, http_post};
use hl_node::peer_loopback::run_loopback_peer_sync;
use node115_abci::state::{ApplyBlockPreconditionError, REQUIRED_FEATURE_VERSION};
use node115_assets::pdi::Side;
use node115_assets::qtys::{Ntl, Px, Sz};
use node115_consensus::commit::{
    CertifiedBlockNode, RegisterBlockOutcome, TwoChainCommitOutcome,
};
use node115_db::rocks_db::TCP_ROCKSDB_MAX_BYTES;
use node115_fees::fee_schedule_compose::Outcome as FeeOutcome;
use node115_fees::tiers::{BaseFeeRates, FeeSchedule};
use node115_orderbook::matching::L2Level;
use node115_orderbook::trigger::{Tpsl, TriggerCondition, TriggerOrder};
use node115_staking::jailing::JailingTime;
use node115_staking::withdrawal_queue::WithdrawalQueueError;

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "hl-node-e2e-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn sample_blocks(count: u64) -> Vec<NodeBlock> {
    (1..=count)
        .map(|h| NodeBlock {
            height: h,
            round: h * 2,
            proposer_id: (h % 4) as u32,
            tx_payload: format!("node115-block-{h}").into_bytes(),
            evm_kvs_writes: vec![(
                format!("slot:{h}").into_bytes(),
                format!("val:{h}").into_bytes(),
            )],
        })
        .collect()
}

#[test]
fn e2e_checkpoint_replay_blake3_root_and_restart_persistence() {
    let data_dir = unique_temp_dir("checkpoint-restart");

    // 1. Fresh boot, ingest 5 blocks, verify BLAKE3 ABCI state root, persist checkpoint.
    let (expected_root, cp_dir) = {
        let mut eng = NodeEngine::open_or_restore(ChainName::Mainnet, &data_dir).expect("open");
        assert_eq!(eng.latest_height(), 0);
        assert_eq!(eng.restored_from_checkpoint(), None);
        let genesis_root = eng.abci_state_root();

        for blk in sample_blocks(5) {
            eng.apply_block(blk).expect("apply block");
        }
        assert_eq!(eng.latest_height(), 5);
        assert_ne!(eng.abci_state_root(), genesis_root);

        let cp_dir = eng.persist_checkpoint().expect("persist checkpoint");
        assert!(cp_dir.join("checkpoint.bin").is_file());
        assert!(eng.db_home().lt_hashes_path(5).is_file());
        (eng.abci_state_root(), cp_dir)
    };

    // 2. Restart from persisted checkpoint and confirm identical height, EVM KV state, and BLAKE3 root.
    {
        let mut resumed =
            NodeEngine::open_or_restore(ChainName::Mainnet, &data_dir).expect("restore");
        assert_eq!(resumed.restored_from_checkpoint(), Some(5));
        assert_eq!(resumed.latest_height(), 5);
        assert_eq!(resumed.abci_state_root(), expected_root);
        assert_eq!(resumed.evm_kv_get(b"slot:5"), Some(b"val:5".as_slice()));

        // Resume applying block 6 cleanly after restart.
        let b6 = NodeBlock {
            height: 6,
            round: 12,
            proposer_id: 2,
            tx_payload: b"node115-block-6".to_vec(),
            evm_kvs_writes: vec![(b"slot:6".to_vec(), b"val:6".to_vec())],
        };
        let root6 = resumed.apply_block(b6).expect("apply block 6");
        assert_ne!(root6, expected_root);
        assert_eq!(resumed.latest_height(), 6);
    }

    // 3. Negative control: corrupting `lt_hashes.json` fails restore closed.
    let lt_path = cp_dir.join("lt_hashes.json");
    fs::write(&lt_path, "{\"abci_state_root\":\"0x0000\"}\n").expect("corrupt lt_hashes");
    let err = NodeEngine::open_or_restore(ChainName::Mainnet, &data_dir).err();
    assert!(matches!(err, Some(EngineError::LtHashesMismatch { .. })));

    let _ = fs::remove_dir_all(&data_dir);
}

#[test]
fn e2e_localhost_http_info_and_evm_rpc_across_restart() {
    let data_dir = unique_temp_dir("http-restart");

    let expected_root_hex = {
        let mut eng = NodeEngine::open_or_restore(ChainName::Testnet, &data_dir).expect("open");
        for blk in sample_blocks(3) {
            eng.apply_block(blk).expect("apply block");
        }
        eng.persist_checkpoint().expect("persist checkpoint");
        let root_hex = eng.abci_state_root_hex();

        let shared = Arc::new(RwLock::new(eng));
        let server = LocalHttpServer::start(
            Arc::clone(&shared),
            HttpServerConfig {
                bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
                serve_info: true,
                serve_evm_rpc: true,
            },
        )
        .expect("start http server");
        let addr = server.local_addr();

        // GET /health
        let health = http_get(addr, "/health").expect("GET /health");
        assert_eq!(health.status_code, 200);
        assert!(health.body.contains("\"height\":3"));
        assert!(health.body.contains(&root_hex));
        assert!(health.body.contains("\"subsystems\":26"));

        // POST /info (exchangeStatus, fileSnapshot localhost allowed, unknown rejected)
        let info_ok =
            http_post(addr, "/info", r#"{"type":"exchangeStatus"}"#).expect("POST /info");
        assert_eq!(info_ok.status_code, 200);
        assert!(info_ok.body.contains("\"type\":\"exchangeStatus\""));
        assert!(info_ok.body.contains("\"height\":3"));
        assert!(info_ok.body.contains(&root_hex));

        let snap_ok = http_post(addr, "/info", r#"{"type":"fileSnapshot"}"#).expect("fileSnapshot");
        assert_eq!(snap_ok.status_code, 200);
        assert!(snap_ok.body.contains(&root_hex));

        let info_bad =
            http_post(addr, "/info", r#"{"type":"notARealVariant"}"#).expect("bad /info");
        assert_eq!(info_bad.status_code, 400);

        // POST /evm (eth_chainId, eth_blockNumber, net_version, web3_clientVersion, unknown -32601)
        let chain_id = http_post(
            addr,
            "/evm",
            r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#,
        )
        .expect("eth_chainId");
        assert_eq!(chain_id.status_code, 200);
        assert!(chain_id.body.contains("\"result\":\"0x3e6\""));

        let blk_num = http_post(
            addr,
            "/evm",
            r#"{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[]}"#,
        )
        .expect("eth_blockNumber");
        assert_eq!(blk_num.status_code, 200);
        assert!(blk_num.body.contains("\"result\":\"0x3\""));

        let ver = http_post(
            addr,
            "/evm",
            r#"{"jsonrpc":"2.0","id":3,"method":"web3_clientVersion","params":[]}"#,
        )
        .expect("web3_clientVersion");
        assert_eq!(ver.status_code, 200);
        assert!(ver.body.contains("hl-node/0.1.0-node115"));

        let unknown = http_post(
            addr,
            "/evm",
            r#"{"jsonrpc":"2.0","id":4,"method":"eth_doesNotExist","params":[]}"#,
        )
        .expect("unknown method");
        assert_eq!(unknown.status_code, 200);
        assert!(unknown.body.contains("-32601"));
        assert!(unknown.body.contains("Method not found"));

        server.stop();
        root_hex
    };

    // Restart engine + new HTTP server from persisted checkpoint and re-verify live responses.
    {
        let eng = NodeEngine::open_or_restore(ChainName::Testnet, &data_dir).expect("restore");
        assert_eq!(eng.restored_from_checkpoint(), Some(3));
        assert_eq!(eng.abci_state_root_hex(), expected_root_hex);

        let shared = Arc::new(RwLock::new(eng));
        let server = LocalHttpServer::start(
            Arc::clone(&shared),
            HttpServerConfig {
                bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
                serve_info: true,
                serve_evm_rpc: true,
            },
        )
        .expect("restart http server");
        let addr = server.local_addr();

        let info_after =
            http_post(addr, "/info", r#"{"type":"exchangeStatus"}"#).expect("info after restart");
        assert_eq!(info_after.status_code, 200);
        assert!(info_after.body.contains("\"height\":3"));
        assert!(info_after.body.contains(&expected_root_hex));

        let evm_after = http_post(
            addr,
            "/evm",
            r#"{"jsonrpc":"2.0","id":9,"method":"eth_blockNumber","params":[]}"#,
        )
        .expect("evm after restart");
        assert_eq!(evm_after.status_code, 200);
        assert!(evm_after.body.contains("\"result\":\"0x3\""));

        server.stop();
    }

    let _ = fs::remove_dir_all(&data_dir);
}

#[test]
fn e2e_loopback_tcp_peer_sync_abci_stream_and_evm_kvs_convergence() {
    let seed_dir = unique_temp_dir("peer-seed");
    let follower_dir = unique_temp_dir("peer-follower");

    let mut seed = NodeEngine::open_or_restore(ChainName::Mainnet, &seed_dir).expect("seed open");
    for blk in sample_blocks(4) {
        seed.apply_block(blk).expect("seed apply");
    }

    let mut follower =
        NodeEngine::open_or_restore(ChainName::Mainnet, &follower_dir).expect("follower open");
    assert_eq!(follower.latest_height(), 0);
    assert_ne!(follower.abci_state_root(), seed.abci_state_root());

    let report = run_loopback_peer_sync(&seed, &mut follower).expect("loopback peer sync");
    assert_eq!(report.discovered_peers, 1);
    assert_eq!(report.greeting_height, 4);
    assert_eq!(report.blocks_synced, 4);
    assert!(report.evm_kvs_synced >= 8);
    assert_eq!(report.follower_height, 4);
    assert_eq!(
        report.remote_status.expect("remote status").latest_height,
        4
    );
    // Exact byte-for-byte BLAKE3 ABCI state-root convergence across loopback TCP!
    assert_eq!(report.follower_abci_root, seed.abci_state_root());
    assert_eq!(follower.abci_state_root(), seed.abci_state_root());

    let _ = fs::remove_dir_all(&seed_dir);
    let _ = fs::remove_dir_all(&follower_dir);
}

#[test]
fn e2e_abci_6_guards_fees_solvency_evm_corewriter_bridge_and_staking_queue() {
    let data_dir = unique_temp_dir("subsystems-guards");
    let mut eng = NodeEngine::open_or_restore(ChainName::Mainnet, &data_dir).expect("open");

    // 1. Canonical Arbitrum Bridge2/Usdc2 contracts (bridge::contracts)
    let (bridge2, usdc2) = eng.canonical_bridge_contracts();
    assert_eq!(bridge2, Some(bridge::contracts::BRIDGE2_MAINNET_ADDRESS));
    assert_eq!(usdc2, Some(bridge::contracts::USDC2_MAINNET_ADDRESS));

    // 2. Dual-block gas limits & CoreWriter v1 17-slot dispatcher (evm::system)
    assert_eq!(eng.evm_block_gas_limit(), SMALL_BLOCK_GAS_LIMIT);
    eng.set_using_big_blocks(true);
    assert_eq!(eng.evm_block_gas_limit(), BIG_BLOCK_GAS_LIMIT);
    let ok_frame = encode_core_writer_frame(CORE_WRITER_VERSION_V1, 1, b"order-payload").unwrap();
    let parsed = eng.validate_core_writer_frame(&ok_frame).expect("valid v1 action 1");
    assert_eq!(parsed.action_id, 1);
    assert_eq!(parsed.payload, b"order-payload");
    // Action ID 14 is explicitly rejected in node #115 jump table 0x79e340
    let bad_14 = encode_core_writer_frame(CORE_WRITER_VERSION_V1, 14, b"x").unwrap();
    assert_eq!(
        eng.validate_core_writer_frame(&bad_14),
        Err(CoreWriterFrameError::UnsupportedActionId(14))
    );

    // 3. FeeSchedule 6-scale protocol net-fee solvency floor (node115-fees::solvency)
    let solvent = FeeSchedule {
        rates: BaseFeeRates {
            perp_cross: 0.0005,
            perp_add: 0.0001,
            spot_cross: 0.0005,
            spot_add: 0.0001,
        },
        vip_tiers: Vec::new(),
        mm_tiers: Vec::new(),
        referral_discount: 0.04,
        referrer_keep: 0.1,
        destination: [0u8; 20],
        extra_destination_fractions: Vec::new(),
        stake_discount_tiers: Vec::new(),
        weigh_spot_volume_double: true,
    };
    assert_eq!(eng.validate_fee_schedule(&solvent, 0.0), FeeOutcome::Passed);
    let mut insolvent = solvent;
    insolvent.rates.perp_add = -0.0005;
    assert_eq!(
        eng.validate_fee_schedule(&insolvent, 0.0),
        FeeOutcome::Rejected
    );

    // 4. CStaking withdrawal queue (node115-staking::withdrawal_queue)
    let user = [0x11u8; 20];
    eng.credit_staking_balance(user, 1_000);
    let t0 = JailingTime {
        major: 100,
        seconds: 0,
        nanos: 0,
    };
    let maturity = eng
        .queue_staking_withdrawal(t0, user, 400)
        .expect("queue withdrawal");
    assert_eq!(
        eng.queue_staking_withdrawal(t0, user, 700),
        Err(WithdrawalQueueError::InsufficientBalance)
    );
    assert!(eng.drain_mature_staking_withdrawals(t0).is_empty());
    let drained = eng.drain_mature_staking_withdrawals(maturity);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].wei, 400);

    // 5. All 6 ordered ABCI apply_block pre-execution guards (node115-abci::state)
    let blk1 = sample_blocks(1).pop().unwrap();
    // Action count mismatch (guard #5)
    assert!(matches!(
        eng.apply_block_guarded(blk1.clone(), 0, (0, 0), 2, 1),
        Err(EngineError::AbciPrecondition(
            ApplyBlockPreconditionError::ActionCountMismatch {
                header_actions: 2,
                payload_actions: 1
            }
        ))
    ));
    // Feature version != 3 (guard #6)
    eng.set_feature_version(2);
    assert!(matches!(
        eng.apply_block_guarded(blk1.clone(), 0, (0, 0), 1, 1),
        Err(EngineError::AbciPrecondition(
            ApplyBlockPreconditionError::FeatureVersionMismatch {
                expected: REQUIRED_FEATURE_VERSION,
                actual: 2
            }
        ))
    ));
    eng.set_feature_version(REQUIRED_FEATURE_VERSION);
    // Hardfork freeze at height 0 (guard #1)
    eng.set_hardfork_height(Some(0));
    assert!(matches!(
        eng.apply_block_guarded(blk1.clone(), 0, (0, 0), 1, 1),
        Err(EngineError::AbciPrecondition(
            ApplyBlockPreconditionError::StateFrozen { height: 0 }
        ))
    ));
    eng.set_hardfork_height(None);
    // Clean application passes all 6 guards
    eng.apply_block(blk1).expect("valid block 1");
    assert_eq!(eng.latest_height(), 1);

    // 6. Verify HTTP /health + /evm reflects live big-block state
    let shared = Arc::new(RwLock::new(eng));
    let server = LocalHttpServer::start(
        Arc::clone(&shared),
        HttpServerConfig {
            bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            serve_info: true,
            serve_evm_rpc: true,
        },
    )
    .expect("start server");
    let addr = server.local_addr();
    let health = http_get(addr, "/health").expect("health");
    assert!(health.body.contains("\"evmBlockGasLimit\":30000000"));
    let big = http_post(
        addr,
        "/evm",
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_usingBigBlocks","params":[]}"#,
    )
    .expect("eth_usingBigBlocks");
    assert!(big.body.contains("\"result\":true"));
    server.stop();

    let _ = fs::remove_dir_all(&data_dir);
}

#[test]
fn e2e_lthash_homomorphic_persistence_lifecycle_and_live_jsonrpc_endpoints() {
    let data_dir = unique_temp_dir("lthash-lifecycle-rpc");

    let (expected_storage_cs, expected_root_hex) = {
        let mut eng = NodeEngine::open_or_restore(ChainName::Mainnet, &data_dir).expect("open");
        assert_eq!(eng.lt_hashes().storage_hash.n_elements, 0);

        for blk in sample_blocks(3) {
            eng.apply_block(blk).expect("apply block");
        }

        // 1. Verify all 7 Exchange::begin_block phases executed in exact #115 order
        assert_eq!(eng.last_begin_block_phases().len(), 7);
        assert_eq!(
            eng.last_begin_block_phases()[0],
            BeginBlockPhase::DistributeFunding.name()
        );
        assert_eq!(
            eng.last_begin_block_phases()[6],
            BeginBlockPhase::ApplyBoleLiquidations.name()
        );

        // 2. Verify homomorphic LtHashes updated across blocks & persisted into lt_hashes.json
        assert!(eng.lt_hashes().accounts_hash.n_elements == 3);
        assert!(eng.lt_hashes().storage_hash.n_elements >= 6);
        let (_, _, stg_cs) = eng.lt_hashes().checksums();
        let cp_dir = eng.persist_checkpoint().expect("persist checkpoint");
        let lt_json = fs::read_to_string(cp_dir.join("lt_hashes.json")).expect("read lt_hashes");
        assert!(lt_json.contains("\"accounts_hash\""));
        assert!(lt_json.contains("\"contracts_hash\""));
        assert!(lt_json.contains("\"storage_hash\""));
        assert!(lt_json.contains(&format_hex_32(&stg_cs)));

        // 3. Clearinghouse liquidation classification & pro-rata backstop allocation
        assert_eq!(
            eng.classify_account_liquidation(500, 400, 266),
            LiquidationAction::Healthy
        );
        assert_eq!(
            eng.classify_account_liquidation(300, 400, 266),
            LiquidationAction::MarketLiquidate {
                shortfall_to_maintenance: 100
            }
        );
        assert_eq!(
            eng.classify_account_liquidation(200, 400, 266),
            LiquidationAction::BackstopLiquidate {
                shortfall_to_backstop: 66
            }
        );
        assert_eq!(
            eng.classify_account_liquidation(-50, 400, 266),
            LiquidationAction::AdlDeficit { deficit_usd: 50 }
        );
        let mut remaining = 200i64;
        let alloc = eng
            .allocate_backstop_liquidation(0, 10, &[100], 1_000, 200, &mut remaining)
            .expect("backstop alloc")
            .expect("some alloc");
        assert_eq!(alloc.allocated_margin, 200);
        assert_eq!(remaining, 0);

        // 4. Exchange bole liquidation forced IOC cross order
        let spots = [SpotPairMeta {
            spot_id: 7,
            base_token: 2,
            quote_token: 0,
        }];
        let bole_order = eng
            .build_bole_liquidation_order(2, 50, 0.95, [0x44u8; 20], &spots, Some(1_000))
            .expect("bole order");
        assert_eq!(bole_order.liquidator, BOLE_LIQUIDATOR_ADDRESS);
        assert_eq!(bole_order.tif, 1);
        assert_eq!(bole_order.limit_px, 950);

        // 5. Orderbook TriggerBook activation check
        eng.trigger_book_mut().insert(TriggerOrder {
            oid: 99,
            user: [0x22u8; 20],
            side: Side::Ask,
            limit_px: Px(105),
            sz: Sz(10),
            reduce_only: true,
            is_position_tpsl: true,
            trigger: TriggerCondition {
                is_market: true,
                trigger_px: Px(100),
                tpsl: Tpsl::Tp,
            },
            timestamp: 1,
            cloid: None,
            peer_oid: None,
        });
        assert!(eng.check_triggers_at_mark(Px(99), &[99]).is_empty());
        assert_eq!(eng.check_triggers_at_mark(Px(100), &[99]), vec![99]);

        (stg_cs, eng.abci_state_root_hex())
    };

    // 6. Restart from disk checkpoint: verify LtHashes + live /info & /evm JSON-RPC 2.0 responses
    let resumed = NodeEngine::open_or_restore(ChainName::Mainnet, &data_dir).expect("restore");
    assert_eq!(resumed.lt_hashes().checksums().2, expected_storage_cs);
    assert_eq!(resumed.abci_state_root_hex(), expected_root_hex);

    let shared = Arc::new(RwLock::new(resumed));
    let server = LocalHttpServer::start(
        Arc::clone(&shared),
        HttpServerConfig {
            bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            serve_info: true,
            serve_evm_rpc: true,
        },
    )
    .expect("start server");
    let addr = server.local_addr();

    for (info_type, expected_substr) in [
        ("exchangeStatus", "\"ltHashes\""),
        ("spotMeta", "\"type\":\"spotMeta\""),
        ("clearinghouseState", "\"marginSummary\""),
        ("openOrders", "\"orders\":[]"),
        ("userFees", "\"protocolFeeScalesCount\":6"),
        ("fileSnapshot", "\"storageHashChecksum\""),
    ] {
        let resp = http_post(addr, "/info", &format!("{{\"type\":\"{info_type}\"}}"))
            .expect("POST /info");
        assert_eq!(resp.status_code, 200, "info {info_type}: {}", resp.body);
        assert!(
            resp.body.contains(expected_substr),
            "info {info_type} missing {expected_substr}: {}",
            resp.body
        );
    }

    let block_rpc = http_post(
        addr,
        "/evm",
        r#"{"jsonrpc":"2.0","id":10,"method":"eth_getBlockByNumber","params":["latest",false]}"#,
    )
    .expect("eth_getBlockByNumber");
    assert!(block_rpc.body.contains("\"number\":\"0x3\""));
    assert!(block_rpc.body.contains(&expected_root_hex));
    assert!(block_rpc.body.contains("\"gasLimit\":\"0x2dc6c0\""));

    let fee_hist = http_post(
        addr,
        "/evm",
        r#"{"jsonrpc":"2.0","id":11,"method":"eth_feeHistory","params":[5,"latest",[]]}"#,
    )
    .expect("eth_feeHistory");
    assert!(fee_hist.body.contains("\"oldestBlock\":\"0x0\""));
    assert!(fee_hist.body.contains("\"blockCount\":4"));

    let logs = http_post(
        addr,
        "/evm",
        r#"{"jsonrpc":"2.0","id":12,"method":"eth_getLogs","params":[{}]}"#,
    )
    .expect("eth_getLogs");
    assert!(logs.body.contains("\"result\":[]"));

    let tx_ok = http_post(
        addr,
        "/evm",
        r#"{"jsonrpc":"2.0","id":13,"method":"eth_sendRawTransaction","params":["0xdeadbeef"]}"#,
    )
    .expect("eth_sendRawTransaction ok");
    assert!(tx_ok.body.contains("\"result\":\"0x"));

    let tx_bad = http_post(
        addr,
        "/evm",
        r#"{"jsonrpc":"2.0","id":14,"method":"eth_sendRawTransaction","params":["0xZZZ"]}"#,
    )
    .expect("eth_sendRawTransaction bad");
    assert!(tx_bad.body.contains("-32602"));

    server.stop();
    let _ = fs::remove_dir_all(&data_dir);
}

#[test]
fn e2e_persistent_kv_hardfork_guard_hotstuff2_and_impact_l2() {
    let data_dir = unique_temp_dir("kv-hf-hotstuff2-l2");

    // 1. Open engine, apply blocks -> persists to PersistentShardKvStore ("EvmStateStorage" CF)
    let cp_dir = {
        let mut eng = NodeEngine::open_or_restore(ChainName::Mainnet, &data_dir).expect("open");
        for blk in sample_blocks(2) {
            eng.apply_block(blk).expect("apply");
        }
        assert_eq!(eng.persistent_evm_storage_get(b"slot:1"), Some(b"val:1".as_slice()));
        assert_eq!(eng.persistent_evm_storage_get(b"slot:2"), Some(b"val:2".as_slice()));

        // TCP RocksDB 100 GB ceiling (`0x5a69415`)
        assert!(NodeEngine::validate_rocksdb_stream_size(TCP_ROCKSDB_MAX_BYTES - 1).is_ok());
        assert!(NodeEngine::validate_rocksdb_stream_size(TCP_ROCKSDB_MAX_BYTES).is_err());

        // 2. HotStuff-2 two-chain commit rule + 128-bit strict 2/3 quorum
        assert!(NodeEngine::has_strict_two_thirds_quorum(67, 100));
        assert!(!NodeEngine::has_strict_two_thirds_quorum(66, 100));
        let h1 = [0x11u8; 32];
        let h2 = [0x22u8; 32];
        let b1 = CertifiedBlockNode {
            block_hash: h1,
            parent_hash: [0u8; 32],
            parent_cert_round: 0,
        };
        let b2 = CertifiedBlockNode {
            block_hash: h2,
            parent_hash: h1,
            parent_cert_round: 1,
        };
        assert_eq!(eng.register_certified_block(b1.clone()), RegisterBlockOutcome::Registered);
        assert_eq!(
            eng.register_certified_block(b1),
            RegisterBlockOutcome::NotNew { tag: 4 }
        );
        assert_eq!(eng.register_certified_block(b2), RegisterBlockOutcome::Registered);
        match eng.try_two_chain_commit(&h2) {
            TwoChainCommitOutcome::Committed {
                new_committed_round,
                committed_blocks,
            } => {
                assert_eq!(new_committed_round, 1);
                assert_eq!(committed_blocks.len(), 1);
            }
            other => panic!("expected two-chain commit, got {other:?}"),
        }
        assert_eq!(eng.committed_round(), 1);

        // 3. Orderbook impact walk (0x46a6370) + L2 bucketing + base BucketGuard & short_string
        let levels = [(Px(100), Sz(5)), (Px(110), Sz(10))];
        assert_eq!(NodeEngine::compute_impact_price(&levels, Ntl(500)), Some(Px(100)));
        let l2 = [
            L2Level {
                px: Px(123456),
                sz: Sz(10),
                n_orders: 1,
            },
            L2Level {
                px: Px(123459),
                sz: Sz(20),
                n_orders: 2,
            },
        ];
        let agg = NodeEngine::aggregate_l2_book(&l2, Side::Bid, Some(5), None, 10);
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].sz, Sz(30));

        assert!(eng.advance_bucket_guard(60_000));
        assert!(!eng.advance_bucket_guard(90_000));
        assert!(eng.advance_bucket_guard(120_000));
        assert_eq!(NodeEngine::pack_short_name("ABCD"), Some(0x4443_4241));
        assert_eq!(NodeEngine::pack_short_name("0123456789abcdefg"), None);

        let cp = eng.persist_checkpoint().expect("persist checkpoint");
        assert!(cp.join("CHECKPOINT_COMPLETE").is_file());
        assert!(cp.join("abci_state_meta.json").is_file());
        cp
    };

    // 4. Restart succeeds via DbHome::load_latest_checkpoint and retains persistent KV + state
    {
        let eng = NodeEngine::open_or_restore(ChainName::Mainnet, &data_dir).expect("restore");
        assert_eq!(eng.restored_from_checkpoint(), Some(2));
        assert_eq!(eng.persistent_evm_storage_get(b"slot:2"), Some(b"val:2".as_slice()));
    }

    // 5. Fail-closed hardfork compatibility guard (`validate_state_hardfork_not_newer`):
    //    reject a snapshot whose hardfork_version exceeds BINARY_HARDFORK_VERSION.
    fs::write(
        cp_dir.join("abci_state_meta.json"),
        format!(
            "{{\"height\":2,\"round\":4,\"hardfork_version\":{},\"committed_round\":1}}\n",
            BINARY_HARDFORK_VERSION + 1
        ),
    )
    .expect("write newer hardfork meta");
    let err = NodeEngine::open_or_restore(ChainName::Mainnet, &data_dir)
        .err()
        .expect("must reject newer state hardfork version");
    assert!(
        matches!(err, EngineError::StateHardforkNewer(_)),
        "expected StateHardforkNewer, got {err:?}"
    );

    let _ = fs::remove_dir_all(&data_dir);
}
