use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use global_constants::ChainName;
use hl_node::engine::{EngineError, NodeBlock, NodeEngine};
use hl_node::http_server::{HttpServerConfig, LocalHttpServer, http_get, http_post};
use hl_node::peer_loopback::run_loopback_peer_sync;

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
