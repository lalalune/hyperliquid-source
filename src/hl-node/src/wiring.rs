//! Cross-crate offline workspace wiring connecting all landed node #115 first-party crates.

use global_constants::{ChainDisplay, ChainName};
use node115_base::api_url::ApiUrlKind;
use node115_base::build_mode::BuildMode;
use node115_base::cid::Cid;
use node115_base::time::split_unix_day_seconds;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceHealth {
    pub chain: String,
    pub api_url: &'static str,
    pub bridge_cid: &'static str,
    pub usdc_cid: &'static str,
    pub build_mode: &'static str,
    pub epoch_packed_date: u32,
    pub bincode_roundtrip_len: usize,
    pub linked_subsystems: Vec<&'static str>,
}

/// Runs a deterministic, zero-network, zero-side-effect self-check across every linked
/// first-party node #115 library crate in the workspace.
pub fn workspace_health(chain: ChainName) -> WorkspaceHealth {
    let api_url = match chain {
        ChainName::Mainnet => ApiUrlKind::Mainnet.base_url(),
        ChainName::Testnet => ApiUrlKind::Testnet.base_url(),
        ChainName::Sandbox | ChainName::Local => ApiUrlKind::WebSandbox.base_url(),
    };
    let (bridge_cid, usdc_cid) = match chain {
        ChainName::Mainnet => (Cid::Bridge2Mainnet.address_hex(), Cid::Usdc2Mainnet.address_hex()),
        ChainName::Testnet | ChainName::Sandbox | ChainName::Local => (
            Cid::Bridge2Testnet.address_hex(),
            Cid::Usdc2Testnet.address_hex(),
        ),
    };

    // Exercise node115-base time conversion
    let epoch = split_unix_day_seconds(0, 0).expect("unix epoch valid");

    // Exercise bincode-fork varint/config round-trip
    let cfg = bincode_fork::config::standard();
    let encoded = bincode_fork::encode_to_vec(115u64, cfg).expect("bincode u64 encode");
    let (decoded, consumed): (u64, usize) =
        bincode_fork::decode_from_slice(&encoded, cfg).expect("bincode u64 decode");
    assert_eq!(decoded, 115u64);
    assert_eq!(consumed, encoded.len());

    // Exercise net-utils LZ4 frame compression + decompression round-trip
    let lz4_frame = net_utils::compress_prepend_size(b"hyperliquid-node-115-offline-wiring")
        .expect("lz4 encode");
    let lz4_back =
        net_utils::decompress_size_prepended(&lz4_frame, 1024).expect("lz4 decode");
    assert_eq!(lz4_back, b"hyperliquid-node-115-offline-wiring");

    // Exercise landed integrated subsystems (assets, fees, orderbook, vaults, dex-registry,
    // l1-shared, bridge, db, consensus, staking, abci, action-wire, action-dispatch, node-runtime,
    // clearinghouse, exchange, evm)
    let _pdi = node115_assets::PDI_STRIDE;
    assert_eq!(node115_fees::TARGET_SHA256, node115_assets::TARGET_SHA256);
    let _books: node115_orderbook::Books<u32> = node115_orderbook::Books::new();
    assert_eq!(vaults::TARGET_SHA256, node115_assets::TARGET_SHA256);
    assert_eq!(dex_registry::TARGET_SHA256, node115_assets::TARGET_SHA256);
    assert_eq!(l1_shared::TARGET_SHA256, node115_assets::TARGET_SHA256);
    assert_eq!(action_wire::TARGET_SHA256, node115_assets::TARGET_SHA256);
    assert_eq!(action_dispatch::TARGET_SHA256, node115_assets::TARGET_SHA256);
    assert_eq!(clearinghouse::position_risk::asset_decimal_scale(8, 2), Some(1_000_000));
    assert_eq!(
        exchange::token_scaling::scaled_mul_div(100, 0, 5, &[]),
        Ok(Some(500))
    );
    assert_eq!(evm::LT_HASH_LANES, 1024);
    const { assert!(bridge::BRIDGE2_SERIALIZED_FIELD_COUNT > 0) };
    let _db_block = node115_db::rocks_db::BLOCK_SIZE;
    assert_eq!(
        node115_consensus::timeout_flow::TAG_FIRST_TIMER,
        0x8000_0000_0000_0006
    );
    assert_eq!(node115_staking::admission::ACTION_CLASS_TABLE.len(), 92);
    assert_eq!(
        node115_abci::checkpoint_replay_fixture::DEFAULT_ROOT_CADENCE_MODULUS,
        10_000
    );
    assert_eq!(node_runtime::node_port::NodePort::Gossip.port(), 4001);

    WorkspaceHealth {
        chain: ChainDisplay(chain).to_string(),
        api_url,
        bridge_cid,
        usdc_cid,
        build_mode: BuildMode::Release.as_str(),
        epoch_packed_date: epoch.packed_date,
        bincode_roundtrip_len: consumed,
        linked_subsystems: vec![
            "node115-base",
            "global-constants",
            "bincode-fork",
            "node115-db",
            "net-utils",
            "node-runtime",
            "node115-consensus",
            "node115-staking",
            "node115-abci",
            "node115-abci-checkpoint-replay-fixture",
            "node115-assets",
            "node115-fees",
            "node115-orderbook",
            "action-wire",
            "action-dispatch",
            "clearinghouse",
            "exchange",
            "vaults",
            "dex-registry",
            "l1-shared",
            "bridge",
            "evm",
            "node115-cli-validators",
            "node115-startup-output",
        ],
    }
}
