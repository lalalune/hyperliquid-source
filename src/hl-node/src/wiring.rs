//! Cross-crate offline workspace wiring connecting all landed node #115 first-party crates.

use std::{borrow::Cow, net::Ipv4Addr};

use global_constants::{ChainDisplay, ChainName};
use node115_base::api_url::ApiUrlKind;
use node115_base::build_mode::BuildMode;
use node115_base::cid::Cid;
use node115_base::time::split_unix_day_seconds;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceHealth {
    pub chain: String,
    pub api_url: Option<Cow<'static, str>>,
    pub bridge_cid: &'static str,
    pub usdc_cid: &'static str,
    pub build_mode: &'static str,
    pub epoch_packed_date: u32,
    pub bincode_roundtrip_len: usize,
    pub linked_subsystems: Vec<&'static str>,
}

/// Resolve the HTTP base selected by the two node #115 API URL consumers.
/// Sandbox uses the IPv4 address associated with the WebSandbox configuration key.
pub fn api_base_url(chain: ChainName, sandbox_ip: Option<Ipv4Addr>) -> Option<Cow<'static, str>> {
    let fixed = match chain {
        ChainName::Mainnet => ApiUrlKind::Mainnet.base_url(),
        ChainName::Testnet => ApiUrlKind::Testnet.base_url(),
        ChainName::Local => ApiUrlKind::WebSandbox.base_url(),
        ChainName::Sandbox => return sandbox_ip.map(|ip| Cow::Owned(format!("http://{ip}:3001/"))),
    };
    Some(Cow::Borrowed(fixed))
}

/// Runs a deterministic, zero-network, zero-side-effect self-check across every linked
/// first-party node #115 library crate in the workspace. It does not read sandbox configuration.
pub fn workspace_health(chain: ChainName) -> WorkspaceHealth {
    let api_url = api_base_url(chain, None);
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
    assert_eq!(evm::system::HYPER_EVM_SYSTEM_CONTRACTS.len(), 3);
    assert_eq!(evm::system::SMALL_BLOCK_GAS_LIMIT, 3_000_000);
    assert_eq!(evm::system::BIG_BLOCK_GAS_LIMIT, 30_000_000);
    assert_eq!(evm_rpc::EVM_RPC_CORE_METHODS.len(), 26);
    assert_eq!(evm_rpc::EVM_RPC_EXTRA_METHODS.len(), 2);
    assert_eq!(info_api::INFO_SERVER_SOURCE_PATHS.len(), 7);
    assert_eq!(info_api::INFO_SERVER_PANIC_LOCATION_COUNT, 43);
    const { assert!(bridge::BRIDGE2_SERIALIZED_FIELD_COUNT > 0) };
    assert_eq!(
        bridge::contracts::BRIDGE2_MAINNET_ADDRESS_HEX,
        Cid::Bridge2Mainnet.address_hex()
    );
    assert_eq!(
        bridge::contracts::USDC2_MAINNET_ADDRESS_HEX,
        Cid::Usdc2Mainnet.address_hex()
    );
    assert_eq!(node115_fees::solvency::PROTOCOL_FEE_SCALES.len(), 6);
    assert_eq!(
        node115_staking::withdrawal_queue::MAX_CONCURRENT_WITHDRAWALS_PER_USER,
        5
    );
    assert_eq!(node_runtime::aux::AUX_OUTPUT_STREAMS.len(), 10);
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
            "evm-rpc",
            "info-api",
            "node115-cli-validators",
            "node115-startup-output",
        ],
    }
}
