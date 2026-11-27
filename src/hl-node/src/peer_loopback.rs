//! Loopback TCP peer synchronization (`GossipRpc`, `AbciStream`, `EvmKvs`)
//! connecting `node-runtime` + `net-utils` + `bincode-fork` directly into `NodeEngine`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::thread;

use bincode_fork::{ByteVec, encode_to_vec, standard};
use net_utils::{
    AbciStreamGreeting, GossipStatus, GreetingHash, Hardfork, PeerEntry, TcpListener,
};
use node_runtime::cli::Chain;
use node_runtime::error::NodeError;
use node_runtime::gossip_config::GossipConfigInner;
use node_runtime::peer_sync::{
    MemoryBlockStore, PeerTable, discover_peers_from, query_gossip_status, serve_one_gossip_rpc,
    sync_client_blocks,
};
use node_runtime::stream_msg::{
    exchange_abci_stream_greeting, recv_evm_kvs_stream, serve_abci_stream_greeting,
    serve_evm_kvs_stream,
};

use crate::engine::{NodeEngine, StrictConsensusHook};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoopbackSyncReport {
    pub discovered_peers: usize,
    pub remote_status: Option<GossipStatus>,
    pub greeting_height: u64,
    pub evm_kvs_synced: usize,
    pub blocks_synced: usize,
    pub follower_height: u64,
    pub follower_abci_root: [u8; 32],
}

/// Runs a full loopback TCP sync from `seed` to `follower` exercising all 3 node #115
/// peer wire protocols over real `127.0.0.1:0` sockets:
/// 1. `GossipRpc` (`Peers`, `Status`, `ClientBlocks`) over LZ4 + `bincode-fork` framing
/// 2. `AbciStream` greeting handshake (port 3999 protocol)
/// 3. `EvmKvs` batched state streaming until `EvmKvsMsg::Done` (port 3998 protocol)
pub fn run_loopback_peer_sync(
    seed: &NodeEngine,
    follower: &mut NodeEngine,
) -> Result<LoopbackSyncReport, NodeError> {
    let seed_height = seed.latest_height();
    let seed_round = seed.latest_round();
    let seed_root = seed.abci_state_root();

    // Prepare seed's serialized block store (`GossipRpcRequest::ClientBlocks`).
    let mut mem_blocks = MemoryBlockStore::new();
    for blk in seed.applied_blocks() {
        let encoded = encode_to_vec(blk, standard())
            .map_err(|e| NodeError::GossipRpc(format!("block encode failed: {e:?}")))?;
        mem_blocks.insert_existing(blk.height, encoded);
    }

    let seed_peers = vec![PeerEntry {
        ip: Ipv4Addr::new(10, 0, 0, 115),
        is_validator: true,
        value: seed_height,
    }];
    let seed_status = GossipStatus {
        hardfork_height: 0,
        latest_height: seed_height,
        hardfork: Hardfork {
            version: 115,
            round: seed_round,
        },
        latest_consensus_round: Some(seed_round),
    };

    // 1. Bind loopback Gossip RPC listener and serve 3 RPC calls (Peers, Status, ClientBlocks).
    let gossip_listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        0,
    )))
    .map_err(|e| NodeError::GossipRpc(e.to_string()))?;
    let gossip_addr = match gossip_listener
        .local_addr()
        .map_err(|e| NodeError::GossipRpc(e.to_string()))?
    {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => unreachable!("bound to IPv4 localhost"),
    };

    let gossip_server = thread::spawn(move || -> Result<(), NodeError> {
        let _ = serve_one_gossip_rpc(&gossip_listener, &seed_peers, &mem_blocks, Some(seed_status))?;
        let _ = serve_one_gossip_rpc(&gossip_listener, &seed_peers, &mem_blocks, Some(seed_status))?;
        let _ = serve_one_gossip_rpc(&gossip_listener, &seed_peers, &mem_blocks, Some(seed_status))?;
        Ok(())
    });

    let mut cfg = GossipConfigInner::default_for_chain(Chain::Mainnet, vec![Ipv4Addr::LOCALHOST])?;
    cfg.try_new_peers = true;
    cfg.n_gossip_peers = 16;
    let mut peer_table = PeerTable::from_config(&cfg);
    let discovered_peers = discover_peers_from(gossip_addr, &mut peer_table)?;
    let remote_status = query_gossip_status(gossip_addr)?;
    let blocks_synced = if seed_height > follower.latest_height() {
        sync_client_blocks(
            gossip_addr,
            follower.latest_height() + 1,
            seed_height,
            &StrictConsensusHook,
            follower,
        )?
    } else {
        0
    };
    gossip_server
        .join()
        .map_err(|_| NodeError::GossipRpc("gossip server thread panicked".to_string()))??;

    // 2. Bind loopback AbciStream listener and exchange `AbciStreamGreeting` (port 3999 protocol).
    let abci_listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        0,
    )))
    .map_err(|e| NodeError::Gossip(e.to_string()))?;
    let abci_addr = match abci_listener
        .local_addr()
        .map_err(|e| NodeError::Gossip(e.to_string()))?
    {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => unreachable!("bound to IPv4 localhost"),
    };

    let server_greeting = AbciStreamGreeting::Kind0 {
        blob: ByteVec(seed_root.to_vec()),
        height: seed_height,
        hash: Box::new(GreetingHash::Signatures {
            first: seed_root,
            left: Vec::new(),
            right: Vec::new(),
            last: seed_root,
        }),
    };
    let client_greeting = server_greeting.clone();
    let abci_server = thread::spawn(move || {
        serve_abci_stream_greeting(&abci_listener, &server_greeting, |peer| {
            matches!(peer, AbciStreamGreeting::Kind0 { height, .. } if *height == seed_height)
        })
    });
    let ack = exchange_abci_stream_greeting(abci_addr, &client_greeting)?;
    abci_server
        .join()
        .map_err(|_| NodeError::Gossip("abci stream thread panicked".to_string()))??;
    let greeting_height = match ack {
        AbciStreamGreeting::Kind0 { height, .. } => height,
        _ => 0,
    };

    // 3. Bind loopback EvmKvs listener and stream seed's EVM KVS snapshot (port 3998 protocol).
    let kvs_listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        0,
    )))
    .map_err(|e| NodeError::EvmKvsWrite(e.to_string()))?;
    let kvs_addr = match kvs_listener
        .local_addr()
        .map_err(|e| NodeError::EvmKvsWrite(e.to_string()))?
    {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => unreachable!("bound to IPv4 localhost"),
    };
    let batch: Vec<(ByteVec, ByteVec)> = seed
        .evm_kvs_snapshot()
        .into_iter()
        .map(|(k, v)| (ByteVec(k), ByteVec(v)))
        .collect();
    let kvs_server = thread::spawn(move || serve_evm_kvs_stream(&kvs_listener, &[batch]));
    let received_pairs = recv_evm_kvs_stream(kvs_addr)?;
    let _sent_count = kvs_server
        .join()
        .map_err(|_| NodeError::EvmKvsWrite("evm kvs server thread panicked".to_string()))??;
    let evm_kvs_synced = received_pairs.len();
    follower
        .apply_evm_kvs_pairs(received_pairs)
        .map_err(|e| NodeError::EvmKvsRead(e.to_string()))?;

    Ok(LoopbackSyncReport {
        discovered_peers,
        remote_status,
        greeting_height,
        evm_kvs_synced,
        blocks_synced,
        follower_height: follower.latest_height(),
        follower_abci_root: follower.abci_state_root(),
    })
}
