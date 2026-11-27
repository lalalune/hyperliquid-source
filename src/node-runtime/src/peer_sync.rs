//! Peer discovery, block synchronization, and storage/consensus integration hooks
//! matching node #115 `node/src/{connections,gossip_rpc,gossip_rpc_client,node}.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use bincode_fork::ByteVec;
use net_utils::{
    DEFAULT_MAX_FRAME_BYTES, GossipRpcRequest, GossipRpcResponse, PeerEntry, TcpClient,
    TcpListener,
};

use crate::error::NodeError;
use crate::gossip_config::GossipConfigInner;
use crate::node_port::NodePort;

/// Storage/ABCI integration hook for committing synchronized client blocks.
/// Ready to wire directly to `storage-abci` (`node115-db` / `abci`).
pub trait BlockSink {
    fn latest_height(&self) -> u64;
    fn apply_client_block(&mut self, height: u64, payload: Vec<u8>) -> Result<(), NodeError>;
}

/// Consensus integration hook for validating incoming block batches / quorum hashes.
/// Ready to wire directly to `consensus-staking` (`node115-consensus` / `node115-staking`).
pub trait ConsensusHook {
    fn verify_client_block_batch(&self, start_height: u64, blocks: &[ByteVec]) -> Result<(), NodeError>;
}

/// Default pass-through verifier for offline transport/runtime unit tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceptAllConsensus;

impl ConsensusHook for AcceptAllConsensus {
    fn verify_client_block_batch(&self, _start_height: u64, _blocks: &[ByteVec]) -> Result<(), NodeError> {
        Ok(())
    }
}

/// In-memory `BlockSink` for deterministic offline sync tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryBlockStore {
    blocks: BTreeMap<u64, Vec<u8>>,
}

impl MemoryBlockStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_existing(&mut self, height: u64, payload: Vec<u8>) {
        self.blocks.insert(height, payload);
    }

    pub fn get_range(&self, start: u64, end: u64) -> Vec<ByteVec> {
        self.blocks
            .range(start..=end)
            .map(|(_, v)| ByteVec(v.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

impl BlockSink for MemoryBlockStore {
    fn latest_height(&self) -> u64 {
        self.blocks.keys().next_back().copied().unwrap_or(0)
    }

    fn apply_client_block(&mut self, height: u64, payload: Vec<u8>) -> Result<(), NodeError> {
        self.blocks.insert(height, payload);
        Ok(())
    }
}

/// Active peer discovery table bounded by `GossipConfigInner`.
#[derive(Clone, Debug)]
pub struct PeerTable {
    root_peers: BTreeSet<Ipv4Addr>,
    reserved_peers: BTreeSet<Ipv4Addr>,
    discovered_peers: BTreeMap<Ipv4Addr, PeerEntry>,
    max_gossip_peers: usize,
    try_new_peers: bool,
}

impl PeerTable {
    pub fn from_config(cfg: &GossipConfigInner) -> Self {
        let mut discovered_peers = BTreeMap::new();
        for &ip in &cfg.root_node_ips {
            discovered_peers.insert(
                ip,
                PeerEntry {
                    ip,
                    port: NodePort::GossipRpc.port(),
                    is_validator: true,
                },
            );
        }
        Self {
            root_peers: cfg.root_node_ips.iter().copied().collect(),
            reserved_peers: cfg.reserved_peer_ips.iter().copied().collect(),
            discovered_peers,
            max_gossip_peers: cfg.n_gossip_peers,
            try_new_peers: cfg.try_new_peers,
        }
    }

    /// Admit newly discovered peers from a `GossipRpcResponse::Peers` message,
    /// respecting `try_new_peers`, `reserved_peer_ips`, and `max_gossip_peers`.
    pub fn merge_discovered(&mut self, entries: &[PeerEntry]) -> usize {
        let mut added = 0;
        for &entry in entries {
            if entry.ip.is_unspecified() || entry.port == 0 {
                continue;
            }
            if self.discovered_peers.contains_key(&entry.ip) {
                continue;
            }
            let privileged =
                self.root_peers.contains(&entry.ip) || self.reserved_peers.contains(&entry.ip);
            if !privileged && (!self.try_new_peers || self.discovered_peers.len() >= self.max_gossip_peers) {
                continue;
            }
            self.discovered_peers.insert(entry.ip, entry);
            added += 1;
        }
        added
    }

    pub fn peers(&self) -> Vec<PeerEntry> {
        self.discovered_peers.values().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.discovered_peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.discovered_peers.is_empty()
    }
}

/// Serve a single gossip RPC request on an already-bound `TcpListener`.
pub fn serve_one_gossip_rpc(
    listener: &TcpListener,
    peers: &[PeerEntry],
    store: &MemoryBlockStore,
    status_fields: Option<[u64; 4]>,
) -> Result<GossipRpcRequest, NodeError> {
    let (mut stream, _addr) = listener
        .accept()
        .map_err(|e| NodeError::GossipRpc(e.to_string()))?;
    let req: GossipRpcRequest = stream
        .recv_bincode(Some(DEFAULT_MAX_FRAME_BYTES))
        .map_err(|e| NodeError::GossipRpc(e.to_string()))?;
    let resp = match &req {
        GossipRpcRequest::Peers => GossipRpcResponse::Peers(peers.to_vec()),
        GossipRpcRequest::ClientBlocks {
            start_height,
            end_height,
        } => {
            if start_height > end_height {
                GossipRpcResponse::ClientBlocks(Err("invalid height range".into()))
            } else {
                GossipRpcResponse::ClientBlocks(Ok(store.get_range(*start_height, *end_height)))
            }
        }
        GossipRpcRequest::Status => GossipRpcResponse::Status(status_fields),
    };
    stream
        .send_bincode(resp)
        .map_err(|e| NodeError::GossipRpc(e.to_string()))?;
    Ok(req)
}

/// Discover peers from a remote gossip RPC endpoint and merge them into `table`.
pub fn discover_peers_from(
    addr: SocketAddrV4,
    table: &mut PeerTable,
) -> Result<usize, NodeError> {
    let mut client = TcpClient::new(SocketAddr::V4(addr), "gossip_rpc_peers")
        .map_err(|e| NodeError::GossipRpc(e.to_string()))?;
    client
        .connect()
        .map_err(|e| NodeError::GossipRpc(e.to_string()))?;
    let resp: GossipRpcResponse = client
        .send_bincode_and_read_response(GossipRpcRequest::Peers, Some(DEFAULT_MAX_FRAME_BYTES))
        .map_err(|e| NodeError::GossipRpc(e.to_string()))?;
    match resp {
        GossipRpcResponse::Peers(entries) => Ok(table.merge_discovered(&entries)),
        other => Err(NodeError::GossipRpc(format!(
            "unexpected response to Peers: {other:?}"
        ))),
    }
}

/// Synchronize client blocks `[start_height..=end_height]` from `addr`, verifying
/// via `consensus` before committing into `sink`.
pub fn sync_client_blocks<S: BlockSink, C: ConsensusHook>(
    addr: SocketAddrV4,
    start_height: u64,
    end_height: u64,
    consensus: &C,
    sink: &mut S,
) -> Result<usize, NodeError> {
    let mut client = TcpClient::new(SocketAddr::V4(addr), "gossip_rpc_blocks")
        .map_err(|e| NodeError::QueryClientBlocks(e.to_string()))?;
    client
        .connect()
        .map_err(|e| NodeError::QueryClientBlocks(e.to_string()))?;
    let resp: GossipRpcResponse = client
        .send_bincode_and_read_response(
            GossipRpcRequest::ClientBlocks {
                start_height,
                end_height,
            },
            Some(DEFAULT_MAX_FRAME_BYTES),
        )
        .map_err(|e| NodeError::QueryClientBlocks(e.to_string()))?;

    let blocks = match resp {
        GossipRpcResponse::ClientBlocks(Ok(blocks)) => blocks,
        GossipRpcResponse::ClientBlocks(Err(msg)) => {
            return Err(NodeError::QueryClientBlocks(msg));
        }
        other => {
            return Err(NodeError::QueryClientBlocks(format!(
                "unexpected response to ClientBlocks: {other:?}"
            )));
        }
    };

    consensus.verify_client_block_batch(start_height, &blocks)?;
    let count = blocks.len();
    for (offset, block) in blocks.into_iter().enumerate() {
        sink.apply_client_block(start_height + offset as u64, block.0)?;
    }
    Ok(count)
}
