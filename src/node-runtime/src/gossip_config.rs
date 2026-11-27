//! Gossip configuration and hot-reload gating matching node #115
//! `node/src/gossip_config.rs` (`.rodata 0x92a77b..0x92a878`, `node115-gossip-reload`).

use std::net::Ipv4Addr;

use crate::cli::Chain;
use crate::error::NodeError;

/// Override config filename observed at `.rodata 0x92a85b`.
pub const OVERRIDE_GOSSIP_CONFIG_FILENAME: &str = "override_gossip_config.json";

/// Configuration fields recovered from `.rodata 0x92a793..0x92a80a` (`GossipConfigInner`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GossipConfigInner {
    pub root_node_ips: Vec<Ipv4Addr>,
    pub try_new_peers: bool,
    pub chain: Chain,
    pub reserved_peer_ips: Vec<Ipv4Addr>,
    pub n_gossip_peers: usize,
    pub split_client_blocks: bool,
    pub slow_abci_engine_read_increment: u64,
}

impl GossipConfigInner {
    /// Validate invariants enforced in `node/src/gossip_config.rs`
    /// (`assertion failed: !res.read().root_node_ips.is_empty()` at `0x92a75d`).
    pub fn validate(&self) -> Result<(), NodeError> {
        if self.root_node_ips.is_empty() {
            return Err(NodeError::Config(
                "assertion failed: !res.read().root_node_ips.is_empty()".into(),
            ));
        }
        Ok(())
    }

    pub fn default_for_chain(chain: Chain, root_node_ips: Vec<Ipv4Addr>) -> Result<Self, NodeError> {
        let cfg = Self {
            root_node_ips,
            try_new_peers: true,
            chain,
            reserved_peer_ips: Vec::new(),
            n_gossip_peers: 8,
            split_client_blocks: false,
            slow_abci_engine_read_increment: 1,
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

/// Raw metadata comparison matching `src/node115-gossip-reload/lib.rs`:
/// strict lexicographic comparison with signed first dword (`[sec_lo/hi, nsec]`).
pub fn metadata_gate_opens(new: [u32; 3], cached: [u32; 3]) -> bool {
    let normalize = |v: [u32; 3]| (v[0] as i32, v[1], v[2]);
    normalize(new) > normalize(cached)
}

/// Hot-reloadable gossip config holder gated by node #115's metadata stamp check.
#[derive(Clone, Debug)]
pub struct GossipConfigReloader {
    current: GossipConfigInner,
    cached_stamp: [u32; 3],
}

impl GossipConfigReloader {
    pub fn new(initial: GossipConfigInner, initial_stamp: [u32; 3]) -> Result<Self, NodeError> {
        initial.validate()?;
        Ok(Self {
            current: initial,
            cached_stamp: initial_stamp,
        })
    }

    pub fn current(&self) -> &GossipConfigInner {
        &self.current
    }

    pub fn cached_stamp(&self) -> [u32; 3] {
        self.cached_stamp
    }

    /// Apply `candidate` only if `metadata_gate_opens(stamp, cached_stamp)` is true
    /// and `candidate.validate()` succeeds. Returns `Ok(true)` if reloaded.
    pub fn try_reload(
        &mut self,
        stamp: [u32; 3],
        candidate: GossipConfigInner,
    ) -> Result<bool, NodeError> {
        if !metadata_gate_opens(stamp, self.cached_stamp) {
            return Ok(false);
        }
        candidate.validate()?;
        self.current = candidate;
        self.cached_stamp = stamp;
        Ok(true)
    }
}
