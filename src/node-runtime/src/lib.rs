//! Independently authored Rust reconstruction of Hyperliquid node #115 runtime
//! (`node-runtime`, target SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
//!
//! Unifies CLI parsing & validation, startup output/directory admission, `NodePort`
//! assignments, `GossipConfigInner` & mtime hot-reload, firewall IP diffing,
//! peer discovery, block synchronization with `BlockSink`/`ConsensusHook` seams,
//! and restart backoff/threshold handling over `net-utils` and `bincode-fork`.

#![forbid(unsafe_code)]

pub mod artifact;
pub mod cli;
pub mod error;
pub mod firewall;
pub mod gossip_config;
pub mod node_port;
pub mod peer_sync;
pub mod restart;
pub mod stream_msg;

pub use artifact::{
    ARTIFACT_POLL_INTERVAL_SECS, ArtifactUpdater, INDEX_DID_NOT_INCREASE_MSG, IndexedArtifact,
    IndexedArtifactContent, NODE_ARTIFACT_DIR, NODE_METADATA_FILENAME, VISOR_METADATA_FILENAME,
};
pub use bincode_fork;
pub use cli::{
    Chain, CliArgs, Command, NODE115_BUILD_STAMP, PROGRAM_ABOUT, PROGRAM_NAME, PROGRAM_VERSION,
    parse_args, replica_style_str,
};
pub use error::NodeError;
pub use firewall::{
    FirewallDiff, FirewallIps, PUBLISHER_VISOR_TIME_LOCK_DIR, UNREACHABLE_PEERS_MSG,
    VISOR_STAGING_NOT_READY, VISOR_TIME_LOCK_DIR, check_peer_reachability,
};
pub use gossip_config::{
    GossipConfigInner, GossipConfigReloader, OVERRIDE_GOSSIP_CONFIG_FILENAME, metadata_gate_opens,
};
pub use net_utils;
pub use node115_cli_validators as cli_validators;
pub use node115_startup_output::{OutputSettings, ReplicaStyle, StyleError};
pub use node_port::NodePort;
pub use peer_sync::{
    AcceptAllConsensus, BlockSink, ConsensusHook, MemoryBlockStore, PeerTable,
    discover_peers_from, serve_one_gossip_rpc, sync_client_blocks,
};
pub use restart::{DEFAULT_RESTART_CAP_SECS, RestartSupervisor, WaitPlan};
pub use stream_msg::{
    AbciLatencySampler, EvmKvsPairs, SharedStreamMsg, exchange_abci_stream_greeting,
    recv_evm_kvs_stream, serve_abci_stream_greeting, serve_evm_kvs_stream,
};
