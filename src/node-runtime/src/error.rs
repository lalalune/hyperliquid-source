//! Node runtime error variants and diagnostic messages observed in node #115
//! `.rodata` (`0x92a930..0x92aae0`).

use core::fmt;

/// Runtime error variants observed in `node/src/node.rs` & `node/src/connections.rs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeError {
    Gossip(String),
    GossipRpc(String),
    ClientBlockParentRound { expected: u64, found: u64 },
    Consensus(String),
    QueryClientBlocks(String),
    PeerFull,
    PeerTimeout,
    PeerRateLimit,
    PeerNoQuorumL1Hash,
    PeerInconsistentGreeting,
    AbciStateDeserialize(String),
    NvStreamClientBlockSend(String),
    L1HashHeightMismatch { expected: u64, found: u64 },
    L1HashMismatch,
    AbciDigestMismatch,
    L1HashNoQuorum,
    EvmKvsRead(String),
    EvmKvsWrite(String),
    ThreadJoin(String),
    Chain { expected: String, found: String },
    Cli(String),
    Config(String),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gossip(s) => write!(f, "Gossip error: {s}"),
            Self::GossipRpc(s) => write!(f, "GossipRpc error: {s}"),
            Self::ClientBlockParentRound { expected, found } => {
                write!(f, "ClientBlockParentRound expected={expected} found={found}")
            }
            Self::Consensus(s) => write!(f, "Consensus error: {s}"),
            Self::QueryClientBlocks(s) => write!(f, "QueryClientBlocks error: {s}"),
            Self::PeerFull => write!(f, "Peer full"),
            Self::PeerTimeout => write!(f, "Timed out connecting to peer"),
            Self::PeerRateLimit => write!(f, "Rate limited by peer"),
            Self::PeerNoQuorumL1Hash => write!(f, "Peer no quorum l1 hash"),
            Self::PeerInconsistentGreeting => write!(f, "Peer inconsistent greeting"),
            Self::AbciStateDeserialize(s) => write!(f, "Abci state not deserializable: {s}"),
            Self::NvStreamClientBlockSend(s) => write!(f, "Could not send client block: {s}"),
            Self::L1HashHeightMismatch { expected, found } => {
                write!(f, "L1HashHeightMismatch expected={expected} found={found}")
            }
            Self::L1HashMismatch => write!(f, "L1HashMismatch"),
            Self::AbciDigestMismatch => write!(f, "AbciDigestMismatch"),
            Self::L1HashNoQuorum => write!(f, "L1 hash no quorum"),
            Self::EvmKvsRead(s) => write!(f, "EvmKvsRead: {s}"),
            Self::EvmKvsWrite(s) => write!(f, "EvmKvsWrite: {s}"),
            Self::ThreadJoin(s) => write!(f, "Thread join error: {s}"),
            Self::Chain { expected, found } => {
                write!(f, "Incorrect chain: expected={expected} found={found}")
            }
            Self::Cli(s) => write!(f, "failed to parse hl-node args: {s}"),
            Self::Config(s) => write!(f, "config error: {s}"),
        }
    }
}

impl std::error::Error for NodeError {}
