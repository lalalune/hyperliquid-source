//! TCP port assignments recovered from node #115 `node/src/node_port.rs`
//! (jump table `0x9394e8`, `0x5a5e3eb..0x5a5e8c4`).

/// All 7 `NodePort` discriminants (`0..=6`) verified from jump table `0x9394e8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum NodePort {
    /// Variant 0 -> port 4001 (gossip mesh)
    Gossip = 0,
    /// Variant 1 -> port 4002 (gossip RPC)
    GossipRpc = 1,
    /// Variant 2 -> port 4003 (consensus transport)
    Consensus = 2,
    /// Variant 3 -> port 4004 (non-validator block stream)
    NvStream = 3,
    /// Variant 4 -> port 4005 (secondary consensus / replica transport)
    ConsensusAux = 4,
    /// Variant 5 -> port 3998 (local uncompressed EVM KVS stream)
    EvmKvs = 5,
    /// Variant 6 -> port 3999 (local uncompressed ABCI stream)
    AbciStream = 6,
}

impl NodePort {
    pub const ALL: [Self; 7] = [
        Self::Gossip,
        Self::GossipRpc,
        Self::Consensus,
        Self::NvStream,
        Self::ConsensusAux,
        Self::EvmKvs,
        Self::AbciStream,
    ];

    /// Exact TCP port number verified from `0x9394e8` (`movw $0xfa1..0xf9f, %ax`).
    pub const fn port(self) -> u16 {
        match self {
            Self::Gossip => 4001,
            Self::GossipRpc => 4002,
            Self::Consensus => 4003,
            Self::NvStream => 4004,
            Self::ConsensusAux => 4005,
            Self::EvmKvs => 3998,
            Self::AbciStream => 3999,
        }
    }

    pub const fn from_port(port: u16) -> Option<Self> {
        match port {
            4001 => Some(Self::Gossip),
            4002 => Some(Self::GossipRpc),
            4003 => Some(Self::Consensus),
            4004 => Some(Self::NvStream),
            4005 => Some(Self::ConsensusAux),
            3998 => Some(Self::EvmKvs),
            3999 => Some(Self::AbciStream),
            _ => None,
        }
    }

    /// Ports `3998` and `3999` bypass LZ4 compression in `node115-tcp-compression-plan`.
    pub const fn is_local_uncompressed(self) -> bool {
        matches!(self, Self::EvmKvs | Self::AbciStream)
    }
}
