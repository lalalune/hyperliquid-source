//! Gossip RPC wire protocol and peer greeting codec built on `bincode-fork`,
//! matching node #115 `0x5aac6a0..0x5aac7b7` (`GossipRpcRequest`),
//! `0x5aac7c0..0x5aacc22` / `0x2e466b0..0x2e469a9` (`GossipRpcResponse`),
//! `0x5a2d540..0x5a2d788` (`ClientBlocksError`), `0x5aabd20..0x5aabf7a` (`GossipStatus`),
//! and `0x5aaa460..0x5aaa628` (`Peers` record).

use bincode_fork::{
    AllowedEnumVariants, ByteVec, Decode, DecodeError, DecoderImpl, Encode, EncodeError,
    EncoderImpl, Reader, Writer,
};
use core::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

pub use node115_greeting_encoder as greeting_encoder;
pub use node115_peer_address_admission as peer_address_admission;

/// Observed `Peers` RPC response limit (`0x2b6a7df`: low32 tag 1 -> `0x2710` = `10_000`).
pub const PEERS_RESPONSE_LIMIT: u64 = 10_000;

/// Peer gossip request envelope matching `node115-gossip-rpc-request` (`0x5aac6a0..0x5aac7b7`):
/// - Variant 0 (`ClientBlocks`): range `[start_height, end_height]`
/// - Variant 1 (`Peers`): request known peer addresses
/// - Variant 2 (`Status` / `GossipStatus`): request node status record
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipRpcRequest {
    ClientBlocks { start_height: u64, end_height: u64 },
    Peers,
    Status,
}

static GOSSIP_REQ_VARIANTS: AllowedEnumVariants = AllowedEnumVariants::Range { min: 0, max: 2 };

impl Encode for GossipRpcRequest {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        match self {
            Self::ClientBlocks {
                start_height,
                end_height,
            } => {
                encoder.write_u32(0)?;
                encoder.write_u64(*start_height)?;
                encoder.write_u64(*end_height)
            }
            Self::Peers => encoder.write_u32(1),
            Self::Status => encoder.write_u32(2),
        }
    }
}

impl Decode for GossipRpcRequest {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        match decoder.read_u32()? {
            0 => {
                let start_height = decoder.read_u64()?;
                let end_height = decoder.read_u64()?;
                Ok(Self::ClientBlocks {
                    start_height,
                    end_height,
                })
            }
            1 => Ok(Self::Peers),
            2 => Ok(Self::Status),
            other => Err(DecodeError::UnexpectedVariant {
                type_name: "GossipRpcRequest",
                allowed: &GOSSIP_REQ_VARIANTS,
                found: other,
            }),
        }
    }
}

/// Hardfork `(version, round)` pair encoded as two `u64` varints inside `GossipStatus`
/// (`0x5aabd70..0x5aabda5`, `.rodata 0x5c9ef1` `"Hardfork with 2 elements"`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hardfork {
    pub version: u64,
    pub round: u64,
}

impl Encode for Hardfork {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_u64(self.version)?;
        encoder.write_u64(self.round)
    }
}

impl Decode for Hardfork {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let version = decoder.read_u64()?;
        let round = decoder.read_u64()?;
        Ok(Self { version, round })
    }
}

/// Exact node #115 `node::gossip_rpc::GossipStatus` (`0x5aabd20..0x5aabf7a`, `Debug` `0x2c7c740..0x2c7c7dc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GossipStatus {
    pub hardfork_height: u64,
    pub latest_height: u64,
    pub hardfork: Hardfork,
    pub latest_consensus_round: Option<u64>,
}

impl Encode for GossipStatus {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_u64(self.hardfork_height)?;
        encoder.write_u64(self.latest_height)?;
        self.hardfork.encode(encoder)?;
        self.latest_consensus_round.encode(encoder)
    }
}

impl Decode for GossipStatus {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let hardfork_height = decoder.read_u64()?;
        let latest_height = decoder.read_u64()?;
        let hardfork = Hardfork::decode(decoder)?;
        let latest_consensus_round = Option::<u64>::decode(decoder)?;
        Ok(Self {
            hardfork_height,
            latest_height,
            hardfork,
            latest_consensus_round,
        })
    }
}

/// Exact 7-variant `node::nv_stream::ClientBlocksError` recovered from node #115:
/// - `Debug` jump table `0x938ee8` (`0x5a2d540..0x5a2d788`)
/// - `Decode` jump table `0x939f28` (`0x5aaca19..0x5aacbca`)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientBlocksError {
    /// Wire tag 0 (`0x93c19f`)
    PeerOnlyRequest,
    /// Wire tag 1 (`0x93c1ae`)
    InvalidRange { start_round: u64, end_round: u64 },
    /// Wire tag 2 (`0x93c1ba`)
    RangeTooLarge,
    /// Wire tag 3 (`0x93c1c7`)
    RateLimited,
    /// Wire tag 4 (`0x93b3b7`)
    NoClientBlocks,
    /// Wire tag 5 (`0x93c1d2`)
    RoundTooSmall {
        start_round: u64,
        first_parent_round: u64,
    },
    /// Wire tag 6 (`0x93c1f1`)
    RoundTooLarge { end_round: u64, max_round: u64 },
}

static CLIENT_BLOCKS_ERR_VARIANTS: AllowedEnumVariants =
    AllowedEnumVariants::Range { min: 0, max: 6 };

impl fmt::Display for ClientBlocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerOnlyRequest => write!(f, "Peer-only request"),
            Self::InvalidRange {
                start_round,
                end_round,
            } => write!(f, "InvalidRange {{ start_round: {start_round}, end_round: {end_round} }}"),
            Self::RangeTooLarge => write!(f, "RangeTooLarge"),
            Self::RateLimited => write!(f, "rate limited"),
            Self::NoClientBlocks => write!(f, "no client blocks to serve"),
            Self::RoundTooSmall {
                start_round,
                first_parent_round,
            } => write!(
                f,
                "RoundTooSmall {{ start_round: {start_round}, first_parent_round: {first_parent_round} }}"
            ),
            Self::RoundTooLarge {
                end_round,
                max_round,
            } => write!(
                f,
                "RoundTooLarge {{ end_round: {end_round}, max_round: {max_round} }}"
            ),
        }
    }
}

impl std::error::Error for ClientBlocksError {}

impl Encode for ClientBlocksError {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        match *self {
            Self::PeerOnlyRequest => encoder.write_u32(0),
            Self::InvalidRange {
                start_round,
                end_round,
            } => {
                encoder.write_u32(1)?;
                encoder.write_u64(start_round)?;
                encoder.write_u64(end_round)
            }
            Self::RangeTooLarge => encoder.write_u32(2),
            Self::RateLimited => encoder.write_u32(3),
            Self::NoClientBlocks => encoder.write_u32(4),
            Self::RoundTooSmall {
                start_round,
                first_parent_round,
            } => {
                encoder.write_u32(5)?;
                encoder.write_u64(start_round)?;
                encoder.write_u64(first_parent_round)
            }
            Self::RoundTooLarge {
                end_round,
                max_round,
            } => {
                encoder.write_u32(6)?;
                encoder.write_u64(end_round)?;
                encoder.write_u64(max_round)
            }
        }
    }
}

impl Decode for ClientBlocksError {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        match decoder.read_u32()? {
            0 => Ok(Self::PeerOnlyRequest),
            1 => Ok(Self::InvalidRange {
                start_round: decoder.read_u64()?,
                end_round: decoder.read_u64()?,
            }),
            2 => Ok(Self::RangeTooLarge),
            3 => Ok(Self::RateLimited),
            4 => Ok(Self::NoClientBlocks),
            5 => Ok(Self::RoundTooSmall {
                start_round: decoder.read_u64()?,
                first_parent_round: decoder.read_u64()?,
            }),
            6 => Ok(Self::RoundTooLarge {
                end_round: decoder.read_u64()?,
                max_round: decoder.read_u64()?,
            }),
            other => Err(DecodeError::UnexpectedVariant {
                type_name: "ClientBlocksError",
                allowed: &CLIENT_BLOCKS_ERR_VARIANTS,
                found: other,
            }),
        }
    }
}

static NODE_IP_VARIANTS: AllowedEnumVariants = AllowedEnumVariants::Range { min: 0, max: 0 };

/// Peer record matching node #115 `0x5aaa460..0x5aaa628` (`NodeIp::Ip(Ipv4Addr)`, `bool`, `u64`),
/// byte-identical on the wire to `node115-gossip-address-vector::Record` and
/// `node115-peers-response-set::Peer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerEntry {
    pub ip: Ipv4Addr,
    pub is_validator: bool,
    pub value: u64,
}

impl PeerEntry {
    pub fn socket_addr(self, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip, port)
    }
}

impl Encode for PeerEntry {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        // NodeIp enum variant 0 = Ip(Ipv4Addr) (0x5aaa475..0x5aaa52f)
        encoder.write_u32(0)?;
        encoder.write_bytes(&self.ip.octets())?;
        self.is_validator.encode(encoder)?;
        encoder.write_u64(self.value)
    }
}

impl Decode for PeerEntry {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let variant = decoder.read_u32()?;
        if variant != 0 {
            return Err(DecodeError::UnexpectedVariant {
                type_name: "NodeIp",
                allowed: &NODE_IP_VARIANTS,
                found: variant,
            });
        }
        let mut octets = [0u8; 4];
        decoder.claim_bytes_read(4)?;
        decoder.reader_mut().read(&mut octets)?;
        let is_validator = bool::decode(decoder)?;
        let value = decoder.read_u64()?;
        Ok(Self {
            ip: Ipv4Addr::from(octets),
            is_validator,
            value,
        })
    }
}

/// Exact node #115 `GossipRpcResponse` wire envelope (`0x5aac7c0..0x5aacc22` & `0x2e466b0..0x2e469a9`):
/// - Tag 0: `ClientBlocks(Result<Vec<ByteVec>, ClientBlocksError>)`
/// - Tag 1: `Peers(Vec<PeerEntry>)`
/// - Tag 2: `GossipStatus(Option<GossipStatus>)`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipRpcResponse {
    ClientBlocks(Result<Vec<ByteVec>, ClientBlocksError>),
    Peers(Vec<PeerEntry>),
    GossipStatus(Option<GossipStatus>),
}

static GOSSIP_RESP_VARIANTS: AllowedEnumVariants = AllowedEnumVariants::Range { min: 0, max: 2 };

impl Encode for GossipRpcResponse {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        match self {
            Self::ClientBlocks(res) => {
                encoder.write_u32(0)?;
                res.encode(encoder)
            }
            Self::Peers(peers) => {
                encoder.write_u32(1)?;
                peers.encode(encoder)
            }
            Self::GossipStatus(st) => {
                encoder.write_u32(2)?;
                st.encode(encoder)
            }
        }
    }
}

impl Decode for GossipRpcResponse {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        match decoder.read_u32()? {
            0 => Ok(Self::ClientBlocks(
                Result::<Vec<ByteVec>, ClientBlocksError>::decode(decoder)?,
            )),
            1 => Ok(Self::Peers(Vec::<PeerEntry>::decode(decoder)?)),
            2 => Ok(Self::GossipStatus(Option::<GossipStatus>::decode(decoder)?)),
            other => Err(DecodeError::UnexpectedVariant {
                type_name: "GossipRpcResponse",
                allowed: &GOSSIP_RESP_VARIANTS,
                found: other,
            }),
        }
    }
}
