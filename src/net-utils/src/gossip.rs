//! Gossip RPC wire protocol and peer greeting codec built on `bincode-fork` and
//! verified node #115 greeting/address-admission micro-crates.

use bincode_fork::{ByteVec, Decode, DecodeError, DecoderImpl, Encode, EncodeError, EncoderImpl, Reader, Writer};
use std::net::{Ipv4Addr, SocketAddrV4};

pub use node115_greeting_encoder as greeting_encoder;
pub use node115_peer_address_admission as peer_address_admission;

/// Peer gossip request envelope matching `node115-gossip-rpc-request`:
/// - Variant 0 (`ClientBlocks`): range `[start_height, end_height]`
/// - Variant 1 (`Peers`): request known peer addresses
/// - Variant 2 (`Status` / `Ping`): request node status record
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipRpcRequest {
    ClientBlocks { start_height: u64, end_height: u64 },
    Peers,
    Status,
}

static GOSSIP_REQ_VARIANTS: bincode_fork::AllowedEnumVariants =
    bincode_fork::AllowedEnumVariants::Range { min: 0, max: 2 };

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

/// Peer address entry matching `node115-gossip-address-vector` (IPv4 + port + flag).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerEntry {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub is_validator: bool,
}

impl PeerEntry {
    pub fn socket_addr(self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip, self.port)
    }
}

impl Encode for PeerEntry {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_bytes(&self.ip.octets())?;
        encoder.write_u16(self.port)?;
        self.is_validator.encode(encoder)
    }
}

impl Decode for PeerEntry {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let mut octets = [0u8; 4];
        decoder.claim_bytes_read(4)?;
        decoder.reader_mut().read(&mut octets)?;
        let port = decoder.read_u16()?;
        let is_validator = bool::decode(decoder)?;
        Ok(Self {
            ip: Ipv4Addr::from(octets),
            port,
            is_validator,
        })
    }
}

/// Gossip RPC response envelope covering Peers, ClientBlocks, and Status responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipRpcResponse {
    Peers(Vec<PeerEntry>),
    ClientBlocks(Result<Vec<ByteVec>, String>),
    Status(Option<[u64; 4]>),
}

static GOSSIP_RESP_VARIANTS: bincode_fork::AllowedEnumVariants =
    bincode_fork::AllowedEnumVariants::Range { min: 0, max: 2 };

impl Encode for GossipRpcResponse {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        match self {
            Self::Peers(peers) => {
                encoder.write_u32(0)?;
                peers.encode(encoder)
            }
            Self::ClientBlocks(res) => {
                encoder.write_u32(1)?;
                res.encode(encoder)
            }
            Self::Status(st) => {
                encoder.write_u32(2)?;
                st.encode(encoder)
            }
        }
    }
}

impl Decode for GossipRpcResponse {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        match decoder.read_u32()? {
            0 => Ok(Self::Peers(Vec::<PeerEntry>::decode(decoder)?)),
            1 => Ok(Self::ClientBlocks(
                Result::<Vec<ByteVec>, String>::decode(decoder)?,
            )),
            2 => Ok(Self::Status(Option::<[u64; 4]>::decode(decoder)?)),
            other => Err(DecodeError::UnexpectedVariant {
                type_name: "GossipRpcResponse",
                allowed: &GOSSIP_RESP_VARIANTS,
                found: other,
            }),
        }
    }
}
