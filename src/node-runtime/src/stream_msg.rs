//! Shared serialized stream messages and ABCI/EVM-KVS stream session helpers
//! matching node #115 `node/src/{stream_msg,abci_stream,evm_kvs,abci_latency_sampler}.rs`.

use std::net::{SocketAddr, SocketAddrV4};
use std::num::TryFromIntError;
use std::sync::Arc;

use bincode_fork::{ByteVec, Encode, encode_to_vec, standard};
pub use dex_registry::date_time_display::{Date, Time};
use dex_registry::{date_time_display, format_address_hex, msgpack};
use net_utils::{AbciStreamGreeting, DEFAULT_MAX_FRAME_BYTES, EvmKvsMsg, TcpClient, TcpListener};

use crate::error::NodeError;

/// Serialized payload wrapped in `Arc<Vec<u8>>` for zero-copy fan-out,
/// matching `node/src/stream_msg.rs:43:48` (`0x4e09ab0..0x4e09bff`, 40-byte `ArcInner<Vec<u8>>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedStreamMsg(Arc<Vec<u8>>);

/// Borrowed fields for the named MessagePack replica record observed at `0x4d6d890`.
/// Each bundle slice and the optional response slice must already contain one complete
/// encoded MessagePack value, as produced by the corresponding nested value writer.
#[derive(Clone, Copy, Debug)]
pub struct ReplicaStreamRecord<'a> {
    pub date: Date,
    pub time: Time,
    pub encoded_bundles: &'a [&'a [u8]],
    pub round: u64,
    pub parent_round: u64,
    pub hardfork_version: u64,
    pub hardfork_round: u64,
    pub proposer: [u8; 20],
    pub encoded_responses: Option<&'a [u8]>,
    pub height: u64,
}

fn write_uint_field(bytes: &mut Vec<u8>, name: &[u8], value: u64) {
    msgpack::write_str(bytes, name);
    msgpack::write_u64(bytes, value);
}

impl SharedStreamMsg {
    /// Encode the named archive envelope and share its owned bytes. The source limit
    /// for a MessagePack array is `u32::MAX` entries, including on a 64-bit host.
    pub fn from_replica_record(record: &ReplicaStreamRecord<'_>) -> Result<Self, TryFromIntError> {
        let bundles = u32::try_from(record.encoded_bundles.len())?;
        let mut bytes = Vec::new();
        msgpack::write_map_len(&mut bytes, 3);
        msgpack::write_str(&mut bytes, b"abci_block");
        msgpack::write_map_len(&mut bytes, 6);
        msgpack::write_str(&mut bytes, b"time");
        let date = date_time_display::render_date(record.date);
        let time = date_time_display::render_time(record.time);
        let datetime = format!("{}T{}", date.as_str(), time.as_str());
        msgpack::write_str(&mut bytes, datetime.as_bytes());
        msgpack::write_str(&mut bytes, b"signed_action_bundles");
        msgpack::write_array_len(&mut bytes, bundles as usize);
        for bundle in record.encoded_bundles {
            bytes.extend_from_slice(bundle);
        }
        write_uint_field(&mut bytes, b"round", record.round);
        write_uint_field(&mut bytes, b"parent_round", record.parent_round);
        msgpack::write_str(&mut bytes, b"hardfork");
        msgpack::write_map_len(&mut bytes, 2);
        write_uint_field(&mut bytes, b"version", record.hardfork_version);
        write_uint_field(&mut bytes, b"round", record.hardfork_round);
        msgpack::write_str(&mut bytes, b"proposer");
        msgpack::write_str(&mut bytes, format_address_hex(&record.proposer).as_bytes());
        msgpack::write_str(&mut bytes, b"resps");
        match record.encoded_responses {
            Some(response) => bytes.extend_from_slice(response),
            None => bytes.push(0xc0),
        }
        write_uint_field(&mut bytes, b"height", record.height);
        Ok(Self::from_bytes(bytes))
    }

    /// Wrap a payload serialized with the explicit bincode-fork configuration.
    pub fn encode_bincode<E: Encode>(msg: &E) -> Result<Self, NodeError> {
        let bytes = encode_to_vec(msg, standard())
            .map_err(|e| NodeError::NvStreamClientBlockSend(e.to_string()))?;
        Ok(Self(Arc::new(bytes)))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(Arc::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.0)
    }
}

/// Serve one `AbciStream` greeting handshake on `listener` (port 3999 protocol):
/// receives client greeting, validates it with `accept_client`, and replies with `server_greeting`.
pub fn serve_abci_stream_greeting<F>(
    listener: &TcpListener,
    server_greeting: &AbciStreamGreeting,
    accept_client: F,
) -> Result<AbciStreamGreeting, NodeError>
where
    F: FnOnce(&AbciStreamGreeting) -> bool,
{
    let (mut stream, _addr) = listener
        .accept()
        .map_err(|e| NodeError::Gossip(e.to_string()))?;
    let peer_greeting: AbciStreamGreeting = stream
        .recv_bincode(Some(DEFAULT_MAX_FRAME_BYTES))
        .map_err(|e| NodeError::AbciStateDeserialize(e.to_string()))?;
    if !accept_client(&peer_greeting) {
        return Err(NodeError::PeerInconsistentGreeting);
    }
    stream
        .send_bincode(server_greeting)
        .map_err(|e| NodeError::Gossip(e.to_string()))?;
    Ok(peer_greeting)
}

/// Perform client-side `AbciStream` greeting exchange against `addr`.
pub fn exchange_abci_stream_greeting(
    addr: SocketAddrV4,
    client_greeting: &AbciStreamGreeting,
) -> Result<AbciStreamGreeting, NodeError> {
    let mut client = TcpClient::new(SocketAddr::V4(addr), "abci_stream")
        .map_err(|e| NodeError::Gossip(e.to_string()))?;
    client
        .connect()
        .map_err(|e| NodeError::Gossip(e.to_string()))?;
    client
        .send_bincode_and_read_response(client_greeting, Some(DEFAULT_MAX_FRAME_BYTES))
        .map_err(|e| NodeError::AbciStateDeserialize(e.to_string()))
}

/// Stream EVM KVS batches followed by `EvmKvsMsg::Done` (port 3998 protocol).
pub fn serve_evm_kvs_stream(
    listener: &TcpListener,
    batches: &[Vec<(ByteVec, ByteVec)>],
) -> Result<usize, NodeError> {
    let (mut stream, _addr) = listener
        .accept()
        .map_err(|e| NodeError::EvmKvsWrite(e.to_string()))?;
    let mut total_pairs = 0usize;
    for batch in batches {
        total_pairs += batch.len();
        stream
            .send_bincode(EvmKvsMsg::Batch(batch.clone()))
            .map_err(|e| NodeError::EvmKvsWrite(e.to_string()))?;
    }
    stream
        .send_bincode(EvmKvsMsg::Done)
        .map_err(|e| NodeError::EvmKvsWrite(e.to_string()))?;
    Ok(total_pairs)
}

/// Key-value byte pairs received from an `EvmKvs` stream (port 3998).
pub type EvmKvsPairs = Vec<(Vec<u8>, Vec<u8>)>;

/// Receive all `EvmKvsMsg::Batch` frames until `EvmKvsMsg::Done` from `addr`.
pub fn recv_evm_kvs_stream(addr: SocketAddrV4) -> Result<EvmKvsPairs, NodeError> {
    let raw = std::net::TcpStream::connect(SocketAddr::V4(addr))
        .map_err(|e| NodeError::EvmKvsRead(e.to_string()))?;
    let mut framed =
        net_utils::FramedTcpStream::new(raw, DEFAULT_MAX_FRAME_BYTES, DEFAULT_MAX_FRAME_BYTES)
            .map_err(|e| NodeError::EvmKvsRead(e.to_string()))?;
    let mut pairs = Vec::new();
    loop {
        let msg: EvmKvsMsg = framed
            .recv_bincode(Some(DEFAULT_MAX_FRAME_BYTES))
            .map_err(|e| NodeError::EvmKvsRead(e.to_string()))?;
        match msg {
            EvmKvsMsg::Batch(batch) => {
                for (k, v) in batch {
                    pairs.push((k.0, v.0));
                }
            }
            EvmKvsMsg::Done => break,
        }
    }
    Ok(pairs)
}

/// Lightweight ABCI latency ring sampler matching `node/src/abci_latency_sampler.rs`.
#[derive(Clone, Debug)]
pub struct AbciLatencySampler {
    samples_ms: Vec<f64>,
    capacity: usize,
    cursor: usize,
}

impl AbciLatencySampler {
    pub fn new(capacity: usize) -> Self {
        Self {
            samples_ms: Vec::with_capacity(capacity),
            capacity: capacity.max(1),
            cursor: 0,
        }
    }

    pub fn record_ms(&mut self, latency_ms: f64) {
        if self.samples_ms.len() < self.capacity {
            self.samples_ms.push(latency_ms);
        } else {
            self.samples_ms[self.cursor] = latency_ms;
            self.cursor = (self.cursor + 1) % self.capacity;
        }
    }

    pub fn mean_ms(&self) -> Option<f64> {
        if self.samples_ms.is_empty() {
            return None;
        }
        let sum: f64 = self.samples_ms.iter().sum();
        Some(sum / (self.samples_ms.len() as f64))
    }

    pub fn len(&self) -> usize {
        self.samples_ms.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples_ms.is_empty()
    }
}
