//! Node #115 selected Peers response: frame bytes to a normalized peer set.
//!
//! One offline call path for the response to a Peers request whose limit
//! selector is raw tag 1 (limit 10,000): five-byte TCP frame, optional
//! size-prefixed LZ4, the existing selected-response decoder, then the new
//! part, the sort / same-key replacement / small-set-or-tree split performed
//! by the wrapper at `0x2dd2980`. Frame, LZ4 and row decoding are the existing
//! crates, unchanged. This is a logical API: it does not claim the native
//! async ABI, allocation or unwind behaviour, peer identity or any network
//! behaviour, and it does not read the bytes as addresses or ports.
#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::io::{Cursor, Read};

use node115_gossip_response_composed::{decode_prefix, AddressRecord, Response};
pub use node115_gossip_response_composed::{address_vector, Error as ResponseError};
pub use node115_gossip_response_v2_envelope as outer;
pub use node115_tcp_stream_frame_lz4::{FrameError, FrameErrorKind, ReadStage};
use node115_tcp_stream_frame_lz4::{read_frame, Limits};

/// Limit selected for a Peers request (`0x2b6a7df`: low32 tag 1 -> 0x2710). It is
/// used three times on this path: frame payload length, LZ4 decoded capacity
/// and the row decoder's charge limit.
pub const PEERS_LIMIT: u64 = 10_000;

/// Largest kept-row count stored as a small set; larger counts go to a tree
/// (`0x2dd2b3d`: `cmp rcx, 0x40; jbe`).
pub const SMALL_SET_MAX: usize = 64;

/// Longest input the wrapper sorts with the plain insertion sort (`0x2dd2a5c`).
pub const INSERTION_SORT_MAX: usize = 20;

/// One logical row: four wire bytes, a boolean and a raw scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub key: [u8; 4],
    pub flag: bool,
    pub value: u64,
}

/// Which representation the wrapper builds. Only the choice is modelled, not
/// the node layout of either container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Storage {
    Small,
    Tree,
}

/// Rows ordered by the four key bytes compared as bytes, one row per key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerSet {
    peers: Vec<Peer>,
    winners: Vec<usize>,
}

impl PeerSet {
    pub fn peers(&self) -> &[Peer] {
        &self.peers
    }
    pub fn len(&self) -> usize {
        self.peers.len()
    }
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
    pub fn storage(&self) -> Storage {
        if self.peers.len() <= SMALL_SET_MAX {
            Storage::Small
        } else {
            Storage::Tree
        }
    }
    pub fn get(&self, key: [u8; 4]) -> Option<&Peer> {
        self.peers
            .binary_search_by(|p| p.key.cmp(&key))
            .ok()
            .map(|i| &self.peers[i])
    }
    /// Index, in the wire vector, of the row that was kept for `peers()[i]`.
    pub fn source_index(&self, i: usize) -> usize {
        self.winners[i]
    }
}

#[derive(Clone, Copy)]
struct Row {
    record: AddressRecord,
    index: usize,
}

fn key_of(row: &Row) -> [u8; 4] {
    (row.record.fixed as u32).to_le_bytes()
}

/// Port of `0x26ca410` with offset 1: a row moves left only while it is
/// strictly smaller than its left neighbour, so equal keys keep input order.
fn insertion_sort(rows: &mut [Row]) {
    for i in 1..rows.len() {
        if key_of(&rows[i]) < key_of(&rows[i - 1]) {
            let cur = rows[i];
            let mut j = i;
            while j > 0 && key_of(&cur) < key_of(&rows[j - 1]) {
                rows[j] = rows[j - 1];
                j -= 1;
            }
            rows[j] = cur;
        }
    }
}

/// Port of the in-place pass `0x2dd2a7b..0x2dd2b3d`: within a run of equal keys
/// the last row of the sorted order survives and the kept prefix is shortened.
fn keep_last_of_equal_keys(rows: &mut Vec<Row>) {
    let len = rows.len();
    let Some(first) = (1..len).find(|&j| key_of(&rows[j]) == key_of(&rows[j - 1])) else {
        return;
    };
    rows.swap(first, first - 1);
    let mut kept = first;
    for idx in first + 1..len {
        if key_of(&rows[idx]) != key_of(&rows[kept - 1]) {
            rows[kept] = rows[idx];
            kept += 1;
        } else {
            rows.swap(idx, kept - 1);
        }
    }
    rows.truncate(kept);
}

/// Sort the wire rows by key bytes, keep the last row of every equal-key run
/// and report the storage the wrapper would choose.
///
/// Fewer than two rows are not sorted. Two to twenty use the insertion sort
/// above. Twenty-one or more use the node's long stable sort; this crate calls
/// the standard library's stable sort for that branch, which yields the same
/// order because a stable sort of a total key order is unique (`TIES.md`
/// reads the long sort's comparison and merge sites in the binary).
pub fn normalize(wire: &[AddressRecord]) -> PeerSet {
    let mut rows: Vec<Row> = wire
        .iter()
        .enumerate()
        .map(|(index, &record)| Row { record, index })
        .collect();
    if rows.len() >= 2 {
        if rows.len() <= INSERTION_SORT_MAX {
            insertion_sort(&mut rows);
        } else {
            rows.sort_by(|a, b| -> Ordering { key_of(a).cmp(&key_of(b)) });
        }
        keep_last_of_equal_keys(&mut rows);
    }
    PeerSet {
        peers: rows
            .iter()
            .map(|r| Peer {
                key: key_of(r),
                flag: r.record.flag,
                value: r.record.value,
            })
            .collect(),
        winners: rows.iter().map(|r| r.index).collect(),
    }
}

/// A well-formed response of a kind other than the address vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtherResponse {
    Variant2,
    ClientBlocksError,
    ResultSuccessBoundary,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The stream ended before the first header byte.
    NoFrame,
    Frame(FrameError),
    /// The payload did not decode as a selected response.
    Response(ResponseError),
    /// New API policy: only the address-vector response is accepted for a Peers
    /// request. The node's own check of request/response agreement is not claimed.
    NotPeers(OtherResponse),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Decoded {
    pub set: PeerSet,
    /// Rows on the wire before replacement.
    pub wire_rows: usize,
    /// The frame flag was exactly 1 and the LZ4 step ran.
    pub compressed: bool,
    /// Logical charge after the response decode (outer tag, count, 13 per row).
    pub charged: u64,
    /// Decoded payload bytes after the vector; the node's EOF check is not assumed.
    pub payload_remaining: usize,
}

/// Decode a response payload (frame already removed).
pub fn decode_payload(payload: &[u8]) -> Result<(PeerSet, usize, u64, usize), Error> {
    let out = decode_prefix(payload, Some(PEERS_LIMIT), 0);
    match out.result {
        Ok(Response::Addresses(rows)) => Ok((
            normalize(&rows),
            rows.len(),
            out.charged,
            out.remaining.len(),
        )),
        Ok(Response::Variant2(_)) => Err(Error::NotPeers(OtherResponse::Variant2)),
        Ok(Response::ClientBlocksError(_)) => Err(Error::NotPeers(OtherResponse::ClientBlocksError)),
        Ok(Response::ResultSuccessBoundary) => {
            Err(Error::NotPeers(OtherResponse::ResultSuccessBoundary))
        }
        Err(e) => Err(Error::Response(e)),
    }
}

/// Read one frame from `reader` and decode it as a Peers response.
pub fn decode_stream<R: Read>(reader: &mut R) -> Result<Decoded, Error> {
    let limits = Limits {
        frame_payload: PEERS_LIMIT,
        decoded_capacity: PEERS_LIMIT,
    };
    let frame = read_frame(reader, limits)
        .map_err(Error::Frame)?
        .ok_or(Error::NoFrame)?;
    let (set, wire_rows, charged, payload_remaining) = decode_payload(&frame.payload)?;
    Ok(Decoded {
        set,
        wire_rows,
        compressed: frame.was_compressed,
        charged,
        payload_remaining,
    })
}

/// Decode the first frame in `bytes`; also returns the bytes after the frame.
pub fn decode_frame(bytes: &[u8]) -> Result<(Decoded, &[u8]), Error> {
    let mut cursor = Cursor::new(bytes);
    let decoded = decode_stream(&mut cursor)?;
    let used = cursor.position() as usize;
    Ok((decoded, &bytes[used..]))
}
