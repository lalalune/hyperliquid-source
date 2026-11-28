#!/usr/bin/env python3
"""Verify 8 strictly disjoint first-party transport & node-runtime compiled-byte FDE matches
(6,117 B: 5 transport = 2,435 B; 3 node-runtime = 3,682 B) for node #115."""

from __future__ import annotations

import argparse
import copy
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_JSON = REPO_ROOT / "research" / "byte-windows.json"
WORK_ITEMS_DIR = REPO_ROOT / "research" / "work-items"
RECORDS_PATH = PACKET_DIR / "records.json"
BODIES_PATH = PACKET_DIR / "bodies.bin"

sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "research" / "work-items" / "RE-002-node115-std-census"))
from byte_progress import compare  # noqa: E402
from census import object_functions  # noqa: E402
from elf_index import sections  # noqa: E402

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032

# 8 strictly disjoint first-party Stream C FDEs (6,117 B):
#   - transport:    5 FDEs = 2,435 B (2 bincode_fork Decode codecs, 1 Display impl, 2 Debug impls)
#   - node-runtime: 3 FDEs = 3,682 B (GossipConfigInner Debug + 2 ThinLTO CGUs of NodeError Debug)
TARGET_WINDOWS = [
    (
        0x2E464F0,
        0x2E466A7,
        "transport-client-blocks-error-decode-2e464f0",
        "transport",
        "bincode_decode",
        "transport gossip <ClientBlocksError as bincode_fork::Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (0x2e464f0)",
    ),
    (
        0x564A710,
        0x564AD5A,
        "node-runtime-node-error-debug-cgu1-564a710",
        "node-runtime",
        "debug_fmt",
        "node-runtime <NodeError as core::fmt::Debug>::fmt (CGU 1, 22-variant niche-tagged enum, 0x564a710)",
    ),
    (
        0x5656A20,
        0x5656BEE,
        "node-runtime-gossip-config-inner-debug-5656a20",
        "node-runtime",
        "debug_fmt",
        "node-runtime <GossipConfigInner as core::fmt::Debug>::fmt (6-field gossip config, 0x5656a20)",
    ),
    (
        0x5A2D540,
        0x5A2D788,
        "transport-ref-client-blocks-error-debug-5a2d540",
        "transport",
        "debug_fmt",
        "transport gossip <&ClientBlocksError as core::fmt::Debug>::fmt (inlined first-party Debug body, 0x5a2d540)",
    ),
    (
        0x5A2E730,
        0x5A2EA13,
        "transport-ref-gossip-rpc-response-debug-5a2e730",
        "transport",
        "debug_fmt",
        "transport gossip <&GossipRpcResponse as core::fmt::Debug>::fmt (inlined first-party 3-variant niche Debug body, 0x5a2e730)",
    ),
    (
        0x5A8A880,
        0x5A8AECA,
        "node-runtime-node-error-debug-cgu2-5a8a880",
        "node-runtime",
        "debug_fmt",
        "node-runtime <NodeError as core::fmt::Debug>::fmt (CGU 2, 22-variant niche-tagged enum, 0x5a8a880)",
    ),
    (
        0x5AAA0C0,
        0x5AAA24A,
        "transport-client-blocks-error-display-5aaa0c0",
        "transport",
        "display_fmt",
        "transport gossip <ClientBlocksError as core::fmt::Display>::fmt (7-variant wire error Display, 0x5aaa0c0)",
    ),
    (
        0x5AAC6A0,
        0x5AAC7B7,
        "transport-gossip-rpc-request-decode-5aac6a0",
        "transport",
        "bincode_decode",
        "transport gossip <GossipRpcRequest as bincode_fork::Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (0x5aac6a0)",
    ),
]

BINCODE_FORK_LIB_RS = r"""#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum IntegerType {
    U8 = 0, U16 = 1, U32 = 2, U64 = 3, U128 = 4, Usize = 5,
    I8 = 6, I16 = 7, I32 = 8, I64 = 9, I128 = 10, Isize = 11,
    Reserved = 12,
}

#[derive(Debug)]
pub enum AllowedEnumVariants {
    Range { min: u32, max: u32 },
    Allowed(&'static [u32]),
}

#[non_exhaustive]
#[derive(Debug)]
pub enum DecodeError {
    UnexpectedEnd { additional: usize },
    InvalidBytesLength,
    LimitExceeded,
    InvalidIntegerType { expected: IntegerType, found: IntegerType },
    NonZeroTypeIsZero { non_zero_type: IntegerType },
    UnexpectedVariant { type_name: &'static str, allowed: &'static AllowedEnumVariants, found: u32 },
    Utf8 { inner: core::str::Utf8Error },
    InvalidCharEncoding([u8; 4]),
    InvalidBooleanValue(u8),
    ArrayLengthMismatch { required: usize, found: usize },
    OutsideUsizeRange(u64),
    EmptyEnum { type_name: &'static str },
    InvalidDuration { secs: i64, nanos: u32 },
    InvalidSystemTime { duration: core::time::Duration },
    CStringNulError { position: usize },
    Io { inner: std::io::Error, additional: usize },
    Other(&'static str),
    OtherString(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Endian { Little, Big }

#[derive(Clone, Copy)]
pub struct Configuration {
    pub limit: Option<usize>,
}

impl Configuration {
    #[inline(always)]
    pub fn limit(&self) -> Option<usize> { self.limit }
}

pub trait Reader {
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), DecodeError>;
    #[inline] fn peek_read(&mut self, _n: usize) -> Option<&[u8]> { None }
    #[inline] fn consume(&mut self, _n: usize) {}
}

pub struct SliceReader<'storage> {
    pub slice: &'storage [u8],
}

impl<'storage> Reader for SliceReader<'storage> {
    #[inline(always)]
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), DecodeError> {
        if bytes.len() > self.slice.len() {
            return Err(DecodeError::UnexpectedEnd { additional: bytes.len() - self.slice.len() });
        }
        let (read_slice, remaining) = self.slice.split_at(bytes.len());
        bytes.copy_from_slice(read_slice);
        self.slice = remaining;
        Ok(())
    }
    #[inline] fn peek_read(&mut self, n: usize) -> Option<&[u8]> { self.slice.get(..n) }
    #[inline] fn consume(&mut self, n: usize) { self.slice = self.slice.get(n..).unwrap_or_default(); }
}

pub struct DecoderImpl<R, C> {
    pub reader: R,
    pub config: C,
    pub bytes_read: usize,
}

impl<R: Reader> DecoderImpl<R, Configuration> {
    #[inline(always)]
    pub fn claim_bytes_read(&mut self, n: usize) -> Result<(), DecodeError> {
        if let Some(limit) = self.config.limit() {
            self.bytes_read = self.bytes_read.checked_add(n).ok_or_else(|| DecodeError::LimitExceeded)?;
            if self.bytes_read > limit {
                return Err(DecodeError::LimitExceeded);
            }
        }
        Ok(())
    }
}

pub const SINGLE_BYTE_MAX: u8 = 250;
pub const U16_BYTE: u8 = 251;
pub const U32_BYTE: u8 = 252;
pub const U64_BYTE: u8 = 253;
pub const U128_BYTE: u8 = 254;

#[cold] #[inline(never)]
pub fn invalid_varint_discriminant(expected: IntegerType, found: IntegerType) -> DecodeError {
    DecodeError::InvalidIntegerType { expected, found }
}

#[cold] #[inline(never)]
pub fn varint_decode_u32_slow<R: Reader>(reader: &mut R, endian: Endian) -> Result<u32, DecodeError> {
    let mut bytes = [0u8; 4];
    reader.read(&mut bytes[..1])?;
    match bytes[0] {
        byte @ 0..=SINGLE_BYTE_MAX => Ok(byte as u32),
        U16_BYTE => {
            reader.read(&mut bytes[..2])?;
            Ok(match endian { Endian::Little => u16::from_le_bytes([bytes[0], bytes[1]]), Endian::Big => u16::from_be_bytes([bytes[0], bytes[1]]) } as u32)
        }
        U32_BYTE => {
            reader.read(&mut bytes)?;
            Ok(match endian { Endian::Little => u32::from_le_bytes(bytes), Endian::Big => u32::from_be_bytes(bytes) })
        }
        U64_BYTE => Err(invalid_varint_discriminant(IntegerType::U32, IntegerType::U64)),
        U128_BYTE => Err(invalid_varint_discriminant(IntegerType::U32, IntegerType::U128)),
        _ => Err(invalid_varint_discriminant(IntegerType::U32, IntegerType::Reserved)),
    }
}

#[cold] #[inline(never)]
pub fn varint_decode_u64_slow<R: Reader>(reader: &mut R, endian: Endian) -> Result<u64, DecodeError> {
    let mut bytes = [0u8; 8];
    reader.read(&mut bytes[..1])?;
    match bytes[0] {
        byte @ 0..=SINGLE_BYTE_MAX => Ok(byte as u64),
        U16_BYTE => {
            reader.read(&mut bytes[..2])?;
            Ok(match endian { Endian::Little => u16::from_le_bytes([bytes[0], bytes[1]]), Endian::Big => u16::from_be_bytes([bytes[0], bytes[1]]) } as u64)
        }
        U32_BYTE => {
            reader.read(&mut bytes[..4])?;
            Ok(match endian { Endian::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), Endian::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) } as u64)
        }
        U64_BYTE => {
            reader.read(&mut bytes)?;
            Ok(match endian { Endian::Little => u64::from_le_bytes(bytes), Endian::Big => u64::from_be_bytes(bytes) })
        }
        U128_BYTE => Err(invalid_varint_discriminant(IntegerType::U64, IntegerType::U128)),
        _ => Err(invalid_varint_discriminant(IntegerType::U64, IntegerType::Reserved)),
    }
}

pub trait Decode: Sized {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R, Configuration>) -> Result<Self, DecodeError>;
}

impl Decode for u32 {
    #[inline(never)]
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R, Configuration>) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(4)?;
        if let Some(bytes) = decoder.reader.peek_read(5) {
            let (val, len) = match bytes[0] {
                byte @ 0..=SINGLE_BYTE_MAX => (byte as u32, 1),
                U16_BYTE => (u16::from_le_bytes([bytes[1], bytes[2]]) as u32, 3),
                U32_BYTE => (u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]), 5),
                U64_BYTE => return Err(invalid_varint_discriminant(IntegerType::U32, IntegerType::U64)),
                U128_BYTE => return Err(invalid_varint_discriminant(IntegerType::U32, IntegerType::U128)),
                _ => return Err(invalid_varint_discriminant(IntegerType::U32, IntegerType::Reserved)),
            };
            decoder.reader.consume(len);
            Ok(val)
        } else {
            varint_decode_u32_slow(&mut decoder.reader, Endian::Little)
        }
    }
}

impl Decode for u64 {
    #[inline(never)]
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R, Configuration>) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(8)?;
        if let Some(bytes) = decoder.reader.peek_read(9) {
            let (val, len) = match bytes[0] {
                byte @ 0..=SINGLE_BYTE_MAX => (byte as u64, 1),
                U16_BYTE => (u16::from_le_bytes([bytes[1], bytes[2]]) as u64, 3),
                U32_BYTE => (u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64, 5),
                U64_BYTE => (u64::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8]]), 9),
                U128_BYTE => return Err(invalid_varint_discriminant(IntegerType::U32, IntegerType::U128)),
                _ => return Err(invalid_varint_discriminant(IntegerType::U32, IntegerType::Reserved)),
            };
            decoder.reader.consume(len);
            Ok(val)
        } else {
            varint_decode_u64_slow(&mut decoder.reader, Endian::Little)
        }
    }
}
"""

DEP_TYPES_RS = r"""#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::fmt;

/// 46-variant ConsensusError with >=64-byte payload so NodeError (max payload 64 B)
/// niches its 22 tags into 0x2e.. at offset 0.
#[derive(Debug)]
pub enum ConsensusError {
    V00([u8; 64]), V01(String), V02, V03, V04, V05, V06, V07, V08, V09,
    V10, V11, V12, V13, V14, V15, V16, V17, V18, V19,
    V20, V21, V22, V23, V24, V25, V26, V27, V28, V29,
    V30, V31, V32, V33, V34, V35, V36, V37, V38, V39,
    V40, V41, V42, V43, V44, V45,
}

#[derive(Copy, Clone, Debug)]
pub struct Round(pub u64);

#[derive(Debug)]
pub struct H256A(pub [u8; 32]);

#[derive(Debug)]
pub struct H256B(pub [u8; 32]);

#[derive(Debug)]
pub struct U64A(pub u64);

#[derive(Debug)]
pub struct U64B(pub u64);

/// Align-8 non-niche payload matching QueryClientBlocks(Round, ClientBlocksError) layout (+0x08, +0x10).
#[derive(Debug)]
pub struct QueryErr(pub [u64; 3]);

#[derive(Copy, Clone, Debug)]
#[repr(u64)]
pub enum Tag3 {
    A = 0,
    B = 1,
    C = 2,
}

#[derive(Debug)]
pub struct GossipStatusPayload {
    pub tag: Tag3,
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
    pub e: u64,
}

#[derive(Debug)]
pub struct ClientBlocksResultPayload {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
    pub e: u64,
}

#[derive(Debug)]
pub struct PeersPayload {
    pub a: u64,
    pub b: u64,
    pub c: u64,
}

/// Anchor <&T as Debug>::fmt instantiations in a separate crate CGU so ThinLTO
/// devirtualizes debug_tuple_field1_finish to direct calls without inlining <&T as Debug>::fmt.
pub fn anchor_debug_refs() -> [usize; 6] {
    [
        <&String as fmt::Debug>::fmt as *const () as usize,
        <&Round as fmt::Debug>::fmt as *const () as usize,
        <&ConsensusError as fmt::Debug>::fmt as *const () as usize,
        <&ClientBlocksResultPayload as fmt::Debug>::fmt as *const () as usize,
        <&PeersPayload as fmt::Debug>::fmt as *const () as usize,
        <&GossipStatusPayload as fmt::Debug>::fmt as *const () as usize,
    ]
}
"""

NODE_RUNTIME_MAIN_RS = r"""#![forbid(unsafe_code)]
#![allow(dead_code, unused_variables, unused_imports)]

use bincode_fork::*;
use dep_types::*;
use std::fmt;
use std::hint::black_box;

#[derive(Copy, Clone)]
pub struct WireRound(pub u64);

impl fmt::Debug for WireRound {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(f.debug_tuple("Round").field(&self.0).finish())
    }
}

impl fmt::Display for WireRound {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(fmt::Display::fmt(&self.0, f))
    }
}

impl Decode for WireRound {
    #[inline]
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R, Configuration>) -> Result<Self, DecodeError> {
        Ok(Self(Decode::decode(decoder)?))
    }
}

// 1. ClientBlocksError (Decode 0x2e464f0, Display 0x5aaa0c0, &Debug 0x5a2d540)
#[derive(Debug)]
pub enum ClientBlocksError {
    PeerOnlyRequest,
    InvalidRange { start_round: WireRound, end_round: WireRound },
    RangeTooLarge,
    RateLimited,
    NoClientBlocks,
    RoundTooSmall { start_round: WireRound, first_parent_round: WireRound },
    RoundTooLarge { end_round: WireRound, max_round: WireRound },
}

impl fmt::Display for ClientBlocksError {
    #[inline(never)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientBlocksError::PeerOnlyRequest => {
                fmt::Formatter::write_str(formatter, "Peer-only request")
            }
            ClientBlocksError::InvalidRange { start_round, end_round } => {
                let (field0, field1) = (start_round, end_round);
                write!(formatter, "invalid client block range: {}-{}", field0, field1)
            }
            ClientBlocksError::RangeTooLarge => {
                fmt::Formatter::write_str(formatter, "too many client blocks requested")
            }
            ClientBlocksError::RateLimited => {
                fmt::Formatter::write_str(formatter, "rate limited")
            }
            ClientBlocksError::NoClientBlocks => {
                fmt::Formatter::write_str(formatter, "no client blocks to serve")
            }
            ClientBlocksError::RoundTooSmall { start_round, first_parent_round } => {
                let (field0, field1) = (start_round, first_parent_round);
                write!(
                    formatter,
                    "start round {} is smaller than first parent round {}",
                    field0, field1
                )
            }
            ClientBlocksError::RoundTooLarge { end_round, max_round } => {
                let (field0, field1) = (end_round, max_round);
                write!(
                    formatter,
                    "end round {} is larger than max round {}",
                    field0, field1
                )
            }
        }
    }
}

impl Decode for ClientBlocksError {
    #[inline(never)]
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R, Configuration>) -> Result<Self, DecodeError> {
        let variant_index = u32::decode(decoder)?;
        match variant_index {
            0u32 => Ok(Self::PeerOnlyRequest),
            1u32 => Ok(Self::InvalidRange {
                start_round: Decode::decode(decoder)?,
                end_round: Decode::decode(decoder)?,
            }),
            2u32 => Ok(Self::RangeTooLarge),
            3u32 => Ok(Self::RateLimited),
            4u32 => Ok(Self::NoClientBlocks),
            5u32 => Ok(Self::RoundTooSmall {
                start_round: Decode::decode(decoder)?,
                first_parent_round: Decode::decode(decoder)?,
            }),
            6u32 => Ok(Self::RoundTooLarge {
                end_round: Decode::decode(decoder)?,
                max_round: Decode::decode(decoder)?,
            }),
            variant => Err(DecodeError::UnexpectedVariant {
                type_name: "ClientBlocksError",
                allowed: &AllowedEnumVariants::Range { min: 0, max: 6 },
                found: variant,
            }),
        }
    }
}

// 2. GossipRpcRequest (Decode 0x5aac6a0)
pub enum GossipRpcRequest {
    ClientBlocks { start_round: WireRound, end_round: WireRound },
    Peers,
    GossipStatus,
}

impl Decode for GossipRpcRequest {
    #[inline(never)]
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R, Configuration>) -> Result<Self, DecodeError> {
        let variant_index = u32::decode(decoder)?;
        match variant_index {
            0u32 => Ok(Self::ClientBlocks {
                start_round: Decode::decode(decoder)?,
                end_round: Decode::decode(decoder)?,
            }),
            1u32 => Ok(Self::Peers),
            2u32 => Ok(Self::GossipStatus),
            variant => Err(DecodeError::UnexpectedVariant {
                type_name: "GossipRpcRequest",
                allowed: &AllowedEnumVariants::Range { min: 0, max: 2 },
                found: variant,
            }),
        }
    }
}

// 3. GossipConfigInner (Debug 0x5656a20)
#[derive(Debug)]
pub enum Chain {
    Local,
    Sandbox,
    Testnet,
    Mainnet,
}

pub struct RootIp(pub u64);
impl fmt::Debug for RootIp {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(f.write_str("r"))
    }
}

pub struct ReservedIp(pub u64);
impl fmt::Debug for ReservedIp {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(f.write_str("p"))
    }
}

#[derive(Debug)]
pub struct GossipConfigInner {
    pub root_node_ips: Vec<RootIp>,
    pub try_new_peers: bool,
    pub chain: Chain,
    pub reserved_peer_ips: Vec<ReservedIp>,
    pub n_gossip_peers: Option<usize>,
    pub split_client_blocks: bool,
}

// 4. GossipRpcResponse (&Debug 0x5a2e730)
#[derive(Debug)]
pub enum GossipRpcResponse {
    ClientBlocks(ClientBlocksResultPayload),
    Peers(PeersPayload),
    GossipStatus(GossipStatusPayload),
}

// 5. NodeError (Debug CGU 1 0x564a710 & CGU 2 0x5a8a880)
#[derive(Debug)]
pub enum NodeError {
    Gossip(String),
    GossipRpc(String),
    ClientBlockParentRound(Round),
    Consensus(ConsensusError),
    QueryClientBlocks(U64A, QueryErr),
    PeerFull,
    PeerTimeout,
    PeerRateLimit,
    PeerNoQuorumL1Hash,
    PeerInconsistentGreeting,
    AbciStateDeserialize,
    NvStreamClientBlockSend,
    L1HashHeightMismatch(U64B, U64B),
    L1HashMismatch(H256A, H256A),
    AbciDigestMismatch(H256B, H256B),
    L1HashNoQuorum,
    EvmKvsRead(String),
    EvmKvsWrite(String),
    MissingConfigFln(String),
    InvalidConfigFln { fln: String, err: String },
    ThreadJoin,
    Chain,
}

fn main() {
    let anchors = dep_types::anchor_debug_refs();
    let p_grr_dec: fn(&mut DecoderImpl<SliceReader<'static>, Configuration>) -> Result<GossipRpcRequest, DecodeError> = GossipRpcRequest::decode;
    let p_cbe_dec: fn(&mut DecoderImpl<SliceReader<'static>, Configuration>) -> Result<ClientBlocksError, DecodeError> = ClientBlocksError::decode;
    let p_cbe_disp: fn(&ClientBlocksError, &mut fmt::Formatter<'_>) -> fmt::Result = <ClientBlocksError as fmt::Display>::fmt;
    let p_cbe_dbg: fn(&'static &'static ClientBlocksError, &mut fmt::Formatter<'_>) -> fmt::Result = <&ClientBlocksError as fmt::Debug>::fmt;
    let p_gci_dbg: fn(&GossipConfigInner, &mut fmt::Formatter<'_>) -> fmt::Result = <GossipConfigInner as fmt::Debug>::fmt;
    let p_grresp_dbg: fn(&'static &'static GossipRpcResponse, &mut fmt::Formatter<'_>) -> fmt::Result = <&GossipRpcResponse as fmt::Debug>::fmt;
    let p_ne_dbg: fn(&NodeError, &mut fmt::Formatter<'_>) -> fmt::Result = <NodeError as fmt::Debug>::fmt;
    black_box((
        anchors,
        p_grr_dec as usize,
        p_cbe_dec as usize,
        p_cbe_disp as usize,
        p_cbe_dbg as usize,
        p_gci_dbg as usize,
        p_grresp_dbg as usize,
        p_ne_dbg as usize,
    ));
}
"""


def _parse_int(v) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 16) if v.startswith(("0x", "0X")) else int(v)
    raise AssertionError(f"Cannot parse integer from {v!r}")


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                fdes[_parse_int(parts[0])] = _parse_int(parts[1])
    return fdes


def check_disjoint_against_repo(records: list[dict]) -> None:
    """Verify internal disjointness and 0 overlap vs byte-windows.json & all sibling packets.

    Wave-7 consolidation-safe: an exact (s, e) == (bs, be) match is permitted ONLY if
    already consolidated as a `first-party clean-room rebuild` in byte-windows.json or
    a `consolidation` sibling packet; dependency or partial overlaps are strictly forbidden.
    """
    ours = sorted((r["start"], r["end"], r["id"]) for r in records)
    for (s1, e1, id1), (s2, e2, id2) in zip(ours, ours[1:]):
        if e1 > s2:
            raise AssertionError(f"Internal overlap: {id1} ({hex(s1)}..{hex(e1)}) vs {id2} ({hex(s2)}..{hex(e2)})")

    bw = json.loads(BYTE_WINDOWS_JSON.read_text(encoding="utf-8"))
    for w in bw.get("windows", []):
        bs = _parse_int(w["start"])
        be = _parse_int(w["end"])
        sk = w.get("source_kind", "")
        for s, e, wid in ours:
            if max(s, bs) < min(e, be):
                if (s, e) == (bs, be) and sk == "first-party clean-room rebuild":
                    continue
                raise AssertionError(
                    f"Overlap vs byte-windows.json: {wid} ({hex(s)}..{hex(e)}) vs "
                    f"{w.get('id')} ({hex(bs)}..{hex(be)}, source_kind={sk!r})"
                )

    for p_str in sorted(glob.glob(str(WORK_ITEMS_DIR / "*" / "*.json"))):
        p = Path(p_str)
        if p.parent == PACKET_DIR:
            continue
        is_consolidation = "consolidation" in p.parent.name
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        items = d if isinstance(d, list) else d.get("records", d.get("windows", d.get("matches", [])))
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            rs = it.get("start", it.get("start_va", it.get("va")))
            re_ = it.get("end", it.get("end_va"))
            if rs is not None and re_ is None and it.get("size") is not None:
                re_ = _parse_int(rs) + _parse_int(it["size"])
            if rs is None or re_ is None:
                continue
            bs, be = _parse_int(rs), _parse_int(re_)
            for s, e, wid in ours:
                if max(s, bs) < min(e, be):
                    if (s, e) == (bs, be) and is_consolidation:
                        continue
                    raise AssertionError(
                        f"Overlap vs sibling packet {p.relative_to(REPO_ROOT)}: "
                        f"{wid} ({hex(s)}..{hex(e)}) vs {hex(bs)}..{hex(be)}"
                    )


def rebuild_from_source(bin_data: bytes, text_sec: dict) -> tuple[bytes, list[dict]]:
    """Compile clean-room #![forbid(unsafe_code)] crates with rustc +1.95.0 ThinLTO
    and match all 8 target node #115 FDEs."""
    env = os.environ.copy()
    env.setdefault("RUST_MIN_STACK", "16777216")

    def read_target(s: int, e: int) -> bytes:
        off = text_sec["offset"] + (s - text_sec["address"])
        return bin_data[off : off + (e - s)]

    with tempfile.TemporaryDirectory(prefix="re005-transport-runtime-") as td:
        work = Path(td)
        (work / "bincode_fork.rs").write_text(BINCODE_FORK_LIB_RS, encoding="utf-8")
        (work / "dep_types.rs").write_text(DEP_TYPES_RS, encoding="utf-8")
        (work / "main.rs").write_text(NODE_RUNTIME_MAIN_RS, encoding="utf-8")

        for cmd in [
            [
                "rustc", "+1.95.0", "--crate-name=bincode_fork", "--crate-type=rlib",
                "--edition=2021", "-C", "opt-level=3", "-C", "overflow-checks=true",
                "-C", "embed-bitcode=yes",
                "-o", str(work / "libbincode_fork.rlib"), str(work / "bincode_fork.rs"),
            ],
            [
                "rustc", "+1.95.0", "--crate-name=dep_types", "--crate-type=rlib",
                "--edition=2021", "-C", "opt-level=3", "-C", "overflow-checks=true",
                "-C", "embed-bitcode=yes",
                "-o", str(work / "libdep_types.rlib"), str(work / "dep_types.rs"),
            ],
            [
                "rustc", "+1.95.0", "--crate-name=transport_runtime", "--crate-type=bin",
                "--edition=2021", "-C", "opt-level=3", "-C", "overflow-checks=true",
                "-C", "lto=thin", "-C", "codegen-units=16", "-C", "save-temps",
                "--extern", f"bincode_fork={work / 'libbincode_fork.rlib'}",
                "--extern", f"dep_types={work / 'libdep_types.rlib'}",
                "-o", str(work / "transport_runtime"), str(work / "main.rs"),
            ],
        ]:
            subprocess.check_call(cmd, env=env, cwd=work)

        compiled: list[tuple[str, bytes, list[dict]]] = []
        for ob in sorted(work.glob("transport_runtime.*.rcgu.o")):
            for names, body, relocs in object_functions(ob.read_bytes()):
                rdicts = [{"offset": o, "width": 4, "type": t, "addend": a} for o, t, a in relocs]
                compiled.append((names[0] if names else "", body, rdicts))

        bodies = bytearray()
        records: list[dict] = []
        for start, end, wid, comp, kind, label in TARGET_WINDOWS:
            tbytes = read_target(start, end)
            best = None
            for sym, body, rdicts in compiled:
                if len(body) != len(tbytes):
                    continue
                res = compare(body, tbytes, rdicts)
                if res["relocation_qualified"]:
                    cand = (-res["raw_equal_bytes"], sym, body, rdicts, res)
                    if best is None or cand[0] < best[0]:
                        best = cand
            if best is None:
                raise AssertionError(f"Rebuild failed to match {wid} ({hex(start)}..{hex(end)}, {len(tbytes)} B)")
            _, sym, body, rdicts, res = best
            offset = len(bodies)
            bodies.extend(body)
            records.append(
                {
                    "id": wid,
                    "component": comp,
                    "kind": kind,
                    "label": label,
                    "start": start,
                    "end": end,
                    "size": end - start,
                    "body_offset": offset,
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "target_body_sha256": hashlib.sha256(tbytes).hexdigest(),
                    "raw_equal": res["raw_equal"],
                    "raw_equal_bytes": res["raw_equal_bytes"],
                    "relocation_qualified": res["relocation_qualified"],
                    "relocations": rdicts,
                    "symbol": sym,
                }
            )
        return bytes(bodies), records


def write_packet_artifacts(bodies: bytes, records: list[dict]) -> None:
    BODIES_PATH.write_bytes(bodies)
    by_comp: dict[str, dict[str, int]] = {}
    for r in records:
        c = by_comp.setdefault(r["component"], {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        c["windows"] += 1
        c["bytes"] += r["size"]
        c["raw_equal_bytes"] += r["raw_equal_bytes"]

    payload = {
        "target": "node115",
        "binary_path": "artifacts/node/115/hl-node",
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "binary_size": EXPECTED_BINARY_SIZE,
        "compiler": "rustc +1.95.0 (opt-level=3, overflow-checks=true, lto=thin, codegen-units=16, #![forbid(unsafe_code)], 0 external deps)",
        "source_kind": "first-party clean-room rebuild",
        "components": by_comp,
        "summary": {
            "total_windows": len(records),
            "matched_bytes": sum(r["size"] for r in records),
            "raw_equal_windows": sum(1 for r in records if r["raw_equal"]),
            "raw_equal_bytes": sum(r["raw_equal_bytes"] for r in records),
            "bodies_sha256": hashlib.sha256(bodies).hexdigest(),
        },
        "windows": records,
    }
    RECORDS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def verify_records(bin_data: bytes, text_sec: dict, fdes: dict[int, int]) -> dict:
    payload = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    bodies = BODIES_PATH.read_bytes()

    if payload["binary_sha256"] != EXPECTED_BINARY_SHA256 or payload["binary_size"] != EXPECTED_BINARY_SIZE:
        raise AssertionError("Pinned binary metadata mismatch")
    if hashlib.sha256(bodies).hexdigest() != payload["summary"]["bodies_sha256"]:
        raise AssertionError("bodies.bin sha256 mismatch")

    records = payload["windows"]
    if len(records) != len(TARGET_WINDOWS):
        raise AssertionError(f"Expected {len(TARGET_WINDOWS)} windows, got {len(records)}")

    expected_keys = [(s, e, wid, comp) for s, e, wid, comp, _, _ in TARGET_WINDOWS]
    actual_keys = [(r["start"], r["end"], r["id"], r["component"]) for r in records]
    if actual_keys != expected_keys:
        raise AssertionError("Window list mismatch vs TARGET_WINDOWS")

    total_bytes = 0
    total_raw = 0
    for r in records:
        s, e = r["start"], r["end"]
        if fdes.get(s) != e:
            raise AssertionError(f"Window {r['id']} ({hex(s)}..{hex(e)}) is not an exact node #115 FDE")
        body = bodies[r["body_offset"] : r["body_offset"] + r["size"]]
        if len(body) != r["size"] or hashlib.sha256(body).hexdigest() != r["body_sha256"]:
            raise AssertionError(f"Body slice/hash mismatch for {r['id']}")
        off = text_sec["offset"] + (s - text_sec["address"])
        tbytes = bin_data[off : off + (e - s)]
        if hashlib.sha256(tbytes).hexdigest() != r["target_body_sha256"]:
            raise AssertionError(f"Target sha256 mismatch for {r['id']}")
        res = compare(body, tbytes, r["relocations"])
        if not res["relocation_qualified"] or res["non_relocation_difference_offsets"]:
            raise AssertionError(f"compare() failed for {r['id']}: {res}")
        if res["raw_equal_bytes"] != r["raw_equal_bytes"]:
            raise AssertionError(f"raw_equal_bytes mismatch for {r['id']}")
        total_bytes += r["size"]
        total_raw += res["raw_equal_bytes"]

    if total_bytes != payload["summary"]["matched_bytes"] or total_raw != payload["summary"]["raw_equal_bytes"]:
        raise AssertionError("Summary totals mismatch")

    check_disjoint_against_repo(records)
    return payload


def run_negative_controls(bin_data: bytes, text_sec: dict, payload: dict) -> int:
    bodies = BODIES_PATH.read_bytes()
    r0 = payload["windows"][0]
    body0 = bodies[r0["body_offset"] : r0["body_offset"] + r0["size"]]
    off0 = text_sec["offset"] + (r0["start"] - text_sec["address"])
    tbytes0 = bin_data[off0 : off0 + r0["size"]]
    rel_covered = set()
    for rel in r0["relocations"]:
        for k in range(rel["width"]):
            rel_covered.add(rel["offset"] + k)
    rejected = 0

    # Control 1: 1-byte flip outside relocation spans must fail compare()
    non_rel = next(i for i in range(len(body0)) if i not in rel_covered)
    mut = bytearray(body0)
    mut[non_rel] ^= 0xFF
    res1 = compare(bytes(mut), tbytes0, r0["relocations"])
    assert not res1["relocation_qualified"] and non_rel in res1["non_relocation_difference_offsets"]
    rejected += 1

    # Control 2: 1-byte length truncation must fail compare()
    try:
        compare(body0[:-1], tbytes0, r0["relocations"])
        raise AssertionError("Expected length mismatch failure")
    except ValueError:
        rejected += 1

    # Control 3: Forged 8-byte relocation width must be rejected by compare()
    bad_rels = copy.deepcopy(r0["relocations"])
    bad_rels[0]["width"] = 8
    try:
        compare(body0, tbytes0, bad_rels)
        raise AssertionError("Expected forged relocation width rejection")
    except ValueError:
        rejected += 1

    # Control 4: Overlapping window must be rejected by check_disjoint_against_repo()
    dup = copy.deepcopy(payload["windows"])
    dup.append(copy.deepcopy(dup[0]))
    try:
        check_disjoint_against_repo(dup)
        raise AssertionError("Expected overlap rejection")
    except AssertionError:
        rejected += 1

    return rejected


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rebuild", action="store_true", help="Rebuild bodies.bin & records.json from Rust source")
    ap.add_argument("--self-test", action="store_true", help="Run 4 negative controls after verification")
    args = ap.parse_args()

    bin_data = BINARY_PATH.read_bytes()
    if len(bin_data) != EXPECTED_BINARY_SIZE:
        raise AssertionError(f"Unexpected binary size: {len(bin_data)}")
    actual_sha = hashlib.sha256(bin_data).hexdigest()
    if actual_sha != EXPECTED_BINARY_SHA256:
        raise AssertionError(f"Unexpected binary sha256: {actual_sha}")

    secs = {s["name"]: s for s in sections(bin_data)}
    text_sec = secs[".text"]
    fdes = load_fde_map()

    if args.rebuild:
        bodies, records = rebuild_from_source(bin_data, text_sec)
        write_packet_artifacts(bodies, records)

    payload = verify_records(bin_data, text_sec, fdes)
    s = payload["summary"]
    comp_parts = ", ".join(
        f"{k}={v['windows']} FDEs/{v['bytes']} B"
        for k, v in sorted(payload["components"].items())
    )
    msg = (
        f"PASS: {s['total_windows']}/{len(TARGET_WINDOWS)} relocation-qualified, "
        f"{s['matched_bytes']} B (raw_equal_bytes={s['raw_equal_bytes']}/{s['matched_bytes']}, {comp_parts})"
    )
    if args.self_test:
        n_neg = run_negative_controls(bin_data, text_sec, payload)
        msg += f" | {n_neg}/4 negative controls rejected"
    print(msg)


if __name__ == "__main__":
    main()
