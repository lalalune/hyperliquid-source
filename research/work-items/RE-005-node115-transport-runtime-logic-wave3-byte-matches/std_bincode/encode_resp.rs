#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::cell::Cell;
use std::collections::{BTreeSet, VecDeque};
use std::hint::black_box;
use std::time::Duration;

#[derive(Debug)]
pub enum EncodeError {
    UnexpectedEnd,
    SizeOverflow,
    AllocationFailed,
    Io { inner: std::io::Error, index: usize },
    Other(&'static str),
    OtherString(String),
    InvalidSystemTime { duration: Duration },
    Serde(String),
}

#[repr(C)]
pub struct VecWriter {
    pub buf: Vec<u8>,
}

#[repr(C)]
pub struct SizeWriter {
    pub bytes_written: usize,
}

#[repr(C)]
pub struct EncVec {
    pub hdr: [u64; 2],
    pub writer: VecWriter,
}

#[repr(C)]
pub struct EncSize {
    pub hdr: [u64; 2],
    pub writer: SizeWriter,
}

#[inline(never)]
pub fn w_u64_vec(w: &mut VecWriter, v: u64) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((w, v));
    black_box(Ok(()))
}

#[inline(never)]
pub fn w_u64_size(w: &mut SizeWriter, v: u64) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((w, v));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_u32_vec(v: &u32, e: &mut EncVec) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((v, e));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_u32_size(v: &u32, e: &mut EncSize) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((v, e));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_cb_vec(v: &ClientBlock, e: &mut EncVec) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((v, e));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_cb_size(v: &ClientBlock, e: &mut EncSize) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((v, e));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_gs_vec(v: &GossipStatus, e: &mut EncVec) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((v, e));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_gs_size(v: &GossipStatus, e: &mut EncSize) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((v, e));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_peers_small_vec(v: &VecDeque<[u64; 3]>, e: &mut EncVec) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((v, e));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_peers_small_size(v: &VecDeque<[u64; 3]>, e: &mut EncSize) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((v, e));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_peers_large_vec(v: &BTreeSet<[u64; 3]>, e: &mut EncVec) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((v, e));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_peers_large_size(v: &BTreeSet<[u64; 3]>, e: &mut EncSize) -> Result<(), EncodeError> {
    if black_box(false) {
        eprintln!("x");
    }
    black_box((v, e));
    black_box(Ok(()))
}

pub trait Writer {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError>;
    fn write_u64(&mut self, v: u64) -> Result<(), EncodeError>;
}

impl Writer for VecWriter {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.buf.extend_from_slice(bytes);
        Ok(())
    }
    #[inline(always)]
    fn write_u64(&mut self, v: u64) -> Result<(), EncodeError> {
        w_u64_vec(self, v)
    }
}

impl Writer for SizeWriter {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.bytes_written += bytes.len();
        Ok(())
    }
    #[inline(always)]
    fn write_u64(&mut self, v: u64) -> Result<(), EncodeError> {
        w_u64_size(self, v)
    }
}

pub trait Encoder: Sized {
    type W: Writer;
    fn writer(&mut self) -> &mut Self::W;
    fn enc_u32(&mut self, v: &u32) -> Result<(), EncodeError>;
    fn enc_cb(&mut self, v: &ClientBlock) -> Result<(), EncodeError>;
    fn enc_gs(&mut self, v: &GossipStatus) -> Result<(), EncodeError>;
    fn enc_peers_small(&mut self, v: &VecDeque<[u64; 3]>) -> Result<(), EncodeError>;
    fn enc_peers_large(&mut self, v: &BTreeSet<[u64; 3]>) -> Result<(), EncodeError>;
}

impl Encoder for EncVec {
    type W = VecWriter;
    #[inline(always)]
    fn writer(&mut self) -> &mut Self::W {
        &mut self.writer
    }
    #[inline(always)]
    fn enc_u32(&mut self, v: &u32) -> Result<(), EncodeError> {
        enc_u32_vec(v, self)
    }
    #[inline(always)]
    fn enc_cb(&mut self, v: &ClientBlock) -> Result<(), EncodeError> {
        enc_cb_vec(v, self)
    }
    #[inline(always)]
    fn enc_gs(&mut self, v: &GossipStatus) -> Result<(), EncodeError> {
        enc_gs_vec(v, self)
    }
    #[inline(always)]
    fn enc_peers_small(&mut self, v: &VecDeque<[u64; 3]>) -> Result<(), EncodeError> {
        enc_peers_small_vec(v, self)
    }
    #[inline(always)]
    fn enc_peers_large(&mut self, v: &BTreeSet<[u64; 3]>) -> Result<(), EncodeError> {
        enc_peers_large_vec(v, self)
    }
}

impl Encoder for EncSize {
    type W = SizeWriter;
    #[inline(always)]
    fn writer(&mut self) -> &mut Self::W {
        &mut self.writer
    }
    #[inline(always)]
    fn enc_u32(&mut self, v: &u32) -> Result<(), EncodeError> {
        enc_u32_size(v, self)
    }
    #[inline(always)]
    fn enc_cb(&mut self, v: &ClientBlock) -> Result<(), EncodeError> {
        enc_cb_size(v, self)
    }
    #[inline(always)]
    fn enc_gs(&mut self, v: &GossipStatus) -> Result<(), EncodeError> {
        enc_gs_size(v, self)
    }
    #[inline(always)]
    fn enc_peers_small(&mut self, v: &VecDeque<[u64; 3]>) -> Result<(), EncodeError> {
        enc_peers_small_size(v, self)
    }
    #[inline(always)]
    fn enc_peers_large(&mut self, v: &BTreeSet<[u64; 3]>) -> Result<(), EncodeError> {
        enc_peers_large_size(v, self)
    }
}

pub trait Encode {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError>;
}

impl<T: Encode + ?Sized> Encode for &T {
    #[inline(never)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        (**self).encode(encoder)
    }
}

#[derive(Copy, Clone)]
pub struct Round(pub u64);

impl Encode for Round {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write_u64(self.0)?;
        Ok(())
    }
}

pub struct ClientBlock(pub Cell<u64>, pub u64);

impl Encode for ClientBlock {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.enc_cb(self)
    }
}

pub struct GossipStatus {
    pub opt: Option<Round>,
    pub a: usize,
    pub b: usize,
    pub c: Round,
    pub d: Cell<u64>,
}

impl Encode for GossipStatus {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.enc_gs(self)
    }
}

pub enum ClientBlocksError {
    PeerOnlyRequest,
    InvalidRange { start_round: Round, end_round: Round },
    RangeTooLarge,
    RateLimited,
    NoClientBlocks,
    RoundTooSmall { start_round: Round, first_parent_round: Round },
    RoundTooLarge { end_round: Round, max_round: Round },
}

impl Encode for ClientBlocksError {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            Self::PeerOnlyRequest => {
                encoder.enc_u32(&0u32)?;
                Ok(())
            }
            Self::InvalidRange {
                start_round,
                end_round,
            } => {
                encoder.enc_u32(&1u32)?;
                start_round.encode(encoder)?;
                end_round.encode(encoder)?;
                Ok(())
            }
            Self::RangeTooLarge => {
                encoder.enc_u32(&2u32)?;
                Ok(())
            }
            Self::RateLimited => {
                encoder.enc_u32(&3u32)?;
                Ok(())
            }
            Self::NoClientBlocks => {
                encoder.enc_u32(&4u32)?;
                Ok(())
            }
            Self::RoundTooSmall {
                start_round,
                first_parent_round,
            } => {
                encoder.enc_u32(&5u32)?;
                start_round.encode(encoder)?;
                first_parent_round.encode(encoder)?;
                Ok(())
            }
            Self::RoundTooLarge {
                end_round,
                max_round,
            } => {
                encoder.enc_u32(&6u32)?;
                end_round.encode(encoder)?;
                max_round.encode(encoder)?;
                Ok(())
            }
        }
    }
}

impl<T: Encode, Er: Encode> Encode for Result<T, Er> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            Ok(v) => {
                encoder.enc_u32(&0u32)?;
                v.encode(encoder)
            }
            Err(e) => {
                encoder.enc_u32(&1u32)?;
                e.encode(encoder)
            }
        }
    }
}

impl<T: Encode> Encode for Vec<T> {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        let len = self.len() as u64;
        encoder.writer().write_u64(len)?;
        for item in self.iter() {
            item.encode(encoder)?;
        }
        Ok(())
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            None => encoder.writer().write(&[0]),
            Some(v) => {
                encoder.writer().write(&[1])?;
                v.encode(encoder)?;
                Ok(())
            }
        }
    }
}

pub enum PeersMap {
    Small(VecDeque<[u64; 3]>),
    Large(BTreeSet<[u64; 3]>),
}

impl Encode for PeersMap {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            Self::Small(v) => encoder.enc_peers_small(v),
            Self::Large(v) => encoder.enc_peers_large(v),
        }?;
        Ok(())
    }
}

pub enum GossipRpcResponse {
    ClientBlocks(Result<Vec<ClientBlock>, ClientBlocksError>),
    Peers(PeersMap),
    GossipStatus(Option<GossipStatus>),
}

impl Encode for GossipRpcResponse {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            Self::ClientBlocks(r) => {
                encoder.enc_u32(&0u32)?;
                r.encode(encoder)?;
                Ok(())
            }
            Self::Peers(p) => {
                encoder.enc_u32(&1u32)?;
                p.encode(encoder)?;
                Ok(())
            }
            Self::GossipStatus(s) => {
                encoder.enc_u32(&2u32)?;
                s.encode(encoder)?;
                Ok(())
            }
        }
    }
}

pub fn call_resp_vec(x: &&GossipRpcResponse, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}

pub fn call_resp_sw(x: &&GossipRpcResponse, e: &mut EncSize) -> Result<(), EncodeError> {
    x.encode(e)
}

pub fn poly_vec_u64(v: &mut Vec<u64>, n: usize) {
    v.reserve(n);
}

pub fn poly_vec_32(v: &mut Vec<[u8; 32]>, n: usize) {
    v.reserve(n);
}
