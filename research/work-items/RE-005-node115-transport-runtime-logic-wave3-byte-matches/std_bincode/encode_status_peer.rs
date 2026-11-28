#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::hint::black_box;
use std::net::Ipv4Addr;
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
    black_box((w, v));
    black_box(Ok(()))
}

#[inline(never)]
pub fn w_u64_size(w: &mut SizeWriter, v: u64) -> Result<(), EncodeError> {
    black_box((w, v));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_u32_vec(v: &u32, e: &mut EncVec) -> Result<(), EncodeError> {
    black_box((v, e));
    black_box(Ok(()))
}

#[inline(never)]
pub fn enc_u32_size(v: &u32, e: &mut EncSize) -> Result<(), EncodeError> {
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
}

pub trait Encode {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError>;
}

#[derive(Copy, Clone)]
pub struct Round(pub u64);

impl Encode for Round {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.0.encode(encoder)?;
        Ok(())
    }
}

impl Encode for usize {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write_u64(*self as u64)
    }
}

impl Encode for u64 {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write_u64(*self)
    }
}

impl Encode for bool {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(&[*self as u8])
    }
}

impl<T: Encode> Encode for Option<T> {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            None => encoder.writer().write(&[0]),
            Some(v) => {
                encoder.writer().write(&[1])?;
                v.encode(encoder)
            }
        }
    }
}

pub struct RoundPair {
    pub c: Round,
    pub d: Round,
}

impl Encode for RoundPair {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.c.encode(encoder)?;
        self.d.encode(encoder)?;
        Ok(())
    }
}

pub struct GossipStatus {
    pub a: usize,
    pub b: usize,
    pub pair: RoundPair,
    pub opt: Option<Round>,
}

impl Encode for GossipStatus {
    #[inline(never)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.a.encode(encoder)?;
        self.b.encode(encoder)?;
        self.pair.encode(encoder)?;
        self.opt.encode(encoder)?;
        Ok(())
    }
}

pub enum NodeIp {
    Ip(Ipv4Addr),
}

impl Encode for NodeIp {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            Self::Ip(ip) => {
                encoder.enc_u32(&0u32)?;
                encoder.writer().write(&ip.octets())?;
                Ok(())
            }
        }
    }
}

pub struct PeerInfo {
    pub is_validator: bool,
    pub ts: u64,
}

impl Encode for PeerInfo {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.is_validator.encode(encoder)?;
        self.ts.encode(encoder)?;
        Ok(())
    }
}

#[repr(C)]
pub struct PeerEntry(pub NodeIp, pub PeerInfo);

impl Encode for PeerEntry {
    #[inline(never)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.0.encode(encoder)?;
        self.1.encode(encoder)?;
        Ok(())
    }
}

pub fn call_gs_sw(x: &GossipStatus, e: &mut EncSize) -> Result<(), EncodeError> {
    x.encode(e)
}

pub fn call_gs_vec(x: &GossipStatus, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}

pub fn call_peer_vec(x: &PeerEntry, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}

pub fn poly_vec_u64(v: &mut Vec<u64>, n: usize) {
    v.reserve(n);
}

pub fn poly_vec_32(v: &mut Vec<[u8; 32]>, n: usize) {
    v.reserve(n);
}
