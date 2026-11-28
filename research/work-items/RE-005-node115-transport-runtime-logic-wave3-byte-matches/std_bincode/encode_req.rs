#![forbid(unsafe_code)]
#![allow(dead_code)]

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
    fn write_u64(&mut self, v: u64) -> Result<(), EncodeError>;
}

impl Writer for VecWriter {
    #[inline(always)]
    fn write_u64(&mut self, v: u64) -> Result<(), EncodeError> {
        w_u64_vec(self, v)
    }
}

impl Writer for SizeWriter {
    #[inline(always)]
    fn write_u64(&mut self, v: u64) -> Result<(), EncodeError> {
        w_u64_size(self, v)
    }
}

pub trait Encoder: Sized {
    type W: Writer;
    fn writer(&mut self) -> &mut Self::W;
    fn enc_variant_u32(&mut self, v: &u32) -> Result<(), EncodeError>;
}

impl Encoder for EncVec {
    type W = VecWriter;
    #[inline(always)]
    fn writer(&mut self) -> &mut Self::W {
        &mut self.writer
    }
    #[inline(always)]
    fn enc_variant_u32(&mut self, v: &u32) -> Result<(), EncodeError> {
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
    fn enc_variant_u32(&mut self, v: &u32) -> Result<(), EncodeError> {
        enc_u32_size(v, self)
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

impl Encode for u64 {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write_u64(*self)
    }
}

#[derive(Copy, Clone)]
pub struct Round(pub u64);

impl Encode for Round {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        Encode::encode(&self.0, encoder)?;
        Ok(())
    }
}

pub enum GossipRpcRequest {
    ClientBlocks { start_round: Round, end_round: Round },
    Peers,
    GossipStatus,
}

impl Encode for GossipRpcRequest {
    #[inline(always)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            Self::ClientBlocks {
                start_round,
                end_round,
            } => {
                encoder.enc_variant_u32(&0u32)?;
                Encode::encode(start_round, encoder)?;
                Encode::encode(end_round, encoder)?;
                Ok(())
            }
            Self::Peers => {
                encoder.enc_variant_u32(&1u32)?;
                Ok(())
            }
            Self::GossipStatus => {
                encoder.enc_variant_u32(&2u32)?;
                Ok(())
            }
        }
    }
}

pub fn call_grr_sw(x: &&GossipRpcRequest, e: &mut EncSize) -> Result<(), EncodeError> {
    x.encode(e)
}

pub fn call_grr_vec(x: &&GossipRpcRequest, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}
