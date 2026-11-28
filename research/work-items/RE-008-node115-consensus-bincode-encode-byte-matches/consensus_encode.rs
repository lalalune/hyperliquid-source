#![forbid(unsafe_code)]
#![allow(dead_code)]
//! First-party `consensus` `bincode-fork` `Encode` implementations for Linux x86-64 node #115.
//!
//! Target binary: `artifacts/node/115/hl-node`
//! SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
//!
//! Compiled under `rustc +1.95.0 --edition=2021 --crate-type=rlib -C opt-level=3
//! -C overflow-checks=yes -C relocation-model=pie -C lto=off --emit=obj` with zero
//! external crates.io dependencies.

use core::num::NonZeroU32;
use std::collections::{BTreeMap, VecDeque};
use std::hint::black_box;
use std::time::Duration;

/// Eight-variant `bincode-fork` encode error (`Ok(())` discriminant = 8, size = 32 bytes).
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

pub trait Writer {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError>;
    fn write_u64(&mut self, v: u64) -> Result<(), EncodeError>;
}

#[repr(C)]
pub struct VecWriter {
    pub buf: Vec<u8>,
}

#[repr(C)]
pub struct SizeWriter {
    pub bytes_written: usize,
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

impl<W: Writer> Writer for &mut W {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        (**self).write(bytes)
    }

    #[inline(always)]
    fn write_u64(&mut self, v: u64) -> Result<(), EncodeError> {
        (**self).write_u64(v)
    }
}

pub trait Encoder: Sized {
    type W: Writer;
    fn writer(&mut self) -> &mut Self::W;
    fn enc_addr20(&mut self, a: &[u8; 20]) -> Result<(), EncodeError>;
    fn enc_hash32(&mut self, h: &[u8; 32]) -> Result<(), EncodeError>;
    fn enc_time(&mut self, t: &NaiveDateTime) -> Result<(), EncodeError>;
    fn enc_variant_u32(&mut self, v: &u32) -> Result<(), EncodeError>;
    fn enc_small_map(&mut self, v: &VecDeque<([u8; 20], [u64; 8])>) -> Result<(), EncodeError>;
    fn enc_large_map(&mut self, m: &BTreeMap<[u8; 20], [u64; 8]>) -> Result<(), EncodeError>;
    fn enc_tc_sigs(&mut self, m: &L1Map<[u8; 20], [u64; 8]>) -> Result<(), EncodeError>;
    fn enc_opt_qc(&mut self, o: &Option<Qc>) -> Result<(), EncodeError>;
    fn enc_blk_helper(&mut self, b: &BlockCompact) -> Result<(), EncodeError>;
    fn enc_horizon_tail(&mut self, t: &HorizonTail) -> Result<(), EncodeError>;
    fn enc_opt_horizon_mt(&mut self, x: &Option<HorizonMapAndTail>) -> Result<(), EncodeError>;
}

/// `bincode-fork` `EncoderImpl` variants with the 16-byte configuration header before `writer`.
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

#[repr(C)]
pub struct EncRefSize<'a> {
    pub hdr: [u64; 2],
    pub writer: &'a mut SizeWriter,
}

/// Direct-reborrow `&mut SizeWriter` encoder layout matching `0x59680a0` (`mov 0x10(%rdx), %r14`).
#[repr(C)]
pub struct EncDirectRefSize<'a> {
    pub hdr: [u64; 2],
    pub writer: &'a mut SizeWriter,
}

#[inline(never)]
pub fn w_addr20_vec(a: &[u8; 20], e: &mut EncVec) -> Result<(), EncodeError> {
    black_box((a, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_addr20_size(_a: &[u8; 20], e: &mut EncSize) -> Result<(), EncodeError> {
    black_box(e);
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_hash32_vec(h: &[u8; 32], e: &mut EncVec) -> Result<(), EncodeError> {
    black_box((h, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_hash32_size(h: &[u8; 32], e: &mut EncSize) -> Result<(), EncodeError> {
    black_box((h, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_hash32_refsize(h: &[u8; 32], e: &mut EncRefSize<'_>) -> Result<(), EncodeError> {
    black_box((h, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_time_vec(t: &NaiveDateTime, e: &mut EncVec) -> Result<(), EncodeError> {
    black_box((t, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_time_size(t: &NaiveDateTime, e: &mut EncSize) -> Result<(), EncodeError> {
    black_box((t, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_time_refsize(t: &NaiveDateTime, e: &mut EncRefSize<'_>) -> Result<(), EncodeError> {
    black_box((t, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_var_vec(v: &u32, e: &mut EncVec) -> Result<(), EncodeError> {
    black_box((v, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_var_size(v: &u32, e: &mut EncSize) -> Result<(), EncodeError> {
    black_box((v, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_var_refsize(v: &u32, e: &mut EncRefSize<'_>) -> Result<(), EncodeError> {
    black_box((v, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_small_vec(v: &VecDeque<([u8; 20], [u64; 8])>, e: &mut EncVec) -> Result<(), EncodeError> {
    black_box((v, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_large_vec(m: &BTreeMap<[u8; 20], [u64; 8]>, e: &mut EncVec) -> Result<(), EncodeError> {
    black_box((m, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_small_size(
    v: &VecDeque<([u8; 20], [u64; 8])>,
    e: &mut EncSize,
) -> Result<(), EncodeError> {
    black_box((v, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_large_size(
    m: &BTreeMap<[u8; 20], [u64; 8]>,
    e: &mut EncSize,
) -> Result<(), EncodeError> {
    black_box((m, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_small_refsize(
    v: &VecDeque<([u8; 20], [u64; 8])>,
    e: &mut EncRefSize<'_>,
) -> Result<(), EncodeError> {
    black_box((v, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_large_refsize(
    m: &BTreeMap<[u8; 20], [u64; 8]>,
    e: &mut EncRefSize<'_>,
) -> Result<(), EncodeError> {
    black_box((m, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_tcsigs_vec(
    m: &L1Map<[u8; 20], [u64; 8]>,
    e: &mut EncVec,
) -> Result<(), EncodeError> {
    black_box((m, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_tcsigs_size(
    m: &L1Map<[u8; 20], [u64; 8]>,
    e: &mut EncSize,
) -> Result<(), EncodeError> {
    black_box((m, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_tcsigs_refsize(
    m: &L1Map<[u8; 20], [u64; 8]>,
    e: &mut EncRefSize<'_>,
) -> Result<(), EncodeError> {
    black_box((m, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_optqc_vec(o: &Option<Qc>, e: &mut EncVec) -> Result<(), EncodeError> {
    black_box((o, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_optqc_size(o: &Option<Qc>, e: &mut EncSize) -> Result<(), EncodeError> {
    black_box((o, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_optqc_refsize(o: &Option<Qc>, e: &mut EncRefSize<'_>) -> Result<(), EncodeError> {
    black_box((o, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_blk_vec(b: &BlockCompact, e: &mut EncVec) -> Result<(), EncodeError> {
    black_box((b, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_blk_size(b: &BlockCompact, e: &mut EncSize) -> Result<(), EncodeError> {
    black_box((b, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_htail_vec(t: &HorizonTail, e: &mut EncVec) -> Result<(), EncodeError> {
    black_box((t, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_htail_size(t: &HorizonTail, e: &mut EncSize) -> Result<(), EncodeError> {
    black_box((t, e));
    black_box(Ok(()))
}
#[inline(never)]
pub fn w_opt_hmt_vec(x: &Option<HorizonMapAndTail>, e: &mut EncVec) -> Result<(), EncodeError> {
    black_box((x, e));
    black_box(Ok(()))
}

impl Encoder for EncVec {
    type W = VecWriter;
    #[inline(always)]
    fn writer(&mut self) -> &mut VecWriter {
        &mut self.writer
    }
    #[inline(always)]
    fn enc_addr20(&mut self, a: &[u8; 20]) -> Result<(), EncodeError> {
        w_addr20_vec(a, self)?;
        Ok(())
    }
    #[inline(always)]
    fn enc_hash32(&mut self, h: &[u8; 32]) -> Result<(), EncodeError> {
        w_hash32_vec(h, self)
    }
    #[inline(always)]
    fn enc_time(&mut self, t: &NaiveDateTime) -> Result<(), EncodeError> {
        w_time_vec(t, self)
    }
    #[inline(always)]
    fn enc_variant_u32(&mut self, v: &u32) -> Result<(), EncodeError> {
        w_var_vec(v, self)
    }
    #[inline(always)]
    fn enc_small_map(&mut self, v: &VecDeque<([u8; 20], [u64; 8])>) -> Result<(), EncodeError> {
        w_small_vec(v, self)
    }
    #[inline(always)]
    fn enc_large_map(&mut self, m: &BTreeMap<[u8; 20], [u64; 8]>) -> Result<(), EncodeError> {
        w_large_vec(m, self)
    }
    #[inline(always)]
    fn enc_tc_sigs(&mut self, m: &L1Map<[u8; 20], [u64; 8]>) -> Result<(), EncodeError> {
        w_tcsigs_vec(m, self)
    }
    #[inline(always)]
    fn enc_opt_qc(&mut self, o: &Option<Qc>) -> Result<(), EncodeError> {
        w_optqc_vec(o, self)
    }
    #[inline(always)]
    fn enc_blk_helper(&mut self, b: &BlockCompact) -> Result<(), EncodeError> {
        w_blk_vec(b, self)
    }
    #[inline(always)]
    fn enc_horizon_tail(&mut self, t: &HorizonTail) -> Result<(), EncodeError> {
        w_htail_vec(t, self)
    }
    #[inline(always)]
    fn enc_opt_horizon_mt(&mut self, x: &Option<HorizonMapAndTail>) -> Result<(), EncodeError> {
        w_opt_hmt_vec(x, self)
    }
}

impl Encoder for EncSize {
    type W = SizeWriter;
    #[inline(always)]
    fn writer(&mut self) -> &mut SizeWriter {
        &mut self.writer
    }
    #[inline(always)]
    fn enc_addr20(&mut self, a: &[u8; 20]) -> Result<(), EncodeError> {
        w_addr20_size(a, self)?;
        Ok(())
    }
    #[inline(always)]
    fn enc_hash32(&mut self, h: &[u8; 32]) -> Result<(), EncodeError> {
        w_hash32_size(h, self)
    }
    #[inline(always)]
    fn enc_time(&mut self, t: &NaiveDateTime) -> Result<(), EncodeError> {
        w_time_size(t, self)
    }
    #[inline(always)]
    fn enc_variant_u32(&mut self, v: &u32) -> Result<(), EncodeError> {
        w_var_size(v, self)
    }
    #[inline(always)]
    fn enc_small_map(&mut self, v: &VecDeque<([u8; 20], [u64; 8])>) -> Result<(), EncodeError> {
        w_small_size(v, self)
    }
    #[inline(always)]
    fn enc_large_map(&mut self, m: &BTreeMap<[u8; 20], [u64; 8]>) -> Result<(), EncodeError> {
        w_large_size(m, self)
    }
    #[inline(always)]
    fn enc_tc_sigs(&mut self, m: &L1Map<[u8; 20], [u64; 8]>) -> Result<(), EncodeError> {
        w_tcsigs_size(m, self)
    }
    #[inline(always)]
    fn enc_opt_qc(&mut self, o: &Option<Qc>) -> Result<(), EncodeError> {
        w_optqc_size(o, self)
    }
    #[inline(always)]
    fn enc_blk_helper(&mut self, b: &BlockCompact) -> Result<(), EncodeError> {
        w_blk_size(b, self)
    }
    #[inline(always)]
    fn enc_horizon_tail(&mut self, t: &HorizonTail) -> Result<(), EncodeError> {
        w_htail_size(t, self)
    }
    #[inline(always)]
    fn enc_opt_horizon_mt(&mut self, _x: &Option<HorizonMapAndTail>) -> Result<(), EncodeError> {
        Ok(())
    }
}

impl<'a> Encoder for EncRefSize<'a> {
    type W = &'a mut SizeWriter;
    #[inline(always)]
    fn writer(&mut self) -> &mut Self::W {
        &mut self.writer
    }
    #[inline(always)]
    fn enc_addr20(&mut self, _a: &[u8; 20]) -> Result<(), EncodeError> {
        self.writer.bytes_written += 20;
        Ok(())
    }
    #[inline(always)]
    fn enc_hash32(&mut self, h: &[u8; 32]) -> Result<(), EncodeError> {
        w_hash32_refsize(h, self)
    }
    #[inline(always)]
    fn enc_time(&mut self, t: &NaiveDateTime) -> Result<(), EncodeError> {
        w_time_refsize(t, self)
    }
    #[inline(always)]
    fn enc_variant_u32(&mut self, v: &u32) -> Result<(), EncodeError> {
        w_var_refsize(v, self)
    }
    #[inline(always)]
    fn enc_small_map(&mut self, v: &VecDeque<([u8; 20], [u64; 8])>) -> Result<(), EncodeError> {
        w_small_refsize(v, self)
    }
    #[inline(always)]
    fn enc_large_map(&mut self, m: &BTreeMap<[u8; 20], [u64; 8]>) -> Result<(), EncodeError> {
        w_large_refsize(m, self)
    }
    #[inline(always)]
    fn enc_tc_sigs(&mut self, m: &L1Map<[u8; 20], [u64; 8]>) -> Result<(), EncodeError> {
        w_tcsigs_refsize(m, self)
    }
    #[inline(always)]
    fn enc_opt_qc(&mut self, o: &Option<Qc>) -> Result<(), EncodeError> {
        w_optqc_refsize(o, self)
    }
    #[inline(always)]
    fn enc_blk_helper(&mut self, _b: &BlockCompact) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_horizon_tail(&mut self, _t: &HorizonTail) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_opt_horizon_mt(&mut self, _x: &Option<HorizonMapAndTail>) -> Result<(), EncodeError> {
        Ok(())
    }
}

impl<'a> Encoder for EncDirectRefSize<'a> {
    type W = SizeWriter;
    #[inline(always)]
    fn writer(&mut self) -> &mut SizeWriter {
        self.writer
    }
    #[inline(always)]
    fn enc_addr20(&mut self, _a: &[u8; 20]) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_hash32(&mut self, _h: &[u8; 32]) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_time(&mut self, _t: &NaiveDateTime) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_variant_u32(&mut self, _v: &u32) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_small_map(&mut self, _v: &VecDeque<([u8; 20], [u64; 8])>) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_large_map(&mut self, _m: &BTreeMap<[u8; 20], [u64; 8]>) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_tc_sigs(&mut self, _m: &L1Map<[u8; 20], [u64; 8]>) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_opt_qc(&mut self, _o: &Option<Qc>) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_blk_helper(&mut self, _b: &BlockCompact) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_horizon_tail(&mut self, _t: &HorizonTail) -> Result<(), EncodeError> {
        Ok(())
    }
    #[inline(always)]
    fn enc_opt_horizon_mt(&mut self, _x: &Option<HorizonMapAndTail>) -> Result<(), EncodeError> {
        Ok(())
    }
}

pub trait Encode {
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError>;
}

impl Encode for u8 {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        enc.writer().write(&[*self])?;
        Ok(())
    }
}

impl Encode for u64 {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        enc.writer().write_u64(*self)?;
        Ok(())
    }
}

impl Encode for usize {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        (*self as u64).encode(enc)
    }
}

pub struct Hardfork {
    pub version: u64,
    pub round: u64,
}
impl Encode for Hardfork {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.version.encode(enc)?;
        self.round.encode(enc)?;
        Ok(())
    }
}

pub struct Round(pub u64);
impl Encode for Round {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.0.encode(enc)
    }
}

pub struct Addr20(pub [u8; 20]);
impl Encode for Addr20 {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        enc.enc_addr20(&self.0)
    }
}

pub struct Hash32(pub [u8; 32]);
impl Encode for Hash32 {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        enc.enc_hash32(&self.0)
    }
}

pub struct NaiveDateTime {
    pub date: NonZeroU32,
    pub secs: u32,
    pub nanos: u32,
}
impl Encode for NaiveDateTime {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        enc.enc_time(self)
    }
}

pub enum L1Map<K, V> {
    Small(VecDeque<(K, V)>),
    Large(BTreeMap<K, V>),
}
impl Encode for L1Map<[u8; 20], [u64; 8]> {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        match self {
            Self::Small(v) => enc.enc_small_map(v),
            Self::Large(m) => enc.enc_large_map(m),
        }
    }
}

impl<T: Encode> Encode for Vec<T> {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.len().encode(enc)?;
        for item in self {
            item.encode(enc)?;
        }
        Ok(())
    }
}

pub struct Signature {
    pub r: [u64; 4],
    pub s: [u64; 4],
    pub v: u8,
}
impl Encode for Signature {
    #[inline(never)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.r[0].encode(enc)?;
        self.r[1].encode(enc)?;
        self.r[2].encode(enc)?;
        self.r[3].encode(enc)?;
        self.s[0].encode(enc)?;
        self.s[1].encode(enc)?;
        self.s[2].encode(enc)?;
        self.s[3].encode(enc)?;
        self.v.encode(enc)?;
        Ok(())
    }
}

pub struct Qc {
    pub hardfork: Hardfork,
    pub round: Round,
    pub parent_round: Round,
    pub committed_round: Round,
    pub hash: Hash32,
    pub sigs: L1Map<[u8; 20], [u64; 8]>,
}
impl Encode for Qc {
    #[inline(never)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.hardfork.encode(enc)?;
        self.round.encode(enc)?;
        self.parent_round.encode(enc)?;
        self.committed_round.encode(enc)?;
        self.hash.encode(enc)?;
        self.sigs.encode(enc)?;
        Ok(())
    }
}

#[repr(C)]
pub struct TcCert {
    pub default_qc: Qc,
    pub signatures: L1Map<[u8; 20], [u64; 8]>,
    pub round: Round,
    pub high_qc: Option<Qc>,
}
impl Encode for TcCert {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.round.encode(enc)?;
        self.default_qc.encode(enc)?;
        enc.enc_tc_sigs(&self.signatures)?;
        enc.enc_opt_qc(&self.high_qc)?;
        Ok(())
    }
}

pub enum Cert {
    Qc(Qc),
    Tc(TcCert),
}
impl Encode for Cert {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        match self {
            Cert::Qc(qc) => {
                enc.enc_variant_u32(&0u32)?;
                qc.encode(enc)?;
                Ok(())
            }
            Cert::Tc(tc) => {
                enc.enc_variant_u32(&1u32)?;
                tc.encode(enc)?;
                Ok(())
            }
        }
    }
}

pub struct Block {
    pub proposer: Addr20,
    pub tx_hashes: Vec<Hash32>,
    pub time: NaiveDateTime,
    pub parent: Cert,
}
impl Encode for Block {
    #[inline(never)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.proposer.encode(enc)?;
        self.tx_hashes.encode(enc)?;
        self.time.encode(enc)?;
        self.parent.encode(enc)?;
        Ok(())
    }
}

pub struct BlockHeader {
    pub proposer: Addr20,
    pub hardfork: Hardfork,
    pub round: Round,
    pub parent_round: Round,
    pub committed_round: Round,
    pub hash: Hash32,
}
impl Encode for BlockHeader {
    #[inline(never)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.proposer.encode(enc)?;
        self.hardfork.encode(enc)?;
        self.round.encode(enc)?;
        self.parent_round.encode(enc)?;
        self.committed_round.encode(enc)?;
        self.hash.encode(enc)?;
        Ok(())
    }
}

pub struct TcVote {
    pub proposer: Addr20,
    pub hardfork: Hardfork,
    pub round: Round,
    pub high_qc: Qc,
}
impl Encode for TcVote {
    #[inline(never)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.proposer.encode(enc)?;
        self.hardfork.encode(enc)?;
        self.round.encode(enc)?;
        self.high_qc.encode(enc)?;
        Ok(())
    }
}

pub struct Timeout {
    pub proposer: Addr20,
    pub hardfork: Hardfork,
    pub round: Round,
    pub other: Round,
}
impl Encode for Timeout {
    #[inline(never)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.proposer.encode(enc)?;
        self.hardfork.encode(enc)?;
        self.round.encode(enc)?;
        self.other.encode(enc)?;
        Ok(())
    }
}

/// 376-byte `Block` layout wrapper used in `Option<(Block, Qc)>` (`0x4e05490`, `0x4e055d0`).
#[repr(C)]
pub struct BlockCompact {
    pub tx_hashes: Vec<u8>,
    pub rest: [u64; 44],
}
impl Encode for BlockCompact {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        enc.enc_blk_helper(self)
    }
}

pub struct HorizonTail {
    pub pad: [u64; 3],
}
impl Encode for HorizonTail {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        enc.enc_horizon_tail(self)
    }
}

#[repr(C)]
pub struct HorizonMapAndTail {
    pub map: L1Map<[u8; 20], [u64; 8]>,
    pub tail: HorizonTail,
}
impl Encode for HorizonMapAndTail {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.map.encode(enc)?;
        self.tail.encode(enc)?;
        Ok(())
    }
}

#[inline(always)]
fn enc_opt_tail_inline<E: Encoder>(
    opt: &Option<HorizonTail>,
    enc: &mut E,
) -> Result<(), EncodeError> {
    if let Some(t) = opt {
        enc.writer().write(&[1])?;
        enc.enc_horizon_tail(t)?;
    } else {
        enc.writer().write(&[0])?;
    }
    Ok(())
}

#[repr(C)]
pub struct HorizonInner {
    pub opt_tail: Option<HorizonTail>,
    pub opt_mt: Option<HorizonMapAndTail>,
}
impl Encode for HorizonInner {
    #[inline(never)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        enc.enc_opt_horizon_mt(&self.opt_mt)?;
        enc_opt_tail_inline(&self.opt_tail, enc)?;
        Ok(())
    }
}

#[repr(C)]
pub struct HorizonState {
    pub inner: HorizonInner,
    pub map: L1Map<[u8; 20], [u64; 8]>,
}
impl Encode for HorizonState {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.inner.encode(enc)?;
        self.map.encode(enc)?;
        Ok(())
    }
}

impl<A: Encode, B: Encode> Encode for (A, B) {
    #[inline(always)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        self.0.encode(enc)?;
        self.1.encode(enc)?;
        Ok(())
    }
}

impl<T: Encode> Encode for Option<T> {
    #[inline(never)]
    fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        match self {
            None => {
                enc.writer().write(&[0])?;
                Ok(())
            }
            Some(v) => {
                enc.writer().write(&[1])?;
                v.encode(enc)?;
                Ok(())
            }
        }
    }
}

/// Prevents intra-CGU dead-argument elimination of `(align, size)` on
/// `RawVecInner::reserve::do_reserve_and_handle`, matching the multi-type node #115 binary.
pub fn prevent_rawvec_dae(v64: &mut Vec<u64>, s: &[u64]) {
    v64.extend_from_slice(s);
}

// Single-call wrappers enabling unambiguous ELF `.rela` symbol resolution for all 23 FDEs.
pub fn call_qc_refsize(x: &Qc, e: &mut EncRefSize<'_>) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_qc_size(x: &Qc, e: &mut EncSize) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_qc_vec(x: &Qc, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_bh_vec(x: &BlockHeader, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_bh_size(x: &BlockHeader, e: &mut EncSize) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_blk_refsize(x: &Block, e: &mut EncRefSize<'_>) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_blk_vec(x: &Block, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_blk_size(x: &Block, e: &mut EncSize) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_tcv_vec(x: &TcVote, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_tcv_size(x: &TcVote, e: &mut EncSize) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_to_vec(x: &Timeout, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_to_size(x: &Timeout, e: &mut EncSize) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_sig_size(x: &Signature, e: &mut EncSize) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_sig_refsize(x: &Signature, e: &mut EncDirectRefSize<'_>) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_opt_bq_size(
    x: &Option<(BlockCompact, Qc)>,
    e: &mut EncSize,
) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_opt_qc_size(x: &Option<Qc>, e: &mut EncSize) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_opt_bq_vec(
    x: &Option<(BlockCompact, Qc)>,
    e: &mut EncVec,
) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_opt_qc_vec(x: &Option<Qc>, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_opt_hmt_vec(x: &Option<HorizonMapAndTail>, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_opt_qc_refsize(x: &Option<Qc>, e: &mut EncRefSize<'_>) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_opt_hmt_size(
    x: &Option<HorizonMapAndTail>,
    e: &mut EncSize,
) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_opt_hs_vec(x: &Option<HorizonState>, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}
pub fn call_hinner_vec(x: &HorizonInner, e: &mut EncVec) -> Result<(), EncodeError> {
    x.encode(e)
}
