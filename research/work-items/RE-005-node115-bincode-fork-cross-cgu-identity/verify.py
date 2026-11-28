#!/usr/bin/env python3
"""Verify 26 standalone cross-CGU bincode_fork primitive FDE byte matches (4,168 B)
and exhaustive 100-FDE cross-CGU Location partition for node #115 serialization."""

from __future__ import annotations

import argparse
import bisect
import copy
import glob
import hashlib
import json
import os
import struct
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
BINCODE_CGU_RANGE = (0x1607C70, 0x1609AAA)

# 26 strictly disjoint, standalone cross-CGU bincode_fork primitive monomorphizations (4,168 B).
# Every symbol is defined in first-party `bincode_fork` (zero core::/alloc::/std:: attribution).
# Note: 0x29360e0 (155 B, varint_encode_u64 CGU 1) is already claimed in research/byte-windows.json
# as `node115-w2-thinlto-29360e0` and is independently re-verified below without double-claiming.
TARGET_WINDOWS = [
    # CGU 1 Encode primitives (0x2788050..0x2788198)
    (0x2788050, 0x27880E7, "bincode-cross-cgu1-enc-u64x4-sw-2788050", "encode_primitive",
     "serialization bincode_fork <[u64; 4] as Encode>::encode::<EncoderImpl<SizeWriter, Configuration>> (CGU 1, 0x2788050)"),
    (0x27880F0, 0x278811B, "bincode-cross-cgu1-enc-u8x32-sw-27880f0", "encode_primitive",
     "serialization bincode_fork <[u8; 32] as Encode>::encode::<EncoderImpl<SizeWriter, Configuration>> (CGU 1, 0x27880f0)"),
    (0x2788120, 0x2788198, "bincode-cross-cgu1-enc-u8x32-vec-2788120", "encode_primitive",
     "serialization bincode_fork <[u8; 32] as Encode>::encode::<EncoderImpl<VecWriter, Configuration>> (CGU 1, 0x2788120)"),
    # CGU 1 Decode primitives (0x2cd7960..0x2cd7d86)
    (0x2CD7960, 0x2CD79B9, "bincode-cross-cgu1-dec-u8-2cd7960", "decode_primitive",
     "serialization bincode_fork <u8 as Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (CGU 1, 0x2cd7960)"),
    (0x2CD79C0, 0x2CD7AB3, "bincode-cross-cgu1-dec-u32-2cd79c0", "decode_primitive",
     "serialization bincode_fork <u32 as Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (CGU 1, 0x2cd79c0)"),
    (0x2CD7AC0, 0x2CD7BA5, "bincode-cross-cgu1-dec-u64-2cd7ac0", "decode_primitive",
     "serialization bincode_fork <u64 as Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (CGU 1, 0x2cd7ac0)"),
    (0x2CD7BB0, 0x2CD7C95, "bincode-cross-cgu1-dec-usize-2cd7bb0", "decode_primitive",
     "serialization bincode_fork <usize as Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (CGU 1, 0x2cd7bb0)"),
    (0x2CD7CA0, 0x2CD7D13, "bincode-cross-cgu1-dec-u8x32-2cd7ca0", "decode_primitive",
     "serialization bincode_fork <[u8; 32] as Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (CGU 1, 0x2cd7ca0)"),
    (0x2CD7D20, 0x2CD7D86, "bincode-cross-cgu1-dec-u8x20-2cd7d20", "decode_primitive",
     "serialization bincode_fork <[u8; 20] as Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (CGU 1, 0x2cd7d20)"),
    # CGU 2 Decode primitives (0x5821150..0x582153d)
    (0x5821150, 0x5821243, "bincode-cross-cgu2-dec-u32-5821150", "decode_primitive",
     "serialization bincode_fork <u32 as Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (CGU 2, 0x5821150)"),
    (0x5821250, 0x5821335, "bincode-cross-cgu2-dec-u64-5821250", "decode_primitive",
     "serialization bincode_fork <u64 as Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (CGU 2, 0x5821250)"),
    (0x5821340, 0x5821425, "bincode-cross-cgu2-dec-usize-5821340", "decode_primitive",
     "serialization bincode_fork <usize as Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (CGU 2, 0x5821340)"),
    (0x5821430, 0x58214A3, "bincode-cross-cgu2-dec-u8x32-5821430", "decode_primitive",
     "serialization bincode_fork <[u8; 32] as Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (CGU 2, 0x5821430)"),
    (0x58214B0, 0x582153D, "bincode-cross-cgu2-dec-u8x2048-58214b0", "decode_primitive",
     "serialization bincode_fork <[u8; 2048] as Decode>::decode::<DecoderImpl<SliceReader, Configuration>> (CGU 2, 0x58214b0)"),
    # CGU 2 Encode primitives (0x58220e0..0x5822c44)
    (0x58220E0, 0x5822157, "bincode-cross-cgu2-enc-u32-sw-58220e0", "encode_primitive",
     "serialization bincode_fork <u32 as Encode>::encode::<EncoderImpl<SizeWriter, Configuration>> (CGU 2, 0x58220e0)"),
    (0x5822160, 0x58221D7, "bincode-cross-cgu2-enc-u32-swref-5822160", "encode_primitive",
     "serialization bincode_fork <u32 as Encode>::encode::<EncoderImpl<&mut SizeWriter, Configuration>> (CGU 2, 0x5822160)"),
    (0x58221E0, 0x5822256, "bincode-cross-cgu2-enc-u8x20-vec-58221e0", "encode_primitive",
     "serialization bincode_fork <[u8; 20] as Encode>::encode::<EncoderImpl<VecWriter, Configuration>> (CGU 2, 0x58221e0)"),
    (0x5822260, 0x58222D8, "bincode-cross-cgu2-enc-u8x32-vec-5822260", "encode_primitive",
     "serialization bincode_fork <[u8; 32] as Encode>::encode::<EncoderImpl<VecWriter, Configuration>> (CGU 2, 0x5822260)"),
    (0x58222E0, 0x582236C, "bincode-cross-cgu2-enc-u64x4-swref-58222e0", "encode_primitive",
     "serialization bincode_fork <[u64; 4] as Encode>::encode::<EncoderImpl<&mut SizeWriter, Configuration>> (CGU 2, 0x58222e0)"),
    (0x5822370, 0x582239B, "bincode-cross-cgu2-enc-u8x32-sw-5822370", "encode_primitive",
     "serialization bincode_fork <[u8; 32] as Encode>::encode::<EncoderImpl<SizeWriter, Configuration>> (CGU 2, 0x5822370)"),
    (0x58223A0, 0x58223CB, "bincode-cross-cgu2-enc-u8x20-sw-58223a0", "encode_primitive",
     "serialization bincode_fork <[u8; 20] as Encode>::encode::<EncoderImpl<SizeWriter, Configuration>> (CGU 2, 0x58223a0)"),
    (0x58223D0, 0x582245F, "bincode-cross-cgu2-enc-u64x4-sw-58223d0", "encode_primitive",
     "serialization bincode_fork <[u64; 4] as Encode>::encode::<EncoderImpl<SizeWriter, Configuration>> (CGU 2, 0x58223d0)"),
    (0x5822460, 0x582248D, "bincode-cross-cgu2-enc-u8x32-swref-5822460", "encode_primitive",
     "serialization bincode_fork <[u8; 32] as Encode>::encode::<EncoderImpl<&mut SizeWriter, Configuration>> (CGU 2, 0x5822460)"),
    (0x5822850, 0x5822904, "bincode-cross-cgu2-varint-u64-sw-5822850", "encode_primitive",
     "serialization bincode_fork varint_encode_u64::<SizeWriter> (CGU 2 ThinLTO internalized LE, 0x5822850)"),
    (0x5822910, 0x5822B90, "bincode-cross-cgu2-varint-u64-vec-5822910", "encode_primitive",
     "serialization bincode_fork varint_encode_u64::<VecWriter> (CGU 2 ThinLTO internalized LE, 0x5822910)"),
    (0x5822B90, 0x5822C44, "bincode-cross-cgu2-varint-usize-sw-5822b90", "encode_primitive",
     "serialization bincode_fork varint_encode_usize::<SizeWriter> (CGU 2 ThinLTO internalized LE, 0x5822b90)"),
]

# Already-claimed standalone cross-CGU Location FDE re-verified without double-claiming:
ALREADY_CLAIMED_REVERIFY = (0x29360E0, 0x293617B)  # 155 B, node115-w2-thinlto-29360e0

# The 11 standalone bincode_fork FDEs inside the 100 cross-CGU Location FDEs (1,946 B):
#   - 8 newly matched here (0x27880f0, 0x58220e0, 0x5822160, 0x5822370, 0x58223a0, 0x5822460, 0x5822850, 0x5822b90 = 772 B)
#   - 1 already claimed in byte-windows.json & re-verified here (0x29360e0 = 155 B)
#   - 2 <[u64; 4] as Decode>::decode FDEs (0x2cd7d90 = 540 B, 0x5821540 = 479 B; 1,019 B total, excluded from byte claims
#     due to 3-byte cmpb $0x0 vs cmpl $0x1 LLVM InstCombine Option<usize> range narrowing / ThinLTO error-tail merge)
STANDALONE_LOCATION_11 = {
    0x27880F0, 0x29360E0, 0x58220E0, 0x5822160, 0x5822370, 0x58223A0,
    0x5822460, 0x5822850, 0x5822B90, 0x2CD7D90, 0x5821540,
}

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

#[non_exhaustive]
#[derive(Debug)]
pub enum EncodeError {
    UnexpectedEnd,
    RefCellAlreadyBorrowed { inner: core::cell::BorrowError, type_name: &'static str },
    Other(&'static str),
    OtherString(String),
    InvalidPathCharacters,
    Io { inner: std::io::Error, index: usize },
    LockFailed { type_name: &'static str },
    InvalidSystemTime { inner: std::time::SystemTimeError, time: Box<std::time::SystemTime> },
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

pub trait Writer {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError>;
}

pub struct SizeWriter {
    pub bytes_written: usize,
}

impl Writer for SizeWriter {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.bytes_written += bytes.len();
        Ok(())
    }
}

impl<T: Writer> Writer for &mut T {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        (**self).write(bytes)
    }
}

pub struct VecWriter {
    pub inner: Vec<u8>,
}

impl Writer for VecWriter {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.inner.extend_from_slice(bytes);
        Ok(())
    }
}

pub struct EncoderImpl<W: Writer, C> {
    pub writer: W,
    pub config: C,
}

pub trait Encoder {
    type W: Writer;
    fn writer(&mut self) -> &mut Self::W;
}

impl<W: Writer, C> Encoder for EncoderImpl<W, C> {
    type W = W;
    #[inline]
    fn writer(&mut self) -> &mut Self::W { &mut self.writer }
}

pub trait Encode {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError>;
}

pub const SINGLE_BYTE_MAX: u8 = 250;
pub const U16_BYTE: u8 = 251;
pub const U32_BYTE: u8 = 252;
pub const U64_BYTE: u8 = 253;
pub const U128_BYTE: u8 = 254;

#[inline]
pub fn varint_encode_u32<W: Writer>(writer: &mut W, endian: Endian, val: u32) -> Result<(), EncodeError> {
    if val <= SINGLE_BYTE_MAX as _ {
        writer.write(&[val as u8])
    } else if val <= u16::MAX as _ {
        writer.write(&[U16_BYTE])?;
        match endian {
            Endian::Big => writer.write(&(val as u16).to_be_bytes()),
            Endian::Little => writer.write(&(val as u16).to_le_bytes()),
        }
    } else {
        writer.write(&[U32_BYTE])?;
        match endian {
            Endian::Big => writer.write(&val.to_be_bytes()),
            Endian::Little => writer.write(&val.to_le_bytes()),
        }
    }
}

#[inline(never)]
pub fn varint_encode_u64<W: Writer>(writer: &mut W, endian: Endian, val: u64) -> Result<(), EncodeError> {
    if val <= SINGLE_BYTE_MAX as _ {
        writer.write(&[val as u8])
    } else if val <= u16::MAX as _ {
        writer.write(&[U16_BYTE])?;
        match endian {
            Endian::Big => writer.write(&(val as u16).to_be_bytes()),
            Endian::Little => writer.write(&(val as u16).to_le_bytes()),
        }
    } else if val <= u32::MAX as _ {
        writer.write(&[U32_BYTE])?;
        match endian {
            Endian::Big => writer.write(&(val as u32).to_be_bytes()),
            Endian::Little => writer.write(&(val as u32).to_le_bytes()),
        }
    } else {
        writer.write(&[U64_BYTE])?;
        match endian {
            Endian::Big => writer.write(&val.to_be_bytes()),
            Endian::Little => writer.write(&val.to_le_bytes()),
        }
    }
}

#[inline(never)]
pub fn varint_encode_usize<W: Writer>(writer: &mut W, endian: Endian, val: usize) -> Result<(), EncodeError> {
    varint_encode_u64(writer, endian, val as u64)
}

impl Encode for u32 {
    #[inline(never)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        varint_encode_u32(encoder.writer(), Endian::Little, *self)
    }
}

impl Encode for u64 {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        varint_encode_u64(encoder.writer(), Endian::Little, *self)
    }
}

impl<T: Encode, const N: usize> Encode for [T; N] {
    #[inline(never)]
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        for item in self.iter() {
            item.encode(encoder)?;
        }
        Ok(())
    }
}

#[inline(never)]
pub fn encode_u8_array<const N: usize, E: Encoder>(arr: &[u8; N], encoder: &mut E) -> Result<(), EncodeError> {
    encoder.writer().write(arr)
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

#[cold] #[inline(never)]
pub fn varint_decode_usize_slow<R: Reader>(reader: &mut R, endian: Endian) -> Result<usize, DecodeError> {
    let mut bytes = [0u8; 8];
    reader.read(&mut bytes[..1])?;
    match bytes[0] {
        byte @ 0..=SINGLE_BYTE_MAX => Ok(byte as usize),
        U16_BYTE => {
            reader.read(&mut bytes[..2])?;
            Ok(match endian { Endian::Little => u16::from_le_bytes([bytes[0], bytes[1]]), Endian::Big => u16::from_be_bytes([bytes[0], bytes[1]]) } as usize)
        }
        U32_BYTE => {
            reader.read(&mut bytes[..4])?;
            Ok(match endian { Endian::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), Endian::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) } as usize)
        }
        U64_BYTE => {
            reader.read(&mut bytes)?;
            Ok(match endian { Endian::Little => u64::from_le_bytes(bytes), Endian::Big => u64::from_be_bytes(bytes) } as usize)
        }
        U128_BYTE => Err(invalid_varint_discriminant(IntegerType::Usize, IntegerType::U128)),
        _ => Err(invalid_varint_discriminant(IntegerType::Usize, IntegerType::Reserved)),
    }
}

pub trait Decode: Sized {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R, Configuration>) -> Result<Self, DecodeError>;
}

impl Decode for u8 {
    #[inline(never)]
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R, Configuration>) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(1)?;
        if let Some(buf) = decoder.reader.peek_read(1) {
            let byte = buf[0];
            decoder.reader.consume(1);
            Ok(byte)
        } else {
            let mut bytes = [0u8; 1];
            decoder.reader.read(&mut bytes)?;
            Ok(bytes[0])
        }
    }
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
                // Upstream bincode 2.0.1 copy-paste fingerprint (passes IntegerType::U32 here!)
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

impl Decode for usize {
    #[inline(never)]
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R, Configuration>) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(8)?;
        if let Some(bytes) = decoder.reader.peek_read(9) {
            let (val, len) = match bytes[0] {
                byte @ 0..=SINGLE_BYTE_MAX => (byte as usize, 1),
                U16_BYTE => (u16::from_le_bytes([bytes[1], bytes[2]]) as usize, 3),
                U32_BYTE => (u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize, 5),
                U64_BYTE => (u64::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8]]) as usize, 9),
                U128_BYTE => return Err(invalid_varint_discriminant(IntegerType::Usize, IntegerType::U128)),
                _ => return Err(invalid_varint_discriminant(IntegerType::Usize, IntegerType::Reserved)),
            };
            decoder.reader.consume(len);
            Ok(val)
        } else {
            varint_decode_usize_slow(&mut decoder.reader, Endian::Little)
        }
    }
}

#[inline(never)]
pub fn decode_u8_array<const N: usize, R: Reader>(decoder: &mut DecoderImpl<R, Configuration>) -> Result<[u8; N], DecodeError> {
    decoder.claim_bytes_read(N)?;
    let mut buf = [0u8; N];
    decoder.reader.read(&mut buf)?;
    Ok(buf)
}
"""

CALLER_A_RS = r"""#![forbid(unsafe_code)]
use bincode_fork::*;
pub fn dec_u8(d: &mut DecoderImpl<SliceReader<'_>, Configuration>) -> Result<u8, DecodeError> { u8::decode(d) }
pub fn dec_u32(d: &mut DecoderImpl<SliceReader<'_>, Configuration>) -> Result<u32, DecodeError> { u32::decode(d) }
pub fn dec_u64(d: &mut DecoderImpl<SliceReader<'_>, Configuration>) -> Result<u64, DecodeError> { u64::decode(d) }
pub fn dec_usize(d: &mut DecoderImpl<SliceReader<'_>, Configuration>) -> Result<usize, DecodeError> { usize::decode(d) }
pub fn dec_u8_20(d: &mut DecoderImpl<SliceReader<'_>, Configuration>) -> Result<[u8; 20], DecodeError> { decode_u8_array::<20, _>(d) }
pub fn dec_u8_32(d: &mut DecoderImpl<SliceReader<'_>, Configuration>) -> Result<[u8; 32], DecodeError> { decode_u8_array::<32, _>(d) }
pub fn dec_u8_2048(d: &mut DecoderImpl<SliceReader<'_>, Configuration>) -> Result<[u8; 2048], DecodeError> { decode_u8_array::<2048, _>(d) }
pub fn enc_sw_u8_20(a: &[u8; 20], e: &mut EncoderImpl<SizeWriter, Configuration>) -> Result<(), EncodeError> { encode_u8_array(a, e) }
pub fn enc_sw_u8_32(a: &[u8; 32], e: &mut EncoderImpl<SizeWriter, Configuration>) -> Result<(), EncodeError> { encode_u8_array(a, e) }
pub fn enc_swref_u8_32(a: &[u8; 32], e: &mut EncoderImpl<&mut SizeWriter, Configuration>) -> Result<(), EncodeError> { encode_u8_array(a, e) }
pub fn enc_sw_u32(v: &u32, e: &mut EncoderImpl<SizeWriter, Configuration>) -> Result<(), EncodeError> { v.encode(e) }
pub fn enc_swref_u32(v: &u32, e: &mut EncoderImpl<&mut SizeWriter, Configuration>) -> Result<(), EncodeError> { v.encode(e) }
pub fn enc_vec_u8_20(a: &[u8; 20], e: &mut EncoderImpl<VecWriter, Configuration>) -> Result<(), EncodeError> { encode_u8_array(a, e) }
pub fn enc_vec_u8_32(a: &[u8; 32], e: &mut EncoderImpl<VecWriter, Configuration>) -> Result<(), EncodeError> { encode_u8_array(a, e) }
pub fn poly_vec_u64(v: &mut Vec<u64>, n: usize) { v.reserve(n); }
pub fn poly_vec_u8(v: &mut Vec<u8>, s: &[u8]) { v.extend_from_slice(s); }
pub fn poly_vec_32(v: &mut Vec<[u8; 32]>, n: usize) { v.reserve(n); }
"""

CALLER_B_RS = r"""#![forbid(unsafe_code)]
use bincode_fork::*;
fn main() {
    let f_arr_sw: fn(&[u64; 4], &mut EncoderImpl<SizeWriter, Configuration>) -> Result<(), EncodeError> = <[u64; 4] as Encode>::encode;
    let f_arr_swref: fn(&[u64; 4], &mut EncoderImpl<&'static mut SizeWriter, Configuration>) -> Result<(), EncodeError> = <[u64; 4] as Encode>::encode;
    let _ = std::hint::black_box((f_arr_sw as usize, f_arr_swref as usize));

    let mut sw = SizeWriter { bytes_written: std::hint::black_box(0) };
    let _ = std::hint::black_box(varint_encode_usize(&mut sw, Endian::Little, std::hint::black_box(999)));

    let mut v1: Vec<u64> = Vec::new();
    v1.reserve(std::hint::black_box(17));
    let mut v2: Vec<[u8; 32]> = Vec::new();
    v2.reserve(std::hint::black_box(17));
    let mut vw = VecWriter { inner: Vec::new() };
    vw.inner.reserve(std::hint::black_box(17));
    let _ = std::hint::black_box(varint_encode_u64(&mut vw, Endian::Little, std::hint::black_box(999)));
    let _ = std::hint::black_box((v1, v2, vw));
}
"""

CALLER_C_RS = r"""#![forbid(unsafe_code)]
use bincode_fork::*;
fn main() {
    let f1: fn(&[u64; 4], &mut EncoderImpl<SizeWriter, Configuration>) -> Result<(), EncodeError> = <[u64; 4] as Encode>::encode;
    let f2: fn(&mut SizeWriter, Endian, u64) -> Result<(), EncodeError> = varint_encode_u64;
    let _ = std::hint::black_box((f1 as usize, f2 as usize));
}
"""


def _parse_int(v) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 16) if v.startswith(("0x", "0X")) else int(v)
    raise AssertionError(f"Cannot parse integer from {v!r}")


def load_fde_map() -> tuple[dict[int, int], list[tuple[int, int]]]:
    fdes: dict[int, int] = {}
    ordered: list[tuple[int, int]] = []
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                s = _parse_int(parts[0])
                e = _parse_int(parts[1])
                fdes[s] = e
                ordered.append((s, e))
    ordered.sort()
    return fdes, ordered


def _make_va_to_off(data: bytes):
    secs = {s["name"]: s for s in sections(data)}

    def va_to_off(va: int) -> int | None:
        for s in secs.values():
            if s["address"] <= va < s["address"] + s["size"]:
                return s["offset"] + (va - s["address"])
        return None

    return secs, va_to_off


def audit_100_cross_cgu_locations(data: bytes, ordered_fdes: list[tuple[int, int]]) -> dict:
    """Authenticate and exhaustively partition all 100 cross-CGU bincode-fork Location FDEs."""
    secs, va_to_off = _make_va_to_off(data)
    rela = secs[".rela.dyn"]
    rel_map: dict[int, int] = {}
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", data, off)
        if (r_info & 0xFFFFFFFF) == 8:
            rel_map[r_off] = r_add

    drr = secs[".data.rel.ro"]
    all_locs: dict[int, str] = {}
    bincode_locs: dict[int, str] = {}
    for va in range(drr["address"], drr["address"] + drr["size"], 8):
        p = rel_map.get(va)
        if p is None:
            continue
        off = va_to_off(va)
        if off is None or off + 24 > len(data):
            continue
        ln, line, col = struct.unpack_from("<QII", data, off + 8)
        if 6 < ln < 140 and 1 <= line < 20000 and 1 <= col < 300:
            po = va_to_off(p)
            if po is not None and po + ln <= len(data):
                raw = data[po : po + ln]
                if b".rs" in raw and all(32 <= b < 127 for b in raw):
                    txt = f"{raw.decode('ascii')}:{line}:{col}"
                    all_locs[va] = txt
                    if b"bincode-fork" in raw:
                        bincode_locs[va] = txt

    if len(bincode_locs) != 13:
        raise AssertionError(f"Expected 13 bincode-fork Locations in .data.rel.ro, got {len(bincode_locs)}")

    text = secs[".text"]
    t_bytes = data[text["offset"] : text["offset"] + text["size"]]
    t_base = text["address"]
    fde_starts = [s for s, _ in ordered_fdes]

    ref_fdes: dict[tuple[int, int], set[str]] = {}
    all_loc_refs: dict[tuple[int, int], set[str]] = {}
    n = len(t_bytes) - 7
    for i in range(n):
        b0 = t_bytes[i]
        if b0 in (0x48, 0x4C) and t_bytes[i + 1] == 0x8D and (t_bytes[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", t_bytes, i + 3)[0]
            target = t_base + i + 7 + disp
            if target in all_locs:
                pc = t_base + i
                idx = bisect.bisect_right(fde_starts, pc) - 1
                if idx >= 0:
                    s, e = ordered_fdes[idx]
                    if s <= pc < e:
                        all_loc_refs.setdefault((s, e), set()).add(all_locs[target])
                        if target in bincode_locs and not (BINCODE_CGU_RANGE[0] <= s < BINCODE_CGU_RANGE[1]):
                            ref_fdes.setdefault((s, e), set()).add(bincode_locs[target])

    if len(ref_fdes) != 100:
        raise AssertionError(f"Expected 100 cross-CGU bincode-fork Location FDEs, got {len(ref_fdes)}")

    total_bytes = sum(e - s for s, e in ref_fdes)
    if total_bytes != 61605:
        raise AssertionError(f"Expected 61,605 cross-CGU Location FDE bytes, got {total_bytes}")

    entries = []
    category_counts: dict[str, list[int]] = {}
    for s, e in sorted(ref_fdes):
        bc = sorted(ref_fdes[(s, e)])
        other = sorted(all_loc_refs[(s, e)] - ref_fdes[(s, e)])
        if s in STANDALONE_LOCATION_11:
            if s in (0x2CD7D90, 0x5821540):
                cat = "standalone_bincode_u64x4_decode_excluded"
                owner = "serialization"
            elif s == 0x29360E0:
                cat = "standalone_bincode_already_claimed_byte_windows"
                owner = "serialization"
            else:
                cat = "standalone_bincode_matched_here"
                owner = "serialization"
        elif any("tokio" in x for x in other):
            cat = "caller_tokio_runtime_mt"
            owner = "caller_crate"
        elif any("btree" in x for x in other):
            cat = "caller_btreemap_btreeset"
            owner = "caller_crate"
        elif bc == ["z_forks/bincode-fork/src/lib.rs:171:22"]:
            cat = "caller_decode_from_slice"
            owner = "caller_crate"
        elif bc == ["z_forks/bincode-fork/src/de/decoder.rs:93:13"]:
            cat = "caller_vec_composite_decode"
            owner = "caller_crate"
        else:
            cat = "caller_composite_size_writer_encode"
            owner = "caller_crate"
        category_counts.setdefault(cat, [0, 0])
        category_counts[cat][0] += 1
        category_counts[cat][1] += e - s
        entries.append({
            "start": hex(s),
            "end": hex(e),
            "bytes": e - s,
            "owner": owner,
            "category": cat,
            "bincode_locations": bc,
            "other_locations": other,
        })

    standalone_entries = [x for x in entries if x["owner"] == "serialization"]
    caller_entries = [x for x in entries if x["owner"] == "caller_crate"]
    if len(standalone_entries) != 11 or sum(x["bytes"] for x in standalone_entries) != 1946:
        raise AssertionError("Standalone 11 cross-CGU Location FDE count/bytes mismatch")
    if len(caller_entries) != 89 or sum(x["bytes"] for x in caller_entries) != 59659:
        raise AssertionError("Caller-crate 89 cross-CGU Location FDE count/bytes mismatch")

    return {
        "bincode_locations_in_data_rel_ro": len(bincode_locs),
        "total_cross_cgu_location_fdes": len(entries),
        "total_cross_cgu_location_bytes": total_bytes,
        "standalone_serialization_fdes": len(standalone_entries),
        "standalone_serialization_bytes": sum(x["bytes"] for x in standalone_entries),
        "caller_crate_composite_fdes": len(caller_entries),
        "caller_crate_composite_bytes": sum(x["bytes"] for x in caller_entries),
        "by_category": {
            k: {"fdes": v[0], "bytes": v[1]} for k, v in sorted(category_counts.items())
        },
        "fdes": entries,
    }


def compile_bincode_primitives() -> tuple[list[tuple[str, str, bytes, list[dict]]], str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    env = os.environ.copy()
    env.setdefault("RUST_MIN_STACK", "16777216")
    with tempfile.TemporaryDirectory(prefix="node115-bincode-cross-") as td:
        root = Path(td)
        (root / "bincode_fork.rs").write_text(BINCODE_FORK_LIB_RS, encoding="utf-8")
        subprocess.run(
            [
                "rustc", "+1.95.0", "--edition=2021", "--crate-type=rlib",
                "--crate-name=bincode_fork", "-C", "opt-level=3",
                "-C", "overflow-checks=yes", "-C", "embed-bitcode=yes",
                "-o", str(root / "libbincode_fork.rlib"), str(root / "bincode_fork.rs"),
            ],
            env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        # Caller A: rlib (non-LTO) for Decode primitives + SizeWriter/VecWriter fixed-array/u32 encoders
        (root / "caller_a.rs").write_text(CALLER_A_RS, encoding="utf-8")
        subprocess.run(
            [
                "rustc", "+1.95.0", "--edition=2021", "--crate-type=rlib", "--emit=obj",
                "-C", "opt-level=3", "-C", "overflow-checks=yes", "-C", "relocation-model=pic",
                "--extern", f"bincode_fork={root / 'libbincode_fork.rlib'}",
                "-o", str(root / "caller_a.o"), str(root / "caller_a.rs"),
            ],
            env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        # Caller B: ThinLTO internalized varint_encode_u64/usize (SizeWriter & VecWriter) + [u64; 4] SizeWriter/&mut SizeWriter
        out_b = root / "out_b"
        out_b.mkdir()
        (root / "caller_b.rs").write_text(CALLER_B_RS, encoding="utf-8")
        subprocess.run(
            [
                "rustc", "+1.95.0", "--edition=2021", "--crate-type=bin",
                "-C", "opt-level=3", "-C", "overflow-checks=yes",
                "-C", "lto=thin", "-C", "codegen-units=1", "-C", "save-temps",
                "--extern", f"bincode_fork={root / 'libbincode_fork.rlib'}",
                "--out-dir", str(out_b), str(root / "caller_b.rs"),
            ],
            env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        # Caller C: ThinLTO non-internalized varint_encode_u64 (CGU 1 [u64; 4] 151 B + 0x29360e0 155 B re-verify)
        out_c = root / "out_c"
        out_c.mkdir()
        (root / "caller_c.rs").write_text(CALLER_C_RS, encoding="utf-8")
        subprocess.run(
            [
                "rustc", "+1.95.0", "--edition=2021", "--crate-type=bin",
                "-C", "opt-level=3", "-C", "overflow-checks=yes",
                "-C", "lto=thin", "-C", "codegen-units=1", "-C", "save-temps",
                "--extern", f"bincode_fork={root / 'libbincode_fork.rlib'}",
                "--out-dir", str(out_c), str(root / "caller_c.rs"),
            ],
            env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        compiled: list[tuple[str, str, bytes, list[dict]]] = []
        sources = (
            [("caller_a", root / "caller_a.o")]
            + [("caller_b", Path(p)) for p in sorted(glob.glob(str(out_b / "*.rcgu.o")))]
            + [("caller_c", Path(p)) for p in sorted(glob.glob(str(out_c / "*.rcgu.o")))]
        )
        for tag, obj_path in sources:
            for syms, body, rels in object_functions(obj_path.read_bytes()):
                sym = syms[0] if syms else ""
                # Strict anti-stdlib-attribution filter: ONLY first-party `bincode_fork` definitions!
                if not _is_first_party_bincode_symbol(sym):
                    continue
                rel_dicts = [
                    {"offset": r[0], "type": r[1], "addend": r[2], "width": 4}
                    for r in rels
                ]
                compiled.append((tag, sym, body, rel_dicts))
        return compiled, ver


def _is_first_party_bincode_symbol(sym: str) -> bool:
    return (
        "bincode_fork" in sym
        and not sym.startswith(("_ZN4core", "_ZN5alloc", "_ZN3std", "_RINvNt"))
        and not any(bad in sym for bad in ("4core3ptr", "rustc_demangle", "5gimli"))
    )


def check_no_overlaps(windows: list[dict]) -> None:
    """Enforce zero overlap internally, against byte-windows.json, and against ALL sibling compiled-byte packets."""
    intervals: list[tuple[int, int, str]] = []
    for w in windows:
        s = _parse_int(w["start"])
        e = _parse_int(w["end"])
        if s >= e:
            raise AssertionError(f"Invalid empty/reversed window {hex(s)}..{hex(e)}")
        intervals.append((s, e, w["id"]))
    intervals.sort()
    for i in range(len(intervals) - 1):
        if intervals[i][1] > intervals[i + 1][0]:
            raise AssertionError(f"Internal overlap: {intervals[i]} vs {intervals[i + 1]}")

    own_set = {(s, e) for s, e, _ in intervals}

    # Check research/byte-windows.json (allow exact (start, end) ONLY for first-party consolidation,
    # NEVER for dependency or partial overlaps!)
    if BYTE_WINDOWS_JSON.exists():
        bw = json.loads(BYTE_WINDOWS_JSON.read_text(encoding="utf-8"))
        for row in bw.get("windows", bw if isinstance(bw, list) else []):
            if not isinstance(row, dict) or "start" not in row or "end" not in row:
                continue
            bs, be = _parse_int(row["start"]), _parse_int(row["end"])
            is_dep = bool(row.get("dependency")) or row.get("source_kind") != "first-party clean-room rebuild"
            for s, e, wid in intervals:
                if s < be and bs < e:
                    if is_dep or (s, e) != (bs, be):
                        raise AssertionError(
                            f"Overlap with byte-windows.json ({row.get('id')} {hex(bs)}..{hex(be)}): {wid} {hex(s)}..{hex(e)}"
                        )

    # Check ALL sibling compiled-byte work-item packets across ALL VA key spellings
    for p in sorted(WORK_ITEMS_DIR.glob("*/*.json")):
        if p.parent.resolve() == PACKET_DIR.resolve():
            continue
        if p.name not in ("records.json", "census.json"):
            continue
        # Allow Wave 5+ first-party consolidation packets ONLY if exact (start, end) & first-party
        is_consolidation = "consolidation" in p.parent.name
        try:
            j = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows = j if isinstance(j, list) else (
            j.get("windows") or j.get("records") or j.get("matches") or []
        )
        if not isinstance(rows, list):
            continue
        for r in rows:
            if not isinstance(r, dict):
                continue
            if not any(k in r for k in ("compiled_body_sha256", "relocation_qualified", "source_offset", "body_sha256", "relocations")):
                continue
            rs_raw = r.get("start") or r.get("start_va") or r.get("start_addr") or r.get("va")
            if rs_raw is None:
                continue
            rs = _parse_int(rs_raw)
            re_raw = r.get("end") or r.get("end_va") or r.get("end_addr")
            if re_raw is not None:
                re = _parse_int(re_raw)
            else:
                sz = r.get("bytes") or r.get("size_bytes") or r.get("size")
                if sz is None:
                    continue
                re = rs + _parse_int(sz)
            for s, e, wid in intervals:
                if s < re and rs < e:
                    if not (is_consolidation and (s, e) == (rs, re)):
                        raise AssertionError(
                            f"Overlap with sibling packet {p.parent.name} ({hex(rs)}..{hex(re)}): {wid} {hex(s)}..{hex(e)}"
                        )


def build_records(data: bytes) -> tuple[dict, bytes]:
    _, va_to_off = _make_va_to_off(data)
    fdes, ordered_fdes = load_fde_map()
    partition = audit_100_cross_cgu_locations(data, ordered_fdes)
    compiled, rustc_ver = compile_bincode_primitives()

    def match_target(start_va: int, end_va: int):
        if fdes.get(start_va) != end_va:
            raise AssertionError(f"FDE mismatch at {hex(start_va)}: expected {hex(end_va)}, got {hex(fdes.get(start_va, 0))}")
        off = va_to_off(start_va)
        if off is None:
            raise AssertionError(f"Unmapped VA {hex(start_va)}")
        t_bytes = data[off : off + (end_va - start_va)]
        for tag, sym, c_bytes, rels in compiled:
            if len(c_bytes) == len(t_bytes):
                cmp_res = compare(c_bytes, t_bytes, rels)
                if cmp_res["relocation_qualified"] and not cmp_res["non_relocation_difference_offsets"]:
                    return tag, sym, t_bytes, c_bytes, rels, cmp_res
        raise AssertionError(f"No relocation-qualified match for {hex(start_va)}..{hex(end_va)} ({end_va - start_va} B)")

    # Re-verify already-claimed 0x29360e0 (155 B) without adding it to `windows`
    _, rv_sym, _, _, _, rv_cmp = match_target(*ALREADY_CLAIMED_REVERIFY)

    bodies = bytearray()
    windows = []
    for s_va, e_va, wid, attr, label in TARGET_WINDOWS:
        tag, sym, t_bytes, c_bytes, rels, cmp_res = match_target(s_va, e_va)
        if not _is_first_party_bincode_symbol(sym):
            raise AssertionError(f"Non-first-party symbol rejected: {sym}")
        src_off = len(bodies)
        bodies.extend(c_bytes)
        windows.append({
            "id": wid,
            "component": "serialization",
            "attribution": attr,
            "build_unit": tag,
            "symbol": sym,
            "start": hex(s_va),
            "end": hex(e_va),
            "start_va": hex(s_va),
            "end_va": hex(e_va),
            "bytes": len(t_bytes),
            "size_bytes": len(t_bytes),
            "source_offset": src_off,
            "label": label,
            "target_body_sha256": hashlib.sha256(t_bytes).hexdigest(),
            "compiled_body_sha256": hashlib.sha256(c_bytes).hexdigest(),
            "raw_equal": cmp_res["raw_equal"],
            "raw_equal_bytes": cmp_res["raw_equal_bytes"],
            "relocation_bytes": cmp_res["relocation_bytes"],
            "relocation_qualified": cmp_res["relocation_qualified"],
            "relocations": rels,
        })

    check_no_overlaps(windows)
    bodies_bytes = bytes(bodies)
    total_bytes = sum(w["bytes"] for w in windows)
    total_raw = sum(w["raw_equal_bytes"] for w in windows)
    raw_equal_windows = sum(1 for w in windows if w["raw_equal"])

    rec = {
        "schema_version": 1,
        "work_item": "RE-005-node115-bincode-fork-cross-cgu-identity",
        "component": "serialization",
        "components": ["serialization"],
        "target": {
            "path": "artifacts/node/115/hl-node",
            "size_bytes": EXPECTED_BINARY_SIZE,
            "sha256": EXPECTED_BINARY_SHA256,
        },
        "toolchain": {
            "rustc_version": rustc_ver,
            "profile": 'opt-level = 3, overflow-checks = true, lto = "thin" (with cross-crate rlib instantiations)',
        },
        "bodies_file": "bodies.bin",
        "bodies_sha256": hashlib.sha256(bodies_bytes).hexdigest(),
        "summary": {
            "matched_windows": len(windows),
            "matched_bytes": total_bytes,
            "raw_equal_windows": raw_equal_windows,
            "raw_equal_bytes": total_raw,
            "relocation_qualified_windows": len(windows),
            "already_claimed_reverified": {
                "start": hex(ALREADY_CLAIMED_REVERIFY[0]),
                "end": hex(ALREADY_CLAIMED_REVERIFY[1]),
                "bytes": ALREADY_CLAIMED_REVERIFY[1] - ALREADY_CLAIMED_REVERIFY[0],
                "existing_id": "node115-w2-thinlto-29360e0",
                "reverified_symbol": rv_sym,
                "raw_equal_bytes": rv_cmp["raw_equal_bytes"],
                "relocation_qualified": rv_cmp["relocation_qualified"],
            },
            "serialization_cumulative_identity": {
                "dedicated_cgu_fdes": 19,
                "dedicated_cgu_bytes": 7575,
                "dedicated_cgu_coverage_pct": 100.0,
                "cross_cgu_slow_varint_fdes": 4,
                "cross_cgu_slow_varint_bytes": 939,
                "cross_cgu_wave2_varint_fdes": 1,
                "cross_cgu_wave2_varint_bytes": 155,
                "cross_cgu_standalone_matched_here_fdes": len(windows),
                "cross_cgu_standalone_matched_here_bytes": total_bytes,
                "total_verified_serialization_fdes": 19 + 4 + 1 + len(windows),
                "total_verified_serialization_bytes": 7575 + 939 + 155 + total_bytes,
                "remaining_standalone_excluded_fdes": 2,
                "remaining_standalone_excluded_bytes": 1019,
                "remaining_standalone_excluded_note": (
                    "0x2cd7d90 (540 B) and 0x5821540 (479 B) <[u64; 4] as Decode>::decode: "
                    "reproduced at exact 540 B extent (505/540 raw-equal, 3-byte Option<usize> "
                    "cmpb $0x0 vs cmpl $0x1 LLVM InstCombine diff at [20, 22, 23]); excluded from byte claims."
                ),
            },
        },
        "cross_cgu_location_100_partition": partition,
        "windows": windows,
    }
    return rec, bodies_bytes


def verify_records(rec: dict, bodies: bytes, data: bytes) -> dict:
    if len(data) != EXPECTED_BINARY_SIZE:
        raise AssertionError(f"Binary size mismatch: {len(data)}")
    if hashlib.sha256(data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise AssertionError("Binary SHA-256 mismatch")
    if hashlib.sha256(bodies).hexdigest() != rec["bodies_sha256"]:
        raise AssertionError("bodies.bin SHA-256 mismatch")

    _, va_to_off = _make_va_to_off(data)
    fdes, ordered_fdes = load_fde_map()
    live_part = audit_100_cross_cgu_locations(data, ordered_fdes)
    if live_part != rec["cross_cgu_location_100_partition"]:
        raise AssertionError("cross_cgu_location_100_partition does not match live binary audit")

    windows = rec["windows"]
    if len(windows) != len(TARGET_WINDOWS):
        raise AssertionError(f"Expected {len(TARGET_WINDOWS)} windows, got {len(windows)}")
    check_no_overlaps(windows)

    total_bytes = 0
    total_raw = 0
    raw_windows = 0
    for w in windows:
        if w["component"] != "serialization":
            raise AssertionError(f"Unexpected component: {w['component']}")
        if not _is_first_party_bincode_symbol(w["symbol"]):
            raise AssertionError(f"Non-first-party symbol in records.json: {w['symbol']}")
        s = _parse_int(w["start"])
        e = _parse_int(w["end"])
        if fdes.get(s) != e:
            raise AssertionError(f"Window {w['id']} does not match exact FDE extent")
        off = va_to_off(s)
        t_bytes = data[off : off + (e - s)]
        if hashlib.sha256(t_bytes).hexdigest() != w["target_body_sha256"]:
            raise AssertionError(f"target_body_sha256 mismatch on {w['id']}")
        c_bytes = bodies[w["source_offset"] : w["source_offset"] + w["bytes"]]
        if hashlib.sha256(c_bytes).hexdigest() != w["compiled_body_sha256"]:
            raise AssertionError(f"compiled_body_sha256 mismatch on {w['id']}")
        cmp_res = compare(c_bytes, t_bytes, w["relocations"])
        if not cmp_res["relocation_qualified"] or cmp_res["non_relocation_difference_offsets"]:
            raise AssertionError(f"Window {w['id']} failed relocation-qualified compare")
        total_bytes += cmp_res["bytes"]
        total_raw += cmp_res["raw_equal_bytes"]
        if cmp_res["raw_equal"]:
            raw_windows += 1

    return {
        "windows": len(windows),
        "bytes": total_bytes,
        "raw_equal_windows": raw_windows,
        "raw_equal_bytes": total_raw,
        "cross_cgu_location_fdes": live_part["total_cross_cgu_location_fdes"],
        "standalone_location_fdes": live_part["standalone_serialization_fdes"],
        "caller_location_fdes": live_part["caller_crate_composite_fdes"],
    }


def run_self_tests(rec: dict, bodies: bytes, data: bytes) -> int:
    # Negative control 1: tampered target binary byte -> must fail
    bad_data = bytearray(data)
    bad_data[0] ^= 0xFF
    try:
        verify_records(rec, bodies, bytes(bad_data))
    except AssertionError:
        pass
    else:
        raise AssertionError("Negative control 1 failed: accepted tampered binary")

    # Negative control 2: tampered non-relocation byte in bodies.bin -> must fail
    bad_bodies = bytearray(bodies)
    bad_bodies[0] ^= 0x01
    bad_rec = copy.deepcopy(rec)
    bad_rec["bodies_sha256"] = hashlib.sha256(bad_bodies).hexdigest()
    bad_rec["windows"][0]["compiled_body_sha256"] = hashlib.sha256(
        bad_bodies[: bad_rec["windows"][0]["bytes"]]
    ).hexdigest()
    try:
        verify_records(bad_rec, bytes(bad_bodies), data)
    except AssertionError:
        pass
    else:
        raise AssertionError("Negative control 2 failed: accepted tampered compiled body")

    # Negative control 3: stdlib symbol attribution injected -> must fail
    bad_sym = copy.deepcopy(rec)
    bad_sym["windows"][0]["symbol"] = "_ZN4core3ptr42drop_in_place$LT$alloc..string..String$GT$17h0000000000000000E"
    try:
        verify_records(bad_sym, bodies, data)
    except AssertionError:
        pass
    else:
        raise AssertionError("Negative control 3 failed: accepted stdlib symbol attribution")

    # Negative control 4: overlap with byte-windows.json dependency window (0x29360e0) -> must fail
    bad_ov = copy.deepcopy(rec)
    bad_ov["windows"].append({
        **bad_ov["windows"][0],
        "id": "injected-overlap-29360e0",
        "start": "0x29360e0",
        "end": "0x293617b",
    })
    try:
        check_no_overlaps(bad_ov["windows"])
    except AssertionError:
        pass
    else:
        raise AssertionError("Negative control 4 failed: accepted overlap with byte-windows.json")

    return 4


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", type=Path, default=BINARY_PATH)
    ap.add_argument("--rebuild", action="store_true", help="Recompile from source and write records.json + bodies.bin")
    ap.add_argument("--self-test", action="store_true", help="Run 4 negative controls after verification")
    args = ap.parse_args()

    data = args.target.read_bytes()
    if args.rebuild:
        rec, bodies = build_records(data)
        BODIES_PATH.write_bytes(bodies)
        RECORDS_PATH.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    else:
        rec = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        bodies = BODIES_PATH.read_bytes()

    stats = verify_records(rec, bodies, data)
    neg = run_self_tests(rec, bodies, data) if args.self_test else 0
    print(
        f"PASS: {stats['windows']}/{len(TARGET_WINDOWS)} relocation-qualified, "
        f"{stats['bytes']} B ({stats['raw_equal_bytes']} raw-equal, "
        f"{stats['raw_equal_windows']} 100%-raw; "
        f"cross-CGU Locations={stats['cross_cgu_location_fdes']} "
        f"[standalone={stats['standalone_location_fdes']}, caller={stats['caller_location_fdes']}]; "
        f"rebuild={args.rebuild})"
        + (f", {neg}/4 negative controls rejected" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
