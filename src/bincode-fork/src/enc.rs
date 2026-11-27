//! Encoder traits, writers, and primitive/container implementations for node #115
//! `z_forks/bincode-fork` (`src/enc/write.rs` and varint writers at `0x5822850`/`0x5822910`).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::num::{
    NonZeroI8, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroI128, NonZeroIsize, NonZeroU8,
    NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{Configuration, Endian, IntEncoding};
use crate::error::EncodeError;

/// Byte sink abstraction matching `bincode::enc::write::Writer`.
pub trait Writer {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError>;
}

impl<W: Writer + ?Sized> Writer for &mut W {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        (**self).write(bytes)
    }
}

/// Growable `Vec<u8>` writer matching `0x5822910`.
#[derive(Debug, Default)]
pub struct VecWriter {
    inner: Vec<u8>,
}

impl VecWriter {
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: Vec::with_capacity(cap),
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.inner
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }
}

impl Writer for VecWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.inner
            .try_reserve(bytes.len())
            .map_err(|_| EncodeError::AllocationFailed)?;
        self.inner.extend_from_slice(bytes);
        Ok(())
    }
}

/// Fixed-capacity mutable slice writer.
pub struct SliceWriter<'a> {
    slice: &'a mut [u8],
    written: usize,
}

impl<'a> SliceWriter<'a> {
    pub fn new(slice: &'a mut [u8]) -> Self {
        Self { slice, written: 0 }
    }

    pub fn bytes_written(&self) -> usize {
        self.written
    }
}

impl Writer for SliceWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let end = self
            .written
            .checked_add(bytes.len())
            .ok_or(EncodeError::UnexpectedEnd)?;
        if end > self.slice.len() {
            return Err(EncodeError::UnexpectedEnd);
        }
        self.slice[self.written..end].copy_from_slice(bytes);
        self.written = end;
        Ok(())
    }
}

/// Size-counting writer matching `z_forks/bincode-fork/src/enc/write.rs:78:9` (`0x5822850`).
///
/// In node #115, `SizeWriter::write` adds each written chunk sequentially with
/// checked overflow; on a two-step varint (1-byte marker + N-byte payload),
/// a marker increment survives a later payload overflow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SizeWriter {
    pub bytes_written: u64,
}

impl SizeWriter {
    pub const fn new() -> Self {
        Self { bytes_written: 0 }
    }

    pub const fn with_initial(bytes_written: u64) -> Self {
        Self { bytes_written }
    }
}

impl Writer for SizeWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let next = self
            .bytes_written
            .checked_add(bytes.len() as u64)
            .ok_or(EncodeError::SizeOverflow)?;
        self.bytes_written = next;
        Ok(())
    }
}

/// Encoder wrapping a `Writer` and `Configuration`.
pub struct EncoderImpl<W> {
    writer: W,
    config: Configuration,
}

impl<W: Writer> EncoderImpl<W> {
    pub fn new(writer: W, config: Configuration) -> Self {
        Self { writer, config }
    }

    pub fn config(&self) -> Configuration {
        self.config
    }

    pub fn writer(&mut self) -> &mut W {
        &mut self.writer
    }

    pub fn into_writer(self) -> W {
        self.writer
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.writer.write(bytes)
    }

    pub fn write_u8(&mut self, v: u8) -> Result<(), EncodeError> {
        self.writer.write(&[v])
    }

    pub fn write_u16(&mut self, v: u16) -> Result<(), EncodeError> {
        match self.config.int_encoding {
            IntEncoding::Fixed => match self.config.endian {
                Endian::Little => self.writer.write(&v.to_le_bytes()),
                Endian::Big => self.writer.write(&v.to_be_bytes()),
            },
            IntEncoding::Varint => self.write_varint_u128(u128::from(v)),
        }
    }

    pub fn write_u32(&mut self, v: u32) -> Result<(), EncodeError> {
        match self.config.int_encoding {
            IntEncoding::Fixed => match self.config.endian {
                Endian::Little => self.writer.write(&v.to_le_bytes()),
                Endian::Big => self.writer.write(&v.to_be_bytes()),
            },
            IntEncoding::Varint => self.write_varint_u128(u128::from(v)),
        }
    }

    pub fn write_u64(&mut self, v: u64) -> Result<(), EncodeError> {
        match self.config.int_encoding {
            IntEncoding::Fixed => match self.config.endian {
                Endian::Little => self.writer.write(&v.to_le_bytes()),
                Endian::Big => self.writer.write(&v.to_be_bytes()),
            },
            IntEncoding::Varint => self.write_varint_u128(u128::from(v)),
        }
    }

    pub fn write_u128(&mut self, v: u128) -> Result<(), EncodeError> {
        match self.config.int_encoding {
            IntEncoding::Fixed => match self.config.endian {
                Endian::Little => self.writer.write(&v.to_le_bytes()),
                Endian::Big => self.writer.write(&v.to_be_bytes()),
            },
            IntEncoding::Varint => self.write_varint_u128(v),
        }
    }

    pub fn write_usize(&mut self, v: usize) -> Result<(), EncodeError> {
        self.write_u64(v as u64)
    }

    pub fn write_i8(&mut self, v: i8) -> Result<(), EncodeError> {
        self.write_u8(v as u8)
    }

    pub fn write_i16(&mut self, v: i16) -> Result<(), EncodeError> {
        match self.config.int_encoding {
            IntEncoding::Fixed => match self.config.endian {
                Endian::Little => self.writer.write(&v.to_le_bytes()),
                Endian::Big => self.writer.write(&v.to_be_bytes()),
            },
            IntEncoding::Varint => self.write_varint_u128(u128::from(zigzag_i16(v))),
        }
    }

    pub fn write_i32(&mut self, v: i32) -> Result<(), EncodeError> {
        match self.config.int_encoding {
            IntEncoding::Fixed => match self.config.endian {
                Endian::Little => self.writer.write(&v.to_le_bytes()),
                Endian::Big => self.writer.write(&v.to_be_bytes()),
            },
            IntEncoding::Varint => self.write_varint_u128(u128::from(zigzag_i32(v))),
        }
    }

    pub fn write_i64(&mut self, v: i64) -> Result<(), EncodeError> {
        match self.config.int_encoding {
            IntEncoding::Fixed => match self.config.endian {
                Endian::Little => self.writer.write(&v.to_le_bytes()),
                Endian::Big => self.writer.write(&v.to_be_bytes()),
            },
            IntEncoding::Varint => self.write_varint_u128(u128::from(zigzag_i64(v))),
        }
    }

    pub fn write_i128(&mut self, v: i128) -> Result<(), EncodeError> {
        match self.config.int_encoding {
            IntEncoding::Fixed => match self.config.endian {
                Endian::Little => self.writer.write(&v.to_le_bytes()),
                Endian::Big => self.writer.write(&v.to_be_bytes()),
            },
            IntEncoding::Varint => self.write_varint_u128(zigzag_i128(v)),
        }
    }

    pub fn write_isize(&mut self, v: isize) -> Result<(), EncodeError> {
        self.write_i64(v as i64)
    }

    /// Minimal varint encoder matching node #115 `0x5822850` / `0x5822910`:
    /// emits marker first, then payload bytes in the configured endianness.
    fn write_varint_u128(&mut self, v: u128) -> Result<(), EncodeError> {
        if v < 251 {
            self.writer.write(&[v as u8])
        } else if v <= u128::from(u16::MAX) {
            self.writer.write(&[251])?;
            let n = v as u16;
            match self.config.endian {
                Endian::Little => self.writer.write(&n.to_le_bytes()),
                Endian::Big => self.writer.write(&n.to_be_bytes()),
            }
        } else if v <= u128::from(u32::MAX) {
            self.writer.write(&[252])?;
            let n = v as u32;
            match self.config.endian {
                Endian::Little => self.writer.write(&n.to_le_bytes()),
                Endian::Big => self.writer.write(&n.to_be_bytes()),
            }
        } else if v <= u128::from(u64::MAX) {
            self.writer.write(&[253])?;
            let n = v as u64;
            match self.config.endian {
                Endian::Little => self.writer.write(&n.to_le_bytes()),
                Endian::Big => self.writer.write(&n.to_be_bytes()),
            }
        } else {
            self.writer.write(&[254])?;
            match self.config.endian {
                Endian::Little => self.writer.write(&v.to_le_bytes()),
                Endian::Big => self.writer.write(&v.to_be_bytes()),
            }
        }
    }
}

#[inline]
pub const fn zigzag_i16(v: i16) -> u16 {
    ((v << 1) ^ (v >> 15)) as u16
}

#[inline]
pub const fn zigzag_i32(v: i32) -> u32 {
    ((v << 1) ^ (v >> 31)) as u32
}

#[inline]
pub const fn zigzag_i64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

#[inline]
pub const fn zigzag_i128(v: i128) -> u128 {
    ((v << 1) ^ (v >> 127)) as u128
}

/// Wire encoding trait mirroring `bincode::Encode`.
pub trait Encode {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError>;
}

impl<T: Encode + ?Sized> Encode for &T {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        (**self).encode(encoder)
    }
}

impl Encode for () {
    fn encode<W: Writer>(&self, _encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        Ok(())
    }
}

impl Encode for bool {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_u8(u8::from(*self))
    }
}

impl Encode for u8 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_u8(*self)
    }
}

impl Encode for u16 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_u16(*self)
    }
}

impl Encode for u32 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_u32(*self)
    }
}

impl Encode for u64 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_u64(*self)
    }
}

impl Encode for u128 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_u128(*self)
    }
}

impl Encode for usize {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_usize(*self)
    }
}

impl Encode for i8 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_i8(*self)
    }
}

impl Encode for i16 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_i16(*self)
    }
}

impl Encode for i32 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_i32(*self)
    }
}

impl Encode for i64 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_i64(*self)
    }
}

impl Encode for i128 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_i128(*self)
    }
}

impl Encode for isize {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_isize(*self)
    }
}

impl Encode for f32 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        match encoder.config().endian {
            Endian::Little => encoder.write_bytes(&self.to_le_bytes()),
            Endian::Big => encoder.write_bytes(&self.to_be_bytes()),
        }
    }
}

impl Encode for f64 {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        match encoder.config().endian {
            Endian::Little => encoder.write_bytes(&self.to_le_bytes()),
            Endian::Big => encoder.write_bytes(&self.to_be_bytes()),
        }
    }
}

impl Encode for char {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        let mut buf = [0u8; 4];
        let encoded = self.encode_utf8(&mut buf);
        encoder.write_bytes(encoded.as_bytes())
    }
}

impl Encode for [u8] {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_usize(self.len())?;
        encoder.write_bytes(self)
    }
}

impl Encode for str {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        self.as_bytes().encode(encoder)
    }
}

impl Encode for String {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        self.as_str().encode(encoder)
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_usize(self.len())?;
        for item in self {
            item.encode(encoder)?;
        }
        Ok(())
    }
}

impl<T: Encode, const N: usize> Encode for [T; N] {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        for item in self {
            item.encode(encoder)?;
        }
        Ok(())
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        match self {
            None => encoder.write_u8(0),
            Some(v) => {
                encoder.write_u8(1)?;
                v.encode(encoder)
            }
        }
    }
}

impl<T: Encode, E: Encode> Encode for Result<T, E> {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        match self {
            Ok(v) => {
                encoder.write_u32(0)?;
                v.encode(encoder)
            }
            Err(e) => {
                encoder.write_u32(1)?;
                e.encode(encoder)
            }
        }
    }
}

impl<T: Encode> Encode for Box<T> {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        (**self).encode(encoder)
    }
}

impl<K: Encode, V: Encode> Encode for BTreeMap<K, V> {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_usize(self.len())?;
        for (k, v) in self {
            k.encode(encoder)?;
            v.encode(encoder)?;
        }
        Ok(())
    }
}

impl<T: Encode> Encode for BTreeSet<T> {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_usize(self.len())?;
        for item in self {
            item.encode(encoder)?;
        }
        Ok(())
    }
}

impl Encode for Duration {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        self.as_secs().encode(encoder)?;
        self.subsec_nanos().encode(encoder)
    }
}

impl<A: Encode, B: Encode> Encode for (A, B) {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        self.0.encode(encoder)?;
        self.1.encode(encoder)
    }
}

impl<A: Encode, B: Encode, C: Encode> Encode for (A, B, C) {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        self.0.encode(encoder)?;
        self.1.encode(encoder)?;
        self.2.encode(encoder)
    }
}

/// Byte vector wrapper that encodes/decodes via the Hyperliquid fork's
/// `InvalidBytesLength` pre-allocation check (`0x5821b64..0x5821b75`).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteVec(pub Vec<u8>);

impl Encode for ByteVec {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        self.0.as_slice().encode(encoder)
    }
}

/// Streaming `std::io::Write` adapter matching `bincode::enc::write::IoWriter`.
pub struct IoWriter<W> {
    inner: W,
    bytes_written: usize,
}

impl<W> IoWriter<W> {
    pub const fn new(inner: W) -> Self {
        Self {
            inner,
            bytes_written: 0,
        }
    }

    pub const fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Writer for IoWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.inner.write_all(bytes).map_err(|inner| EncodeError::Io {
            inner,
            index: self.bytes_written,
        })?;
        self.bytes_written = self.bytes_written.saturating_add(bytes.len());
        Ok(())
    }
}

macro_rules! impl_encode_nonzero {
    ($nz:ty) => {
        impl Encode for $nz {
            fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
                self.get().encode(encoder)
            }
        }
    };
}

impl_encode_nonzero!(NonZeroU8);
impl_encode_nonzero!(NonZeroU16);
impl_encode_nonzero!(NonZeroU32);
impl_encode_nonzero!(NonZeroU64);
impl_encode_nonzero!(NonZeroU128);
impl_encode_nonzero!(NonZeroUsize);
impl_encode_nonzero!(NonZeroI8);
impl_encode_nonzero!(NonZeroI16);
impl_encode_nonzero!(NonZeroI32);
impl_encode_nonzero!(NonZeroI64);
impl_encode_nonzero!(NonZeroI128);
impl_encode_nonzero!(NonZeroIsize);

impl Encode for CStr {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        self.to_bytes().encode(encoder)
    }
}

impl Encode for CString {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        self.as_bytes().encode(encoder)
    }
}

impl Encode for SystemTime {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        let duration = self
            .duration_since(UNIX_EPOCH)
            .map_err(|e| EncodeError::InvalidSystemTime {
                duration: e.duration(),
            })?;
        duration.encode(encoder)
    }
}
