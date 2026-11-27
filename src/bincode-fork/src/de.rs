//! Decoder traits, readers, limit accounting, and primitive/container implementations
//! matching Hyperliquid node #115 `z_forks/bincode-fork` (`src/de/decoder.rs`,
//! `src/de/impls.rs`, and varint readers `0x5821150`/`0x5821250`/`0x5821340`).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::io::Read;
use std::num::{
    NonZeroI8, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroI128, NonZeroIsize, NonZeroU8,
    NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{Configuration, Endian, IntEncoding, Limit};
use crate::enc::ByteVec;
use crate::error::{AllowedEnumVariants, DecodeError, IntegerType};

/// Maximum preallocation budget per container decode observed in node #115 `0x58245fe`
/// (`cmpq $0xa3d, %r12` for 400-byte elements => `1_048_576 / 400 = 2621`).
pub const MAX_PREALLOCATION_SIZE: usize = 1024 * 1024;

static OPTION_VARIANTS: AllowedEnumVariants = AllowedEnumVariants::Range { min: 0, max: 1 };
static RESULT_VARIANTS: AllowedEnumVariants = AllowedEnumVariants::Range { min: 0, max: 1 };

/// Byte source abstraction matching `bincode::de::read::Reader`.
pub trait Reader {
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), DecodeError>;

    /// Remaining slice length when backed by an in-memory slice.
    /// Used by `z_forks/bincode-fork`'s `InvalidBytesLength` pre-allocation check.
    fn remaining_len(&self) -> Option<usize> {
        None
    }

    fn peek_slice(&self) -> Option<&[u8]> {
        None
    }

    fn advance(&mut self, _n: usize) -> bool {
        false
    }
}

/// Borrowed slice reader matching node #115 decoder state (`+0x10` ptr, `+0x18` len).
#[derive(Clone, Copy, Debug)]
pub struct SliceReader<'a> {
    slice: &'a [u8],
}

impl<'a> SliceReader<'a> {
    pub const fn new(slice: &'a [u8]) -> Self {
        Self { slice }
    }

    pub const fn remaining(&self) -> &'a [u8] {
        self.slice
    }
}

impl Reader for SliceReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), DecodeError> {
        if bytes.len() > self.slice.len() {
            return Err(DecodeError::UnexpectedEnd {
                additional: bytes.len() - self.slice.len(),
            });
        }
        let (head, tail) = self.slice.split_at(bytes.len());
        bytes.copy_from_slice(head);
        self.slice = tail;
        Ok(())
    }

    fn remaining_len(&self) -> Option<usize> {
        Some(self.slice.len())
    }

    fn peek_slice(&self) -> Option<&[u8]> {
        Some(self.slice)
    }

    fn advance(&mut self, n: usize) -> bool {
        if n <= self.slice.len() {
            self.slice = &self.slice[n..];
            true
        } else {
            false
        }
    }
}

/// Decoder state matching node #115 `z_forks/bincode-fork/src/de/decoder.rs`.
///
/// Layout verified in `0x5821150` / `0x5821250` / `0x5821340` / `0x5824570`:
/// - `config.limit` (`+0x0` mode, `+0x8` limit)
/// - `reader` (`+0x10` ptr, `+0x18` len)
/// - `bytes_read` (`+0x20` cumulative claimed bytes)
pub struct DecoderImpl<R> {
    reader: R,
    config: Configuration,
    bytes_read: u64,
}

impl<R: Reader> DecoderImpl<R> {
    pub fn new(reader: R, config: Configuration) -> Self {
        Self {
            reader,
            config,
            bytes_read: 0,
        }
    }

    pub fn with_initial_bytes_read(reader: R, config: Configuration, bytes_read: u64) -> Self {
        Self {
            reader,
            config,
            bytes_read,
        }
    }

    pub fn config(&self) -> Configuration {
        self.config
    }

    pub fn reader(&self) -> &R {
        &self.reader
    }

    pub fn reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Claim `n` bytes against the configured limit.
    ///
    /// Matches node #115 `0x5821150`/`0x5821250`/`0x5821340` exact side effects:
    /// - Arithmetic overflow returns `LimitExceeded` WITHOUT mutating `bytes_read`.
    /// - Otherwise, the sum is STORED into `bytes_read` BEFORE comparing `> limit`,
    ///   so an over-limit charge remains recorded after returning `LimitExceeded`.
    pub fn claim_bytes_read(&mut self, n: usize) -> Result<(), DecodeError> {
        if let Limit::Bytes(limit) = self.config.limit {
            let next = self
                .bytes_read
                .checked_add(n as u64)
                .ok_or(DecodeError::LimitExceeded)?;
            self.bytes_read = next;
            if next > limit {
                return Err(DecodeError::LimitExceeded);
            }
        }
        Ok(())
    }

    /// Claim container payload bytes `len * size_of::<T>()`, matching `0x58245aa..0x58245ca`.
    pub fn claim_container_read<T>(&mut self, len: usize) -> Result<(), DecodeError> {
        if let Limit::Bytes(limit) = self.config.limit {
            let total = (len as u64)
                .checked_mul(core::mem::size_of::<T>() as u64)
                .ok_or(DecodeError::LimitExceeded)?;
            let next = self
                .bytes_read
                .checked_add(total)
                .ok_or(DecodeError::LimitExceeded)?;
            self.bytes_read = next;
            if next > limit {
                return Err(DecodeError::LimitExceeded);
            }
        }
        Ok(())
    }

    /// Refund previously pre-claimed bytes before decoding an element, matching
    /// `z_forks/bincode-fork/src/de/decoder.rs:93:13` (`0x5824692..0x58246aa`, `0x5821606..0x5821618`).
    pub fn unclaim_bytes_read(&mut self, n: usize) {
        if let Limit::Bytes(_) = self.config.limit {
            self.bytes_read = self
                .bytes_read
                .checked_sub(n as u64)
                .expect("bincode-fork::de::decoder: unclaim_bytes_read underflow");
        }
    }

    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        self.claim_bytes_read(1)?;
        let mut buf = [0u8; 1];
        self.reader.read(&mut buf)?;
        Ok(buf[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        self.claim_bytes_read(2)?;
        match self.config.int_encoding {
            IntEncoding::Fixed => {
                let mut buf = [0u8; 2];
                self.reader.read(&mut buf)?;
                Ok(match self.config.endian {
                    Endian::Little => u16::from_le_bytes(buf),
                    Endian::Big => u16::from_be_bytes(buf),
                })
            }
            IntEncoding::Varint => self.read_varint_u16(),
        }
    }

    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        self.claim_bytes_read(4)?;
        match self.config.int_encoding {
            IntEncoding::Fixed => {
                let mut buf = [0u8; 4];
                self.reader.read(&mut buf)?;
                Ok(match self.config.endian {
                    Endian::Little => u32::from_le_bytes(buf),
                    Endian::Big => u32::from_be_bytes(buf),
                })
            }
            IntEncoding::Varint => self.read_varint_u32(),
        }
    }

    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        self.claim_bytes_read(8)?;
        match self.config.int_encoding {
            IntEncoding::Fixed => {
                let mut buf = [0u8; 8];
                self.reader.read(&mut buf)?;
                Ok(match self.config.endian {
                    Endian::Little => u64::from_le_bytes(buf),
                    Endian::Big => u64::from_be_bytes(buf),
                })
            }
            IntEncoding::Varint => self.read_varint_u64(IntegerType::U32, IntegerType::U64),
        }
    }

    pub fn read_usize(&mut self) -> Result<usize, DecodeError> {
        self.claim_bytes_read(core::mem::size_of::<usize>())?;
        match self.config.int_encoding {
            IntEncoding::Fixed => {
                let mut buf = [0u8; 8];
                self.reader.read(&mut buf)?;
                let v = match self.config.endian {
                    Endian::Little => u64::from_le_bytes(buf),
                    Endian::Big => u64::from_be_bytes(buf),
                };
                usize::try_from(v).map_err(|_| DecodeError::OutsideUsizeRange(v))
            }
            IntEncoding::Varint => {
                // Node #115 `0x5821340` / `0x5822710` reports `expected = IntegerType::Usize` (5)
                // on both fast and slow paths.
                let v = self.read_varint_u64(IntegerType::Usize, IntegerType::Usize)?;
                usize::try_from(v).map_err(|_| DecodeError::OutsideUsizeRange(v))
            }
        }
    }

    pub fn read_u128(&mut self) -> Result<u128, DecodeError> {
        self.claim_bytes_read(16)?;
        match self.config.int_encoding {
            IntEncoding::Fixed => {
                let mut buf = [0u8; 16];
                self.reader.read(&mut buf)?;
                Ok(match self.config.endian {
                    Endian::Little => u128::from_le_bytes(buf),
                    Endian::Big => u128::from_be_bytes(buf),
                })
            }
            IntEncoding::Varint => self.read_varint_u128(),
        }
    }

    pub fn read_i8(&mut self) -> Result<i8, DecodeError> {
        Ok(self.read_u8()? as i8)
    }

    pub fn read_i16(&mut self) -> Result<i16, DecodeError> {
        self.claim_bytes_read(2)?;
        match self.config.int_encoding {
            IntEncoding::Fixed => {
                let mut buf = [0u8; 2];
                self.reader.read(&mut buf)?;
                Ok(match self.config.endian {
                    Endian::Little => i16::from_le_bytes(buf),
                    Endian::Big => i16::from_be_bytes(buf),
                })
            }
            IntEncoding::Varint => {
                let u = self.read_varint_u16_with_expected(IntegerType::I16)?;
                Ok(unzigzag_i16(u))
            }
        }
    }

    pub fn read_i32(&mut self) -> Result<i32, DecodeError> {
        self.claim_bytes_read(4)?;
        match self.config.int_encoding {
            IntEncoding::Fixed => {
                let mut buf = [0u8; 4];
                self.reader.read(&mut buf)?;
                Ok(match self.config.endian {
                    Endian::Little => i32::from_le_bytes(buf),
                    Endian::Big => i32::from_be_bytes(buf),
                })
            }
            IntEncoding::Varint => {
                let u = self.read_varint_u32_with_expected(IntegerType::I32)?;
                Ok(unzigzag_i32(u))
            }
        }
    }

    pub fn read_i64(&mut self) -> Result<i64, DecodeError> {
        self.claim_bytes_read(8)?;
        match self.config.int_encoding {
            IntEncoding::Fixed => {
                let mut buf = [0u8; 8];
                self.reader.read(&mut buf)?;
                Ok(match self.config.endian {
                    Endian::Little => i64::from_le_bytes(buf),
                    Endian::Big => i64::from_be_bytes(buf),
                })
            }
            IntEncoding::Varint => {
                // Node #115 signed scalar (`node115-signed-scalar`): fast path reports
                // expected=I32(8), slow path reports expected=I64(9), found=I128(10)/Reserved(12).
                let u = self.read_varint_signed_u64()?;
                Ok(unzigzag_i64(u))
            }
        }
    }

    pub fn read_i128(&mut self) -> Result<i128, DecodeError> {
        self.claim_bytes_read(16)?;
        match self.config.int_encoding {
            IntEncoding::Fixed => {
                let mut buf = [0u8; 16];
                self.reader.read(&mut buf)?;
                Ok(match self.config.endian {
                    Endian::Little => i128::from_le_bytes(buf),
                    Endian::Big => i128::from_be_bytes(buf),
                })
            }
            IntEncoding::Varint => {
                let u = self.read_varint_u128_with_expected(IntegerType::I128)?;
                Ok(unzigzag_i128(u))
            }
        }
    }

    pub fn read_isize(&mut self) -> Result<isize, DecodeError> {
        let v = self.read_i64()?;
        isize::try_from(v).map_err(|_| DecodeError::OutsideUsizeRange(v as u64))
    }

    /// Hyperliquid fork byte-vector decoder verified at `0x5821b1c..0x5821da5`:
    /// 1. Reads varint `len: usize`
    /// 2. Calls `claim_bytes_read(len)` (LimitExceeded takes precedence!)
    /// 3. If backed by a slice and `remaining < len`, returns `DecodeError::InvalidBytesLength`
    ///    BEFORE allocating any heap memory.
    /// 4. Allocates and copies `len` bytes.
    pub fn decode_byte_vec(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.read_usize()?;
        self.claim_bytes_read(len)?;
        if let Some(remaining) = self.reader.remaining_len()
            && remaining < len
        {
            return Err(DecodeError::InvalidBytesLength);
        }
        let mut buf = vec![0u8; len];
        self.reader.read(&mut buf)?;
        Ok(buf)
    }

    fn read_varint_u16(&mut self) -> Result<u16, DecodeError> {
        self.read_varint_u16_with_expected(IntegerType::U16)
    }

    fn read_varint_u16_with_expected(&mut self, expected: IntegerType) -> Result<u16, DecodeError> {
        if let Some(slice) = self.reader.peek_slice() {
            let slow = slice.len() <= 2;
            let Some(&marker) = slice.first() else {
                return Err(DecodeError::UnexpectedEnd { additional: 1 });
            };
            let (advance, res) = match marker {
                0..=250 => (1, Ok(u16::from(marker))),
                251 if slice.len() < 3 => (
                    usize::from(slow),
                    Err(DecodeError::UnexpectedEnd {
                        additional: 3 - slice.len(),
                    }),
                ),
                251 => {
                    let b = [slice[1], slice[2]];
                    let v = match self.config.endian {
                        Endian::Little => u16::from_le_bytes(b),
                        Endian::Big => u16::from_be_bytes(b),
                    };
                    (3, Ok(v))
                }
                252 => (
                    usize::from(slow),
                    Err(DecodeError::InvalidIntegerType {
                        expected,
                        found: IntegerType::U32,
                    }),
                ),
                253 => (
                    usize::from(slow),
                    Err(DecodeError::InvalidIntegerType {
                        expected,
                        found: IntegerType::U64,
                    }),
                ),
                254 => (
                    usize::from(slow),
                    Err(DecodeError::InvalidIntegerType {
                        expected,
                        found: IntegerType::U128,
                    }),
                ),
                255 => (
                    usize::from(slow),
                    Err(DecodeError::InvalidIntegerType {
                        expected,
                        found: IntegerType::Reserved,
                    }),
                ),
            };
            if advance > 0 {
                self.reader.advance(advance);
            }
            return res;
        }
        let mut marker = [0u8; 1];
        self.reader.read(&mut marker)?;
        match marker[0] {
            0..=250 => Ok(u16::from(marker[0])),
            251 => {
                let mut b = [0u8; 2];
                self.reader.read(&mut b)?;
                Ok(match self.config.endian {
                    Endian::Little => u16::from_le_bytes(b),
                    Endian::Big => u16::from_be_bytes(b),
                })
            }
            252 => Err(DecodeError::InvalidIntegerType {
                expected,
                found: IntegerType::U32,
            }),
            253 => Err(DecodeError::InvalidIntegerType {
                expected,
                found: IntegerType::U64,
            }),
            254 => Err(DecodeError::InvalidIntegerType {
                expected,
                found: IntegerType::U128,
            }),
            255 => Err(DecodeError::InvalidIntegerType {
                expected,
                found: IntegerType::Reserved,
            }),
        }
    }

    fn read_varint_u32(&mut self) -> Result<u32, DecodeError> {
        self.read_varint_u32_with_expected(IntegerType::U32)
    }

    /// Matches node #115 `0x5821150` (fast: `remaining > 4`) and `0x5822490` (slow: `remaining <= 4`).
    fn read_varint_u32_with_expected(&mut self, expected: IntegerType) -> Result<u32, DecodeError> {
        if let Some(slice) = self.reader.peek_slice() {
            let slow = slice.len() <= 4;
            let Some(&marker) = slice.first() else {
                return Err(DecodeError::UnexpectedEnd { additional: 1 });
            };
            let (advance, res) = match marker {
                0..=250 => (1, Ok(u32::from(marker))),
                251 if slice.len() < 3 => (
                    usize::from(slow),
                    Err(DecodeError::UnexpectedEnd {
                        additional: 3 - slice.len(),
                    }),
                ),
                251 => {
                    let b = [slice[1], slice[2]];
                    let v = match self.config.endian {
                        Endian::Little => u16::from_le_bytes(b),
                        Endian::Big => u16::from_be_bytes(b),
                    };
                    (3, Ok(u32::from(v)))
                }
                252 if slice.len() < 5 => (
                    usize::from(slow),
                    Err(DecodeError::UnexpectedEnd {
                        additional: 5 - slice.len(),
                    }),
                ),
                252 => {
                    let b = [slice[1], slice[2], slice[3], slice[4]];
                    let v = match self.config.endian {
                        Endian::Little => u32::from_le_bytes(b),
                        Endian::Big => u32::from_be_bytes(b),
                    };
                    (5, Ok(v))
                }
                253 => (
                    usize::from(slow),
                    Err(DecodeError::InvalidIntegerType {
                        expected,
                        found: IntegerType::U64,
                    }),
                ),
                254 => (
                    usize::from(slow),
                    Err(DecodeError::InvalidIntegerType {
                        expected,
                        found: IntegerType::U128,
                    }),
                ),
                255 => (
                    usize::from(slow),
                    Err(DecodeError::InvalidIntegerType {
                        expected,
                        found: IntegerType::Reserved,
                    }),
                ),
            };
            if advance > 0 {
                self.reader.advance(advance);
            }
            return res;
        }
        let mut marker = [0u8; 1];
        self.reader.read(&mut marker)?;
        match marker[0] {
            0..=250 => Ok(u32::from(marker[0])),
            251 => {
                let mut b = [0u8; 2];
                self.reader.read(&mut b)?;
                let v = match self.config.endian {
                    Endian::Little => u16::from_le_bytes(b),
                    Endian::Big => u16::from_be_bytes(b),
                };
                Ok(u32::from(v))
            }
            252 => {
                let mut b = [0u8; 4];
                self.reader.read(&mut b)?;
                Ok(match self.config.endian {
                    Endian::Little => u32::from_le_bytes(b),
                    Endian::Big => u32::from_be_bytes(b),
                })
            }
            253 => Err(DecodeError::InvalidIntegerType {
                expected,
                found: IntegerType::U64,
            }),
            254 => Err(DecodeError::InvalidIntegerType {
                expected,
                found: IntegerType::U128,
            }),
            255 => Err(DecodeError::InvalidIntegerType {
                expected,
                found: IntegerType::Reserved,
            }),
        }
    }

    /// Matches node #115 `0x5821250`/`0x58225c0` (`u64`) and `0x5821340`/`0x5822710` (`usize`).
    fn read_varint_u64(
        &mut self,
        expected_fast: IntegerType,
        expected_slow: IntegerType,
    ) -> Result<u64, DecodeError> {
        if let Some(slice) = self.reader.peek_slice() {
            let slow = slice.len() <= 8;
            let Some(&marker) = slice.first() else {
                return Err(DecodeError::UnexpectedEnd { additional: 1 });
            };
            let (advance, res) = if marker < 251 {
                (1, Ok(u64::from(marker)))
            } else {
                match marker {
                    251..=253 => {
                        let width = match marker {
                            251 => 3,
                            252 => 5,
                            _ => 9,
                        };
                        if slice.len() < width {
                            (
                                usize::from(slow),
                                Err(DecodeError::UnexpectedEnd {
                                    additional: width - slice.len(),
                                }),
                            )
                        } else {
                            let val =
                                decode_endian_u64(&slice[1..width], width - 1, self.config.endian);
                            (width, Ok(val))
                        }
                    }
                    254 => (
                        usize::from(slow),
                        Err(DecodeError::InvalidIntegerType {
                            expected: if slow { expected_slow } else { expected_fast },
                            found: IntegerType::U128,
                        }),
                    ),
                    _ => (
                        usize::from(slow),
                        Err(DecodeError::InvalidIntegerType {
                            expected: if slow { expected_slow } else { expected_fast },
                            found: IntegerType::Reserved,
                        }),
                    ),
                }
            };
            if advance > 0 {
                self.reader.advance(advance);
            }
            return res;
        }
        let mut marker = [0u8; 1];
        self.reader.read(&mut marker)?;
        if marker[0] < 251 {
            return Ok(u64::from(marker[0]));
        }
        let payload_len = match marker[0] {
            251 => 2,
            252 => 4,
            253 => 8,
            254 => {
                return Err(DecodeError::InvalidIntegerType {
                    expected: expected_slow,
                    found: IntegerType::U128,
                });
            }
            _ => {
                return Err(DecodeError::InvalidIntegerType {
                    expected: expected_slow,
                    found: IntegerType::Reserved,
                });
            }
        };
        let mut buf = [0u8; 8];
        self.reader.read(&mut buf[..payload_len])?;
        Ok(decode_endian_u64(
            &buf[..payload_len],
            payload_len,
            self.config.endian,
        ))
    }

    fn read_varint_signed_u64(&mut self) -> Result<u64, DecodeError> {
        if let Some(slice) = self.reader.peek_slice() {
            let slow = slice.len() <= 8;
            let Some(&marker) = slice.first() else {
                return Err(DecodeError::UnexpectedEnd { additional: 1 });
            };
            let (advance, res) = if marker < 251 {
                (1, Ok(u64::from(marker)))
            } else {
                match marker {
                    251..=253 => {
                        let width = match marker {
                            251 => 3,
                            252 => 5,
                            _ => 9,
                        };
                        if slice.len() < width {
                            (
                                usize::from(slow),
                                Err(DecodeError::UnexpectedEnd {
                                    additional: width - slice.len(),
                                }),
                            )
                        } else {
                            let val =
                                decode_endian_u64(&slice[1..width], width - 1, self.config.endian);
                            (width, Ok(val))
                        }
                    }
                    254 => (
                        usize::from(slow),
                        Err(DecodeError::InvalidIntegerType {
                            expected: if slow {
                                IntegerType::I64
                            } else {
                                IntegerType::I32
                            },
                            found: IntegerType::I128,
                        }),
                    ),
                    _ => (
                        usize::from(slow),
                        Err(DecodeError::InvalidIntegerType {
                            expected: if slow {
                                IntegerType::I64
                            } else {
                                IntegerType::I32
                            },
                            found: IntegerType::Reserved,
                        }),
                    ),
                }
            };
            if advance > 0 {
                self.reader.advance(advance);
            }
            return res;
        }
        self.read_varint_u64(IntegerType::I32, IntegerType::I64)
    }

    fn read_varint_u128(&mut self) -> Result<u128, DecodeError> {
        self.read_varint_u128_with_expected(IntegerType::U128)
    }

    fn read_varint_u128_with_expected(
        &mut self,
        expected: IntegerType,
    ) -> Result<u128, DecodeError> {
        if let Some(slice) = self.reader.peek_slice() {
            let slow = slice.len() <= 16;
            let Some(&marker) = slice.first() else {
                return Err(DecodeError::UnexpectedEnd { additional: 1 });
            };
            let (advance, res) = if marker < 251 {
                (1, Ok(u128::from(marker)))
            } else {
                match marker {
                    251..=254 => {
                        let width = match marker {
                            251 => 3,
                            252 => 5,
                            253 => 9,
                            _ => 17,
                        };
                        if slice.len() < width {
                            (
                                usize::from(slow),
                                Err(DecodeError::UnexpectedEnd {
                                    additional: width - slice.len(),
                                }),
                            )
                        } else {
                            let val =
                                decode_endian_u128(&slice[1..width], width - 1, self.config.endian);
                            (width, Ok(val))
                        }
                    }
                    _ => (
                        usize::from(slow),
                        Err(DecodeError::InvalidIntegerType {
                            expected,
                            found: IntegerType::Reserved,
                        }),
                    ),
                }
            };
            if advance > 0 {
                self.reader.advance(advance);
            }
            return res;
        }
        let mut marker = [0u8; 1];
        self.reader.read(&mut marker)?;
        if marker[0] < 251 {
            return Ok(u128::from(marker[0]));
        }
        let payload_len = match marker[0] {
            251 => 2,
            252 => 4,
            253 => 8,
            254 => 16,
            _ => {
                return Err(DecodeError::InvalidIntegerType {
                    expected,
                    found: IntegerType::Reserved,
                });
            }
        };
        let mut buf = [0u8; 16];
        self.reader.read(&mut buf[..payload_len])?;
        Ok(decode_endian_u128(
            &buf[..payload_len],
            payload_len,
            self.config.endian,
        ))
    }
}

fn decode_endian_u64(payload: &[u8], payload_len: usize, endian: Endian) -> u64 {
    let mut bytes = [0u8; 8];
    match endian {
        Endian::Little => {
            bytes[..payload_len].copy_from_slice(payload);
            u64::from_le_bytes(bytes)
        }
        Endian::Big => {
            bytes[8 - payload_len..].copy_from_slice(payload);
            u64::from_be_bytes(bytes)
        }
    }
}

fn decode_endian_u128(payload: &[u8], payload_len: usize, endian: Endian) -> u128 {
    let mut bytes = [0u8; 16];
    match endian {
        Endian::Little => {
            bytes[..payload_len].copy_from_slice(payload);
            u128::from_le_bytes(bytes)
        }
        Endian::Big => {
            bytes[16 - payload_len..].copy_from_slice(payload);
            u128::from_be_bytes(bytes)
        }
    }
}

#[inline]
pub const fn unzigzag_i16(u: u16) -> i16 {
    ((u >> 1) as i16) ^ -((u & 1) as i16)
}

#[inline]
pub const fn unzigzag_i32(u: u32) -> i32 {
    ((u >> 1) as i32) ^ -((u & 1) as i32)
}

#[inline]
pub const fn unzigzag_i64(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}

#[inline]
pub const fn unzigzag_i128(u: u128) -> i128 {
    ((u >> 1) as i128) ^ -((u & 1) as i128)
}

/// Wire decoding trait mirroring `bincode::Decode`.
pub trait Decode: Sized {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError>;
}

impl Decode for () {
    fn decode<R: Reader>(_decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        Ok(())
    }
}

impl Decode for bool {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        match decoder.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(DecodeError::InvalidBooleanValue(other)),
        }
    }
}

impl Decode for u8 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_u8()
    }
}

impl Decode for u16 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_u16()
    }
}

impl Decode for u32 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_u32()
    }
}

impl Decode for u64 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_u64()
    }
}

impl Decode for u128 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_u128()
    }
}

impl Decode for usize {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_usize()
    }
}

impl Decode for i8 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_i8()
    }
}

impl Decode for i16 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_i16()
    }
}

impl Decode for i32 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_i32()
    }
}

impl Decode for i64 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_i64()
    }
}

impl Decode for i128 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_i128()
    }
}

impl Decode for isize {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.read_isize()
    }
}

impl Decode for f32 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(4)?;
        let mut buf = [0u8; 4];
        decoder.reader_mut().read(&mut buf)?;
        Ok(match decoder.config().endian {
            Endian::Little => f32::from_le_bytes(buf),
            Endian::Big => f32::from_be_bytes(buf),
        })
    }
}

impl Decode for f64 {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(8)?;
        let mut buf = [0u8; 8];
        decoder.reader_mut().read(&mut buf)?;
        Ok(match decoder.config().endian {
            Endian::Little => f64::from_le_bytes(buf),
            Endian::Big => f64::from_be_bytes(buf),
        })
    }
}

impl Decode for char {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 4];
        bytes[0] = decoder.read_u8()?;
        let width = utf8_char_width(bytes[0]);
        if width == 0 {
            return Err(DecodeError::InvalidCharEncoding(bytes));
        }
        if width > 1 {
            decoder.claim_bytes_read(width - 1)?;
            decoder.reader_mut().read(&mut bytes[1..width])?;
        }
        let s = core::str::from_utf8(&bytes[..width])
            .map_err(|_| DecodeError::InvalidCharEncoding(bytes))?;
        s.chars()
            .next()
            .ok_or(DecodeError::InvalidCharEncoding(bytes))
    }
}

const fn utf8_char_width(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if (first & 0xE0) == 0xC0 {
        2
    } else if (first & 0xF0) == 0xE0 {
        3
    } else if (first & 0xF8) == 0xF0 {
        4
    } else {
        0
    }
}

impl Decode for ByteVec {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.decode_byte_vec().map(ByteVec)
    }
}

impl Decode for String {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let bytes = decoder.decode_byte_vec()?;
        String::from_utf8(bytes).map_err(|e| DecodeError::Utf8 {
            inner: e.utf8_error(),
        })
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let len = decoder.read_usize()?;
        decoder.claim_container_read::<T>(len)?;
        let elem_size = core::mem::size_of::<T>();
        let cap = MAX_PREALLOCATION_SIZE
            .checked_div(elem_size)
            .map_or(0, |max_items| len.min(max_items));
        let mut vec = Vec::with_capacity(cap);
        for _ in 0..len {
            decoder.unclaim_bytes_read(elem_size);
            vec.push(T::decode(decoder)?);
        }
        Ok(vec)
    }
}

impl<T: Decode, const N: usize> Decode for [T; N] {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        decoder.claim_container_read::<T>(N)?;
        let elem_size = core::mem::size_of::<T>();
        let mut items = Vec::with_capacity(N);
        for _ in 0..N {
            decoder.unclaim_bytes_read(elem_size);
            items.push(T::decode(decoder)?);
        }
        let arr: [T; N] = items
            .try_into()
            .unwrap_or_else(|_| unreachable!("bincode-fork::de::impls array length mismatch"));
        Ok(arr)
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        match decoder.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(T::decode(decoder)?)),
            other => Err(DecodeError::UnexpectedVariant {
                type_name: "Option",
                allowed: &OPTION_VARIANTS,
                found: u32::from(other),
            }),
        }
    }
}

impl<T: Decode, E: Decode> Decode for Result<T, E> {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        match decoder.read_u32()? {
            0 => Ok(Ok(T::decode(decoder)?)),
            1 => Ok(Err(E::decode(decoder)?)),
            other => Err(DecodeError::UnexpectedVariant {
                type_name: "Result",
                allowed: &RESULT_VARIANTS,
                found: other,
            }),
        }
    }
}

impl<T: Decode> Decode for Box<T> {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        T::decode(decoder).map(Box::new)
    }
}

impl<K: Decode + Ord, V: Decode> Decode for BTreeMap<K, V> {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let len = decoder.read_usize()?;
        decoder.claim_container_read::<(K, V)>(len)?;
        let elem_size = core::mem::size_of::<(K, V)>();
        let mut map = BTreeMap::new();
        for _ in 0..len {
            decoder.unclaim_bytes_read(elem_size);
            let k = K::decode(decoder)?;
            let v = V::decode(decoder)?;
            map.insert(k, v);
        }
        Ok(map)
    }
}

impl<T: Decode + Ord> Decode for BTreeSet<T> {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let len = decoder.read_usize()?;
        decoder.claim_container_read::<T>(len)?;
        let elem_size = core::mem::size_of::<T>();
        let mut set = BTreeSet::new();
        for _ in 0..len {
            decoder.unclaim_bytes_read(elem_size);
            set.insert(T::decode(decoder)?);
        }
        Ok(set)
    }
}

impl Decode for Duration {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let secs = u64::decode(decoder)?;
        let nanos = u32::decode(decoder)?;
        if nanos >= 1_000_000_000 {
            return Err(DecodeError::InvalidDuration {
                secs: secs as i64,
                nanos,
            });
        }
        Ok(Duration::new(secs, nanos))
    }
}

impl<A: Decode, B: Decode> Decode for (A, B) {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let a = A::decode(decoder)?;
        let b = B::decode(decoder)?;
        Ok((a, b))
    }
}

impl<A: Decode, B: Decode, C: Decode> Decode for (A, B, C) {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let a = A::decode(decoder)?;
        let b = B::decode(decoder)?;
        let c = C::decode(decoder)?;
        Ok((a, b, c))
    }
}

/// Streaming `std::io::Read` adapter matching `bincode::de::read::IoReader`.
pub struct IoReader<R> {
    inner: R,
}

impl<R> IoReader<R> {
    pub const fn new(inner: R) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Reader for IoReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), DecodeError> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            match self.inner.read(&mut bytes[offset..]) {
                Ok(0) => {
                    return Err(DecodeError::UnexpectedEnd {
                        additional: bytes.len() - offset,
                    });
                }
                Ok(n) => offset += n,
                Err(inner) => {
                    return Err(DecodeError::Io {
                        inner,
                        additional: bytes.len() - offset,
                    });
                }
            }
        }
        Ok(())
    }
}

macro_rules! impl_decode_nonzero {
    ($nz:ty, $prim:ty, $tag:expr) => {
        impl Decode for $nz {
            fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
                let raw = <$prim>::decode(decoder)?;
                Self::new(raw).ok_or(DecodeError::NonZeroTypeIsZero {
                    non_zero_type: $tag,
                })
            }
        }
    };
}

impl_decode_nonzero!(NonZeroU8, u8, IntegerType::U8);
impl_decode_nonzero!(NonZeroU16, u16, IntegerType::U16);
impl_decode_nonzero!(NonZeroU32, u32, IntegerType::U32);
impl_decode_nonzero!(NonZeroU64, u64, IntegerType::U64);
impl_decode_nonzero!(NonZeroU128, u128, IntegerType::U128);
impl_decode_nonzero!(NonZeroUsize, usize, IntegerType::Usize);
impl_decode_nonzero!(NonZeroI8, i8, IntegerType::I8);
impl_decode_nonzero!(NonZeroI16, i16, IntegerType::I16);
impl_decode_nonzero!(NonZeroI32, i32, IntegerType::I32);
impl_decode_nonzero!(NonZeroI64, i64, IntegerType::I64);
impl_decode_nonzero!(NonZeroI128, i128, IntegerType::I128);
impl_decode_nonzero!(NonZeroIsize, isize, IntegerType::Isize);

impl Decode for CString {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let bytes = decoder.decode_byte_vec()?;
        CString::new(bytes).map_err(|err| DecodeError::CStringNulError {
            position: err.nul_position(),
        })
    }
}

impl Decode for SystemTime {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let duration = Duration::decode(decoder)?;
        UNIX_EPOCH
            .checked_add(duration)
            .ok_or(DecodeError::InvalidSystemTime { duration })
    }
}
