//! Node #115 `z_forks/bincode-fork` compiled-byte match harness.
//!
//! Pure-Rust (`#![forbid(unsafe_code)]`, 0 external deps) reconstruction of:
//! - Four business-logic varint slow-path decoders (`0x5822490`, `0x58225c0`,
//!   `0x5822700`, `0x5822710` = 939 B),
//! - Four `z_forks/bincode-fork` CGU formatting FDEs (`0x1609a70`, `0x1608320`,
//!   `0x1609310`, `0x16090f0` = 105 B).
//!
//! Compiled under `rustc +1.95.0 --edition=2021 --crate-type=rlib -C opt-level=3
//! -C overflow-checks=yes --emit=obj` for relocation-qualified byte comparison
//! against `artifacts/node/115/hl-node`.

#![forbid(unsafe_code)]

use core::fmt;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum IntegerType {
    U8 = 0,
    U16 = 1,
    U32 = 2,
    U64 = 3,
    U128 = 4,
    Usize = 5,
    I8 = 6,
    I16 = 7,
    I32 = 8,
    I64 = 9,
    I128 = 10,
    Isize = 11,
    Reserved = 12,
}

#[derive(Debug)]
pub enum AllowedEnumVariants {
    Range { min: u32, max: u32 },
    Allowed(&'static [u32]),
}

#[derive(Debug)]
pub enum DecodeError {
    UnexpectedEnd {
        additional: usize,
    },
    InvalidBytesLength,
    LimitExceeded,
    InvalidIntegerType {
        expected: IntegerType,
        found: IntegerType,
    },
    NonZeroTypeIsZero {
        non_zero_type: IntegerType,
    },
    UnexpectedVariant {
        type_name: &'static str,
        allowed: &'static AllowedEnumVariants,
        found: u32,
    },
    Utf8 {
        inner: core::str::Utf8Error,
    },
    InvalidCharEncoding([u8; 4]),
    InvalidBooleanValue(u8),
    ArrayLengthMismatch {
        required: usize,
        found: usize,
    },
    OutsideUsizeRange(u64),
    EmptyEnum {
        type_name: &'static str,
    },
    InvalidDuration {
        secs: i64,
        nanos: u32,
    },
    InvalidSystemTime {
        duration: core::time::Duration,
    },
    CStringNulError {
        position: usize,
    },
    Io {
        inner: std::io::Error,
        additional: usize,
    },
    Other(&'static str),
    OtherString(String),
}

impl fmt::Display for DecodeError {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cold]
#[inline(never)]
pub fn fp_cold_invalid_int_u32(
    expected: IntegerType,
    found: IntegerType,
) -> Result<u32, DecodeError> {
    Err(DecodeError::InvalidIntegerType { expected, found })
}

#[cold]
#[inline(never)]
pub fn fp_cold_invalid_int_u64(
    expected: IntegerType,
    found: IntegerType,
) -> Result<u64, DecodeError> {
    Err(DecodeError::InvalidIntegerType { expected, found })
}

#[cold]
#[inline(never)]
pub fn fp_cold_invalid_int_usize(
    expected: IntegerType,
    found: IntegerType,
) -> Result<usize, DecodeError> {
    Err(DecodeError::InvalidIntegerType { expected, found })
}

#[inline(always)]
fn read_exact(slice: &mut &[u8], out: &mut [u8]) -> Result<(), DecodeError> {
    if out.len() > slice.len() {
        return Err(DecodeError::UnexpectedEnd {
            additional: out.len() - slice.len(),
        });
    }
    let (head, tail) = slice.split_at(out.len());
    out.copy_from_slice(head);
    *slice = tail;
    Ok(())
}

#[inline(never)]
pub fn fp_varint_decode_u32_slow(
    slice: &mut &[u8],
    big_endian: bool,
) -> Result<u32, DecodeError> {
    let mut byte = [0u8; 1];
    read_exact(slice, &mut byte)?;
    if byte[0] < 251 {
        return Ok(byte[0] as u32);
    }
    match byte[0] {
        251 => {
            let mut b = [0u8; 2];
            read_exact(slice, &mut b)?;
            Ok(if big_endian {
                u16::from_be_bytes(b)
            } else {
                u16::from_le_bytes(b)
            } as u32)
        }
        252 => {
            let mut b = [0u8; 4];
            read_exact(slice, &mut b)?;
            Ok(if big_endian {
                u32::from_be_bytes(b)
            } else {
                u32::from_le_bytes(b)
            })
        }
        253 => fp_cold_invalid_int_u32(IntegerType::U32, IntegerType::U64),
        254 => fp_cold_invalid_int_u32(IntegerType::U32, IntegerType::U128),
        _ => fp_cold_invalid_int_u32(IntegerType::U32, IntegerType::Reserved),
    }
}

#[inline(never)]
pub fn fp_varint_decode_u64_slow(
    slice: &mut &[u8],
    big_endian: bool,
) -> Result<u64, DecodeError> {
    let mut byte = [0u8; 1];
    read_exact(slice, &mut byte)?;
    if byte[0] < 251 {
        return Ok(byte[0] as u64);
    }
    match byte[0] {
        251 => {
            let mut b = [0u8; 2];
            read_exact(slice, &mut b)?;
            Ok(if big_endian {
                u16::from_be_bytes(b)
            } else {
                u16::from_le_bytes(b)
            } as u64)
        }
        252 => {
            let mut b = [0u8; 4];
            read_exact(slice, &mut b)?;
            Ok(if big_endian {
                u32::from_be_bytes(b)
            } else {
                u32::from_le_bytes(b)
            } as u64)
        }
        253 => {
            let mut b = [0u8; 8];
            read_exact(slice, &mut b)?;
            Ok(if big_endian {
                u64::from_be_bytes(b)
            } else {
                u64::from_le_bytes(b)
            })
        }
        254 => fp_cold_invalid_int_u64(IntegerType::U64, IntegerType::U128),
        _ => fp_cold_invalid_int_u64(IntegerType::U64, IntegerType::Reserved),
    }
}

#[inline(never)]
pub fn fp_varint_decode_usize_slow(
    slice: &mut &[u8],
    big_endian: bool,
) -> Result<usize, DecodeError> {
    let mut byte = [0u8; 1];
    read_exact(slice, &mut byte)?;
    if byte[0] < 251 {
        return Ok(byte[0] as usize);
    }
    match byte[0] {
        251 => {
            let mut b = [0u8; 2];
            read_exact(slice, &mut b)?;
            Ok(if big_endian {
                u16::from_be_bytes(b)
            } else {
                u16::from_le_bytes(b)
            } as usize)
        }
        252 => {
            let mut b = [0u8; 4];
            read_exact(slice, &mut b)?;
            Ok(if big_endian {
                u32::from_be_bytes(b)
            } else {
                u32::from_le_bytes(b)
            } as usize)
        }
        253 => {
            let mut b = [0u8; 8];
            read_exact(slice, &mut b)?;
            Ok(if big_endian {
                u64::from_be_bytes(b)
            } else {
                u64::from_le_bytes(b)
            } as usize)
        }
        254 => fp_cold_invalid_int_usize(IntegerType::Usize, IntegerType::U128),
        _ => fp_cold_invalid_int_usize(IntegerType::Usize, IntegerType::Reserved),
    }
}

/// Retain the three `core::fmt::Debug` ref-forwarder shims emitted in the
/// `z_forks/bincode-fork` CGU (`0x1608320`, `0x1609310`, `0x16090f0`).
#[inline(never)]
pub fn fp_bincode_cgu_debug_ref_str_double(
    v: &&&str,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    <&str as fmt::Debug>::fmt(*v, f)
}

#[inline(never)]
pub fn fp_bincode_cgu_debug_ref_str_single(v: &&str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <str as fmt::Debug>::fmt(*v, f)
}

#[inline(never)]
pub fn fp_bincode_cgu_debug_ref_io_error(
    v: &&std::io::Error,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    <std::io::Error as fmt::Debug>::fmt(*v, f)
}
