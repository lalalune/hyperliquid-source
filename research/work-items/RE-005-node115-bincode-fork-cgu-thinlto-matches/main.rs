//! Node #115 `z_forks/bincode-fork` CGU (`0x1607c70..0x1609aaa`) ThinLTO
//! compiled-byte verification harness.
//!
//! Pure-Rust (`#![forbid(unsafe_code)]`, 0 external deps) reconstruction of
//! `DecodeError`, `AllowedEnumVariants`, and `IntegerType` compiled under
//! `rustc +1.95.0 --edition=2021 --crate-name bincode_cgu_thin -C opt-level=3
//! -C overflow-checks=yes -C lto=thin -C save-temps` to reproduce all 12
//! remaining non-jemalloc FDEs of the `z_forks/bincode-fork` CGU (`7,170 B`).

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

#[inline(never)]
fn sink(x: &dyn fmt::Display) -> usize {
    format!("{x}").len()
}

fn main() {
    let e = DecodeError::InvalidBytesLength;
    std::process::exit((sink(&e) & 1) as i32);
}
