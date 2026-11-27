//! Error types recovered from node #115 `z_forks/bincode-fork`.
//!
//! All 18 `DecodeError` variants (`0..=17`) and 13 `IntegerType` variants (`0..=12`)
//! match the jump table at ELF VA `0x46a86c` (`DecodeError::fmt` at `0x16087a0`) and
//! the pointer/length tables at `0x6403308` / `0x46aa30` (`0x1609930`).

use core::fmt;
use core::str::Utf8Error;
use core::time::Duration;

/// Integer type diagnostic tags (`0..=12`) verified from node #115 `.data.rel.ro`
/// `0x6403308` and `.rodata` `0x46aa30`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

impl IntegerType {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::U8),
            1 => Some(Self::U16),
            2 => Some(Self::U32),
            3 => Some(Self::U64),
            4 => Some(Self::U128),
            5 => Some(Self::Usize),
            6 => Some(Self::I8),
            7 => Some(Self::I16),
            8 => Some(Self::I32),
            9 => Some(Self::I64),
            10 => Some(Self::I128),
            11 => Some(Self::Isize),
            12 => Some(Self::Reserved),
            _ => None,
        }
    }

    pub const fn as_raw(self) -> u8 {
        self as u8
    }
}

/// Allowed enum variant specification used in `DecodeError::UnexpectedVariant`,
/// verified from `0x1609100` (`Allowed`, `Range { min, max }`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowedEnumVariants {
    Range { min: u32, max: u32 },
    Allowed(&'static [u32]),
}

/// Complete 18-variant `DecodeError` enum in node #115 discriminant order (`0..=17`).
///
/// Notably, tag `1` (`InvalidBytesLength`) is a Hyperliquid fork addition checked
/// before byte-vector heap allocation (`0x5821b64..0x5821b75`).
#[derive(Debug)]
pub enum DecodeError {
    /// Tag 0: input ended before the required bytes were available.
    UnexpectedEnd { additional: usize },
    /// Tag 1 (Hyperliquid fork addition): declared byte-slice/Vec<u8> length exceeds
    /// remaining slice length, rejected before allocating.
    InvalidBytesLength,
    /// Tag 2: cumulative claimed bytes exceeded or overflowed the configured limit.
    LimitExceeded,
    /// Tag 3: varint marker encodes an integer width incompatible with the target type.
    InvalidIntegerType {
        expected: IntegerType,
        found: IntegerType,
    },
    /// Tag 4: decoded a zero value for a `NonZero*` target type.
    NonZeroTypeIsZero { non_zero_type: IntegerType },
    /// Tag 5: enum discriminant outside allowed variants.
    UnexpectedVariant {
        type_name: &'static str,
        allowed: &'static AllowedEnumVariants,
        found: u32,
    },
    /// Tag 6: invalid UTF-8 sequence while decoding `str`/`String`.
    Utf8 { inner: Utf8Error },
    /// Tag 7: invalid UTF-8 bytes while decoding `char`.
    InvalidCharEncoding([u8; 4]),
    /// Tag 8: boolean byte other than `0` or `1`.
    InvalidBooleanValue(u8),
    /// Tag 9: array length mismatch.
    ArrayLengthMismatch { required: usize, found: usize },
    /// Tag 10: decoded `u64` length cannot fit in platform `usize`.
    OutsideUsizeRange(u64),
    /// Tag 11: attempted to decode an uninhabited enum.
    EmptyEnum { type_name: &'static str },
    /// Tag 12: invalid `Duration` fields (e.g. `nanos >= 1_000_000_000`).
    InvalidDuration { secs: i64, nanos: u32 },
    /// Tag 13: invalid `SystemTime` offset from UNIX epoch.
    InvalidSystemTime { duration: Duration },
    /// Tag 14: interior NUL byte while decoding `CString`.
    CStringNulError { position: usize },
    /// Tag 15: I/O error while reading.
    Io {
        inner: std::io::Error,
        additional: usize,
    },
    /// Tag 16: static error message.
    Other(&'static str),
    /// Tag 17: owned error message.
    OtherString(String),
}

impl DecodeError {
    /// Native discriminant tag (`0..=17`) verified from `0x16087a0` jump table `0x46a86c`.
    /// `Result<T, DecodeError>::Ok` carries discriminant `18` (`0x12`).
    pub const fn tag(&self) -> u8 {
        match self {
            Self::UnexpectedEnd { .. } => 0,
            Self::InvalidBytesLength => 1,
            Self::LimitExceeded => 2,
            Self::InvalidIntegerType { .. } => 3,
            Self::NonZeroTypeIsZero { .. } => 4,
            Self::UnexpectedVariant { .. } => 5,
            Self::Utf8 { .. } => 6,
            Self::InvalidCharEncoding(_) => 7,
            Self::InvalidBooleanValue(_) => 8,
            Self::ArrayLengthMismatch { .. } => 9,
            Self::OutsideUsizeRange(_) => 10,
            Self::EmptyEnum { .. } => 11,
            Self::InvalidDuration { .. } => 12,
            Self::InvalidSystemTime { .. } => 13,
            Self::CStringNulError { .. } => 14,
            Self::Io { .. } => 15,
            Self::Other(_) => 16,
            Self::OtherString(_) => 17,
        }
    }
}

impl PartialEq for DecodeError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UnexpectedEnd { additional: a }, Self::UnexpectedEnd { additional: b }) => {
                a == b
            }
            (Self::InvalidBytesLength, Self::InvalidBytesLength) => true,
            (Self::LimitExceeded, Self::LimitExceeded) => true,
            (
                Self::InvalidIntegerType {
                    expected: e1,
                    found: f1,
                },
                Self::InvalidIntegerType {
                    expected: e2,
                    found: f2,
                },
            ) => e1 == e2 && f1 == f2,
            (
                Self::NonZeroTypeIsZero { non_zero_type: a },
                Self::NonZeroTypeIsZero { non_zero_type: b },
            ) => a == b,
            (
                Self::UnexpectedVariant {
                    type_name: t1,
                    allowed: a1,
                    found: f1,
                },
                Self::UnexpectedVariant {
                    type_name: t2,
                    allowed: a2,
                    found: f2,
                },
            ) => t1 == t2 && a1 == a2 && f1 == f2,
            (Self::Utf8 { inner: a }, Self::Utf8 { inner: b }) => a == b,
            (Self::InvalidCharEncoding(a), Self::InvalidCharEncoding(b)) => a == b,
            (Self::InvalidBooleanValue(a), Self::InvalidBooleanValue(b)) => a == b,
            (
                Self::ArrayLengthMismatch {
                    required: r1,
                    found: f1,
                },
                Self::ArrayLengthMismatch {
                    required: r2,
                    found: f2,
                },
            ) => r1 == r2 && f1 == f2,
            (Self::OutsideUsizeRange(a), Self::OutsideUsizeRange(b)) => a == b,
            (Self::EmptyEnum { type_name: a }, Self::EmptyEnum { type_name: b }) => a == b,
            (
                Self::InvalidDuration { secs: s1, nanos: n1 },
                Self::InvalidDuration { secs: s2, nanos: n2 },
            ) => s1 == s2 && n1 == n2,
            (
                Self::InvalidSystemTime { duration: a },
                Self::InvalidSystemTime { duration: b },
            ) => a == b,
            (Self::CStringNulError { position: a }, Self::CStringNulError { position: b }) => {
                a == b
            }
            (
                Self::Io {
                    inner: a,
                    additional: aa,
                },
                Self::Io {
                    inner: b,
                    additional: ab,
                },
            ) => a.kind() == b.kind() && aa == ab,
            (Self::Other(a), Self::Other(b)) => a == b,
            (Self::OtherString(a), Self::OtherString(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for DecodeError {}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for DecodeError {}

/// Encoding errors (`Result<(), EncodeError>` has `Ok` discriminant `8` in node #115
/// `0x5822850`/`0x5822c50`, indicating 8 error variants `0..=7`).
#[derive(Debug)]
pub enum EncodeError {
    /// Output slice ran out of space.
    UnexpectedEnd,
    /// Size counter overflow (`SizeWriter`, `z_forks/bincode-fork/src/enc/write.rs:78`).
    SizeOverflow,
    /// Allocation failure while extending buffer.
    AllocationFailed,
    /// Underlying `std::io::Error` at byte offset `index`.
    Io {
        inner: std::io::Error,
        index: usize,
    },
    /// Static message error.
    Other(&'static str),
    /// Owned string error.
    OtherString(String),
    /// Value outside representable wire range.
    InvalidSystemTime { duration: Duration },
    /// Serialization adapter error.
    Serde(String),
}

impl PartialEq for EncodeError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UnexpectedEnd, Self::UnexpectedEnd) => true,
            (Self::SizeOverflow, Self::SizeOverflow) => true,
            (Self::AllocationFailed, Self::AllocationFailed) => true,
            (Self::Io { inner: a, index: ia }, Self::Io { inner: b, index: ib }) => {
                a.kind() == b.kind() && ia == ib
            }
            (Self::Other(a), Self::Other(b)) => a == b,
            (Self::OtherString(a), Self::OtherString(b)) => a == b,
            (
                Self::InvalidSystemTime { duration: a },
                Self::InvalidSystemTime { duration: b },
            ) => a == b,
            (Self::Serde(a), Self::Serde(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for EncodeError {}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for EncodeError {}
