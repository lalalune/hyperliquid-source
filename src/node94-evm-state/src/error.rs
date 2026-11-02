use core::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    WrongLength {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    WrongPrefix {
        expected: [u8; 2],
        actual: [u8; 2],
    },
    UnknownPrefix([u8; 2]),
    UnexpectedEof,
    InvalidMarker(u8),
    NonCanonical(&'static str),
    WrongContainerLength {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    WrongField {
        expected: &'static str,
        actual: String,
    },
    DuplicateField(String),
    MissingField(&'static str),
    TrailingBytes(usize),
    IntegerOverflow,
    InvalidBinaryLength {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidOrder(String),
    InvalidJumpTable(&'static str),
    UnsupportedVariant(String),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength {
                context,
                expected,
                actual,
            } => write!(f, "{context} length must be {expected}, got {actual}"),
            Self::WrongPrefix { expected, actual } => write!(
                f,
                "wrong table prefix: expected {:02x}{:02x}, got {:02x}{:02x}",
                expected[0], expected[1], actual[0], actual[1]
            ),
            Self::UnknownPrefix(prefix) => {
                write!(f, "unknown table prefix {:02x}{:02x}", prefix[0], prefix[1])
            }
            Self::UnexpectedEof => f.write_str("unexpected end of MessagePack input"),
            Self::InvalidMarker(marker) => {
                write!(f, "unsupported MessagePack marker 0x{marker:02x}")
            }
            Self::NonCanonical(kind) => write!(f, "non-canonical {kind} encoding"),
            Self::WrongContainerLength {
                context,
                expected,
                actual,
            } => write!(f, "{context} must contain {expected} entries, got {actual}"),
            Self::WrongField { expected, actual } => {
                write!(f, "expected field {expected:?}, got {actual:?}")
            }
            Self::DuplicateField(field) => write!(f, "duplicate field {field:?}"),
            Self::MissingField(field) => write!(f, "missing field {field:?}"),
            Self::TrailingBytes(count) => write!(f, "{count} trailing bytes"),
            Self::IntegerOverflow => f.write_str("integer does not fit the destination type"),
            Self::InvalidBinaryLength {
                context,
                expected,
                actual,
            } => write!(
                f,
                "{context} binary length must be {expected}, got {actual}"
            ),
            Self::InvalidOrder(order) => write!(f, "unsupported bit order {order:?}"),
            Self::InvalidJumpTable(reason) => write!(f, "invalid jump table: {reason}"),
            Self::UnsupportedVariant(variant) => {
                write!(f, "unsupported stored-code variant {variant:?}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodeError {
    LengthOverflow(&'static str),
    InvalidJumpTable(&'static str),
    UnsupportedVariant(&'static str),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow(context) => write!(f, "{context} is too long to serialize"),
            Self::InvalidJumpTable(reason) => write!(f, "invalid jump table: {reason}"),
            Self::UnsupportedVariant(variant) => {
                write!(f, "stored-code variant {variant} is not implemented")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

#[derive(Debug)]
pub enum OfflineError {
    Decode(DecodeError),
    Encode(EncodeError),
    Store(StoreError),
}

impl fmt::Display for OfflineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "decode failed: {error}"),
            Self::Encode(error) => write!(f, "encode failed: {error}"),
            Self::Store(error) => write!(f, "store operation failed: {error}"),
        }
    }
}

impl std::error::Error for OfflineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Encode(error) => Some(error),
            Self::Store(error) => Some(error),
        }
    }
}

impl From<DecodeError> for OfflineError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl From<EncodeError> for OfflineError {
    fn from(value: EncodeError) -> Self {
        Self::Encode(value)
    }
}

impl From<StoreError> for OfflineError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}
