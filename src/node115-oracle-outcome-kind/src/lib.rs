#![no_std]

extern crate alloc;

use alloc::{borrow::Cow, string::String};

/// The three exact wire names recovered from the node #115 oracle visitor.
///
/// The original Rust type identity is inferred from its name pool; the byte
/// comparisons and tag order are observations recorded in the evidence packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleOutcomeKind {
    StandaloneOutcome,
    Question,
    QuestionOutcome,
}

impl OracleOutcomeKind {
    /// Return the declaration-order tag observed in the three name visitors.
    pub const fn tag(self) -> u8 {
        match self {
            Self::StandaloneOutcome => 0,
            Self::Question => 1,
            Self::QuestionOutcome => 2,
        }
    }

    /// Return the exact name associated with this tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StandaloneOutcome => "StandaloneOutcome",
            Self::Question => "Question",
            Self::QuestionOutcome => "QuestionOutcome",
        }
    }

    /// Return the tagged `Ok` word written by the recovered visitor bodies.
    pub const fn tagged_result_word(self) -> u64 {
        0x09 | ((self.tag() as u64) << 8)
    }

    /// Match one of the three observed names byte for byte.
    pub fn from_name(value: &str) -> Result<Self, UnknownOracleOutcomeKind<'_>> {
        match value {
            "StandaloneOutcome" => Ok(Self::StandaloneOutcome),
            "Question" => Ok(Self::Question),
            "QuestionOutcome" => Ok(Self::QuestionOutcome),
            _ => Err(UnknownOracleOutcomeKind {
                value: Cow::Borrowed(value),
            }),
        }
    }

    /// Match the byte visitor's exact-name path and lossy unknown-value path.
    ///
    /// Invalid UTF-8 is replacement-decoded only for the unknown value. The
    /// recognized ASCII names take the borrowed path and allocate nothing.
    pub fn from_bytes(value: &[u8]) -> Result<Self, UnknownOracleOutcomeKind<'_>> {
        match String::from_utf8_lossy(value) {
            Cow::Borrowed(text) => Self::from_name(text),
            Cow::Owned(text) => match Self::from_name(&text) {
                Ok(kind) => Ok(kind),
                Err(_) => Err(UnknownOracleOutcomeKind {
                    value: Cow::Owned(text),
                }),
            },
        }
    }
}

/// Unknown visitor input after the target's applicable UTF-8 handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownOracleOutcomeKind<'a> {
    value: Cow<'a, str>,
}

impl<'a> UnknownOracleOutcomeKind<'a> {
    /// The original text, or replacement-decoded text for invalid UTF-8 bytes.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Whether the displayed value is borrowed from the input or replacement-decoded.
    pub fn is_borrowed(&self) -> bool {
        matches!(self.value, Cow::Borrowed(_))
    }

    /// Consume the error and return its borrowed or owned display value.
    pub fn into_value(self) -> Cow<'a, str> {
        self.value
    }
}
