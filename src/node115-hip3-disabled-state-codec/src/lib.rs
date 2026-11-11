#![no_std]

//! The bounded node #115 HIP-3 `disabled_state` enum name codec.
//!
//! This models the four observed enum tags, exact variant names, and the JSON
//! unit-variant representation. It does not encode the enclosing MessagePack
//! state record or reproduce serde error/allocation behavior.

/// HIP-3 DEX disabled-state enum, in the observed declaration/tag order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DisabledState {
    Na = 0,
    UserDisabled = 1,
    ValidatorDisabled = 2,
    M = 3,
}

impl DisabledState {
    /// Return the exact variant spelling observed in node #115.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Na => "Na",
            Self::UserDisabled => "UserDisabled",
            Self::ValidatorDisabled => "ValidatorDisabled",
            Self::M => "m",
        }
    }

    /// Decode one of the four exact UTF-8 names. Matching is case-sensitive.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Na" => Some(Self::Na),
            "UserDisabled" => Some(Self::UserDisabled),
            "ValidatorDisabled" => Some(Self::ValidatorDisabled),
            "m" => Some(Self::M),
            _ => None,
        }
    }

    /// Decode the one-byte enum tag used by the observed writer jump table.
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Na),
            1 => Some(Self::UserDisabled),
            2 => Some(Self::ValidatorDisabled),
            3 => Some(Self::M),
            _ => None,
        }
    }

    /// Tagged visitor result word observed for the recognized variants.
    /// The low byte is the success marker `0x09`; the tag occupies bits 8..15.
    pub const fn tagged_result_word(self) -> u64 {
        0x09 | ((self as u64) << 8)
    }

    /// Append the JSON unit-variant text, including its surrounding quotes.
    ///
    /// Variant names contain only ASCII letters, so the observed output needs
    /// no JSON escaping. This appends bytes only; it does not model capacity
    /// growth or the native writer's error result.
    pub fn append_json(self, output: &mut alloc::vec::Vec<u8>) {
        output.push(b'"');
        output.extend_from_slice(self.name().as_bytes());
        output.push(b'"');
    }
}

extern crate alloc;
