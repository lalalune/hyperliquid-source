#![no_std]

//! Bounded name and MessagePack fixstr codec for the node #115 `borrowLend`
//! operation enum and its three struct-field identifiers.
//!
//! This models successful exact-name lookup and serializer bytes. It does not
//! model serde error objects, lossy conversion ownership, vector capacity growth,
//! callers, or the lending state transition.

extern crate alloc;

/// `borrowLend` operation in the observed declaration/tag order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Operation {
    Borrow = 0,
    Supply = 1,
    Repay = 2,
    Withdraw = 3,
}

impl Operation {
    pub const ALL: [Self; 4] = [Self::Borrow, Self::Supply, Self::Repay, Self::Withdraw];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Borrow => "borrow",
            Self::Supply => "supply",
            Self::Repay => "repay",
            Self::Withdraw => "withdraw",
        }
    }

    pub const fn tag(self) -> u8 {
        self as u8
    }

    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Borrow),
            1 => Some(Self::Supply),
            2 => Some(Self::Repay),
            3 => Some(Self::Withdraw),
            _ => None,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "borrow" => Some(Self::Borrow),
            "supply" => Some(Self::Supply),
            "repay" => Some(Self::Repay),
            "withdraw" => Some(Self::Withdraw),
            _ => None,
        }
    }

    /// Tagged visitor success word observed in the target.
    pub const fn tagged_result_word(self) -> u64 {
        0x09 | ((self as u64) << 8)
    }

    /// Append the observed MessagePack fixstr representation to `output`.
    pub fn append_msgpack_fixstr(self, output: &mut alloc::vec::Vec<u8>) {
        let bytes = self.name().as_bytes();
        output.push(0xa0 | bytes.len() as u8);
        output.extend_from_slice(bytes);
    }
}

/// Struct field identifiers; unknown names are rejected by `from_name`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BorrowLendField {
    Operation = 0,
    Token = 1,
    Amount = 2,
}

impl BorrowLendField {
    pub const ALL: [Self; 3] = [Self::Operation, Self::Token, Self::Amount];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::Token => "token",
            Self::Amount => "amount",
        }
    }

    pub const fn tag(self) -> u8 {
        self as u8
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "operation" => Some(Self::Operation),
            "token" => Some(Self::Token),
            "amount" => Some(Self::Amount),
            _ => None,
        }
    }

    /// Tagged field-visitor success word observed in the target.
    pub const fn tagged_result_word(self) -> u64 {
        0x09 | ((self as u64) << 8)
    }
}
