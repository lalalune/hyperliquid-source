#![no_std]

//! Exact variant-name visitor for the node #115 EVM `ReadPrecompileResult`.
//!
//! This is a name/tag codec only. In particular, the `Ok` payload and the
//! enclosing MessagePack serializer are outside this crate's claim.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReadPrecompileOutcomeName {
    Ok = 0,
    OutOfGas = 1,
    Error = 2,
    UnexpectedError = 3,
}

impl ReadPrecompileOutcomeName {
    pub const ALL: [Self; 4] = [Self::Ok, Self::OutOfGas, Self::Error, Self::UnexpectedError];

    pub const fn tag(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Ok => "Ok",
            Self::OutOfGas => "OutOfGas",
            Self::Error => "Error",
            Self::UnexpectedError => "UnexpectedError",
        }
    }

    /// Decode only the exact, case-sensitive wire spelling.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Ok" => Some(Self::Ok),
            "OutOfGas" => Some(Self::OutOfGas),
            "Error" => Some(Self::Error),
            "UnexpectedError" => Some(Self::UnexpectedError),
            _ => None,
        }
    }

    /// Tagged visitor success word observed in both target copies.
    pub const fn tagged_result_word(self) -> u64 {
        0x09 | ((self.tag() as u64) << 8)
    }
}
