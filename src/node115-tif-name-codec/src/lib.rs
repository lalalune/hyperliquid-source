#![no_std]

extern crate alloc;

use alloc::{borrow::Cow, string::String, vec::Vec};

/// Successful MessagePack serializer result word observed in all three copies.
pub const SERIALIZE_OK_WORD: u64 = 0x8000_0000_0000_0004;

/// The five exact Tif names and declaration-order tags in node #115.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tif {
    Alo,
    Ioc,
    Gtc,
    FrontendMarket,
    LiquidationMarket,
}

impl Tif {
    /// Return the observed declaration-order tag.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Alo => 0,
            Self::Ioc => 1,
            Self::Gtc => 2,
            Self::FrontendMarket => 3,
            Self::LiquidationMarket => 4,
        }
    }

    /// Return the exact name associated with this tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alo => "Alo",
            Self::Ioc => "Ioc",
            Self::Gtc => "Gtc",
            Self::FrontendMarket => "FrontendMarket",
            Self::LiquidationMarket => "LiquidationMarket",
        }
    }

    /// Return the tagged visitor result word, `0x09 | tag << 8`.
    pub const fn tagged_result_word(self) -> u64 {
        0x09 | ((self.tag() as u64) << 8)
    }

    /// Match an exact, case-sensitive name.
    pub fn from_name(value: &str) -> Result<Self, UnknownTif<'_>> {
        match value {
            "Alo" => Ok(Self::Alo),
            "Ioc" => Ok(Self::Ioc),
            "Gtc" => Ok(Self::Gtc),
            "FrontendMarket" => Ok(Self::FrontendMarket),
            "LiquidationMarket" => Ok(Self::LiquidationMarket),
            _ => Err(UnknownTif {
                value: Cow::Borrowed(value),
            }),
        }
    }

    /// Match the byte visitor's exact-name and lossy unknown-value behavior.
    pub fn from_bytes(value: &[u8]) -> Result<Self, UnknownTif<'_>> {
        match String::from_utf8_lossy(value) {
            Cow::Borrowed(text) => Self::from_name(text),
            Cow::Owned(text) => match Self::from_name(&text) {
                Ok(tif) => Ok(tif),
                Err(_) => Err(UnknownTif {
                    value: Cow::Owned(text),
                }),
            },
        }
    }

    /// Append this name as a MessagePack fixstr and return the observed Ok word.
    ///
    /// This models the emitted wire bytes. It deliberately leaves the target's
    /// internal Vec reserve/growth call sequence outside this API.
    pub fn write_msgpack(self, output: &mut Vec<u8>) -> u64 {
        let name = self.as_str().as_bytes();
        output.push(0xa0 | name.len() as u8);
        output.extend_from_slice(name);
        SERIALIZE_OK_WORD
    }
}

/// Unknown name after the byte visitor's applicable UTF-8 handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownTif<'a> {
    value: Cow<'a, str>,
}

impl<'a> UnknownTif<'a> {
    /// Return the input text or its lossy replacement-decoded form.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Whether the reported value still borrows the input bytes.
    pub fn is_borrowed(&self) -> bool {
        matches!(&self.value, Cow::Borrowed(_))
    }

    /// Consume the error and retrieve the borrowed or owned value.
    pub fn into_value(self) -> Cow<'a, str> {
        self.value
    }
}
