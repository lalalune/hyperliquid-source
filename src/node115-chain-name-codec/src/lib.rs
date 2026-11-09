#![no_std]

//! Bounded chain-name enum codec for the observed node #115 wire names.
//!
//! This models exact names, declaration tags, tagged visitor success words,
//! and MessagePack fixstr output. It does not model serde errors or vector
//! allocation and growth behavior.

extern crate alloc;

/// Chain-name enum in the observed tag order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ChainName {
    Local = 0,
    Sandbox = 1,
    Testnet = 2,
    Mainnet = 3,
}

impl ChainName {
    pub const ALL: [Self; 4] = [Self::Local, Self::Sandbox, Self::Testnet, Self::Mainnet];

    pub const fn tag(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Local => "Local",
            Self::Sandbox => "Sandbox",
            Self::Testnet => "Testnet",
            Self::Mainnet => "Mainnet",
        }
    }

    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Local),
            1 => Some(Self::Sandbox),
            2 => Some(Self::Testnet),
            3 => Some(Self::Mainnet),
            _ => None,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Local" => Some(Self::Local),
            "Sandbox" => Some(Self::Sandbox),
            "Testnet" => Some(Self::Testnet),
            "Mainnet" => Some(Self::Mainnet),
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
