#![no_std]

//! Bounded margin-mode name codec from the node #115 evidence packet.
//!
//! Models exact visitor names, tagged results, and MessagePack fixstr output.
//! The serializer's observed two-compare dispatch maps every tag above 1 to
//! `StrictIsolated`; error payloads and allocation behavior are excluded.

extern crate alloc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MarginMode {
    Normal = 0,
    NoCross = 1,
    StrictIsolated = 2,
}

impl MarginMode {
    pub const ALL: [Self; 3] = [Self::Normal, Self::NoCross, Self::StrictIsolated];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::NoCross => "noCross",
            Self::StrictIsolated => "strictIsolated",
        }
    }

    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Decode the target serializer's raw tag-byte dispatch.
    pub const fn from_serializer_tag(tag: u8) -> Self {
        match tag {
            0 => Self::Normal,
            1 => Self::NoCross,
            _ => Self::StrictIsolated,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "normal" => Some(Self::Normal),
            "noCross" => Some(Self::NoCross),
            "strictIsolated" => Some(Self::StrictIsolated),
            _ => None,
        }
    }

    /// Tagged visitor success word observed in the target.
    pub const fn tagged_result_word(self) -> u64 {
        0x09 | ((self.tag() as u64) << 8)
    }

    /// Append the observed MessagePack fixstr representation.
    pub fn append_msgpack_fixstr(self, output: &mut alloc::vec::Vec<u8>) {
        let bytes = self.name().as_bytes();
        output.push(0xa0 | bytes.len() as u8);
        output.extend_from_slice(bytes);
    }
}
