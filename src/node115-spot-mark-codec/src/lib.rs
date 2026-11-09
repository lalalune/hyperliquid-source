#![no_std]

//! Bounded `Spot`/`Mark`/`ExternalPerp` name codec from the node #115 packet.
//!
//! This models exact name visitors and the serializer's observed tag dispatch.
//! It does not model serde errors or vector allocation behavior.

extern crate alloc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpotMarkKind {
    Spot,
    Mark,
    ExternalPerp,
}

impl SpotMarkKind {
    pub const ALL: [Self; 3] = [Self::Spot, Self::Mark, Self::ExternalPerp];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Spot => "Spot",
            Self::Mark => "Mark",
            Self::ExternalPerp => "ExternalPerp",
        }
    }

    /// Return the declaration-order tag for this enum variant.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Spot => 0,
            Self::Mark => 1,
            Self::ExternalPerp => 2,
        }
    }

    /// Model the serializer's observed two-compare chain: every byte other
    /// than 0 and 1 selects the `ExternalPerp` arm.
    pub const fn from_serializer_tag(tag: u8) -> Self {
        match tag {
            0 => Self::Spot,
            1 => Self::Mark,
            _ => Self::ExternalPerp,
        }
    }

    /// Decode an exact, case-sensitive wire name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Spot" => Some(Self::Spot),
            "Mark" => Some(Self::Mark),
            "ExternalPerp" => Some(Self::ExternalPerp),
            _ => None,
        }
    }

    /// Tagged visitor success word observed in the target.
    pub const fn tagged_result_word(self) -> u64 {
        0x09 | ((self.tag() as u64) << 8)
    }

    /// Append the observed MessagePack fixstr bytes.
    pub fn append_msgpack_fixstr(self, output: &mut alloc::vec::Vec<u8>) {
        let bytes = self.name().as_bytes();
        output.push(0xa0 | bytes.len() as u8);
        output.extend_from_slice(bytes);
    }
}
