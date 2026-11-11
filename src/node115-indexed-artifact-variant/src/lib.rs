#![no_std]

//! Exact variant-name visitor for node #115 `IndexedArtifactContentSerde`.
//!
//! This implements name-to-index recognition only. The enum entry, variant
//! seed, object access, struct payload bodies, and allocator/error callees are
//! outside this crate's scope.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IndexedArtifactVariant {
    NodeMetadata = 0,
    VisorMetadata = 1,
    HotfixMetadata = 2,
    NodeArtifact = 3,
    PublisherBinaryMetadata = 4,
}

impl IndexedArtifactVariant {
    pub const ALL: [Self; 5] = [
        Self::NodeMetadata,
        Self::VisorMetadata,
        Self::HotfixMetadata,
        Self::NodeArtifact,
        Self::PublisherBinaryMetadata,
    ];

    pub const fn index(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::NodeMetadata => "NodeMetadata",
            Self::VisorMetadata => "VisorMetadata",
            Self::HotfixMetadata => "HotfixMetadata",
            Self::NodeArtifact => "NodeArtifact",
            Self::PublisherBinaryMetadata => "PublisherBinaryMetadata",
        }
    }

    /// Match the complete, case-sensitive variant spelling.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "NodeMetadata" => Some(Self::NodeMetadata),
            "VisorMetadata" => Some(Self::VisorMetadata),
            "HotfixMetadata" => Some(Self::HotfixMetadata),
            "NodeArtifact" => Some(Self::NodeArtifact),
            "PublisherBinaryMetadata" => Some(Self::PublisherBinaryMetadata),
            _ => None,
        }
    }
}
