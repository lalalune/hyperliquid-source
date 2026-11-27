//! Contract identifier (`Cid`) constants anchored to node #115 `base/src/cid.rs` (`0x154d390..0x154e96a`).

/// Known on-chain contract identifiers observed in node #115 `.rodata`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cid {
    Usdc2Mainnet,
    Bridge2Mainnet,
    Bridge2Testnet,
    Usdc2Testnet,
}

impl Cid {
    pub const ALL: [Cid; 4] = [
        Cid::Usdc2Mainnet,
        Cid::Bridge2Mainnet,
        Cid::Bridge2Testnet,
        Cid::Usdc2Testnet,
    ];

    /// Exact checksummed hex address observed in node #115 `.rodata`.
    pub const fn address_hex(self) -> &'static str {
        match self {
            Cid::Usdc2Mainnet => "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
            Cid::Bridge2Mainnet => "0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7",
            Cid::Bridge2Testnet => "0x08cfc1B6b2dCF36A1480b99353A354AA8AC56f89",
            Cid::Usdc2Testnet => "0x1baAbB04529D43a73232B713C0FE471f7c7334d5",
        }
    }

    /// Exact 20-byte address decoded from the node #115 `.rodata` constant.
    pub const fn address_bytes(self) -> [u8; 20] {
        match self {
            Cid::Usdc2Mainnet => [
                0xaf, 0x88, 0xd0, 0x65, 0xe7, 0x7c, 0x8c, 0xc2, 0x23, 0x93, 0x27, 0xc5, 0xed, 0xb3,
                0xa4, 0x32, 0x26, 0x8e, 0x58, 0x31,
            ],
            Cid::Bridge2Mainnet => [
                0x2d, 0xf1, 0xc5, 0x1e, 0x09, 0xae, 0xcf, 0x9c, 0xac, 0xb7, 0xbc, 0x98, 0xcb, 0x17,
                0x42, 0x75, 0x7f, 0x16, 0x3d, 0xf7,
            ],
            Cid::Bridge2Testnet => [
                0x08, 0xcf, 0xc1, 0xb6, 0xb2, 0xdc, 0xf3, 0x6a, 0x14, 0x80, 0xb9, 0x93, 0x53, 0xa3,
                0x54, 0xaa, 0x8a, 0xc5, 0x6f, 0x89,
            ],
            Cid::Usdc2Testnet => [
                0x1b, 0xaa, 0xbb, 0x04, 0x52, 0x9d, 0x43, 0xa7, 0x32, 0x32, 0xb7, 0x13, 0xc0, 0xfe,
                0x47, 0x1f, 0x7c, 0x73, 0x34, 0xd5,
            ],
        }
    }

    /// Exact variant label string observed in node #115 `.rodata`.
    pub const fn name(self) -> &'static str {
        match self {
            Cid::Usdc2Mainnet => "Usdc2Mainnet",
            Cid::Bridge2Mainnet => "Bridge2Mainnet",
            Cid::Bridge2Testnet => "Bridge2Testnet",
            Cid::Usdc2Testnet => "Usdc2Testnet",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Usdc2Mainnet" => Some(Cid::Usdc2Mainnet),
            "Bridge2Mainnet" => Some(Cid::Bridge2Mainnet),
            "Bridge2Testnet" => Some(Cid::Bridge2Testnet),
            "Usdc2Testnet" => Some(Cid::Usdc2Testnet),
            _ => None,
        }
    }
}
