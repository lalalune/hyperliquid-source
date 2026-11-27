//! Canonical Arbitrum `Bridge2` and `Usdc2` contract address registry recovered
//! statically from node #115 `0x154d390..0x154e96a` (`.rodata` `0x466e9f..0x466f7b`).
//!
//! For `Mainnet` and `Testnet`, node #115 embeds the checksummed Arbitrum addresses
//! directly; for `Sandbox` and `Local`, it falls back to `../contract_addresses/<name>.json`
//! (`.rodata` `0x432652`).

use global_constants::ChainName;

pub const USDC2_MAINNET_KEY: &str = "Usdc2Mainnet";
pub const USDC2_MAINNET_ADDRESS_HEX: &str = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";
pub const USDC2_MAINNET_ADDRESS: [u8; 20] = [
    0xaf, 0x88, 0xd0, 0x65, 0xe7, 0x7c, 0x8c, 0xc2, 0x23, 0x93, 0x27, 0xc5, 0xed, 0xb3, 0xa4, 0x32,
    0x26, 0x8e, 0x58, 0x31,
];

pub const BRIDGE2_MAINNET_KEY: &str = "Bridge2Mainnet";
pub const BRIDGE2_MAINNET_ADDRESS_HEX: &str = "0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7";
pub const BRIDGE2_MAINNET_ADDRESS: [u8; 20] = [
    0x2d, 0xf1, 0xc5, 0x1e, 0x09, 0xae, 0xcf, 0x9c, 0xac, 0xb7, 0xbc, 0x98, 0xcb, 0x17, 0x42, 0x75,
    0x7f, 0x16, 0x3d, 0xf7,
];

pub const BRIDGE2_TESTNET_KEY: &str = "Bridge2Testnet";
pub const BRIDGE2_TESTNET_ADDRESS_HEX: &str = "0x08cfc1B6b2dCF36A1480b99353A354AA8AC56f89";
pub const BRIDGE2_TESTNET_ADDRESS: [u8; 20] = [
    0x08, 0xcf, 0xc1, 0xb6, 0xb2, 0xdc, 0xf3, 0x6a, 0x14, 0x80, 0xb9, 0x93, 0x53, 0xa3, 0x54, 0xaa,
    0x8a, 0xc5, 0x6f, 0x89,
];

pub const USDC2_TESTNET_KEY: &str = "Usdc2Testnet";
pub const USDC2_TESTNET_ADDRESS_HEX: &str = "0x1baAbB04529D43a73232B713C0FE471f7c7334d5";
pub const USDC2_TESTNET_ADDRESS: [u8; 20] = [
    0x1b, 0xaa, 0xbb, 0x04, 0x52, 0x9d, 0x43, 0xa7, 0x32, 0x32, 0xb7, 0x13, 0xc0, 0xfe, 0x47, 0x1f,
    0x7c, 0x73, 0x34, 0xd5,
];

/// Fallback directory suffix observed in `0x154db44` (`{}/contract_addresses/{}.json`, `.rodata` `0x432654`).
pub const CONTRACT_ADDRESSES_FALLBACK_SUBDIR: &str = "/contract_addresses/";

/// Return the embedded canonical Arbitrum `Bridge2` address for `Mainnet` or `Testnet`.
/// Returns `None` for `Sandbox` and `Local` (which load from `../contract_addresses/`).
#[must_use]
pub const fn canonical_bridge2_address(chain: ChainName) -> Option<[u8; 20]> {
    match chain {
        ChainName::Mainnet => Some(BRIDGE2_MAINNET_ADDRESS),
        ChainName::Testnet => Some(BRIDGE2_TESTNET_ADDRESS),
        ChainName::Sandbox | ChainName::Local => None,
    }
}

/// Return the embedded canonical Arbitrum `Usdc2` address for `Mainnet` or `Testnet`.
#[must_use]
pub const fn canonical_usdc2_address(chain: ChainName) -> Option<[u8; 20]> {
    match chain {
        ChainName::Mainnet => Some(USDC2_MAINNET_ADDRESS),
        ChainName::Testnet => Some(USDC2_TESTNET_ADDRESS),
        ChainName::Sandbox | ChainName::Local => None,
    }
}

/// Lookup an embedded contract address by its exact node #115 registry key.
#[must_use]
pub fn embedded_contract_by_key(key: &str) -> Option<[u8; 20]> {
    match key {
        USDC2_MAINNET_KEY => Some(USDC2_MAINNET_ADDRESS),
        BRIDGE2_MAINNET_KEY => Some(BRIDGE2_MAINNET_ADDRESS),
        BRIDGE2_TESTNET_KEY => Some(BRIDGE2_TESTNET_ADDRESS),
        USDC2_TESTNET_KEY => Some(USDC2_TESTNET_ADDRESS),
        _ => None,
    }
}
