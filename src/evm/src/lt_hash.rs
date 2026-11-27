//! Node #115 EVM DB checkpoint `LtHash` and `lt_hashes.json` (`l1/src/evm/evm_db.rs`, `l1/src/evm/hash.rs`).
//!
//! Grounded in `research/work-items/RE-011-evm-db-checkpoint-hashes-115`:
//! - Three keyspaces: `Ea` (selector 26, 20B suffix), `Ec` (selector 27, 32B suffix),
//!   `Es` (selector 28, 52B suffix = 20B address + 32B reversed-limb slot).
//! - Each `LtHash` record is `0x810` bytes: `hash: [u8; 2048]` (1024 independent
//!   big-endian `u16` lanes merged via wrapping `u16` addition / SSE `paddw`),
//!   `n_elements: u64`, `n_bytes: u64` (both merged via `u64::saturating_add`).

use std::fmt::Write as _;

pub const LT_HASH_BYTES: usize = 0x800; // 2048 bytes
pub const LT_HASH_LANES: usize = LT_HASH_BYTES / 2; // 1024 u16 lanes

/// The three EVM DB RocksDB keyspaces scanned by `0x38c2690` / `0x3915d30`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmDbKeyspace {
    Accounts,
    Contracts,
    Storage,
}

impl EvmDbKeyspace {
    pub const ALL: [Self; 3] = [Self::Accounts, Self::Contracts, Self::Storage];

    pub const fn selector(self) -> u8 {
        match self {
            Self::Accounts => 26,
            Self::Contracts => 27,
            Self::Storage => 28,
        }
    }

    pub const fn prefix(self) -> &'static [u8; 2] {
        match self {
            Self::Accounts => b"Ea",
            Self::Contracts => b"Ec",
            Self::Storage => b"Es",
        }
    }

    pub const fn required_suffix_len(self) -> usize {
        match self {
            Self::Accounts => 20,
            Self::Contracts => 32,
            Self::Storage => 52,
        }
    }

    pub const fn json_field(self) -> &'static str {
        match self {
            Self::Accounts => "accounts_hash",
            Self::Contracts => "contracts_hash",
            Self::Storage => "storage_hash",
        }
    }
}

/// 0x810-byte homomorphic lattice-hash accumulator (`l1/src/evm/hash.rs`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LtHash {
    pub hash: [u8; LT_HASH_BYTES],
    pub n_elements: u64,
    pub n_bytes: u64,
}

impl Default for LtHash {
    fn default() -> Self {
        Self::zero()
    }
}

impl LtHash {
    pub const fn zero() -> Self {
        Self {
            hash: [0u8; LT_HASH_BYTES],
            n_elements: 0,
            n_bytes: 0,
        }
    }

    /// Merge `other` into `self` matching the exact node #115 SSE `paddw`
    /// big-endian 16-bit lane loop + saturating `u64` counter additions.
    pub fn merge_assign(&mut self, other: &Self) {
        for i in 0..LT_HASH_LANES {
            let off = i * 2;
            let a = u16::from_be_bytes([self.hash[off], self.hash[off + 1]]);
            let b = u16::from_be_bytes([other.hash[off], other.hash[off + 1]]);
            let sum = a.wrapping_add(b).to_be_bytes();
            self.hash[off] = sum[0];
            self.hash[off + 1] = sum[1];
        }
        self.n_elements = self.n_elements.saturating_add(other.n_elements);
        self.n_bytes = self.n_bytes.saturating_add(other.n_bytes);
    }

    /// Serialize in exact `0x36c5cf0` / `0x4670ae0` JSON field order:
    /// `{"n_elements":...,"n_bytes":...,"hash":[u8; 2048]}`.
    pub fn to_json_string(&self) -> String {
        let mut out = String::with_capacity(LT_HASH_BYTES * 4 + 64);
        let _ = write!(
            out,
            r#"{{"n_elements":{},"n_bytes":{},"hash":["#,
            self.n_elements, self.n_bytes
        );
        for (i, &b) in self.hash.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            let _ = write!(out, "{b}");
        }
        out.push_str("]}");
        out
    }
}

/// Complete `lt_hashes.json` triple (`0x38c2230`, `0x38c2580`, `0x38c2690`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvmLtHashes {
    pub accounts_hash: LtHash,
    pub contracts_hash: LtHash,
    pub storage_hash: LtHash,
}

impl EvmLtHashes {
    /// Emit `lt_hashes.json` in exact node #115 key order (`0x38c2230`).
    pub fn to_json_string(&self) -> String {
        format!(
            r#"{{"accounts_hash":{},"contracts_hash":{},"storage_hash":{}}}"#,
            self.accounts_hash.to_json_string(),
            self.contracts_hash.to_json_string(),
            self.storage_hash.to_json_string()
        )
    }
}
