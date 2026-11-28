//! Node #115 `LtHash` and `LtHashes` incremental homomorphic BLAKE3-XOF state accumulators.
//!
//! Binary anchors (`RE-009-node115-lthash-homomorphic-and-hardfork-version`):
//! - `0x36c6100..0x36c628e`: element expansion via unkeyed `blake3::Hasher::update().finalize_xof().fill(&mut [0u8; 0x800])`
//! - `0x36c5b50..0x36c5ce5`: `LtHash` wire fields (`n_elements`, `n_bytes`, `hash` [2048 B])
//! - `0x3c27a20..0x3c27b98` / `0x3c27ba0..0x3c27d08`: `mix_out` (`saturating_sub`, **big-endian** `u16` `psubw` across `0x400` lanes)
//! - `0x3c287d0..0x3c28a81`: `replace` (`mix_out(old)` then `mix_in(new)` with **big-endian** `u16` `paddw` across `0x400` lanes)
//! - `0x3c27f30..0x3c28210`: `LtHash` rebuild (`0xf4240` = 1,000,000 batch) & 32-byte `blake3::hash(&hash[..0x800])` checksum
//! - `.rodata 0x793711`: `LtHashes` 3 fields (`accounts_hash`, `contracts_hash`, `storage_hash`)

use node115_abci_blake3::{blake3_hash, blake3_xof};

/// Exact `LtHash` accumulator width in bytes (`0x800` = 2048 B, proven at `0x36c61e3` & `0x36c5c79`).
pub const LT_HASH_BYTES: usize = 0x800;

/// Fixed native batch-summary record: payload plus two little-endian u64 counters.
pub const LT_HASH_RECORD_BYTES: usize = LT_HASH_BYTES + 16;

/// Exact number of 16-bit big-endian homomorphic lanes (`0x400` = 1024, proven at `0x3c27b69`).
pub const LT_HASH_LANES: usize = LT_HASH_BYTES / 2;

/// RocksDB rebuild batch size (`mov edx, 0xf4240` at `0x3c27fd4`).
pub const LT_HASH_REBUILD_BATCH_SIZE: usize = 1_000_000;

/// Exact `LtHash` serialized field order proven in `0x36c5b50..0x36c5ce5`.
pub const LT_HASH_WIRE_FIELDS: [&str; 3] = ["n_elements", "n_bytes", "hash"];

/// Exact `LtHashes` serialized field order proven at `.rodata 0x793711`.
pub const LT_HASHES_WIRE_FIELDS: [&str; 3] = ["accounts_hash", "contracts_hash", "storage_hash"];

/// Node #115 incremental homomorphic state accumulator (`0x810` B layout: `[u8; 2048]` + `n_elements` + `n_bytes`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LtHash {
    pub hash: [u8; LT_HASH_BYTES],
    pub n_elements: u64,
    pub n_bytes: u64,
}

impl Default for LtHash {
    fn default() -> Self {
        Self::new()
    }
}

impl LtHash {
    pub const fn new() -> Self {
        Self {
            hash: [0u8; LT_HASH_BYTES],
            n_elements: 0,
            n_bytes: 0,
        }
    }

    /// Expand an encoded element into `LT_HASH_BYTES` (`2048`) via standard unkeyed BLAKE3 XOF (`0x36c6100`).
    pub fn expand_element(encoded: &[u8]) -> [u8; LT_HASH_BYTES] {
        let mut out = [0u8; LT_HASH_BYTES];
        blake3_xof(encoded, &mut out);
        out
    }

    /// Add `delta` into `self.hash` using big-endian `u16::wrapping_add` across all 1,024 lanes (`0x3c289d0..0x3c28a27`).
    pub fn add_be_u16_lanes(acc: &mut [u8; LT_HASH_BYTES], delta: &[u8; LT_HASH_BYTES]) {
        for (a, d) in acc.chunks_exact_mut(2).zip(delta.chunks_exact(2)) {
            let av = u16::from_be_bytes([a[0], a[1]]);
            let dv = u16::from_be_bytes([d[0], d[1]]);
            let sum = av.wrapping_add(dv).to_be_bytes();
            a[0] = sum[0];
            a[1] = sum[1];
        }
    }

    /// Subtract `delta` from `self.hash` using big-endian `u16::wrapping_sub` across all 1,024 lanes (`0x3c27b10..0x3c27b70`).
    pub fn sub_be_u16_lanes(acc: &mut [u8; LT_HASH_BYTES], delta: &[u8; LT_HASH_BYTES]) {
        for (a, d) in acc.chunks_exact_mut(2).zip(delta.chunks_exact(2)) {
            let av = u16::from_be_bytes([a[0], a[1]]);
            let dv = u16::from_be_bytes([d[0], d[1]]);
            let diff = av.wrapping_sub(dv).to_be_bytes();
            a[0] = diff[0];
            a[1] = diff[1];
        }
    }

    /// Homomorphically mix an encoded element in (`0x3c2897f..0x3c28a27`).
    pub fn mix_in(&mut self, encoded: &[u8]) {
        self.n_elements = self.n_elements.saturating_add(1);
        self.n_bytes = self.n_bytes.saturating_add(encoded.len() as u64);
        let xof = Self::expand_element(encoded);
        Self::add_be_u16_lanes(&mut self.hash, &xof);
    }

    /// Homomorphically remove an encoded element (`0x3c27ad1..0x3c27b70`).
    pub fn mix_out(&mut self, encoded: &[u8]) {
        self.n_elements = self.n_elements.saturating_sub(1);
        self.n_bytes = self.n_bytes.saturating_sub(encoded.len() as u64);
        let xof = Self::expand_element(encoded);
        Self::sub_be_u16_lanes(&mut self.hash, &xof);
    }

    /// Update an entry in place (`0x3c287d0..0x3c28a81`): remove `old_encoded` if present, then mix in `new_encoded`.
    pub fn replace(&mut self, old_encoded: Option<&[u8]>, new_encoded: &[u8]) {
        if let Some(old) = old_encoded {
            self.mix_out(old);
        }
        self.mix_in(new_encoded);
    }

    /// Rebuild one cache lane from already computed native batch summaries.
    ///
    /// Starts at the zero record used on cache miss. The inputs are complete
    /// 0x810-byte fold outputs, not DB keys or encoded elements.
    pub fn from_rebuild_batches<'a>(
        records: impl IntoIterator<Item = &'a [u8; LT_HASH_RECORD_BYTES]>,
    ) -> Self {
        let mut result = Self::new();
        for record in records {
            let (hash, counters) = record.split_at(LT_HASH_BYTES);
            Self::add_be_u16_lanes(&mut result.hash, hash.try_into().unwrap());
            let n_elements = u64::from_le_bytes(counters[..8].try_into().unwrap());
            let n_bytes = u64::from_le_bytes(counters[8..].try_into().unwrap());
            result.n_elements = result.n_elements.saturating_add(n_elements);
            result.n_bytes = result.n_bytes.saturating_add(n_bytes);
        }
        result
    }

    /// Encode the hash payload and counters in the cache constructor's native layout.
    pub fn to_record_bytes(&self) -> [u8; LT_HASH_RECORD_BYTES] {
        let mut record = [0; LT_HASH_RECORD_BYTES];
        record[..LT_HASH_BYTES].copy_from_slice(&self.hash);
        record[LT_HASH_BYTES..LT_HASH_BYTES + 8].copy_from_slice(&self.n_elements.to_le_bytes());
        record[LT_HASH_BYTES + 8..].copy_from_slice(&self.n_bytes.to_le_bytes());
        record
    }

    /// Compute the 32-byte BLAKE3 checksum of the 2,048-byte `hash` buffer (`0x3c2808d..0x3c280af`).
    pub fn checksum(&self) -> [u8; 32] {
        blake3_hash(&self.hash)
    }
}

/// Complete EVM state `LtHashes` triple persisted in `<db_home>/checkpoint/<height>/lt_hashes.json`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LtHashes {
    pub accounts_hash: LtHash,
    pub contracts_hash: LtHash,
    pub storage_hash: LtHash,
}

impl LtHashes {
    pub const fn new() -> Self {
        Self {
            accounts_hash: LtHash::new(),
            contracts_hash: LtHash::new(),
            storage_hash: LtHash::new(),
        }
    }

    pub fn checksums(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        (
            self.accounts_hash.checksum(),
            self.contracts_hash.checksum(),
            self.storage_hash.checksum(),
        )
    }
}
