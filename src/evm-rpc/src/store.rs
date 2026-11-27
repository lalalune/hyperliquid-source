//! Node #115 `evm_rpc/src/evm_store.rs` key-building helpers.
//!
//! Combines `node115-storage-key-builder` (`Es` storage keys) with the 8-byte
//! big-endian block-height range key builder (`0x26990d0`, `RE-011-evm-fee-history-115`).

/// Build `prefix || block_height.to_be_bytes()` matching `0x26990d0` + `0x231fef0`.
pub fn build_block_height_key(prefix: &[u8], block_height: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 8);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&block_height.to_be_bytes());
    out
}

/// Verify prefix and decode the trailing 8-byte big-endian block height (`0x2698000`).
pub fn decode_block_height_suffix(prefix: &[u8], key: &[u8]) -> Option<u64> {
    let suffix = key.strip_prefix(prefix)?;
    let bytes: [u8; 8] = suffix.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}
