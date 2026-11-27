//! Node #115 `db/src/rocks_db.rs` open-result error niche and SSTable `BlockHandle` codec.
//!
//! Binary anchors (`RE-009-node115-db-crate-map`):
//! - `0x4524660..0x4524adb` & `0x57c6530..0x57c70b4` (`rocks_db.rs:58:49`):
//!   unwrap niche `0x8000_0000_0000_0000` and open configuration constants.

pub use node115_block_handle_codec::{
    BAD_BLOCK_HANDLE, BlockHandle, DecodeStatus, InputSlice, decode_into, decode_varint64, encode,
    encode_varint64,
};
pub use node115_owned_db_open::{
    BLOCK_SIZE, COMPANION_BYTES, DEFAULT_CACHE_BUDGET, ERROR_NICHE, OPTIONS_FLAG,
    result_word_is_error_niche,
};

/// Result wrapper matching the observed `rocks_db.rs:58` open-word niche discrimination.
pub fn interpret_open_word(word: u64) -> Result<u64, u64> {
    if result_word_is_error_niche(word) {
        Err(word)
    } else {
        Ok(word)
    }
}
