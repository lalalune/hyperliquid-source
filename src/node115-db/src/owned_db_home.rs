//! Node #115 `db/src/owned_db_home.rs` guards and open-budget selection.
//!
//! Binary anchors (`RE-009-node115-db-crate-map`):
//! - `0x16961b0..0x1696729` (`owned_db_home.rs:21:9`): rejects any path containing
//!   the exact 10-byte ASCII substring `"checkpoint"` (`OwnedDbDirError`).
//! - `0x4524660..0x4524adb` (`owned_db_home.rs:72:37`, live): 2 GiB default cache budget.
//! - `0x57c6530..0x57c70b4` (`owned_db_home.rs:72:37`, slow): 16 GiB default cache budget.

use std::path::{Path, PathBuf};

use node115_owned_db_open::{
    BLOCK_SIZE, COMPANION_BYTES, DEFAULT_CACHE_BUDGET, OPTIONS_FLAG, cache_budget,
};

/// Default cache budget on the slow/replay open path (`0x57c6530`: `0x4000 << 20` = 16 GiB).
pub const SLOW_DEFAULT_CACHE_BUDGET: u64 = 0x4000 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenProfile {
    /// Live node open (`0x4524660`, default 2 GiB).
    Live,
    /// Slow/replay open (`0x57c6530`, default 16 GiB).
    Slow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedDbDirError {
    ContainsCheckpoint { path: PathBuf },
}

/// Validates a mutable owned DB directory path per `0x16961b0..0x1696239`:
/// rejects any path whose UTF-8 / byte representation contains `"checkpoint"`.
pub fn validate_owned_db_path(path: &Path) -> Result<PathBuf, OwnedDbDirError> {
    let raw = path.as_os_str().as_encoded_bytes();
    if raw.windows(10).any(|w| w == b"checkpoint") {
        return Err(OwnedDbDirError::ContainsCheckpoint {
            path: path.to_path_buf(),
        });
    }
    Ok(path.to_path_buf())
}

/// Effective cache budget in bytes for the selected open profile and caller flag/value.
pub fn open_cache_budget(profile: OpenProfile, flag: u8, gib_override: u64) -> u64 {
    if flag & 1 == 0 {
        return match profile {
            OpenProfile::Live => DEFAULT_CACHE_BUDGET,
            OpenProfile::Slow => SLOW_DEFAULT_CACHE_BUDGET,
        };
    }
    cache_budget(flag, gib_override)
}

/// Binary-grounded RocksDB option snapshot produced by `owned_db_home.rs:72`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedDbOpenConfig {
    pub profile: OpenProfile,
    pub cache_budget_bytes: u64,
    pub block_size: u32,
    pub options_flag: u32,
    pub companion_bytes: u32,
}

impl OwnedDbOpenConfig {
    pub fn for_profile(profile: OpenProfile, flag: u8, gib_override: u64) -> Self {
        Self {
            profile,
            cache_budget_bytes: open_cache_budget(profile, flag, gib_override),
            block_size: BLOCK_SIZE,
            options_flag: OPTIONS_FLAG,
            companion_bytes: COMPANION_BYTES,
        }
    }
}
