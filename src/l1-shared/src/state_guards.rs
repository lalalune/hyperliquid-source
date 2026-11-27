//! Binary-grounded state guards for `simulate_panic.rs`, `raw_signature_tracker.rs`,
//! and `bole/user_state.rs` in node #115 `l1-shared`.
//!
//! Anchored to node #115 `.data.rel.ro` `Location`s and `.text` FDEs:
//! - `l1/src/simulate_panic.rs:10:13` (`0x6492ef0` -> 6 FDEs, `"explicit panic"` at `0x7db393`)
//! - `l1/src/raw_signature_tracker.rs:231:9` (`0x6468b38`, `0x64a7f08` -> 10 FDEs, cap `0x897` = 2,199)
//! - `l1/src/bole/user_state.rs:239:44` (`0x644d5d8`, `0x64aa2a8` -> 8 FDEs, status `2`/`3` code `0xc`)

/// Exact 14-byte panic message loaded at `0x2bdf889` (`l1/src/simulate_panic.rs:10:13`).
pub const EXPLICIT_PANIC_MESSAGE: &str = "explicit panic";

/// Maximum accepted raw-signature bucket index compared at `0x368b341` (`cmp rax, 0x897`).
pub const RAW_SIGNATURE_MAX_BUCKET_INDEX: u64 = 0x897;

/// BOLE user-state lookup status word for empty/zero reserve operation (`0x2bb9979`).
pub const BOLE_USER_STATUS_EMPTY: u64 = 2;

/// BOLE user-state lookup status word for rejected/missing reserve (`0x2bb99f8`).
pub const BOLE_USER_STATUS_ERROR: u64 = 3;

/// BOLE user-state error sub-code stored at `[rbx + 8]` on missing reserve (`0x2bb99f4`).
pub const BOLE_USER_ERR_MISSING_RESERVE: u8 = 0x0c;

/// Checks the `l1/src/simulate_panic.rs:10:13` (`0x2bdf881`) explicit-panic gate.
///
/// In node #115, `test cl, cl; jne normal_path` emits `"explicit panic"` when `allow_continue == false`.
pub const fn check_simulate_panic_gate(allow_continue: bool) -> Result<(), &'static str> {
    if allow_continue {
        Ok(())
    } else {
        Err(EXPLICIT_PANIC_MESSAGE)
    }
}

/// Validates a bucket index against `l1/src/raw_signature_tracker.rs:231:9` (`0x368b341`: `cmp rax, 0x897; ja`).
pub const fn raw_signature_bucket_in_bounds(bucket_index: u64) -> bool {
    bucket_index <= RAW_SIGNATURE_MAX_BUCKET_INDEX
}

/// Lookup outcome matching `l1/src/bole/user_state.rs:239:44` (`0x2bb98a0..0x2bb99ff`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoleUserLookupOutcome {
    /// Zero input amount short-circuits with `status = 2`, output amount `0` (`0x2bb9979`).
    ZeroAmount { status: u64 },
    /// Reserve missing or validation rejected (`status = 3`, sub-code `0x0c`, `0x2bb99f4`).
    MissingReserve { status: u64, err_code: u8 },
    /// Reserve resolved and available for user-state update.
    Resolved { reserve_index: usize },
}

/// Reconstructs the entry lookup guard of `l1/src/bole/user_state.rs:239:44` (`0x2bb98a0`).
pub const fn classify_bole_user_lookup(
    amount: u64,
    reserve_index: Option<usize>,
    reserve_valid: bool,
) -> BoleUserLookupOutcome {
    if amount == 0 {
        return BoleUserLookupOutcome::ZeroAmount {
            status: BOLE_USER_STATUS_EMPTY,
        };
    }
    match reserve_index {
        Some(idx) if reserve_valid => BoleUserLookupOutcome::Resolved { reserve_index: idx },
        _ => BoleUserLookupOutcome::MissingReserve {
            status: BOLE_USER_STATUS_ERROR,
            err_code: BOLE_USER_ERR_MISSING_RESERVE,
        },
    }
}
