#![no_std]
#![forbid(unsafe_code)]

//! Safe finite-record projection of node #94 VA 0x3c1d690.
//! See README.md for the aligned, nonwrapping, disjoint memory correspondence.

pub const RECORD_BYTES: usize = 0x38;

/// Unequal indices do not form a forward range contained in the slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidRange;

/// Walk records whose tag at byte 9 is 2 and whose first byte is zero.
///
/// Entry equality returns false, even outside the slice. Unequal invalid ranges
/// return an error without mutation. Each visited record advances the cursor
/// before checking, so failure leaves it one past the failed record. Success
/// requires a nonempty passing range and leaves the cursor at `limit`.
/// This value/index API does not reproduce arbitrary raw-pointer behavior.
pub fn walk(
    records: &[[u8; RECORD_BYTES]],
    cursor: &mut usize,
    limit: usize,
) -> Result<bool, InvalidRange> {
    let start = *cursor;
    if start == limit {
        return Ok(false);
    }
    if start > limit || limit > records.len() {
        return Err(InvalidRange);
    }
    while *cursor != limit {
        let index = *cursor;
        *cursor += 1;
        if records[index][9] != 2 || records[index][0] != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}
