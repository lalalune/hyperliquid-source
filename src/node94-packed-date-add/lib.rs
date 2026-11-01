#![no_std]
//! Numeric projection of node #94 [0x151f870, 0x151fa9c).
//!
//! `add_days` accepts a validated packed year/ordinal/flag representation and
//! a signed 32-bit day offset. `Ok(0)` preserves the target's range rejection;
//! `Err(InvalidPackedDate)` is this API's refusal to specify invalid inputs.
//! This is not the target ABI, its outer checked wrapper, or a panic model.

const MIN_YEAR: i64 = -262_143;
const MAX_YEAR: i64 = 262_142;

/// The supplied bits are outside this reconstruction's admitted domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPackedDate;

fn leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Serial day of ordinal one, with year zero's ordinal one at zero.
fn year_start(year: i64) -> i64 {
    let preceding = year - 1;
    365 * year + preceding.div_euclid(4) - preceding.div_euclid(100) + preceding.div_euclid(400) + 1
}

fn flags(year: i64) -> u32 {
    let common = if leap(year) { 0 } else { 8 };
    common | ((year_start(year) + 3).rem_euclid(7) + 1) as u32
}

/// Add `delta` calendar days to a validated packed date.
///
/// Bits 31..13 are a signed 19-bit year in -262143..=262142. Bits 12..4
/// are a one-based ordinal (1..=365, or 366 for Gregorian leap years).
/// Bits 3..0 must equal the cycle-derived flag nibble: bit 3 is set for
/// common years; bits 2..0 are 1 + (year_start + 3) modulo 7.
///
/// Every `i32` delta is admitted. An out-of-range result returns `Ok(0)`.
/// Invalid input bits return `Err` even where the original might return a
/// value or reach a panic arm; no claim is made for those original paths.
pub fn add_days(packed: u32, delta: i32) -> Result<u32, InvalidPackedDate> {
    let year = i64::from((packed as i32) >> 13);
    let ordinal = i64::from((packed >> 4) & 511);
    let last = if leap(year) { 366 } else { 365 };
    if !(MIN_YEAR..=MAX_YEAR).contains(&year)
        || !(1..=last).contains(&ordinal)
        || packed & 15 != flags(year)
    {
        return Err(InvalidPackedDate);
    }

    let serial = year_start(year) + ordinal - 1 + i64::from(delta);
    if serial < year_start(MIN_YEAR) || serial >= year_start(MAX_YEAR + 1) {
        return Ok(0);
    }

    let mut low = MIN_YEAR;
    let mut high = MAX_YEAR + 1;
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if year_start(middle) <= serial {
            low = middle;
        } else {
            high = middle;
        }
    }
    let result_ordinal = (serial - year_start(low) + 1) as u32;
    Ok(((low as u32) << 13) | (result_ordinal << 4) | flags(low))
}
