//! Vault amount helper (`0x44a9430`) and base-conversion accumulation loop (`0x3beb980`).
//!
//! Anchored to node #115 evidence packets:
//! - `research/work-items/vaults-amount-helper-115`
//! - `research/work-items/vaults-base-conversion-115`

use crate::{sat_add_i64, sat_add_u64};

/// Overflow event emitted by [`vault_amount`] (`0x44a9430`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountOverflow {
    /// Unsigned `held + extra` overflowed `u64::MAX` (`0x6487460`).
    Sum,
    /// Signed `base + (total / 100)` overflowed `i64::MAX` (`0x648ba50`).
    Total,
}

/// Result of [`vault_amount`] (`0x44a9430`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultAmountResult {
    pub value: i64,
    pub overflows: Vec<AmountOverflow>,
}

/// Reconstructs the arithmetic core of node #115 vault amount helper `0x44a9430`.
///
/// Combines:
/// - `base`: signed cell value from the first lookup (defaults to `default_cell` if absent),
/// - `held`: unsigned held value from the second lookup (0 if absent),
/// - `extra`: optional unsigned bonus when present in the third store and `(extra_flag & 1) == 0`.
///
/// Computes `total = held.saturating_add(extra)`, `quotient = total / 100`
/// (unsigned floor division via `0x28f5c28f5c28f5c3`), and returns
/// `base + quotient` saturating at `i64::MAX` while recording any overflow events.
pub fn vault_amount(
    base_cell: Option<i64>,
    default_cell: i64,
    held: u64,
    present_in_third: bool,
    extra_flag: u8,
    extra_value: u64,
) -> VaultAmountResult {
    let mut overflows = Vec::new();
    let base = base_cell.unwrap_or(default_cell);
    let extra = if present_in_third && (extra_flag & 1) == 0 {
        extra_value
    } else {
        0
    };
    let (total, sum_ovf) = sat_add_u64(held, extra);
    if sum_ovf {
        overflows.push(AmountOverflow::Sum);
    }
    let quotient = total / 100;
    let sum = (base as i128) + (quotient as i128);
    let value = if sum > i64::MAX as i128 {
        overflows.push(AmountOverflow::Total);
        i64::MAX
    } else {
        sum as i64
    };
    VaultAmountResult { value, overflows }
}

/// Divisor-selection mode for the base-conversion entry body (`0x3beb980`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ConversionMode {
    Zero = 0,
    DirectDivisor = 1,
    ScaledDown = 2,
    ScaledUp = 3,
    CappedDivisor = 4,
}

/// One row consumed by the base-conversion entry body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConversionRow {
    pub tag: u8,
    pub divisor: u64,
    pub offset: i64,
    pub multiplier: i64,
    pub precision: u32,
}

/// Per-entry output of [`base_entry_amount`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryAmount {
    pub carries_offset: bool,
    pub first: i64,
    pub second: u64,
    pub magnitude: u64,
    pub offset: i64,
    pub quotient: u64,
    pub offset_overflowed: bool,
}

/// Failure / halt reasons of the base-conversion family (`0x3beb980`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversionStop {
    /// Input `value >= 2^63` or `value * multiplier` out of `i64` range.
    UnwrapPanic,
    /// Division by zero in mode 1 or mode 4.
    DivideByZeroHalt,
    /// `key % 10_000 >= rows.len()`.
    IndexOutOfBounds { index: usize, len: usize },
}

/// Per-entry calculation of `0x3beb980` (`vaults-base-conversion-115`).
///
/// For modes `ScaledDown` (2) and `ScaledUp` (3), the caller supplies the
/// external scaling callback `scale_fn(mode, magnitude, precision)` matching
/// the native indirect prep/scale hook.
pub fn base_entry_amount<F>(
    row: ConversionRow,
    value: u64,
    mode: ConversionMode,
    cap_divisor: u64,
    mut scale_fn: F,
) -> Result<EntryAmount, ConversionStop>
where
    F: FnMut(ConversionMode, u64, u32) -> u64,
{
    if value >= (1u64 << 63) {
        return Err(ConversionStop::UnwrapPanic);
    }
    let product128 = (value as i128) * (row.multiplier as i128);
    if product128 < i64::MIN as i128 || product128 > i64::MAX as i128 {
        return Err(ConversionStop::UnwrapPanic);
    }
    let product = product128 as i64;
    let magnitude = product.unsigned_abs();

    let quotient = match mode {
        ConversionMode::Zero => 0,
        ConversionMode::DirectDivisor => {
            if row.divisor == 0 {
                return Err(ConversionStop::DivideByZeroHalt);
            }
            magnitude / row.divisor
        }
        ConversionMode::CappedDivisor => {
            let d = row.divisor.min(cap_divisor);
            if d == 0 {
                return Err(ConversionStop::DivideByZeroHalt);
            }
            magnitude / d
        }
        ConversionMode::ScaledDown | ConversionMode::ScaledUp => {
            scale_fn(mode, magnitude, row.precision)
        }
    };

    if row.tag == 1 {
        let (total, offset_overflowed) = sat_add_i64(product, row.offset);
        let second = total.max(0) as u64;
        Ok(EntryAmount {
            carries_offset: true,
            first: total,
            second,
            magnitude,
            offset: row.offset,
            quotient,
            offset_overflowed,
        })
    } else {
        Ok(EntryAmount {
            carries_offset: false,
            first: product,
            second: quotient,
            magnitude,
            offset: 0,
            quotient,
            offset_overflowed: false,
        })
    }
}

/// Four-accumulator output of [`accumulate_base_conversion`] (`0x3beb980`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConversionAccumulators {
    pub signed_total: i64,
    pub unsigned_second: u64,
    pub unsigned_magnitude: u64,
    pub signed_offset_total: i64,
    pub signed_overflows: usize,
    pub unsigned_overflows: usize,
}

/// Accumulation loop of node #115 `0x3beb980`.
///
/// Iterates ordered `(key, row)` entries, skipping rows with `row.tag != 0`
/// unless `include_tagged` is true. Looks up `values[key % 10_000]` with
/// explicit bounds checking and saturating accumulation across all 4 slots.
pub fn accumulate_base_conversion<F>(
    start: i64,
    include_tagged: bool,
    items: &[(u64, ConversionRow)],
    values: &[u64],
    mode: ConversionMode,
    cap_divisor: u64,
    mut scale_fn: F,
) -> Result<ConversionAccumulators, ConversionStop>
where
    F: FnMut(ConversionMode, u64, u32) -> u64,
{
    let mut acc = ConversionAccumulators {
        signed_total: start,
        unsigned_second: 0,
        unsigned_magnitude: 0,
        signed_offset_total: start,
        signed_overflows: 0,
        unsigned_overflows: 0,
    };

    for &(key, row) in items {
        if row.tag != 0 && !include_tagged {
            continue;
        }
        let index = (key % 10_000) as usize;
        if index >= values.len() {
            return Err(ConversionStop::IndexOutOfBounds {
                index,
                len: values.len(),
            });
        }
        let entry = base_entry_amount(row, values[index], mode, cap_divisor, &mut scale_fn)?;
        if entry.offset_overflowed {
            acc.signed_overflows += 1;
        }
        let (s0, o0) = sat_add_i64(acc.signed_total, entry.first);
        acc.signed_total = s0;
        if o0 {
            acc.signed_overflows += 1;
        }
        let (u1, o1) = sat_add_u64(acc.unsigned_second, entry.second);
        acc.unsigned_second = u1;
        if o1 {
            acc.unsigned_overflows += 1;
        }
        let (u2, o2) = sat_add_u64(acc.unsigned_magnitude, entry.magnitude);
        acc.unsigned_magnitude = u2;
        if o2 {
            acc.unsigned_overflows += 1;
        }
        let carried = if entry.carries_offset { entry.offset } else { 0 };
        let (s3, o3) = sat_add_i64(acc.signed_offset_total, carried);
        acc.signed_offset_total = s3;
        if o3 {
            acc.signed_overflows += 1;
        }
    }

    Ok(acc)
}
