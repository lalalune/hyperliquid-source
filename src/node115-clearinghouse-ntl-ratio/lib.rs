//! Node #115 clearinghouse notional ratio at `0x44dcf80`.
//!
//! The arithmetic follows the decoded body
//! `l1/src/clearinghouse/clearinghouse.rs:179`. It is a raw-word model of
//! that body, with IEEE round-ties-even for the two binary64 operations.
//! The native image does not set MXCSR inside the body. Diagnostic-helper
//! unwinding, the caller's loop and the original struct names stay outside
//! this crate.

#![no_std]

/// Bytes from one selected record to the next.
pub const RECORD_STRIDE: u64 = 96;
/// Signed field loaded from the selected record.
pub const FIELD_OFFSET: u64 = 0x20;
/// Unsigned divisor used to form the record index.
pub const INDEX_DIVISOR: u64 = 10_000;

const LOW: f64 = -9223372036854775808.0;
const HIGH: f64 = 9223372036854775808.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyError {
    /// `key % 10000` is not a valid record index.
    IndexOutOfRange { index: u64, len: u64 },
    /// The record field at +0x20 is negative. The native edge calls the
    /// `clearinghouse.rs:179` diagnostic slot.
    NegativeRowField,
    /// Signed multiplication of the field by the scalar overflows.
    ProductOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Applied {
    pub key: u64,
    pub multiplier: i64,
    /// Truncated scaled ratio. Nonfinite products become 0; finite products
    /// saturate to the signed 64-bit range, with the exact 2^63 encoding
    /// landing on `i64::MAX`.
    pub converted: i64,
    /// `converted` minus the signed product, saturating.
    pub difference: i64,
    pub product: i64,
    /// Balance after subtracting `converted`, saturating.
    pub balance: i64,
    /// The difference subtraction took the `impl_ntl.rs:70` overflow edge.
    pub difference_overflow: bool,
    /// The balance subtraction took that same overflow edge.
    pub balance_overflow: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Denominator word is zero. The tag word becomes 0 and the balance
    /// pointer is left unchanged.
    Absent,
    Applied(Applied),
}

/// Record index `key % 10000`. The native sequence is the unsigned
/// reciprocal multiply by `0x346dc5d63886594b`, a shift of 11, then the
/// remainder against `10000`.
pub const fn record_index(key: u64) -> u64 {
    key % INDEX_DIVISOR
}

/// Byte offset of the signed field inside the indexed 96-byte record.
pub const fn field_byte_offset(key: u64) -> u64 {
    record_index(key) * RECORD_STRIDE + FIELD_OFFSET
}

fn saturating_sub(value: i64, amount: i64) -> (i64, bool) {
    if let Some(result) = value.checked_sub(amount) {
        (result, false)
    } else if amount < 0 {
        (i64::MAX, true)
    } else {
        (i64::MIN, true)
    }
}

fn ratio_to_i64(value: f64) -> i64 {
    if !value.is_finite() {
        return 0;
    }
    let clamped = value.clamp(LOW, HIGH);
    if clamped == HIGH {
        i64::MAX
    } else {
        clamped as i64
    }
}

/// Apply the decoded ratio.
///
/// `len` is the record count at table+0x10. `field` is the signed word at
/// the selected record+0x20. `multiplier` is the word at descriptor+0x10.
/// `denominator` and `scale` are the signed/unsigned words loaded through
/// the two pointers at input+0x08 and input+0x18. `balance` is the word
/// loaded through input+0x20.
///
/// On `Applied`, both overflow flags describe the numeric saturation used
/// when the `impl_ntl.rs:70` helper returns. A helper that does not return
/// leaves the later stores unperformed.
pub fn apply(
    key: u64,
    len: u64,
    field: i64,
    multiplier: i64,
    denominator: u64,
    scale: i64,
    balance: i64,
) -> Result<Outcome, ApplyError> {
    let index = record_index(key);
    if index >= len {
        return Err(ApplyError::IndexOutOfRange { index, len });
    }
    if field < 0 {
        return Err(ApplyError::NegativeRowField);
    }
    let Some(product) = field.checked_mul(multiplier) else {
        return Err(ApplyError::ProductOverflow);
    };
    if denominator == 0 {
        return Ok(Outcome::Absent);
    }
    let numerator = product.unsigned_abs() as f64;
    let scaled = (scale as f64) * (numerator / (denominator as f64));
    let converted = ratio_to_i64(scaled);
    let (difference, difference_overflow) = saturating_sub(converted, product);
    let (balance, balance_overflow) = saturating_sub(balance, converted);
    Ok(Outcome::Applied(Applied {
        key,
        multiplier,
        converted,
        difference,
        product,
        balance,
        difference_overflow,
        balance_overflow,
    }))
}

/// Little-endian words written on the normal return.
///
/// `Absent` defines only word 0. The other four words are the caller's
/// previous bytes. `Applied` writes tag 1, the original key, the multiplier,
/// the saturating difference and the signed product, at offsets 0, 8, 0x10,
/// 0x18 and 0x20.
pub fn output_words(outcome: Outcome) -> (u64, Option<[u64; 4]>) {
    match outcome {
        Outcome::Absent => (0, None),
        Outcome::Applied(row) => (
            1,
            Some([
                row.key,
                row.multiplier as u64,
                row.difference as u64,
                row.product as u64,
            ]),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply, field_byte_offset, output_words, ratio_to_i64, record_index, Applied, ApplyError,
        Outcome, FIELD_OFFSET, INDEX_DIVISOR, RECORD_STRIDE,
    };

    fn applied(result: Result<Outcome, ApplyError>) -> Applied {
        match result {
            Ok(Outcome::Applied(row)) => row,
            other => panic!("expected applied outcome, got {other:?}"),
        }
    }

    #[test]
    fn index_and_field_offset_follow_the_remainder() {
        assert_eq!(record_index(0), 0);
        assert_eq!(record_index(9999), 9999);
        assert_eq!(record_index(10_000), 0);
        assert_eq!(record_index(10_001), 1);
        assert_eq!(record_index(u64::MAX), 1615);
        assert_eq!(field_byte_offset(10_001), RECORD_STRIDE + FIELD_OFFSET);
        assert_eq!(INDEX_DIVISOR, 10_000);
    }

    #[test]
    fn exact_positive_ratio_updates_balance_and_words() {
        let row = applied(apply(0, 1, 3, 5, 2, 2, 100));
        assert_eq!(row.product, 15);
        assert_eq!(row.converted, 15);
        assert_eq!(row.difference, 0);
        assert_eq!(row.balance, 85);
        assert!(!row.difference_overflow && !row.balance_overflow);
        assert_eq!(
            output_words(Outcome::Applied(row)),
            (1, Some([0, 5, 0, 15]))
        );
    }

    #[test]
    fn negative_multiplier_uses_the_absolute_numerator() {
        let row = applied(apply(10_001, 10_000, 4, -3, 3, 10, 0));
        assert_eq!(row.product, -12);
        assert_eq!(row.converted, 40);
        assert_eq!(row.difference, 52);
        assert_eq!(row.balance, -40);
    }

    #[test]
    fn rejected_inputs_leave_the_balance_decision_unapplied() {
        assert_eq!(
            apply(9999, 9999, 1, 1, 1, 1, 7),
            Err(ApplyError::IndexOutOfRange {
                index: 9999,
                len: 9999
            })
        );
        assert_eq!(
            apply(5, 10, -1, 1, 1, 1, 7),
            Err(ApplyError::NegativeRowField)
        );
        assert_eq!(
            apply(5, 10, 1 << 62, 4, 1, 1, 7),
            Err(ApplyError::ProductOverflow)
        );
        assert_eq!(apply(5, 10, 1, 1, 0, 9, 50), Ok(Outcome::Absent));
        assert_eq!(output_words(Outcome::Absent), (0, None));
    }

    #[test]
    fn magnitude_above_two_pow_63_saturates() {
        let low = applied(apply(5, 10, 2, 1, 1, i64::MIN, 0));
        assert_eq!(low.converted, i64::MIN);
        assert_eq!(low.difference, i64::MIN);
        assert!(low.difference_overflow);
        assert_eq!(low.balance, i64::MAX);
        assert!(low.balance_overflow);

        let high = applied(apply(5, 10, 2, 1, 1, i64::MAX, 0));
        assert_eq!(high.converted, i64::MAX);
        assert_eq!(high.difference, i64::MAX - 2);
        assert_eq!(high.balance, -i64::MAX);
        assert!(!high.difference_overflow && !high.balance_overflow);
    }

    #[test]
    fn inexact_u64_magnitude_rounds_before_the_subtraction() {
        let magnitude = (1_i64 << 53) + 1;
        let row = applied(apply(5, 10, magnitude, 1, 1, 1, 0));
        assert_eq!(row.product, magnitude);
        assert_eq!(row.converted, 1_i64 << 53);
        assert_eq!(row.difference, -1);
    }

    #[test]
    fn division_happens_before_scaling() {
        let magnitude = (1_i64 << 53) + 1;
        let row = applied(apply(5, 10, magnitude, 1, 3, 7, 0));
        let numerator = magnitude.unsigned_abs() as f64;
        let native = (7_f64) * (numerator / 3_f64);
        let reassociated = (7_f64 * numerator) / 3_f64;
        assert_ne!(native.to_bits(), reassociated.to_bits());
        assert_eq!(row.converted, native as i64);
        assert_eq!(native.to_bits(), 0x4352aaaaaaaaaaaa);
    }

    #[test]
    fn nonfinite_scaled_product_becomes_zero() {
        assert_eq!(ratio_to_i64(f64::INFINITY), 0);
        assert_eq!(ratio_to_i64(f64::NEG_INFINITY), 0);
        assert_eq!(ratio_to_i64(f64::NAN), 0);
    }

    #[test]
    fn minimum_product_magnitude_saturates_at_the_high_encoding() {
        // 1 * i64::MIN fits in i64. Its absolute bit pattern is 2^63, which
        // the cvtt/cmova sequence returns as i64::MAX.
        let row = applied(apply(1, 2, 1, i64::MIN, 1, 1, 0));
        assert_eq!(row.product, i64::MIN);
        assert_eq!(row.converted, i64::MAX);
        assert_eq!(row.difference, i64::MAX);
        assert!(row.difference_overflow);
    }

    #[test]
    fn balance_saturation_is_independent_of_an_exact_ratio() {
        let row = applied(apply(5, 10, 1, 1, 1, 1, i64::MIN));
        assert_eq!(row.converted, 1);
        assert_eq!(row.balance, i64::MIN);
        assert!(row.balance_overflow);
        assert!(!row.difference_overflow);
    }
}
