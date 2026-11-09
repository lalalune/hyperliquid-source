#![no_std]
#![forbid(unsafe_code)]
//! Bounded model of node115 margin arithmetic leaf `0x38b5300`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Diagnostic {
    DoubleOverflow,
    SubtractionBorrow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarginLeafError {
    ZeroScale,
}

/// Computes `floor(max(sat(2*n)-sat(4*b*c), 0)/(6*b))`.
///
/// `on_diagnostic` represents the measured slot `0x64e4ea8` on the two routes
/// that invoke it. A `4*b*c` overflow only selects `u64::MAX`; it does not call
/// the diagnostic route.
pub fn margin_leaf_b<F>(n: u64, b: u8, c: u64, mut on_diagnostic: F) -> Result<u64, MarginLeafError>
where
    F: FnMut(Diagnostic),
{
    if b == 0 {
        return Err(MarginLeafError::ZeroScale);
    }

    let a = if n > i64::MAX as u64 {
        on_diagnostic(Diagnostic::DoubleOverflow);
        u64::MAX
    } else {
        n * 2
    };

    let b_times_c = u128::from(b) * u128::from(c);
    let product = b_times_c * 4;
    let b_term = if product > u128::from(u64::MAX) {
        u64::MAX
    } else {
        product as u64
    };

    let numerator = if let Some(value) = a.checked_sub(b_term) {
        value
    } else {
        on_diagnostic(Diagnostic::SubtractionBorrow);
        0
    };

    Ok(numerator / (6 * u64::from(b)))
}

#[cfg(test)]
mod tests {
    use super::{Diagnostic, MarginLeafError, margin_leaf_b};
    use core::cell::Cell;

    #[test]
    fn subtracts_then_floors() {
        let calls = Cell::new(0);
        assert_eq!(
            margin_leaf_b(10, 2, 1, |_| calls.set(calls.get() + 1)),
            Ok(1)
        );
        assert_eq!(calls.get(), 0);

        assert_eq!(margin_leaf_b(9, 1, 1, |_| unreachable!()), Ok(2));
    }

    #[test]
    fn equal_terms_yield_zero_without_borrow() {
        let calls = Cell::new(0);
        assert_eq!(
            margin_leaf_b(2, 1, 1, |_| calls.set(calls.get() + 1)),
            Ok(0)
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn borrow_reports_once_and_returns_zero() {
        let calls = Cell::new(0);
        assert_eq!(
            margin_leaf_b(1, 1, 1, |diagnostic| {
                assert_eq!(diagnostic, Diagnostic::SubtractionBorrow);
                calls.set(calls.get() + 1);
            }),
            Ok(0)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn high_input_bit_reports_double_overflow() {
        let calls = Cell::new(0);
        assert_eq!(
            margin_leaf_b(1_u64 << 63, 1, 0, |diagnostic| {
                assert_eq!(diagnostic, Diagnostic::DoubleOverflow);
                calls.set(calls.get() + 1);
            }),
            Ok(u64::MAX / 6)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn product_overflow_saturates_without_extra_diagnostic() {
        let calls = Cell::new(0);
        assert_eq!(
            margin_leaf_b(100, u8::MAX, u64::MAX, |diagnostic| {
                assert_eq!(diagnostic, Diagnostic::SubtractionBorrow);
                calls.set(calls.get() + 1);
            }),
            Ok(0)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn rejects_zero_scale() {
        assert_eq!(
            margin_leaf_b(u64::MAX, 0, u64::MAX, |_| unreachable!()),
            Err(MarginLeafError::ZeroScale)
        );
    }
}
