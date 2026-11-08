#![no_std]
#![forbid(unsafe_code)]
//! Bounded model of node115 margin arithmetic leaf `0x38b54b0`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarginLeafError {
    ZeroScale,
}

/// Computes unsigned `floor(n / (2*b)) - c`.
///
/// A subtraction borrow invokes `on_borrow` once and returns zero, matching the
/// measured branch after the diagnostic helper returns normally.
pub fn margin_leaf_a<F>(n: u64, b: u8, c: u64, mut on_borrow: F) -> Result<u64, MarginLeafError>
where
    F: FnMut(),
{
    if b == 0 {
        return Err(MarginLeafError::ZeroScale);
    }

    let quotient = n / (2 * u64::from(b));
    if quotient >= c {
        Ok(quotient - c)
    } else {
        on_borrow();
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::{MarginLeafError, margin_leaf_a};
    use core::cell::Cell;

    #[test]
    fn floors_and_subtracts_without_borrow() {
        let calls = Cell::new(0);
        assert_eq!(
            margin_leaf_a(15, 2, 2, || calls.set(calls.get() + 1)),
            Ok(1)
        );
        assert_eq!(calls.get(), 0);

        assert_eq!(margin_leaf_a(16, 2, 3, || unreachable!()), Ok(1));
    }

    #[test]
    fn exact_borrow_boundary_does_not_diagnose() {
        let calls = Cell::new(0);
        assert_eq!(
            margin_leaf_a(16, 2, 4, || calls.set(calls.get() + 1)),
            Ok(0)
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn one_borrow_returns_zero() {
        let calls = Cell::new(0);
        assert_eq!(margin_leaf_a(5, 2, 2, || calls.set(calls.get() + 1)), Ok(0));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn exercises_low_and_high_quotient_words() {
        assert_eq!(margin_leaf_a(15, 2, 2, || unreachable!()), Ok(1));
        assert_eq!(
            margin_leaf_a((1_u64 << 32) + 5, 2, 3, || unreachable!()),
            Ok((1_u64 << 30) - 2)
        );
    }

    #[test]
    fn rejects_zero_scale_before_division() {
        let calls = Cell::new(0);
        assert_eq!(
            margin_leaf_a(u64::MAX, 0, u64::MAX, || calls.set(calls.get() + 1)),
            Err(MarginLeafError::ZeroScale)
        );
        assert_eq!(calls.get(), 0);
    }
}
