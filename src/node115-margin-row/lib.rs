#![no_std]
//! Three independent node115 arithmetic points after row selection.
//! No lookup, diagnostic callback, caller reachability or whole-risk API.
use core::num::NonZeroU8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    Normal(u64),
    SubtractionDiagnosticBoundary,
    DoublingDiagnosticBoundary,
}

/// Fresh selected row at0x38b5592; b0 is outside the native division premise.
pub fn first_selected_row(n: u64, b: NonZeroU8, c: u64) -> Observation {
    let quotient = n / (2 * u64::from(b.get()));
    match quotient.checked_sub(c) {
        Some(value) => Observation::Normal(value),
        None => Observation::SubtractionDiagnosticBoundary,
    }
}

/// Fresh selected row at0x38b53e3; stop before the actual doubling diagnostic.
pub fn second_selected_row(n: u64, b: NonZeroU8, c: u64) -> Observation {
    if n >= (1_u64 << 63) {
        return Observation::DoublingDiagnosticBoundary;
    }
    second_finish(n * 2, b, c)
}

/// Independent fresh row at0x38b5475. The original MOV sets the numerator base.
/// This does not assert that an opaque diagnostic returned or preserved a row.
pub fn post_doubling_point(b: NonZeroU8, c: u64) -> Observation {
    second_finish(u64::MAX, b, c)
}

fn second_finish(base: u64, b: NonZeroU8, c: u64) -> Observation {
    let product = (4 * u64::from(b.get())).saturating_mul(c);
    let Some(numerator) = base.checked_sub(product) else {
        return Observation::SubtractionDiagnosticBoundary;
    };
    Observation::Normal(numerator / (6 * u64::from(b.get())))
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    include!("../../research/work-items/RE-007-margin-row-115/client_fixture.rs");
    #[test]
    fn frozen_original_points() {
        for line in
            include_str!("../../research/work-items/RE-007-margin-row-115/target-smoke.tsv").lines()
        {
            let (input, expected) = line.rsplit_once('\t').unwrap();
            assert_eq!(adapt(input), expected);
        }
    }
    #[test]
    fn independent_fresh_post_diagnostic_row() {
        let b = NonZeroU8::new(1).unwrap();
        assert_eq!(
            second_selected_row(0, b, 1 << 62),
            Observation::SubtractionDiagnosticBoundary
        );
        assert_eq!(post_doubling_point(b, 1 << 62), Observation::Normal(0));
    }
}
