use node115_margin_flat_compose::{Mode, Observation, Refusal, evaluate};
use node115_margin_range::{InvalidView, Row};

fn row(key: u64, offset: u64, divisor: u8) -> Row {
    let mut r = [0; 40];
    r[..8].copy_from_slice(&key.to_le_bytes());
    r[24..32].copy_from_slice(&offset.to_le_bytes());
    r[32] = divisor;
    r
}

#[test]
fn wrapped_equal_keys_choose_the_last_logical_row() {
    // Logical sequence: 10, 20, 20, 30; equal entries cross the seam.
    let rows = [row(20, 3, 2), row(30, 5, 2), row(10, 1, 2), row(20, 9, 2)];
    let a = evaluate(&rows, 2, 4, 20, Mode::First).unwrap();
    assert_eq!((a.logical_index, a.physical_index, a.key), (2, 0, 20));
    assert_eq!(a.arithmetic, Observation::Normal(2));
    let b = evaluate(&rows, 2, 4, 20, Mode::Second).unwrap();
    assert_eq!(b.arithmetic, Observation::Normal(1));
}

#[test]
fn empty_and_invalid_views_are_explicit_host_boundaries() {
    assert_eq!(
        evaluate(&[], 0, 0, 1, Mode::First),
        Err(Refusal::NoSelectedRow)
    );
    assert_eq!(
        evaluate(&[row(5, 0, 1)], 0, 1, 4, Mode::First),
        Err(Refusal::NoSelectedRow)
    );
    assert_eq!(
        evaluate(&[row(5, 0, 1)], 1, 1, 5, Mode::First),
        Err(Refusal::InvalidView(InvalidView::Bounds))
    );
    assert_eq!(
        evaluate(&[row(5, 0, 1), row(4, 0, 1)], 0, 2, 5, Mode::First),
        Err(Refusal::InvalidView(InvalidView::Order))
    );
}

#[test]
fn arithmetic_boundaries_do_not_invent_diagnostic_returns() {
    assert_eq!(
        evaluate(&[row(0, 0, 0)], 0, 1, 1, Mode::First),
        Err(Refusal::ZeroDivisor)
    );
    assert_eq!(
        evaluate(&[row(0, 9, 1)], 0, 1, 1, Mode::First)
            .unwrap()
            .arithmetic,
        Observation::SubtractionDiagnosticBoundary
    );
    assert_eq!(
        evaluate(&[row(0, 9, 1)], 0, 1, 1, Mode::Second)
            .unwrap()
            .arithmetic,
        Observation::SubtractionDiagnosticBoundary
    );
    assert_eq!(
        evaluate(&[row(0, 0, 1)], 0, 1, 1u64 << 63, Mode::Second)
            .unwrap()
            .arithmetic,
        Observation::DoublingDiagnosticBoundary
    );
}

#[test]
fn small_sorted_ring_composition_matches_direct_formulas() {
    for head in 0..4 {
        for n in 0..=24u64 {
            for b in 1..=4u8 {
                let mut rows = [row(0, 0, 1); 4];
                for i in 0..4 {
                    rows[(head + i) % 4] = row((i as u64) * 6, i as u64, b);
                }
                let expected = (0..4).rev().find(|&i| (i as u64) * 6 <= n).unwrap();
                let c = expected as u64;
                for mode in [Mode::First, Mode::Second] {
                    let out = evaluate(&rows, head, 4, n, mode).unwrap();
                    assert_eq!(
                        (out.logical_index, out.physical_index),
                        (expected, (head + expected) % 4)
                    );
                    let calculated = match mode {
                        Mode::First => (n / (2 * u64::from(b))).checked_sub(c),
                        Mode::Second => (2 * n)
                            .checked_sub(4 * u64::from(b) * c)
                            .map(|v| v / (6 * u64::from(b))),
                    };
                    assert_eq!(
                        out.arithmetic,
                        calculated
                            .map(Observation::Normal)
                            .unwrap_or(Observation::SubtractionDiagnosticBoundary)
                    );
                }
            }
        }
    }
}
