#![no_std]
//! Values at three independent node115 program points, not an opaque-hook API.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Values {
    pub quotient: u64,
    pub threshold: u64,
    pub raw_head: u64,
}

/// A boundary is arrival before native diagnostic code, not a native error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    Values(Values),
    SumDiagnosticBoundary,
    SecondaryDiagnosticBoundary,
}

fn finish(sum: u64, level: u64) -> Values {
    let quotient = sum / 500_000_000;
    let threshold = quotient.min(4000) + 1000;
    let raw_head = if level < threshold {
        0x800000000000001b
    } else {
        0x8000000000000018
    };
    Values {
        quotient,
        threshold,
        raw_head,
    }
}

fn secondary(sum: u64, b: u64, bound: u64, level: u64) -> Observation {
    if b > bound {
        return Observation::SecondaryDiagnosticBoundary;
    }
    Observation::Values(finish(sum, level))
}

/// Independent entry state at 0x2a824d6. Addition overflow has precedence.
pub fn enter(a: u64, p: u64, b: u64, bound: u64, level: u64) -> Observation {
    let Some(sum) = a.checked_add(p) else {
        return Observation::SumDiagnosticBoundary;
    };
    secondary(sum, b, bound, level)
}

/// Fresh explicit state at 0x2a82581; no handler is called or assumed to return.
pub fn after_sum_diagnostic(a: u64, p: u64, b: u64, bound: u64, level: u64) -> Observation {
    secondary(a.saturating_add(p), b, bound, level)
}

/// Fresh retained word/level at 0x2a825aa, independent of earlier hook effects.
pub fn after_secondary_diagnostic(saved_sum: u64, level: u64) -> Observation {
    Observation::Values(finish(saved_sum, level))
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_diagnostic_precedence_when_both_guards_reject() {
        // This input's A/B outcomes were captured before Rust in the sealed corpus.
        assert_eq!(
            enter(u64::MAX, 1, 1, 0, 1000),
            Observation::SumDiagnosticBoundary
        );
        assert_eq!(
            after_sum_diagnostic(u64::MAX, 1, 1, 0, 1000),
            Observation::SecondaryDiagnosticBoundary
        );
    }

    #[test]
    fn frozen_original_point_observations() {
        for line in
            include_str!("../../research/work-items/RE-014-raw-threshold-115/target-smoke.tsv")
                .lines()
        {
            let fields: std::vec::Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 7);
            let v: std::vec::Vec<u64> = fields[..6].iter().map(|s| s.parse().unwrap()).collect();
            let observed = match v[0] {
                0 => enter(v[1], v[2], v[3], v[4], v[5]),
                1 => after_sum_diagnostic(v[1], v[2], v[3], v[4], v[5]),
                2 => after_secondary_diagnostic(v[1], v[5]),
                _ => panic!("qualified phase"),
            };
            let text = match observed {
                Observation::SumDiagnosticBoundary => std::string::String::from("A"),
                Observation::SecondaryDiagnosticBoundary => std::string::String::from("B"),
                Observation::Values(x) => {
                    std::format!("V:{}:{}:{}", x.quotient, x.threshold, x.raw_head)
                }
            };
            assert_eq!(text, fields[6], "input {:?}", v);
        }
    }
}
