//! Selected node115 inclusive bootstrap range semantics; scalar interface only.
//! No original ABI, asynchronous future, helper effects or network requests.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    SpanExit,
    ReversedContinuation,
    Window { first: u64, last: u64 },
}

/// Qualified at the two observed input pointers, before the span guard.
/// ReversedContinuation records only its route, not subsequent state effects.
pub fn plan(lower: u64, target: u64) -> Plan {
    if matches!(target.checked_sub(lower), Some(span) if span > 30_000) {
        return Plan::SpanExit;
    }
    if lower > target {
        return Plan::ReversedContinuation;
    }
    Plan::Window {
        first: lower,
        last: core::cmp::min(target, lower.saturating_add(99)),
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{plan, Plan};
    #[test]
    fn frozen_native_rows() {
        for line in include_str!("target-smoke.tsv").lines() {
            let f: std::vec::Vec<_> = line.split('\t').collect();
            let expected = match f[2] {
                "S" => Plan::SpanExit,
                "R" => Plan::ReversedContinuation,
                "W" => Plan::Window {
                    first: f[3].parse().unwrap(),
                    last: f[4].parse().unwrap(),
                },
                _ => panic!("unknown frozen result"),
            };
            assert_eq!(
                plan(f[0].parse().unwrap(), f[1].parse().unwrap()),
                expected,
                "{line}"
            );
        }
    }
}
