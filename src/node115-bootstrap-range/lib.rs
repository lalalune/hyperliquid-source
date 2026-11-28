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
        last: inclusive_end(lower, target),
    }
}

fn inclusive_end(lower: u64, target: u64) -> u64 {
    core::cmp::min(target, lower.saturating_add(99))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FollowingChunk {
    More { first: u64, last: u64 },
    Complete,
    BaselineMismatch { observed: u64, target: u64 },
}

/// Advance after the current response cursor has reached its end.
/// The saved target and previously requested inclusive upper bound come from
/// the active bootstrap query. Supply the refreshed receive baseline for the
/// terminal comparison; the nonterminal transition does not use it.
pub fn after_consumed_chunk(last: u64, target: u64, observed: u64) -> FollowingChunk {
    let first = last.saturating_add(1);
    if first <= target {
        return FollowingChunk::More {
            first,
            last: inclusive_end(first, target),
        };
    }
    if observed == target {
        FollowingChunk::Complete
    } else {
        FollowingChunk::BaselineMismatch { observed, target }
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

#[cfg(test)]
mod progression_tests {
    use super::{after_consumed_chunk, FollowingChunk};

    #[test]
    fn advances_from_the_prior_end_and_shortens_the_final_chunk() {
        assert_eq!(
            after_consumed_chunk(199, 305, 170),
            FollowingChunk::More {
                first: 200,
                last: 299
            }
        );
        assert_eq!(
            after_consumed_chunk(299, 305, 190),
            FollowingChunk::More {
                first: 300,
                last: 305
            }
        );
    }

    #[test]
    fn requests_the_equal_endpoint_then_uses_the_refreshed_baseline() {
        assert_eq!(
            after_consumed_chunk(304, 305, 302),
            FollowingChunk::More {
                first: 305,
                last: 305
            }
        );
        assert_eq!(
            after_consumed_chunk(305, 305, 305),
            FollowingChunk::Complete
        );
        assert_eq!(
            after_consumed_chunk(305, 305, 303),
            FollowingChunk::BaselineMismatch {
                observed: 303,
                target: 305
            }
        );
    }
}
