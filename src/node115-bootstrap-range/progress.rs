//! Conditional scalar continuation of node115 bootstrap range planning.
//! Value projections only: no original pointer, result or async-future ABI.
#![no_std]
#![forbid(unsafe_code)]

extern crate node115_bootstrap_range;
pub use node115_bootstrap_range::Plan;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub lower: u64,
    pub plan: Plan,
}

/// Fresh setup after reading the selected predecessor qword (state +0x200).
/// The qword's earlier producer and original type are not asserted by this API.
pub fn initial(predecessor: u64, target: u64) -> Step {
    let lower = predecessor.saturating_add(1);
    Step {
        lower,
        plan: node115_bootstrap_range::plan(lower, target),
    }
}

/// Next iteration after the stored inclusive endpoint. This entry does not
/// repeat the initial span guard. MAX/MAX remains a one-element window;
/// no end-of-domain termination is invented.
pub fn after_window(endpoint: u64, target: u64) -> Step {
    let lower = endpoint.saturating_add(1);
    let plan = if lower > target {
        Plan::ReversedContinuation
    } else {
        Plan::Window {
            first: lower,
            last: core::cmp::min(target, lower.saturating_add(99)),
        }
    };
    Step { lower, plan }
}

/// Available raw fields of a qualified last record, not a native record layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LastRecord {
    pub tag: u64,
    pub at_60: u64,
    pub at_b0: u64,
}

/// The equality gate before logging/error construction and execution waiting.
/// A matching target does not establish whole bootstrap completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionCheck {
    pub expected: u64,
    pub matches_target: bool,
}

/// None projects the observed zero-length or zero last-entry-address fallback.
/// It does not mean a null loaded record pointer. Some assumes the selected
/// record fields are readable. Container ownership, lookup and helper memory
/// effects are outside this value API.
pub fn completion_check(
    fallback: u64,
    last_record: Option<LastRecord>,
    target: u64,
) -> CompletionCheck {
    let expected = match last_record {
        None => fallback,
        Some(record) => {
            let value = if record.tag == 0x8000_0000_0000_0001 {
                record.at_60
            } else {
                record.at_b0
            };
            value.saturating_add(1)
        }
    };
    CompletionCheck {
        expected,
        matches_target: expected == target,
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_and_iteration_have_different_span_gates() {
        assert_eq!(initial(0, 30_002).plan, Plan::SpanExit);
        assert_eq!(
            after_window(0, 30_002),
            Step {
                lower: 1,
                plan: Plan::Window {
                    first: 1,
                    last: 100
                }
            }
        );
    }

    #[test]
    fn maximum_endpoint_keeps_the_native_window() {
        assert_eq!(
            after_window(u64::MAX, u64::MAX),
            Step {
                lower: u64::MAX,
                plan: Plan::Window {
                    first: u64::MAX,
                    last: u64::MAX
                }
            }
        );
    }

    #[test]
    fn fallback_and_last_record_are_distinct() {
        assert_eq!(
            completion_check(17, None, 17),
            CompletionCheck {
                expected: 17,
                matches_target: true
            }
        );
        assert_eq!(
            completion_check(
                17,
                Some(LastRecord {
                    tag: 0x8000_0000_0000_0001,
                    at_60: u64::MAX,
                    at_b0: 0,
                }),
                u64::MAX,
            ),
            CompletionCheck {
                expected: u64::MAX,
                matches_target: true
            }
        );
        assert_eq!(
            completion_check(
                99,
                Some(LastRecord {
                    tag: 0,
                    at_60: 0,
                    at_b0: 3
                }),
                5
            ),
            CompletionCheck {
                expected: 4,
                matches_target: false
            }
        );
    }
}
