#![no_std]
#![forbid(unsafe_code)]
//! Immediate branch projection after the node's fixed-width key comparator.

/// Next control-flow edge after the 20-byte child-key comparison.
/// Values are supplied by a comparison boundary; this does not compare keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareStep {
    /// A positive signed result visits the next 20-byte sibling when one remains.
    NextSibling,
    /// Equality returns to the current-root admission route; it is not a final
    /// user-admission result.
    ReenterRootRoute,
    /// A non-equal result at depth zero reaches the observed empty result word.
    EmptyAtDepthZero,
    /// A negative result, or a positive result after the last sibling, moves up
    /// one level when depth is nonzero.
    Ascend { remaining_depth: u64 },
}

/// Project the immediate branch after the node's signed 20-byte comparison.
///
/// The target converts the comparator return to -1/0/1, continues across
/// siblings only for +1, routes 0 to `0x2c776ac`, and sends -1 (or an exhausted
/// sibling list) through the depth-decrement path. `depth` and
/// `siblings_remain` are caller-supplied state; key contents and the actual
/// comparison are outside this function.
pub fn after_key_compare(comparison: i32, siblings_remain: bool, depth: u64) -> CompareStep {
    if comparison == 0 {
        CompareStep::ReenterRootRoute
    } else if comparison > 0 && siblings_remain {
        CompareStep::NextSibling
    } else if depth == 0 {
        CompareStep::EmptyAtDepthZero
    } else {
        CompareStep::Ascend {
            remaining_depth: depth - 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{after_key_compare, CompareStep};

    #[test]
    fn signed_compare_results_follow_observed_edges() {
        assert_eq!(after_key_compare(0, true, 0), CompareStep::ReenterRootRoute);
        assert_eq!(
            after_key_compare(i32::MAX, true, 3),
            CompareStep::NextSibling
        );
        assert_eq!(
            after_key_compare(1, false, 3),
            CompareStep::Ascend { remaining_depth: 2 }
        );
        assert_eq!(
            after_key_compare(-1, true, 1),
            CompareStep::Ascend { remaining_depth: 0 }
        );
        assert_eq!(
            after_key_compare(i32::MIN, true, 0),
            CompareStep::EmptyAtDepthZero
        );
    }
}
