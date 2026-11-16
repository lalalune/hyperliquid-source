//! Selected digest support gate after native set/weight materialization.
//! The two key families are distinct; no native container ABI is claimed.
use node115_staking_weight_comparison::exceeds_threshold;
use std::collections::{BTreeMap, BTreeSet};
pub type Key32 = [u8; 32];
pub type Key20 = [u8; 20];

/// Numeric tail of 0x2738c80. `total` is the independent stored word, not
/// necessarily the number of elements presented to a host collection. Assumes
/// the normal binary64 floating-point environment.
pub fn raw_count_gate(fraction: f64, matched: u64, total: u64) -> bool {
    if fraction == 0.0 {
        return true;
    }
    (matched as f64) > fraction * (total as f64)
}

/// Count selected 20-byte keys found in the second context's exact-key tree.
/// Valid logical sets and successful native helper returns are prerequisites.
pub fn count_gate(
    fraction: f64,
    eligible: &BTreeSet<Key20>,
    stored_total: u64,
    selected: &BTreeSet<Key20>,
) -> bool {
    if fraction == 0.0 {
        return true;
    }
    let matched = selected
        .iter()
        .filter(|key| eligible.contains(*key))
        .count() as u64;
    raw_count_gate(fraction, matched, stored_total)
}

/// Selected normal 0x28a9db0 relation, after the caller's two key sets and
/// weighted view are materialized. The first false result skips the second.
pub fn supports(
    weights: &BTreeMap<Key32, u64>,
    selected32: &BTreeSet<Key32>,
    fraction: f64,
    eligible20: &BTreeSet<Key20>,
    stored_total: u64,
    selected20: &BTreeSet<Key20>,
) -> bool {
    exceeds_threshold(weights, selected32.iter().copied())
        && count_gate(fraction, eligible20, stored_total, selected20)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_twenty_bytes_and_distinct_support_families() {
        let a = [1; 32];
        let b = [2; 32];
        let weights = BTreeMap::from([(a, 2), (b, 1)]);
        let selected32 = BTreeSet::from([a, b]);
        let a20 = [3; 20];
        let mut diff = a20;
        diff[19] = 4;
        let eligible = BTreeSet::from([a20]);
        assert!(supports(
            &weights,
            &selected32,
            0.5,
            &eligible,
            1,
            &BTreeSet::from([a20])
        ));
        assert!(!supports(
            &weights,
            &selected32,
            0.5,
            &eligible,
            1,
            &BTreeSet::from([diff])
        ));
        assert!(!supports(
            &weights,
            &BTreeSet::from([a]),
            0.0,
            &eligible,
            1,
            &BTreeSet::from([a20])
        ));
    }
    #[test]
    fn raw_fraction_not_clamped_and_nonfinite_not_normalized() {
        for bits in [0_u64, 1_u64 << 63] {
            assert!(raw_count_gate(f64::from_bits(bits), 0, 999));
        }
        assert!(!raw_count_gate(f64::NAN, 2, 1));
        assert!(!raw_count_gate(f64::INFINITY, 2, 1));
        assert!(!raw_count_gate(f64::NEG_INFINITY, 0, 0)); // -inf * 0 is NaN
        assert!(raw_count_gate(f64::NEG_INFINITY, 0, 1));
        assert!(raw_count_gate(-1.0, 0, 1));
        assert!(!raw_count_gate(1.0, 1, 1));
        assert!(raw_count_gate(0.7, 3, 4));
        assert!(!raw_count_gate(0.75, 3, 4));
    }
    #[test]
    fn stored_count_is_not_replaced_by_collection_length() {
        let key = [7; 20];
        let s = BTreeSet::from([key]);
        assert!(count_gate(0.5, &s, 1, &s));
        assert!(!count_gate(0.5, &s, 2, &s));
        assert!(!count_gate(0.5, &s, 10, &s));
    }
    #[test]
    fn conversion_rounding_and_checked_weight_overflow() {
        assert!(!raw_count_gate(
            1.0,
            9_007_199_254_740_993,
            9_007_199_254_740_992
        ));
        assert!(raw_count_gate(
            1.0,
            9_007_199_254_740_994,
            9_007_199_254_740_992
        ));
        let a = [1; 32];
        let b = [2; 32];
        let weights = BTreeMap::from([(a, u64::MAX), (b, 1)]);
        assert!(!supports(
            &weights,
            &BTreeSet::from([a, b]),
            0.0,
            &BTreeSet::new(),
            0,
            &BTreeSet::new()
        ));
    }
}
