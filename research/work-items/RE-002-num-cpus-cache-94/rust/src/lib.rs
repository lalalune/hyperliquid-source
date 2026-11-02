//! Value/publication projection of node94's num_cpus-linked initializer.
//!
//! Inputs are already parsed quota/period and an already obtained logical CPU
//! count. This is not a cgroup parser, OS query, once primitive or target ABI.
//! Floating-point results assume round-to-nearest with invalid/precision
//! exceptions masked. Sticky exception flags are not projected outputs.

use std::sync::atomic::{AtomicU64, Ordering};

/// The target converts each u64 to f64 before division, then rounds upward and
/// saturates back to u64. Integer ceil-division is observably different.
pub fn quota_cpus(quota: u64, period: u64) -> Option<u64> {
    if period == 0 {
        None
    } else {
        Some(((quota as f64) / (period as f64)).ceil() as u64)
    }
}

/// None means no cache write. Some(0) is a write and remains distinguishable:
/// a nonzero quota combined with a synthetic empty affinity mask stores zero.
pub fn cache_value(quota: u64, period: u64, logical: u64) -> Option<u64> {
    match quota_cpus(quota, period) {
        None | Some(0) => None,
        Some(limit) => Some(limit.min(logical)),
    }
}

/// Project the observed final sequentially consistent exchange into Rust.
/// Allocation, file IO, once admission and cleanup precede this bounded API.
pub fn publish(cache: &AtomicU64, quota: u64, period: u64, logical: u64) -> bool {
    if let Some(value) = cache_value(quota, period, logical) {
        cache.store(value, Ordering::SeqCst);
        true
    } else {
        false
    }
}

/// The target's successful 128-byte affinity result contains 1024 bits.
pub fn affinity_count(words: &[u64; 16]) -> u64 {
    words.iter().map(|word| u64::from(word.count_ones())).sum()
}

/// Called only on the observed nonzero affinity status branch.
pub fn sysconf_count(result: i64) -> u64 {
    result.max(1) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_write_differs_from_publishing_zero() {
        let cache = AtomicU64::new(37);
        assert!(!publish(&cache, 9, 0, 8));
        assert!(!publish(&cache, 0, 100_000, 8));
        assert_eq!(cache.load(Ordering::Acquire), 37);
        assert!(publish(&cache, 1, 100_000, 0));
        assert_eq!(cache.load(Ordering::Acquire), 0);
    }

    #[test]
    fn quota_and_logical_count_both_bound_the_store() {
        let cache = AtomicU64::new(0);
        assert!(publish(&cache, 150_000, 100_000, 8));
        assert_eq!(cache.load(Ordering::Acquire), 2);
        assert!(publish(&cache, 150_000, 100_000, 1));
        assert_eq!(cache.load(Ordering::Acquire), 1);
    }

    #[test]
    fn separately_rounded_inputs_refute_integer_ceil_division() {
        let period = 1_u64 << 53;
        let quota = period + 1;
        assert_eq!(quota.div_ceil(period), 2);
        assert_eq!(quota_cpus(quota, period), Some(1));
    }

    #[test]
    fn conversion_at_the_unsigned_limit_saturates() {
        assert_eq!(quota_cpus(u64::MAX, 1), Some(u64::MAX));
        assert_eq!(quota_cpus(u64::MAX, u64::MAX), Some(1));
        assert_eq!(quota_cpus(1, u64::MAX), Some(1));
    }

    #[test]
    fn all_affinity_bits_contribute_once() {
        for bit in 0..1024 {
            let mut words = [0_u64; 16];
            words[bit / 64] = 1 << (bit % 64);
            assert_eq!(affinity_count(&words), 1);
        }
        assert_eq!(affinity_count(&[0; 16]), 0);
        assert_eq!(affinity_count(&[u64::MAX; 16]), 1024);
        assert_eq!(affinity_count(&[0xaaaaaaaaaaaaaaaa; 16]), 512);
    }

    #[test]
    fn signed_sysconf_failure_and_small_results_floor_to_one() {
        for value in [i64::MIN, -42, -1, 0, 1] {
            assert_eq!(sysconf_count(value), 1);
        }
        assert_eq!(sysconf_count(2), 2);
        assert_eq!(sysconf_count(i64::MAX), i64::MAX as u64);
    }
}
