//! Value projections of node115's quota/cache and affinity branches.
//!
//! Inputs stand for successful parsing and observed import outputs. This API
//! does not read cgroups, call Linux, implement Once, or reproduce the private ABI.
//! Float operations assume the target's ordinary round-to-nearest environment.
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, PartialEq, Eq)]
pub struct QuotaStage {
    pub quota_bits: u64,
    pub period_bits: u64,
    pub ratio_bits: u64,
    pub rounded_quota: u64,
}

pub fn quota_stage(quota: u64, period: u64) -> Option<QuotaStage> {
    if period == 0 {
        return None;
    }
    let q = quota as f64;
    let p = period as f64;
    let ratio = q / p;
    Some(QuotaStage {
        quota_bits: q.to_bits(),
        period_bits: p.to_bits(),
        ratio_bits: ratio.to_bits(),
        rounded_quota: ratio.ceil() as u64,
    })
}

/// A missing or zero quota leaves the cache untouched. A zero logical count
/// can instead publish zero: those two effects are intentionally distinct.
pub fn publish_quota(cache: &AtomicU64, stage: Option<&QuotaStage>, logical: u64) -> Option<u64> {
    let quota = stage?.rounded_quota;
    if quota == 0 {
        return None;
    }
    let value = quota.min(logical);
    cache.store(value, Ordering::SeqCst);
    Some(value)
}

/// `Some(mask)` denotes an ordinary successful sched_getaffinity result for
/// the observed 128-byte request. `None` selects the signed sysconf(84) result.
pub fn logical_count(mask: Option<&[u64; 16]>, sysconf_result: i64) -> u64 {
    match mask {
        Some(words) => words.iter().map(|w| u64::from(w.count_ones())).sum(),
        None => sysconf_result.max(1) as u64,
    }
}

/// Getter projection after any required opaque once call has returned and the
/// actual cache word has been loaded. No interleaving or Once transition claim.
pub fn cached_or_logical(loaded_cache: u64, mask: Option<&[u64; 16]>, sysconf_result: i64) -> u64 {
    if loaded_cache != 0 {
        loaded_cache
    } else {
        logical_count(mask, sysconf_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn separately_rounded_inputs_disagree_with_integer_ceildiv() {
        let stage = quota_stage((1 << 53) + 1, 1 << 53).unwrap();
        assert_eq!(stage.quota_bits, stage.period_bits);
        assert_eq!(stage.rounded_quota, 1);
    }
    #[test]
    fn saturating_unsigned_conversion() {
        assert_eq!(quota_stage(u64::MAX, 1).unwrap().rounded_quota, u64::MAX);
    }
    #[test]
    fn skip_and_zero_publication_are_different_effects() {
        let cache = AtomicU64::new(17);
        assert_eq!(publish_quota(&cache, quota_stage(0, 1).as_ref(), 8), None);
        assert_eq!(cache.load(Ordering::SeqCst), 17);
        assert_eq!(publish_quota(&cache, quota_stage(1, 1).as_ref(), 0), Some(0));
        assert_eq!(cache.load(Ordering::SeqCst), 0);
        assert_eq!(quota_stage(3, 0), None);
    }
    #[test]
    fn empty_success_mask_does_not_use_sysconf_fallback() {
        assert_eq!(logical_count(Some(&[0; 16]), 1024), 0);
        assert_eq!(logical_count(None, -1), 1);
        assert_eq!(logical_count(Some(&[u64::MAX; 16]), -1), 1024);
    }
    #[test]
    fn nonzero_cached_word_takes_precedence() {
        assert_eq!(cached_or_logical(17, Some(&[u64::MAX; 16]), 99), 17);
        assert_eq!(cached_or_logical(0, None, 99), 99);
    }
}
