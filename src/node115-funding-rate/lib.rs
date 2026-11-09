//! Node115 selected funding-rate calculation on logical per-key state.
//! Collection ABI, floating exceptions and NaN payload bits are not projected.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub struct Config<'a> {
    pub baselines: &'a BTreeMap<u64, f64>,
    pub correction_bounds: &'a BTreeMap<u64, f64>,
    pub default_correction_bound: f64,
    pub multipliers: &'a BTreeMap<u64, f64>,
}

// SSE MINSD/MAXSD return the second operand on equality or unordered inputs.
// All uses below have already been checked finite; signed-zero ties still matter.
fn min_second(a: f64, b: f64) -> f64 {
    if a < b { a } else { b }
}
fn max_second(a: f64, b: f64) -> f64 {
    if a > b { a } else { b }
}

/// Compute the selected rate, or absence for a missing or empty sample vector.
///
/// Samples are folded in stored order from negative zero. Config maps have
/// logical unique keys; no physical hash/tree/deque ABI is reconstructed.
/// Arithmetic assumes ordinary nontrapping binary64 round-to-nearest-even.
/// NaN results preserve classification, not payload/sign/exception flags.
pub fn rate(key: u64, samples: &BTreeMap<u64, Vec<f64>>, config: &Config<'_>) -> Option<f64> {
    let samples = samples.get(&key)?;
    if samples.is_empty() {
        return None;
    }
    let mut sum = -0.0f64;
    for value in samples {
        sum += *value;
    }
    let baseline = config.baselines.get(&key).copied().unwrap_or(0.0001);
    let bound = config
        .correction_bounds
        .get(&key)
        .copied()
        .unwrap_or(config.default_correction_bound);
    let mean = sum / samples.len() as f64;
    let mut correction = baseline - mean;
    if bound.is_finite() && correction.is_finite() {
        let negative = f64::from_bits(bound.to_bits() ^ (1u64 << 63));
        let lower = min_second(bound, negative);
        let upper = max_second(negative, bound);
        correction = min_second(upper, max_second(lower, correction));
    }
    let multiplier = config.multipliers.get(&key).copied().unwrap_or(1.0);
    let mut result = (mean + correction) * multiplier;
    if result.is_finite() {
        result = min_second(0.04, max_second(-0.04, result));
    }
    Some(result * 0.125)
}
