//! Independently authored scalar calculation from node 115's `0x44ad9e0`.
//!
//! This implements the numeric path only. The arguments name their role in that
//! calculation; they do not establish business units, share ownership, admission,
//! map behavior, persistence, or full vault behavior. See the evidence packet
//! `RE-001-node115-vault-redistribution` for the pinned target and call graph.
//!
//! Correspondence assumes IEEE binary64 round-to-nearest/ties-to-even with
//! gradual underflow and normal return from the surrounding native helpers.
#![no_std]
#![forbid(unsafe_code)]

/// Compute the scalar written for one entry by the selected post-transfer path.
///
/// `prior_weight` is the original entry's first binary64 payload value. `selected`
/// says whether this is the key chosen for the additional delta. A newly inserted
/// selected entry starts with zero in the native staging map; the caller supplies
/// `prior_weight = 0.0` for that case. Key matching and insertion are not implemented.
///
/// Each conversion, division, multiplication and addition is a separate rounded
/// operation. In particular, neither the scale conversions nor the multiplication
/// followed by selected addition may be algebraically cancelled or fused.
pub fn reweight_value(
    prior_units: i64,
    delta_units: i64,
    prior_weight: f64,
    selected: bool,
) -> f64 {
    let sum = prior_units.saturating_add(delta_units);
    let denominator = (sum.max(0) as f64) / 1_000_000.0;
    let prior_scale = (prior_units as f64) / 1_000_000.0;
    let staged = prior_weight * prior_scale;
    let numerator = if selected {
        staged + (delta_units as f64) / 1_000_000.0
    } else {
        staged
    };

    if numerator < 1e-7 || !numerator.is_finite() || denominator < 1e-15 {
        return 0.0;
    }
    // The denominator comes from a clamped i64, so it cannot be NaN or infinity.
    // The native caller also rejects +infinity/unordered denominators; those
    // states are unreachable through this typed entry point.
    let quotient = numerator / denominator;
    if quotient.is_finite() {
        quotient
    } else {
        0.0
    }
}
