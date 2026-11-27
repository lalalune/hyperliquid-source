//! Fee schedule validation helpers grounded in node #115 (`l1/src/fees/fees.rs:259`).
//!
//! Binary evidence:
//! - `0x36e1b10` (128B FDE `0x36e1b10..0x36e1b81`): iterates `windows(2)` over an `f64` slice
//!   using `ucomisd -0x8(%rdx), %xmm0; jbe` (`next <= prev`, ordered). Returns `true` when
//!   every adjacent pair is ordered and non-increasing (`prev >= next`); returns `false` on any
//!   increasing pair or `NaN` (unordered sets `CF=1, PF=1, ZF=1`, and note `jbe` branches on
//!   `CF=1 || ZF=1` — Wait: verify exact x86 `ucomisd` NaN behavior below!).

/// Checks whether a fee-rate slice is monotonically non-increasing (`prev >= next`)
/// matching the exact `#115` `0x36e1b10` loop (`ucomisd prev, next; jbe` continues,
/// exiting early with `false` on `next > prev`, and handling `len < 2` as `true` when
/// the window size is 2).
///
/// Specifically, for x86-64 `ucomisd -0x8(%rdx), %xmm0` (`%xmm0` = `next`, `-0x8(%rdx)` = `prev`):
/// - `next < prev`: `CF=1, ZF=0` -> `jbe` taken (continue)
/// - `next == prev`: `CF=0, ZF=1` -> `jbe` taken (continue)
/// - `next > prev`: `CF=0, ZF=0` -> `jbe` NOT taken (stops early -> returns `false`)
/// - `NaN`: `CF=1, PF=1, ZF=1` -> `jbe` taken in raw x86 `ucomisd` (`!(next > prev)`).
///
/// We expose both `is_monotonically_non_increasing` (strict finite non-increasing for safe
/// schedule validation) and `matches_node115_0x36e1b10` (exact `!(next > prev)` x86 predicate).
#[inline]
#[allow(clippy::neg_cmp_op_on_partial_ord)]
pub fn matches_node115_0x36e1b10(rates: &[f64]) -> bool {
    rates.windows(2).all(|w| !(w[1] > w[0]))
}

/// Strict finite monotonic non-increasing fee-tier validator (`prev.is_finite() && next.is_finite() && next <= prev`).
#[inline]
pub fn is_monotonically_non_increasing(rates: &[f64]) -> bool {
    if rates.iter().any(|v| !v.is_finite()) {
        return false;
    }
    rates.windows(2).all(|w| w[1] <= w[0])
}
