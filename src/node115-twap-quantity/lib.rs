//! Perpetual TWAP scheduled quantity calculation, independently authored.
//!
//! Inputs are a selected logical TWAP state, a positive already computed limit
//! price and a clamped epoch-millisecond timestamp. Book lookup/price building,
//! native collection ABI, order submission and the advance callback are excluded.
#![forbid(unsafe_code)]
use std::num::NonZeroU64;

/// The native date domain fits this bound. The bound also makes its reciprocal
/// phase calculation exactly equivalent to timestamp modulo forty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimestampMs(u64);
impl TimestampMs {
    pub const fn new(value: u64) -> Option<Self> {
        if value < (1u64 << 53) {
            Some(Self(value))
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct State {
    pub total: u64,
    pub filled: u64,
    pub slice_index: u64,
    pub duration: f64,
    pub jitter: bool,
}

/// A selected quantity result, not the native order-record or option ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slice {
    pub quantity: u64,
    pub target: u64,
    pub slice_count: u64,
}

/// Non-finite divided duration becomes zero, then 2*trunc(x)+1 saturates.
pub fn slice_count(duration: f64) -> u64 {
    let divided = duration / 60.0;
    let n = if divided.is_finite() {
        divided as u64
    } else {
        0
    };
    n.saturating_mul(2).saturating_add(1)
}

fn floor_unsigned(value: f64) -> u64 {
    if value.is_finite() {
        value.floor() as u64
    } else {
        0
    }
}

fn size_step(quantity: u64) -> u64 {
    let digits = quantity.ilog10() + 1;
    10u64.pow(digits.saturating_sub(5))
}

/// Returns `None` for the selected calculation's advance/no-slice decision.
/// It does not invoke or reproduce the separate native advance callback.
///
/// Jitter uses a fused multiply-add, matching the native selected FMA3/FMA4
/// dispatch paths. No equivalence claim is made for the software fallback.
/// Native diagnostic paths are modeled only when their helper returns.
pub fn plan(state: State, limit_price: NonZeroU64, timestamp: TimestampMs) -> Option<Slice> {
    let n = slice_count(state.duration);
    let average = state.total as f64 / n as f64;
    let target = if state.slice_index == n {
        state.total
    } else if state.jitter {
        let phase = (timestamp.0 % 40) as f64 / 100.0 - 0.2;
        let offset = phase * average;
        floor_unsigned(average.mul_add(state.slice_index as f64, offset))
    } else {
        floor_unsigned(average * state.slice_index as f64)
    };
    let due = target.checked_sub(state.filled)?;
    let remaining = state.total.saturating_sub(state.filled);
    let price = limit_price.get();
    let mut quantity = remaining;
    // A product over u64::MAX also takes the large-notional path natively.
    if u128::from(remaining) * u128::from(price) > 30_000_000 {
        let minimum = 12_000_000u64.div_ceil(price);
        let cap = floor_unsigned(average).saturating_mul(3).saturating_add(1);
        quantity = due.min(cap).max(minimum).min(remaining);
        if state.slice_index < n && quantity != 0 {
            let step = size_step(quantity);
            quantity = quantity / step * step;
        }
    }
    (quantity != 0).then_some(Slice {
        quantity,
        target,
        slice_count: n,
    })
}
