//! Node 115 restart backoff on first entry to the delay future.
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub enum WaitPlan {
    /// The future finishes without constructing a timer.
    Immediate,
    /// Arguments supplied to the timer constructor, including rounded zero.
    Timer(Duration),
    /// Native duration conversion takes the out-of-range path.
    OutOfRange,
}

/// `counter` is the already updated word at frame offset 0xb0. `cap` is
/// the binary64 stored at 0xa8. The normal initialization path supplies 30.
pub fn delay_seconds(counter: u64, cap: f64) -> f64 {
    // The native powi helper raises exactly 2 to a nonnegative i32 exponent.
    // Every binary64 power through 2^1023 is exact, and all larger ones overflow.
    let power = if counter <= 1023 {
        f64::from_bits((counter + 1023) << 52)
    } else {
        f64::INFINITY
    };
    // The caller selects power for an unordered cap, caps the result before
    // subtracting one, and maps a sign bit or all-ones exponent to positive zero.
    let seconds = power.min(cap) - 1.0;
    if seconds.is_sign_negative() || !seconds.is_finite() {
        0.0
    } else {
        seconds
    }
}

/// The native zero fast path precedes rounding to a whole nanosecond.
pub fn first_wait(counter: u64, cap: f64) -> WaitPlan {
    let seconds = delay_seconds(counter, cap);
    if seconds == 0.0 {
        return WaitPlan::Immediate;
    }
    match Duration::try_from_secs_f64(seconds) {
        Ok(duration) => WaitPlan::Timer(duration),
        Err(_) => WaitPlan::OutOfRange,
    }
}
