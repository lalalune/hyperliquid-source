//! Supplied-u64-nanosecond projection of the node94 accept Pending-poll metrics.
//!
//! Callers establish normal helper returns and representable nanoseconds.
//! This does not implement clocks, Instant overflow, wakers or atomic ordering.
#![no_std]
#![forbid(unsafe_code)]

/// Observed monitor byte offsets; this array is not the original Rust layout.
pub const OFFSETS: [usize; 14] = [
    0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Projection {
    pub increments: [u64; 14],
    pub last_end: u64,
}

/// Produce the counter increments for one poll that takes the normal Pending exit.
///
/// Times are nanoseconds since creation; `start` is the post-bookkeeping clock.
/// Threshold equality selects the long-delay / slow-poll counters. No-wake is
/// the raw zero sentinel. These values do not prove original clock reachability.
pub fn pending_poll(
    first: bool,
    now: u64,
    woke: u64,
    last_end: u64,
    start: u64,
    end: u64,
    long_delay: u64,
    slow_poll: u64,
) -> Projection {
    let mut increments = [0; 14];
    if first {
        increments[0] = 1;
        increments[7] = now;
    }
    if woke > last_end {
        increments[1] = 1;
        increments[8] = woke - last_end;
    }
    if woke != 0 {
        let delay = now.saturating_sub(woke);
        increments[2] = 1;
        increments[9] = delay;
        let (count, duration) = if delay < long_delay { (6, 12) } else { (5, 13) };
        increments[count] = 1;
        increments[duration] = delay;
    }
    let poll = end.saturating_sub(start);
    let (count, duration) = if poll < slow_poll { (3, 10) } else { (4, 11) };
    increments[count] = 1;
    increments[duration] = poll;
    Projection {
        increments,
        last_end: end,
    }
}

/// Offline modulo-2^64 addition, conditional on the observed locked-qword adds.
/// Concurrent updates and the original atomic memory model are outside this API.
pub fn apply(counters: &mut [u64; 14], result: &Projection) {
    for (value, increment) in counters.iter_mut().zip(result.increments) {
        *value = value.wrapping_add(increment);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_takes_long_and_slow_without_counting_idle() {
        let result = pending_poll(false, 12, 10, 10, 12, 14, 2, 2);
        assert_eq!(result.increments[1], 0);
        assert_eq!(result.increments[5], 1);
        assert_eq!(result.increments[4], 1);
        assert_eq!(result.last_end, 14);
    }

    #[test]
    fn no_wake_omits_schedule_and_clock_differences_saturate() {
        let result = pending_poll(true, 2, 0, 0, 9, 3, 0, 0);
        assert_eq!(result.increments[7], 2);
        assert_eq!(result.increments[2], 0);
        assert_eq!(result.increments[11], 0);
        let mut counters = [u64::MAX; 14];
        apply(&mut counters, &result);
        assert_eq!(counters[0], 0);
    }
}
