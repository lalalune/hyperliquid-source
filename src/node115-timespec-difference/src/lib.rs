//! Complete normalized two-input Timespec difference observed in node #115.
//! Reuses licensed core::time::Duration; no OS, clock or capture is executed.
#![no_std]
use core::time::Duration;

/// Logical normalized fields, not a repr(C) or original native type claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp {
    seconds: i64,
    nanoseconds: u32,
}
impl Timestamp {
    /// Raw-invalid nanos are refused by this safe wrapper. The subtraction
    /// primitive is compared only for the normalized domain ns<1e9.
    pub fn new(seconds: i64, nanoseconds: u32) -> Option<Self> {
        if nanoseconds >= 1_000_000_000 {
            None
        } else {
            Some(Self {
                seconds,
                nanoseconds,
            })
        }
    }
    /// Ok magnitude if self>=other, Err magnitude if self<other. Equality is
    /// Ok(Duration::ZERO). Every normalized i64 timestamp pair fits Duration,
    /// including a u64::MAX seconds span; no signed subtraction is attempted.
    pub fn difference(self, other: Self) -> Result<Duration, Duration> {
        if self >= other {
            Ok(self.magnitude(other))
        } else {
            Err(other.magnitude(self))
        }
    }
    fn magnitude(self, other: Self) -> Duration {
        let seconds = self.seconds.abs_diff(other.seconds);
        if self.nanoseconds >= other.nanoseconds {
            Duration::new(seconds, self.nanoseconds - other.nanoseconds)
        } else {
            // Lexical order guarantees strictly later seconds in this branch.
            Duration::new(
                seconds - 1,
                self.nanoseconds + 1_000_000_000 - other.nanoseconds,
            )
        }
    }
}
