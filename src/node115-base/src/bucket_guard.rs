//! Periodic bucket-start time conversion grounded in node #115
//! `base/src/bucket_guard.rs:66` (`0x14c2c50..0x14c2d82`, 306 B).

use crate::time::{SECS_PER_DAY, UNIX_EPOCH_DAYS};

/// Maximum millisecond timestamp accepted before falling back to the slow path (`0x14c2c9a`).
pub const MAX_FAST_PATH_MILLIS: u64 = 0x0292_f57c_e8ac_cbff;
pub const MILLIS_PER_SEC: u64 = 1_000;
pub const NANOS_PER_MILLI: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BucketStartTime {
    pub packed_date: u32,
    pub secs_of_day: u32,
    pub subsec_nanos: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BucketTimeError {
    OverflowedMillis,
    MillisOutOfRange,
    DateOutOfRange,
}

/// Periodic time-bucket guard matching `base/src/bucket_guard.rs` (`0x14c2c50..0x14c2d82`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BucketGuard {
    pub bucket_millis: u64,
    pub last_bucket: u64,
}

impl BucketGuard {
    pub const fn new(bucket_millis: u64) -> Self {
        Self {
            bucket_millis,
            last_bucket: 0,
        }
    }

    /// Computes `bucket_id * bucket_millis` saturating to `u64::MAX` on `u64` overflow
    /// (matching `mul [rsi]; jo -> mov [rsp], u64::MAX` at `0x14c2c62..0x14c2d25`).
    #[inline]
    pub const fn bucket_start_millis(&self, bucket_id: u64) -> u64 {
        match bucket_id.checked_mul(self.bucket_millis) {
            Some(ms) => ms,
            None => u64::MAX,
        }
    }

    /// Reconstructs the `0x14c2c50..0x14c2d82` fast-path conversion from `(bucket_id, bucket_millis)`
    /// into `(packed_date, secs_of_day, subsec_nanos)`.
    pub fn bucket_start_time(&self, bucket_id: u64) -> Result<BucketStartTime, BucketTimeError> {
        let Some(ms) = bucket_id.checked_mul(self.bucket_millis) else {
            return Err(BucketTimeError::OverflowedMillis);
        };
        if ms > MAX_FAST_PATH_MILLIS {
            return Err(BucketTimeError::MillisOutOfRange);
        }
        let total_secs = ms / MILLIS_PER_SEC;
        let subsec_ms = (ms - total_secs * MILLIS_PER_SEC) as u32;
        let subsec_nanos = subsec_ms * NANOS_PER_MILLI;
        let days = total_secs / u64::from(SECS_PER_DAY);
        let secs_of_day = (total_secs - days * u64::from(SECS_PER_DAY)) as u32;
        let ce_days = i32::try_from(
            days.checked_add(u64::from(UNIX_EPOCH_DAYS))
                .ok_or(BucketTimeError::DateOutOfRange)?,
        )
        .map_err(|_| BucketTimeError::DateOutOfRange)?;
        let packed_date = node115_daycount_date::node115_date_from_ce_days(ce_days);
        if packed_date == 0 {
            return Err(BucketTimeError::DateOutOfRange);
        }
        Ok(BucketStartTime {
            packed_date,
            secs_of_day,
            subsec_nanos,
        })
    }

    /// Advances `last_bucket` strictly monotonically when `time_ms / bucket_millis > last_bucket`.
    pub fn guard(&mut self, time_ms: u64) -> bool {
        if self.bucket_millis == 0 {
            return false;
        }
        let bucket = time_ms / self.bucket_millis;
        if bucket > self.last_bucket {
            self.last_bucket = bucket;
            true
        } else {
            false
        }
    }
}
