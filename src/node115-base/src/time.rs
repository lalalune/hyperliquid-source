//! Time and Unix-day conversion grounded in node #115 `base/src/time.rs` (`0x15027d0..0x15028e1`).

pub const NANOS_PER_SEC: u64 = 1_000_000_000;
pub const SECS_PER_HOUR: u32 = 3_600;
pub const SECS_PER_DAY: u32 = 86_400;
/// Upper bound enforced by `base/src/time.rs:57` (`0x1567ad8`, `0xe1000 = 256 * 3600`).
pub const MAX_U8_HOUR_SECS: u32 = 256 * SECS_PER_HOUR;
/// Secondary day-window guard enforced at `0x1567af3` (`0x15f90 = 90_000 = 25 * 3600`).
pub const MAX_EXTENDED_DAY_SECS: u32 = 90_000;
/// Proleptic Gregorian day offset of 1970-01-01 embedded at `0x150285f` (`0xaf93b`).
pub const UNIX_EPOCH_DAYS: u32 = 719_163;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HourDecodeError {
    ExceedsU8HourRange,
    ExceedsExtendedDayWindow,
}

/// Reconstructs the `base/src/time.rs:57` (`0x1567ad0..0x1567b94`, 196 B) hour extraction
/// and dual range check (`secs < 0xe1000`, `hour = (secs / 3600) as u8`, `secs < 0x15f90`).
pub const fn hour_from_secs_of_day(secs: u32) -> Result<u8, HourDecodeError> {
    if secs >= MAX_U8_HOUR_SECS {
        return Err(HourDecodeError::ExceedsU8HourRange);
    }
    let hour = (secs / SECS_PER_HOUR) as u8;
    if secs >= MAX_EXTENDED_DAY_SECS {
        return Err(HourDecodeError::ExceedsExtendedDayWindow);
    }
    Ok(hour)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeDecodeError {
    NanosOutOfRange,
    SecsExceedsU32,
    DateOutOfRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedDaySeconds {
    pub packed_date: u32,
    pub secs_of_day: u32,
}

/// Reconstructs the `0x15027d0..0x15028e1` Unix-seconds + nanoseconds to `(packed_date, secs_of_day)`
/// check and day-offset conversion via `node115_daycount_date`.
pub fn split_unix_day_seconds(secs: u64, nanos: u64) -> Result<PackedDaySeconds, TimeDecodeError> {
    if nanos >= NANOS_PER_SEC {
        return Err(TimeDecodeError::NanosOutOfRange);
    }
    if (secs >> 32) != 0 {
        return Err(TimeDecodeError::SecsExceedsU32);
    }
    let secs32 = secs as u32;
    let days = secs32 / SECS_PER_DAY;
    let secs_of_day = secs32 - days * SECS_PER_DAY;
    let ce_days = i32::try_from(
        days.checked_add(UNIX_EPOCH_DAYS)
            .ok_or(TimeDecodeError::DateOutOfRange)?,
    )
    .map_err(|_| TimeDecodeError::DateOutOfRange)?;
    let packed_date = node115_daycount_date::node115_date_from_ce_days(ce_days);
    if packed_date == 0 {
        return Err(TimeDecodeError::DateOutOfRange);
    }
    Ok(PackedDaySeconds {
        packed_date,
        secs_of_day,
    })
}
