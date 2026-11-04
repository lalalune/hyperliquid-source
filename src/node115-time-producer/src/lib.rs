//! Node #115's time producer and CE-day packed-date semantics, independently
//! reconstructed from target-bound arithmetic/tables; no clock is called.
#![no_std]

pub const MIN_YEAR: i32 = -262143;
pub const MAX_YEAR: i32 = 262142;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Date {
    pub year: i32,
    pub ordinal: u16,
    pub flags: u8,
    pub packed: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DateTime {
    pub date: Date,
    pub seconds_of_day: u32,
    pub nanoseconds: u32,
}

/// Logical failure boundaries, not original enum discriminants or panic ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Nanoseconds,
    BeforeEpoch,
    DateRange,
}

const fn leap(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_before_year(year: i32) -> i64 {
    let previous = i64::from(year) - 1;
    previous * 365 + previous.div_euclid(4) - previous.div_euclid(100) + previous.div_euclid(400)
}

/// The native input is a signed CE day: CE1 is 0001-01-01.
/// Full Gregorian cycle arithmetic covers year zero and negative years.
/// The binary search intentionally differs from the target's reciprocal/table
/// implementation; exact packed-field semantics are the comparison boundary.
pub fn from_ce_day(day: i32) -> Option<Date> {
    let day = i64::from(day);
    if day < days_before_year(MIN_YEAR) + 1 || day > days_before_year(MAX_YEAR + 1) {
        return None;
    }
    let mut low = MIN_YEAR;
    let mut high = MAX_YEAR + 1;
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if days_before_year(middle) < day {
            low = middle;
        } else {
            high = middle;
        }
    }
    let year = low;
    let before = days_before_year(year);
    let ordinal = (day - before) as u16;
    // January 1 weekday encoded as the target's 1..7 cycle, high bit nonleap.
    let flags = (((before + 5).rem_euclid(7) + 1) as u8) | if leap(year) { 0 } else { 8 };
    let packed = (year << 13) | (i32::from(ordinal) << 4) | i32::from(flags);
    Some(Date {
        year,
        ordinal,
        flags,
        packed,
    })
}

/// Resume at a successful clock-read boundary. Seconds are the Linux signed
/// seconds field and nanoseconds the raw unsigned qword interpretation.
/// Invalid nanos maps the clock adapter's failure boundary; a pre-origin read
/// maps duration-since-zero failure. No OS call or synthetic clock is provided.
pub fn from_clock_read(seconds: i64, nanoseconds: u64) -> Result<DateTime, Error> {
    if nanoseconds >= 1_000_000_000 {
        return Err(Error::Nanoseconds);
    }
    if seconds < 0 {
        return Err(Error::BeforeEpoch);
    }
    let days = seconds / 86400;
    let seconds_of_day = (seconds % 86400) as u32;
    let ce_day = i32::try_from(days + 719163).map_err(|_| Error::DateRange)?;
    let date = from_ce_day(ce_day).ok_or(Error::DateRange)?;
    Ok(DateTime {
        date,
        seconds_of_day,
        nanoseconds: nanoseconds as u32,
    })
}
