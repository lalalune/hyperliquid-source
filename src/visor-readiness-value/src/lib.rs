//! Safe values for the conditional Visor sample/calendar/fixed60 relation.
//!
//! Inputs are supplied numbers. This crate never reads a clock or executes a
//! target. `None` is new safe refusal policy, not a recovered native error ABI.
//! See RE-013-visor-readiness-value-rust for the static proof and its premises.
#![forbid(unsafe_code)]

const MIN_YEAR: i32 = -262143;
const MAX_YEAR: i32 = 262142;
const MAX_SAMPLE: i64 = 8210266876799;

fn leap(year: i32) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

fn year_length(year: i32) -> u16 {
    365 + u16::from(leap(year))
}

/// A canonical ordinary timestamp. Fields and raw-word construction are private.
/// Its host layout is not the captured target's ABI or source type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    year: i32,
    ordinal: u16,
    second: u32,
    nano: u32,
}

impl Timestamp {
    /// Admit only the proved Gregorian/ordinary-nanosecond value domain.
    pub fn from_parts(year: i32, ordinal: u16, second: u32, nano: u32) -> Option<Self> {
        if !(MIN_YEAR..=MAX_YEAR).contains(&year)
            || ordinal == 0
            || ordinal > year_length(year)
            || second >= 86400
            || nano >= 1000000000
        {
            return None;
        }
        Some(Self {
            year,
            ordinal,
            second,
            nano,
        })
    }

    /// Convert an admitted numeric sample; zero is year1970, ordinal1, second0.
    /// No OS clock, environment, timezone or external helper is consulted.
    pub fn from_clock_sample(seconds: i64, nano: u64) -> Option<Self> {
        if !(0..=MAX_SAMPLE).contains(&seconds) || nano >= 1000000000 {
            return None;
        }
        let days = seconds as u64 / 86400 + 719528;
        let mut year = (days / 146097 * 400) as i32;
        let mut remainder = (days % 146097) as u32;
        // At most399 whole years are removed from this bounded400-year cycle.
        while remainder >= u32::from(year_length(year)) {
            remainder -= u32::from(year_length(year));
            year += 1;
        }
        Self::from_parts(
            year,
            (remainder + 1) as u16,
            (seconds % 86400) as u32,
            nano as u32,
        )
    }

    /// Logical signed packed date, second and nano; no target memory layout.
    pub fn raw_words(self) -> (i32, u32, u32) {
        let residue = self.year.rem_euclid(400);
        let leap_prefix = (residue + 3) / 4 - (residue + 99) / 100 + (residue + 399) / 400;
        let flags =
            (if leap(self.year) { 0 } else { 8 }) | ((365 * residue + leap_prefix + 3) % 7 + 1);
        let packed = 8192 * self.year + 16 * i32::from(self.ordinal) + flags;
        (packed, self.second, self.nano)
    }

    /// Add exactly60 seconds, saturating at the greatest ordinary timestamp.
    pub fn deadline_60(self) -> Self {
        let mut result = self;
        result.second += 60;
        if result.second >= 86400 {
            result.second -= 86400;
            result.ordinal += 1;
            if result.ordinal > year_length(result.year) {
                if result.year == MAX_YEAR {
                    return Self {
                        year: MAX_YEAR,
                        ordinal: 365,
                        second: 86399,
                        nano: 999999999,
                    };
                }
                result.year += 1;
                result.ordinal = 1;
            }
        }
        result
    }
}

/// The local strict signed-date/unsigned-time comparison against source+60.
/// Equality is false. This does not reconstruct the whole readiness policy.
pub fn is_strictly_past_deadline(current: Timestamp, source: Timestamp) -> bool {
    current.raw_words() > source.deadline_60().raw_words()
}
