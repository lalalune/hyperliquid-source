//! Scalar relation of node115 packed-date difference at 0x162a290.
//! Explicit integer projections, not recovered Chrono types or native ABI.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Words {
    pub date_word: u32,
    pub seconds_word: u32,
    pub nanos_word: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Difference {
    pub seconds: i64,
    /// Always less than 1,000,000,000.
    pub nanos: u32,
}

fn day_number(word: u32) -> Option<i64> {
    let year = i64::from((word as i32) >> 13);
    let ordinal = i64::from((word >> 4) & 511);
    // The observed zero-day-of-cycle pre-panic boundary is not full date validation.
    if year.rem_euclid(400) == 0 && ordinal == 0 {
        return None;
    }
    // Gregorian leap years in [0, year), including negative years.
    let leap_days =
        (year + 3).div_euclid(4) - (year + 99).div_euclid(100) + (year + 399).div_euclid(400);
    Some(year * 365 + leap_days + ordinal)
}

/// The selected normal-return raw integer relation.
///
/// Low four date bits are ignored. Complete date validity, actual caller
/// reachability, clocks, original panic/unwind behavior and native ABI remain
/// outside this value API. None denotes the native pre-helper zero-sum boundary.
pub fn difference(left: Words, right: Words) -> Option<Difference> {
    let left_day = day_number(left.date_word)?;
    let right_day = day_number(right.date_word)?;
    let leap_adjustment =
        if left.nanos_word >= 1_000_000_000 && left.seconds_word < right.seconds_word {
            -1
        } else if right.nanos_word >= 1_000_000_000 && left.seconds_word > right.seconds_word {
            1
        } else {
            0
        };
    let nanos = i64::from(left.nanos_word) - i64::from(right.nanos_word);
    let seconds = (left_day - right_day) * 86_400 + i64::from(left.seconds_word)
        - i64::from(right.seconds_word)
        + leap_adjustment
        + nanos.div_euclid(1_000_000_000);
    Some(Difference {
        seconds,
        nanos: nanos.rem_euclid(1_000_000_000) as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::{difference, Difference, Words};
    fn words(year: i32, ordinal: u32, seconds: u32, nanos: u32) -> Words {
        Words {
            date_word: ((year as u32) << 13) | (ordinal << 4),
            seconds_word: seconds,
            nanos_word: nanos,
        }
    }
    #[test]
    fn complete_cycle_and_negative_years() {
        let origin = words(0, 1, 0, 0);
        assert_eq!(
            difference(words(400, 1, 0, 0), origin),
            Some(Difference {
                seconds: 146_097 * 86_400,
                nanos: 0
            })
        );
        assert_eq!(
            difference(words(-400, 1, 0, 0), origin),
            Some(Difference {
                seconds: -146_097 * 86_400,
                nanos: 0
            })
        );
        assert_eq!(
            difference(words(1, 1, 0, 0), origin),
            Some(Difference {
                seconds: 366 * 86_400,
                nanos: 0
            })
        );
    }
    #[test]
    fn borrow_and_native_leap_adjustments() {
        assert_eq!(
            difference(words(2000, 1, 1, 0), words(2000, 1, 0, 999_999_999)),
            Some(Difference {
                seconds: 0,
                nanos: 1
            })
        );
        assert_eq!(
            difference(words(2000, 1, 0, 999_999_999), words(2000, 1, 1, 0)),
            Some(Difference {
                seconds: -1,
                nanos: 999_999_999
            })
        );
        assert_eq!(
            difference(words(2000, 1, 60, 0), words(2000, 1, 59, 1_000_000_000)),
            Some(Difference {
                seconds: 1,
                nanos: 0
            })
        );
        assert_eq!(
            difference(words(2000, 1, 59, 1_000_000_000), words(2000, 1, 60, 0)),
            Some(Difference {
                seconds: -1,
                nanos: 0
            })
        );
    }
    #[test]
    fn raw_guard_and_ignored_flags() {
        assert_eq!(difference(words(400, 0, 0, 0), words(0, 1, 0, 0)), None);
        let mut raw = words(-1, 1, 0, 0);
        let original = difference(raw, words(0, 1, 0, 0));
        raw.date_word |= 15;
        assert_eq!(difference(raw, words(0, 1, 0, 0)), original);
    }
}
