//! Calendar inputs for the normal-return heartbeat age path.
use super::{HeartbeatClass, HeartbeatError, classify_present};
use crate::{DateTime, days_before_year, from_ce_day};

const NANOS_PER_SECOND: i128 = 1_000_000_000;
const SECONDS_PER_DAY: i128 = 86_400;

/// A canonical calendar date and time in the domain of the #115 heartbeat comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeartbeatTime {
    ce_day: i32,
    seconds_of_day: u32,
    nanoseconds: u32,
}

impl HeartbeatTime {
    /// Accept the clock producer's dates and the conventional leap-second representation.
    /// A leap second uses a nanosecond field of 1e9 or more on second 59 of a minute.
    pub fn from_datetime(value: DateTime) -> Option<Self> {
        let ce_day =
            i32::try_from(days_before_year(value.date.year) + i64::from(value.date.ordinal))
                .ok()?;
        if from_ce_day(ce_day)? != value.date
            || value.seconds_of_day >= 86_400
            || value.nanoseconds >= 2_000_000_000
            || (value.nanoseconds >= 1_000_000_000 && value.seconds_of_day % 60 != 59)
        {
            return None;
        }
        Some(Self {
            ce_day,
            seconds_of_day: value.seconds_of_day,
            nanoseconds: value.nanoseconds,
        })
    }

    fn age_since(self, earlier: Self) -> f64 {
        let days = i128::from(self.ce_day) - i128::from(earlier.ce_day);
        let mut seconds = days * SECONDS_PER_DAY + i128::from(self.seconds_of_day)
            - i128::from(earlier.seconds_of_day);
        // The helper adjusts by the *time-of-day* ordering, even across different dates.
        if self.seconds_of_day > earlier.seconds_of_day && earlier.nanoseconds >= 1_000_000_000 {
            seconds += 1;
        } else if self.seconds_of_day < earlier.seconds_of_day && self.nanoseconds >= 1_000_000_000
        {
            seconds -= 1;
        }
        let total = seconds * NANOS_PER_SECOND + i128::from(self.nanoseconds)
            - i128::from(earlier.nanoseconds);
        if total <= 0 {
            return 0.0;
        }
        // The consumer first converts whole seconds and the remainder separately.
        (total / NANOS_PER_SECOND) as f64 + (total % NANOS_PER_SECOND) as f64 / 1_000_000_000.0
    }
}

/// The values read from a found row. A missing lookup is represented by `None`.
#[derive(Clone, Copy, Debug)]
pub struct TimedSample {
    pub numerator: f64,
    pub denominator: f64,
    pub recorded_at: HeartbeatTime,
}

/// Classify using the current clock projection and the row's recorded time.
/// Age arithmetic is deferred until the selected ratio/configuration path needs it.
pub fn classify_at(
    now: HeartbeatTime,
    sample: Option<TimedSample>,
    threshold: f64,
    config_flag: bool,
) -> Result<HeartbeatClass, HeartbeatError> {
    let Some(sample) = sample else {
        return Ok(HeartbeatClass::Missing);
    };
    classify_present(
        sample.numerator,
        sample.denominator,
        threshold,
        config_flag,
        || now.age_since(sample.recorded_at),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::from_clock_read;

    fn time(ce_day: i32, seconds: u32, nanos: u32) -> HeartbeatTime {
        HeartbeatTime::from_datetime(DateTime {
            date: from_ce_day(ce_day).unwrap(),
            seconds_of_day: seconds,
            nanoseconds: nanos,
        })
        .unwrap()
    }

    fn sample(recorded_at: HeartbeatTime) -> TimedSample {
        TimedSample {
            numerator: 0.0,
            denominator: 1.0,
            recorded_at,
        }
    }

    #[test]
    fn clock_and_row_cross_midnight_at_the_exact_threshold() {
        let recorded = sample(time(719_163, 86_399, 500_000_000));
        let now = from_clock_read(86_579, 500_000_000).unwrap();
        assert_eq!(
            classify_at(
                HeartbeatTime::from_datetime(now).unwrap(),
                Some(recorded),
                0.0,
                false
            ),
            Ok(HeartbeatClass::Skip)
        );
        let next = from_clock_read(86_579, 500_000_001).unwrap();
        assert_eq!(
            classify_at(
                HeartbeatTime::from_datetime(next).unwrap(),
                Some(recorded),
                0.0,
                false
            ),
            Ok(HeartbeatClass::Age(180.000_000_001))
        );
    }

    #[test]
    fn leap_fraction_changes_the_selected_heartbeat_class() {
        let recorded = sample(time(719_163, 59, 1_500_000_000));
        let now = time(719_163, 240, 0);
        assert_eq!(
            classify_at(now, Some(recorded), 0.0, false),
            Ok(HeartbeatClass::Age(180.5))
        );
        assert_eq!(
            classify_at(recorded.recorded_at, Some(sample(now)), 0.0, false),
            Ok(HeartbeatClass::Skip)
        );
    }

    #[test]
    fn missing_and_ratio_routes_finish_before_age_conversion() {
        let now = time(719_163, 0, 0);
        assert_eq!(
            classify_at(now, None, 0.0, false),
            Ok(HeartbeatClass::Missing)
        );
        assert_eq!(
            classify_present(2.0, 1.0, 1.0, false, || panic!(
                "unexpected age calculation"
            )),
            Ok(HeartbeatClass::Ratio(2.0))
        );
    }

    #[test]
    fn clock_projections_preserve_valid_leap_seconds_and_consistent_dates() {
        let mut value = from_clock_read(59, 0).unwrap();
        value.nanoseconds = 1_999_999_999;
        assert!(HeartbeatTime::from_datetime(value).is_some());
        value.seconds_of_day = 60;
        assert!(HeartbeatTime::from_datetime(value).is_none());
        value.nanoseconds = 0;
        value.date.ordinal += 1;
        assert!(HeartbeatTime::from_datetime(value).is_none());
    }
}
