//! Archive replica timestamp input for the selected replay clock.

use crate::{AdmittedTimestamp, Error, admit_timestamp};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicaClockError {
    TimestampSyntax,
    InvalidCalendarOrTime,
    NativeAdmission(Error),
}

fn unsigned(text: &str, width: usize) -> Result<u32, ReplicaClockError> {
    if text.len() != width || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ReplicaClockError::TimestampSyntax);
    }
    text.parse().map_err(|_| ReplicaClockError::TimestampSyntax)
}

fn split(text: &str, separator: char) -> Result<(&str, &str), ReplicaClockError> {
    text.split_once(separator)
        .ok_or(ReplicaClockError::TimestampSyntax)
}

fn epoch_day(date: &str) -> Result<i64, ReplicaClockError> {
    let (year_month, day) = date
        .rsplit_once('-')
        .ok_or(ReplicaClockError::TimestampSyntax)?;
    let (year, month) = year_month
        .rsplit_once('-')
        .ok_or(ReplicaClockError::TimestampSyntax)?;
    let valid_year = match year.strip_prefix(['+', '-']) {
        Some(digits) => digits.len() >= 4 && digits.bytes().all(|byte| byte.is_ascii_digit()),
        None => year.len() == 4 && year.bytes().all(|byte| byte.is_ascii_digit()),
    };
    if !valid_year {
        return Err(ReplicaClockError::TimestampSyntax);
    }
    let year: i32 = year
        .parse()
        .map_err(|_| ReplicaClockError::TimestampSyntax)?;
    let month = unsigned(month, 2)?;
    let day = unsigned(day, 2)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mut month_lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if leap {
        month_lengths[1] = 29;
    }
    if !(1..=12).contains(&month) || day == 0 || day > month_lengths[month as usize - 1] {
        return Err(ReplicaClockError::InvalidCalendarOrTime);
    }
    let ordinal = month_lengths[..month as usize - 1].iter().sum::<u32>() + day;
    let previous_year = i64::from(year) - 1;
    let completed_days = 365 * previous_year + previous_year.div_euclid(4)
        - previous_year.div_euclid(100)
        + previous_year.div_euclid(400);
    Ok(completed_days + i64::from(ordinal) - 719_163)
}

/// Map a zone-free replica `abci_block.time` to the admitted #115 clock fields.
/// The fraction is interpreted in decimal nanoseconds. The archive convention
/// supplies the civil date and time directly, without local-time adjustment.
pub fn decode_replica_clock(text: &str) -> Result<AdmittedTimestamp, ReplicaClockError> {
    let (date, time) = split(text, 'T')?;
    let day = epoch_day(date)?;
    let (hour, tail) = split(time, ':')?;
    let (minute, tail) = split(tail, ':')?;
    let (second, fraction) = match tail.split_once('.') {
        Some((second, fraction)) if (1..=9).contains(&fraction.len()) => (second, Some(fraction)),
        Some(_) => return Err(ReplicaClockError::TimestampSyntax),
        None => (tail, None),
    };
    let hour = unsigned(hour, 2)?;
    let minute = unsigned(minute, 2)?;
    let second = unsigned(second, 2)?;
    if hour >= 24 || minute >= 60 || second > 60 {
        return Err(ReplicaClockError::InvalidCalendarOrTime);
    }
    let mut nanos = if let Some(fraction) = fraction {
        unsigned(fraction, fraction.len())? * 10u32.pow(9 - fraction.len() as u32)
    } else {
        0
    };
    if second == 60 {
        nanos += 1_000_000_000;
    }
    let seconds = day * 86_400 + i64::from(hour * 3600 + minute * 60 + second.min(59));
    admit_timestamp(seconds, nanos).map_err(ReplicaClockError::NativeAdmission)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_examples_keep_nanoseconds_and_calendar_position() {
        let cases = [
            ("1970-01-01T00:00:00", 0, 0),
            ("1969-12-31T23:59:59.1", -1, 100_000_000),
            ("2000-02-29T12:00:00.000002", 951_825_600, 2_000),
            ("2025-12-04T08:00:47.509497915", 1_764_835_247, 509_497_915),
            ("2026-10-21T03:04:05.123456789", 1_792_551_845, 123_456_789),
            ("2016-12-31T23:59:60.500", 1_483_228_799, 1_500_000_000),
        ];
        for (text, seconds, nanos) in cases {
            assert_eq!(
                decode_replica_clock(text),
                admit_timestamp(seconds, nanos).map_err(ReplicaClockError::NativeAdmission),
                "{text}"
            );
        }
    }

    #[test]
    fn distinct_fractional_ticks_have_the_same_date_and_second() {
        let first = decode_replica_clock("2026-10-21T03:04:05.123456788").unwrap();
        let next = decode_replica_clock("2026-10-21T03:04:05.123456789").unwrap();
        assert_eq!(first.packed_date, next.packed_date);
        assert_eq!(first.second_of_day, next.second_of_day);
        assert_eq!(first.nanoseconds + 1, next.nanoseconds);
    }

    #[test]
    fn rejects_shape_calendar_and_native_range_errors_separately() {
        for text in [
            "2026-10-21T03:04:05Z",
            "2026-10-21T03:04:05.",
            "2026-10-21T03:04:05.1234567890",
        ] {
            assert_eq!(
                decode_replica_clock(text),
                Err(ReplicaClockError::TimestampSyntax)
            );
        }
        for text in [
            "1900-02-29T03:04:05",
            "2026-04-31T03:04:05",
            "2026-10-21T24:00:00",
        ] {
            assert_eq!(
                decode_replica_clock(text),
                Err(ReplicaClockError::InvalidCalendarOrTime)
            );
        }
        assert!(matches!(
            decode_replica_clock("+262143-01-01T00:00:00"),
            Err(ReplicaClockError::NativeAdmission(_))
        ));
        assert!(decode_replica_clock("-0001-12-31T00:00:00").is_ok());
    }
}
