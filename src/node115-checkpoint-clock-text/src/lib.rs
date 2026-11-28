//! Bounded checkpoint clock text adapter for the node #115 fixture.
#![no_std]

use node115_date_time_display::{Date, Time, render_date, render_time};

pub struct CheckpointClockText {
    bytes: [u8; 32],
    length: usize,
}

impl CheckpointClockText {
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.length]).expect("formatters emit ASCII")
    }
}

/// Render the three checkpoint clock words as a named context date-time string.
/// The packed date flags do not change the logical year or ordinal.
pub fn render_checkpoint_clock(
    date_word: u32,
    seconds: u32,
    nanos: u32,
) -> Option<CheckpointClockText> {
    let year = (date_word as i32) >> 13;
    let ordinal = ((date_word >> 4) & 0x1ff) as u16;
    let date = render_date(Date::new(year, ordinal)?);
    let time = render_time(Time::new(seconds, nanos)?);
    let date_len = date.as_bytes().len();
    let length = date_len + 1 + time.as_bytes().len();

    let mut bytes = [0; 32];
    bytes[..date_len].copy_from_slice(date.as_bytes());
    bytes[date_len] = b'T';
    bytes[date_len + 1..length].copy_from_slice(time.as_bytes());
    Some(CheckpointClockText { bytes, length })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_checkpoint_words_with_literal_t() {
        for (date_word, seconds, nanos, expected) in [
            (0x00fd_402a, 11_045, 0, "2026-01-02T03:04:05"),
            (
                0x00fa_03c4,
                45_296,
                123_456,
                "2000-02-29T12:34:56.000123456",
            ),
            (
                0x00fc_16e3,
                86_399,
                1_123_000_000,
                "2016-12-31T23:59:60.123",
            ),
            (0xffff_e01b, 0, 0, "-0001-01-01T00:00:00"),
        ] {
            let output = render_checkpoint_clock(date_word, seconds, nanos).unwrap();
            assert_eq!(output.as_str(), expected);
        }
    }

    #[test]
    fn retains_the_display_domain() {
        assert!(render_checkpoint_clock(0, 0, 0).is_none());
        assert!(render_checkpoint_clock(0x00fd_402a, 86_400, 0).is_none());
        assert!(render_checkpoint_clock(0x00fd_402a, 11_045, 1_000_000_000).is_none());
    }
}

/// Logical clock fields for a canonical checkpoint timestamp.
/// The packed calendar flags are outside this projection.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedClock {
    pub year: i32,
    pub ordinal: u16,
    pub seconds: u32,
    pub nanos: u32,
}

/// Read the canonical text emitted by the checkpoint formatter. The native
/// format-item interpreter also accepts some noncanonical spellings.
pub fn parse_canonical_checkpoint_clock(input: &str) -> Option<ParsedClock> {
    let (input_date, input_time) = input.split_once('T')?;
    let (year_month, day) = input_date.rsplit_once('-')?;
    let (year, month) = year_month.rsplit_once('-')?;
    let year: i32 = year.parse().ok()?;
    let month: usize = month.parse().ok()?;
    let day: u16 = day.parse().ok()?;

    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let lengths = [
        31,
        28 + u16::from(leap),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let month_index = month.checked_sub(1)?;
    if day == 0 || day > *lengths.get(month_index)? {
        return None;
    }
    let ordinal = lengths[..month_index].iter().sum::<u16>() + day;
    let date = Date::new(year, ordinal)?;

    let (hour, remainder) = input_time.split_once(':')?;
    let (minute, second) = remainder.split_once(':')?;
    let hour: u32 = hour.parse().ok()?;
    let minute: u32 = minute.parse().ok()?;
    let (second, fraction) = second.split_once('.').unwrap_or((second, ""));
    let second: u32 = second.parse().ok()?;
    if hour > 23 || minute > 59 || second > 60 || fraction.len() > 9 {
        return None;
    }
    let fraction_nanos = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u32>().ok()? * 10_u32.pow(9 - fraction.len() as u32)
    };
    let seconds = hour * 3600 + minute * 60 + second.min(59);
    let nanos = fraction_nanos + u32::from(second == 60) * 1_000_000_000;
    let time = Time::new(seconds, nanos)?;

    let canonical_date = render_date(date);
    let canonical_time = render_time(time);
    (input_date == canonical_date.as_str() && input_time == canonical_time.as_str()).then_some(
        ParsedClock {
            year,
            ordinal,
            seconds,
            nanos,
        },
    )
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn reads_the_selected_checkpoint_clock_words() {
        for (text, year, ordinal, seconds, nanos) in [
            ("2026-01-02T03:04:05", 2026, 2, 11_045, 0),
            ("2000-02-29T12:34:56.000123456", 2000, 60, 45_296, 123_456),
            ("2016-12-31T23:59:60.123", 2016, 366, 86_399, 1_123_000_000),
            ("-0001-01-01T00:00:00", -1, 1, 0, 0),
        ] {
            assert_eq!(
                parse_canonical_checkpoint_clock(text),
                Some(ParsedClock {
                    year,
                    ordinal,
                    seconds,
                    nanos
                })
            );
        }
    }

    #[test]
    fn rejects_values_outside_the_canonical_checkpoint_boundary() {
        for text in [
            "2100-02-29T00:00:00",
            "2026-04-31T00:00:00",
            "2026-01-02T03:60:00",
            "2026-01-02T03:04:61",
            "2026-01-02 03:04:05",
            "2026-01-02T03:04:05Z",
            "2026-1-02T03:04:05",
            "2026-01-02T03:04:05.00",
        ] {
            assert_eq!(parse_canonical_checkpoint_clock(text), None, "{text}");
        }
    }
}
