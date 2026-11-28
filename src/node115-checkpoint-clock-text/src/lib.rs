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

mod ingress;
pub use ingress::{ClockIngressError, parse_checkpoint_clock, stage_decoded_clock_pair};

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
