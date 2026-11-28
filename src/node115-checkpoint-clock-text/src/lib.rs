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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactClockError {
    WrongSize { actual: usize },
    HeightMismatch { expected: u64, actual: u64 },
}

/// Read current then previous date/second/nanosecond words from a caller-pinned
/// materialized checkpoint. Reading preserves the packed date flags.
pub fn read_compact_checkpoint_clocks(
    image: &[u8],
    expected_height: u64,
) -> Result<[[u32; 3]; 2], CompactClockError> {
    if image.len() != 0x42c8 {
        return Err(CompactClockError::WrongSize { actual: image.len() });
    }
    let height = u64::from_le_bytes(image[0x28..0x30].try_into().unwrap());
    if height != expected_height {
        return Err(CompactClockError::HeightMismatch { expected: expected_height, actual: height });
    }
    let words = |base| core::array::from_fn(|index| {
        let offset = base + 4 * index;
        u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap())
    });
    Ok([words(0x60), words(0x6c)])
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
