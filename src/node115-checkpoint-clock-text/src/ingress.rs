use node115_time_producer::{DateTime, from_ce_day};

const DECODED_SIZE: usize = 0x27a8;

fn digits(bytes: &[u8]) -> Option<u32> {
    let mut result = 0;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        result = result * 10 + u32::from(byte - b'0');
    }
    Some(result)
}

/// Parse the selected checkpoint calendar spelling for positive four-digit years.
///
/// The date word is produced by the reconstructed CE-day constructor. The
/// second-60 representation uses the preceding second with a one-billion
/// nanosecond bias. Optional fractions preserve up to nine decimal digits.
pub fn parse_checkpoint_clock(text: &str) -> Option<DateTime> {
    let bytes = text.as_bytes();
    let base = bytes.get(..19)?;
    if base[4] != b'-'
        || base[7] != b'-'
        || base[10] != b'T'
        || base[13] != b':'
        || base[16] != b':'
    {
        return None;
    }
    let year = digits(&base[..4])?;
    let month = digits(&base[5..7])?;
    let day = digits(&base[8..10])?;
    let hour = digits(&base[11..13])?;
    let minute = digits(&base[14..16])?;
    let second = digits(&base[17..19])?;
    if year == 0 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let months = [
        31,
        28 + u32::from(leap),
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
    let month_index = (month - 1) as usize;
    if day == 0 || day > months[month_index] {
        return None;
    }
    let ordinal = months[..month_index].iter().sum::<u32>() + day;
    let prior = year - 1;
    let ce_day = prior * 365 + prior / 4 - prior / 100 + prior / 400 + ordinal;
    let date = from_ce_day(ce_day as i32)?;

    let fraction = match &bytes[19..] {
        [] => 0,
        [b'.', tail @ ..] if (1..=9).contains(&tail.len()) => {
            digits(tail)? * 10_u32.pow(9 - tail.len() as u32)
        }
        _ => return None,
    };
    Some(DateTime {
        date,
        seconds_of_day: hour * 3600 + minute * 60 + second.min(59),
        nanoseconds: fraction + u32::from(second == 60) * 1_000_000_000,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockIngressError {
    WrongSize { actual: usize },
    HeightMismatch { expected: u64, actual: u64 },
    CurrentClock,
    PreviousClock,
}

/// Stage the two clock words into a caller-pinned decoded checkpoint fixture.
/// This validates both clock texts before writing either field.
pub fn stage_decoded_clock_pair(
    image: &mut [u8],
    height: u64,
    current: &str,
    previous: &str,
) -> Result<(), ClockIngressError> {
    if image.len() != DECODED_SIZE {
        return Err(ClockIngressError::WrongSize {
            actual: image.len(),
        });
    }
    let actual = u64::from_le_bytes(image[0x28..0x30].try_into().unwrap());
    if actual != height {
        return Err(ClockIngressError::HeightMismatch {
            expected: height,
            actual,
        });
    }
    let current = parse_checkpoint_clock(current).ok_or(ClockIngressError::CurrentClock)?;
    let previous = parse_checkpoint_clock(previous).ok_or(ClockIngressError::PreviousClock)?;
    for (time, region) in [current, previous]
        .into_iter()
        .zip(image[0x60..0x78].chunks_exact_mut(12))
    {
        region[..4].copy_from_slice(&(time.date.packed as u32).to_le_bytes());
        region[4..8].copy_from_slice(&time.seconds_of_day.to_le_bytes());
        region[8..].copy_from_slice(&time.nanoseconds.to_le_bytes());
    }
    Ok(())
}
