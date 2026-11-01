#![no_std]
#![forbid(unsafe_code)]
//! Full-RAX projection of node94 [0x1683670, 0x16836c5).

/// A new safe refusal, distinct from the original parser's zero result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TooShort;

/// Return full RAX for an explicit native length and a supplied byte prefix.
///
/// Lengths other than three return zero without requiring any bytes. Length
/// three requires the complete first three bytes, even when the first byte is
/// invalid. Additional supplied bytes are ignored. Original pointer/ABI, faults,
/// flags, other registers and physical access traces are not projected.
pub fn parse(length: u64, bytes: &[u8]) -> Result<u64, TooShort> {
    if length != 3 {
        return Ok(0);
    }
    let triple = bytes.get(..3).ok_or(TooShort)?;
    let (a, b, c) = (triple[0], triple[1], triple[2]);
    if !(b'1'..=b'9').contains(&a) || !b.is_ascii_digit() || !c.is_ascii_digit() {
        return Ok(0);
    }
    let hundreds = u64::from(a.wrapping_sub(b'0'));
    let tens = u64::from(b.wrapping_sub(b'0'));
    let ones = u64::from(c.wrapping_sub(b'0'));
    Ok(hundreds * 100 + tens * 10 + ones)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_and_all_valid_endpoints() {
        assert_eq!(parse(3, b"100"), Ok(100));
        assert_eq!(parse(3, b"999"), Ok(999));
        assert_eq!(parse(3, b"012"), Ok(0));
        assert_eq!(parse(3, b"1:3"), Ok(0));
    }

    #[test]
    fn full_width_length_skips_all_bytes() {
        assert_eq!(parse(0, &[]), Ok(0));
        assert_eq!(parse((1 << 32) | 3, &[]), Ok(0));
        assert_eq!(parse(u64::MAX, b"123"), Ok(0));
    }

    #[test]
    fn complete_required_prefix_precedes_digit_rejection() {
        assert_eq!(parse(3, b"x"), Err(TooShort));
        assert_eq!(parse(3, b"123ignored"), Ok(123));
    }
}
