#![no_std]
//! Value projection of the complete node94 decimal parser 0x54307c0..0x5430857.
//!
//! Input is the logical concatenation of `leading_zeroes` ASCII zero bytes and
//! `tail`. The prefix is compressed, not allocated. Ordinary byte strings use
//! a zero prefix count. Input, cursor record and output slot do not alias.
//! Native pointer validity, address wrap, faults and concurrent mutation are
//! excluded; consumed/remaining describe cursor effects without native pointers.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Projection {
    pub rax: u64,
    pub consumed: u64,
    pub remaining: u64,
    pub output: u64,
    pub output_written: bool,
}

/// New API refusal: the logical input length cannot be represented by u64.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LengthOverflow;

/// Parse a decimal prefix, preserving raw RAX, cursor and output-store effects.
/// Numeric overflow is an original parser outcome (RAX=0, no output write),
/// distinct from LengthOverflow. The failing digit remains unconsumed.
/// Nondigit termination uses signed low32 digit count and replaces only AL in
/// the sign-extended stopping byte's EAX. End-of-input always returns RAX=1
/// after any digits, even when that count's signed low32 would be nonpositive.
pub fn parse(
    leading_zeroes: u64,
    tail: &[u8],
    previous_output: u64,
) -> Result<Projection, LengthOverflow> {
    let total = u64::try_from(tail.len())
        .ok()
        .and_then(|length| leading_zeroes.checked_add(length))
        .ok_or(LengthOverflow)?;
    let mut value = 0_u64;
    let mut consumed = leading_zeroes;
    let mut digits = leading_zeroes as u32;
    for &byte in tail {
        if !byte.is_ascii_digit() {
            let signed_byte = i32::from(byte as i8) as u32;
            let accepted = (digits as i32) > 0;
            return Ok(Projection {
                rax: u64::from(signed_byte & 0xffff_ff00) | u64::from(accepted),
                consumed,
                remaining: total - consumed,
                output: value,
                output_written: true,
            });
        }
        digits = digits.wrapping_add(1);
        let digit = u64::from(byte - b'0');
        if value > u64::MAX / 10 || (value == u64::MAX / 10 && digit > 5) {
            return Ok(Projection {
                rax: 0,
                consumed,
                remaining: total - consumed,
                output: previous_output,
                output_written: false,
            });
        }
        value = value * 10 + digit;
        consumed += 1;
    }
    Ok(Projection {
        rax: u64::from(total != 0),
        consumed,
        remaining: 0,
        output: value,
        output_written: true,
    })
}
