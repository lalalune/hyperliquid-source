#![no_std]

//! Safe logical projection of the node #115 leaf at `0x179b360`.
//!
//! The original source name, Rust signature, and caller-level meaning are
//! unknown. The evidence packet records the target-bound instruction proof.

/// Returns the value encoded by exactly three ASCII decimal digits, or zero.
///
/// The first digit must be `1` through `9`; the other two must be `0` through
/// `9`. Any other slice length or byte sequence returns zero. This describes
/// the observed value relation, not the original function ABI.
pub fn parse_three_digit_ascii(input: &[u8]) -> u32 {
    if input.len() != 3 {
        return 0;
    }

    let first = input[0];
    let second = input[1];
    let third = input[2];
    if !(b'1'..=b'9').contains(&first) || !second.is_ascii_digit() || !third.is_ascii_digit() {
        return 0;
    }

    u32::from(first - b'0') * 100 + u32::from(second - b'0') * 10 + u32::from(third - b'0')
}

#[cfg(test)]
mod tests {
    use super::parse_three_digit_ascii;

    #[test]
    fn accepts_every_three_digit_decimal_value() {
        for value in 100u32..=999u32 {
            let bytes = [
                b'0' + (value / 100) as u8,
                b'0' + ((value / 10) % 10) as u8,
                b'0' + (value % 10) as u8,
            ];
            assert_eq!(parse_three_digit_ascii(&bytes), value);
        }
    }

    #[test]
    fn rejects_non_three_byte_lengths() {
        for length in [0, 1, 2, 4, 32] {
            let input = [b'7'; 32];
            assert_eq!(parse_three_digit_ascii(&input[..length]), 0);
        }
    }

    #[test]
    fn matches_the_instruction_derived_relation_for_every_byte_triple() {
        for first in u8::MIN..=u8::MAX {
            for second in u8::MIN..=u8::MAX {
                for third in u8::MIN..=u8::MAX {
                    let expected = if (b'1'..=b'9').contains(&first)
                        && second.is_ascii_digit()
                        && third.is_ascii_digit()
                    {
                        u32::from(first - b'0') * 100
                            + u32::from(second - b'0') * 10
                            + u32::from(third - b'0')
                    } else {
                        0
                    };
                    assert_eq!(parse_three_digit_ascii(&[first, second, third]), expected);
                }
            }
        }
    }
}
