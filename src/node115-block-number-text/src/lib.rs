//! Source reconstruction of node115 0x143e0e0's string-to-number selector.
//! Input is already decoded string content; JSON and BlockId hash dispatch are
//! separate. In particular the BlockId caller diverts length-66 strings to a
//! hash parser before this function, which is intentionally not reproduced here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NumberSelector {
    pub raw_mode: u64,
    /// Native named variants do not give their second word semantic meaning.
    pub number: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Native outer result tag 7: no recognized name and no lowercase 0x prefix.
    Unrecognized,
    /// Native outer result tag 5, inner error byte 0.
    EmptyNumber,
    /// Native outer result tag 5, inner error byte 1.
    InvalidDigit,
    /// Native outer result tag 5, inner error byte 2.
    Overflow,
}
pub fn parse_number_text(text: &str) -> Result<NumberSelector, ParseError> {
    let named = match text {
        "latest" => Some(0),
        "finalized" => Some(1),
        "safe" => Some(2),
        "earliest" => Some(3),
        "pending" => Some(4),
        _ => None,
    };
    if let Some(raw_mode) = named {
        return Ok(NumberSelector {
            raw_mode,
            number: None,
        });
    }
    let digits = text.strip_prefix("0x").ok_or(ParseError::Unrecognized)?;
    if digits.is_empty() {
        return Err(ParseError::EmptyNumber);
    }
    let digits = digits.strip_prefix('+').unwrap_or(digits);
    if digits.is_empty() {
        return Err(ParseError::InvalidDigit);
    }
    let mut number = 0u64;
    for byte in digits.bytes() {
        // Invalid character wins even when the accumulated prefix cannot shift.
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(ParseError::InvalidDigit),
        };
        number = number
            .checked_mul(16)
            .and_then(|v| v.checked_add(u64::from(digit)))
            .ok_or(ParseError::Overflow)?;
    }
    Ok(NumberSelector {
        raw_mode: 5,
        number: Some(number),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn named_variants_have_target_tags() {
        for (name, tag) in [
            ("latest", 0),
            ("finalized", 1),
            ("safe", 2),
            ("earliest", 3),
            ("pending", 4),
        ] {
            assert_eq!(
                parse_number_text(name),
                Ok(NumberSelector {
                    raw_mode: tag,
                    number: None
                })
            );
            assert_eq!(
                parse_number_text(&name.to_uppercase()),
                Err(ParseError::Unrecognized)
            );
            assert_eq!(
                parse_number_text(&format!("{name} ")),
                Err(ParseError::Unrecognized)
            );
        }
    }
    #[test]
    fn numeric_matrix_has_no_fixed_digit_count() {
        for number in 0..=4096u64 {
            for spelling in [
                format!("0x{number:x}"),
                format!("0x+{number:X}"),
                format!("0x{number:032x}"),
            ] {
                assert_eq!(
                    parse_number_text(&spelling),
                    Ok(NumberSelector {
                        raw_mode: 5,
                        number: Some(number)
                    })
                );
            }
        }
    }
    #[test]
    fn numeric_boundaries_and_error_precedence() {
        assert_eq!(
            parse_number_text("0xffffFFFFFFFFffff").unwrap().number,
            Some(u64::MAX)
        );
        assert_eq!(
            parse_number_text("0x0000ffffffffffffffff").unwrap().number,
            Some(u64::MAX)
        );
        assert_eq!(
            parse_number_text("0x10000000000000000"),
            Err(ParseError::Overflow)
        );
        assert_eq!(
            parse_number_text("0x1000000000000000g"),
            Err(ParseError::InvalidDigit)
        );
        assert_eq!(
            parse_number_text("0x10000000000000000g"),
            Err(ParseError::Overflow)
        );
        assert_eq!(parse_number_text("0x"), Err(ParseError::EmptyNumber));
        for text in [
            "0x+", "0x-", "0x-1", "0x++1", "0x 1", "0x１", "0x1_0", "0x1\n",
        ] {
            assert_eq!(
                parse_number_text(text),
                Err(ParseError::InvalidDigit),
                "{text}"
            );
        }
        for text in ["", "0", "1", "0X1", "0x1 ".trim_start_matches('0')] {
            assert_eq!(parse_number_text(text), Err(ParseError::Unrecognized));
        }
    }
    #[test]
    fn direct_number_parser_is_not_block_id_hash_dispatch() {
        // 66 total bytes are routed to a different parser by the BlockId caller.
        let text = format!("0x{}1", "0".repeat(63));
        assert_eq!(text.len(), 66);
        assert_eq!(parse_number_text(&text).unwrap().number, Some(1));
    }
}
