//! Reconstructed input-acceptance predicates for two node #115 CLI validators.

pub const TARGET_SHA256: &str = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

/// The CLI's numeric validator accepts an optional leading `+`, then at least
/// one decimal digit, provided the value fits in an unsigned 64-bit integer.
/// It validates only; the target callback returns a unit-like success result.
pub fn accepts_u64_decimal(input: &[u8]) -> bool {
    let digits = match input.first() {
        Some(b'+') => &input[1..],
        _ => input,
    };
    if digits.is_empty() {
        return false;
    }
    let mut value = 0u64;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return false;
        }
        let digit = u64::from(byte - b'0');
        let Some(next) = value.checked_mul(10).and_then(|n| n.checked_add(digit)) else {
            return false;
        };
        value = next;
    }
    true
}

/// The observed Boolean callback admits only the exact lowercase ASCII words.
pub fn accepts_lowercase_bool(input: &[u8]) -> bool {
    matches!(input, b"true" | b"false")
}

#[cfg(test)]
mod tests {
    use super::{accepts_lowercase_bool, accepts_u64_decimal};

    #[test]
    fn checked_decimal_u64_boundaries() {
        for valid in [
            b"0".as_slice(),
            b"+0",
            b"+42",
            b"00042",
            b"18446744073709551615",
        ] {
            assert!(accepts_u64_decimal(valid), "{valid:?}");
        }
        for invalid in [
            b"".as_slice(),
            b"+",
            b"-1",
            b"18446744073709551616",
            b"1x",
            b" 1",
            b"1\n",
        ] {
            assert!(!accepts_u64_decimal(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn boolean_acceptance_is_exact_and_case_sensitive() {
        assert!(accepts_lowercase_bool(b"true"));
        assert!(accepts_lowercase_bool(b"false"));
        for invalid in [b"True".as_slice(), b"FALSE", b"1", b"", b"true "] {
            assert!(!accepts_lowercase_bool(invalid), "{invalid:?}");
        }
    }
}
