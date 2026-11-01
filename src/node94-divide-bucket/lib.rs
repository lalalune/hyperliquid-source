//! Returned bucket of node94 ELF VA 0x4f9eb10..0x4f9eb82.
#![no_std]
#![forbid(unsafe_code)]

const MAX_BUCKET: u32 = 6;

/// Project the target's zero-extended RAX result into Some(0..=6).
///
/// None is a new safe refusal for divisor zero: the captured DIV has no normal
/// return in that case. It does not represent a recovered target error value.
pub const fn bucket(dividend: u64, divisor: u64) -> Option<u8> {
    if divisor == 0 {
        return None;
    }
    let quotient = dividend / divisor;
    if quotient < 2 {
        return Some(0);
    }
    let logarithm = 63 - quotient.leading_zeros();
    let capped = if logarithm > MAX_BUCKET {
        MAX_BUCKET
    } else {
        logarithm
    };
    Some(capped as u8)
}

#[cfg(test)]
mod tests {
    use super::bucket;

    #[test]
    fn refusal_differs_from_zero_bucket() {
        for dividend in [0, 1, u64::MAX] {
            assert_eq!(bucket(dividend, 0), None);
        }
        assert_eq!(bucket(0, 1), Some(0));
        assert_eq!(bucket(1, 1), Some(0));
        assert_eq!(bucket(1, u64::MAX), Some(0));
    }

    #[test]
    fn thresholds_use_the_full_unsigned_quotient() {
        for power in 1..=6 {
            assert_eq!(bucket((1 << power) - 1, 1), Some(power - 1));
            assert_eq!(bucket(1 << power, 1), Some(power));
        }
        assert_eq!(bucket(u64::MAX, 1), Some(6));
        assert_eq!(bucket(1 << 63, u64::MAX), Some(0));
        assert_eq!(bucket(u64::MAX, 1 << 63), Some(0));
    }

    #[test]
    fn observed_caller_divisor() {
        assert_eq!(bucket(0x80000, 0x80000), Some(0));
        assert_eq!(bucket(0xfffff, 0x80000), Some(0));
        assert_eq!(bucket(0x100000, 0x80000), Some(1));
        assert_eq!(bucket(0x2000000, 0x80000), Some(6));
    }
}
