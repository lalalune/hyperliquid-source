//! Scalar value reconstruction of node94 ELF VA 0x565f670..0x565f6e7.
//! The original symbol, upper XMM lanes and caller ABI are not reconstructed.
#![no_std]
#![forbid(unsafe_code)]

const SIGN: u64 = 1 << 63;
const ONE: u64 = 0x3ff0_0000_0000_0000;

/// Binary64 ceiling with the captured leaf's signed-zero and NaN-bit policy.
/// Every input bit pattern is admitted, including signaling NaNs.
pub const fn ceil_bits(bits: u64) -> u64 {
    let exponent = (bits >> 52) & 0x7ff;
    if exponent >= 1075 {
        return bits;
    }
    if exponent < 1023 {
        return if bits == 0 {
            0
        } else if bits & SIGN != 0 {
            SIGN
        } else {
            ONE
        };
    }

    let unit = 1_u64 << (1075 - exponent);
    let fraction = bits & (unit - 1);
    let integral = bits & !(unit - 1);
    if bits & SIGN == 0 && fraction != 0 {
        integral + unit
    } else {
        integral
    }
}

/// The same scalar rule through Rust's binary64 type, without FP arithmetic.
pub const fn ceil(value: f64) -> f64 {
    f64::from_bits(ceil_bits(value.to_bits()))
}

#[cfg(test)]
mod tests {
    use super::{ceil, ceil_bits};

    #[test]
    fn predecessor_binary_grounded_examples() {
        let examples = include_str!("../../research/work-items/RE-001-ceil-f64-94/samples.tsv");
        let mut count = 0;
        for row in examples.lines().skip(1) {
            let mut fields = row.split('\t');
            let name = fields.next().unwrap();
            let input =
                u64::from_str_radix(fields.next().unwrap().trim_start_matches("0x"), 16).unwrap();
            let expected =
                u64::from_str_radix(fields.next().unwrap().trim_start_matches("0x"), 16).unwrap();
            assert_eq!(ceil_bits(input), expected, "{name}");
            assert_eq!(ceil(f64::from_bits(input)).to_bits(), expected, "{name}");
            count += 1;
        }
        assert_eq!(count, 16);
    }

    #[test]
    fn positive_and_negative_exact_integers_are_fixed_points() {
        for integer in -4096..=4096 {
            let value = f64::from(integer);
            assert_eq!(ceil(value).to_bits(), value.to_bits());
        }
    }
}
