//! Logical conversion of an already parsed, valid 96-bit decimal.
//! No string grammar, native layout or upstream action acceptance is modeled.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decimal96 {
    coefficient: u128,
    scale: u8,
    negative: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidScale;

impl Decimal96 {
    /// `low` and `high` are the coefficient's low 64 and high 32 bits.
    /// Valid decimal scales are 0 through 28. Rejection outside that domain is
    /// an adapter guard, not a reconstruction of malformed native flags.
    pub fn new(low: u64, high: u32, scale: u8, negative: bool) -> Result<Self, InvalidScale> {
        if scale > 28 {
            return Err(InvalidScale);
        }
        Ok(Self {
            coefficient: (u128::from(high) << 64) | u128::from(low),
            scale,
            negative,
        })
    }

    /// Preserve the selected native operation order, including its decimal
    /// rescaling step. This is not a single coefficient/divisor conversion.
    pub fn to_f64(self) -> f64 {
        if self.scale == 0 {
            let signed = if self.negative {
                -(self.coefficient as i128)
            } else {
                self.coefficient as i128
            };
            return signed as f64;
        }
        let divisor = 10_u128.pow(u32::from(self.scale));
        let quotient = self.coefficient / divisor;
        let remainder = self.coefficient % divisor;
        let fraction = (remainder as f64) / (divisor as f64);
        let mut value = quotient as f64;
        if fraction != 0.0 {
            value += fraction;
            let multiplier = power_ten(self.scale);
            let scaled = value * multiplier;
            // 0x63efe40 adds the immediately preceding binary64 value below
            // one half, then truncates. Inputs here are finite/nonnegative.
            let rounded = (scaled + f64::from_bits(0x3fdf_ffff_ffff_ffff)).trunc();
            value = rounded / multiplier;
        }
        if self.negative { -value } else { value }
    }
}

/// The same multiply/square order as the selected nonnegative powi helper.
fn power_ten(exponent: u8) -> f64 {
    let mut remaining = exponent;
    let mut base = 10.0_f64;
    let mut result = if remaining & 1 != 0 { base } else { 1.0 };
    remaining >>= 1;
    while remaining != 0 {
        base *= base;
        if remaining & 1 != 0 {
            result *= base;
        }
        remaining >>= 1;
    }
    result
}
