//! Four-limb decimal conversion at node 115 VA 0x434f910.

/// Exclusive upper bound for a representable native amount (floor of 2^63 / 10).
pub const SIGNED_SCALER_BOUND: u64 = 0x0ccc_cccc_cccc_cccc;

/// Returns the native optional amount. The input is four little-endian u64
/// limbs. Division writes the quotient back even if narrowing then refuses it.
/// Multiplication works on a copy, including on success.
pub fn scale_amount(input: &mut [u64; 4], exponent: i8) -> Option<u64> {
    let factor = 10_u64.checked_pow(u32::from(exponent.unsigned_abs()))?;
    let scaled = if exponent < 0 {
        let mut product = *input;
        let mut carry = 0_u128;
        for limb in &mut product {
            let wide = u128::from(*limb) * u128::from(factor) + carry;
            *limb = wide as u64;
            carry = wide >> 64;
        }
        if carry != 0 {
            return None;
        }
        product
    } else {
        let mut remainder = 0_u128;
        for limb in input.iter_mut().rev() {
            let dividend = (remainder << 64) | u128::from(*limb);
            *limb = (dividend / u128::from(factor)) as u64;
            remainder = dividend % u128::from(factor);
        }
        *input
    };
    let [amount, 0, 0, 0] = scaled else {
        return None;
    };
    (amount < SIGNED_SCALER_BOUND).then_some(amount)
}
