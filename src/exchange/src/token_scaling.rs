//! Token-decimals scaling helpers `0x434f660`, `0x434f790`, and `0x434f910`.
//!
//! Anchored to `research/work-items/exchange-token-decimal-scaling-115`
//! (12,000 byte-executed cases, 60/60 negative controls, 0 mismatches).

/// Maximum `u64` result accepted by `0x434f790` (`floor(2^64 / 100)`).
pub const PERCENT_DIV_BOUND: u64 = 0x028f_5c28_f5c2_8f5c;

pub use node115_u256_decimal_scale::SIGNED_SCALER_BOUND;

/// Minimal token decimals metadata (`+0x48` sz_decimals, `+0x49` wei_decimals).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenDecimals {
    pub sz_decimals: u8,
    pub wei_decimals: u8,
}

/// Panic / refusal errors of the token-decimals scaling family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalingError {
    /// `token_index >= tokens.len()` (`spot_meta.rs:119:33`).
    TokenIndexOutOfBounds { index: usize, len: usize },
    /// `wei_decimals < sz_decimals` or `diff >= 20` (`spot_meta.rs:1206:57`).
    InvalidDecimalDifference,
}

/// Computes `10^(wei_decimals - sz_decimals)` matching `0x434f660` / `0x434f790`.
pub fn token_scale(tokens: &[TokenDecimals], token_index: usize) -> Result<u64, ScalingError> {
    let row = tokens
        .get(token_index)
        .ok_or(ScalingError::TokenIndexOutOfBounds {
            index: token_index,
            len: tokens.len(),
        })?;
    let diff = row
        .wei_decimals
        .checked_sub(row.sz_decimals)
        .ok_or(ScalingError::InvalidDecimalDifference)?;
    if diff >= 20 {
        return Err(ScalingError::InvalidDecimalDifference);
    }
    Ok(10u64.pow(u32::from(diff)))
}

/// Reconstructs `0x434f660`: `a * b / 10^d` with token-0 shortcut (scale = 1,
/// skipping token lookup) and divide-first fallback `(a / scale) * b` on u64 overflow.
///
/// Returns `Ok(Some(value))` on success, `Ok(None)` when the divide-first fallback
/// still overflows `u64`, and `Err` on bounds/decimals panic.
pub fn scaled_mul_div(
    a: u64,
    token_index: usize,
    b: u64,
    tokens: &[TokenDecimals],
) -> Result<Option<u64>, ScalingError> {
    let scale = if token_index == 0 {
        1u64
    } else {
        token_scale(tokens, token_index)?
    };
    if let Some(prod) = a.checked_mul(b) {
        Ok(Some(prod / scale))
    } else {
        Ok((a / scale).checked_mul(b))
    }
}

/// Reconstructs `0x434f790`: `(a * b) / (scale * 100)` using 128-bit division,
/// optional round-up when `round_up && rem != 0`, requiring result `< PERCENT_DIV_BOUND`.
///
/// Note: unlike `0x434f660`, `0x434f790` does NOT skip token lookup for index 0.
pub fn scaled_percent_div(
    a: u64,
    token_index: usize,
    b: u64,
    round_up: bool,
    tokens: &[TokenDecimals],
) -> Result<Option<u64>, ScalingError> {
    let scale = token_scale(tokens, token_index)?;
    let prod = u128::from(a) * u128::from(b);
    let denom = u128::from(scale) * 100u128;
    let mut q = prod / denom;
    let r = prod % denom;
    if round_up && r != 0 {
        q += 1;
    }
    if q < u128::from(PERCENT_DIV_BOUND) {
        Ok(Some(q as u64))
    } else {
        Ok(None)
    }
}

/// Little-endian 256-bit unsigned integer (`[u64; 4]`) used by `0x434f910`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U256(pub [u64; 4]);

/// Reconstructs `0x434f910` through the shared four-limb scaler.
/// Negative exponents multiply a copy. Nonnegative exponents write the
/// quotient back before checking the exclusive amount bound.
pub fn signed_exponent_scale_u256(exp: i8, value: &mut U256) -> Option<u64> {
    node115_u256_decimal_scale::scale_amount(&mut value.0, exp)
}
