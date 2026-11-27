//! Token-decimals scaling helpers `0x434f660`, `0x434f790`, and `0x434f910`.
//!
//! Anchored to `research/work-items/exchange-token-decimal-scaling-115`
//! (12,000 byte-executed cases, 60/60 negative controls, 0 mismatches).

/// Maximum `u64` result accepted by `0x434f790` (`floor(2^64 / 100)`).
pub const PERCENT_DIV_BOUND: u64 = 0x028f_5c28_f5c2_8f5c;

/// Maximum `u64` result accepted by `0x434f910` (`floor(2^63 / 10)`).
pub const SIGNED_SCALER_BOUND: u64 = 0x0ccc_cccc_cccc_cccc;

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

impl U256 {
    fn checked_mul_u64(self, rhs: u64) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (slot, &limb) in out.iter_mut().zip(self.0.iter()) {
            let v = u128::from(limb) * u128::from(rhs) + carry;
            *slot = v as u64;
            carry = v >> 64;
        }
        if carry != 0 {
            None
        } else {
            Some(Self(out))
        }
    }

    fn div_u64(self, rhs: u64) -> Self {
        let mut out = [0u64; 4];
        let mut rem = 0u128;
        for (slot, &limb) in out.iter_mut().zip(self.0.iter()).rev() {
            let cur = (rem << 64) | u128::from(limb);
            *slot = (cur / u128::from(rhs)) as u64;
            rem = cur % u128::from(rhs);
        }
        Self(out)
    }

    fn fits_below_bound(self, bound: u64) -> Option<u64> {
        if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 && self.0[0] < bound {
            Some(self.0[0])
        } else {
            None
        }
    }
}

/// Reconstructs `0x434f910`: signed-exponent 256-bit scaler.
///
/// - `exp < 0`: multiplies by `10^(-exp)` (leaves `value` untouched on overflow).
/// - `exp >= 0`: divides `value` in place by `10^exp` (even if the final bound check refuses).
/// - Rejects `|exp| >= 20` (including `-128`) and results `>= SIGNED_SCALER_BOUND`.
pub fn signed_exponent_scale_u256(exp: i8, value: &mut U256) -> Option<u64> {
    let mag = exp.unsigned_abs();
    if mag >= 20 {
        return None;
    }
    let factor = 10u64.pow(u32::from(mag));
    if exp < 0 {
        let scaled = value.checked_mul_u64(factor)?;
        *value = scaled;
        scaled.fits_below_bound(SIGNED_SCALER_BOUND)
    } else {
        let quot = value.div_u64(factor);
        *value = quot;
        quot.fits_below_bound(SIGNED_SCALER_BOUND)
    }
}
