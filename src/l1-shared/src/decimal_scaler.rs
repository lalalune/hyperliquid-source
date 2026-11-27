//! 96-bit decimal scaler (`0x421e9d0`), price/size wrappers (`w1..w5`), and
//! f64-to-decimal converter (`0x5c43c60` / `0x43099f0`).
//!
//! Anchored to node #115 evidence packets:
//! - `research/work-items/l1-shared-decimal-amount-scaler-115`
//! - `research/work-items/l1-shared-amount-wrappers-115`
//! - `research/work-items/l1-shared-f64-to-decimal-115`

/// Maximum 96-bit unsigned magnitude (`2^96 - 1`).
pub const MAX_MANTISSA_96: u128 = (1u128 << 96) - 1;

/// Maximum scale accepted by `rust_decimal`-style 96-bit decimals.
pub const MAX_SCALE: u8 = 28;

/// Maximum scaled `u64` result accepted by `0x421e9d0` (`0x7fff_ffff_ffff_fffe`).
pub const MAX_SCALED_U64: u64 = 0x7fff_ffff_ffff_fffe;

/// Observed result tags in `0x421e9d0`, `w1..w5`, and `0x43099f0`.
pub const TAG_OK: u16 = 0x1a2;
pub const TAG_SCALER_REFUSED: u16 = 0xac;
pub const TAG_WRAPPER_REFUSED: u16 = 0xad;
pub const TAG_F64_PARSE_REFUSED: u16 = 0xb0;

/// Canonical 96-bit decimal (`sign`, `scale 0..=28`, `96-bit mantissa`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decimal96 {
    pub negative: bool,
    pub scale: u8,
    pub mantissa: u128,
}

impl Decimal96 {
    pub const ZERO: Self = Self {
        negative: false,
        scale: 0,
        mantissa: 0,
    };

    pub fn new(negative: bool, scale: u8, mantissa: u128) -> Option<Self> {
        if scale > MAX_SCALE || mantissa > MAX_MANTISSA_96 {
            return None;
        }
        Some(Self {
            negative,
            scale,
            mantissa,
        })
    }

    /// Packs the 32-bit flags word (`scale << 16 | (negative << 31)`).
    pub const fn flags(self) -> u32 {
        ((self.scale as u32) << 16) | if self.negative { 0x8000_0000 } else { 0 }
    }
}

/// Rounding mode byte (`dl`) passed to `0x421e9d0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalerMode {
    /// Mode `0`: exact integer required after `× 10^digits` (no rounding).
    Exact,
    /// Mode `1`: half-to-even rounding accepted only when `|x - round(x)| < 0.001`.
    Tolerant,
    /// Mode `>= 2`: always round half-to-even to integer.
    RoundHalfEven,
}

impl ScalerMode {
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Exact,
            1 => Self::Tolerant,
            _ => Self::RoundHalfEven,
        }
    }
}

/// Output of [`scale_decimal_to_u64`] (`0x421e9d0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalerOutput {
    pub value: u64,
    /// True when mode 1 (`Tolerant`) rounded a non-zero fractional part `< 0.001`
    /// and therefore touched the lazy global at `0x421eb74`.
    pub touched_lazy_global: bool,
}

/// Pow10 helper for `0..=28` in `u128`.
fn pow10_u128(exp: u8) -> u128 {
    10u128.pow(u32::from(exp))
}

/// Half-to-even rounding of `mantissa / 10^scale` to an integer `u128`.
fn round_half_even_integer(mantissa: u128, scale: u8) -> u128 {
    if scale == 0 {
        return mantissa;
    }
    let div = pow10_u128(scale);
    let q = mantissa / div;
    let r = mantissa % div;
    let half = div / 2;
    if r > half || (r == half && (q & 1) == 1) {
        q + 1
    } else {
        q
    }
}

/// Reconstructs node #115's decimal-to-u64 amount scaler `0x421e9d0`.
///
/// Refusal returns `Err(TAG_SCALER_REFUSED)` (`0xac`).
pub fn scale_decimal_to_u64(
    dec: Decimal96,
    mode: ScalerMode,
    digits: u8,
) -> Result<ScalerOutput, u16> {
    if dec.scale > MAX_SCALE || dec.mantissa > MAX_MANTISSA_96 || digits > 19 {
        return Err(TAG_SCALER_REFUSED);
    }
    // Step 1: 10^digits fits in u64 for digits <= 19.
    let mult = pow10_u128(digits);

    // Step 2: multiply by 10^digits; zero collapses to (+0, scale=0).
    let (mut negative, mut scale, mut mantissa) = if dec.mantissa == 0 {
        (false, 0u8, 0u128)
    } else {
        let mut s = dec.scale;
        let prod = dec.mantissa.checked_mul(mult);
        // If mantissa * 10^digits overflows 96 bits, reduce scale by whole powers of 10
        // (exact because the multiplier is 10^digits).
        match prod {
            Some(v) if v <= MAX_MANTISSA_96 => (dec.negative, s, v),
            _ => {
                let mut rem_digits = digits;
                while rem_digits > 0 && s > 0 {
                    s -= 1;
                    rem_digits -= 1;
                }
                let p = dec
                    .mantissa
                    .checked_mul(pow10_u128(rem_digits))
                    .ok_or(TAG_SCALER_REFUSED)?;
                if p > MAX_MANTISSA_96 {
                    return Err(TAG_SCALER_REFUSED);
                }
                (dec.negative, s, p)
            }
        }
    };

    // Step 3: mode-dependent integer rounding.
    let mut touched_lazy_global = false;
    match mode {
        ScalerMode::Exact => {}
        ScalerMode::Tolerant => {
            if scale > 0 {
                let rounded = round_half_even_integer(mantissa, scale);
                let div = pow10_u128(scale);
                let rounded_scaled = rounded * div;
                let diff = mantissa.abs_diff(rounded_scaled);
                // Strictly below 0.001 <=> diff * 1000 < div.
                if diff * 1000 < div {
                    if diff != 0 {
                        touched_lazy_global = true;
                    }
                    mantissa = rounded;
                    scale = 0;
                    if mantissa == 0 {
                        negative = false;
                    }
                }
            }
        }
        ScalerMode::RoundHalfEven => {
            if scale > 0 {
                mantissa = round_half_even_integer(mantissa, scale);
                scale = 0;
                if mantissa == 0 {
                    negative = false;
                }
            }
        }
    }

    // Step 4: fractional part must be zero, sign must be non-negative, value <= MAX_SCALED_U64.
    let div = pow10_u128(scale);
    if mantissa % div != 0 {
        return Err(TAG_SCALER_REFUSED);
    }
    if negative && mantissa != 0 {
        return Err(TAG_SCALER_REFUSED);
    }
    let integer = mantissa / div;
    if integer > u128::from(MAX_SCALED_U64) {
        return Err(TAG_SCALER_REFUSED);
    }

    Ok(ScalerOutput {
        value: integer as u64,
        touched_lazy_global,
    })
}

/// Wrapper `w1` (`0x46aa250`): mode 2, constant 6 digits, tag `0xac` passed through.
pub fn scale_usdc_w1(dec: Decimal96) -> Result<u64, u16> {
    scale_decimal_to_u64(dec, ScalerMode::RoundHalfEven, 6).map(|o| o.value)
}

/// Wrapper `w2` (`0x274b760` / `0x57c70c0`): mode 2, caller-supplied digits,
/// folding zero and any scaler error into tag `0xad` ([`TAG_WRAPPER_REFUSED`]).
pub fn scale_nonzero_w2(dec: Decimal96, digits: u8) -> Result<u64, u16> {
    match scale_decimal_to_u64(dec, ScalerMode::RoundHalfEven, digits) {
        Ok(out) if out.value != 0 => Ok(out.value),
        _ => Err(TAG_WRAPPER_REFUSED),
    }
}

/// Wrapper `w4` (`0x3be28a0` / `0x5a00cc0`): derives `digits = 6 - sz_decimals`
/// (returning `None` where the native wrapper panics on `sz_decimals > 6`),
/// then applies [`scale_nonzero_w2`].
pub fn scale_perp_w4(dec: Decimal96, sz_decimals: u8) -> Option<Result<u64, u16>> {
    let digits = 6u8.checked_sub(sz_decimals)?;
    Some(scale_nonzero_w2(dec, digits))
}

/// Wrapper `w3` (`0x2891af0` / `0x5a00b00`): derives `digits = quote_wei_dec - base_sz_dec`
/// (returning `None` on borrow panic), then applies [`scale_nonzero_w2`].
pub fn scale_spot_w3(
    dec: Decimal96,
    base_sz_decimals: u8,
    quote_wei_decimals: u8,
) -> Option<Result<u64, u16>> {
    let digits = quote_wei_decimals.checked_sub(base_sz_decimals)?;
    Some(scale_nonzero_w2(dec, digits))
}

/// Reconstructs node #115's binary-exponent-to-decimal converter `0x5c43c60`.
pub fn decimal_from_binary_exp(
    mut mantissa: u128,
    exp2: i32,
    positive: bool,
    f64_mode: bool,
    round: bool,
) -> Option<Decimal96> {
    if mantissa > MAX_MANTISSA_96 {
        return None;
    }
    let mut exp10: i32 = exp2;

    if exp2 > 0 {
        for _ in 0..exp2 {
            if (mantissa & (1u128 << 95)) != 0 {
                mantissa /= 5;
            } else {
                mantissa = (mantissa << 1) & MAX_MANTISSA_96;
                exp10 -= 1;
            }
        }
        if exp10 > 0 {
            for _ in 0..exp10 {
                mantissa = mantissa.checked_mul(10)?;
                if mantissa > MAX_MANTISSA_96 {
                    return None;
                }
            }
            exp10 = 0;
        }
    } else if exp2 < 0 {
        for _ in 0..(-exp2) {
            if (mantissa & 1) == 1 && mantissa <= MAX_MANTISSA_96 / 5 {
                mantissa *= 5;
            } else {
                mantissa >>= 1;
                exp10 += 1;
            }
        }
    }

    // Clamp scale to <= 28 using round-half-up (remainder > 4).
    if exp10 < -i32::from(MAX_SCALE) {
        let mut left = -(exp10 + i32::from(MAX_SCALE));
        let mut underflowed = false;
        while left > 0 {
            if mantissa < 10 {
                mantissa = 0;
                exp10 = 0;
                underflowed = true;
                break;
            }
            let rem = mantissa % 10;
            mantissa /= 10;
            if rem > 4 {
                mantissa += 1;
            }
            left -= 1;
        }
        if !underflowed {
            exp10 = -i32::from(MAX_SCALE);
        }
    }

    // Significant-digit trim when exp10 < 0 and round is enabled.
    let limit = if f64_mode { 1u128 << 52 } else { 1u128 << 24 };
    if round && exp10 < 0 {
        while exp10 < 0 {
            if mantissa >= limit {
                let rem = mantissa % 10;
                mantissa /= 10;
                if rem > 4 {
                    mantissa += 1;
                }
                exp10 += 1;
                continue;
            }
            while exp10 < 0 && mantissa.is_multiple_of(10) {
                mantissa /= 10;
                exp10 += 1;
            }
            break;
        }
    }

    if exp10 >= 0 {
        exp10 = 0;
    }
    if mantissa > MAX_MANTISSA_96 || -exp10 > i32::from(MAX_SCALE) {
        return None;
    }
    Some(Decimal96 {
        negative: !positive,
        scale: (-exp10) as u8,
        mantissa,
    })
}

/// Reconstructs node #115's `f64` caller `0x43099f0` (with `f64_mode = true, round = true`).
pub fn decimal_from_f64(value: f64) -> Result<Decimal96, u16> {
    let bits = value.to_bits();
    if (bits & 0x7fff_ffff_ffff_ffff) >= 0x7ff0_0000_0000_0000 {
        return Err(TAG_F64_PARSE_REFUSED);
    }
    let positive = (bits as i64) >= 0;
    if (bits & 0x7fff_ffff_ffff_ffff) == 0 {
        return Ok(Decimal96 {
            negative: !positive,
            scale: 0,
            mantissa: 0,
        });
    }
    let biased = ((bits >> 52) & 0x7ff) as i32;
    let frac = bits & 0x000f_ffff_ffff_ffff;
    let (mantissa, exp2) = if biased == 0 {
        (u128::from(frac), -1074)
    } else {
        (u128::from(frac | (1u64 << 52)), biased - 1075)
    };
    decimal_from_binary_exp(mantissa, exp2, positive, true, true).ok_or(TAG_F64_PARSE_REFUSED)
}
