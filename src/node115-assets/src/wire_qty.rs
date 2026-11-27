//! Wire quantity & Decimal96 normalization helpers grounded in node #115
//! (`l1/src/wire_qty.rs:29` at `0x41c57f0`, `RE-004-node115-decimal96-normalize`).

/// Normalized 96-bit decimal representation matching `node115-decimal96-normalize`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NormalizedDecimal96 {
    pub coefficient: u128,
    pub flags: u32,
}

impl NormalizedDecimal96 {
    /// Four 32-bit words in `#115` stack order (`+b8, +bc, +c0, +c4`).
    #[inline]
    pub const fn observed_words(self) -> [u32; 4] {
        [
            self.flags,
            (self.coefficient >> 64) as u32,
            self.coefficient as u32,
            (self.coefficient >> 32) as u32,
        ]
    }
}

/// Normalize a 96-bit decimal coefficient and raw flags word per `#115` `0x41c57f0`:
/// - zero coefficient clears all flags;
/// - zero initial scale preserves raw flags unchanged;
/// - otherwise strips trailing factors of 10 up to `scale` and keeps only sign bit (`0x8000_0000`)
///   and remaining `scale << 16`.
#[inline]
pub fn normalize_decimal96_parts(lo: u32, mid: u32, hi: u32, flags: u32) -> NormalizedDecimal96 {
    let mut coefficient = (u128::from(hi) << 64) | (u128::from(mid) << 32) | u128::from(lo);
    if coefficient == 0 {
        return NormalizedDecimal96 {
            coefficient: 0,
            flags: 0,
        };
    }
    let mut scale = (flags >> 16) & 0xff;
    if scale == 0 {
        return NormalizedDecimal96 { coefficient, flags };
    }
    while scale > 0 && coefficient % 10 == 0 {
        coefficient /= 10;
        scale -= 1;
    }
    NormalizedDecimal96 {
        coefficient,
        flags: (flags & 0x8000_0000) | (scale << 16),
    }
}

/// Format a non-negative scaled integer into canonical trimmed wire decimal text
/// (matching `wire_qty.rs` stripped trailing fractional zeros).
pub fn format_wire_decimal(raw: u64, scale: u8) -> String {
    if raw == 0 || scale == 0 {
        return raw.to_string();
    }
    let pow10 = 10_u128.pow(u32::from(scale));
    let whole = u128::from(raw) / pow10;
    let frac = u128::from(raw) % pow10;
    if frac == 0 {
        return whole.to_string();
    }
    let mut frac_str = format!("{frac:0width$}", width = usize::from(scale));
    while frac_str.ends_with('0') {
        frac_str.pop();
    }
    format!("{whole}.{frac_str}")
}
