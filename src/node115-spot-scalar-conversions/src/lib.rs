//! Two node 115 scalar conversions using the spot metadata decimal difference.

#[derive(Clone, Copy, Debug)]
pub struct Decimals {
    /// Bytes +0x48 and +0x49 of the 0x158-byte metadata row.
    pub field_48: u8,
    pub field_49: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    PairIndex,
    TokenIndex,
    DecimalScale,
}

pub struct Metadata<'a> {
    /// Token selector at +8 of each 32-byte pair record.
    pub pair_tokens: &'a [u64],
    pub tokens: &'a [Decimals],
}

impl Metadata<'_> {
    fn factor(&self, token: u64) -> Result<u64, Stop> {
        let row = usize::try_from(token)
            .ok()
            .and_then(|index| self.tokens.get(index))
            .ok_or(Stop::TokenIndex)?;
        let exponent = row
            .field_49
            .checked_sub(row.field_48)
            .ok_or(Stop::DecimalScale)?;
        10_u64
            .checked_pow(u32::from(exponent))
            .ok_or(Stop::DecimalScale)
    }

    /// 0x46aa2e0. The zero quotient becomes one after a successful calculation.
    /// A zero divisor or overflowing fallback product returns zero.
    pub fn scaled_ratio(&self, value: u64, token: u64, divisor: u64) -> Result<u64, Stop> {
        let factor = self.factor(token)?;
        if divisor == 0 {
            return Ok(0);
        }
        let quotient = if let Some(product) = value.checked_mul(factor) {
            product / divisor
        } else {
            let Some(product) = (value / divisor).checked_mul(factor) else {
                return Ok(0);
            };
            product
        };
        Ok(quotient.max(1))
    }

    /// 0x3c201e0. On product overflow the native path tries exact cancellation
    /// in operand order, then truncates the larger operand before multiplying.
    pub fn unscale_product(&self, lhs: u64, rhs: u64, pair: u64) -> Result<u64, Stop> {
        let token = usize::try_from(pair)
            .ok()
            .and_then(|index| self.pair_tokens.get(index))
            .ok_or(Stop::PairIndex)?;
        let factor = self.factor(*token)?;
        if let Some(product) = lhs.checked_mul(rhs) {
            return Ok(product / factor);
        }
        let (divide, other) = if lhs.is_multiple_of(factor) {
            (lhs, rhs)
        } else if rhs.is_multiple_of(factor) {
            (rhs, lhs)
        } else {
            (lhs.max(rhs), lhs.min(rhs))
        };
        Ok((divide / factor).checked_mul(other).unwrap_or(0))
    }
}
