#![no_std]
#![forbid(unsafe_code)]
//! Safe decimal-scaling gate recovered from node115 slot 0x64e71b8.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScaleError {
    IndexOutOfRange,
    Scale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GateResult {
    pub admitted: bool,
    pub quotient: u64,
}

pub fn checked_scale_gate(
    left: u64,
    right: u64,
    index: u64,
    records: &[(u8, u8)],
    round_up: bool,
) -> Result<GateResult, ScaleError> {
    let &(before, after) = records
        .get(index as usize)
        .ok_or(ScaleError::IndexOutOfRange)?;
    if after < before || after - before > 19 {
        return Err(ScaleError::Scale);
    }
    let scale = 10u128.pow(u32::from(after - before));
    let denominator = 100 * scale;
    let product = u128::from(left) * u128::from(right);
    let mut quotient = product / denominator;
    if round_up && product % denominator != 0 {
        quotient += 1;
    }
    let quotient = u64::try_from(quotient).unwrap_or(u64::MAX);
    Ok(GateResult {
        admitted: quotient < (u64::MAX / 100),
        quotient,
    })
}

#[cfg(test)]
mod tests {
    use super::{GateResult, ScaleError, checked_scale_gate};

    #[test]
    fn scale_and_rounding_boundaries() {
        assert_eq!(
            checked_scale_gate(1, 100, 0, &[(2, 4)], false),
            Ok(GateResult {
                admitted: true,
                quotient: 0,
            })
        );
        assert_eq!(
            checked_scale_gate(1, 101, 0, &[(2, 4)], false),
            Ok(GateResult {
                admitted: true,
                quotient: 0,
            })
        );
        assert_eq!(
            checked_scale_gate(1, 101, 0, &[(2, 4)], true),
            Ok(GateResult {
                admitted: true,
                quotient: 1,
            })
        );
    }

    #[test]
    fn rejects_bad_index_and_scale() {
        assert_eq!(
            checked_scale_gate(0, 0, 1, &[(2, 4)], false),
            Err(ScaleError::IndexOutOfRange)
        );
        assert_eq!(
            checked_scale_gate(0, 0, 0, &[(4, 2)], false),
            Err(ScaleError::Scale)
        );
        assert_eq!(
            checked_scale_gate(0, 0, 0, &[(0, 20)], false),
            Err(ScaleError::Scale)
        );
    }
}
