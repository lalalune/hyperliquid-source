#![no_std]
#![forbid(unsafe_code)]
//! Safe projection of the selected node115 position mode and direct arithmetic.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModePlan {
    None,
    Divide(u64),
    MarginTableA,
    MarginTableB,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModeError {
    Unknown,
    ZeroDivisor,
}

pub fn dispatch(mode: u8, divisor: u32, cap: u8) -> Result<ModePlan, ModeError> {
    match mode {
        0 => Ok(ModePlan::None),
        1 => nonzero(u64::from(divisor)).map(ModePlan::Divide),
        2 => Ok(ModePlan::MarginTableA),
        3 => Ok(ModePlan::MarginTableB),
        4 => nonzero(u64::from(divisor).min(u64::from(cap))).map(ModePlan::Divide),
        _ => Err(ModeError::Unknown),
    }
}

fn nonzero(value: u64) -> Result<u64, ModeError> {
    if value == 0 {
        Err(ModeError::ZeroDivisor)
    } else {
        Ok(value)
    }
}

pub fn magnitude(value: i64) -> u64 {
    value.unsigned_abs()
}

pub fn quotient(magnitude: u64, divisor: u64) -> Result<u64, ModeError> {
    Ok(magnitude / nonzero(divisor)?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveOffset {
    pub saturated_sum: i64,
    pub positive_part: u64,
}

pub fn active_offset(product: i64, offset: i64) -> ActiveOffset {
    let sum = product.saturating_add(offset);
    ActiveOffset {
        saturated_sum: sum,
        positive_part: sum.max(0) as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::{ModeError, ModePlan, active_offset, dispatch, magnitude, quotient};

    #[test]
    fn frozen_mode_dispatch() {
        assert_eq!(dispatch(0, 0, 0), Ok(ModePlan::None));
        assert_eq!(dispatch(1, 7, 0), Ok(ModePlan::Divide(7)));
        assert_eq!(dispatch(2, 0, 0), Ok(ModePlan::MarginTableA));
        assert_eq!(dispatch(3, 0, 0), Ok(ModePlan::MarginTableB));
        assert_eq!(dispatch(4, 20, 8), Ok(ModePlan::Divide(8)));
        assert_eq!(dispatch(4, 6, 8), Ok(ModePlan::Divide(6)));
        assert_eq!(dispatch(5, 1, 1), Err(ModeError::Unknown));
        assert_eq!(dispatch(1, 0, 1), Err(ModeError::ZeroDivisor));
    }

    #[test]
    fn signed_magnitude_and_floor_division() {
        assert_eq!(magnitude(-7), 7);
        assert_eq!(magnitude(i64::MIN), 1 << 63);
        assert_eq!(quotient(7, 2), Ok(3));
        assert_eq!(quotient(7, 0), Err(ModeError::ZeroDivisor));
    }

    #[test]
    fn active_offset_saturates_and_clamps_positive_part() {
        assert_eq!(
            active_offset(i64::MAX, 1),
            super::ActiveOffset {
                saturated_sum: i64::MAX,
                positive_part: i64::MAX as u64,
            }
        );
        assert_eq!(
            active_offset(-10, 3),
            super::ActiveOffset {
                saturated_sum: -7,
                positive_part: 0,
            }
        );
    }
}
