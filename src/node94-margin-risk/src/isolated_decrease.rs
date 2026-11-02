use crate::{
    AccountingMode, LiquidationError, MarginMode, MarginTable, PositionCalculationError,
    PositionInput, assess_isolated_liquidation, calculate_position_margin,
    position_leverage_cap,
};

/// Resolved scalar fields for the selected one-position isolated decrease path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustomIsolatedDecrease {
    pub metadata_table_id: u32,
    pub position_table_id: u32,
    pub position_mode_word: u32,
    pub cross_requested: bool,
    pub old_leverage: u32,
    pub requested_leverage: u32,
    pub position_size: i64,
    pub isolated_margin: i64,
    pub price_word: u64,
}

/// Safe projection errors, not native refusal tags or recovered panic ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IsolatedDecreaseProjectionError {
    BuiltinTableOutsideScope,
    DifferentPositionTable,
    NoncanonicalIsolated,
    NotPositiveDecrease,
    InactivePosition,
    PriceOutsideSignedRange,
    PositionCalculation(PositionCalculationError),
    Surplus(LiquidationError),
}

/// Initialized caller decision fields without a speculative status-memory ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolatedDecreaseDecision {
    /// Branch to 0x3709cfa after normal clone cleanup, not action success.
    EnterCommit,
    RejectOverallMaximum,
    RejectPositionCap { cap: u32 },
    RejectIsolatedMargin,
}
impl IsolatedDecreaseDecision {
    /// Only the initialized native refusal tag and optional cap detail.
    /// EnterCommit does not synthesize the later success tag0x186.
    #[must_use]
    pub const fn native_refusal(self) -> Option<(u16, Option<u32>)> {
        match self {
            Self::EnterCommit => None,
            Self::RejectOverallMaximum => Some((0x43, None)),
            Self::RejectPositionCap { cap } => Some((0x50, Some(cap))),
            Self::RejectIsolatedMargin => Some((0x47, None)),
        }
    }
}

/// Project the proved same-table, canonical-isolated leverage-decrease gate.
///
/// Native premises include the actual custom table/position association, a
/// coherent one-leaf positions tree with one matching key, empty companion
/// tree, prior valid indices, and the reviewed provider preservation/alias and
/// ordinary-return contracts. No native clone, allocator, ownership, lifetime
/// or complete action success is implemented by this scalar decision function.
///
/// A native shadow preserves mode/margin/size and replaces leverage/table only.
/// The same supplied table derives maximum/cap; the same price and signed size
/// feed the existing mode1 position calculation. The isolated assessment uses
/// margin_after and computed_requirement, never effective_margin. Its numeric
/// negative predicate is reused here without claiming a liquidation action.
pub fn check_custom_isolated_decrease(
    table: &MarginTable,
    input: CustomIsolatedDecrease,
) -> Result<IsolatedDecreaseDecision, IsolatedDecreaseProjectionError> {
    use IsolatedDecreaseProjectionError as Error;
    if input.metadata_table_id < 50 {
        return Err(Error::BuiltinTableOutsideScope);
    }
    if input.position_table_id != input.metadata_table_id {
        return Err(Error::DifferentPositionTable);
    }
    if input.position_mode_word != 1 || input.cross_requested {
        return Err(Error::NoncanonicalIsolated);
    }
    if input.position_size == 0 {
        return Err(Error::InactivePosition);
    }
    if input.requested_leverage == 0 || input.requested_leverage >= input.old_leverage {
        return Err(Error::NotPositiveDecrease);
    }
    let price = i64::try_from(input.price_word).map_err(|_| Error::PriceOutsideSignedRange)?;
    let maximum = u32::from(table.tiers()[0].max_leverage());
    if input.requested_leverage > maximum {
        return Ok(IsolatedDecreaseDecision::RejectOverallMaximum);
    }
    let cap = u32::from(position_leverage_cap(Some(table), input.price_word, input.position_size));
    if input.requested_leverage > cap {
        return Ok(IsolatedDecreaseDecision::RejectPositionCap { cap });
    }
    let shadow = PositionInput {
        accounting: AccountingMode::Isolated,
        leverage_divisor: input.requested_leverage,
        margin: input.isolated_margin,
        size: input.position_size,
        tier_selector: input.metadata_table_id,
    };
    let position = calculate_position_margin(
        shadow, price, MarginMode::PositionDivisor as u8, 0, Some(table),
    ).map_err(Error::PositionCalculation)?;
    let assessment = assess_isolated_liquidation(position).map_err(Error::Surplus)?;
    if assessment.eligible {
        return Ok(IsolatedDecreaseDecision::RejectIsolatedMargin);
    }
    Ok(IsolatedDecreaseDecision::EnterCommit)
}
