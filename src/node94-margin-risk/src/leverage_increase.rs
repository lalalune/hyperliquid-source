use crate::{MarginTable, position_leverage_cap};

/// Resolved native fields for the qualified custom-table increase path.
///
/// The metadata/table/position association and prior asset and price-index
/// validation are caller premises. This API does not perform native lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustomLeverageIncrease {
    pub metadata_table_id: u32,
    pub position_table_id: u32,
    pub position_mode_word: u32,
    pub old_leverage: u32,
    pub position_size: i64,
    pub requested_leverage: u32,
    pub price_word: u64,
    pub cross_requested: bool,
    pub kind_byte: u8,
}

/// Chosen safe-API domain errors, not native rejection tags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustomIncreaseDomainError {
    BuiltinTableOutsideScope,
    DifferentPositionTable,
    InactivePosition,
    RequestedDecrease,
}

/// The caller's selected gate result, represented without uninitialized bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustomIncreaseDecision {
    /// Branch to native `0x3709cfa`, before mutation helpers. Not action success.
    EnterCommit,
    /// Native u16 tag `0x44`; no other status fields are established here.
    RejectCrossKind,
    /// Native u16 tag `0x43`; no other status fields are established here.
    RejectOverallMaximum,
    /// Native u16 tag `0x45`; no other status fields are established here.
    RejectAccountingMode,
    /// Native u16 tag `0x50` and initialized u32 cap detail at status+4.
    RejectPositionCap { cap: u32 },
}

/// Project the selected node94 custom-table leverage-increase admission gate.
///
/// `table` must be the same resolved custom registry entry selected by
/// `metadata_table_id`; its validated tiers supply both the first-tier maximum
/// and position-size cap. Its runtime registration and native storage lifetime
/// are not reconstructed. A canonical Rust bool models only native cross0/1.
///
/// The four domain checks are explicit safe-API policy. They exclude builtin
/// tables, inactive positions, table changes and decreases; those native paths
/// need additional helper semantics. For admitted inputs, rejection order is
/// cross kind, overall maximum, DWORD-mode consistency, then the position cap.
/// A passing result means only entry to the native commit block. Later helper
/// returns/effects and complete action success remain outside this function.
pub fn check_custom_leverage_increase(
    table: &MarginTable,
    input: CustomLeverageIncrease,
) -> Result<CustomIncreaseDecision, CustomIncreaseDomainError> {
    if input.metadata_table_id < 50 {
        return Err(CustomIncreaseDomainError::BuiltinTableOutsideScope);
    }
    if input.position_table_id != input.metadata_table_id {
        return Err(CustomIncreaseDomainError::DifferentPositionTable);
    }
    if input.position_size == 0 {
        return Err(CustomIncreaseDomainError::InactivePosition);
    }
    if input.requested_leverage < input.old_leverage {
        return Err(CustomIncreaseDomainError::RequestedDecrease);
    }

    if input.cross_requested && input.kind_byte != 0 {
        return Ok(CustomIncreaseDecision::RejectCrossKind);
    }
    let maximum = u32::from(table.tiers()[0].max_leverage());
    if input.requested_leverage > maximum {
        return Ok(CustomIncreaseDecision::RejectOverallMaximum);
    }
    if (input.position_mode_word == 0) != input.cross_requested {
        return Ok(CustomIncreaseDecision::RejectAccountingMode);
    }
    let cap = u32::from(position_leverage_cap(
        Some(table), input.price_word, input.position_size,
    ));
    if input.requested_leverage > cap {
        return Ok(CustomIncreaseDecision::RejectPositionCap { cap });
    }
    Ok(CustomIncreaseDecision::EnterCommit)
}
