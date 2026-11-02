//! Qualified node94 QC-row one-byte field at native entry `0x4c7e4f3`.
//! Callers premise successful prior row groups and a valid disjoint input slice.
//! These names and types are a chosen safe API, not recovered target Rust types.
//! This module is separate from admission/authentication and does not decode a QC.
//! See `RE-008-qc-recovery-byte-94` for authenticated native observations.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChargeState {
    pub mode: u32,
    pub charge: u64,
    pub limit: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldError {
    ChargeRejected,
    EmptyInput,
}

impl FieldError {
    /// Only the active native error-kind byte, not an enum representation.
    pub fn observed_kind(self) -> u8 {
        match self {
            Self::ChargeRejected => 2,
            Self::EmptyInput => 0,
        }
    }

    /// Value stored at native O+0x10; its shortfall meaning is known only on EOF.
    pub fn observed_error_word(self) -> u64 {
        match self {
            Self::ChargeRejected | Self::EmptyInput => 1,
        }
    }
}

/// Return one uninterpreted byte, retaining any permitted charge on errors.
///
/// A slice suffix represents the abstract pointer/remaining transition. This
/// function does not claim target pointer provenance, output layout, or store
/// instruction ordering. It neither validates recovery IDs nor verifies crypto.
pub fn read_field<'a>(
    state: &mut ChargeState,
    input: &mut &'a [u8],
) -> Result<u8, FieldError> {
    if state.mode == 1 {
        let incremented = state
            .charge
            .checked_add(1)
            .ok_or(FieldError::ChargeRejected)?;
        state.charge = incremented;
        if incremented > state.limit {
            return Err(FieldError::ChargeRejected);
        }
    }

    let (&value, suffix) = input.split_first().ok_or(FieldError::EmptyInput)?;
    *input = suffix;
    Ok(value)
}
