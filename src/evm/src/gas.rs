//! Node #115 mode-13 intrinsic gas schedule and admission gate (`0x5be2560`, `0x5be0720`, `0x2b93030`).
//!
//! Grounded in `research/work-items/RE-021-precompile-preflight-115`:
//! - `tokens = zero_bytes + 4 * nonzero_bytes`
//! - `initial = 21000 + 4 * tokens + 2400 * access_addresses + 1900 * access_slots + 25000 * auth_items`
//!   plus `32000 + 2 * ceil(input_len / 32)` when `is_create` is true.
//! - `floor = 21000 + 10 * tokens` (EIP-7623).
//! - Admission checks `initial > gas_limit` (tag 3) before `floor > gas_limit` (tag 4).

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Mode13GasInput {
    pub zero_bytes: u64,
    pub nonzero_bytes: u64,
    pub access_addresses: u64,
    pub access_slots: u64,
    pub auth_items: u64,
    pub is_create: bool,
}

impl Mode13GasInput {
    pub fn from_calldata(data: &[u8], is_create: bool) -> Self {
        let zero_bytes = data.iter().filter(|&&b| b == 0).count() as u64;
        let nonzero_bytes = (data.len() as u64) - zero_bytes;
        Self {
            zero_bytes,
            nonzero_bytes,
            access_addresses: 0,
            access_slots: 0,
            auth_items: 0,
            is_create,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mode13GasBreakdown {
    pub tokens: u64,
    pub initial: u64,
    pub floor: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Mode13GasAdmission {
    /// Tag `3`: `initial > gas_limit`.
    InitialExceedsLimit = 3,
    /// Tag `4`: `floor > gas_limit` (when floor check enabled).
    FloorExceedsLimit = 4,
    /// Tag `0x21`: admitted (`initial <= gas_limit` and `floor <= gas_limit`).
    Admitted = 0x21,
}

/// Compute `(tokens, initial, floor)` under the node #115 mode-13 schedule (`0x5be2560`).
pub fn compute_mode13_gas(input: Mode13GasInput) -> Option<Mode13GasBreakdown> {
    let tokens = input.zero_bytes.checked_add(input.nonzero_bytes.checked_mul(4)?)?;
    let mut initial = 21_000u64
        .checked_add(tokens.checked_mul(4)?)?
        .checked_add(input.access_addresses.checked_mul(2_400)?)?
        .checked_add(input.access_slots.checked_mul(1_900)?)?
        .checked_add(input.auth_items.checked_mul(25_000)?)?;
    if input.is_create {
        let input_len = input.zero_bytes.checked_add(input.nonzero_bytes)?;
        let words = input_len.checked_add(31)? / 32;
        initial = initial.checked_add(32_000)?.checked_add(words.checked_mul(2)?)?;
    }
    let floor = 21_000u64.checked_add(tokens.checked_mul(10)?)?;
    Some(Mode13GasBreakdown {
        tokens,
        initial,
        floor,
    })
}

/// Evaluate node #115 mode-13 gas admission (`0x2b93030`).
pub fn admit_mode13_gas(
    breakdown: Mode13GasBreakdown,
    gas_limit: u64,
    disable_floor: bool,
) -> Mode13GasAdmission {
    if breakdown.initial > gas_limit {
        Mode13GasAdmission::InitialExceedsLimit
    } else if !disable_floor && breakdown.floor > gas_limit {
        Mode13GasAdmission::FloorExceedsLimit
    } else {
        Mode13GasAdmission::Admitted
    }
}
