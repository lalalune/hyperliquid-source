//! Qualified FD-only state projections of node94 `0x466bf60`.
//!
//! Inputs contain four consecutive `FD` markers and eight little-endian payload
//! bytes each; charge plus 32 must fit and be within the supplied limit. The
//! 40-byte result view is the observed tag qword followed by four value qwords.
//! The original bool interface covers complete success. The outcome interface
//! additionally covers the first short FD/EOF at any position. Neither recovers
//! the decoder ABI, inactive error bytes, intermediate charge writes, other
//! markers or the complete QC row decoder.

/// Read the qualified mode-1 group, returning false outside this API's domain.
///
/// A false result leaves all arguments unchanged. That is a chosen safe-API
/// behavior; native error behavior is deliberately unqualified. On success the
/// input advances by 36 bytes and charge increases by 32, independently of any
/// remaining suffix. Output holds tag zero and the four ordered value words.
pub fn read_mode1_fd_group(
    charge: &mut u64,
    limit: u64,
    input: &mut &[u8],
    output: &mut [u8; 40],
) -> bool {
    let Some(final_charge) = charge.checked_add(32) else {
        return false;
    };
    if final_charge > limit || input.len() < 36 {
        return false;
    }
    if [0, 9, 18, 27].iter().any(|&at| input[at] != 0xfd) {
        return false;
    }
    let word0 = u64::from_le_bytes(input[1..9].try_into().unwrap());
    let word1 = u64::from_le_bytes(input[10..18].try_into().unwrap());
    let word2 = u64::from_le_bytes(input[19..27].try_into().unwrap());
    let word3 = u64::from_le_bytes(input[28..36].try_into().unwrap());
    output[0..8].copy_from_slice(&0u64.to_le_bytes());
    output[8..16].copy_from_slice(&word0.to_le_bytes());
    output[16..24].copy_from_slice(&word1.to_le_bytes());
    output[24..32].copy_from_slice(&word2.to_le_bytes());
    output[32..40].copy_from_slice(&word3.to_le_bytes());
    *charge = final_charge;
    *input = &input[36..];
    true
}

/// A chosen safe result type, with no native enum-layout or ABI claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdGroupOutcome {
    /// Nonadmitted charge or a marker outside this qualified FD-only domain.
    /// Arguments remain unchanged; native behavior there is unqualified.
    OutsideDomain,
    Complete([u64; 4]),
    Incomplete { needed: u64 },
}

impl FdGroupOutcome {
    /// Observed group tag qword, kind byte and need qword, only for this error.
    /// No inactive bytes or source error representation are exposed.
    pub fn observed_short_fields(&self) -> Option<(u64, u8, u64)> {
        match self {
            Self::Incomplete { needed } => Some((1, 0, *needed)),
            _ => None,
        }
    }
}

/// Read four FD words or return the first qualified short-input outcome.
///
/// Mode1 is a premise. Charge+32 must fit and be admitted, and every available
/// marker up to the first short field must be FD. Outside that domain this safe
/// API returns OutsideDomain without effects. Qualified outcomes retain C+32.
/// Complete words consume9 bytes each; short FD consumes only its marker and
/// leaves the payload unread; EOF consumes nothing more and reports need1.
/// Only final state is projected, not native charge-store timing or row reachability.
pub fn read_mode1_fd_group_outcome(
    charge: &mut u64,
    limit: u64,
    input: &mut &[u8],
) -> FdGroupOutcome {
    let Some(reserved_charge) = charge.checked_add(32) else {
        return FdGroupOutcome::OutsideDomain;
    };
    if reserved_charge > limit {
        return FdGroupOutcome::OutsideDomain;
    }
    let mut check = *input;
    for _ in 0..4 {
        if check.is_empty() {
            break;
        }
        if check[0] != 0xfd {
            return FdGroupOutcome::OutsideDomain;
        }
        if check.len() < 9 {
            break;
        }
        check = &check[9..];
    }
    *charge = reserved_charge;
    let mut words = [0u64; 4];
    for index in 0..4 {
        if input.is_empty() {
            return FdGroupOutcome::Incomplete { needed: 1 };
        }
        if input.len() < 9 {
            let needed = (9 - input.len()) as u64;
            *input = &input[1..];
            return FdGroupOutcome::Incomplete { needed };
        }
        words[index] = u64::from_le_bytes(input[1..9].try_into().unwrap());
        *input = &input[9..];
    }
    FdGroupOutcome::Complete(words)
}
