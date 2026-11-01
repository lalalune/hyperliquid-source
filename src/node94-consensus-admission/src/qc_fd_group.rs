//! Final-state projection of node94 `0x466bf60` on its qualified success domain.
//!
//! Inputs contain four consecutive `FD` markers and eight little-endian payload
//! bytes each; charge plus 32 must fit and be within the supplied limit. The
//! 40-byte result view is the observed tag qword followed by four value qwords.
//! This safe interface does not reproduce the decoder ABI, intermediate charge
//! writes, failure paths, or the complete QC row decoder.

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
