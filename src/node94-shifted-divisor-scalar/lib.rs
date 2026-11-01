//! Value reconstruction of node94 ELF VA 0x565ede0..0x565ee3d.
//!
//! Both arguments cover all 128-bit values. They replace the native input
//! pointer and RSI/RDX threshold pair with stable numeric snapshots. No
//! pointer ABI, fault behavior or source-level division identity is claimed.
#![no_std]
#![forbid(unsafe_code)]

/// Produce 65 greedy comparison bits, saturating if the first bit is set.
///
/// The threshold shifts right after each of the first 64 decisions; the final
/// decision uses its original value shifted by 64. Zero thresholds accept a
/// bit. This is not ordinary division for arbitrary threshold low halves:
/// `shifted_divisor_scalar(0, 1)` returns `u64::MAX`.
pub fn shifted_divisor_scalar(numerator: u128, threshold: u128) -> u64 {
    let mut remainder = numerator;
    let mut weight = threshold;
    let mut digits = 0u64;
    for _ in 0..64 {
        let accepted = remainder >= weight;
        if accepted {
            remainder -= weight;
        }
        digits = (digits << 1) | u64::from(accepted);
        weight >>= 1;
    }
    let first_bit = digits >> 63;
    let final_digit = u64::from(remainder >= weight);
    let value = (digits << 1) | final_digit;
    if first_bit != 0 { u64::MAX } else { value }
}
