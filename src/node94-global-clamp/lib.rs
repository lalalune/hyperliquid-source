#![no_std]
#![forbid(unsafe_code)]

//! Closed value/state projection of node94 global clamp and its tail helper.

/// Replace the three destination globals and return the complete native RAX.
///
/// `value` is one snapshot of the signed input global at ELF VA 0x57881e0.
/// `state` represents the qwords at 0x59afc98, 0x59afca0 and 0x59afca8.
/// The actual tail helper clears the middle word, stores the unshifted normalized
/// value in the last word and returns zero. Runtime globals must be ordinary
/// stable valid memory for correspondence; this is not a global-memory or ABI
/// implementation, and it assigns no application meaning to the three words.
pub fn initialize(value: i64, state: &mut [u64; 3]) -> u64 {
    let normalized = if value < 0 { 0 } else { value.max(1) as u64 };
    state[0] = if normalized == 0 {
        0
    } else {
        (normalized >> 6).clamp(1, 0x400000)
    };
    state[1] = 0;
    state[2] = normalized;
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_clears_all_words() {
        let mut state = [u64::MAX; 3];
        assert_eq!(initialize(i64::MIN, &mut state), 0);
        assert_eq!(state, [0, 0, 0]);
    }

    #[test]
    fn zero_normalizes_the_unshifted_tail_value() {
        let mut state = [u64::MAX; 3];
        assert_eq!(initialize(0, &mut state), 0);
        assert_eq!(state, [1, 0, 1]);
    }

    #[test]
    fn cap_does_not_replace_unshifted_value() {
        let mut state = [u64::MAX; 3];
        assert_eq!(initialize(0x10000040, &mut state), 0);
        assert_eq!(state, [0x400000, 0, 0x10000040]);
    }
}
