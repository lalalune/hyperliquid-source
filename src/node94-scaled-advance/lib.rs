#![no_std]
#![forbid(unsafe_code)]
//! Exact value/state projection of node94 [0x4ea41e0,0x4ea4216).

const INVERSE_ELEVEN: u64 = 0x2e8b_a2e8_ba2e_8ba3;

/// Update the cursor and return the unadvanced request, preserving all u64 bits.
///
/// For a nonwrapping span divisible by 88, the scaled count is (end-cursor)/88.
/// Other spans retain the original modular inverse multiplication; replacing it
/// with ordinary division changes behavior. No pointer is dereferenced, and no
/// validity, alignment or ordering of the numeric inputs is assumed.
pub fn advance(cursor: &mut u64, end: u64, requested: u64) -> u64 {
    let count = end.wrapping_sub(*cursor) >> 3;
    let scaled = count.wrapping_mul(INVERSE_ELEVEN);
    let taken = requested.min(scaled);
    *cursor = cursor.wrapping_add(taken.wrapping_mul(88));
    requested.wrapping_sub(taken)
}

#[cfg(test)]
mod tests {
    use super::advance;

    #[test]
    fn valid_span_uses_exact_element_count() {
        let mut cursor = 100;
        assert_eq!(advance(&mut cursor, 716, 9), 2);
        assert_eq!(cursor, 716);
    }

    #[test]
    fn noncanonical_span_is_not_floor_division() {
        let mut cursor = 0;
        assert_eq!(advance(&mut cursor, 8, 1), 0);
        assert_eq!(cursor, 88);
    }

    #[test]
    fn wrapped_span_and_cursor_follow_word_arithmetic() {
        let mut cursor = u64::MAX - 7;
        assert_eq!(advance(&mut cursor, 80, 2), 1);
        assert_eq!(cursor, 80);
    }
}
