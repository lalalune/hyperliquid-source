#![no_std]

//! The bounded 256-bit subtract-and-copy relation observed in node #115.
//!
//! The public operation uses explicit little-endian byte buffers and does not
//! assign the native leaf a source-level name, type, or ABI.

/// Subtracts `right` from `left` modulo 2^256, stores the result in `left` and
/// the first 32 bytes of `out`, and stores the final unsigned borrow in
/// `out[32]`.
///
/// Both operands and the result bytes use little-endian limb order. The
/// caller must supply valid, stable buffers; Rust's exclusive borrows ensure
/// the three regions do not alias for the duration of this call.
///
/// This projects only the arithmetic and final memory values. It does not
/// claim the original source API, quantity units, native register state,
/// caller behavior, or partial-alias semantics.
pub fn subtract(left: &mut [u8; 32], right: &[u8; 32], out: &mut [u8; 33]) {
    let mut borrow = false;

    for limb in 0..4 {
        let start = limb * 8;
        let mut left_bytes = [0u8; 8];
        let mut right_bytes = [0u8; 8];
        left_bytes.copy_from_slice(&left[start..start + 8]);
        right_bytes.copy_from_slice(&right[start..start + 8]);

        let a = u64::from_le_bytes(left_bytes);
        let b = u64::from_le_bytes(right_bytes);
        let (first, borrow_first) = a.overflowing_sub(b);
        let (difference, borrow_second) = first.overflowing_sub(u64::from(borrow));
        borrow = borrow_first || borrow_second;

        let bytes = difference.to_le_bytes();
        left[start..start + 8].copy_from_slice(&bytes);
        out[start..start + 8].copy_from_slice(&bytes);
    }

    out[32] = u8::from(borrow);
}

#[cfg(test)]
mod tests {
    use super::subtract;

    #[test]
    fn zero_minus_one_wraps_and_reports_borrow() {
        let mut left = [0u8; 32];
        let right = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let mut out = [0u8; 33];

        subtract(&mut left, &right, &mut out);

        assert_eq!(left, [u8::MAX; 32]);
        assert_eq!(&out[..32], &[u8::MAX; 32]);
        assert_eq!(out[32], 1);
    }

    #[test]
    fn equality_has_zero_result_and_no_borrow() {
        let value = [0x81; 32];
        let mut left = value;
        let mut out = [0x55; 33];

        subtract(&mut left, &value, &mut out);

        assert_eq!(left, [0; 32]);
        assert_eq!(&out[..32], &[0; 32]);
        assert_eq!(out[32], 0);
    }

    #[test]
    fn borrow_propagates_through_maximal_right_limbs() {
        let mut left = [0u8; 32];
        left[24] = 1;
        let mut right = [0u8; 32];
        right[..24].fill(u8::MAX);
        let mut out = [0u8; 33];

        subtract(&mut left, &right, &mut out);

        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(left, expected);
        assert_eq!(&out[..32], &expected);
        assert_eq!(out[32], 0);
    }
}
