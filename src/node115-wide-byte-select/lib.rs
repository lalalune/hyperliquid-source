#![no_std]

//! A bounded logical projection of node #115's wide-byte selection leaf.
//!
//! This module implements only the register and two-slot transformation
//! derived for `0x43352f0`. It does not claim the source type, module owner,
//! calling convention, dispatch meaning, or integration with the node.

/// Register and depth values visible at this leaf's normal return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transition {
    /// Depth after the operation. Underflow leaves it unchanged.
    pub depth: u64,
    /// RAX value after the operation, including the preserved upper bits on
    /// the underflow return.
    pub rax: u64,
}

/// Applies the observed byte-selection relation to the two relevant slots.
///
/// `index_slot` and `preceding_slot` are each a 256-bit little-endian word in
/// memory order. For depth at least two, the full-width index in
/// `index_slot` selects byte `31 - index` from `preceding_slot` when the
/// index is below 32; otherwise the selected value is zero. The preceding
/// slot is then replaced by that value in its low byte and zeroes elsewhere,
/// and depth is decremented.
///
/// For depth below two, neither slot is read or changed and only AL is set to
/// `0x2c`, preserving the upper bits of `entry_rax`.
///
/// # Boundary
///
/// The caller must pass the two slots corresponding to `depth - 1` and
/// `depth - 2` when `depth >= 2`, with valid, non-overlapping storage. This
/// safe projection does not model pointer faults, the function's red-zone
/// scratch, ABI details beyond the returned RAX value, or any caller meaning.
#[must_use]
pub fn apply(
    depth: u64,
    index_slot: &[u8; 32],
    preceding_slot: &mut [u8; 32],
    entry_rax: u64,
) -> Transition {
    if depth < 2 {
        return Transition {
            depth,
            rax: (entry_rax & !0xff) | 0x2c,
        };
    }

    let low_index = u64::from_le_bytes([
        index_slot[0],
        index_slot[1],
        index_slot[2],
        index_slot[3],
        index_slot[4],
        index_slot[5],
        index_slot[6],
        index_slot[7],
    ]);
    let high_index_is_zero = index_slot[8..].iter().all(|byte| *byte == 0);
    let selected = if high_index_is_zero && low_index < 32 {
        preceding_slot[31 - low_index as usize]
    } else {
        0
    };

    preceding_slot.fill(0);
    preceding_slot[0] = selected;

    Transition {
        depth: depth - 1,
        rax: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{apply, Transition};

    #[test]
    fn selects_each_byte_from_the_most_significant_end() {
        let original = core::array::from_fn(|i| i as u8);
        for index in 0..32u64 {
            let mut index_slot = [0u8; 32];
            index_slot[0] = index as u8;
            let mut preceding_slot = original;
            let result = apply(2, &index_slot, &mut preceding_slot, u64::MAX);

            assert_eq!(result, Transition { depth: 1, rax: 0 });
            assert_eq!(preceding_slot[0], original[31 - index as usize]);
            assert!(preceding_slot[1..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn rejects_wide_and_out_of_range_indices() {
        let original = [0xa5; 32];
        for index_slot in [[32u8; 32], {
            let mut wide = [0u8; 32];
            wide[0] = 1;
            wide[31] = 1;
            wide
        }] {
            let mut preceding_slot = original;
            let result = apply(3, &index_slot, &mut preceding_slot, 0x1234);
            assert_eq!(result, Transition { depth: 2, rax: 0 });
            assert_eq!(preceding_slot, [0; 32]);
        }
    }

    #[test]
    fn underflow_preserves_depth_slots_and_upper_rax() {
        let index_slot = [0x5a; 32];
        let mut preceding_slot = [0xa5; 32];
        for depth in [0, 1] {
            let before = preceding_slot;
            let result = apply(
                depth,
                &index_slot,
                &mut preceding_slot,
                0x1234_5678_9abc_def1,
            );
            assert_eq!(
                result,
                Transition {
                    depth,
                    rax: 0x1234_5678_9abc_de2c,
                }
            );
            assert_eq!(preceding_slot, before);
        }
    }

    #[test]
    fn writes_the_selected_byte_as_a_zero_extended_word() {
        let mut index_slot = [0u8; 32];
        index_slot[0] = 31;
        let mut preceding_slot = [0u8; 32];
        preceding_slot[0] = 0x11;
        preceding_slot[31] = 0xfe;

        let result = apply(2, &index_slot, &mut preceding_slot, u64::MAX);

        assert_eq!(result, Transition { depth: 1, rax: 0 });
        assert_eq!(
            preceding_slot,
            [
                0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ]
        );
    }
}
