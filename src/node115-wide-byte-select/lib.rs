#![no_std]
//! Safe logical projection of the Node 115 wide-byte selection leaf.
//! No source name, protocol meaning, or original ABI is inferred.

/// Abstract effect of the native red-zone scratch writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScratchEffect {
    /// The depth-underflow return performs no memory writes.
    Untouched,
    /// Either normal arm zeros the 24-byte scratch region.
    Zeroed24Bytes,
}

/// Observable logical result of the bounded leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Projection {
    pub depth_after: u64,
    pub rax: u64,
    pub scratch: ScratchEffect,
}

/// Host-side guard for a buffer that cannot represent the target's valid-memory
/// precondition. This is not a branch or error produced by the captured leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidBuffer {
    pub requested_depth: u64,
    pub available_slots: usize,
}

/// Project the byte-selection function at `0x43352f0` over little-endian
/// 256-bit slots.
///
/// Slot `depth - 1` is the index; slot `depth - 2` is the value and receives
/// the zero-extended selected byte. All other slots remain unchanged. For
/// depths below two the buffer is not accessed and only AL of `entry_rax` is
/// replaced by `0x2c`. For valid normal execution, `depth` must not exceed the
/// provided slot slice; an invalid slice is reported separately as a model
/// input error.
pub fn select_byte(
    slots: &mut [[u8; 32]],
    depth: u64,
    entry_rax: u64,
) -> Result<Projection, InvalidBuffer> {
    if depth < 2 {
        return Ok(Projection {
            depth_after: depth,
            rax: (entry_rax & !0xff) | 0x2c,
            scratch: ScratchEffect::Untouched,
        });
    }

    let depth_index = usize::try_from(depth).map_err(|_| InvalidBuffer {
        requested_depth: depth,
        available_slots: slots.len(),
    })?;
    if depth_index > slots.len() {
        return Err(InvalidBuffer {
            requested_depth: depth,
            available_slots: slots.len(),
        });
    }

    let index_slot = slots[depth_index - 1];
    let value_slot = slots[depth_index - 2];
    let selected = if index_slot[1..].iter().any(|&limb| limb != 0) || index_slot[0] >= 32 {
        0
    } else {
        value_slot[31 - usize::from(index_slot[0])]
    };

    slots[depth_index - 2] = [0; 32];
    slots[depth_index - 2][0] = selected;

    Ok(Projection {
        depth_after: depth - 1,
        rax: 0,
        scratch: ScratchEffect::Zeroed24Bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_index(slot: &mut [u8; 32], low: u8, high_bit: Option<usize>) {
        *slot = [0; 32];
        slot[0] = low;
        if let Some(bit) = high_bit {
            slot[bit / 8] |= 1 << (bit % 8);
        }
    }

    #[test]
    fn all_32_valid_indices_select_the_expected_little_endian_byte() {
        let original: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
        let mut slots = [[0; 32]; 2];
        for index in 0..32u8 {
            slots[0] = original;
            set_index(&mut slots[1], index, None);
            let projection = select_byte(&mut slots, 2, u64::MAX).unwrap();
            assert_eq!(projection.depth_after, 1, "index={index}");
            assert_eq!(projection.rax, 0, "index={index}");
            assert_eq!(projection.scratch, ScratchEffect::Zeroed24Bytes);
            assert_eq!(slots[0][0], 32 - index, "index={index}");
            assert!(slots[0][1..].iter().all(|&byte| byte == 0));
            assert_eq!(slots[1][0], index);
        }
    }

    #[test]
    fn out_of_range_and_every_high_limb_reject_the_index() {
        let mut slots = [[u8::MAX; 32]; 2];
        for low in [32, 33, 63, 255] {
            set_index(&mut slots[1], low, None);
            select_byte(&mut slots, 2, 7).unwrap();
            assert_eq!(slots[0], [0; 32], "low={low}");
        }
        for bit in 8..256 {
            set_index(&mut slots[1], 0, Some(bit));
            slots[0] = [u8::MAX; 32];
            select_byte(&mut slots, 2, 7).unwrap();
            assert_eq!(slots[0], [0; 32], "high bit={bit}");
        }
    }

    #[test]
    fn underflow_preserves_slots_depth_and_upper_rax_without_buffer_access() {
        for depth in [0, 1] {
            for entry_rax in [0, u64::MAX, 0x1234_5678_9abc_def0] {
                let mut slots = [];
                let projection = select_byte(&mut slots, depth, entry_rax).unwrap();
                assert_eq!(projection.depth_after, depth);
                assert_eq!(projection.rax, (entry_rax & !0xff) | 0x2c);
                assert_eq!(projection.scratch, ScratchEffect::Untouched);
            }
        }
    }

    #[test]
    fn only_the_result_slot_changes_and_popped_or_inactive_slots_remain() {
        let mut slots = [[0x56; 32], [0; 32], [0; 32], [0xcd; 32]];
        slots[1][31] = 0x80;
        set_index(&mut slots[2], 0, None);
        let popped_index = slots[2];
        let projection = select_byte(&mut slots, 3, u64::MAX).unwrap();
        assert_eq!(projection.depth_after, 2);
        assert_eq!(projection.rax, 0);
        assert_eq!(slots[0], [0x56; 32]);
        assert_eq!(
            slots[1],
            [
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ]
        );
        assert_eq!(slots[2], popped_index);
        assert_eq!(slots[3], [0xcd; 32]);
    }

    #[test]
    fn insufficient_host_buffer_is_separate_from_target_behavior() {
        let mut slots = [[0x31; 32]; 2];
        let before = slots;
        assert_eq!(
            select_byte(&mut slots, 3, 0),
            Err(InvalidBuffer {
                requested_depth: 3,
                available_slots: 2,
            })
        );
        assert_eq!(slots, before);
    }
}

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
mod tests_explicit_slots {
    use super::{Transition, apply};

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
