#![no_std]
//! Logical projection of the complete node #115 leaf at `0x4332f70`.
//!
//! This module models the observed byte transform and capacity return. It
//! does not claim the original state type, owner, protocol role, or ABI.

/// The observed unsigned capacity boundary is `0x3ff` inclusive.
pub const MAX_SLOT_INDEX: u64 = 1023;

/// Reverses one 32-byte value into the next slot.
///
/// On success, increments `count`, writes the reversed bytes at that index,
/// and returns zero. If `count > MAX_SLOT_INDEX`, it leaves both inputs
/// unchanged and returns the observed RAX value: the original count with its
/// low byte replaced by `0x2d`.
///
/// The fixed array models the leaf's bounded slot region. As with the binary
/// evidence, this contract assumes valid, non-overlapping memory and no
/// concurrent mutation; safe Rust references enforce the aliasing condition.
pub fn append_reversed_word(
    count: &mut u64,
    slots: &mut [[u8; 32]; 1024],
    source: &[u8; 32],
) -> u64 {
    let index = *count;
    if index > MAX_SLOT_INDEX {
        return (index & !0xff) | 0x2d;
    }

    *count = index + 1;
    let mut reversed = [0; 32];
    for (destination, input) in reversed.iter_mut().zip(source.iter().rev()) {
        *destination = *input;
    }
    slots[index as usize] = reversed;
    0
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    fn slots() -> [[u8; 32]; 1024] {
        [[0; 32]; 1024]
    }

    #[test]
    fn reverses_all_bytes_and_advances_count() {
        let source: [u8; 32] = core::array::from_fn(|i| i as u8);
        let mut output = slots();
        let mut count = 0;

        assert_eq!(append_reversed_word(&mut count, &mut output, &source), 0);
        assert_eq!(count, 1);
        assert_eq!(output[0], core::array::from_fn(|i| (31 - i) as u8));
        assert_eq!(output[1], [0; 32]);
    }

    #[test]
    fn accepts_last_slot() {
        let source = [0xa5; 32];
        let mut output = slots();
        let mut count = MAX_SLOT_INDEX;

        assert_eq!(append_reversed_word(&mut count, &mut output, &source), 0);
        assert_eq!(count, 1024);
        assert_eq!(output[1023], source);
    }

    #[test]
    fn rejects_count_above_boundary_without_writes() {
        let source = [0x5a; 32];
        let mut output = slots();
        let mut count = 1024;

        assert_eq!(
            append_reversed_word(&mut count, &mut output, &source),
            0x42d
        );
        assert_eq!(count, 1024);
        assert_eq!(output, slots());
    }

    #[test]
    fn failure_preserves_upper_rax_bits() {
        let mut output = slots();
        let mut count = 0x1234_5678_9abc_deff;

        assert_eq!(
            append_reversed_word(&mut count, &mut output, &[0; 32]),
            0x1234_5678_9abc_de2d
        );
        assert_eq!(count, 0x1234_5678_9abc_deff);
        assert_eq!(output, slots());
    }
}
