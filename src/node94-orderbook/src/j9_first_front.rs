#![forbid(unsafe_code)]

//! Two separate local node94 projections, not a sorting pipeline.
//!
//! The j9 insertion is conditional on arrival at its recorded local state.
//! The first-front write is conditional on arrival at the n21 merge front.
//! Neither assumes seed ordering or recovers the intervening right transform.
//! Target: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.

/// Insert loaded A[9] into the selected ten-word scratch window.
///
/// Only the maximal contiguous suffix strictly unsigned-greater than `value`
/// shifts right. Earlier prefix words remain unchanged even if unsorted.
/// Equality stops the scan. The returned index is chosen observation metadata,
/// not native RAX. The fixed initialized array is a chosen safe value view;
/// pointer alignment, original ABI and physical store order are not recovered.
#[must_use]
pub fn insert_j9_loaded(words: &mut [u64; 10], value: u64) -> usize {
    words[9] = value;
    let mut destination = 9;
    while destination > 0 && value < words[destination - 1] {
        words[destination] = words[destination - 1];
        destination -= 1;
    }
    if destination < 9 {
        words[destination] = value;
    }
    destination
}

/// Chosen metadata for the native front selection; not an original enum ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontSide {
    Left,
    Right,
}

/// Write only the first output word from the current two front values.
///
/// This projects node94 `0x4918fe0..0x4919018` after its n21 setup. It does
/// not claim either input is the minimum of its half, a global minimum,
/// later pointer advances, a back store or any complete merge behavior.
/// Ties select the left. All words preserve their complete unsigned bits.
#[must_use]
pub fn write_first_front(output: &mut u64, left: u64, right: u64) -> FrontSide {
    let (word, side) = if right < left {
        (right, FrontSide::Right)
    } else {
        (left, FrontSide::Left)
    };
    *output = word;
    side
}

#[cfg(test)]
mod tests {
    use super::{FrontSide, insert_j9_loaded, write_first_front};

    #[test]
    fn j9_only_moves_the_contiguous_suffix() {
        let mut words = [8, 0, 7, 1, 6, 2, 5, 9, 10, 999];
        assert_eq!(insert_j9_loaded(&mut words, 4), 6);
        assert_eq!(words, [8, 0, 7, 1, 6, 2, 4, 5, 9, 10]);
    }

    #[test]
    fn j9_can_shift_all_nine_unsigned_words() {
        let mut words = [u64::MAX; 10];
        assert_eq!(insert_j9_loaded(&mut words, 0), 0);
        assert_eq!(words[0], 0);
        assert_eq!(&words[1..], &[u64::MAX; 9]);
    }

    #[test]
    fn front_preserves_high_bits_and_left_ties() {
        let mut output = 999;
        assert_eq!(write_first_front(&mut output, 1 << 63, u64::MAX), FrontSide::Left);
        assert_eq!(output, 1 << 63);
        assert_eq!(write_first_front(&mut output, 7, 7), FrontSide::Left);
        assert_eq!(output, 7);
    }
}
