//! Ordered memory-image projection of node94 0x32d8310..0x32d8361.

/// A required span is absent. This new safe policy leaves the image unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unavailable;

fn admits(image: &[u8], start: usize, width: usize) -> bool {
    start
        .checked_add(width)
        .is_some_and(|end| end <= image.len())
}

fn word(image: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(image[at..at + 8].try_into().unwrap())
}

/// Subtract with live aliased operands, then copy in the target's 16/8/8 order.
///
/// `left` and `right` select 32 bytes; `destination` selects 33 bytes, including
/// the borrow flag. Every data overlap is allowed within stable ordinary memory.
/// Each lower-limb store precedes the next subtrahend load. The copy's later
/// qword loads likewise observe earlier copy stores. Return the final qword
/// loaded into original RAX, before the borrow-byte store.
///
/// Offsets represent nonwrapping target addresses within the image. Native
/// pointer ABI, faults/partial fault writes, concurrency and control-state
/// aliases are excluded. Unavailable is additional atomic refusal policy.
pub fn subtract_into_image(
    image: &mut [u8],
    destination: usize,
    left: usize,
    right: usize,
) -> Result<u64, Unavailable> {
    if !admits(image, left, 32) || !admits(image, right, 32) || !admits(image, destination, 33) {
        return Err(Unavailable);
    }
    let mut borrow = false;
    for limb in 0..4 {
        let right_word = word(image, right + 8 * limb);
        let left_word = word(image, left + 8 * limb);
        let (partial, first) = left_word.overflowing_sub(right_word);
        let (value, second) = partial.overflowing_sub(u64::from(borrow));
        borrow = first || second;
        image[left + 8 * limb..left + 8 * limb + 8].copy_from_slice(&value.to_le_bytes());
    }
    let mut low = [0_u8; 16];
    low.copy_from_slice(&image[left..left + 16]);
    image[destination..destination + 16].copy_from_slice(&low);
    let third = word(image, left + 16);
    image[destination + 16..destination + 24].copy_from_slice(&third.to_le_bytes());
    let last = word(image, left + 24);
    image[destination + 24..destination + 32].copy_from_slice(&last.to_le_bytes());
    image[destination + 32] = u8::from(borrow);
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::{Unavailable, subtract_into_image, word};

    fn put(image: &mut [u8], at: usize, words: &[u64]) {
        for (i, value) in words.iter().enumerate() {
            image[at + i * 8..at + i * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
    }

    #[test]
    fn live_subtrahend_is_not_a_snapshot_integer() {
        let mut image = [0; 256];
        put(&mut image, 56, &[5, 10, 20, 30, 40]);
        assert_eq!(subtract_into_image(&mut image, 160, 64, 56), Ok(25));
        assert_eq!(
            [
                word(&image, 160),
                word(&image, 168),
                word(&image, 176),
                word(&image, 184)
            ],
            [5, 15, 15, 25]
        );
        assert_eq!(image[192], 0);
    }

    #[test]
    fn earlier_copy_stores_change_later_reads_and_rax() {
        let mut image = [0; 256];
        put(&mut image, 64, &[1, 2, 3, 4]);
        assert_eq!(subtract_into_image(&mut image, 72, 64, 160), Ok(2));
        assert_eq!(
            [
                word(&image, 72),
                word(&image, 80),
                word(&image, 88),
                word(&image, 96)
            ],
            [1, 2, 2, 2]
        );
    }

    #[test]
    fn disjoint_underflow_copies_wrapped_value_and_borrow() {
        let mut image = [0; 256];
        put(&mut image, 96, &[1, 0, 0, 0]);
        assert_eq!(subtract_into_image(&mut image, 160, 32, 96), Ok(u64::MAX));
        assert_eq!(&image[160..192], &[255; 32]);
        assert_eq!(image[192], 1);
    }

    #[test]
    fn missing_borrow_byte_refuses_atomically() {
        let mut image = [255; 256];
        let before = image;
        assert_eq!(
            subtract_into_image(&mut image, 224, 32, 64),
            Err(Unavailable)
        );
        assert_eq!(image, before);
    }
}
